"""CURVE-authenticated PUB/SUB transport for neutral v2 market events.

The publisher's principal map is a server-owned audience ACL: listed CURVE
keys are authorized to connect and receive traffic. Version 1 sends every
single-frame event to that audience; version 2 adds per-topic delivery
filtering, but the topic is not an authorization decision. This module does
not replay history or acknowledge delivery. Construct, use, and close each
transport on one thread; each instance owns its context, socket, and (for
publishers) authenticator.
"""

from __future__ import annotations

import math
import threading
from collections.abc import Mapping
from types import MappingProxyType
from typing import Optional

import zmq
from bt_api_base.market_protocol import (
    MARKET_EVENT_OPERATION,
    MARKET_EVENT_SCHEMA,
    MARKET_EVENT_SCHEMA_VERSION,
    MarketSubscriptionKey,
)
from bt_api_base.service_protocol import (
    MAX_REFERENCE_BYTES,
    MAX_WIRE_MESSAGE_BYTES,
    WireEnvelope,
    WireIdentity,
    WireRole,
    WireScope,
    decode_envelope,
    encode_envelope,
    validate_event,
)
from nacl import bindings
from nacl.exceptions import CryptoError
from zmq.auth.thread import ThreadAuthenticator
from zmq.utils import z85

from .server import CurveClientCredentials, CurveServerCredentials
from .service_v2 import ServiceTransportStartupCleanupError

DEFAULT_HIGH_WATER_MARK = 1000
DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024
MAX_PRINCIPALS = 4096
MAX_DRAIN_FRAMES_PER_CALL = 64
_MAX_SOCKET_OPTION_INT = 2_147_483_647
_ZAP_DOMAIN = "bt-api-market-v2"
MARKET_WIRE_VERSION_LEGACY = 1
MARKET_WIRE_VERSION_TOPIC_FILTERED = 2
_SUPPORTED_MARKET_WIRE_VERSIONS = frozenset(
    {MARKET_WIRE_VERSION_LEGACY, MARKET_WIRE_VERSION_TOPIC_FILTERED}
)
_TOPIC_FILTERED_FRAME_PREFIX = b"\x00BTAPI-MARKET\x00\x02"
_MAX_TOPIC_FRAME_BYTES = len(_TOPIC_FILTERED_FRAME_PREFIX) + len("market-") + 64 + 1


class _MarketPrincipalRegistry:
    """ZAP callback for a finite publisher-owned CURVE audience map."""

    def __init__(self, principals: Mapping[bytes, str]) -> None:
        self._principals = principals

    def callback(self, domain: str, client_key: bytes) -> bool:
        return domain == _ZAP_DOMAIN and client_key in self._principals


class _BoundedMultipartReceiver:
    """Read one bounded frame and incrementally discard multipart messages."""

    def __init__(self, socket: zmq.Socket) -> None:
        self._socket = socket
        self._discarding = False

    def receive(self) -> Optional[zmq.Frame]:  # noqa: UP045 -- Python 3.9 compatibility.
        if self._discarding:
            self._drain()
            return None

        try:
            frame = self._socket.recv(flags=zmq.NOBLOCK, copy=False)
        except zmq.Again:
            return None
        if self._socket.getsockopt(zmq.RCVMORE):
            self._discarding = True
            self._drain()
            return None
        return frame

    def _drain(self) -> None:
        for _ in range(MAX_DRAIN_FRAMES_PER_CALL):
            try:
                self._socket.recv(flags=zmq.NOBLOCK, copy=False)
            except zmq.Again:
                return
            if not self._socket.getsockopt(zmq.RCVMORE):
                self._discarding = False
                return


class _BoundedTopicReceiver:
    """Read exactly two bounded topic/envelope frames and drain extras safely."""

    def __init__(self, socket: zmq.Socket) -> None:
        self._socket = socket
        self._discarding = False

    def receive(self) -> tuple[zmq.Frame, zmq.Frame] | None:
        if self._discarding:
            self._drain()
            return None

        try:
            topic = self._socket.recv(flags=zmq.NOBLOCK, copy=False)
        except zmq.Again:
            return None
        if not self._socket.getsockopt(zmq.RCVMORE):
            return None

        try:
            envelope = self._socket.recv(flags=zmq.NOBLOCK, copy=False)
        except zmq.Again:
            self._discarding = True
            self._drain()
            return None
        if self._socket.getsockopt(zmq.RCVMORE):
            self._discarding = True
            self._drain()
            return None
        return topic, envelope

    def _drain(self) -> None:
        for _ in range(MAX_DRAIN_FRAMES_PER_CALL):
            try:
                self._socket.recv(flags=zmq.NOBLOCK, copy=False)
            except zmq.Again:
                return
            if not self._socket.getsockopt(zmq.RCVMORE):
                self._discarding = False
                return


class MarketTransportError(RuntimeError):
    """The authenticated market event transport could not safely operate."""


def validate_publisher_configuration(
    endpoint: str,
    identity: WireIdentity,
    scope: WireScope,
    principals: Mapping[bytes, str],
    *,
    credentials: CurveServerCredentials,
    high_water_mark: int = DEFAULT_HIGH_WATER_MARK,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    wire_version: int = MARKET_WIRE_VERSION_LEGACY,
) -> None:
    """Validate publisher inputs without creating ZMQ resources."""

    _validated_publisher_configuration(
        endpoint,
        identity,
        scope,
        principals,
        credentials=credentials,
        high_water_mark=high_water_mark,
        max_message_bytes=max_message_bytes,
        wire_version=wire_version,
    )


def _validated_publisher_configuration(
    endpoint: str,
    identity: WireIdentity,
    scope: WireScope,
    principals: Mapping[bytes, str],
    *,
    credentials: CurveServerCredentials,
    high_water_mark: int,
    max_message_bytes: int,
    wire_version: int,
) -> Mapping[bytes, str]:
    _validate_endpoint(endpoint)
    if type(identity) is not WireIdentity or identity.role is not WireRole.SERVICE:
        raise ValueError("market publisher identity must have the service role")
    if type(scope) is not WireScope:
        raise ValueError("market publisher scope must be a WireScope")
    _validate_public_market_scope(scope)
    _validate_limits(high_water_mark, max_message_bytes)
    _validate_market_wire_version(wire_version)
    copied_principals = _copy_principals(principals)
    if not copied_principals:
        raise ValueError("market publisher audience must not be empty")
    server_public, server_secret = _server_keypair(credentials)
    if bindings.crypto_scalarmult_base(server_secret) != server_public:
        raise ValueError("server CURVE public and secret keys do not match")
    return copied_principals


class ZmqMarketPublisher:
    """CURVE-authenticated PUB socket for one identity and scope.

    ``principals`` maps each authorized client's Z85 CURVE public key to a
    finite trusted reference. Legacy wire version 1 broadcasts each
    single-frame envelope to authorized peers. Version 2 sends a topic frame
    derived from the complete event stream ID before the unchanged envelope,
    allowing matching subscribers to filter in ZeroMQ. This topic is not an
    authorization decision; the CURVE audience remains authoritative. Both
    peers must be configured for the same transport version by the trusted
    control/deployment layer. ``publish`` follows the neutral publisher port
    and returns no delivery status. The optional ``try_publish`` reports local
    send acceptance only; PUB may still discard for a slow subscriber.
    """

    def __init__(
        self,
        endpoint: str,
        identity: WireIdentity,
        scope: WireScope,
        principals: Mapping[bytes, str],
        *,
        credentials: CurveServerCredentials,
        high_water_mark: int = DEFAULT_HIGH_WATER_MARK,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        wire_version: int = MARKET_WIRE_VERSION_LEGACY,
    ) -> None:
        copied_principals = _validated_publisher_configuration(
            endpoint,
            identity,
            scope,
            principals,
            credentials=credentials,
            high_water_mark=high_water_mark,
            max_message_bytes=max_message_bytes,
            wire_version=wire_version,
        )
        self._identity = identity
        self._scope = scope
        self._principals = copied_principals
        self._credentials = credentials
        self._high_water_mark = high_water_mark
        self._max_message_bytes = max_message_bytes
        self._wire_version = wire_version
        self._owner_thread = threading.get_ident()
        self._closed = False
        self._close_pending = False
        self._context = None
        self._socket = None
        self._authenticator = None
        self.endpoint = endpoint
        try:
            self._context = zmq.Context()
            self._socket = self._context.socket(zmq.PUB)
            _configure_publisher_socket(self._socket, high_water_mark, max_message_bytes)
            self._socket.zap_domain = _ZAP_DOMAIN.encode("ascii")
            self._socket.curve_publickey = credentials.public_key
            self._socket.curve_secretkey = credentials.secret_key
            self._socket.curve_server = True

            self._authenticator = ThreadAuthenticator(self._context)
            self._authenticator.configure_curve_callback(
                domain=_ZAP_DOMAIN,
                credentials_provider=_MarketPrincipalRegistry(self._principals),
            )
            self._authenticator.start()
            self._socket.bind(endpoint)
            actual_endpoint = self._socket.getsockopt(zmq.LAST_ENDPOINT)
            self.endpoint = actual_endpoint.decode("utf-8", errors="strict")
        except BaseException:
            try:
                self.close()
            except BaseException:
                raise ServiceTransportStartupCleanupError(self) from None
            raise

    def publish(self, event: WireEnvelope) -> None:
        """Queue one validated event through the neutral publisher contract."""

        self.try_publish(event)

    def try_publish(self, event: WireEnvelope) -> bool:
        """Report local send acceptance only; this is not a delivery receipt."""

        self._check_thread()
        if self._closed or self._close_pending:
            raise RuntimeError("market publisher is closed")
        _validate_market_event(event, self._identity, self._scope)
        encoded = encode_envelope(event, max_bytes=self._max_message_bytes)
        try:
            if self._wire_version == MARKET_WIRE_VERSION_LEGACY:
                self._socket.send(encoded, flags=zmq.NOBLOCK)
            else:
                key = MarketSubscriptionKey.from_dict(event.payload["key"])
                topic = _market_topic_for_stream_id(key.stream_id)
                self._socket.send_multipart([topic, encoded], flags=zmq.NOBLOCK)
        except zmq.Again:
            return False
        return True

    def close(self) -> None:
        """Close owned resources; a failed stage can be retried on this thread."""

        if self._closed:
            return
        self._check_thread()
        self._close_pending = True
        authenticator = self._authenticator
        if authenticator is not None:
            authenticator.stop()
            self._authenticator = None
        socket = self._socket
        if socket is not None:
            socket.close(linger=0)
            self._socket = None
        context = self._context
        if context is not None:
            context.term()
            self._context = None
        self._closed = True
        self._close_pending = False

    def _check_thread(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise RuntimeError("ZMQ market publisher must be used and closed by its owning thread")


class ZmqMarketSubscriber:
    """CURVE-authenticated SUB socket for one expected service and scope.

    Wire version 1 receives all market keys for the configured audience and
    leaves key filtering to the SDK. Wire version 2 requires one exact
    ``MarketSubscriptionKey`` and subscribes with its full topic as a ZeroMQ
    prefix filter, then checks exact topic equality before decoding. The event
    envelope and that key are also checked after receipt. Sequence
    cursors and replay remain SDK responsibilities. This socket provides no
    baseline recovery; a timeout or dropped malformed frame both return
    ``None`` and do not establish whether a sequence gap occurred.
    """

    def __init__(
        self,
        endpoint: str,
        expected_peer: WireIdentity,
        expected_scope: WireScope,
        *,
        credentials: CurveClientCredentials,
        high_water_mark: int = DEFAULT_HIGH_WATER_MARK,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        wire_version: int = MARKET_WIRE_VERSION_LEGACY,
        subscription_key: MarketSubscriptionKey | None = None,
    ) -> None:
        _validate_subscriber_configuration(
            endpoint,
            expected_peer,
            expected_scope,
            credentials=credentials,
            high_water_mark=high_water_mark,
            max_message_bytes=max_message_bytes,
            wire_version=wire_version,
            subscription_key=subscription_key,
        )
        self._endpoint = endpoint
        self.endpoint = endpoint
        self._expected_peer = expected_peer
        self._expected_scope = expected_scope
        self._high_water_mark = high_water_mark
        self._max_message_bytes = max_message_bytes
        self._wire_version = wire_version
        self._subscription_key = subscription_key
        self._topic = (
            _market_topic_for_stream_id(subscription_key.stream_id)
            if wire_version == MARKET_WIRE_VERSION_TOPIC_FILTERED
            else None
        )
        self._credentials = credentials
        self._owner_thread = threading.get_ident()
        self._closed = False
        self._close_pending = False
        self._context = None
        self._socket = None
        self._receiver = None
        try:
            self._context = zmq.Context()
            self._socket = self._context.socket(zmq.SUB)
            if wire_version == MARKET_WIRE_VERSION_LEGACY:
                self._receiver = _BoundedMultipartReceiver(self._socket)
                subscription = b""
            else:
                self._receiver = _BoundedTopicReceiver(self._socket)
                assert self._topic is not None
                subscription = self._topic
            socket_max_message_bytes = max_message_bytes
            if wire_version == MARKET_WIRE_VERSION_TOPIC_FILTERED:
                # The application limit covers the unchanged envelope. ZMQ's
                # inbound limit covers the full multipart message, including
                # its bounded topic frame.
                socket_max_message_bytes += _MAX_TOPIC_FRAME_BYTES
            _configure_subscriber_socket(self._socket, high_water_mark, socket_max_message_bytes)
            self._socket.curve_serverkey = credentials.server_key
            self._socket.curve_publickey = credentials.public_key
            self._socket.curve_secretkey = credentials.secret_key
            self._socket.setsockopt(zmq.SUBSCRIBE, subscription)
            self._socket.connect(endpoint)
        except BaseException:
            try:
                self.close()
            except BaseException:
                raise ServiceTransportStartupCleanupError(self) from None
            raise

    def receive(
        self,
        *,
        timeout: Optional[float] = None,  # noqa: UP045 -- Python 3.9 compatibility.
        timeout_ms: Optional[int] = None,  # noqa: UP045 -- Python 3.9 compatibility.
    ) -> Optional[WireEnvelope]:  # noqa: UP045 -- Python 3.9 compatibility.
        """Return one event; timeout is seconds, with timeout_ms kept as an alias.

        ``timeout=None`` waits until a frame arrives. Invalid or multipart
        messages are dropped and return ``None`` immediately, including when
        timeout is ``None``; call again to continue receiving. A returned
        ``None`` therefore does not distinguish timeout from dropped input.
        """

        self._check_thread()
        if self._closed or self._close_pending:
            raise RuntimeError("market subscriber is closed")
        if timeout is not None and timeout_ms is not None:
            raise ValueError("specify only one of timeout or timeout_ms")
        poll_timeout_ms = timeout_ms
        if poll_timeout_ms is not None:
            if (
                type(poll_timeout_ms) is not int
                or not 0 <= poll_timeout_ms <= _MAX_SOCKET_OPTION_INT
            ):
                raise ValueError("timeout_ms must be a bounded non-negative integer")
        elif timeout is not None:
            if (
                type(timeout) not in (int, float)
                or timeout < 0
                or timeout > _MAX_SOCKET_OPTION_INT / 1000
                or not math.isfinite(timeout)
            ):
                raise ValueError("timeout must be a bounded non-negative number of seconds")
            poll_timeout_ms = math.ceil(timeout * 1000)

        if self._socket.poll(poll_timeout_ms, zmq.POLLIN) == 0:
            return None
        if self._wire_version == MARKET_WIRE_VERSION_LEGACY:
            frame = self._receiver.receive()
        else:
            parts = self._receiver.receive()
            if parts is None:
                return None
            topic, frame = parts
            if len(topic) > _MAX_TOPIC_FRAME_BYTES or bytes(topic) != self._topic:
                return None
        if frame is None or len(frame) > self._max_message_bytes:
            return None
        try:
            event = decode_envelope(bytes(frame), max_bytes=self._max_message_bytes)
            _validate_market_event(event, self._expected_peer, self._expected_scope)
            if self._subscription_key is not None:
                actual_key = MarketSubscriptionKey.from_dict(event.payload["key"])
                if (
                    event.header.stream_id != self._subscription_key.stream_id
                    or actual_key != self._subscription_key
                ):
                    return None
        except ValueError:
            return None
        return event

    def close(self) -> None:
        """Close owned resources; a failed stage can be retried on this thread."""

        if self._closed:
            return
        self._check_thread()
        self._close_pending = True
        socket = self._socket
        if socket is not None:
            socket.close(linger=0)
            self._socket = None
            self._receiver = None
        else:
            self._receiver = None
        context = self._context
        if context is not None:
            context.term()
            self._context = None
        self._closed = True
        self._close_pending = False

    def _check_thread(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise RuntimeError("ZMQ market subscriber must be used and closed by its owning thread")


def _validate_market_event(
    event: WireEnvelope,
    expected_identity: WireIdentity,
    expected_scope: WireScope,
) -> None:
    if type(event) is not WireEnvelope:
        raise ValueError("market event must be a WireEnvelope")
    header = event.header
    validate_event(event, expected_scope=expected_scope)
    if header.identity != expected_identity:
        raise ValueError("market event identity does not match the configured peer")
    if (
        header.operation != MARKET_EVENT_OPERATION
        or header.schema_id != MARKET_EVENT_SCHEMA
        or header.schema_version != MARKET_EVENT_SCHEMA_VERSION
    ):
        raise ValueError("market event schema or operation is unsupported")
    if set(event.payload) != {"key", "data"}:
        raise ValueError("market event payload must contain exactly key and data")
    try:
        key = MarketSubscriptionKey.from_dict(event.payload["key"])
    except (TypeError, ValueError):
        raise ValueError("market event subscription key is invalid") from None
    if header.stream_id != key.stream_id:
        raise ValueError("market event stream does not match its subscription key")
    if not isinstance(event.payload["data"], Mapping):
        raise ValueError("market event data must be an object")


def _validate_subscriber_configuration(
    endpoint: str,
    expected_peer: WireIdentity,
    expected_scope: WireScope,
    *,
    credentials: CurveClientCredentials,
    high_water_mark: int,
    max_message_bytes: int,
    wire_version: int,
    subscription_key: MarketSubscriptionKey | None,
) -> None:
    _validate_endpoint(endpoint)
    if type(expected_peer) is not WireIdentity or expected_peer.role is not WireRole.SERVICE:
        raise ValueError("expected market peer must have the service role")
    if type(expected_scope) is not WireScope:
        raise ValueError("expected market scope must be a WireScope")
    _validate_public_market_scope(expected_scope)
    _validate_market_wire_version(wire_version)
    if wire_version == MARKET_WIRE_VERSION_TOPIC_FILTERED:
        if type(subscription_key) is not MarketSubscriptionKey:
            raise ValueError("topic-filtered market transport requires a subscription key")
        _market_topic_for_stream_id(subscription_key.stream_id)
    elif subscription_key is not None:
        raise ValueError("legacy market transport does not accept a subscription key")
    if not isinstance(credentials, CurveClientCredentials):
        raise ValueError("Curve client credentials are required")
    _validate_limits(high_water_mark, max_message_bytes)
    try:
        server_key = z85.decode(credentials.server_key)
        public_key = z85.decode(credentials.public_key)
        secret_key = z85.decode(credentials.secret_key)
        derived_public_key = bindings.crypto_scalarmult_base(secret_key)
    except (KeyError, TypeError, ValueError, CryptoError) as exc:
        raise ValueError("client CURVE key is invalid") from exc
    if derived_public_key != public_key:
        raise ValueError("client CURVE public and secret keys do not match")
    if len(server_key) != 32:
        raise ValueError("server CURVE public key is invalid")


def _server_keypair(credentials: CurveServerCredentials) -> tuple[bytes, bytes]:
    if not isinstance(credentials, CurveServerCredentials):
        raise ValueError("Curve server credentials are required")
    try:
        return z85.decode(credentials.public_key), z85.decode(credentials.secret_key)
    except (KeyError, TypeError, ValueError, CryptoError) as exc:
        raise ValueError("server CURVE key is invalid") from exc


def _validate_public_market_scope(scope: WireScope) -> None:
    if scope != WireScope(execution_domain_ref=scope.execution_domain_ref):
        raise ValueError("market transport scope must exclude account and strategy claims")


def _validate_endpoint(endpoint: str) -> None:
    if type(endpoint) is not str or not endpoint.startswith("tcp://"):
        raise MarketTransportError("market v2 requires CURVE-authenticated TCP endpoints")


def _validate_limits(high_water_mark: int, max_message_bytes: int) -> None:
    if (
        type(high_water_mark) is not int
        or high_water_mark <= 0
        or high_water_mark > _MAX_SOCKET_OPTION_INT
    ):
        raise ValueError("high_water_mark must be a positive bounded integer")
    if (
        type(max_message_bytes) is not int
        or max_message_bytes <= 0
        or max_message_bytes > MAX_WIRE_MESSAGE_BYTES
    ):
        raise ValueError("max_message_bytes is outside the protocol limit")


def _validate_market_wire_version(version: int) -> None:
    if type(version) is not int or version not in _SUPPORTED_MARKET_WIRE_VERSIONS:
        raise ValueError("unsupported market wire version")


def _market_topic_for_stream_id(stream_id: str) -> bytes:
    if (
        type(stream_id) is not str
        or len(stream_id) != len("market-") + 64
        or not stream_id.startswith("market-")
        or any(character not in "0123456789abcdef" for character in stream_id[len("market-") :])
    ):
        raise ValueError("market topic requires a canonical subscription stream ID")
    return _TOPIC_FILTERED_FRAME_PREFIX + stream_id.encode("ascii") + b"\x00"


def _copy_principals(principals: Mapping[bytes, str]) -> Mapping[bytes, str]:
    if not isinstance(principals, Mapping):
        raise ValueError("principals must map CURVE Z85 public keys to trusted references")
    copied = {}
    for public_key, principal_ref in principals.items():
        if len(copied) >= MAX_PRINCIPALS:
            raise ValueError("market publisher audience exceeds the finite principal limit")
        if type(public_key) is not bytes or len(public_key) != 40:
            raise ValueError("principal map keys must be 40-byte Z85 public keys")
        try:
            z85.decode(public_key)
        except (KeyError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError("principal map key is not valid Z85") from exc
        _validate_principal_ref(principal_ref)
        copied[public_key] = principal_ref
    return MappingProxyType(copied)


def _validate_principal_ref(principal_ref: str) -> None:
    if type(principal_ref) is not str:
        raise ValueError("trusted principal references must be strings")
    try:
        encoded = principal_ref.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("trusted principal reference is invalid") from exc
    if (
        not encoded
        or len(encoded) > MAX_REFERENCE_BYTES
        or principal_ref != principal_ref.strip()
        or any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in principal_ref)
    ):
        raise ValueError("trusted principal reference is invalid")


def _configure_publisher_socket(
    socket: zmq.Socket,
    high_water_mark: int,
    max_message_bytes: int,
) -> None:
    socket.setsockopt(zmq.LINGER, 0)
    socket.setsockopt(zmq.SNDHWM, high_water_mark)
    socket.setsockopt(zmq.MAXMSGSIZE, max_message_bytes)


def _configure_subscriber_socket(
    socket: zmq.Socket,
    high_water_mark: int,
    max_message_bytes: int,
) -> None:
    socket.setsockopt(zmq.LINGER, 0)
    socket.setsockopt(zmq.RCVHWM, high_water_mark)
    socket.setsockopt(zmq.MAXMSGSIZE, max_message_bytes)
