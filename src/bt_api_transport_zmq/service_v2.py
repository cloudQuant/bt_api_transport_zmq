"""Authenticated ZeroMQ transport for the neutral v2 service protocol.

Each transport owns its sockets and request state. Clients can optionally
share a process-local ZMQ context through an explicit pool; without a pool,
each client retains an independent context. Construct, use, and close each
transport on one thread. The transport authenticates peers with CURVE and
passes the trusted principal reference derived from ZAP metadata to the handler;
identity claims in the envelope remain the SDK's responsibility to authorize.
"""

from __future__ import annotations

import errno
import math
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Optional

import zmq
from bt_api_base.service_protocol import (
    MAX_REFERENCE_BYTES,
    MAX_WIRE_MESSAGE_BYTES,
    WIRE_PROTOCOL_VERSION,
    WireEnvelope,
    WireErrorCode,
    WireHeader,
    WireIdentity,
    WireMessageKind,
    WireRole,
    WireValidationError,
    decode_envelope,
    encode_envelope,
    validate_reply,
    validate_request,
)
from nacl import bindings
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from zmq.auth.thread import ThreadAuthenticator
from zmq.utils import z85

from .server import CurveClientCredentials, CurveServerCredentials

DEFAULT_HIGH_WATER_MARK = 1000
DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024
_MAX_SOCKET_OPTION_INT = 2_147_483_647
_MAX_MESSAGE_IDS_PER_SOCKET = 4096
_MAX_ROUTER_ID_BYTES = 255
_ZAP_DOMAIN = "bt-api-service-v2"
_CODE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_GENERIC_HANDLER_ERROR = {"ok": False, "code": "INTERNAL_ERROR", "result": {}}
_MAX_DRAIN_FRAMES_PER_CALL = 64
_REPLY_FRAME_PREFIX = b"BTAPI-ZMQ-REPLY-V2\x00"
_REPLY_FRAME_OVERHEAD = len(_REPLY_FRAME_PREFIX) + bindings.crypto_box_SEALBYTES


class _BoundedMultipartReceiver:
    """Read a bounded prefix and incrementally discard excess message frames."""

    def __init__(self, socket: zmq.Socket) -> None:
        self._socket = socket
        self._discarding = False

    def receive(self, max_frames: int) -> Optional[list[zmq.Frame]]:  # noqa: UP045 -- Python 3.9 compatibility.
        if self._discarding:
            self._drain()
            return None

        frames = []
        for _ in range(max_frames):
            try:
                frame = self._socket.recv(flags=zmq.NOBLOCK, copy=False)
            except zmq.Again:
                return None
            frames.append(frame)
            if not self._socket.getsockopt(zmq.RCVMORE):
                return frames

        # The message exceeded the protocol's frame count. Keep no more frames
        # than the bounded prefix, and finish discarding it over later calls.
        self._discarding = True
        self._drain()
        return None

    def _drain(self) -> None:
        for _ in range(_MAX_DRAIN_FRAMES_PER_CALL):
            try:
                self._socket.recv(flags=zmq.NOBLOCK, copy=False)
            except zmq.Again:
                return
            if not self._socket.getsockopt(zmq.RCVMORE):
                self._discarding = False
                return


class ServiceTransportError(RuntimeError):
    """The authenticated v2 transport could not safely process an operation."""


class ServiceTransportStartupCleanupError(ServiceTransportError):
    """Startup failed and cleanup remains available for a same-thread retry."""

    def __init__(self, transport: Any) -> None:
        self.transport = transport
        self.cause_code = "startup_cleanup_failed"
        super().__init__("service transport startup cleanup failed; retry close")


class ZmqServiceContextPool:
    """Share a process-local ZMQ context across service clients.

    Each client retains its own DEALER socket, receiver, CURVE keys and
    request-correlation state. The context is terminated only after the last
    client has closed its socket and released its lease. A live pool cannot be
    used across a process boundary.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._context = None
        self._owner_pid = os.getpid()
        self._active_leases = 0
        self._generation = 0
        self._termination_pending = False

    def acquire(self) -> _ZmqServiceContextLease:
        current_pid = os.getpid()
        if current_pid != self._owner_pid:
            raise RuntimeError("service ZMQ context pool cannot cross a process boundary")
        with self._lock:
            # Check again under the lock. The pre-lock check prevents a forked
            # child from blocking on an inherited locked RLock.
            current_pid = os.getpid()
            if current_pid != self._owner_pid:
                raise RuntimeError("service ZMQ context pool cannot cross a process boundary")
            if self._context is not None:
                if self._termination_pending:
                    raise RuntimeError("service ZMQ context termination is pending")
            else:
                self._context = zmq.Context(io_threads=1)
                self._generation += 1
            self._active_leases += 1
            return _ZmqServiceContextLease(
                self,
                self._context,
                current_pid,
                self._generation,
            )

    def _release(self, lease: _ZmqServiceContextLease) -> None:
        current_pid = os.getpid()
        if current_pid != self._owner_pid or current_pid != lease._owner_pid:
            raise RuntimeError("service ZMQ context lease cannot cross a process boundary")
        with self._lock:
            current_pid = os.getpid()
            if current_pid != self._owner_pid or current_pid != lease._owner_pid:
                raise RuntimeError("service ZMQ context lease cannot cross a process boundary")
            if lease._pool is not self:
                raise RuntimeError("service ZMQ context lease has the wrong owner")
            if lease._released:
                if (
                    self._termination_pending
                    and self._active_leases == 0
                    and self._context is lease._context
                    and self._generation == lease._generation
                ):
                    self._terminate_context_locked(lease._context, lease._generation)
                return
            if (
                self._context is not lease._context
                or self._generation != lease._generation
                or self._active_leases <= 0
            ):
                raise RuntimeError("service ZMQ context lease state is inconsistent")
            self._active_leases -= 1
            lease._released = True
            if self._active_leases == 0:
                self._terminate_context_locked(lease._context, lease._generation)

    def _terminate_context_locked(self, context: zmq.Context, generation: int) -> None:
        if self._context is not context or self._generation != generation:
            raise RuntimeError("service ZMQ context termination owner is inconsistent")
        try:
            context.term()
        except BaseException:
            self._termination_pending = True
            raise
        self._context = None
        self._termination_pending = False


class _ZmqServiceContextLease:
    def __init__(
        self,
        pool: ZmqServiceContextPool,
        context: zmq.Context,
        owner_pid: int,
        generation: int,
    ) -> None:
        self._pool = pool
        self._context = context
        self._owner_pid = owner_pid
        self._generation = generation
        self._released = False

    @property
    def context(self) -> zmq.Context:
        return self._context

    def close(self) -> None:
        self._pool._release(self)


class RequestNotSentError(TimeoutError):
    """The request was not queued by ZeroMQ and can be retried with its ID."""

    def __init__(self, message_id: str, cause_code: str = "send_timeout") -> None:
        self.message_id = message_id
        self.cause_code = cause_code
        super().__init__("request was not sent; retry message id " + message_id)


class RequestOutcomeUnknownError(TimeoutError):
    """A request may have reached the service; reconcile using its message ID."""

    def __init__(self, message_id: str, cause_code: str = "response_timeout") -> None:
        self.message_id = message_id
        self.cause_code = cause_code
        super().__init__("request outcome is unknown; reconcile message id " + message_id)


class _CurvePrincipalRegistry:
    """ZAP callback for the finite server-owned CURVE key/principal map."""

    def __init__(self, principals: Mapping[bytes, str]) -> None:
        self._principals = principals

    def callback(self, domain: str, client_key: bytes) -> bool:
        return domain == _ZAP_DOMAIN and client_key in self._principals


def validate_service_server_configuration(
    endpoint: str,
    identity: WireIdentity,
    principals: Mapping[bytes, str],
    *,
    credentials: CurveServerCredentials,
    high_water_mark: int = DEFAULT_HIGH_WATER_MARK,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
) -> None:
    """Validate v2 server inputs without creating ZeroMQ resources."""

    _validated_service_server_configuration(
        endpoint,
        identity,
        principals,
        credentials=credentials,
        high_water_mark=high_water_mark,
        max_message_bytes=max_message_bytes,
    )


def _validated_service_server_configuration(
    endpoint: str,
    identity: WireIdentity,
    principals: Mapping[bytes, str],
    *,
    credentials: CurveServerCredentials,
    high_water_mark: int,
    max_message_bytes: int,
) -> tuple[Mapping[bytes, str], dict[bytes, PublicKey]]:
    _validate_endpoint(endpoint)
    if type(identity) is not WireIdentity or identity.role is not WireRole.SERVICE:
        raise ValueError("service identity must have the service role")
    if not isinstance(credentials, CurveServerCredentials):
        raise ValueError("Curve server credentials are required")
    _validate_limits(high_water_mark, max_message_bytes)
    copied_principals = _copy_principals(principals)
    try:
        server_public_key = z85.decode(credentials.public_key)
        server_secret_key = z85.decode(credentials.secret_key)
        derived_public_key = bindings.crypto_scalarmult_base(server_secret_key)
        reply_keys = {
            public_key: PublicKey(z85.decode(public_key)) for public_key in copied_principals
        }
    except (KeyError, TypeError, ValueError, CryptoError) as exc:
        raise ValueError("server or principal CURVE key is invalid") from exc
    if derived_public_key != server_public_key:
        raise ValueError("server CURVE public and secret keys do not match")
    return copied_principals, reply_keys


class ZmqServiceServer:
    """CURVE-authenticated ROUTER for one request/reply v2 service.

    ``principals`` maps Z85-encoded CURVE client public keys to trusted
    principal references. The request's ROUTER identity and ``principal_ref``
    claim are never used to derive that value. ``serve_once`` handles at most
    one received message; malformed or unauthenticated messages are dropped.
    """

    def __init__(
        self,
        endpoint: str,
        identity: WireIdentity,
        principals: Mapping[bytes, str],
        handler: Callable[[str, WireEnvelope], Mapping[str, Any]],
        *,
        credentials: CurveServerCredentials,
        high_water_mark: int = DEFAULT_HIGH_WATER_MARK,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> None:
        if not callable(handler):
            raise ValueError("handler is required")
        copied_principals, reply_keys = _validated_service_server_configuration(
            endpoint,
            identity,
            principals,
            credentials=credentials,
            high_water_mark=high_water_mark,
            max_message_bytes=max_message_bytes,
        )
        self._identity = identity
        self._principals = copied_principals
        self._reply_keys = reply_keys
        self._handler = handler
        self._max_message_bytes = max_message_bytes
        self._reply_envelope_max_bytes = max_message_bytes - _REPLY_FRAME_OVERHEAD
        self._owner_thread = threading.get_ident()
        self._closed = False
        self._close_pending = False
        self._context = None
        self._socket = None
        self._receiver = None
        self._authenticator = None
        try:
            self._context = zmq.Context()
            self._socket = self._context.socket(zmq.ROUTER)
            self._receiver = _BoundedMultipartReceiver(self._socket)
            _configure_socket(self._socket, high_water_mark, max_message_bytes)
            self._socket.setsockopt(zmq.ROUTER_MANDATORY, 1)
            self._socket.zap_domain = _ZAP_DOMAIN.encode("ascii")
            self._socket.curve_publickey = credentials.public_key
            self._socket.curve_secretkey = credentials.secret_key
            self._socket.curve_server = True

            self._authenticator = ThreadAuthenticator(self._context)
            self._authenticator.configure_curve_callback(
                domain=_ZAP_DOMAIN,
                credentials_provider=_CurvePrincipalRegistry(self._principals),
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

    def serve_once(self, timeout_ms: int = 0) -> bool:
        """Handle one received message, returning false when the wait expires."""

        self._check_thread()
        if self._closed or self._close_pending:
            raise RuntimeError("server is closed")
        if type(timeout_ms) is not int or timeout_ms < 0:
            raise ValueError("timeout_ms must be a non-negative integer")
        if self._socket.poll(timeout_ms, zmq.POLLIN) == 0:
            return False

        frames = self._receiver.receive(2)
        if frames is None or len(frames) != 2:
            return True
        route = bytes(frames[0])
        body_frame = frames[1]
        if not route or len(route) > 255 or len(body_frame) > self._max_message_bytes:
            return True
        authenticated_peer = self._authenticated_peer(body_frame)
        if authenticated_peer is None:
            return True
        principal_ref, recipient_key = authenticated_peer
        try:
            request = decode_envelope(bytes(body_frame), max_bytes=self._max_message_bytes)
            validate_request(request)
        except WireValidationError:
            return True

        try:
            result = self._handler(principal_ref, request)
            payload = _handler_payload(result)
            reply = _make_reply(self._identity, request, payload)
            encoded_reply = encode_envelope(reply, max_bytes=self._reply_envelope_max_bytes)
        except Exception:
            reply = _make_reply(self._identity, request, _GENERIC_HANDLER_ERROR)
            try:
                encoded_reply = encode_envelope(reply, max_bytes=self._reply_envelope_max_bytes)
            except WireValidationError:
                # The request was valid but a safe fallback cannot fit. Drop it;
                # the client observes an uncertain outcome and can reconcile.
                return True

        try:
            framed_reply = _seal_reply(encoded_reply, recipient_key)
        except Exception:
            # Never downgrade to plaintext, even for a generic fallback.
            return True
        try:
            self._socket.send_multipart([route, framed_reply], flags=zmq.NOBLOCK)
        except zmq.Again:
            # The caller will time out with an uncertain outcome and reconcile.
            pass
        except zmq.ZMQError as exc:
            unreachable_codes = {
                getattr(errno, "EHOSTUNREACH", None),
                getattr(zmq, "EHOSTUNREACH", None),
            }
            if exc.errno not in unreachable_codes:
                raise
            # A ROUTER_MANDATORY route may disappear after the handler ran.
            # Its result is uncertain to that peer; keep serving other clients.
        return True

    def close(self) -> None:
        """Close owned resources in order; retry a failed stage on this thread."""

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
            self._receiver = None
        else:
            self._receiver = None
        context = self._context
        if context is not None:
            context.term()
            self._context = None
        self._closed = True
        self._close_pending = False

    def _authenticated_peer(self, frame: zmq.Frame) -> Optional[tuple[str, PublicKey]]:  # noqa: UP045 -- Python 3.9 compatibility.
        try:
            user_id = frame["User-Id"]
        except (KeyError, zmq.ZMQError):
            return None
        if isinstance(user_id, str):
            try:
                user_id = user_id.encode("ascii", errors="strict")
            except UnicodeEncodeError:
                return None
        if not isinstance(user_id, bytes):
            return None
        principal_ref = self._principals.get(user_id)
        if principal_ref is None:
            return None
        return principal_ref, self._reply_keys[user_id]

    def _check_thread(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise RuntimeError("ZMQ server must be used and closed by its owning thread")


class ZmqServiceClient:
    """Single-in-flight CURVE DEALER client for v2 RPC requests.

    A timeout never triggers a retry. Replies for other correlation IDs and
    undecodable late traffic are ignored until this request's deadline. An
    uncertain request retires its socket so a late reply cannot cross calls;
    completed sockets also retire after a bounded number of unique IDs.
    """

    def __init__(
        self,
        endpoint: str,
        identity: WireIdentity,
        *,
        credentials: CurveClientCredentials,
        high_water_mark: int = DEFAULT_HIGH_WATER_MARK,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        context_pool: ZmqServiceContextPool | None = None,
    ) -> None:
        _validate_endpoint(endpoint)
        if type(identity) is not WireIdentity or identity.role is not WireRole.SERVICE:
            raise ValueError("expected service identity must have the service role")
        if not isinstance(credentials, CurveClientCredentials):
            raise ValueError("Curve client credentials are required")
        _validate_limits(high_water_mark, max_message_bytes)
        if context_pool is not None and type(context_pool) is not ZmqServiceContextPool:
            raise ValueError("context_pool must be a ZmqServiceContextPool")
        self._identity = identity
        self._endpoint = endpoint
        self._high_water_mark = high_water_mark
        self._max_message_bytes = max_message_bytes
        self._reply_envelope_max_bytes = max_message_bytes - _REPLY_FRAME_OVERHEAD
        self._server_key = credentials.server_key
        self._public_key = credentials.public_key
        self._secret_key = credentials.secret_key
        try:
            reply_private_key = PrivateKey(z85.decode(credentials.secret_key))
        except (TypeError, ValueError, CryptoError) as exc:
            raise ValueError("client CURVE secret key cannot decrypt replies") from exc
        if bytes(reply_private_key.public_key) != z85.decode(credentials.public_key):
            raise ValueError("client CURVE public and secret keys do not match")
        self._reply_box = SealedBox(reply_private_key)
        self._owner_pid = os.getpid()
        self._owner_thread = threading.get_ident()
        self._closed = False
        self._close_pending = False
        self._inflight = False
        self._last_uncertain_message_id = None
        self._socket_message_ids = set()
        self._socket_retirement_pending = False
        self._context = None
        self._context_lease = None
        self._socket = None
        self._receiver = None
        try:
            if context_pool is None:
                self._context = zmq.Context()
            else:
                self._context_lease = context_pool.acquire()
                self._context = self._context_lease.context
            self._open_socket()
        except BaseException:
            try:
                self.close()
            except BaseException:
                raise ServiceTransportStartupCleanupError(self) from None
            raise

    def request(self, request: WireEnvelope, *, timeout: float) -> WireEnvelope:
        """Send one request and return only its correctly bound service reply."""

        self._check_thread()
        if self._closed or self._close_pending:
            raise RuntimeError("client is closed")
        if self._inflight:
            raise RuntimeError("only one request may be in flight")
        validate_request(request)
        message_id = request.header.message_id
        if message_id == self._last_uncertain_message_id:
            raise ValueError("message_id cannot be reused after an uncertain outcome")
        if message_id in self._socket_message_ids:
            raise ValueError("message_id cannot be reused on the current connection")
        encoded_request = encode_envelope(request, max_bytes=self._max_message_bytes)
        deadline = _deadline(timeout)
        self._inflight = True
        sent = False
        try:
            if len(self._socket_message_ids) >= _MAX_MESSAGE_IDS_PER_SOCKET:
                self._retire_socket()
                self._socket_message_ids.clear()
            self._ensure_socket()
            try:
                writable = self._socket.poll(_remaining_ms(deadline), zmq.POLLOUT)
                if writable == 0:
                    raise RequestNotSentError(message_id, "send_timeout")
                self._socket.send(encoded_request, flags=zmq.NOBLOCK)
                sent = True
                self._socket_message_ids.add(message_id)
            except zmq.Again as exc:
                raise RequestNotSentError(message_id, "send_not_queued") from exc
            except zmq.ZMQError:
                self._socket_message_ids.discard(message_id)
                raise

            while True:
                remaining = _remaining_ms(deadline)
                if remaining == 0:
                    raise RequestOutcomeUnknownError(message_id, "response_timeout")
                try:
                    readable = self._socket.poll(remaining, zmq.POLLIN)
                except zmq.ZMQError as exc:
                    raise RequestOutcomeUnknownError(message_id, "receive_transport_error") from exc
                if readable == 0:
                    raise RequestOutcomeUnknownError(message_id, "response_timeout")
                frames = self._receiver.receive(1)
                if frames is None or len(frames) != 1:
                    continue
                raw_reply = bytes(frames[0])
                if (
                    len(raw_reply) > self._max_message_bytes
                    or not raw_reply.startswith(_REPLY_FRAME_PREFIX)
                    or len(raw_reply) < _REPLY_FRAME_OVERHEAD
                ):
                    continue
                try:
                    raw_reply = self._reply_box.decrypt(raw_reply[len(_REPLY_FRAME_PREFIX) :])
                except (CryptoError, ValueError):
                    continue
                try:
                    reply = decode_envelope(raw_reply, max_bytes=self._reply_envelope_max_bytes)
                except WireValidationError:
                    continue
                if reply.header.correlation_id != request.header.message_id:
                    continue
                try:
                    validate_reply(reply, request, expected_peer=self._identity)
                except WireValidationError as exc:
                    raise RequestOutcomeUnknownError(message_id, "reply_validation_failed") from exc
                return reply
        except RequestOutcomeUnknownError:
            self._last_uncertain_message_id = message_id
            with suppress(zmq.ZMQError):
                self._retire_socket()
            self._socket_message_ids.clear()
            raise
        except zmq.ZMQError as exc:
            if sent:
                self._last_uncertain_message_id = message_id
                with suppress(zmq.ZMQError):
                    self._retire_socket()
                self._socket_message_ids.clear()
                raise RequestOutcomeUnknownError(message_id, "receive_transport_error") from exc
            raise
        except Exception as exc:
            if sent:
                self._last_uncertain_message_id = message_id
                with suppress(zmq.ZMQError):
                    self._retire_socket()
                self._socket_message_ids.clear()
                raise RequestOutcomeUnknownError(message_id, "reply_processing_error") from exc
            raise
        finally:
            self._inflight = False

    def close(self) -> None:
        """Close owned resources in order; retry a failed stage on this thread."""

        if self._closed:
            return
        self._check_thread()
        self._close_pending = True
        self._retire_socket()
        lease = self._context_lease
        if lease is not None:
            lease.close()
            self._context_lease = None
            self._context = None
        else:
            context = self._context
            if context is not None:
                context.term()
                self._context = None
        self._closed = True
        self._close_pending = False

    def _open_socket(self) -> None:
        context = self._context
        if context is None:
            raise ServiceTransportError("client context is unavailable")
        socket = context.socket(zmq.DEALER)
        self._socket = socket
        self._receiver = None
        self._socket_retirement_pending = True
        _configure_socket(socket, self._high_water_mark, self._max_message_bytes)
        socket.setsockopt(zmq.IMMEDIATE, 1)
        socket.setsockopt(zmq.IDENTITY, ("bt-api-v2-" + uuid.uuid4().hex).encode("ascii"))
        socket.curve_serverkey = self._server_key
        socket.curve_publickey = self._public_key
        socket.curve_secretkey = self._secret_key
        socket.connect(self._endpoint)
        self._receiver = _BoundedMultipartReceiver(socket)
        self._socket_retirement_pending = False

    def _ensure_socket(self) -> None:
        if self._socket_retirement_pending:
            raise ServiceTransportError("client socket cleanup is pending; call close() to retry")
        if self._socket is None:
            self._open_socket()

    def _retire_socket(self) -> None:
        socket = self._socket
        if socket is None:
            self._receiver = None
            self._socket_retirement_pending = False
            return
        self._socket_retirement_pending = True
        socket.close(linger=0)
        self._socket = None
        self._receiver = None
        self._socket_retirement_pending = False

    def _check_thread(self) -> None:
        if os.getpid() != self._owner_pid:
            raise RuntimeError("ZMQ client cannot cross a process boundary")
        if threading.get_ident() != self._owner_thread:
            raise RuntimeError("ZMQ client must be used and closed by its owning thread")


def _validate_endpoint(endpoint: str) -> None:
    if type(endpoint) is not str or not endpoint.startswith("tcp://"):
        raise ServiceTransportError("service v2 requires CURVE-authenticated TCP endpoints")


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
    if max_message_bytes <= _REPLY_FRAME_OVERHEAD:
        raise ValueError("max_message_bytes is too small for sealed reply framing")


def _configure_socket(socket: zmq.Socket, high_water_mark: int, max_message_bytes: int) -> None:
    socket.setsockopt(zmq.LINGER, 0)
    socket.setsockopt(zmq.RCVHWM, high_water_mark)
    socket.setsockopt(zmq.SNDHWM, high_water_mark)
    # ROUTER adds the bounded routing identity to the local multipart message.
    # Keep that framing allowance at libzmq's layer; application frames are
    # still checked against max_message_bytes before decoding or decryption.
    socket.setsockopt(zmq.MAXMSGSIZE, max_message_bytes + _MAX_ROUTER_ID_BYTES)


def _copy_principals(principals: Mapping[bytes, str]) -> Mapping[bytes, str]:
    if not isinstance(principals, Mapping):
        raise ValueError("principals must map CURVE Z85 public keys to trusted references")
    copied = {}
    for public_key, principal_ref in principals.items():
        if not isinstance(public_key, bytes) or len(public_key) != 40:
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


def _handler_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("handler result must be a mapping")
    payload = dict(value)
    if set(payload) != {"ok", "code", "result"}:
        raise ValueError("handler result has an invalid shape")
    if type(payload["ok"]) is not bool:
        raise ValueError("handler result ok must be boolean")
    code = payload["code"]
    if type(code) is not str or _CODE_PATTERN.fullmatch(code) is None:
        raise ValueError("handler result code must be a finite code token")
    if not isinstance(payload["result"], Mapping):
        raise ValueError("handler result result must be a mapping")
    payload["result"] = dict(payload["result"])
    return payload


def _make_reply(
    identity: WireIdentity,
    request: WireEnvelope,
    payload: Mapping[str, Any],
) -> WireEnvelope:
    request_header = request.header
    header = WireHeader(
        protocol_version=WIRE_PROTOCOL_VERSION,
        kind=WireMessageKind.REPLY,
        message_id=uuid.uuid4().hex,
        correlation_id=request_header.message_id,
        identity=identity,
        scope=request_header.scope,
        operation=request_header.operation,
        schema_id=request_header.schema_id,
        schema_version=request_header.schema_version,
        sent_at_utc=datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        owner_epoch=request_header.owner_epoch,
    )
    return WireEnvelope(header=header, payload=payload)


def service_reply_fits(
    identity: WireIdentity,
    request: WireEnvelope,
    payload: Mapping[str, Any],
    *,
    max_message_bytes: int,
) -> bool:
    """Return whether a normal SDK reply fits the configured sealed-frame budget.

    The payload must be the complete ``ok``/``code``/``result`` wrapper accepted
    from a service handler. This performs the same envelope encoding and budget
    calculation as the server without creating or using transport resources.
    """

    _validate_limits(DEFAULT_HIGH_WATER_MARK, max_message_bytes)
    if type(identity) is not WireIdentity or identity.role is not WireRole.SERVICE:
        raise ValueError("service identity must have the service role")
    if type(request) is not WireEnvelope:
        raise ValueError("request must be a WireEnvelope")
    validate_request(request)

    reply = _make_reply(identity, request, _handler_payload(payload))
    try:
        encode_envelope(reply, max_bytes=max_message_bytes - _REPLY_FRAME_OVERHEAD)
    except WireValidationError as exc:
        if exc.code is WireErrorCode.MESSAGE_TOO_LARGE:
            return False
        raise
    return True


def service_reply_result_budget(
    identity: WireIdentity,
    request: WireEnvelope,
    *,
    max_message_bytes: int,
) -> int:
    """Return the exact JSON-byte budget available to a reply ``result``.

    The budget uses the same reply header construction, canonical envelope
    encoder, and sealed-frame overhead as :func:`service_reply_fits`. Replacing
    the empty result object's two JSON bytes with a serialized result is the
    only change to the envelope body, so the returned value is an exact limit,
    not an estimate. A negative result means even an empty successful result
    cannot fit the configured frame.
    """

    _validate_limits(DEFAULT_HIGH_WATER_MARK, max_message_bytes)
    if type(identity) is not WireIdentity or identity.role is not WireRole.SERVICE:
        raise ValueError("service identity must have the service role")
    if type(request) is not WireEnvelope:
        raise ValueError("request must be a WireEnvelope")
    validate_request(request)

    empty_payload = _handler_payload({"ok": True, "code": "OK", "result": {}})
    empty_reply = _make_reply(identity, request, empty_payload)
    encoded_empty_reply = encode_envelope(empty_reply, max_bytes=MAX_WIRE_MESSAGE_BYTES)
    return (
        max_message_bytes
        - _REPLY_FRAME_OVERHEAD
        - len(encoded_empty_reply)
        + 2  # The empty result mapping serializes to exactly "{}".
    )


def _seal_reply(encoded_reply: bytes, recipient_key: PublicKey) -> bytes:
    sealed = SealedBox(recipient_key).encrypt(encoded_reply)
    if len(sealed) != len(encoded_reply) + bindings.crypto_box_SEALBYTES:
        raise ServiceTransportError("sealed reply length is invalid")
    return _REPLY_FRAME_PREFIX + sealed


def _deadline(timeout: float) -> float:
    if type(timeout) not in (float, int) or not math.isfinite(timeout) or timeout < 0:
        raise ValueError("timeout must be a finite non-negative number of seconds")
    return time.monotonic() + timeout


def _remaining_ms(deadline: float) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 0
    if remaining >= _MAX_SOCKET_OPTION_INT / 1000:
        return _MAX_SOCKET_OPTION_INT
    return max(1, int(math.ceil(remaining * 1000)))
