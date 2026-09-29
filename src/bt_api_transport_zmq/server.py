"""Fail-closed authenticated ROUTER command boundary."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Optional, Protocol

import zmq
from zmq.auth.thread import ThreadAuthenticator
from zmq.utils import z85

from .wire import (
    MAX_MESSAGE_BYTES,
    WireChannel,
    WireError,
    WireMessage,
    decode_message,
    encode_message,
)


class TransportSecurityError(RuntimeError):
    """A bind/connect security policy is insufficient for the requested endpoint."""


class BackpressureError(RuntimeError):
    """A bounded ZeroMQ socket cannot accept another message immediately."""


@dataclass(frozen=True)
class CurveServerCredentials:
    """CurveZMQ server keys for an authenticated encrypted remote socket."""

    public_key: bytes
    secret_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_z85_key(self.public_key, "server public key")
        _require_z85_key(self.secret_key, "server secret key")


@dataclass(frozen=True)
class CurveClientCredentials:
    """CurveZMQ client/server keys for an authenticated encrypted remote socket."""

    server_key: bytes
    public_key: bytes
    secret_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_z85_key(self.server_key, "server key")
        _require_z85_key(self.public_key, "client public key")
        _require_z85_key(self.secret_key, "client secret key")


@dataclass(frozen=True)
class RemotePrincipalGrant:
    """Server-owned ACL binding an identity to gateway scopes and command kinds.

    Account/strategy IDs and their gateway scope labels are kept in one
    immutable grant because scope labels are opaque application values; the
    transport does not infer them from IDs or parse them from client text.
    Every supplied identity/scope claim is checked against this grant.
    """

    principal_id: str
    account_id: str
    strategy_id: str
    account_scope: str
    strategy_scope: str
    allowed_kinds: frozenset[str]

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (
                self.principal_id,
                self.account_id,
                self.strategy_id,
                self.account_scope,
                self.strategy_scope,
            )
        ):
            raise ValueError(
                "remote principal, identity, account scope, and strategy scope are required"
            )
        if (
            not isinstance(self.allowed_kinds, frozenset)
            or not self.allowed_kinds
            or any(not isinstance(kind, str) or not kind.strip() for kind in self.allowed_kinds)
        ):
            raise ValueError("remote principal allowed_kinds must be a non-empty frozenset")


class PrincipalAuthenticator(Protocol):
    """Derive a server-trusted principal from ZMQ peer identity and request."""

    def __call__(self, peer_identity: bytes, message: WireMessage) -> Any:
        """Return a server-derived principal or raise to reject the peer."""


class CommandHandler(Protocol):
    """Perform server-side admission; it owns execution and risk decisions."""

    def __call__(self, principal: Any, message: WireMessage) -> Mapping[str, Any]:
        """Return a redacted result mapping after handling one durable command."""


class ZmqCommandServer:
    """A bounded ROUTER server with remote ZAP identity and command ACL checks.

    Remote TCP binds require an explicit CURVE client-key ACL. The server
    starts a ZAP authenticator for exactly those keys, then uses the resulting
    ``User-Id`` message metadata (never the client-chosen ROUTER identity) to
    select a fixed account/strategy/kind grant before calling the handler.
    Local endpoints retain the injected authenticator for fake/in-process use.
    """

    def __init__(
        self,
        endpoint: str,
        authenticator: PrincipalAuthenticator,
        handler: CommandHandler,
        *,
        bind: bool = True,
        context: Optional[zmq.Context] = None,  # noqa: UP045 -- package supports Python 3.9.
        curve_credentials: Optional[CurveServerCredentials] = None,  # noqa: UP045 -- Python 3.9.
        allow_remote: bool = False,
        remote_principals: Optional[Mapping[bytes, RemotePrincipalGrant]] = None,  # noqa: UP045 -- Python 3.9.
        high_water_mark: int = 256,
        max_message_bytes: int = MAX_MESSAGE_BYTES,
    ) -> None:
        if not endpoint:
            raise ValueError("endpoint is required")
        if high_water_mark <= 0 or max_message_bytes <= 0:
            raise ValueError("queue and byte limits must be positive")
        if not callable(authenticator) or not callable(handler):
            raise ValueError("authenticator and handler are required")
        remote_endpoint = not is_loopback_or_ipc(endpoint)
        _validate_endpoint_security(endpoint, curve_credentials, allow_remote, remote_principals)
        if not remote_endpoint and remote_principals is not None:
            raise TransportSecurityError("remote client ACL cannot be used on a local endpoint")
        self.endpoint = endpoint
        self._authenticator = authenticator
        self._handler = handler
        self._max_message_bytes = max_message_bytes
        self._context = context or zmq.Context.instance()
        self._remote_principals = _validated_remote_principals(remote_principals)
        self._zap_authenticator = None
        self._closed = False
        self._socket = self._context.socket(zmq.ROUTER)
        self._socket.setsockopt(zmq.LINGER, 0)
        self._socket.setsockopt(zmq.RCVHWM, high_water_mark)
        self._socket.setsockopt(zmq.SNDHWM, high_water_mark)
        if curve_credentials is not None:
            self._socket.curve_secretkey = curve_credentials.secret_key
            self._socket.curve_publickey = curve_credentials.public_key
            self._socket.curve_server = True
        if remote_endpoint:
            self._socket.zap_domain = _REMOTE_ZAP_DOMAIN.encode("ascii")
            peer_registry = _CurvePeerRegistry(self._remote_principals)
            zap_authenticator = ThreadAuthenticator(self._context)
            zap_authenticator.configure_curve_callback(
                domain=_REMOTE_ZAP_DOMAIN,
                credentials_provider=peer_registry,
            )
            self._zap_authenticator = zap_authenticator
            try:
                zap_authenticator.start()
                if bind:
                    self._socket.bind(endpoint)
                else:
                    self._socket.connect(endpoint)
            except Exception:
                if self._zap_authenticator is not None:
                    self._zap_authenticator.stop()
                    self._zap_authenticator = None
                self._socket.close(linger=0)
                raise
        elif bind:
            self._socket.bind(endpoint)
        else:
            self._socket.connect(endpoint)

    def serve_once(self, timeout_ms: int = 0) -> bool:
        """Serve at most one command and return false when no command arrived."""
        if timeout_ms < 0:
            raise ValueError("timeout_ms must be non-negative")
        if self._socket.poll(timeout_ms) == 0:
            return False
        frames = self._socket.recv_multipart(copy=False)
        if len(frames) != 2:
            return False
        peer_identity = bytes(frames[0])
        raw = bytes(frames[1])
        authenticated_user_id = _message_user_id(frames[1]) if self._remote_principals else None
        response = self._handle(peer_identity, raw, authenticated_user_id)
        try:
            self._socket.send_multipart(
                [
                    peer_identity,
                    encode_message(response, max_message_bytes=self._max_message_bytes),
                ],
                flags=zmq.NOBLOCK,
            )
        except zmq.Again as exc:
            raise BackpressureError(
                "response queue is full; command outcome requires reconciliation"
            ) from exc
        return True

    def close(self) -> None:
        """Close only the owned socket, never the caller-shared context."""
        if self._closed:
            return
        self._closed = True
        if self._zap_authenticator is not None:
            self._zap_authenticator.stop()
            self._zap_authenticator = None
        self._socket.close(linger=0)

    def _handle(
        self,
        peer_identity: bytes,
        raw: bytes,
        authenticated_user_id: Optional[bytes] = None,  # noqa: UP045 -- Python 3.9.
    ) -> WireMessage:
        try:
            message = decode_message(raw, max_message_bytes=self._max_message_bytes)
            if message.channel not in {WireChannel.COMMAND, WireChannel.RECONCILE}:
                raise WireError("server only accepts command or reconcile messages")
            if self._remote_principals is not None:
                principal = _authorize_remote_message(
                    self._remote_principals, authenticated_user_id, message
                )
            else:
                principal = self._authenticator(peer_identity, message)
            outcome = self._handler(principal, message)
            if not isinstance(outcome, Mapping):
                raise WireError("command handler must return an object")
            payload = {"accepted": True, "outcome": dict(outcome), "status": "handled"}
        except Exception as exc:
            # Error detail stays bounded and never copies a likely secret into a reply.
            message = _best_effort_message(raw, self._max_message_bytes)
            payload = {
                "accepted": False,
                "error_code": _safe_error_code(exc),
                "status": "rejected",
            }
        return WireMessage(
            message_id=message.message_id,
            channel=WireChannel.RESPONSE,
            scope=message.scope,
            sequence=message.sequence,
            sent_at=time.time(),
            payload=payload,
        )


def is_loopback_or_ipc(endpoint: str) -> bool:
    """Recognize conservative local ZMQ endpoint forms."""
    if not isinstance(endpoint, str) or not endpoint:
        return False
    if endpoint.startswith("ipc://") or endpoint.startswith("inproc://"):
        return True
    if endpoint.startswith("tcp://"):
        host = endpoint[len("tcp://") :].rsplit(":", 1)[0].strip("[]")
        return host in {"127.0.0.1", "::1"}
    return False


def _validate_endpoint_security(
    endpoint: str,
    curve_credentials: Optional[CurveServerCredentials],  # noqa: UP045 -- Python 3.9.
    allow_remote: bool,
    remote_principals: Optional[Mapping[bytes, RemotePrincipalGrant]],  # noqa: UP045 -- Python 3.9.
) -> None:
    if is_loopback_or_ipc(endpoint):
        return
    if not allow_remote:
        raise TransportSecurityError("non-local endpoint requires allow_remote=True")
    if curve_credentials is None:
        raise TransportSecurityError("remote endpoint requires CurveZMQ credentials")
    if not remote_principals:
        raise TransportSecurityError("remote endpoint requires an explicit client principal ACL")


def _require_z85_key(value: bytes, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != 40:
        raise ValueError(f"CurveZMQ {label} must be a 40-byte Z85 key")
    try:
        z85.decode(value)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"CurveZMQ {label} is not valid Z85") from exc


def _validated_remote_principals(
    remote_principals: Optional[Mapping[bytes, RemotePrincipalGrant]],  # noqa: UP045 -- Python 3.9.
) -> Optional[Mapping[bytes, RemotePrincipalGrant]]:  # noqa: UP045 -- Python 3.9.
    if remote_principals is None:
        return None
    if not isinstance(remote_principals, Mapping) or not remote_principals:
        raise TransportSecurityError("remote endpoint requires an explicit client principal ACL")
    copied = {}
    for client_key, grant in remote_principals.items():
        _require_z85_key(client_key, "client public key")
        if not isinstance(grant, RemotePrincipalGrant):
            raise TransportSecurityError("remote client ACL entries must be RemotePrincipalGrant")
        copied[client_key] = grant
    return MappingProxyType(copied)


_REMOTE_ZAP_DOMAIN = "bt-api-transport-zmq-v1"


class _CurvePeerRegistry:
    """ZAP callback which admits only public keys present in the server ACL."""

    def __init__(self, principals: Mapping[bytes, RemotePrincipalGrant]) -> None:
        self._principals = principals

    def callback(self, domain: str, client_key: bytes) -> bool:
        return domain == _REMOTE_ZAP_DOMAIN and client_key in self._principals


def _message_user_id(frame: zmq.Frame) -> Optional[bytes]:  # noqa: UP045 -- Python 3.9.
    """Read ZAP-authenticated metadata from the actual payload frame."""
    try:
        user_id = frame["User-Id"]
    except (KeyError, zmq.ZMQError):
        return None
    if isinstance(user_id, str):
        try:
            user_id = user_id.encode("ascii")
        except UnicodeEncodeError:
            return None
    if not isinstance(user_id, bytes) or not user_id:
        return None
    return user_id


def _authorize_remote_message(
    principals: Mapping[bytes, RemotePrincipalGrant],
    authenticated_user_id: Optional[bytes],  # noqa: UP045 -- Python 3.9.
    message: WireMessage,
) -> RemotePrincipalGrant:
    if not authenticated_user_id:
        raise TransportSecurityError("remote ZAP peer identity is required")
    grant = principals.get(authenticated_user_id)
    if grant is None:
        raise TransportSecurityError("remote peer has no principal ACL")
    if message.scope != grant.strategy_scope:
        raise TransportSecurityError("remote principal strategy scope is not authorized")

    payload = message.payload
    command = payload.get("command")
    if command is not None:
        if not isinstance(command, Mapping):
            raise TransportSecurityError("remote command envelope is invalid")
        kind = command.get("kind")
    else:
        kind = payload.get("kind")

    _validate_identity_claims(payload, grant)
    if "kind" in payload and payload["kind"] != kind:
        raise TransportSecurityError("remote command kind claims disagree")
    if not isinstance(kind, str) or kind not in grant.allowed_kinds:
        raise TransportSecurityError("remote command kind is not authorized")
    return grant


def _validate_identity_claims(value: Any, grant: RemotePrincipalGrant) -> None:
    """Reject nested account/strategy identity or scope claims outside server policy."""
    if isinstance(value, Mapping):
        expected = {
            "account_id": grant.account_id,
            "strategy_id": grant.strategy_id,
            "account_scope": grant.account_scope,
            "strategy_scope": grant.strategy_scope,
        }
        aliases = {
            "accountid": "account_id",
            "strategyid": "strategy_id",
            "accountscope": "account_scope",
            "strategyscope": "strategy_scope",
        }
        for key, nested in value.items():
            normalized = key.lower().replace("-", "_") if isinstance(key, str) else key
            normalized = aliases.get(normalized, normalized)
            if normalized in expected and nested != expected[normalized]:
                raise TransportSecurityError(
                    f"remote principal {normalized} claim is not authorized"
                )
            _validate_identity_claims(nested, grant)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _validate_identity_claims(nested, grant)


def _best_effort_message(raw: bytes, max_message_bytes: int) -> WireMessage:
    try:
        return decode_message(raw, max_message_bytes=max_message_bytes)
    except Exception:
        return WireMessage(
            message_id="invalid-request",
            channel=WireChannel.COMMAND,
            scope="invalid",
            sequence=0,
            sent_at=time.time(),
            payload={},
        )


def _safe_error_code(exc: Exception) -> str:
    if isinstance(exc, WireError):
        return "WIRE_INVALID"
    if isinstance(exc, TransportSecurityError):
        return "TRANSPORT_SECURITY_REJECTED"
    return "COMMAND_REJECTED"
