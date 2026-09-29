"""Explicit request/reconciliation client with no write retry loop."""

from __future__ import annotations

from typing import Optional

import zmq

from .server import CurveClientCredentials, TransportSecurityError, is_loopback_or_ipc
from .wire import (
    MAX_MESSAGE_BYTES,
    WireChannel,
    WireMessage,
    decode_message,
    encode_message,
)


class CommandOutcomeUnknownError(TimeoutError):
    """A command may have reached the server; callers must reconcile its ID."""

    def __init__(self, message_id: str) -> None:
        super().__init__("command outcome is unknown; reconcile message id " + message_id)
        self.message_id = message_id


class ZmqCommandClient:
    """A bounded DEALER client that never auto-resends an uncertain write."""

    def __init__(
        self,
        endpoint: str,
        *,
        context: Optional[zmq.Context] = None,  # noqa: UP045 -- package supports Python 3.9.
        curve_credentials: Optional[CurveClientCredentials] = None,  # noqa: UP045 -- Python 3.9.
        allow_remote: bool = False,
        high_water_mark: int = 256,
        max_message_bytes: int = MAX_MESSAGE_BYTES,
    ) -> None:
        if not endpoint:
            raise ValueError("endpoint is required")
        if high_water_mark <= 0 or max_message_bytes <= 0:
            raise ValueError("queue and byte limits must be positive")
        if not is_loopback_or_ipc(endpoint):
            if not allow_remote:
                raise TransportSecurityError("non-local endpoint requires allow_remote=True")
            if curve_credentials is None:
                raise TransportSecurityError("remote endpoint requires CurveZMQ credentials")
        self._max_message_bytes = max_message_bytes
        self._pending: dict[str, WireMessage] = {}
        self._socket = (context or zmq.Context.instance()).socket(zmq.DEALER)
        self._socket.setsockopt(zmq.LINGER, 0)
        self._socket.setsockopt(zmq.RCVHWM, high_water_mark)
        self._socket.setsockopt(zmq.SNDHWM, high_water_mark)
        if curve_credentials is not None:
            self._socket.curve_serverkey = curve_credentials.server_key
            self._socket.curve_publickey = curve_credentials.public_key
            self._socket.curve_secretkey = curve_credentials.secret_key
        self._socket.connect(endpoint)

    @property
    def pending_message_ids(self) -> tuple[str, ...]:
        """IDs with an uncertain outcome; this is not a retry queue."""
        return tuple(self._pending)

    def request(self, message: WireMessage, timeout_ms: int) -> WireMessage:
        """Send one command or reconciliation request and await its correlated response."""
        if timeout_ms < 0:
            raise ValueError("timeout_ms must be non-negative")
        if message.channel not in {WireChannel.COMMAND, WireChannel.RECONCILE}:
            raise ValueError("client requests must be command or reconcile messages")
        try:
            self._socket.send(
                encode_message(message, max_message_bytes=self._max_message_bytes),
                flags=zmq.NOBLOCK,
            )
        except zmq.Again as exc:
            self._pending[message.message_id] = message
            raise CommandOutcomeUnknown(message.message_id) from exc
        if self._socket.poll(timeout_ms) == 0:
            self._pending[message.message_id] = message
            raise CommandOutcomeUnknown(message.message_id)
        response = decode_message(self._socket.recv(), max_message_bytes=self._max_message_bytes)
        if (
            response.channel is not WireChannel.RESPONSE
            or response.message_id != message.message_id
        ):
            self._pending[message.message_id] = message
            raise CommandOutcomeUnknown(message.message_id)
        self._pending.pop(message.message_id, None)
        return response

    def close(self) -> None:
        """Close the client socket without closing a shared ZMQ context."""
        self._socket.close(linger=0)


# The concise public name is the protocol outcome, while the implementation
# class follows normal Python exception naming for introspection and tooling.
CommandOutcomeUnknown = CommandOutcomeUnknownError
