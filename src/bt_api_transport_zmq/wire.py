"""Strict versioned JSON envelopes for the transport boundary."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 1_000_000
_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "passphrase",
    "password",
    "private_key",
    "secret",
    "token",
)


class WireError(ValueError):
    """A transport message is malformed, oversized, or unsafe to serialize."""


class WireChannel(str, Enum):
    """The transport request class, which never implies an execution result."""

    COMMAND = "command"
    RESPONSE = "response"
    EVENT = "event"
    RECONCILE = "reconcile"


@dataclass(frozen=True)
class WireMessage:
    """An immutable, redacted, versioned application envelope.

    ``scope`` identifies a server-defined routing stream.  It is not treated as
    an authorization claim; server-side code must derive authorization from the
    authenticated peer and pass it to the gateway command boundary.
    """

    message_id: str
    channel: WireChannel
    scope: str
    sequence: int
    sent_at: float
    payload: Mapping[str, Any]
    protocol_version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.message_id, str) or not self.message_id.strip():
            raise WireError("message_id is required")
        if not isinstance(self.scope, str) or not self.scope.strip():
            raise WireError("scope is required")
        if not isinstance(self.channel, WireChannel):
            raise WireError("channel must be a WireChannel")
        if self.protocol_version != PROTOCOL_VERSION:
            raise WireError("unsupported protocol version")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
            raise WireError("sequence must be a non-negative integer")
        if not isinstance(self.sent_at, (int, float)) or isinstance(self.sent_at, bool):
            raise WireError("sent_at must be a finite number")
        if not math.isfinite(float(self.sent_at)):
            raise WireError("sent_at must be finite")
        if not isinstance(self.payload, Mapping):
            raise WireError("payload must be an object")
        _validate_json_value(self.payload)

    def to_dict(self) -> dict[str, Any]:
        """Return the sole supported wire projection."""
        return {
            "channel": self.channel.value,
            "message_id": self.message_id,
            "payload": dict(self.payload),
            "protocol_version": self.protocol_version,
            "scope": self.scope,
            "sent_at": self.sent_at,
            "sequence": self.sequence,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WireMessage:
        """Parse a message without silently accepting unknown fields."""
        required = {
            "channel",
            "message_id",
            "payload",
            "protocol_version",
            "scope",
            "sent_at",
            "sequence",
        }
        supplied = set(value)
        if supplied != required:
            unexpected = sorted(supplied - required)
            missing = sorted(required - supplied)
            detail = (
                "unknown=" + ",".join(unexpected) if unexpected else "missing=" + ",".join(missing)
            )
            raise WireError("invalid envelope fields: " + detail)
        try:
            channel = WireChannel(str(value["channel"]))
        except ValueError as exc:
            raise WireError("unsupported channel") from exc
        return cls(
            message_id=value["message_id"],
            channel=channel,
            scope=value["scope"],
            sequence=value["sequence"],
            sent_at=value["sent_at"],
            payload=value["payload"],
            protocol_version=value["protocol_version"],
        )


def encode_message(message: WireMessage, *, max_message_bytes: int = MAX_MESSAGE_BYTES) -> bytes:
    """Encode one validated message using deterministic compact JSON."""
    if max_message_bytes <= 0:
        raise ValueError("max_message_bytes must be positive")
    try:
        encoded = json.dumps(
            message.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:  # defensive: dataclass validation ran already
        raise WireError("message is not JSON serializable") from exc
    if len(encoded) > max_message_bytes:
        raise WireError("message exceeds configured byte limit")
    return encoded


def decode_message(value: bytes, *, max_message_bytes: int = MAX_MESSAGE_BYTES) -> WireMessage:
    """Decode untrusted bytes into the exact current envelope schema."""
    if not isinstance(value, bytes):
        raise WireError("wire payload must be bytes")
    if len(value) > max_message_bytes:
        raise WireError("message exceeds configured byte limit")
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WireError("invalid JSON envelope") from exc
    if not isinstance(decoded, Mapping):
        raise WireError("wire envelope must be an object")
    return WireMessage.from_dict(decoded)


def _validate_json_value(value: Any, path: str = "") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise WireError("non-finite number at " + (path or "payload"))
        return
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise WireError("object keys must be strings")
            normalized = key.lower().replace("-", "_")
            if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
                raise WireError("secret-shaped field is forbidden at " + (path + key))
            _validate_json_value(nested, path + key + ".")
        return
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _validate_json_value(nested, path + str(index) + ".")
        return
    raise WireError("unsupported JSON value at " + (path or "payload"))
