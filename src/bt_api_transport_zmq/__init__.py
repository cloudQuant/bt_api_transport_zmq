"""Provider-neutral, fail-closed ZMQ transport contracts.

This package intentionally has no dependency on ``bt_api_py`` or a provider
adapter.  A gateway integrates it through the injected authenticator and
command handler, preserving one authoritative execution/risk/account owner.
"""

from .client import CommandOutcomeUnknown, ZmqCommandClient
from .events import EventReplayBuffer, ReplayGapError, SequenceObservation, SequenceTracker
from .server import (
    BackpressureError,
    CurveClientCredentials,
    CurveServerCredentials,
    RemotePrincipalGrant,
    TransportSecurityError,
    ZmqCommandServer,
    is_loopback_or_ipc,
)
from .wire import (
    MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    WireChannel,
    WireError,
    WireMessage,
    decode_message,
    encode_message,
)

__all__ = [
    "BackpressureError",
    "CommandOutcomeUnknown",
    "CurveClientCredentials",
    "CurveServerCredentials",
    "EventReplayBuffer",
    "MAX_MESSAGE_BYTES",
    "PROTOCOL_VERSION",
    "ReplayGapError",
    "RemotePrincipalGrant",
    "SequenceObservation",
    "SequenceTracker",
    "TransportSecurityError",
    "WireChannel",
    "WireError",
    "WireMessage",
    "ZmqCommandClient",
    "ZmqCommandServer",
    "decode_message",
    "encode_message",
    "is_loopback_or_ipc",
]
