from __future__ import annotations

import math

import pytest

from bt_api_transport_zmq import (
    EventReplayBuffer,
    ReplayGapError,
    SequenceTracker,
    WireChannel,
    WireError,
    WireMessage,
    decode_message,
    encode_message,
)


def _event(sequence: int, scope: str = "account-a") -> WireMessage:
    return WireMessage(
        message_id=f"event-{scope}-{sequence}",
        channel=WireChannel.EVENT,
        scope=scope,
        sequence=sequence,
        sent_at=1.0,
        payload={"kind": "order_update"},
    )


def test_wire_round_trip_is_exact_and_rejects_unknown_schema_fields() -> None:
    message = _event(1)
    assert decode_message(encode_message(message)) == message

    encoded = (
        b'{"channel":"event","extra":true,"message_id":"x","payload":{},'
        b'"protocol_version":1,"scope":"a","sent_at":1,"sequence":0}'
    )
    with pytest.raises(WireError, match="invalid envelope fields"):
        decode_message(encoded)


@pytest.mark.parametrize(
    "payload",
    (
        {"api_key": "not-allowed"},
        {"nested": {"password": "not-allowed"}},
        {"value": math.nan},
        {"value": math.inf},
    ),
)
def test_wire_rejects_secrets_and_nonfinite_values(payload: dict) -> None:
    with pytest.raises(WireError):
        WireMessage("x", WireChannel.COMMAND, "scope", 1, 1.0, payload)


def test_sequence_tracker_reports_gap_without_inventing_facts() -> None:
    tracker = SequenceTracker()
    assert tracker.observe(_event(1)).status == "initial"
    assert tracker.observe(_event(3)).status == "gap"
    assert tracker.observe(_event(2)).status == "regression"
    assert tracker.observe(_event(3)).status == "duplicate"


def test_bounded_replay_requires_reconciliation_after_eviction() -> None:
    replay = EventReplayBuffer(capacity_per_scope=2)
    replay.append(_event(1))
    replay.append(_event(2))
    replay.append(_event(3))

    assert [item.sequence for item in replay.replay_after("account-a", 1)] == [2, 3]
    with pytest.raises(ReplayGapError):
        replay.replay_after("account-a", 0)

    with pytest.raises(ValueError, match="increase"):
        replay.append(_event(3))
