"""Iteration 60 G2: receiver-side drop of stale frames after a runtime revocation.

Offline CURVE over loopback. A frame already queued in the receiver's socket
when the publisher is rebuilt cannot be recalled by the publisher; the
receiver drops it once it has learned of the revocation, and after a re-grant
accepts only frames strictly after the re-grant cut.
"""

from __future__ import annotations

import time

import pytest
import zmq
from test_market_v2_topic_filter import _IDENTITY, _SCOPE, _curve_client, _event, _key

from bt_api_transport_zmq.market_v2 import ZmqMarketPublisher, ZmqMarketSubscriber
from bt_api_transport_zmq.server import CurveServerCredentials


def _pair():
    server_public, server_secret = zmq.curve_keypair()
    public, credentials = _curve_client(server_public)
    key = _key("REVOKE-RT")
    publisher = ZmqMarketPublisher(
        "tcp://127.0.0.1:*",
        _IDENTITY,
        _SCOPE,
        {public: "principal"},
        credentials=CurveServerCredentials(server_public, server_secret),
        wire_version=2,
        stream_grants={"principal": {key.stream_id}},
    )
    subscriber = ZmqMarketSubscriber(
        publisher.endpoint,
        _IDENTITY,
        _SCOPE,
        credentials=credentials,
        wire_version=2,
        subscription_key=key,
    )
    return publisher, subscriber, key


def _first(publisher, subscriber, key, start):
    deadline = time.monotonic() + 5
    sequence = start
    while time.monotonic() < deadline:
        sequence += 1
        assert publisher.try_publish(_event(key, sequence))
        event = subscriber.receive(timeout=0.02)
        if event is not None:
            return event, sequence
    raise AssertionError("no frame delivered")


def test_queued_frames_are_dropped_after_revoke_and_stale_ones_after_regrant():
    publisher, subscriber, key = _pair()
    try:
        first, sequence = _first(publisher, subscriber, key, 0)
        assert first.header.sequence >= 1
        # Frames now queued in the receiver socket (published under the old grant).
        for offset in range(1, 4):
            assert publisher.try_publish(_event(key, sequence + offset))
        sequence += 3
        time.sleep(0.2)
        assert publisher.regrant({"principal": set()}) is True
        assert publisher.reconfigurations == 1
        subscriber.revoke()
        assert subscriber.revoked == "AUTHORIZATION_REVOKED"
        for _ in range(5):
            assert subscriber.receive(timeout=0.05) is None
        assert subscriber.dropped_revoked >= 1
        # Re-grant: transport grants restored, receiver accepts only after the cut.
        assert publisher.regrant({"principal": {key.stream_id}}) is True
        cut = sequence + 5
        subscriber.regrant(generation=2, epoch="synthetic-epoch-1", after_sequence=cut)
        stale_before = subscriber.dropped_stale_authorization
        delivered = None
        deadline = time.monotonic() + 5
        next_sequence = sequence
        while delivered is None and time.monotonic() < deadline:
            next_sequence += 1
            assert publisher.try_publish(_event(key, next_sequence))
            delivered = subscriber.receive(timeout=0.02)
        # Per-peer delivery is FIFO: frames at or below the cut were published
        # first, so any that reached the socket were dropped, not returned.
        assert delivered is not None and delivered.header.sequence > cut
        assert subscriber.dropped_stale_authorization >= stale_before
        with pytest.raises(ValueError):
            subscriber.regrant(generation=2, epoch="synthetic-epoch-1", after_sequence=0)
    finally:
        subscriber.close()
        publisher.close()


def test_regrant_rejects_invalid_cuts_and_counts_backpressure_drops():
    publisher, subscriber, key = _pair()
    try:
        for bad in (
            {"generation": 0, "epoch": "e", "after_sequence": 0},
            {"generation": 1, "epoch": "", "after_sequence": 0},
            {"generation": 1, "epoch": "e", "after_sequence": -1},
        ):
            with pytest.raises(ValueError):
                subscriber.regrant(**bad)
        with pytest.raises(ValueError):
            subscriber.revoke("")
        assert publisher.dropped_would_block == 0
        assert subscriber.dropped_invalid == 0
    finally:
        subscriber.close()
        publisher.close()
