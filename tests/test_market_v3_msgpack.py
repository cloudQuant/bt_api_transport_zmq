"""Iteration 60, step 60.09: MessagePack v1 market wire (version 3) over CURVE PUB/SUB.

Real ZeroMQ sockets on the loopback interface: the publisher encodes a Base
``MarketTickPayload`` once, each subscribed process decodes each received
message once into the same frozen container, and in-process consumers share
that object. Wrong topics, other wire versions and unauthorized clients
receive nothing; stream gaps are observable.
"""

from __future__ import annotations

import time

import pytest
import zmq

pytest.importorskip("msgpack")

from bt_api_base.market_protocol import MarketInstrumentKey, MarketSubscriptionKey
from bt_api_base.market_tick_protocol import (
    MarketClockQuality,
    MarketFreshnessStatus,
    MarketTickPayload,
)
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_base.wire_codec_v1 import StreamPosition, WireMessageV1

from bt_api_transport_zmq.market_v2 import (
    MARKET_WIRE_VERSION_MSGPACK_V1,
    MARKET_WIRE_VERSION_TOPIC_FILTERED,
    ContainerSequenceMonitor,
    ZmqMarketPublisher,
    ZmqMarketSubscriber,
)
from bt_api_transport_zmq.server import CurveClientCredentials, CurveServerCredentials

_IDENTITY = WireIdentity(
    role=WireRole.SERVICE, principal_ref="gateway-market-hub", actor_ref="ctp-provider"
)
_SCOPE = WireScope(execution_domain_ref="public:ctp-market")
_INSTRUMENT = MarketInstrumentKey("ctp", "CZCE", "simulation", "future", "SA2701", "SA2701")


def _key(channel: str = "tick") -> MarketSubscriptionKey:
    return MarketSubscriptionKey(
        source_ref="ctp.md.front",
        entitlement_ref="public-entitlement",
        instrument=_INSTRUMENT,
        channel=channel,
    )


def _tick(sequence: int) -> MarketTickPayload:
    return MarketTickPayload(
        instrument=_INSTRUMENT,
        last_price=1500.0 + sequence,
        bid_price=1499.0,
        ask_price=1501.0,
        bid_size=10.0,
        ask_size=12.0,
        lower_limit=1400.0,
        upper_limit=1600.0,
        turnover=1.0e8,
        open_interest=5000.0,
        delta_volume=1.0,
        cumulative_volume=float(12345 + sequence),
        volume_complete=True,
        volume_quality="CONTINUOUS",
        continuity_status="continuous",
        trading_date="2026-11-02",
        event_session_date="2026-11-02",
        provider_event_time_utc="2026-11-02T02:00:00.500000Z",
        event_time_provenance="provider_reported",
        received_at_utc="2026-11-02T02:00:00.600000Z",
        received_monotonic_ns=123456789 + sequence,
        provider_source="ctp.native.md",
        quality_contract_ref="ctp.quote.v2",
        provider_connection_generation=1,
        provider_sequence=sequence,
        provider_subscription_epoch=1,
        clock_domain_id="clock-domain-1",
        clock_source_session_id="clock-session-1",
        clock_source="ctp.exchange",
        source_clock_quality=MarketClockQuality.VERIFIED,
        receive_clock_quality=MarketClockQuality.VERIFIED,
        source_clock_error_ms=1.0,
        receive_clock_error_ms=1.0,
        freshness_status=MarketFreshnessStatus.FRESH,
        freshness_reason_codes=(),
        execution_eligible=False,
        quality_flags=(),
    )


def _client(server_public: bytes) -> tuple[bytes, CurveClientCredentials]:
    public_key, secret_key = zmq.curve_keypair()
    return public_key, CurveClientCredentials(server_public, public_key, secret_key)


@pytest.fixture
def curve():
    server_public, server_secret = zmq.curve_keypair()
    return server_public, CurveServerCredentials(server_public, server_secret)


def _publisher(server_credentials, principals, *, version=MARKET_WIRE_VERSION_MSGPACK_V1):
    return ZmqMarketPublisher(
        "tcp://127.0.0.1:*",
        _IDENTITY,
        _SCOPE,
        principals,
        credentials=server_credentials,
        wire_version=version,
    )


def _subscriber(endpoint, credentials, key, *, version=MARKET_WIRE_VERSION_MSGPACK_V1):
    return ZmqMarketSubscriber(
        endpoint,
        _IDENTITY,
        _SCOPE,
        credentials=credentials,
        wire_version=version,
        subscription_key=key,
    )


def _pump(publisher, subscribers, key, *, start=1, timeout=4.0, epoch="epoch-1"):
    """Publish until every subscriber decoded at least one message."""

    received = {id(sub): [] for sub in subscribers}
    deadline = time.monotonic() + timeout
    sequence = start
    while time.monotonic() < deadline and not all(received.values()):
        assert publisher.try_publish_container(
            "tick", _tick(sequence), StreamPosition(key.stream_id, epoch, sequence)
        )
        sequence += 1
        for sub in subscribers:
            message = sub.receive_container(timeout_ms=5)
            if message is not None:
                received[id(sub)].append(message)
    return received, sequence


def test_tick_crosses_the_process_boundary_as_the_same_frozen_container(curve):
    server_public, server_credentials = curve
    client_public, client_credentials = _client(server_public)
    key = _key()
    publisher = _publisher(server_credentials, {client_public: "strategy-host-1"})
    subscriber = _subscriber(publisher.endpoint, client_credentials, key)
    try:
        received, _ = _pump(publisher, [subscriber], key)
        message = received[id(subscriber)][0]
        assert type(message) is WireMessageV1
        assert type(message.payload) is MarketTickPayload
        sequence = message.stream.sequence
        assert message.payload == _tick(sequence)
        assert message.stream.stream_id == key.stream_id
    finally:
        subscriber.close()
        publisher.close()


def test_ten_in_process_strategies_share_one_decoded_object(curve):
    server_public, server_credentials = curve
    client_public, client_credentials = _client(server_public)
    key = _key()
    publisher = _publisher(server_credentials, {client_public: "strategy-host-1"})
    subscriber = _subscriber(publisher.endpoint, client_credentials, key)
    try:
        received, _ = _pump(publisher, [subscriber], key)
        message = received[id(subscriber)][0]
        # One decode per received message; ten strategies read the same
        # immutable object instead of ten copies.
        seen = [message.payload for _strategy in range(10)]
        assert all(item is message.payload for item in seen)
        with pytest.raises(AttributeError):
            message.payload.last_price = 0.0  # frozen: no consumer can mutate it
    finally:
        subscriber.close()
        publisher.close()


def test_subscriber_receives_only_its_own_stream_and_wire_version(curve):
    server_public, server_credentials = curve
    client_public, client_credentials = _client(server_public)
    tick_key, other_key = _key("tick"), _key("depth")
    publisher = _publisher(server_credentials, {client_public: "strategy-host-1"})
    own = _subscriber(publisher.endpoint, client_credentials, tick_key)
    other = _subscriber(publisher.endpoint, client_credentials, other_key)
    old = _subscriber(
        publisher.endpoint, client_credentials, tick_key, version=MARKET_WIRE_VERSION_TOPIC_FILTERED
    )
    try:
        received, _ = _pump(publisher, [own], tick_key)
        assert received[id(own)]
        assert other.receive_container(timeout_ms=50) is None
        assert old.receive(timeout=0.05) is None
    finally:
        own.close()
        other.close()
        old.close()
        publisher.close()


def test_unauthorized_curve_client_receives_nothing(curve):
    server_public, server_credentials = curve
    client_public, client_credentials = _client(server_public)
    _intruder_public, intruder_credentials = _client(server_public)
    key = _key()
    publisher = _publisher(server_credentials, {client_public: "strategy-host-1"})
    allowed = _subscriber(publisher.endpoint, client_credentials, key)
    intruder = _subscriber(publisher.endpoint, intruder_credentials, key)
    try:
        received, _ = _pump(publisher, [allowed], key)
        assert received[id(allowed)]
        for _ in range(20):
            assert intruder.receive_container(timeout_ms=5) is None
    finally:
        allowed.close()
        intruder.close()
        publisher.close()


def test_message_whose_stream_does_not_match_its_topic_is_dropped(curve):
    server_public, server_credentials = curve
    client_public, client_credentials = _client(server_public)
    key, other_key = _key("tick"), _key("depth")
    publisher = _publisher(server_credentials, {client_public: "strategy-host-1"})
    subscriber = _subscriber(publisher.endpoint, client_credentials, key)
    try:
        _pump(publisher, [subscriber], key)
        from bt_api_base.wire_codec_v1 import encode_message

        from bt_api_transport_zmq import market_v2

        body = encode_message("tick", _tick(99), stream=StreamPosition(other_key.stream_id, "e", 99))
        topic = market_v2._market_topic_for_stream_id(key.stream_id, MARKET_WIRE_VERSION_MSGPACK_V1)
        for _ in range(5):
            publisher._socket.send_multipart([topic, body])
        for _ in range(10):
            assert subscriber.receive_container(timeout_ms=10) is None
    finally:
        subscriber.close()
        publisher.close()


def test_legacy_envelope_api_is_refused_on_version_3(curve):
    server_public, server_credentials = curve
    client_public, client_credentials = _client(server_public)
    publisher = _publisher(server_credentials, {client_public: "strategy-host-1"})
    subscriber = _subscriber(publisher.endpoint, client_credentials, _key())
    try:
        with pytest.raises(ValueError, match="try_publish_container"):
            publisher.try_publish(object())
        with pytest.raises(ValueError, match="receive_container"):
            subscriber.receive(timeout=0)
    finally:
        subscriber.close()
        publisher.close()


def test_sequence_monitor_reports_gaps_duplicates_and_epochs():
    monitor = ContainerSequenceMonitor()
    key = _key()

    def message(epoch, sequence):
        return WireMessageV1("tick", None, StreamPosition(key.stream_id, epoch, sequence), 0, {})

    assert monitor.observe(message("e1", 1)) == "FIRST"
    assert monitor.observe(message("e1", 2)) == "IN_ORDER"
    assert monitor.observe(message("e1", 5)) == "GAP"
    assert monitor.observe(message("e1", 5)) == "DUPLICATE"
    assert monitor.observe(message("e1", 3)) == "DUPLICATE"
    assert monitor.observe(message("e2", 1)) == "NEW_EPOCH"
    assert monitor.observe(message("e2", 2)) == "IN_ORDER"
