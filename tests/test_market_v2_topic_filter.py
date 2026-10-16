"""Focused tests for opt-in topic-filtered market PUB/SUB wire version 2."""

from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest
import zmq
from bt_api_base.market_protocol import (
    MARKET_EVENT_OPERATION,
    MARKET_EVENT_SCHEMA,
    MARKET_EVENT_SCHEMA_VERSION,
    MarketInstrumentKey,
    MarketSubscriptionKey,
)
from bt_api_base.service_protocol import (
    WIRE_PROTOCOL_VERSION,
    WireEnvelope,
    WireHeader,
    WireIdentity,
    WireMessageKind,
    WireRole,
    WireScope,
    encode_envelope,
)

from bt_api_transport_zmq import market_v2
from bt_api_transport_zmq.market_v2 import (
    MARKET_WIRE_VERSION_LEGACY,
    MARKET_WIRE_VERSION_TOPIC_FILTERED,
    ZmqMarketContextPool,
    ZmqMarketPublisher,
    ZmqMarketSubscriber,
    validate_publisher_configuration,
)
from bt_api_transport_zmq.server import CurveClientCredentials, CurveServerCredentials
from bt_api_transport_zmq.service_v2 import ServiceTransportStartupCleanupError

_IDENTITY = WireIdentity(
    role=WireRole.SERVICE,
    principal_ref="synthetic-market-hub",
    actor_ref="synthetic-provider",
)
_SCOPE = WireScope(execution_domain_ref="public:synthetic-market")


def _key(instrument_id: str, channel: str = "ticker") -> MarketSubscriptionKey:
    return MarketSubscriptionKey(
        source_ref="synthetic-source",
        entitlement_ref="public-entitlement",
        instrument=MarketInstrumentKey(
            provider="synthetic",
            venue="synthetic-venue",
            environment="paper",
            product_type="linear-perpetual",
            instrument_id=instrument_id,
            native_symbol=instrument_id,
        ),
        channel=channel,
    )


def _event(
    key: MarketSubscriptionKey,
    sequence: int,
    *,
    data: dict[str, Any] | None = None,
) -> WireEnvelope:
    return WireEnvelope(
        header=WireHeader(
            protocol_version=WIRE_PROTOCOL_VERSION,
            kind=WireMessageKind.EVENT,
            message_id=uuid.uuid4().hex,
            correlation_id=None,
            identity=_IDENTITY,
            scope=_SCOPE,
            operation=MARKET_EVENT_OPERATION,
            schema_id=MARKET_EVENT_SCHEMA,
            schema_version=MARKET_EVENT_SCHEMA_VERSION,
            sent_at_utc=(
                datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
            ),
            stream_id=key.stream_id,
            stream_epoch="synthetic-epoch-1",
            sequence=sequence,
        ),
        payload={"key": key.to_dict(), "data": data or {"last": float(sequence)}},
    )


def _curve_client(server_public: bytes) -> tuple[bytes, CurveClientCredentials]:
    public_key, secret_key = zmq.curve_keypair()
    return public_key, CurveClientCredentials(server_public, public_key, secret_key)


def _publisher(
    server_credentials: CurveServerCredentials,
    principals: dict[bytes, str],
    *,
    wire_version: int = MARKET_WIRE_VERSION_LEGACY,
    high_water_mark: int = 1000,
    max_message_bytes: int = 1024 * 1024,
) -> ZmqMarketPublisher:
    return ZmqMarketPublisher(
        "tcp://127.0.0.1:*",
        _IDENTITY,
        _SCOPE,
        principals,
        credentials=server_credentials,
        wire_version=wire_version,
        high_water_mark=high_water_mark,
        max_message_bytes=max_message_bytes,
    )


def _subscriber(
    endpoint: str,
    credentials: CurveClientCredentials,
    *,
    key: MarketSubscriptionKey | None = None,
    wire_version: int = MARKET_WIRE_VERSION_LEGACY,
    high_water_mark: int = 1000,
    max_message_bytes: int = 1024 * 1024,
    context_pool: ZmqMarketContextPool | None = None,
) -> ZmqMarketSubscriber:
    return ZmqMarketSubscriber(
        endpoint,
        _IDENTITY,
        _SCOPE,
        credentials=credentials,
        wire_version=wire_version,
        subscription_key=key,
        high_water_mark=high_water_mark,
        max_message_bytes=max_message_bytes,
        context_pool=context_pool,
    )


def _wait_for_two_topics(
    publisher: ZmqMarketPublisher,
    subscriber_a: ZmqMarketSubscriber,
    key_a: MarketSubscriptionKey,
    subscriber_b: ZmqMarketSubscriber,
    key_b: MarketSubscriptionKey,
    *,
    denied_subscriber: ZmqMarketSubscriber | None = None,
    timeout: float = 4.0,
) -> tuple[WireEnvelope, WireEnvelope]:
    """Prove both CURVE subscribers received their own key before returning."""

    deadline = time.monotonic() + timeout
    sequence = 1
    received_a: WireEnvelope | None = None
    received_b: WireEnvelope | None = None
    while time.monotonic() < deadline:
        assert publisher.try_publish(_event(key_a, sequence))
        assert publisher.try_publish(_event(key_b, sequence))
        sequence += 1
        event_a = subscriber_a.receive(timeout=0.005)
        if event_a is not None:
            assert event_a.payload["key"] == key_a.to_dict()
            if received_a is None:
                received_a = event_a
        event_b = subscriber_b.receive(timeout=0.005)
        if event_b is not None:
            assert event_b.payload["key"] == key_b.to_dict()
            if received_b is None:
                received_b = event_b
        if denied_subscriber is not None:
            assert denied_subscriber.receive(timeout_ms=0) is None
        if received_a is not None and received_b is not None:
            return received_a, received_b
    raise AssertionError("authorized subscribers did not receive both matching topics")


def _drain_expected(
    subscribers: tuple[ZmqMarketSubscriber, ...], keys: tuple[MarketSubscriptionKey, ...]
) -> None:
    deadline = time.monotonic() + 2.0
    quiet_since = time.monotonic()
    while time.monotonic() < deadline:
        found = False
        for subscriber, key in zip(subscribers, keys):
            while (event := subscriber.receive(timeout_ms=0)) is not None:
                assert event.payload["key"] == key.to_dict()
                found = True
        if found:
            quiet_since = time.monotonic()
        elif time.monotonic() - quiet_since >= 0.05:
            return
        else:
            time.sleep(0.002)
    raise AssertionError("topic subscriber queues did not become quiet")


def test_topic_wire_v2_filters_two_topics_and_keeps_curve_acl_and_limits() -> None:
    server_public, server_secret = zmq.curve_keypair()
    server_credentials = CurveServerCredentials(server_public, server_secret)
    public_a, credentials_a = _curve_client(server_public)
    public_b, credentials_b = _curve_client(server_public)
    _denied_public, denied_credentials = _curve_client(server_public)
    key_a = _key("SYNTH-A")
    key_b = _key("SYNTH-B", channel="depth")
    publisher = _publisher(
        server_credentials,
        {public_a: "authorized-a", public_b: "authorized-b"},
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        high_water_mark=17,
        max_message_bytes=4096,
    )
    subscriber_a = _subscriber(
        publisher.endpoint,
        credentials_a,
        key=key_a,
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        high_water_mark=13,
        max_message_bytes=4096,
    )
    subscriber_b = _subscriber(
        publisher.endpoint,
        credentials_b,
        key=key_b,
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        high_water_mark=13,
        max_message_bytes=4096,
    )
    denied_subscriber = _subscriber(
        publisher.endpoint,
        denied_credentials,
        key=key_a,
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        high_water_mark=13,
        max_message_bytes=4096,
    )
    try:
        assert publisher._wire_version == MARKET_WIRE_VERSION_TOPIC_FILTERED
        assert subscriber_a._topic == (
            b"\x00BTAPI-MARKET\x00\x02" + key_a.stream_id.encode("ascii") + b"\x00"
        )
        assert publisher._socket.getsockopt(zmq.SNDHWM) == 17
        assert subscriber_a._socket.getsockopt(zmq.RCVHWM) == 13
        assert subscriber_a._socket.getsockopt(zmq.MAXMSGSIZE) == (
            4096 + market_v2._MAX_TOPIC_FRAME_BYTES
        )
        with pytest.raises(ValueError):
            publisher.try_publish(_event(key_a, 999, data={"oversized": "x" * 4096}))

        _wait_for_two_topics(
            publisher,
            subscriber_a,
            key_a,
            subscriber_b,
            key_b,
            denied_subscriber=denied_subscriber,
        )
        _drain_expected((subscriber_a, subscriber_b), (key_a, key_b))

        # Send one key at a time. A send return is never treated as a receive:
        # each target must return the matching sequence from receive().
        for target, other, key, sequence in (
            (subscriber_a, subscriber_b, key_a, 1001),
            (subscriber_b, subscriber_a, key_b, 2001),
        ):
            deadline = time.monotonic() + 3.0
            received = None
            while time.monotonic() < deadline and received is None:
                assert publisher.try_publish(_event(key, sequence))
                event = target.receive(timeout=0.020)
                if event is not None:
                    assert event.payload["key"] == key.to_dict()
                    if event.header.sequence == sequence:
                        received = event
                assert other.receive(timeout_ms=0) is None
                assert denied_subscriber.receive(timeout_ms=0) is None
            assert received is not None, (
                "the matching subscriber did not receive the published event"
            )
            assert other.receive(timeout_ms=50) is None
            assert denied_subscriber.receive(timeout_ms=50) is None
            _drain_expected((subscriber_a, subscriber_b), (key_a, key_b))

        raw_socket = publisher._socket

        class BackpressuredSocket:
            def send_multipart(self, *_args: Any, **_kwargs: Any) -> None:
                raise zmq.Again()

        publisher._socket = BackpressuredSocket()
        try:
            assert publisher.try_publish(_event(key_a, 3001)) is False
        finally:
            publisher._socket = raw_socket
    finally:
        denied_subscriber.close()
        subscriber_b.close()
        subscriber_a.close()
        publisher.close()


class _ObservedSocket:
    """Transparent receive proxy that records frames from a real CURVE socket."""

    def __init__(self, socket: zmq.Socket) -> None:
        self._socket = socket
        self.frames: list[bytes] = []

    def recv(self, *, flags: int, copy: bool) -> zmq.Frame:
        frame = self._socket.recv(flags=flags, copy=copy)
        self.frames.append(bytes(frame))
        return frame

    def getsockopt(self, option: int) -> int:
        return self._socket.getsockopt(option)


def _send_bad_message_then_sentinel(
    publisher: ZmqMarketPublisher,
    subscriber: ZmqMarketSubscriber,
    observed_socket: _ObservedSocket,
    key: MarketSubscriptionKey,
    bad_parts: list[bytes],
    sequence: int,
) -> None:
    start = len(observed_socket.frames)
    publisher._socket.send_multipart(bad_parts, flags=zmq.NOBLOCK)
    sentinel = _event(key, sequence, data={"received_after_bad_frame": sequence})
    sentinel_frames = [subscriber._topic, encode_envelope(sentinel)]
    assert publisher.try_publish(sentinel)

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        event = subscriber.receive(timeout=0.050)
        if event is None:
            continue
        assert event == sentinel, "a topic collision or invalid envelope escaped the receiver"
        break
    else:
        raise AssertionError("valid sentinel was not received after the injected bad message")

    observed = observed_socket.frames[start:]
    expected_prefix = bad_parts + sentinel_frames
    assert observed[: len(expected_prefix)] == expected_prefix


def test_topic_v2_drops_prefix_collision_key_mismatch_malformed_and_extra_parts() -> None:
    server_public, server_secret = zmq.curve_keypair()
    server_credentials = CurveServerCredentials(server_public, server_secret)
    client_public, client_credentials = _curve_client(server_public)
    key = _key("SYNTH-COLLISION")
    other_key = _key("SYNTH-OTHER")
    publisher = _publisher(
        server_credentials,
        {client_public: "authorized"},
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
    )
    subscriber = _subscriber(
        publisher.endpoint,
        client_credentials,
        key=key,
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
    )
    try:
        deadline = time.monotonic() + 3.0
        ready = None
        while time.monotonic() < deadline and ready is None:
            assert publisher.try_publish(_event(key, 1))
            ready = subscriber.receive(timeout=0.020)
        assert ready is not None, "the CURVE subscriber did not receive its readiness event"
        _drain_expected((subscriber,), (key,))

        raw_socket = subscriber._socket
        observed_socket = _ObservedSocket(raw_socket)
        subscriber._receiver._socket = observed_socket
        topic = subscriber._topic
        assert topic is not None

        suffix_collision = topic + b"suffix"
        assert suffix_collision.startswith(topic) and suffix_collision != topic
        _send_bad_message_then_sentinel(
            publisher,
            subscriber,
            observed_socket,
            key,
            [suffix_collision, encode_envelope(_event(key, 10))],
            11,
        )
        _send_bad_message_then_sentinel(
            publisher,
            subscriber,
            observed_socket,
            key,
            [topic, encode_envelope(_event(other_key, 20))],
            21,
        )
        _send_bad_message_then_sentinel(
            publisher,
            subscriber,
            observed_socket,
            key,
            [topic, b"{not-a-wire-envelope"],
            31,
        )
        _send_bad_message_then_sentinel(
            publisher,
            subscriber,
            observed_socket,
            key,
            [topic, encode_envelope(_event(key, 40)), b"unexpected-third-frame"],
            41,
        )
    finally:
        subscriber.close()
        publisher.close()


def test_wire_v1_defaults_to_single_frame_broadcast_over_curve() -> None:
    server_public, server_secret = zmq.curve_keypair()
    server_credentials = CurveServerCredentials(server_public, server_secret)
    public_a, credentials_a = _curve_client(server_public)
    public_b, credentials_b = _curve_client(server_public)
    publisher = _publisher(server_credentials, {public_a: "a", public_b: "b"})
    subscriber_a = _subscriber(publisher.endpoint, credentials_a)
    subscriber_b = _subscriber(publisher.endpoint, credentials_b)
    key = _key("SYNTH-LEGACY")
    try:
        assert publisher._wire_version == MARKET_WIRE_VERSION_LEGACY
        assert subscriber_a._wire_version == MARKET_WIRE_VERSION_LEGACY
        deadline = time.monotonic() + 3.0
        received_a = None
        received_b = None
        while time.monotonic() < deadline and (received_a is None or received_b is None):
            event = _event(key, 7)
            assert publisher.try_publish(event)
            if received_a is None:
                received_a = subscriber_a.receive(timeout=0.020)
            if received_b is None:
                received_b = subscriber_b.receive(timeout=0.020)
        assert received_a is not None and received_a.payload["key"] == key.to_dict()
        assert received_b is not None and received_b.payload["key"] == key.to_dict()
    finally:
        subscriber_b.close()
        subscriber_a.close()
        publisher.close()


class _FakeMultipartSocket:
    def __init__(self, messages: list[list[bytes]]) -> None:
        self.messages = deque(messages)
        self.active: list[bytes] | None = None
        self.offset = 0

    def poll(self, _timeout_ms: int | None, _flags: int) -> int:
        return int(self.active is not None or bool(self.messages))

    def recv(self, *, flags: int, copy: bool) -> bytes:
        assert flags == zmq.NOBLOCK
        assert copy is False
        if self.active is None:
            self.active = self.messages.popleft()
            self.offset = 0
        frame = self.active[self.offset]
        self.offset += 1
        if self.offset == len(self.active):
            self.active = None
            self.offset = 0
        return frame

    def getsockopt(self, option: int) -> int:
        assert option == zmq.RCVMORE
        return int(self.active is not None)


def _fake_subscriber(
    socket: _FakeMultipartSocket,
    *,
    wire_version: int,
    key: MarketSubscriptionKey,
) -> ZmqMarketSubscriber:
    subscriber = object.__new__(ZmqMarketSubscriber)
    subscriber._endpoint = "tcp://127.0.0.1:1"
    subscriber.endpoint = subscriber._endpoint
    subscriber._expected_peer = _IDENTITY
    subscriber._expected_scope = _SCOPE
    subscriber._high_water_mark = 10
    subscriber._max_message_bytes = 4096
    subscriber._wire_version = wire_version
    subscriber._subscription_key = (
        key if wire_version == MARKET_WIRE_VERSION_TOPIC_FILTERED else None
    )
    subscriber._topic = (
        b"\x00BTAPI-MARKET\x00\x02" + key.stream_id.encode("ascii") + b"\x00"
        if wire_version == MARKET_WIRE_VERSION_TOPIC_FILTERED
        else None
    )
    subscriber._credentials = None
    subscriber._owner_pid = market_v2.os.getpid()
    subscriber._owner_thread = threading.get_ident()
    subscriber._closed = False
    subscriber._close_pending = False
    subscriber._context = None
    subscriber._socket = socket
    if wire_version == MARKET_WIRE_VERSION_LEGACY:
        subscriber._receiver = market_v2._BoundedMultipartReceiver(socket)
    else:
        subscriber._receiver = market_v2._BoundedTopicReceiver(socket)
    return subscriber


def test_subscriber_rejects_same_thread_identity_after_fork_before_socket_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_public, _server_secret = zmq.curve_keypair()
    client_public, client_credentials = _curve_client(server_public)
    pool = ZmqMarketContextPool()
    subscriber = _subscriber(
        "tcp://127.0.0.1:1",
        client_credentials,
        key=_key("PID-GUARD"),
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        context_pool=pool,
    )
    raw_socket = subscriber._socket

    class SocketProbe:
        def __init__(self) -> None:
            self.poll_calls = 0
            self.close_calls = 0

        def __getattr__(self, name: str) -> Any:
            return getattr(raw_socket, name)

        def poll(self, *args: Any, **kwargs: Any) -> int:
            self.poll_calls += 1
            return raw_socket.poll(*args, **kwargs)

        def close(self, *args: Any, **kwargs: Any) -> None:
            self.close_calls += 1
            raw_socket.close(*args, **kwargs)

    probe = SocketProbe()
    subscriber._socket = probe  # type: ignore[assignment]
    owner_pid = subscriber._owner_pid
    owner_thread = subscriber._owner_thread
    try:
        monkeypatch.setattr(market_v2, "os", SimpleNamespace(getpid=lambda: owner_pid + 1))
        with pytest.raises(RuntimeError, match="cannot cross a process boundary"):
            subscriber.receive(timeout=0)
        with pytest.raises(RuntimeError, match="cannot cross a process boundary"):
            subscriber.close()

        assert threading.get_ident() == owner_thread
        assert probe.poll_calls == 0
        assert probe.close_calls == 0
        assert subscriber._closed is False
        assert subscriber._close_pending is False
        assert subscriber._socket is probe
        assert pool._active_leases == 1
    finally:
        monkeypatch.setattr(market_v2, "os", SimpleNamespace(getpid=lambda: owner_pid))
        subscriber._socket = raw_socket
        if not subscriber._closed:
            subscriber.close()
    assert subscriber._closed is True
    assert subscriber._context is None
    assert pool._active_leases == 0


def test_context_pool_rejects_fork_before_acquiring_inherited_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = ZmqMarketContextPool()
    lease = pool.acquire()
    owner_pid = pool._owner_pid
    original_lock = pool._lock

    class InheritedLockedRLock:
        def __enter__(self) -> None:
            raise AssertionError("child blocked on an inherited pool lock")

        def __exit__(self, *_args: Any) -> None:
            return None

    monkeypatch.setattr(pool, "_lock", InheritedLockedRLock())
    monkeypatch.setattr(market_v2, "os", SimpleNamespace(getpid=lambda: owner_pid + 1))
    with pytest.raises(RuntimeError, match="context pool cannot cross a process boundary"):
        pool.acquire()
    with pytest.raises(RuntimeError, match="context lease cannot cross a process boundary"):
        lease.close()

    assert lease._released is False
    assert pool._active_leases == 1

    monkeypatch.setattr(market_v2, "os", SimpleNamespace(getpid=lambda: owner_pid))
    monkeypatch.setattr(pool, "_lock", original_lock)
    lease.close()
    assert lease._released is True
    assert pool._active_leases == 0
    assert pool._context is None


def test_pooled_constructor_cleanup_failure_retains_lease_for_close_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_public, _server_secret = zmq.curve_keypair()
    _client_public, client_credentials = _curve_client(server_public)
    pool = ZmqMarketContextPool()
    original_configure = market_v2._configure_subscriber_socket
    original_close = zmq.Socket.close
    close_failed = False

    def fail_configuration(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("injected subscriber configuration failure")

    def fail_first_socket_close(socket: zmq.Socket, *args: Any, **kwargs: Any) -> None:
        nonlocal close_failed
        if not close_failed:
            close_failed = True
            raise RuntimeError("injected startup socket close failure")
        original_close(socket, *args, **kwargs)

    monkeypatch.setattr(market_v2, "_configure_subscriber_socket", fail_configuration)
    monkeypatch.setattr(zmq.Socket, "close", fail_first_socket_close)
    with pytest.raises(ServiceTransportStartupCleanupError) as captured:
        _subscriber(
            "tcp://127.0.0.1:1",
            client_credentials,
            key=_key("STARTUP-RETRY"),
            wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
            context_pool=pool,
        )

    retained = captured.value.transport
    assert isinstance(retained, ZmqMarketSubscriber)
    assert retained._close_pending is True
    assert retained._closed is False
    assert retained._context is pool._context
    assert retained._socket is not None
    assert pool._active_leases == 1

    monkeypatch.setattr(zmq.Socket, "close", original_close)
    retained.close()
    assert retained._closed is True
    assert retained._context is None
    assert pool._context is None
    assert pool._active_leases == 0
    assert close_failed is True
    monkeypatch.setattr(market_v2, "_configure_subscriber_socket", original_configure)


def test_mixed_wire_frames_are_dropped_without_automatic_fallback() -> None:
    key = _key("SYNTH-MIXED")
    other_key = _key("SYNTH-MIXED-OTHER")
    legacy_event = _event(key, 1)
    topic_event = _event(key, 2)
    topic = b"\x00BTAPI-MARKET\x00\x02" + key.stream_id.encode("ascii") + b"\x00"

    legacy_subscriber = _fake_subscriber(
        _FakeMultipartSocket(
            [[topic, encode_envelope(topic_event)], [encode_envelope(legacy_event)]]
        ),
        wire_version=MARKET_WIRE_VERSION_LEGACY,
        key=key,
    )
    assert legacy_subscriber.receive(timeout=0) is None
    assert legacy_subscriber.receive(timeout=0) == legacy_event

    topic_subscriber = _fake_subscriber(
        _FakeMultipartSocket(
            [[encode_envelope(legacy_event)], [topic, encode_envelope(topic_event)]]
        ),
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        key=key,
    )
    assert topic_subscriber.receive(timeout=0) is None
    assert topic_subscriber.receive(timeout=0) == topic_event

    wrong_topic_subscriber = _fake_subscriber(
        _FakeMultipartSocket([[topic, encode_envelope(_event(other_key, 3))]]),
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        key=key,
    )
    assert wrong_topic_subscriber.receive(timeout=0) is None


def test_wire_versions_and_required_key_are_validated_before_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_public, server_secret = zmq.curve_keypair()
    server_credentials = CurveServerCredentials(server_public, server_secret)
    client_public, client_credentials = _curve_client(server_public)
    key = _key("SYNTH-VALIDATION")

    def no_context() -> None:
        raise AssertionError("invalid wire configuration created a ZMQ context")

    monkeypatch.setattr(market_v2.zmq, "Context", no_context)
    for invalid_version in (True, 0, 3):
        with pytest.raises(ValueError, match="wire version"):
            validate_publisher_configuration(
                "tcp://127.0.0.1:*",
                _IDENTITY,
                _SCOPE,
                {client_public: "authorized"},
                credentials=server_credentials,
                wire_version=invalid_version,
            )

    with pytest.raises(ValueError, match="wire version"):
        _publisher(server_credentials, {client_public: "authorized"}, wire_version=True)
    with pytest.raises(ValueError, match="wire version"):
        _subscriber(
            "tcp://127.0.0.1:12345",
            client_credentials,
            wire_version=3,
        )
    with pytest.raises(ValueError, match="requires a subscription key"):
        _subscriber(
            "tcp://127.0.0.1:12345",
            client_credentials,
            wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        )
    with pytest.raises(ValueError, match="does not accept a subscription key"):
        _subscriber("tcp://127.0.0.1:12345", client_credentials, key=key)


def test_shared_context_pool_keeps_topic_sockets_independent_and_close_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_public, server_secret = zmq.curve_keypair()
    server_credentials = CurveServerCredentials(server_public, server_secret)
    client_public, client_credentials = _curve_client(server_public)
    publisher = _publisher(
        server_credentials,
        {client_public: "shared-context-reader"},
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
    )
    pool = ZmqMarketContextPool()
    key_a = _key("BTC-USD-PERP")
    key_b = _key("ETH-USD-PERP")
    subscriber_a = _subscriber(
        publisher.endpoint,
        client_credentials,
        key=key_a,
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        high_water_mark=17,
        max_message_bytes=8192,
        context_pool=pool,
    )
    subscriber_b = _subscriber(
        publisher.endpoint,
        client_credentials,
        key=key_b,
        wire_version=MARKET_WIRE_VERSION_TOPIC_FILTERED,
        high_water_mark=19,
        max_message_bytes=16384,
        context_pool=pool,
    )
    shared_context = subscriber_a._context
    raw_socket_a = subscriber_a._socket
    assert shared_context is subscriber_b._context
    assert raw_socket_a is not subscriber_b._socket
    assert subscriber_a._socket.getsockopt(zmq.RCVHWM) == 17
    assert subscriber_b._socket.getsockopt(zmq.RCVHWM) == 19
    assert subscriber_a._socket.getsockopt(zmq.MAXMSGSIZE) == (
        8192 + market_v2._MAX_TOPIC_FRAME_BYTES
    )
    assert subscriber_b._socket.getsockopt(zmq.MAXMSGSIZE) == (
        16384 + market_v2._MAX_TOPIC_FRAME_BYTES
    )

    original_term = zmq.Context.term
    term_calls = 0

    def fail_once_term(context: zmq.Context) -> None:
        nonlocal term_calls
        if context is shared_context and term_calls == 0:
            term_calls += 1
            raise RuntimeError("injected shared-context termination failure")
        original_term(context)

    monkeypatch.setattr(zmq.Context, "term", fail_once_term)

    class FailOnceSocket:
        def __init__(self) -> None:
            self.calls = 0

        def close(self, *, linger: int) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("injected shared subscriber close failure")
            raw_socket_a.close(linger=linger)

    try:
        _wait_for_two_topics(publisher, subscriber_a, key_a, subscriber_b, key_b)
        subscriber_a._socket = FailOnceSocket()
        with pytest.raises(RuntimeError, match="injected shared subscriber close failure"):
            subscriber_a.close()
        assert subscriber_a._close_pending is True
        assert subscriber_a._context is shared_context
        assert shared_context.closed is False

        subscriber_a.close()
        assert subscriber_a._closed is True
        assert subscriber_b._context is shared_context
        assert shared_context.closed is False

        with pytest.raises(RuntimeError, match="injected shared-context termination failure"):
            subscriber_b.close()
        assert subscriber_b._close_pending is True
        assert subscriber_b._context is shared_context
        assert shared_context.closed is False

        subscriber_b.close()
        assert subscriber_b._closed is True
        assert subscriber_b._context is None
        assert shared_context.closed is True
    finally:
        if not subscriber_a._closed:
            try:
                subscriber_a.close()
            except RuntimeError:
                subscriber_a.close()
        if not subscriber_b._closed:
            try:
                subscriber_b.close()
            except RuntimeError:
                subscriber_b.close()
        if not publisher._closed:
            publisher.close()
