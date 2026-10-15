"""Tests for the CURVE-authenticated neutral market PUB/SUB transport."""

from __future__ import annotations

import queue
import threading
import time
import uuid
from collections import deque
from dataclasses import replace
from datetime import datetime, timezone
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
    EventPublisher,
    EventSubscriber,
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
    MarketTransportError,
    ServiceTransportStartupCleanupError,
    ZmqMarketPublisher,
    ZmqMarketSubscriber,
    validate_publisher_configuration,
)
from bt_api_transport_zmq.server import CurveClientCredentials, CurveServerCredentials


def _identity(role: WireRole = WireRole.SERVICE, principal: str = "market-hub") -> WireIdentity:
    return WireIdentity(role=role, principal_ref=principal, actor_ref="provider-alpha")


def _scope(execution_domain: str = "public:market") -> WireScope:
    return WireScope(execution_domain_ref=execution_domain)


def _key(**updates: Any) -> MarketSubscriptionKey:
    values: dict[str, Any] = {
        "source_ref": "market-source-a",
        "entitlement_ref": "entitlement-public-a",
        "instrument": MarketInstrumentKey(
            provider="alpha",
            venue="alpha-futures",
            environment="paper",
            product_type="linear-perpetual",
            instrument_id="BTC-USD-PERP",
            native_symbol="BTCUSD_PERP",
        ),
        "channel": "ticker",
        "depth": None,
        "timeframe": None,
    }
    values.update(updates)
    return MarketSubscriptionKey(**values)


def _event(
    *,
    identity: WireIdentity | None = None,
    scope: WireScope | None = None,
    key: MarketSubscriptionKey | None = None,
    payload: dict[str, Any] | None = None,
    operation: str = MARKET_EVENT_OPERATION,
    schema_id: str = MARKET_EVENT_SCHEMA,
    schema_version: int = MARKET_EVENT_SCHEMA_VERSION,
    sequence: int = 1,
) -> WireEnvelope:
    subscription_key = key or _key()
    return WireEnvelope(
        header=WireHeader(
            protocol_version=WIRE_PROTOCOL_VERSION,
            kind=WireMessageKind.EVENT,
            message_id=uuid.uuid4().hex,
            correlation_id=None,
            identity=identity or _identity(),
            scope=scope or _scope(),
            operation=operation,
            schema_id=schema_id,
            schema_version=schema_version,
            sent_at_utc=datetime.now(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            stream_id=subscription_key.stream_id,
            stream_epoch="epoch-1",
            sequence=sequence,
        ),
        payload=payload
        if payload is not None
        else {"key": subscription_key.to_dict(), "data": {"last": 65000.25}},
    )


def _curve_credentials() -> tuple[CurveServerCredentials, bytes, CurveClientCredentials]:
    server_public, server_secret = zmq.curve_keypair()
    client_public, client_secret = zmq.curve_keypair()
    return (
        CurveServerCredentials(server_public, server_secret),
        client_public,
        CurveClientCredentials(server_public, client_public, client_secret),
    )


def _new_publisher(
    principals: dict[bytes, str],
    server_credentials: CurveServerCredentials,
    *,
    endpoint: str = "tcp://127.0.0.1:*",
) -> ZmqMarketPublisher:
    return ZmqMarketPublisher(
        endpoint,
        _identity(),
        _scope(),
        principals,
        credentials=server_credentials,
    )


def _new_subscriber(endpoint: str, credentials: CurveClientCredentials) -> ZmqMarketSubscriber:
    return ZmqMarketSubscriber(
        endpoint,
        _identity(),
        _scope(),
        credentials=credentials,
    )


def _publish_until_received(
    publisher: ZmqMarketPublisher,
    subscribers: tuple[ZmqMarketSubscriber, ...],
    *,
    timeout: float = 4.0,
) -> tuple[WireEnvelope, ...]:
    deadline = time.monotonic() + timeout
    sequence = 1
    received: list[WireEnvelope | None] = [None] * len(subscribers)
    while time.monotonic() < deadline:
        assert publisher.try_publish(_event(sequence=sequence))
        sequence += 1
        for index, subscriber in enumerate(subscribers):
            if received[index] is None:
                received[index] = subscriber.receive(timeout=0.020)
        if all(event is not None for event in received):
            return tuple(event for event in received if event is not None)
    raise AssertionError("subscribers did not receive a synchronized market event")


def test_publisher_configuration_is_pure_and_rejects_invalid_audience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_credentials, client_public, _client_credentials = _curve_credentials()

    def no_context() -> None:
        raise AssertionError("pure preflight created a ZMQ context")

    monkeypatch.setattr(market_v2.zmq, "Context", no_context)
    validate_publisher_configuration(
        "tcp://127.0.0.1:*",
        _identity(),
        _scope(),
        {client_public: "audience-a"},
        credentials=server_credentials,
    )

    with pytest.raises(ValueError, match="must not be empty"):
        validate_publisher_configuration(
            "tcp://127.0.0.1:*",
            _identity(),
            _scope(),
            {},
            credentials=server_credentials,
        )
    with pytest.raises(ValueError, match="service role"):
        validate_publisher_configuration(
            "tcp://127.0.0.1:*",
            _identity(WireRole.STRATEGY_CLIENT),
            _scope(),
            {client_public: "audience-a"},
            credentials=server_credentials,
        )
    with pytest.raises(ValueError, match="exclude account and strategy"):
        validate_publisher_configuration(
            "tcp://127.0.0.1:*",
            _identity(),
            WireScope(execution_domain_ref="public:market", account_ref="account-a"),
            {client_public: "audience-a"},
            credentials=server_credentials,
        )


def test_subscriber_rejects_private_scope_before_creating_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _server_credentials, _client_public, client_credentials = _curve_credentials()

    def no_context() -> None:
        raise AssertionError("invalid subscriber configuration created a ZMQ context")

    monkeypatch.setattr(market_v2.zmq, "Context", no_context)
    with pytest.raises(ValueError, match="exclude account and strategy"):
        ZmqMarketSubscriber(
            "tcp://127.0.0.1:12345",
            _identity(),
            WireScope(execution_domain_ref="public:market", account_ref="private-account"),
            credentials=client_credentials,
        )


def test_publisher_rejects_wrong_event_identity_schema_scope_and_size() -> None:
    server_credentials, client_public, _client_credentials = _curve_credentials()
    publisher = _new_publisher({client_public: "audience-a"}, server_credentials)
    try:
        assert publisher.endpoint.startswith("tcp://127.0.0.1:")
        assert publisher.try_publish(_event()) is True
        assert publisher.publish(_event()) is None
        with pytest.raises(ValueError, match="identity"):
            publisher.publish(_event(identity=_identity(principal="other-hub")))
        with pytest.raises(ValueError, match="scope"):
            publisher.publish(_event(scope=_scope("private:account-a")))
        with pytest.raises(ValueError, match="schema or operation"):
            publisher.publish(_event(operation="market.snapshot"))
        with pytest.raises(ValueError, match="subscription key"):
            publisher.publish(_event(payload={"key": {"channel": "ticker"}, "data": {}}))
        mismatched_stream = _event()
        mismatched_stream = WireEnvelope(
            header=replace(mismatched_stream.header, stream_id="market-wrong"),
            payload=dict(mismatched_stream.payload),
        )
        with pytest.raises(ValueError, match="stream"):
            publisher.publish(mismatched_stream)
        with pytest.raises(ValueError, match="data must be an object"):
            publisher.publish(_event(payload={"key": _key().to_dict(), "data": "invalid"}))
        with pytest.raises(ValueError, match="exactly key and data"):
            publisher.publish(_event(payload={"key": _key().to_dict(), "data": {}, "extra": True}))

        raw_socket = publisher._socket

        class BackpressuredSocket:
            def send(self, *_args: Any, **_kwargs: Any) -> None:
                raise zmq.Again()

        publisher._socket = BackpressuredSocket()
        assert publisher.try_publish(_event()) is False
        publisher._socket = raw_socket
    finally:
        publisher.close()

    small = ZmqMarketPublisher(
        "tcp://127.0.0.1:*",
        _identity(),
        _scope(),
        {client_public: "audience-a"},
        credentials=server_credentials,
        max_message_bytes=512,
    )
    try:
        large = _event(payload={"key": _key().to_dict(), "data": {"raw": "x" * 1000}})
        with pytest.raises(ValueError):
            small.publish(large)
    finally:
        small.close()


def test_authenticated_loopback_pub_sub_delivers_neutral_market_envelope() -> None:
    server_credentials, client_public, client_credentials = _curve_credentials()
    publisher = _new_publisher({client_public: "audience-a"}, server_credentials)
    subscriber = _new_subscriber(publisher.endpoint, client_credentials)
    try:
        assert isinstance(publisher, EventPublisher)
        assert isinstance(subscriber, EventSubscriber)
        (event,) = _publish_until_received(publisher, (subscriber,))
        assert event.header.identity == _identity()
        assert event.header.scope == _scope()
        assert event.header.schema_id == MARKET_EVENT_SCHEMA
        assert event.header.operation == MARKET_EVENT_OPERATION
        assert event.payload["key"] == _key().to_dict()
        assert event.payload["data"] == {"last": 65000.25}
    finally:
        subscriber.close()
        publisher.close()


def test_wrong_curve_credentials_receive_no_event() -> None:
    server_credentials, allowed_public, allowed_credentials = _curve_credentials()
    denied_public, denied_secret = zmq.curve_keypair()
    denied_credentials = CurveClientCredentials(
        server_credentials.public_key,
        denied_public,
        denied_secret,
    )
    publisher = _new_publisher({allowed_public: "allowed"}, server_credentials)
    allowed = _new_subscriber(publisher.endpoint, allowed_credentials)
    denied = _new_subscriber(publisher.endpoint, denied_credentials)
    try:
        deadline = time.monotonic() + 4.0
        delivered = None
        sequence = 1
        while time.monotonic() < deadline:
            assert publisher.try_publish(_event(sequence=sequence))
            sequence += 1
            delivered = allowed.receive(timeout=0.025)
            assert denied.receive(timeout_ms=0) is None
            if delivered is not None:
                break
        assert delivered is not None
        assert denied.receive(timeout_ms=50) is None
    finally:
        denied.close()
        allowed.close()
        publisher.close()


def test_publisher_recreation_revokes_old_curve_audience_on_same_endpoint() -> None:
    server_credentials, revoked_public, revoked_credentials = _curve_credentials()
    survivor_public, survivor_secret = zmq.curve_keypair()
    survivor_credentials = CurveClientCredentials(
        server_credentials.public_key,
        survivor_public,
        survivor_secret,
    )
    initial_principals = {revoked_public: "revoked", survivor_public: "survivor"}
    publisher = _new_publisher(initial_principals, server_credentials)
    endpoint = publisher.endpoint
    revoked = _new_subscriber(endpoint, revoked_credentials)
    survivor = _new_subscriber(endpoint, survivor_credentials)
    try:
        _publish_until_received(publisher, (revoked, survivor))
        while revoked.receive(timeout_ms=0) is not None:
            pass
        while survivor.receive(timeout_ms=0) is not None:
            pass
        publisher.close()

        replacement = _new_publisher(
            {survivor_public: "survivor"},
            server_credentials,
            endpoint=endpoint,
        )
        try:
            deadline = time.monotonic() + 4.0
            survivor_received = False
            sequence = 100
            while time.monotonic() < deadline and not survivor_received:
                assert replacement.try_publish(_event(sequence=sequence))
                sequence += 1
                survivor_received = survivor.receive(timeout=0.025) is not None
                assert revoked.receive(timeout_ms=0) is None
            assert survivor_received, "authorized subscriber did not reconnect to replacement"
            assert revoked.receive(timeout_ms=75) is None
        finally:
            replacement.close()
    finally:
        if not publisher._closed:
            publisher.close()
        revoked.close()
        survivor.close()


class _FakeMultipartSocket:
    def __init__(self, messages: list[list[bytes]]) -> None:
        self.messages = deque(messages)
        self.active: list[bytes] | None = None
        self.offset = 0
        self.receive_count = 0
        self.poll_timeouts: list[int | None] = []

    def poll(self, timeout_ms: int | None, _flags: int) -> int:
        self.poll_timeouts.append(timeout_ms)
        return int(self.active is not None or bool(self.messages))

    def recv(self, *, flags: int, copy: bool) -> bytes:
        assert flags == zmq.NOBLOCK
        assert copy is False
        if self.active is None:
            self.active = self.messages.popleft()
            self.offset = 0
        result = self.active[self.offset]
        self.offset += 1
        self.receive_count += 1
        if self.offset == len(self.active):
            self.active = None
            self.offset = 0
        return result

    def getsockopt(self, option: int) -> int:
        assert option == zmq.RCVMORE
        return int(self.active is not None)


def _fake_subscriber(socket_object: _FakeMultipartSocket, *, max_message_bytes: int = 1024):
    subscriber = object.__new__(ZmqMarketSubscriber)
    subscriber._endpoint = "tcp://127.0.0.1:1"
    subscriber.endpoint = subscriber._endpoint
    subscriber._expected_peer = _identity()
    subscriber._expected_scope = _scope()
    subscriber._high_water_mark = 10
    subscriber._max_message_bytes = max_message_bytes
    subscriber._wire_version = market_v2.MARKET_WIRE_VERSION_LEGACY
    subscriber._subscription_key = None
    subscriber._topic = None
    subscriber._credentials = None
    subscriber._owner_thread = threading.get_ident()
    subscriber._closed = False
    subscriber._close_pending = False
    subscriber._context = None
    subscriber._socket = socket_object
    subscriber._receiver = market_v2._BoundedMultipartReceiver(socket_object)
    return subscriber


def test_subscriber_drops_oversized_malformed_multipart_and_foreign_scope_frames() -> None:
    valid = _event()
    valid_bytes = encode_envelope(valid)
    messages = [
        [b"x" * 2049],
        [b"{not-json"],
        [encode_envelope(_event(scope=_scope("other-scope")))],
        [encode_envelope(_event(identity=_identity(principal="other-hub")))],
        [encode_envelope(_event(schema_version=2))],
        [valid_bytes, b"second-frame"],
        [valid_bytes],
    ]
    socket_object = _FakeMultipartSocket(messages)
    subscriber = _fake_subscriber(socket_object, max_message_bytes=2048)

    for _ in range(6):
        assert subscriber.receive(timeout=0) is None
    received = subscriber.receive(timeout=0)
    assert received == valid
    assert socket_object.receive_count == 8


def test_bounded_multipart_drain_continues_on_later_receive_call() -> None:
    multipart = [b""] * 5000
    valid_bytes = encode_envelope(_event())
    socket_object = _FakeMultipartSocket([multipart, [valid_bytes]])
    receiver = market_v2._BoundedMultipartReceiver(socket_object)

    assert receiver.receive() is None
    assert socket_object.receive_count <= market_v2.MAX_DRAIN_FRAMES_PER_CALL + 1
    assert receiver._discarding is True

    while receiver._discarding:
        assert receiver.receive() is None
    assert socket_object.receive_count == len(multipart)
    frame = receiver.receive()
    assert frame is not None
    assert bytes(frame) == valid_bytes


def test_subscriber_timeout_seconds_and_compatibility_alias_are_bounded() -> None:
    socket_object = _FakeMultipartSocket([])
    subscriber = _fake_subscriber(socket_object)

    assert subscriber.receive(timeout=0) is None
    assert socket_object.poll_timeouts[-1] == 0
    assert subscriber.receive(timeout=0.0001) is None
    assert socket_object.poll_timeouts[-1] == 1
    assert subscriber.receive(timeout=1.001) is None
    assert socket_object.poll_timeouts[-1] == 1001
    assert subscriber.receive(timeout_ms=25) is None
    assert socket_object.poll_timeouts[-1] == 25
    assert subscriber.receive(timeout=None) is None
    assert socket_object.poll_timeouts[-1] is None

    with pytest.raises(ValueError, match="only one"):
        subscriber.receive(timeout=0, timeout_ms=0)
    for invalid in (-1, float("nan"), float("inf"), True, 2_147_484):
        with pytest.raises(ValueError, match="timeout must"):
            subscriber.receive(timeout=invalid)
    for invalid in (-1, True, 2_147_483_648):
        with pytest.raises(ValueError, match="timeout_ms must"):
            subscriber.receive(timeout_ms=invalid)


def test_transports_enforce_owner_thread_and_close_is_idempotent() -> None:
    server_credentials, client_public, client_credentials = _curve_credentials()
    publisher = _new_publisher({client_public: "audience-a"}, server_credentials)
    subscriber = _new_subscriber(publisher.endpoint, client_credentials)
    errors: queue.Queue[BaseException] = queue.Queue()

    def wrong_thread() -> None:
        for operation in (publisher.close, lambda: subscriber.receive(timeout=0)):
            try:
                operation()
            except BaseException as exc:
                errors.put(exc)

    worker = threading.Thread(target=wrong_thread)
    worker.start()
    worker.join(timeout=2)
    try:
        assert not worker.is_alive()
        first, second = errors.get(timeout=1), errors.get(timeout=1)
        assert isinstance(first, RuntimeError) and "owning thread" in str(first)
        assert isinstance(second, RuntimeError) and "owning thread" in str(second)
    finally:
        subscriber.close()
        publisher.close()
        subscriber.close()
        publisher.close()


def test_publisher_startup_cleanup_failure_preserves_partial_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_credentials, client_public, _client_credentials = _curve_credentials()
    events: list[str] = []

    class FakeSocket:
        def __init__(self) -> None:
            self.close_calls = 0

        def setsockopt(self, *_args: Any) -> None:
            pass

        def bind(self, _endpoint: str) -> None:
            events.append("bind")
            raise RuntimeError("injected bind failure")

        def close(self, *, linger: int) -> None:
            assert linger == 0
            self.close_calls += 1
            events.append("socket.close")

    class FakeContext:
        def __init__(self) -> None:
            self.socket_object = FakeSocket()
            self.term_calls = 0

        def socket(self, _socket_type: int) -> FakeSocket:
            return self.socket_object

        def term(self) -> None:
            self.term_calls += 1
            events.append("context.term")

    class FakeAuthenticator:
        def __init__(self, _context: FakeContext) -> None:
            self.stop_calls = 0

        def configure_curve_callback(self, **_kwargs: Any) -> None:
            pass

        def start(self) -> None:
            events.append("auth.start")

        def stop(self) -> None:
            self.stop_calls += 1
            if self.stop_calls == 1:
                events.append("auth.stop.failed")
                raise RuntimeError("injected authenticator stop failure")
            events.append("auth.stop")

    context = FakeContext()
    authenticator_holder: dict[str, FakeAuthenticator] = {}

    def make_context() -> FakeContext:
        return context

    def make_authenticator(ctx: FakeContext) -> FakeAuthenticator:
        authenticator = FakeAuthenticator(ctx)
        authenticator_holder["value"] = authenticator
        return authenticator

    monkeypatch.setattr(market_v2.zmq, "Context", make_context)
    monkeypatch.setattr(market_v2, "ThreadAuthenticator", make_authenticator)
    with pytest.raises(ServiceTransportStartupCleanupError) as caught:
        _new_publisher({client_public: "audience-a"}, server_credentials)

    publisher = caught.value.transport
    assert isinstance(publisher, ZmqMarketPublisher)
    assert publisher._close_pending is True
    assert publisher._closed is False
    assert publisher._socket is context.socket_object
    assert publisher._context is context
    assert publisher._authenticator is authenticator_holder["value"]
    assert events[-1] == "auth.stop.failed"
    with pytest.raises(RuntimeError, match="publisher is closed"):
        publisher.try_publish(_event())

    publisher.close()
    assert publisher._closed is True
    assert events[-3:] == ["auth.stop", "socket.close", "context.term"]


def test_subscriber_startup_cleanup_failure_preserves_partial_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _server_credentials, _client_public, client_credentials = _curve_credentials()

    class FakeSocket:
        def __init__(self) -> None:
            self.close_calls = 0

        def setsockopt(self, *_args: Any) -> None:
            pass

        def connect(self, _endpoint: str) -> None:
            raise RuntimeError("injected connect failure")

        def close(self, *, linger: int) -> None:
            assert linger == 0
            self.close_calls += 1
            if self.close_calls == 1:
                raise RuntimeError("injected socket close failure")

    class FakeContext:
        def __init__(self) -> None:
            self.socket_object = FakeSocket()
            self.term_calls = 0

        def socket(self, _socket_type: int) -> FakeSocket:
            return self.socket_object

        def term(self) -> None:
            self.term_calls += 1

    context = FakeContext()
    monkeypatch.setattr(market_v2.zmq, "Context", lambda: context)
    with pytest.raises(ServiceTransportStartupCleanupError) as caught:
        _new_subscriber("tcp://127.0.0.1:1", client_credentials)

    subscriber = caught.value.transport
    assert isinstance(subscriber, ZmqMarketSubscriber)
    assert subscriber._close_pending is True
    assert subscriber._closed is False
    assert subscriber._socket is context.socket_object
    assert subscriber._receiver is not None
    assert subscriber._context is context
    with pytest.raises(RuntimeError, match="subscriber is closed"):
        subscriber.receive(timeout=0)

    subscriber.close()
    assert subscriber._closed is True
    assert subscriber._socket is None
    assert subscriber._receiver is None
    assert subscriber._context is None
    assert context.term_calls == 1


def test_close_failures_retain_only_unresolved_resources_for_retry() -> None:
    server_credentials, client_public, client_credentials = _curve_credentials()
    publisher = _new_publisher({client_public: "audience-a"}, server_credentials)
    raw_authenticator = publisher._authenticator

    class FailOnceAuthenticator:
        def __init__(self) -> None:
            self.calls = 0

        def stop(self) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("injected stop failure")
            raw_authenticator.stop()

    failing_authenticator = FailOnceAuthenticator()
    publisher._authenticator = failing_authenticator
    raw_socket = publisher._socket
    raw_context = publisher._context
    try:
        with pytest.raises(RuntimeError, match="injected stop failure"):
            publisher.close()
        assert publisher._close_pending is True
        assert publisher._socket is raw_socket
        assert publisher._context is raw_context
        publisher.close()
        assert publisher._closed is True
        assert failing_authenticator.calls == 2
    finally:
        if not publisher._closed:
            publisher.close()

    subscriber = _new_subscriber("tcp://127.0.0.1:1", client_credentials)
    raw_sub_socket = subscriber._socket
    raw_sub_context = subscriber._context

    class FailOnceSocket:
        def __init__(self) -> None:
            self.calls = 0

        def close(self, *, linger: int) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("injected subscriber close failure")
            raw_sub_socket.close(linger=linger)

    failing_socket = FailOnceSocket()
    subscriber._socket = failing_socket
    try:
        with pytest.raises(RuntimeError, match="injected subscriber close failure"):
            subscriber.close()
        assert subscriber._close_pending is True
        assert subscriber._socket is failing_socket
        assert subscriber._receiver is not None
        assert subscriber._context is raw_sub_context
        subscriber.close()
        assert subscriber._closed is True
        assert subscriber._socket is None
        assert subscriber._receiver is None
        assert subscriber._context is None
    finally:
        if not subscriber._closed:
            subscriber._socket = raw_sub_socket
            subscriber.close()


def test_denied_or_invalid_configuration_does_not_echo_credentials() -> None:
    server_credentials, client_public, _client_credentials = _curve_credentials()
    bad_credentials = CurveServerCredentials(
        server_credentials.public_key, server_credentials.secret_key
    )
    assert "secret" not in repr(bad_credentials).lower()

    with pytest.raises(MarketTransportError):
        validate_publisher_configuration(
            "ipc:///tmp/not-allowed",
            _identity(),
            _scope(),
            {client_public: "audience-a"},
            credentials=server_credentials,
        )
