"""Offline CURVE checks for the opt-in per-stream audience boundary.

The raw sockets deliberately bypass the SDK subscriber's local topic checks:
the security boundary must be enforced at the publisher, not by the receiver.
"""

from __future__ import annotations

import time

import pytest
import zmq
from bt_api_base.service_protocol import decode_envelope
from test_market_v2_topic_filter import _IDENTITY, _SCOPE, _curve_client, _event, _key

from bt_api_transport_zmq.market_v2 import ZmqMarketPublisher, _market_topic_for_stream_id
from bt_api_transport_zmq.server import CurveServerCredentials


def _raw_subscriber(context, endpoint, credentials, subscriptions):
    socket = context.socket(zmq.SUB)
    socket.linger = 0
    socket.curve_serverkey = credentials.server_key
    socket.curve_publickey = credentials.public_key
    socket.curve_secretkey = credentials.secret_key
    for subscription in subscriptions:
        socket.setsockopt(zmq.SUBSCRIBE, subscription)
    socket.connect(endpoint)
    return socket


def test_manual_xpub_filters_unauthorized_exact_and_broad_topics_with_curve():
    server_public, server_secret = zmq.curve_keypair()
    public_a, credentials_a = _curve_client(server_public)
    public_b, credentials_b = _curve_client(server_public)
    key_a, key_b = _key("ACL-A"), _key("ACL-B")
    topic_a = _market_topic_for_stream_id(key_a.stream_id)
    topic_b = _market_topic_for_stream_id(key_b.stream_id)
    publisher = ZmqMarketPublisher(
        "tcp://127.0.0.1:*",
        _IDENTITY,
        _SCOPE,
        {public_a: "principal-a", public_b: "principal-b"},
        credentials=CurveServerCredentials(server_public, server_secret),
        wire_version=2,
        stream_grants={"principal-a": {key_a.stream_id}, "principal-b": {key_b.stream_id}},
    )
    context = zmq.Context()
    a = _raw_subscriber(context, publisher.endpoint, credentials_a, (topic_a, topic_b, b""))
    b = _raw_subscriber(context, publisher.endpoint, credentials_b, (topic_b, topic_a))
    try:
        received_a, received_b = set(), set()
        deadline = time.monotonic() + 4
        sequence = 0
        while time.monotonic() < deadline:
            sequence += 1
            assert publisher.try_publish(_event(key_a, sequence))
            assert publisher.try_publish(_event(key_b, sequence))
            for socket, received in ((a, received_a), (b, received_b)):
                while socket.poll(1, zmq.POLLIN):
                    topic, _ = socket.recv_multipart()
                    received.add(topic)
            if received_a and received_b and publisher.denied_subscriptions >= 3:
                break
        assert received_a == {topic_a}
        assert received_b == {topic_b}
        assert publisher.denied_subscriptions >= 3
        # Keep publishing after both subscriptions are registered; an
        # authorized subscription on B must not authorize A's B request.
        for sequence in range(100):
            assert publisher.try_publish(_event(key_a, 10_000 + sequence))
            assert publisher.try_publish(_event(key_b, 10_000 + sequence))
            for socket, expected in ((a, topic_a), (b, topic_b)):
                while socket.poll(1, zmq.POLLIN):
                    topic, _ = socket.recv_multipart()
                    assert topic == expected
    finally:
        a.close()
        b.close()
        context.term()
        publisher.close()


def test_reconfigure_cannot_remove_a_frame_already_in_the_client_queue():
    server_public, server_secret = zmq.curve_keypair()
    public, credentials = _curve_client(server_public)
    key = _key("ACL-QUEUED")
    topic = _market_topic_for_stream_id(key.stream_id)
    publisher = ZmqMarketPublisher(
        "tcp://127.0.0.1:*",
        _IDENTITY,
        _SCOPE,
        {public: "principal"},
        credentials=CurveServerCredentials(server_public, server_secret),
        wire_version=2,
        stream_grants={"principal": {key.stream_id}},
    )
    context = zmq.Context()
    subscriber = _raw_subscriber(context, publisher.endpoint, credentials, (topic,))
    try:
        deadline = time.monotonic() + 4
        sequence = 0
        while not subscriber.poll(1, zmq.POLLIN) and time.monotonic() < deadline:
            sequence += 1
            assert publisher.try_publish(_event(key, sequence))
        assert subscriber.poll(100, zmq.POLLIN)
        # Publisher revocation cannot erase data already in another process.
        publisher.reconfigure({public: "principal"}, stream_grants={"principal": set()})
        assert subscriber.poll(100, zmq.POLLIN)
        assert subscriber.recv_multipart()[0] == topic
    finally:
        subscriber.close()
        context.term()
        publisher.close()


def test_reconfigure_startup_failure_keeps_publisher_closed_to_writes(monkeypatch):
    server_public, server_secret = zmq.curve_keypair()
    public, _ = _curve_client(server_public)
    key = _key("ACL-FAILURE")
    publisher = ZmqMarketPublisher(
        "tcp://127.0.0.1:*",
        _IDENTITY,
        _SCOPE,
        {public: "principal"},
        credentials=CurveServerCredentials(server_public, server_secret),
        wire_version=2,
        stream_grants={"principal": {key.stream_id}},
    )
    try:

        def fail_open(_endpoint):
            raise RuntimeError("synthetic bind failure")

        monkeypatch.setattr(publisher, "_open", fail_open)
        with pytest.raises(RuntimeError, match="synthetic bind failure"):
            publisher.reconfigure({public: "principal"}, stream_grants={"principal": set()})
        with pytest.raises(RuntimeError, match="publisher is closed"):
            publisher.try_publish(_event(key, 1))
    finally:
        publisher.close()


def test_reconfigure_reauthorizes_connections_before_new_publications():
    server_public, server_secret = zmq.curve_keypair()
    allowed_public, allowed_credentials = _curve_client(server_public)
    revoked_public, revoked_credentials = _curve_client(server_public)
    key = _key("ACL-RECONFIGURE")
    topic = _market_topic_for_stream_id(key.stream_id)
    audience = {allowed_public: "allowed", revoked_public: "revoked"}
    publisher = ZmqMarketPublisher(
        "tcp://127.0.0.1:*",
        _IDENTITY,
        _SCOPE,
        audience,
        credentials=CurveServerCredentials(server_public, server_secret),
        wire_version=2,
        stream_grants={"allowed": {key.stream_id}, "revoked": {key.stream_id}},
    )
    context = zmq.Context()
    allowed = _raw_subscriber(context, publisher.endpoint, allowed_credentials, (topic,))
    revoked = _raw_subscriber(context, publisher.endpoint, revoked_credentials, (topic,))
    try:
        received = [False, False]
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and not all(received):
            assert publisher.try_publish(_event(key, 1))
            for index, socket in enumerate((allowed, revoked)):
                if socket.poll(1, zmq.POLLIN):
                    socket.recv_multipart()
                    received[index] = True
        assert all(received), "both clients must be connected before the revoke"
        publisher.reconfigure(
            audience, stream_grants={"allowed": {key.stream_id}, "revoked": set()}
        )
        # Messages previously delivered cannot be recalled; drain them before
        # checking only events published after the transport was replaced.
        for socket in (allowed, revoked):
            while socket.poll(0, zmq.POLLIN):
                socket.recv_multipart()
        seen_allowed = False
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            assert publisher.try_publish(_event(key, 2))
            if allowed.poll(5, zmq.POLLIN):
                allowed.recv_multipart()
                seen_allowed = True
            while revoked.poll(0, zmq.POLLIN):
                _, encoded = revoked.recv_multipart()
                # Pre-revocation frames may still arrive asynchronously.
                assert decode_envelope(encoded).header.sequence == 1
            if seen_allowed and publisher.denied_subscriptions >= 1:
                break
        assert seen_allowed, "remaining authorized client must reconnect"
        assert publisher.denied_subscriptions >= 1, "revoked client must be denied on reconnect"
        while revoked.poll(100, zmq.POLLIN):
            _, encoded = revoked.recv_multipart()
            assert decode_envelope(encoded).header.sequence == 1
    finally:
        allowed.close()
        revoked.close()
        context.term()
        publisher.close()
