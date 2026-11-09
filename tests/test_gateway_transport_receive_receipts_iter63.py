"""Socket read receipts bind to validated messages and never leak prior frames."""
import os
import threading
import time

import pytest
import zmq

from bt_api_base.service_protocol import WireRole
from bt_api_transport_zmq.market_v2 import MarketFrameReceipt
from bt_api_transport_zmq.server import CurveServerCredentials
from bt_api_transport_zmq.service_v2 import ServiceReplyReceipt, ZmqServiceClient
from test_market_v2 import _curve_credentials, _new_publisher, _new_subscriber, _publish_until_received
from test_service_v2 import _client_credentials, _identity, _join_server, _request, _server_thread


def test_pub_receipt_is_bound_to_validated_frame_and_cleared():
    server, client_public, credentials = _curve_credentials()
    publisher = _new_publisher({client_public: "principal"}, server)
    subscriber = _new_subscriber(publisher.endpoint, credentials)
    try:
        before_wall, before_mono = time.time_ns(), time.monotonic_ns()
        event, = _publish_until_received(publisher, (subscriber,))
        after_wall, after_mono = time.time_ns(), time.monotonic_ns()
        receipt = subscriber.last_receive_receipt
        assert type(receipt) is MarketFrameReceipt
        assert (receipt.stream_id, receipt.stream_epoch, receipt.sequence, receipt.message_id) == (
            event.header.stream_id, event.header.stream_epoch, event.header.sequence, event.header.message_id
        )
        assert before_wall <= receipt.received_wall_ns <= after_wall
        assert before_mono <= receipt.received_monotonic_ns <= after_mono
        assert receipt.pid == os.getpid() and receipt.thread_id == threading.get_ident()
        errors = []
        def other_thread():
            try:
                subscriber.last_receive_receipt
            except Exception as exc:
                errors.append(type(exc))
        t = threading.Thread(target=other_thread)
        t.start(); t.join()
        assert errors == [RuntimeError]
        # A new attempt never exposes a stale receipt, regardless of whether it
        # yields another valid queued event or returns no event.
        next_event = subscriber.receive(timeout=0)
        next_receipt = subscriber.last_receive_receipt
        assert (next_event is None) == (next_receipt is None)
        if next_event is not None:
            assert next_receipt.message_id == next_event.header.message_id
    finally:
        subscriber.close()
        publisher.close()
    assert subscriber.last_receive_receipt is None


def test_rpc_receipt_is_bound_to_authenticated_reply_and_cleared():
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=lambda *_: {"ok": True, "code": "OK", "result": {}},
        serve_timeouts=(2000,),
    )
    client = ZmqServiceClient(server["endpoint"], _identity(WireRole.SERVICE, "service-a", "gateway-a"), credentials=credentials)
    request = _request("receipt-validated")
    try:
        before_wall, before_mono = time.time_ns(), time.monotonic_ns()
        reply = client.request(request, timeout=4)
        after_wall, after_mono = time.time_ns(), time.monotonic_ns()
        receipt = client.last_reply_receipt
        assert type(receipt) is ServiceReplyReceipt
        assert receipt.request_message_id == receipt.correlation_id == request.header.message_id
        assert receipt.reply_message_id == reply.header.message_id
        assert receipt.operation == reply.header.operation
        assert before_wall <= receipt.received_wall_ns <= after_wall
        assert before_mono <= receipt.received_monotonic_ns <= after_mono
        assert receipt.pid == os.getpid() and receipt.thread_id == threading.get_ident()
        # Rejected duplicate cannot expose a receipt from the previous call.
        with pytest.raises(ValueError):
            client.request(request, timeout=1)
        assert client.last_reply_receipt is None
    finally:
        client.close()
        _join_server(server)
    assert client.last_reply_receipt is None
