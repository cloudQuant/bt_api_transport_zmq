from __future__ import annotations

import queue
import socket
import threading
import time
from contextlib import suppress
from typing import Any, Optional

import pytest
import zmq
from bt_api_base.service_protocol import (
    WIRE_PROTOCOL_VERSION,
    RequestReplyTransport,
    WireEnvelope,
    WireHeader,
    WireIdentity,
    WireMessageKind,
    WireRole,
    WireScope,
    decode_envelope,
    encode_envelope,
)
from nacl.bindings import crypto_box_SEALBYTES
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from zmq.auth.thread import ThreadAuthenticator
from zmq.utils import z85

from bt_api_transport_zmq import service_v2
from bt_api_transport_zmq.server import CurveClientCredentials, CurveServerCredentials
from bt_api_transport_zmq.service_v2 import (
    RequestNotSentError,
    RequestOutcomeUnknownError,
    ServiceTransportError,
    ServiceTransportStartupCleanupError,
    ZmqServiceClient,
    ZmqServiceServer,
    _make_reply,
    validate_service_server_configuration,
)

_SEALED_REPLY_PREFIX = b"BTAPI-ZMQ-REPLY-V2\x00"


def _identity(role: WireRole, principal_ref: str, actor_ref: str) -> WireIdentity:
    return WireIdentity(role=role, principal_ref=principal_ref, actor_ref=actor_ref)


def _request(message_id: str, *, principal_ref: str = "claimed-principal") -> WireEnvelope:
    header = WireHeader(
        protocol_version=WIRE_PROTOCOL_VERSION,
        kind=WireMessageKind.REQUEST,
        message_id=message_id,
        correlation_id=None,
        identity=_identity(WireRole.STRATEGY_CLIENT, principal_ref, "actor-a"),
        scope=WireScope(execution_domain_ref="execution-a", account_ref="account-a"),
        operation="account.snapshot",
        schema_id="account.snapshot.request",
        schema_version=1,
        sent_at_utc="2026-10-13T00:00:00Z",
        owner_epoch="owner-1",
    )
    return WireEnvelope(header=header, payload={"request": message_id})


def _server_thread(
    *,
    server_credentials: CurveServerCredentials,
    principals: dict[bytes, str],
    handler: Any,
    serve_timeouts: tuple[int, ...],
    endpoint: str = "tcp://127.0.0.1:*",
    identity: Optional[WireIdentity] = None,  # noqa: UP045 -- Python 3.9 compatibility.
    max_message_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "ready": threading.Event(),
        "progress": queue.Queue(),
        "errors": queue.Queue(),
    }
    service_identity = identity or _identity(WireRole.SERVICE, "service-a", "gateway-a")

    def run() -> None:
        server = None
        try:
            server = ZmqServiceServer(
                endpoint,
                service_identity,
                principals,
                handler,
                credentials=server_credentials,
                max_message_bytes=max_message_bytes,
            )
            state["server"] = server
            state["endpoint"] = server.endpoint
            state["ready"].set()
            for index, timeout_ms in enumerate(serve_timeouts):
                state["progress"].put((index, server.serve_once(timeout_ms)))
        except BaseException as exc:
            state["errors"].put(exc)
            state["ready"].set()
        finally:
            if server is not None:
                try:
                    server.close()
                except BaseException as exc:
                    state["errors"].put(exc)

    state["thread"] = threading.Thread(target=run, name="service-v2-test-server")
    state["thread"].start()
    assert state["ready"].wait(3), "service server did not bind"
    assert state["errors"].empty(), "service server failed during startup"
    return state


def _wait_step(state: dict[str, Any], index: int, *, handled: bool = True) -> None:
    assert state["progress"].get(timeout=3) == (index, handled)


def _join_server(state: dict[str, Any]) -> None:
    state["thread"].join(timeout=3)
    assert not state["thread"].is_alive(), "service server did not stop"
    assert state["errors"].empty(), "service server failed"


def _client_credentials(
    server_public_key: bytes,
) -> tuple[bytes, CurveClientCredentials]:
    client_public_key, client_secret_key = zmq.curve_keypair()
    return client_public_key, CurveClientCredentials(
        server_key=server_public_key,
        public_key=client_public_key,
        secret_key=client_secret_key,
    )


def _raw_curve_client(
    endpoint: str,
    credentials: CurveClientCredentials,
    *,
    identity: bytes,
) -> tuple[zmq.Context, zmq.Socket]:
    context = zmq.Context()
    client = context.socket(zmq.DEALER)
    client.setsockopt(zmq.LINGER, 0)
    client.setsockopt(zmq.IMMEDIATE, 1)
    client.setsockopt(zmq.IDENTITY, identity)
    client.curve_serverkey = credentials.server_key
    client.curve_publickey = credentials.public_key
    client.curve_secretkey = credentials.secret_key
    client.connect(endpoint)
    assert client.poll(2000, zmq.POLLOUT), "CURVE client did not authenticate"
    return context, client


def _send_raw(client: zmq.Socket, raw: bytes) -> None:
    client.send(raw, flags=zmq.NOBLOCK)


def _send_raw_multipart(client: zmq.Socket, frames: list[bytes]) -> None:
    client.send_multipart(frames, flags=zmq.NOBLOCK)


def _seal_for_client(encoded: bytes, client_public_key: bytes) -> bytes:
    ciphertext = SealedBox(PublicKey(z85.decode(client_public_key))).encrypt(encoded)
    assert len(ciphertext) == len(encoded) + crypto_box_SEALBYTES
    return _SEALED_REPLY_PREFIX + ciphertext


def _decode_sealed_reply(frame: bytes, credentials: CurveClientCredentials) -> WireEnvelope:
    assert frame.startswith(_SEALED_REPLY_PREFIX)
    assert len(frame) >= len(_SEALED_REPLY_PREFIX) + crypto_box_SEALBYTES
    private_key = PrivateKey(z85.decode(credentials.secret_key))
    plaintext = SealedBox(private_key).decrypt(frame[len(_SEALED_REPLY_PREFIX) :])
    return decode_envelope(plaintext)


def _reply(request: WireEnvelope, identity: WireIdentity, payload: dict[str, Any]) -> WireEnvelope:
    header = request.header
    return WireEnvelope(
        header=WireHeader(
            protocol_version=WIRE_PROTOCOL_VERSION,
            kind=WireMessageKind.REPLY,
            message_id="r" * 32,
            correlation_id=header.message_id,
            identity=identity,
            scope=header.scope,
            operation=header.operation,
            schema_id=header.schema_id,
            schema_version=header.schema_version,
            sent_at_utc="2026-10-13T00:00:00Z",
            owner_epoch=header.owner_epoch,
        ),
        payload=payload,
    )


class _SingleClientCurveAcl:
    def __init__(self, public_key: bytes) -> None:
        self._public_key = public_key

    def callback(self, domain: str, client_key: bytes) -> bool:
        return domain == "bt-api-service-v2" and client_key == self._public_key


def _multipart_reply_server(
    server_public: bytes,
    server_secret: bytes,
    allowed_client_public: bytes,
    *,
    plaintext_first_reply: bool = False,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "ready": threading.Event(),
        "errors": queue.Queue(),
    }
    service_identity = _identity(WireRole.SERVICE, "service-a", "gateway-a")

    def run() -> None:
        context = zmq.Context()
        server = context.socket(zmq.ROUTER)
        authenticator = ThreadAuthenticator(context)
        try:
            server.setsockopt(zmq.LINGER, 0)
            server.setsockopt(zmq.ROUTER_MANDATORY, 1)
            server.zap_domain = b"bt-api-service-v2"
            server.curve_publickey = server_public
            server.curve_secretkey = server_secret
            server.curve_server = True
            authenticator.configure_curve_callback(
                domain="bt-api-service-v2",
                credentials_provider=_SingleClientCurveAcl(allowed_client_public),
            )
            authenticator.start()
            server.bind("tcp://127.0.0.1:*")
            state["endpoint"] = server.getsockopt(zmq.LAST_ENDPOINT).decode("utf-8")
            state["ready"].set()
            for index in range(2):
                if server.poll(3000, zmq.POLLIN) == 0:
                    raise AssertionError("client request was not received")
                frames = server.recv_multipart(copy=True)
                if len(frames) != 2:
                    raise AssertionError("client sent an unexpected multipart request")
                request = decode_envelope(frames[1])
                payload = {"ok": True, "code": "OK", "result": {"index": index}}
                encoded_envelope = encode_envelope(_reply(request, service_identity, payload))
                encoded = (
                    encoded_envelope
                    if plaintext_first_reply and index == 0
                    else _seal_for_client(encoded_envelope, allowed_client_public)
                )
                if index == 0:
                    if plaintext_first_reply:
                        server.send_multipart([frames[0], encoded])
                    else:
                        server.send_multipart([frames[0], encoded, b"extra-frame"])
                else:
                    server.send_multipart([frames[0], encoded])
        except BaseException as exc:
            state["errors"].put(exc)
            state["ready"].set()
        finally:
            try:
                authenticator.stop()
            except BaseException as exc:
                state["errors"].put(exc)
            server.close(linger=0)
            context.term()

    state["thread"] = threading.Thread(target=run, name="service-v2-multipart-reply-server")
    state["thread"].start()
    assert state["ready"].wait(3), "multipart reply server did not bind"
    assert state["errors"].empty(), "multipart reply server failed during startup"
    return state


def _join_custom_server(state: dict[str, Any]) -> None:
    state["thread"].join(timeout=4)
    assert not state["thread"].is_alive(), "custom CURVE server did not stop"
    assert state["errors"].empty(), "custom CURVE server failed"


def test_curve_authenticated_principal_overrides_forged_routing_and_header_claims() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, client_credentials = _client_credentials(server_public)
    seen: list[tuple[str, WireEnvelope]] = []

    def handler(principal_ref: str, request: WireEnvelope) -> dict[str, Any]:
        seen.append((principal_ref, request))
        return {"ok": True, "code": "OK", "result": {"accepted": True}}

    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=handler,
        serve_timeouts=(2000,),
    )
    client = ZmqServiceClient(
        server["endpoint"],
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=client_credentials,
    )
    assert isinstance(client, RequestReplyTransport)
    raw_context = None
    raw_client = None
    try:
        raw_context, raw_client = _raw_curve_client(
            server["endpoint"], client_credentials, identity=b"forged-router-principal"
        )
        _send_raw(raw_client, encode_envelope(_request("forged-claims")))
        assert raw_client.poll(2000, zmq.POLLIN)
        raw_reply = raw_client.recv()
        reply = _decode_sealed_reply(raw_reply, client_credentials)
        _wait_step(server, 0)
    finally:
        client.close()
        if raw_client is not None:
            raw_client.close(linger=0)
        if raw_context is not None:
            raw_context.term()
    _join_server(server)

    assert len(seen) == 1
    trusted_principal, received_request = seen[0]
    other_public, other_credentials = _client_credentials(server_public)
    other_private_key = PrivateKey(z85.decode(other_credentials.secret_key))
    assert other_public != client_credentials.public_key
    assert raw_reply.startswith(_SEALED_REPLY_PREFIX)
    with pytest.raises(CryptoError):
        SealedBox(other_private_key).decrypt(raw_reply[len(_SEALED_REPLY_PREFIX) :])
    assert trusted_principal == "trusted-principal"
    assert received_request.header.identity.principal_ref == "claimed-principal"
    assert reply.header.identity == _identity(WireRole.SERVICE, "service-a", "gateway-a")
    assert reply.header.correlation_id == "forged-claims"
    assert reply.header.scope == received_request.header.scope
    assert reply.header.operation == received_request.header.operation
    assert reply.header.schema_id == received_request.header.schema_id
    assert reply.header.schema_version == received_request.header.schema_version
    assert reply.header.owner_epoch == received_request.header.owner_epoch
    assert dict(reply.payload) == {"ok": True, "code": "OK", "result": {"accepted": True}}


def test_curve_acl_denies_unlisted_key_without_calling_handler() -> None:
    server_public, server_secret = zmq.curve_keypair()
    allowed_public, _ = _client_credentials(server_public)
    _unknown_public, unknown_credentials = _client_credentials(server_public)
    calls = []
    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={allowed_public: "trusted-principal"},
        handler=lambda principal, request: (
            calls.append((principal, request)) or {"ok": True, "code": "OK", "result": {}}
        ),
        serve_timeouts=(250,),
    )
    client = ZmqServiceClient(
        server["endpoint"],
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=unknown_credentials,
    )
    try:
        request = _request("denied-peer")
        with pytest.raises(RequestNotSentError) as caught:
            client.request(request, timeout=0.1)
        _wait_step(server, 0, handled=False)
        _join_server(server)

        assert caught.value.message_id == "denied-peer"
        assert caught.value.cause_code in {"send_timeout", "send_not_queued"}
        assert calls == []
    finally:
        client.close()


def test_request_not_sent_allows_same_id_after_server_becomes_available() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        endpoint = f"tcp://127.0.0.1:{listener.getsockname()[1]}"
    client = ZmqServiceClient(
        endpoint,
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=credentials,
    )
    request = _request("retry-after-not-sent")
    try:
        with pytest.raises(RequestNotSentError) as caught:
            client.request(request, timeout=0.1)
        assert caught.value.message_id == request.header.message_id
        assert caught.value.cause_code == "send_timeout"

        server = _server_thread(
            server_credentials=CurveServerCredentials(server_public, server_secret),
            principals={client_public: "trusted-principal"},
            handler=lambda *_: {"ok": True, "code": "OK", "result": {"accepted": True}},
            serve_timeouts=(2000,),
            endpoint=endpoint,
        )
        reply = client.request(request, timeout=4.0)
        _wait_step(server, 0)
        _join_server(server)
    finally:
        client.close()

    assert reply.header.correlation_id == request.header.message_id
    assert dict(reply.payload["result"]) == {"accepted": True}


def test_malformed_and_unsupported_version_messages_are_dropped() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    calls = []
    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=lambda principal, request: (
            calls.append((principal, request)) or {"ok": True, "code": "OK", "result": {}}
        ),
        serve_timeouts=(2000, 2000),
    )
    context, client = _raw_curve_client(server["endpoint"], credentials, identity=b"raw-client")
    try:
        _send_raw(client, b"not-json")
        _wait_step(server, 0)
        assert not client.poll(50, zmq.POLLIN)

        unsupported_version = encode_envelope(_request("old-version")).replace(
            b'"protocol_version":2', b'"protocol_version":1', 1
        )
        _send_raw(client, unsupported_version)
        _wait_step(server, 1)
        assert not client.poll(50, zmq.POLLIN)
    finally:
        client.close(linger=0)
        context.term()
    _join_server(server)
    assert calls == []


def test_server_boundedly_drains_excess_multipart_frames_then_handles_next_request() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    handled_ids = []

    def handler(principal: str, request: WireEnvelope) -> dict[str, Any]:
        handled_ids.append(request.header.message_id)
        return {"ok": True, "code": "OK", "result": {"processed": True}}

    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=handler,
        serve_timeouts=(2000, 2000, 2000, 2000),
    )
    context, client = _raw_curve_client(server["endpoint"], credentials, identity=b"many-frames")
    try:
        _send_raw_multipart(client, [b"malformed-body"] + [b"extra"] * 130)
        _wait_step(server, 0)
        _wait_step(server, 1)
        _wait_step(server, 2)
        assert not client.poll(50, zmq.POLLIN)

        _send_raw(client, encode_envelope(_request("valid-after-multipart")))
        assert client.poll(2000, zmq.POLLIN)
        reply = _decode_sealed_reply(client.recv(), credentials)
        _wait_step(server, 3)
    finally:
        client.close(linger=0)
        context.term()
    _join_server(server)

    assert handled_ids == ["valid-after-multipart"]
    assert reply.header.correlation_id == "valid-after-multipart"
    assert dict(reply.payload) == {"ok": True, "code": "OK", "result": {"processed": True}}


def test_unreachable_router_route_does_not_stop_following_service_requests() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    entered_handler = threading.Event()
    release_handler = threading.Event()
    handled_ids = []

    def handler(principal: str, request: WireEnvelope) -> dict[str, Any]:
        handled_ids.append(request.header.message_id)
        if request.header.message_id == "disconnect-after-dispatch":
            entered_handler.set()
            if not release_handler.wait(3):
                raise TimeoutError("test did not release handler")
        return {"ok": True, "code": "OK", "result": {"handled": True}}

    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=handler,
        serve_timeouts=(2000, 2000),
    )
    raw_context, raw_client = _raw_curve_client(
        server["endpoint"], credentials, identity=b"disconnecting-client"
    )
    _send_raw(raw_client, encode_envelope(_request("disconnect-after-dispatch")))
    assert entered_handler.wait(2), "service handler was not entered"
    raw_client.close(linger=0)
    raw_context.term()
    # Let ROUTER observe the disconnect before allowing the handler to return.
    time.sleep(0.15)
    release_handler.set()
    _wait_step(server, 0)

    client = ZmqServiceClient(
        server["endpoint"],
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=credentials,
    )
    try:
        reply = client.request(_request("normal-after-disconnect"), timeout=2.0)
    finally:
        client.close()
    _wait_step(server, 1)
    _join_server(server)

    assert handled_ids == ["disconnect-after-dispatch", "normal-after-disconnect"]
    assert reply.header.correlation_id == "normal-after-disconnect"


def test_delayed_reply_after_route_reuse_is_sealed_to_original_curve_principal() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_a_public, credentials_a = _client_credentials(server_public)
    client_b_public, credentials_b = _client_credentials(server_public)
    handler_entered = threading.Event()
    release_handler = threading.Event()
    handled = []

    def handler(principal: str, request: WireEnvelope) -> dict[str, Any]:
        handled.append((principal, request.header.message_id))
        if request.header.message_id == "request-from-a":
            handler_entered.set()
            if not release_handler.wait(3):
                raise TimeoutError("test did not release the service handler")
        return {"ok": True, "code": "OK", "result": {"recipient": principal}}

    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={
            client_a_public: "principal-a",
            client_b_public: "principal-b",
        },
        handler=handler,
        serve_timeouts=(2000, 2000, 2000),
    )
    route_identity = b"shared-router-id"
    context_a, client_a = _raw_curve_client(
        server["endpoint"], credentials_a, identity=route_identity
    )
    context_b = None
    client_b = None
    try:
        _send_raw(client_a, encode_envelope(_request("request-from-a")))
        assert handler_entered.wait(2), "production server did not enter A's handler"
        client_a.close(linger=0)
        client_a = None
        context_a.term()
        context_a = None
        time.sleep(0.15)

        # B's readiness and successful send are observed; the default ROUTER
        # may still drop this attempt while A's handler is blocking.
        context_b, client_b = _raw_curve_client(
            server["endpoint"], credentials_b, identity=route_identity
        )
        _send_raw(client_b, encode_envelope(_request("request-from-b-first")))
        release_handler.set()
        _wait_step(server, 0)
        assert server["progress"].get(timeout=3)[0] == 1
        private_key_b = PrivateKey(z85.decode(credentials_b.secret_key))
        while client_b.poll(50, zmq.POLLIN):
            received_frame = client_b.recv()
            assert received_frame.startswith(_SEALED_REPLY_PREFIX), "server leaked plaintext"
            try:
                received_plaintext = SealedBox(private_key_b).decrypt(
                    received_frame[len(_SEALED_REPLY_PREFIX) :]
                )
            except CryptoError:
                # A delayed A reply may be dropped or delivered to B's reused
                # route, but it must remain unreadable to B.
                continue
            received_reply = decode_envelope(received_plaintext)
            assert received_reply.header.correlation_id == "request-from-b-first"
            assert dict(received_reply.payload["result"]) == {"recipient": "principal-b"}
        client_b.close(linger=0)
        client_b = None
        context_b.term()
        context_b = None
        time.sleep(0.15)

        context_b, client_b = _raw_curve_client(
            server["endpoint"], credentials_b, identity=route_identity
        )
        _send_raw(client_b, encode_envelope(_request("request-from-b-reconnected")))
        assert client_b.poll(2000, zmq.POLLIN), "server did not answer B after reconnect"
        reply_b = _decode_sealed_reply(client_b.recv(), credentials_b)
        _wait_step(server, 2)
    finally:
        release_handler.set()
        if client_a is not None:
            client_a.close(linger=0)
        if context_a is not None:
            context_a.term()
        if client_b is not None:
            client_b.close(linger=0)
        if context_b is not None:
            context_b.term()
    _join_server(server)

    assert handled[0] == ("principal-a", "request-from-a")
    assert handled[-1] == ("principal-b", "request-from-b-reconnected")
    assert all(principal == "principal-b" for principal, _ in handled[1:])
    assert reply_b.header.correlation_id == "request-from-b-reconnected"
    assert dict(reply_b.payload["result"]) == {"recipient": "principal-b"}


def test_sealed_reply_overhead_is_reserved_inside_configured_frame_budget() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    service_identity = _identity(WireRole.SERVICE, "service-a", "gateway-a")
    request = _request("exact-reply-budget")
    encoded_reply = encode_envelope(
        _make_reply(service_identity, request, {"ok": True, "code": "OK", "result": {}})
    )
    max_message_bytes = len(encoded_reply) + len(_SEALED_REPLY_PREFIX) + crypto_box_SEALBYTES
    assert len(encode_envelope(request)) <= max_message_bytes

    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=lambda *_: {"ok": True, "code": "OK", "result": {}},
        serve_timeouts=(2000, 1000),
        identity=service_identity,
        max_message_bytes=max_message_bytes,
    )
    client = ZmqServiceClient(
        server["endpoint"],
        service_identity,
        credentials=credentials,
        max_message_bytes=max_message_bytes,
    )
    try:
        reply = client.request(request, timeout=2.0)
    finally:
        client.close()
    _wait_step(server, 0)
    _wait_step(server, 1, handled=False)
    _join_server(server)

    assert reply.header.correlation_id == request.header.message_id


def test_oversized_generic_fallback_is_dropped_and_server_handles_next_request() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    handled_ids = []
    service_identity = _identity(WireRole.SERVICE, "p" * 256, "g" * 256)
    near_limit_request = WireEnvelope(
        header=WireHeader(
            protocol_version=WIRE_PROTOCOL_VERSION,
            kind=WireMessageKind.REQUEST,
            message_id="near-limit-fallback",
            correlation_id=None,
            identity=_identity(WireRole.STRATEGY_CLIENT, "principal-a", "actor-a"),
            scope=WireScope(execution_domain_ref="e" * 256, account_ref="a" * 256),
            operation="o" * 256,
            schema_id="s" * 256,
            schema_version=1,
            sent_at_utc="2026-10-13T00:00:00Z",
            owner_epoch="p" * 256,
        ),
        payload={},
    )
    max_bytes = len(encode_envelope(near_limit_request)) + 256
    generic_reply = _reply(
        near_limit_request,
        service_identity,
        {"ok": False, "code": "INTERNAL_ERROR", "result": {}},
    )
    assert len(_seal_for_client(encode_envelope(generic_reply), client_public)) > max_bytes

    def handler(principal: str, request: WireEnvelope) -> dict[str, Any]:
        handled_ids.append(request.header.message_id)
        if request.header.message_id == near_limit_request.header.message_id:
            return {
                "ok": True,
                "code": "OK",
                "result": {"oversized": "x" * (max_bytes * 2)},
            }
        return {"ok": True, "code": "OK", "result": {"handled": True}}

    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=handler,
        serve_timeouts=(2000, 2000),
        identity=service_identity,
        max_message_bytes=max_bytes,
    )
    client = ZmqServiceClient(
        server["endpoint"],
        service_identity,
        credentials=credentials,
        max_message_bytes=max_bytes,
    )
    try:
        with pytest.raises(RequestOutcomeUnknownError) as caught:
            client.request(near_limit_request, timeout=0.15)
        _wait_step(server, 0)
        reply = client.request(_request("normal-after-fallback"), timeout=2.0)
    finally:
        client.close()
    _wait_step(server, 1)
    _join_server(server)

    assert caught.value.message_id == "near-limit-fallback"
    assert handled_ids == ["near-limit-fallback", "normal-after-fallback"]
    assert reply.header.correlation_id == "normal-after-fallback"


def test_client_rejects_multipart_reply_then_accepts_next_single_frame_reply() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    server = _multipart_reply_server(server_public, server_secret, client_public)
    client = ZmqServiceClient(
        server["endpoint"],
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=credentials,
    )
    try:
        with pytest.raises(RequestOutcomeUnknownError) as caught:
            client.request(_request("multipart-reply"), timeout=0.15)
        reply = client.request(_request("single-frame-reply"), timeout=2.0)
    finally:
        client.close()
    _join_custom_server(server)

    assert caught.value.message_id == "multipart-reply"
    assert reply.header.correlation_id == "single-frame-reply"
    assert dict(reply.payload["result"]) == {"index": 1}


def test_client_has_no_plaintext_reply_fallback() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    server = _multipart_reply_server(
        server_public,
        server_secret,
        client_public,
        plaintext_first_reply=True,
    )
    client = ZmqServiceClient(
        server["endpoint"],
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=credentials,
    )
    try:
        with pytest.raises(RequestOutcomeUnknownError) as caught:
            client.request(_request("plaintext-only-reply"), timeout=0.15)
        reply = client.request(_request("sealed-reply-only"), timeout=2.0)
    finally:
        client.close()
    _join_custom_server(server)

    assert caught.value.message_id == "plaintext-only-reply"
    assert reply.header.correlation_id == "sealed-reply-only"
    assert dict(reply.payload["result"]) == {"index": 1}


def test_handler_failure_returns_only_safe_generic_payload() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=lambda *_: (_ for _ in ()).throw(RuntimeError("private-secret-value")),
        serve_timeouts=(2000,),
    )
    client = ZmqServiceClient(
        server["endpoint"],
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=credentials,
    )
    try:
        reply = client.request(_request("handler-failure"), timeout=2.0)
        with pytest.raises(ValueError, match="cannot be reused on the current connection"):
            client.request(_request("handler-failure"), timeout=2.0)
    finally:
        client.close()
    _wait_step(server, 0)
    _join_server(server)

    assert dict(reply.payload) == {"ok": False, "code": "INTERNAL_ERROR", "result": {}}
    assert "private-secret-value" not in repr(dict(reply.payload))


def test_timeout_is_uncertain_and_late_unrelated_reply_is_ignored() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    handled_ids = []

    def handler(principal_ref: str, request: WireEnvelope) -> dict[str, Any]:
        handled_ids.append(request.header.message_id)
        if request.header.message_id == "slow-first":
            time.sleep(0.15)
        return {"ok": True, "code": "OK", "result": {"id": request.header.message_id}}

    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=handler,
        serve_timeouts=(2000, 2000),
    )
    client = ZmqServiceClient(
        server["endpoint"],
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=credentials,
    )
    try:
        with pytest.raises(RequestOutcomeUnknownError) as caught:
            client.request(_request("slow-first"), timeout=0.04)
        assert caught.value.cause_code == "response_timeout"
        with pytest.raises(ValueError, match="cannot be reused after an uncertain outcome"):
            client.request(_request("slow-first"), timeout=2.0)
        second_reply = client.request(_request("fast-second"), timeout=2.0)
    finally:
        client.close()
    _wait_step(server, 0)
    _wait_step(server, 1)
    _join_server(server)

    assert caught.value.message_id == "slow-first"
    assert second_reply.header.correlation_id == "fast-second"
    assert dict(second_reply.payload["result"]) == {"id": "fast-second"}
    assert handled_ids == ["slow-first", "fast-second"]


def test_reply_must_match_configured_service_identity() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    wrong_service = _identity(WireRole.SERVICE, "different-service", "gateway-b")
    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=lambda *_: {"ok": True, "code": "OK", "result": {}},
        serve_timeouts=(2000,),
        identity=wrong_service,
    )
    client = ZmqServiceClient(
        server["endpoint"],
        _identity(WireRole.SERVICE, "expected-service", "gateway-a"),
        credentials=credentials,
    )
    try:
        with pytest.raises(RequestOutcomeUnknownError) as caught:
            client.request(_request("wrong-service-reply"), timeout=2.0)
    finally:
        client.close()
    _wait_step(server, 0)
    _join_server(server)
    assert caught.value.message_id == "wrong-service-reply"
    assert caught.value.cause_code == "reply_validation_failed"


def test_independent_servers_own_isolated_zap_authenticators() -> None:
    server_a_public, server_a_secret = zmq.curve_keypair()
    server_b_public, server_b_secret = zmq.curve_keypair()
    client_a_public, client_a_credentials = _client_credentials(server_a_public)
    client_b_public, client_b_credentials = _client_credentials(server_b_public)
    server_a = _server_thread(
        server_credentials=CurveServerCredentials(server_a_public, server_a_secret),
        principals={client_a_public: "principal-a"},
        handler=lambda principal, request: {
            "ok": True,
            "code": "OK",
            "result": {"principal": principal},
        },
        serve_timeouts=(2000,),
    )
    server_b = _server_thread(
        server_credentials=CurveServerCredentials(server_b_public, server_b_secret),
        principals={client_b_public: "principal-b"},
        handler=lambda principal, request: {
            "ok": True,
            "code": "OK",
            "result": {"principal": principal},
        },
        serve_timeouts=(2000,),
        identity=_identity(WireRole.SERVICE, "service-b", "gateway-b"),
    )
    client_a = ZmqServiceClient(
        server_a["endpoint"],
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=client_a_credentials,
    )
    client_b = ZmqServiceClient(
        server_b["endpoint"],
        _identity(WireRole.SERVICE, "service-b", "gateway-b"),
        credentials=client_b_credentials,
    )
    try:
        reply_a = client_a.request(_request("server-a"), timeout=2.0)
        reply_b = client_b.request(_request("server-b"), timeout=2.0)
    finally:
        client_a.close()
        client_b.close()
    _wait_step(server_a, 0)
    _wait_step(server_b, 0)
    _join_server(server_a)
    _join_server(server_b)

    assert dict(reply_a.payload["result"]) == {"principal": "principal-a"}
    assert dict(reply_b.payload["result"]) == {"principal": "principal-b"}


def test_server_and_client_require_authenticated_tcp_and_service_identity() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, credentials = _client_credentials(server_public)
    service_identity = _identity(WireRole.SERVICE, "service-a", "gateway-a")
    with pytest.raises(ServiceTransportError, match="CURVE-authenticated TCP"):
        ZmqServiceServer(
            "inproc://unauthenticated",
            service_identity,
            {client_public: "principal-a"},
            lambda *_: {},
            credentials=CurveServerCredentials(server_public, server_secret),
        )
    with pytest.raises(ValueError, match="service role"):
        ZmqServiceClient(
            "tcp://127.0.0.1:1",
            _identity(WireRole.STRATEGY_CLIENT, "not-service", "actor-a"),
            credentials=credentials,
        )


def test_service_server_configuration_preflight_is_pure_and_rejects_bad_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, _client_secret = zmq.curve_keypair()
    identity = _identity(WireRole.SERVICE, "service-a", "gateway-a")
    credentials = CurveServerCredentials(server_public, server_secret)
    principals = {client_public: "principal-a"}
    resource_calls = []

    def forbidden_resource_creation(*_args: Any, **_kwargs: Any) -> None:
        resource_calls.append(True)
        raise AssertionError("configuration preflight must not create resources")

    monkeypatch.setattr(service_v2.zmq, "Context", forbidden_resource_creation)
    monkeypatch.setattr(service_v2, "ThreadAuthenticator", forbidden_resource_creation)

    assert (
        validate_service_server_configuration(
            "tcp://127.0.0.1:*",
            identity,
            principals,
            credentials=credentials,
        )
        is None
    )
    with pytest.raises(ValueError, match="not valid Z85"):
        validate_service_server_configuration(
            "tcp://127.0.0.1:*",
            identity,
            {b"\x00" * 40: "principal-a"},
            credentials=credentials,
        )
    other_public, _other_secret = zmq.curve_keypair()
    with pytest.raises(ValueError, match="public and secret keys do not match"):
        validate_service_server_configuration(
            "tcp://127.0.0.1:*",
            identity,
            principals,
            credentials=CurveServerCredentials(server_public, other_public),
        )
    with pytest.raises(ValueError, match="high_water_mark"):
        validate_service_server_configuration(
            "tcp://127.0.0.1:*",
            identity,
            principals,
            credentials=credentials,
            high_water_mark=0,
        )

    with pytest.raises(ValueError, match="public and secret keys do not match"):
        ZmqServiceServer(
            "tcp://127.0.0.1:*",
            identity,
            principals,
            lambda *_: {},
            credentials=CurveServerCredentials(server_public, other_public),
        )
    assert resource_calls == []


@pytest.mark.parametrize("startup_error", [RuntimeError, KeyboardInterrupt])
def test_server_startup_cleanup_failure_returns_retryable_transport(
    monkeypatch: pytest.MonkeyPatch,
    startup_error: type[BaseException],
) -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, _credentials = _client_credentials(server_public)
    credentials = CurveServerCredentials(server_public, server_secret)
    identity = _identity(WireRole.SERVICE, "service-a", "gateway-a")

    def install_startup_fakes(*, fail_auth_stop_once: bool) -> dict[str, Any]:
        events = []
        state: dict[str, Any] = {"events": events}

        class FakeSocket:
            def __init__(self) -> None:
                self.close_calls = 0
                self.closed = False

            def setsockopt(self, *_args: Any) -> None:
                return None

            def bind(self, _endpoint: str) -> None:
                events.append("socket.bind")
                raise startup_error("injected bind failure")

            def close(self, *, linger: int) -> None:
                assert linger == 0
                self.close_calls += 1
                events.append("socket.close")
                self.closed = True

        class FakeContext:
            def __init__(self) -> None:
                self.socket_object = FakeSocket()
                self.term_calls = 0
                self.terminated = False

            def socket(self, _socket_type: int) -> FakeSocket:
                events.append("context.socket")
                return self.socket_object

            def term(self) -> None:
                self.term_calls += 1
                events.append("context.term")
                self.terminated = True

        class FakeAuthenticator:
            def __init__(self, _context: FakeContext) -> None:
                self.stop_calls = 0
                self.stopped = False

            def configure_curve_callback(self, **_kwargs: Any) -> None:
                events.append("auth.configure")

            def start(self) -> None:
                events.append("auth.start")

            def stop(self) -> None:
                self.stop_calls += 1
                if fail_auth_stop_once and self.stop_calls == 1:
                    events.append("auth.stop.failed")
                    raise RuntimeError("injected authenticator stop failure")
                events.append("auth.stop")
                self.stopped = True

        def make_context() -> FakeContext:
            events.append("context.create")
            context = FakeContext()
            state.update(context=context, socket=context.socket_object)
            return context

        def make_authenticator(context: FakeContext) -> FakeAuthenticator:
            events.append("auth.create")
            authenticator = FakeAuthenticator(context)
            state["authenticator"] = authenticator
            return authenticator

        monkeypatch.setattr(service_v2.zmq, "Context", make_context)
        monkeypatch.setattr(service_v2, "ThreadAuthenticator", make_authenticator)
        return state

    partial = install_startup_fakes(fail_auth_stop_once=True)
    with pytest.raises(ServiceTransportStartupCleanupError) as caught:
        ZmqServiceServer(
            "tcp://127.0.0.1:*",
            identity,
            {client_public: "principal-a"},
            lambda *_: {},
            credentials=credentials,
        )
    transport = caught.value.transport
    assert transport is not None
    assert caught.value.cause_code == "startup_cleanup_failed"
    assert str(caught.value) == "service transport startup cleanup failed; retry close"
    assert transport._closed is False
    assert transport._close_pending is True
    assert transport._authenticator is partial["authenticator"]
    assert transport._socket is partial["socket"]
    assert transport._context is partial["context"]
    assert partial["authenticator"].stop_calls == 1
    assert partial["socket"].close_calls == 0
    assert partial["context"].term_calls == 0
    assert partial["events"][-1] == "auth.stop.failed"
    with pytest.raises(RuntimeError, match="server is closed"):
        transport.serve_once(0)

    transport.close()
    assert transport._closed is True
    assert transport._close_pending is False
    assert transport._authenticator is None
    assert transport._socket is None
    assert transport._receiver is None
    assert transport._context is None
    assert partial["authenticator"].stop_calls == 2
    assert partial["authenticator"].stopped is True
    assert partial["socket"].close_calls == 1
    assert partial["socket"].closed is True
    assert partial["context"].term_calls == 1
    assert partial["context"].terminated is True
    assert partial["events"][-3:] == ["auth.stop", "socket.close", "context.term"]

    normal = install_startup_fakes(fail_auth_stop_once=False)
    with pytest.raises(startup_error, match="injected bind failure"):
        ZmqServiceServer(
            "tcp://127.0.0.1:*",
            identity,
            {client_public: "principal-a"},
            lambda *_: {},
            credentials=credentials,
        )
    assert normal["authenticator"].stop_calls == 1
    assert normal["authenticator"].stopped is True
    assert normal["socket"].close_calls == 1
    assert normal["socket"].closed is True
    assert normal["context"].term_calls == 1
    assert normal["context"].terminated is True
    assert normal["events"][-4:] == [
        "socket.bind",
        "auth.stop",
        "socket.close",
        "context.term",
    ]


def test_server_close_retries_only_unresolved_resources_on_owner_thread() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, _credentials = _client_credentials(server_public)
    server = ZmqServiceServer(
        "tcp://127.0.0.1:*",
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        {client_public: "principal-a"},
        lambda *_: {"ok": True, "code": "OK", "result": {}},
        credentials=CurveServerCredentials(server_public, server_secret),
    )
    raw_authenticator = server._authenticator
    raw_socket = server._socket
    raw_context = server._context
    receiver = server._receiver

    class FailOnceAuthenticator:
        def __init__(self) -> None:
            self.calls = 0

        def stop(self) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("injected authenticator stop failure")
            raw_authenticator.stop()

    class FailOnceSocket:
        def __init__(self) -> None:
            self.calls = 0

        def close(self, *, linger: int) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("injected socket close failure")
            raw_socket.close(linger=linger)

    class CountingContext:
        def __init__(self) -> None:
            self.calls = 0

        def term(self) -> None:
            self.calls += 1
            raw_context.term()

    authenticator = FailOnceAuthenticator()
    sock = FailOnceSocket()
    context = CountingContext()
    server._authenticator = authenticator
    server._socket = sock
    server._context = context

    try:
        with pytest.raises(RuntimeError, match="authenticator stop failure"):
            server.close()
        assert server._closed is False
        assert server._close_pending is True
        assert server._authenticator is authenticator
        assert server._socket is sock
        assert server._receiver is receiver
        assert server._context is context
        assert authenticator.calls == 1
        assert sock.calls == 0
        assert context.calls == 0
        assert raw_socket.closed is False
        with pytest.raises(RuntimeError, match="server is closed"):
            server.serve_once(0)

        with pytest.raises(RuntimeError, match="socket close failure"):
            server.close()
        assert server._closed is False
        assert server._authenticator is None
        assert server._socket is sock
        assert server._receiver is receiver
        assert server._context is context
        assert authenticator.calls == 2
        assert sock.calls == 1
        assert context.calls == 0
        assert raw_socket.closed is False

        server.close()
        assert server._closed is True
        assert server._close_pending is False
        assert server._authenticator is None
        assert server._socket is None
        assert server._receiver is None
        assert server._context is None
        assert authenticator.calls == 2
        assert sock.calls == 2
        assert context.calls == 1
        assert raw_socket.closed is True
        assert raw_context.closed is True
        server.close()
        assert (authenticator.calls, sock.calls, context.calls) == (2, 2, 1)
    finally:
        for _ in range(3):
            if server._closed:
                break
            with suppress(RuntimeError):
                server.close()


def test_client_close_retries_failed_socket_then_context() -> None:
    server_public, _server_secret = zmq.curve_keypair()
    _client_public, credentials = _client_credentials(server_public)
    client = ZmqServiceClient(
        "tcp://127.0.0.1:1",
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=credentials,
    )
    raw_socket = client._socket
    raw_context = client._context
    receiver = client._receiver

    class FailOnceSocket:
        def __init__(self) -> None:
            self.calls = 0

        def close(self, *, linger: int) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("injected socket close failure")
            raw_socket.close(linger=linger)

    class FailOnceContext:
        def __init__(self) -> None:
            self.calls = 0

        def term(self) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("injected context term failure")
            raw_context.term()

    sock = FailOnceSocket()
    context = FailOnceContext()
    client._socket = sock
    client._context = context

    try:
        with pytest.raises(RuntimeError, match="socket close failure"):
            client.close()
        assert client._closed is False
        assert client._close_pending is True
        assert client._socket is sock
        assert client._receiver is receiver
        assert client._context is context
        assert client._socket_retirement_pending is True
        assert sock.calls == 1
        assert context.calls == 0
        assert raw_socket.closed is False
        with pytest.raises(RuntimeError, match="client is closed"):
            client.request(_request("during-close"), timeout=0.1)

        with pytest.raises(RuntimeError, match="context term failure"):
            client.close()
        assert client._closed is False
        assert client._socket is None
        assert client._receiver is None
        assert client._context is context
        assert client._socket_retirement_pending is False
        assert sock.calls == 2
        assert context.calls == 1
        assert raw_socket.closed is True

        client.close()
        assert client._closed is True
        assert client._close_pending is False
        assert client._socket is None
        assert client._receiver is None
        assert client._context is None
        assert sock.calls == 2
        assert context.calls == 2
        assert raw_context.closed is True
        client.close()
        assert (sock.calls, context.calls) == (2, 2)
    finally:
        for _ in range(3):
            if client._closed:
                break
            with suppress(RuntimeError):
                client.close()


def test_client_enforces_thread_affinity_and_close_is_idempotent() -> None:
    server_public, _server_secret = zmq.curve_keypair()
    _client_public, credentials = _client_credentials(server_public)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        endpoint = f"tcp://127.0.0.1:{listener.getsockname()[1]}"
    client = ZmqServiceClient(
        endpoint,
        _identity(WireRole.SERVICE, "service-a", "gateway-a"),
        credentials=credentials,
    )
    errors = queue.Queue()

    def wrong_thread() -> None:
        try:
            client.close()
        except BaseException as exc:
            errors.put(exc)

    worker = threading.Thread(target=wrong_thread)
    worker.start()
    worker.join(timeout=2)
    try:
        assert not worker.is_alive()
        error = errors.get(timeout=1)
        assert isinstance(error, RuntimeError)
        assert "owning thread" in str(error)
    finally:
        client.close()
        client.close()


def test_server_enforces_thread_affinity_and_shuts_down_on_owner_thread() -> None:
    server_public, server_secret = zmq.curve_keypair()
    client_public, _credentials = _client_credentials(server_public)
    server = _server_thread(
        server_credentials=CurveServerCredentials(server_public, server_secret),
        principals={client_public: "trusted-principal"},
        handler=lambda *_: {"ok": True, "code": "OK", "result": {}},
        serve_timeouts=(150,),
    )

    with pytest.raises(RuntimeError, match="owning thread"):
        server["server"].serve_once(0)
    _wait_step(server, 0, handled=False)
    _join_server(server)
