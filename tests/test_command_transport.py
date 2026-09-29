from __future__ import annotations

import socket
import threading
import time
import uuid

import pytest
import zmq

from bt_api_transport_zmq import (
    CommandOutcomeUnknown,
    CurveClientCredentials,
    CurveServerCredentials,
    RemotePrincipalGrant,
    TransportSecurityError,
    WireChannel,
    WireMessage,
    ZmqCommandClient,
    ZmqCommandServer,
    encode_message,
    is_loopback_or_ipc,
)


def _command(message_id: str = "command-1") -> WireMessage:
    return WireMessage(
        message_id=message_id,
        channel=WireChannel.COMMAND,
        scope="account-a.strategy-a",
        sequence=1,
        sent_at=time.time(),
        payload={"kind": "submit", "order": "opaque-id"},
    )


def _gateway_command(
    message_id: str,
    *,
    kind: str = "submit",
    account_scope: str = "account:demo",
    strategy_scope: str = "strategy:one",
    account_id: str = "account-a",
    strategy_id: str = "strategy-a",
) -> WireMessage:
    return WireMessage(
        message_id=message_id,
        channel=WireChannel.COMMAND,
        scope=strategy_scope,
        sequence=1,
        sent_at=time.time(),
        payload={
            "command": {
                "account_scope": account_scope,
                "command_id": message_id,
                "expires_at": time.time() + 10,
                "issued_at": time.time(),
                "kind": kind,
                "manual_resume_authorized": False,
                "payload": {
                    "account_id": account_id,
                    "strategy_id": strategy_id,
                    "symbol": "TEST",
                },
                "receipt_digest": "a" * 64,
                "strategy_scope": strategy_scope,
            },
            "command_fingerprint": "b" * 64,
            "schema": "gateway-command-v1",
        },
    )


def test_server_uses_server_derived_principal_and_returns_one_response() -> None:
    context = zmq.Context()
    endpoint = "inproc://transport-" + uuid.uuid4().hex
    seen = []

    def authenticate(peer_identity: bytes, message: WireMessage) -> dict:
        assert peer_identity
        assert message.payload["kind"] == "submit"
        return {"principal_id": "server-derived", "account_scope": "account-a"}

    def handle(principal: dict, message: WireMessage) -> dict:
        seen.append((principal, message.message_id))
        return {"dispatched": False, "reason": "dry_run"}

    server = ZmqCommandServer(endpoint, authenticate, handle, context=context)
    client = ZmqCommandClient(endpoint, context=context)
    worker = threading.Thread(target=lambda: server.serve_once(timeout_ms=1000))
    worker.start()
    try:
        response = client.request(_command(), timeout_ms=1000)
    finally:
        worker.join(timeout=2)
        client.close()
        server.close()
        context.term()

    assert not worker.is_alive()
    assert response.channel is WireChannel.RESPONSE
    assert response.payload == {
        "accepted": True,
        "outcome": {"dispatched": False, "reason": "dry_run"},
        "status": "handled",
    }
    assert seen == [({"principal_id": "server-derived", "account_scope": "account-a"}, "command-1")]


def test_timeout_is_unknown_and_does_not_issue_an_automatic_retry() -> None:
    context = zmq.Context()
    endpoint = "inproc://no-server-" + uuid.uuid4().hex
    client = ZmqCommandClient(endpoint, context=context)
    command = _command("uncertain")
    try:
        with pytest.raises(CommandOutcomeUnknown) as caught:
            client.request(command, timeout_ms=5)
    finally:
        client.close()
        context.term()

    assert caught.value.message_id == "uncertain"
    assert client.pending_message_ids == ("uncertain",)


def test_remote_endpoint_requires_curve_before_socket_open() -> None:
    assert not is_loopback_or_ipc("tcp://localhost:19001")
    with pytest.raises(TransportSecurityError, match="allow_remote"):
        ZmqCommandServer("tcp://0.0.0.0:19001", lambda *_: {}, lambda *_: {})
    with pytest.raises(TransportSecurityError, match="allow_remote"):
        ZmqCommandServer("tcp://localhost:19001", lambda *_: {}, lambda *_: {})
    with pytest.raises(TransportSecurityError, match="CurveZMQ"):
        ZmqCommandClient("tcp://192.0.2.1:19001", allow_remote=True)

    server_public, server_secret = zmq.curve_keypair()
    with pytest.raises(TransportSecurityError, match="client principal ACL"):
        ZmqCommandServer(
            "tcp://192.0.2.1:19001",
            lambda *_: {},
            lambda *_: {},
            allow_remote=True,
            curve_credentials=CurveServerCredentials(server_public, server_secret),
        )


def test_remote_handler_requires_zap_identity_and_matching_scope_kind_acl() -> None:
    client_public, _ = zmq.curve_keypair()
    grant = RemotePrincipalGrant(
        principal_id="principal-a",
        account_id="account-a",
        strategy_id="strategy-a",
        account_scope="account-a",
        strategy_scope="account-a.strategy-a",
        allowed_kinds=frozenset({"submit"}),
    )
    handler_calls = []
    server = object.__new__(ZmqCommandServer)
    server._max_message_bytes = 1024 * 1024
    server._remote_principals = {client_public: grant}
    server._authenticator = lambda *_: pytest.fail("remote path must not use ROUTER identity")
    server._handler = lambda principal, message: handler_calls.append((principal, message)) or {}

    missing_identity = server._handle(b"client-chosen-routing-id", encode_message(_command()))
    wrong_scope_message = WireMessage(
        "wrong-scope",
        WireChannel.COMMAND,
        "account-b.strategy-a",
        1,
        time.time(),
        {"kind": "submit"},
    )
    wrong_scope = server._handle(
        b"client-chosen-routing-id", encode_message(wrong_scope_message), client_public
    )
    wrong_kind_message = WireMessage(
        "wrong-kind",
        WireChannel.COMMAND,
        "account-a.strategy-a",
        1,
        time.time(),
        {"kind": "cancel"},
    )
    wrong_kind = server._handle(
        b"client-chosen-routing-id", encode_message(wrong_kind_message), client_public
    )
    wrong_account_id = server._handle(
        b"client-chosen-routing-id",
        encode_message(
            WireMessage(
                "wrong-account-id",
                WireChannel.COMMAND,
                "account-a.strategy-a",
                1,
                time.time(),
                {"kind": "submit", "account_id": "account-b"},
            )
        ),
        client_public,
    )
    wrong_strategy_id = server._handle(
        b"client-chosen-routing-id",
        encode_message(
            WireMessage(
                "wrong-strategy-id",
                WireChannel.COMMAND,
                "account-a.strategy-a",
                1,
                time.time(),
                {"kind": "submit", "strategy_id": "strategy-b"},
            )
        ),
        client_public,
    )
    accepted = server._handle(
        b"client-chosen-routing-id", encode_message(_command()), client_public
    )

    assert missing_identity.payload["accepted"] is False
    assert wrong_scope.payload["accepted"] is False
    assert wrong_kind.payload["accepted"] is False
    assert wrong_account_id.payload["accepted"] is False
    assert wrong_strategy_id.payload["accepted"] is False
    assert accepted.payload["accepted"] is True
    assert len(handler_calls) == 1
    assert handler_calls[0][0] == grant
    assert handler_calls[0][1].message_id == "command-1"


def test_remote_curve_zap_identity_and_scope_acl_gate_handler_on_local_tcp() -> None:
    context = zmq.Context()
    server_public, server_secret = zmq.curve_keypair()
    client_public, client_secret = zmq.curve_keypair()
    grant = RemotePrincipalGrant(
        principal_id="principal-a",
        account_id="account-a",
        strategy_id="strategy-a",
        account_scope="account:demo",
        strategy_scope="strategy:one",
        allowed_kinds=frozenset({"submit"}),
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    endpoint = f"tcp://0.0.0.0:{port}"
    client_endpoint = f"tcp://127.0.0.1:{port}"
    handled = []
    server = ZmqCommandServer(
        endpoint,
        lambda *_: pytest.fail("remote ACL derives the principal from ZAP metadata"),
        lambda principal, message: (
            handled.append((principal, message.payload["command"]["kind"])) or {}
        ),
        context=context,
        curve_credentials=CurveServerCredentials(server_public, server_secret),
        allow_remote=True,
        remote_principals={client_public: grant},
    )
    client = ZmqCommandClient(
        client_endpoint,
        context=context,
        curve_credentials=CurveClientCredentials(server_public, client_public, client_secret),
        allow_remote=True,
    )
    unknown_public, unknown_secret = zmq.curve_keypair()
    unknown_client = ZmqCommandClient(
        client_endpoint,
        context=context,
        curve_credentials=CurveClientCredentials(server_public, unknown_public, unknown_secret),
        allow_remote=True,
    )
    worker = threading.Thread(
        target=lambda: (
            server.serve_once(2000),
            server.serve_once(2000),
            server.serve_once(2000),
            server.serve_once(2000),
            server.serve_once(500),
        )
    )
    worker.start()
    try:
        accepted = client.request(_gateway_command("remote-accepted"), timeout_ms=2000)
        rejected = client.request(
            _gateway_command("remote-kind-denied", kind="cancel"),
            timeout_ms=2000,
        )
        wrong_account = client.request(
            _gateway_command("remote-account-denied", account_scope="account:other"),
            timeout_ms=2000,
        )
        wrong_strategy_id = client.request(
            _gateway_command("remote-strategy-id-denied", strategy_id="strategy-b"),
            timeout_ms=2000,
        )
        with pytest.raises(CommandOutcomeUnknown):
            unknown_client.request(_command("unknown-curve-peer"), timeout_ms=100)
    finally:
        worker.join(timeout=3)
        unknown_client.close()
        client.close()
        server.close()
        context.term()

    assert not worker.is_alive()
    assert accepted.payload["accepted"] is True
    assert rejected.payload["accepted"] is False
    assert wrong_account.payload["accepted"] is False
    assert wrong_strategy_id.payload["accepted"] is False
    assert handled == [(grant, "submit")]
