from __future__ import annotations

import os
import queue
import threading
from typing import Any

import pytest
import zmq

from bt_api_base.service_protocol import (
    WIRE_PROTOCOL_VERSION,
    WireEnvelope,
    WireHeader,
    WireIdentity,
    WireMessageKind,
    WireRole,
    WireScope,
)
from bt_api_transport_zmq.server import CurveClientCredentials, CurveServerCredentials
from bt_api_transport_zmq.service_v2 import (
    RequestOutcomeUnknownError,
    ServiceTransportStartupCleanupError,
    ZmqServiceClient,
    ZmqServiceContextPool,
    ZmqServiceServer,
)


def _identity(principal_ref: str) -> WireIdentity:
    return WireIdentity(
        role=WireRole.SERVICE,
        principal_ref=principal_ref,
        actor_ref=f"actor-{principal_ref}",
    )


def _request(message_id: str) -> WireEnvelope:
    return WireEnvelope(
        header=WireHeader(
            protocol_version=WIRE_PROTOCOL_VERSION,
            kind=WireMessageKind.REQUEST,
            message_id=message_id,
            correlation_id=None,
            identity=WireIdentity(
                role=WireRole.STRATEGY_CLIENT,
                principal_ref="caller",
                actor_ref="strategy",
            ),
            scope=WireScope(execution_domain_ref="execution", account_ref="account"),
            operation="account.snapshot",
            schema_id="account.snapshot.request",
            schema_version=1,
            sent_at_utc="2026-10-17T00:00:00Z",
            owner_epoch="owner-1",
        ),
        payload={"request": message_id},
    )


def _client_credentials(server_key: bytes) -> CurveClientCredentials:
    public_key, secret_key = zmq.curve_keypair()
    return CurveClientCredentials(server_key, public_key, secret_key)


class _FakeSocket:
    def __init__(self, owner: _FakeContext) -> None:
        self.owner = owner
        self.close_calls = 0
        self.closed = False
        self.poll_results: list[int] = []
        self.options: list[tuple[int, Any]] = []
        self.connected_endpoint: str | None = None

    def setsockopt(self, option: int, value: Any) -> None:
        self.options.append((option, value))

    def connect(self, endpoint: str) -> None:
        self.connected_endpoint = endpoint
        if self.owner.connect_error is not None:
            raise self.owner.connect_error

    def close(self, *, linger: int) -> None:
        assert linger == 0
        self.close_calls += 1
        if self.owner.socket_close_failures:
            self.owner.socket_close_failures -= 1
            raise RuntimeError("injected socket close failure")
        self.closed = True

    def poll(self, _timeout_ms: int, _flags: int) -> int:
        if self.poll_results:
            return self.poll_results.pop(0)
        return 0

    def send(self, _payload: bytes, *, flags: int) -> None:
        assert flags == zmq.NOBLOCK


class _FakeContext:
    def __init__(
        self,
        *,
        socket_close_failures: int = 0,
        term_failures: int = 0,
        connect_error: BaseException | None = None,
    ) -> None:
        self.sockets: list[_FakeSocket] = []
        self.socket_close_failures = socket_close_failures
        self.term_failures = term_failures
        self.connect_error = connect_error
        self.term_calls = 0
        self.terminated = False

    def socket(self, _socket_type: int) -> _FakeSocket:
        socket = _FakeSocket(self)
        self.sockets.append(socket)
        return socket

    def term(self) -> None:
        self.term_calls += 1
        if self.term_failures:
            self.term_failures -= 1
            raise RuntimeError("injected context term failure")
        self.terminated = True


def _install_fake_contexts(
    monkeypatch: pytest.MonkeyPatch,
    contexts: list[_FakeContext],
) -> None:
    def make_context(*, io_threads: int | None = None) -> _FakeContext:
        if io_threads is not None:
            assert io_threads == 1
        context = contexts.pop(0)
        return context

    monkeypatch.setattr("bt_api_transport_zmq.service_v2.zmq.Context", make_context)


def _new_client(
    pool: ZmqServiceContextPool | None,
    credentials: CurveClientCredentials,
    principal_ref: str,
) -> ZmqServiceClient:
    return ZmqServiceClient(
        "tcp://127.0.0.1:1",
        _identity(principal_ref),
        credentials=credentials,
        context_pool=pool,
    )


def test_pool_shares_only_context_and_terms_after_first_middle_and_last_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_key, _server_secret = zmq.curve_keypair()
    credentials = [_client_credentials(server_key) for _ in range(3)]
    context = _FakeContext()
    _install_fake_contexts(monkeypatch, [context])
    pool = ZmqServiceContextPool()

    clients = [
        _new_client(pool, credentials[index], f"service-{index}")
        for index in range(3)
    ]
    sockets = [client._socket for client in clients]
    assert clients[0]._context is clients[1]._context is clients[2]._context is context
    assert len({id(socket) for socket in sockets}) == 3
    assert len({client._public_key for client in clients}) == 3
    assert len({client._secret_key for client in clients}) == 3
    assert len({id(client._reply_box) for client in clients}) == 3
    assert len({client._identity.principal_ref for client in clients}) == 3
    assert len({client._identity.actor_ref for client in clients}) == 3
    assert pool._active_leases == 3

    clients[0].close()
    assert context.term_calls == 0
    assert context.terminated is False
    assert pool._active_leases == 2
    assert clients[1]._socket is sockets[1]
    clients[1].close()
    assert context.term_calls == 0
    assert pool._active_leases == 1
    clients[2].close()

    assert context.term_calls == 1
    assert context.terminated is True
    assert pool._active_leases == 0
    assert pool._context is None


def test_default_clients_keep_independent_contexts(monkeypatch: pytest.MonkeyPatch) -> None:
    server_key, _server_secret = zmq.curve_keypair()
    credentials = [_client_credentials(server_key) for _ in range(2)]
    contexts = [_FakeContext(), _FakeContext()]
    _install_fake_contexts(monkeypatch, contexts)

    client_a = _new_client(None, credentials[0], "service-a")
    client_b = _new_client(None, credentials[1], "service-b")
    context_a = client_a._context
    context_b = client_b._context
    assert context_a is not context_b

    client_a.close()
    assert context_a.term_calls == 1
    assert context_b.term_calls == 0
    client_b.close()
    assert context_b.term_calls == 1


def test_timeout_retires_only_the_requesting_clients_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_key, _server_secret = zmq.curve_keypair()
    credentials = [_client_credentials(server_key) for _ in range(2)]
    context = _FakeContext()
    _install_fake_contexts(monkeypatch, [context])
    pool = ZmqServiceContextPool()
    client_a = _new_client(pool, credentials[0], "service-a")
    client_b = _new_client(pool, credentials[1], "service-b")
    socket_a = client_a._socket
    socket_b = client_b._socket
    socket_a.poll_results = [1, 0]

    with pytest.raises(RequestOutcomeUnknownError) as error:
        client_a.request(_request("timeout-a"), timeout=0.1)
    assert error.value.cause_code == "response_timeout"
    assert error.value.message_id == "timeout-a"

    assert client_a._socket is None
    assert socket_a.closed is True
    assert client_b._socket is socket_b
    assert socket_b.closed is False
    assert client_b._context is context
    assert pool._active_leases == 2
    assert context.term_calls == 0
    client_a.close()
    assert pool._active_leases == 1
    assert client_b._socket is socket_b
    client_b.close()
    assert context.term_calls == 1


def test_startup_failure_cleans_partial_socket_and_cleanup_failure_keeps_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_key, _server_secret = zmq.curve_keypair()
    credentials = _client_credentials(server_key)
    identity = _identity("service-startup")

    clean_context = _FakeContext(connect_error=RuntimeError("injected connect failure"))
    _install_fake_contexts(monkeypatch, [clean_context])
    clean_pool = ZmqServiceContextPool()
    with pytest.raises(RuntimeError, match="injected connect failure"):
        ZmqServiceClient(
            "tcp://127.0.0.1:1", identity, credentials=credentials, context_pool=clean_pool
        )
    assert clean_context.sockets[0].closed is True
    assert clean_context.term_calls == 1
    assert clean_pool._active_leases == 0
    assert clean_pool._context is None

    partial_context = _FakeContext(
        socket_close_failures=1,
        connect_error=RuntimeError("injected connect failure"),
    )
    _install_fake_contexts(monkeypatch, [partial_context])
    partial_pool = ZmqServiceContextPool()
    with pytest.raises(ServiceTransportStartupCleanupError) as caught:
        ZmqServiceClient(
            "tcp://127.0.0.1:1", identity, credentials=credentials, context_pool=partial_pool
        )

    retained = caught.value.transport
    assert isinstance(retained, ZmqServiceClient)
    assert retained._close_pending is True
    assert retained._closed is False
    assert retained._socket is partial_context.sockets[0]
    assert retained._context is partial_context
    assert retained._context_lease is not None
    assert partial_pool._active_leases == 1
    assert partial_context.term_calls == 0

    retained.close()
    assert retained._closed is True
    assert partial_context.sockets[0].closed is True
    assert partial_context.term_calls == 1
    assert partial_pool._active_leases == 0
    assert partial_pool._context is None


def test_last_term_failure_is_retryable_and_stale_lease_cannot_term_new_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_key, _server_secret = zmq.curve_keypair()
    credentials = [_client_credentials(server_key) for _ in range(3)]
    old_context = _FakeContext(term_failures=1)
    new_context = _FakeContext(term_failures=1)
    _install_fake_contexts(monkeypatch, [old_context, new_context])
    pool = ZmqServiceContextPool()

    old_client = _new_client(pool, credentials[0], "service-old")
    old_lease = old_client._context_lease
    with pytest.raises(RuntimeError, match="context term failure"):
        old_client.close()
    assert old_client._closed is False
    assert old_client._context_lease is old_lease
    assert old_context.term_calls == 1
    assert pool._termination_pending is True
    assert pool._active_leases == 0

    with pytest.raises(RuntimeError, match="termination is pending"):
        _new_client(pool, credentials[1], "service-blocked")
    assert pool._context is old_context

    old_client.close()
    assert old_client._closed is True
    assert old_context.term_calls == 2
    assert pool._context is None
    assert pool._termination_pending is False

    new_client = _new_client(pool, credentials[2], "service-new")
    assert new_client._context is new_context
    with pytest.raises(RuntimeError, match="context term failure"):
        new_client.close()
    assert pool._context is new_context
    assert pool._termination_pending is True
    assert new_context.term_calls == 1

    old_lease.close()
    assert pool._context is new_context
    assert new_context.term_calls == 1
    assert old_context.term_calls == 2

    new_client.close()
    assert new_client._closed is True
    assert new_context.term_calls == 2
    assert pool._context is None


def test_pid_and_owner_thread_checks_leave_context_lease_owned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_key, _server_secret = zmq.curve_keypair()
    credentials = _client_credentials(server_key)
    context = _FakeContext()
    _install_fake_contexts(monkeypatch, [context])
    pool = ZmqServiceContextPool()
    client = _new_client(pool, credentials, "service-boundary")
    socket = client._socket

    class LockMustNotBeEntered:
        def __enter__(self) -> LockMustNotBeEntered:
            raise AssertionError("PID check must happen before taking inherited lock")

        def __exit__(self, *_args: Any) -> None:
            return None

    probe_pool = ZmqServiceContextPool()
    probe_pool._owner_pid += 1
    probe_pool._lock = LockMustNotBeEntered()
    with pytest.raises(RuntimeError, match="process boundary"):
        probe_pool.acquire()

    owner_pid = client._owner_pid
    client._owner_pid = owner_pid + 1
    with pytest.raises(RuntimeError, match="process boundary"):
        client.close()
    client._owner_pid = owner_pid
    assert socket.closed is False
    assert pool._active_leases == 1

    errors: queue.Queue[BaseException] = queue.Queue()

    def close_from_other_thread() -> None:
        for action in (
            client.close,
            lambda: client.request(_request("wrong-thread"), timeout=0.1),
        ):
            try:
                action()
            except BaseException as exc:
                errors.put(exc)

    worker = threading.Thread(target=close_from_other_thread)
    worker.start()
    worker.join(timeout=2)
    assert not worker.is_alive()
    observed_errors = [errors.get_nowait(), errors.get_nowait()]
    assert all(isinstance(error, RuntimeError) for error in observed_errors)
    assert all("owning thread" in str(error) for error in observed_errors)
    assert socket.closed is False
    assert pool._active_leases == 1
    client.close()
    assert pool._active_leases == 0


def test_real_curve_peer_remains_usable_after_another_shared_client_closes() -> None:
    server_public, server_secret = zmq.curve_keypair()
    credentials_a = _client_credentials(server_public)
    credentials_b = _client_credentials(server_public)
    server_identity = _identity("server")
    calls: list[tuple[str, str]] = []
    state: dict[str, Any] = {
        "ready": threading.Event(),
        "errors": queue.Queue(),
    }

    def handler(principal_ref: str, request: WireEnvelope) -> dict[str, Any]:
        calls.append((principal_ref, request.header.message_id))
        return {"ok": True, "code": "OK", "result": {"principal": principal_ref}}

    def serve() -> None:
        server = None
        try:
            server = ZmqServiceServer(
                "tcp://127.0.0.1:*",
                server_identity,
                {
                    credentials_a.public_key: "principal-a",
                    credentials_b.public_key: "principal-b",
                },
                handler,
                credentials=CurveServerCredentials(server_public, server_secret),
            )
            state["server"] = server
            state["endpoint"] = server.endpoint
            state["ready"].set()
            server.serve_once(3000)
            server.serve_once(3000)
        except BaseException as exc:
            state["errors"].put(exc)
            state["ready"].set()
        finally:
            if server is not None:
                try:
                    server.close()
                except BaseException as exc:
                    state["errors"].put(exc)

    server_thread = threading.Thread(target=serve, name="service-context-pool-curve-server")
    server_thread.start()
    pool = ZmqServiceContextPool()
    clients: list[ZmqServiceClient] = []
    primary_error: BaseException | None = None
    try:
        assert state["ready"].wait(3), "service server did not bind"
        assert state["errors"].empty(), "service server failed during startup"
        client_a = ZmqServiceClient(
            state["endpoint"], server_identity, credentials=credentials_a, context_pool=pool
        )
        clients.append(client_a)
        client_b = ZmqServiceClient(
            state["endpoint"], server_identity, credentials=credentials_b, context_pool=pool
        )
        clients.append(client_b)
        context = client_a._context
        socket_a = client_a._socket
        socket_b = client_b._socket
        assert context is client_b._context
        assert socket_a is not socket_b
        assert client_a._public_key != client_b._public_key
        assert client_a._secret_key != client_b._secret_key

        reply_a = client_a.request(_request("client-a-first"), timeout=2.0)
        assert reply_a.payload["result"]["principal"] == "principal-a"
        client_a.close()
        assert pool._active_leases == 1
        assert client_b._context is context
        assert client_b._socket is socket_b
        reply_b = client_b.request(_request("client-b-after-peer-close"), timeout=2.0)
        assert reply_b.payload["result"]["principal"] == "principal-b"
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors = []
        for client in clients:
            try:
                client.close()
            except BaseException as exc:
                cleanup_errors.append(exc)
        server_thread.join(timeout=7)
        if cleanup_errors:
            if primary_error is None:
                raise AssertionError("shared-context client cleanup failed") from cleanup_errors[0]
            add_note = getattr(primary_error, "add_note", None)
            if callable(add_note):
                add_note(f"shared-context client cleanup error: {cleanup_errors[0]!r}")
        if server_thread.is_alive() and primary_error is not None:
            add_note = getattr(primary_error, "add_note", None)
            if callable(add_note):
                add_note("shared-context service server thread did not stop after bounded join")

    assert not server_thread.is_alive(), "service server did not stop"
    assert state["errors"].empty(), "service server failed"
    assert calls == [
        ("principal-a", "client-a-first"),
        ("principal-b", "client-b-after-peer-close"),
    ]
    assert pool._active_leases == 0
    assert pool._context is None
