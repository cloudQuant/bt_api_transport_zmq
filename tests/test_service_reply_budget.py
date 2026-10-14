"""Tests for predicting the exact sealed service reply frame budget."""

from __future__ import annotations

import pytest
from bt_api_base.service_protocol import (
    MAX_WIRE_MESSAGE_BYTES,
    WIRE_PROTOCOL_VERSION,
    WireEnvelope,
    WireErrorCode,
    WireHeader,
    WireIdentity,
    WireMessageKind,
    WireRole,
    WireScope,
    WireValidationError,
    encode_envelope,
    validate_reply,
)
from nacl.public import PrivateKey

from bt_api_transport_zmq import service_v2


def _identity(
    role: WireRole = WireRole.SERVICE,
    *,
    principal_ref: str = "service-é",
    actor_ref: str = "gateway-π",
) -> WireIdentity:
    return WireIdentity(role=role, principal_ref=principal_ref, actor_ref=actor_ref)


def _request() -> WireEnvelope:
    return WireEnvelope(
        header=WireHeader(
            protocol_version=WIRE_PROTOCOL_VERSION,
            kind=WireMessageKind.REQUEST,
            message_id="request-🧪",
            correlation_id=None,
            identity=_identity(WireRole.STRATEGY_CLIENT, principal_ref="client-ü"),
            scope=WireScope(execution_domain_ref="execution-🌐", account_ref="account-a"),
            operation='account.snapshot/"quoted"',
            schema_id="account.snapshot.response",
            schema_version=1,
            sent_at_utc="2026-10-14T12:34:56.123456Z",
            owner_epoch="owner-epoch-é",
        ),
        payload={"request": "escaped\\path\nwith π"},
    )


def _payload() -> dict[str, object]:
    return {
        "ok": True,
        "code": "OK",
        "result": {"message": 'quoted "text"; newline\n; emoji 🧪'},
    }


def test_exact_sealed_frame_boundary_matches_server_reply_encoding() -> None:
    identity = _identity()
    request = _request()
    payload = _payload()
    reply = service_v2._make_reply(identity, request, service_v2._handler_payload(payload))
    encoded = encode_envelope(reply)
    sealed = service_v2._seal_reply(encoded, PrivateKey.generate().public_key)
    exact_cap = len(sealed)

    assert "🧪".encode() in encoded
    assert b'\\"quoted\\"' in encoded
    assert len(sealed) == len(encoded) + service_v2._REPLY_FRAME_OVERHEAD
    assert service_v2.service_reply_fits(identity, request, payload, max_message_bytes=exact_cap)
    assert not service_v2.service_reply_fits(
        identity, request, payload, max_message_bytes=exact_cap - 1
    )


def test_reply_keeps_request_scope_and_owner_epoch() -> None:
    identity = _identity()
    request = _request()
    reply = service_v2._make_reply(identity, request, service_v2._handler_payload(_payload()))

    assert reply.header.scope == request.header.scope
    assert reply.header.owner_epoch == request.header.owner_epoch
    validate_reply(reply, request, expected_peer=identity)


@pytest.mark.parametrize(
    "max_message_bytes",
    [True, False, 0, -1, service_v2._REPLY_FRAME_OVERHEAD, MAX_WIRE_MESSAGE_BYTES + 1],
)
def test_invalid_message_caps_raise_instead_of_reporting_no_fit(max_message_bytes: int) -> None:
    with pytest.raises(ValueError):
        service_v2.service_reply_fits(
            _identity(), _request(), _payload(), max_message_bytes=max_message_bytes
        )


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {"ok": True, "code": "OK"},
        {"ok": True, "code": "OK", "result": []},
        {"ok": True, "code": "OK", "result": {"bad": object()}},
    ],
)
def test_invalid_or_malformed_payload_raises_instead_of_reporting_no_fit(
    payload: object,
) -> None:
    with pytest.raises(ValueError):
        service_v2.service_reply_fits(
            _identity(),
            _request(),
            payload,
            max_message_bytes=4096,  # type: ignore[arg-type]
        )


def test_invalid_request_protocol_error_is_not_reported_as_no_fit() -> None:
    identity = _identity()
    request = _request()
    invalid_request = service_v2._make_reply(identity, request, _payload())

    with pytest.raises(WireValidationError) as caught:
        service_v2.service_reply_fits(identity, invalid_request, _payload(), max_message_bytes=4096)

    assert caught.value.code is WireErrorCode.UNEXPECTED_KIND


def test_non_service_identity_is_rejected() -> None:
    with pytest.raises(ValueError):
        service_v2.service_reply_fits(
            _identity(WireRole.STRATEGY_CLIENT),
            _request(),
            _payload(),
            max_message_bytes=4096,
        )
