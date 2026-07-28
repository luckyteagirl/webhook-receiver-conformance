"""End-to-end contract tests for REF-CORRECT-001."""
# ruff: noqa: INP001, PLR0913, S105

from __future__ import annotations

import inspect
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from reference_receivers.correct import (
    CorrectReferenceReceiver,
    MutableReferenceClock,
    ObserverEvidenceName,
    ReferenceAsgiApp,
    ReferenceAuthenticationError,
    ReferenceCapabilityError,
    ReferenceOutcome,
    ReferenceProbeRequest,
    ReferenceProbeResponse,
    ReferenceRequest,
    ReferenceSignatureConfiguration,
    ReferenceSigningKey,
    SignatureProfile,
    sign_reference_request,
)
from reference_receivers.correct import receiver as receiver_module

NOW = 2_000_000_000
OBSERVER_TOKEN = "observer-token-that-is-independent"
ACCOUNT = "acct_test"
OLD_KEY = ReferenceSigningKey(
    "old",
    b"old-reference-secret-material",
    active_from=NOW - 1_000,
    active_until=NOW + 10,
)
NEW_KEY = ReferenceSigningKey(
    "new",
    b"new-reference-secret-material",
    active_from=NOW - 10,
)


@pytest.fixture
def clock() -> MutableReferenceClock:
    return MutableReferenceClock(NOW)


@pytest.fixture
def receiver(tmp_path: Path, clock: MutableReferenceClock) -> CorrectReferenceReceiver:
    return _receiver(tmp_path / "receiver.sqlite3", clock)


def _receiver(path: Path, clock: MutableReferenceClock) -> CorrectReferenceReceiver:
    return CorrectReferenceReceiver(
        database_path=path,
        signature_configurations=tuple(
            ReferenceSignatureConfiguration(profile, (OLD_KEY, NEW_KEY))
            for profile in SignatureProfile
        ),
        observer_token=OBSERVER_TOKEN,
        clock=clock,
    )


def _body(
    event_id: str,
    *,
    event_type: str = "payment.succeeded",
    order_id: str = "order_1",
) -> bytes:
    return json.dumps(
        {"id": event_id, "type": event_type, "data": {"order_id": order_id}},
        separators=(",", ":"),
    ).encode()


def _request(
    profile: SignatureProfile,
    event_id: str,
    *,
    event_type: str = "payment.succeeded",
    order_id: str = "order_1",
    key: ReferenceSigningKey = NEW_KEY,
    timestamp: int = NOW,
    body: bytes | None = None,
) -> ReferenceRequest:
    payload = (
        body
        if body is not None
        else _body(
            event_id,
            event_type=event_type,
            order_id=order_id,
        )
    )
    return ReferenceRequest(
        profile,
        ACCOUNT,
        payload,
        sign_reference_request(
            profile=profile,
            key=key,
            body=payload,
            event_id=event_id,
            timestamp=timestamp,
        ),
    )


def _probe(
    receiver: CorrectReferenceReceiver,
    *names: ObserverEvidenceName,
    token: str = OBSERVER_TOKEN,
    event_ids: tuple[str, ...] = (),
    order_ids: tuple[str, ...] = (),
) -> ReferenceProbeResponse:
    return receiver.probe(
        ReferenceProbeRequest(
            token=token,
            capabilities=tuple(name.value for name in names),
            evidence_names=names,
            event_ids=event_ids,
            order_ids=order_ids,
        )
    )


@pytest.mark.parametrize("profile", list(SignatureProfile))
def test_all_profiles_process_exactly_once(
    receiver: CorrectReferenceReceiver,
    profile: SignatureProfile,
) -> None:
    event_id = f"evt_{profile.name.lower()}"
    request = _request(profile, event_id)
    first = receiver.handle(request)
    duplicate = receiver.handle(request)

    assert (first.status_code, first.outcome) == (204, ReferenceOutcome.ACCEPTED)
    assert (duplicate.status_code, duplicate.outcome) == (
        204,
        ReferenceOutcome.DUPLICATE,
    )
    evidence = _probe(
        receiver,
        ObserverEvidenceName.PROCESSING_COUNT,
        ObserverEvidenceName.EFFECT_COUNT,
        ObserverEvidenceName.OUTBOX_COUNT,
        event_ids=(event_id,),
    ).evidence
    assert evidence == {
        "processing_count": 1,
        "effect_count": 1,
        "outbox_count": 1,
    }


@pytest.mark.parametrize("profile", list(SignatureProfile))
def test_stale_or_body_altered_request_has_no_state(
    receiver: CorrectReferenceReceiver,
    profile: SignatureProfile,
) -> None:
    stale = _request(profile, f"evt_stale_{profile.name}", timestamp=NOW - 301)
    exact = _request(profile, f"evt_altered_{profile.name}")
    altered = ReferenceRequest(exact.profile, exact.account_id, exact.body + b" ", exact.headers)

    assert receiver.handle(stale).outcome is ReferenceOutcome.REJECTED
    assert receiver.handle(altered).outcome is ReferenceOutcome.REJECTED
    assert _probe(
        receiver,
        ObserverEvidenceName.PROCESSING_COUNT,
        ObserverEvidenceName.EFFECT_COUNT,
        ObserverEvidenceName.OUTBOX_COUNT,
    ).evidence == {
        "processing_count": 0,
        "effect_count": 0,
        "outbox_count": 0,
    }


def test_concurrent_duplicate_is_atomic(
    receiver: CorrectReferenceReceiver,
) -> None:
    request = _request(SignatureProfile.GENERIC_HMAC_SHA256, "evt_concurrent")
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = tuple(pool.map(receiver.handle, (request,) * 8))

    assert [response.outcome for response in responses].count(ReferenceOutcome.ACCEPTED) == 1
    assert [response.outcome for response in responses].count(ReferenceOutcome.DUPLICATE) == len(
        responses
    ) - 1
    evidence = _probe(
        receiver,
        ObserverEvidenceName.PROCESSING_COUNT,
        ObserverEvidenceName.EFFECT_COUNT,
        ObserverEvidenceName.OUTBOX_COUNT,
    ).evidence
    assert evidence == {
        "processing_count": 1,
        "effect_count": 1,
        "outbox_count": 1,
    }


def test_dependency_reversal_is_staged_then_resolved(
    receiver: CorrectReferenceReceiver,
) -> None:
    refund = _request(
        SignatureProfile.STRIPE_V1,
        "evt_refund",
        event_type="payment.refunded",
        order_id="order_reverse",
    )
    success = _request(
        SignatureProfile.STRIPE_V1,
        "evt_success",
        order_id="order_reverse",
    )

    assert receiver.handle(refund).outcome is ReferenceOutcome.ACCEPTED
    pending = _probe(
        receiver,
        ObserverEvidenceName.INBOX_STATE,
        ObserverEvidenceName.EFFECT_COUNT,
        event_ids=("evt_refund",),
    )
    assert pending.evidence == {
        "inbox_state": {"evt_refund": "pending_dependency"},
        "effect_count": 0,
    }

    assert receiver.handle(success).outcome is ReferenceOutcome.ACCEPTED
    resolved = _probe(
        receiver,
        ObserverEvidenceName.INBOX_STATE,
        ObserverEvidenceName.EFFECT_COUNT,
        ObserverEvidenceName.OUTBOX_COUNT,
        ObserverEvidenceName.ORDER_STATE,
        event_ids=("evt_refund", "evt_success"),
        order_ids=("order_reverse",),
    )
    assert resolved.evidence == {
        "inbox_state": {
            "evt_refund": "processed",
            "evt_success": "processed",
        },
        "effect_count": 2,
        "outbox_count": 2,
        "order_state": {"order_reverse": {"state": "refunded", "version": 2}},
    }


def test_rotation_old_only_overlap_and_new_only(
    tmp_path: Path,
    clock: MutableReferenceClock,
) -> None:
    old_only = NOW - 20
    overlap = NOW
    new_only = NOW + 20
    receiver = _receiver(tmp_path / "rotation.sqlite3", clock)

    clock.value = old_only
    assert (
        receiver.handle(
            _request(
                SignatureProfile.STANDARD_WEBHOOKS_HMAC, "evt_old", key=OLD_KEY, timestamp=old_only
            )
        ).outcome
        is ReferenceOutcome.ACCEPTED
    )
    assert (
        receiver.handle(
            _request(
                SignatureProfile.STANDARD_WEBHOOKS_HMAC,
                "evt_new_early",
                key=NEW_KEY,
                timestamp=old_only,
            )
        ).outcome
        is ReferenceOutcome.REJECTED
    )

    clock.value = overlap
    assert (
        receiver.handle(
            _request(
                SignatureProfile.STANDARD_WEBHOOKS_HMAC,
                "evt_old_overlap",
                key=OLD_KEY,
                timestamp=overlap,
            )
        ).outcome
        is ReferenceOutcome.ACCEPTED
    )
    assert (
        receiver.handle(
            _request(
                SignatureProfile.STANDARD_WEBHOOKS_HMAC,
                "evt_new_overlap",
                key=NEW_KEY,
                timestamp=overlap,
            )
        ).outcome
        is ReferenceOutcome.ACCEPTED
    )

    clock.value = new_only
    assert (
        receiver.handle(
            _request(
                SignatureProfile.STANDARD_WEBHOOKS_HMAC,
                "evt_old_late",
                key=OLD_KEY,
                timestamp=new_only,
            )
        ).outcome
        is ReferenceOutcome.REJECTED
    )
    assert (
        receiver.handle(
            _request(
                SignatureProfile.STANDARD_WEBHOOKS_HMAC, "evt_new", key=NEW_KEY, timestamp=new_only
            )
        ).outcome
        is ReferenceOutcome.ACCEPTED
    )


def test_probe_is_authenticated_minimized_read_only_and_content_addressed(
    receiver: CorrectReferenceReceiver,
) -> None:
    before = receiver.database_path.read_bytes()
    first = _probe(receiver, ObserverEvidenceName.PROCESSING_COUNT)
    after = receiver.database_path.read_bytes()
    assert before == after
    assert first.capabilities == ("processing_count",)
    assert first.evidence == {"processing_count": 0}

    wrong_token = "wrong-token-value"
    with pytest.raises(ReferenceAuthenticationError):
        _probe(receiver, ObserverEvidenceName.PROCESSING_COUNT, token=wrong_token)
    with pytest.raises(ReferenceCapabilityError):
        receiver.probe(
            ReferenceProbeRequest(
                token=OBSERVER_TOKEN,
                capabilities=("not_supported",),
                evidence_names=(),
            )
        )

    receiver.handle(_request(SignatureProfile.GENERIC_HMAC_SHA256, "evt_snapshot"))
    second = _probe(receiver, ObserverEvidenceName.PROCESSING_COUNT)
    assert second.snapshot_id != first.snapshot_id


def test_constant_time_primitive_is_static_contract() -> None:
    source = inspect.getsource(receiver_module)
    assert "hmac.compare_digest" in source


@pytest.mark.anyio
async def test_asgi_webhook_health_and_minimized_probe(
    receiver: CorrectReferenceReceiver,
) -> None:
    app = ReferenceAsgiApp(receiver)
    transport = httpx.ASGITransport(app=app)
    event_id = "evt_http"
    request = _request(SignatureProfile.GENERIC_HMAC_SHA256, event_id)
    async with httpx.AsyncClient(transport=transport, base_url="http://reference.test") as client:
        health = await client.get("/health")
        response = await client.post(
            f"/webhooks/{request.profile.value}/{request.account_id}",
            content=request.body,
            headers=dict(request.headers),
        )
        probe = await client.post(
            "/__test__/observe",
            json={
                "token": OBSERVER_TOKEN,
                "capabilities": ["processing_count"],
                "evidence_names": ["processing_count"],
                "event_ids": [event_id],
            },
        )

    assert health.json() == {"status": "ok"}
    assert (response.status_code, response.headers["x-reference-outcome"]) == (
        204,
        "accepted",
    )
    assert probe.status_code == httpx.codes.OK
    assert probe.json()["evidence"] == {"processing_count": 1}
