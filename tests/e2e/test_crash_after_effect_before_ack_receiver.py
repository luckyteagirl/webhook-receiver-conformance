"""Detection contract for a crash after effect commit and before acknowledgment."""
# ruff: noqa: INP001, S105

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from reference_receivers.correct import (
    MutableReferenceClock,
    ObserverEvidenceName,
    ReferenceOutcome,
    ReferenceProbeRequest,
    ReferenceRequest,
    ReferenceSignatureConfiguration,
    ReferenceSigningKey,
    SignatureProfile,
    sign_reference_request,
)


def test_crash_occurs_after_effect_is_durable_and_retry_is_duplicate(tmp_path: Path) -> None:
    module: Any = importlib.import_module(
        "reference_receivers.flawed.crash-after-effect-before-ack-receiver.receiver"
    )
    receiver_type = cast("type[Any]", module.CrashAfterEffectBeforeAckReceiver)
    crash_type = cast("type[Exception]", module.SimulatedPostCommitCrashError)
    now = 2_000_000_000
    token = "isolated-observer-token"
    key = ReferenceSigningKey("test", b"reference-secret-material")
    receiver = receiver_type(
        database_path=tmp_path / "post-commit-crash.sqlite3",
        signature_configurations=(
            ReferenceSignatureConfiguration(SignatureProfile.GENERIC_HMAC_SHA256, (key,)),
        ),
        observer_token=token,
        clock=MutableReferenceClock(now),
    )
    body = json.dumps(
        {"id": "evt_crash", "type": "payment.succeeded", "data": {"order_id": "order_1"}},
        separators=(",", ":"),
    ).encode()
    request = ReferenceRequest(
        SignatureProfile.GENERIC_HMAC_SHA256,
        "acct_test",
        body,
        sign_reference_request(
            profile=SignatureProfile.GENERIC_HMAC_SHA256,
            key=key,
            body=body,
            event_id="evt_crash",
            timestamp=now,
        ),
    )

    receiver.crash_next_after_effect()
    with pytest.raises(crash_type):
        receiver.handle(request)
    evidence = receiver.probe(
        ReferenceProbeRequest(
            token=token,
            capabilities=("processing_count", "effect_count", "outbox_count"),
            evidence_names=(
                ObserverEvidenceName.PROCESSING_COUNT,
                ObserverEvidenceName.EFFECT_COUNT,
                ObserverEvidenceName.OUTBOX_COUNT,
            ),
            event_ids=("evt_crash",),
        )
    ).evidence
    retry = receiver.handle(request)
    after_retry = receiver.probe(
        ReferenceProbeRequest(
            token=token,
            capabilities=("processing_count", "effect_count", "outbox_count"),
            evidence_names=(
                ObserverEvidenceName.PROCESSING_COUNT,
                ObserverEvidenceName.EFFECT_COUNT,
                ObserverEvidenceName.OUTBOX_COUNT,
            ),
            event_ids=("evt_crash",),
        )
    ).evidence

    assert evidence == {
        "processing_count": 1,
        "effect_count": 1,
        "outbox_count": 1,
    }
    assert retry.outcome is ReferenceOutcome.DUPLICATE
    assert after_retry == {
        "processing_count": 1,
        "effect_count": 2,
        "outbox_count": 1,
    }
