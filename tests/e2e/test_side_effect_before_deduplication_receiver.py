"""Detection contract for a business effect committed before deduplication."""
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
    ReferenceProbeRequest,
    ReferenceRequest,
    ReferenceSignatureConfiguration,
    ReferenceSigningKey,
    SignatureProfile,
    sign_reference_request,
)


def test_crash_leaves_effect_without_logical_identity(tmp_path: Path) -> None:
    module: Any = importlib.import_module(
        "reference_receivers.flawed.side-effect-before-deduplication-receiver.receiver"
    )
    receiver_type = cast("type[Any]", module.SideEffectBeforeDeduplicationReceiver)
    crash_type = cast("type[Exception]", module.SimulatedEffectCrashError)
    now = 2_000_000_000
    token = "isolated-observer-token"
    key = ReferenceSigningKey("test", b"reference-secret-material")
    receiver = receiver_type(
        database_path=tmp_path / "effect-first.sqlite3",
        signature_configurations=(
            ReferenceSignatureConfiguration(SignatureProfile.GENERIC_HMAC_SHA256, (key,)),
        ),
        observer_token=token,
        clock=MutableReferenceClock(now),
    )
    body = json.dumps(
        {"id": "evt_effect_first", "type": "payment.succeeded", "data": {"order_id": "order_1"}},
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
            event_id="evt_effect_first",
            timestamp=now,
        ),
    )

    receiver.fail_next_after_effect()
    with pytest.raises(crash_type):
        receiver.handle(request)
    evidence = receiver.probe(
        ReferenceProbeRequest(
            token=token,
            capabilities=("processing_count", "effect_count"),
            evidence_names=(
                ObserverEvidenceName.PROCESSING_COUNT,
                ObserverEvidenceName.EFFECT_COUNT,
            ),
            event_ids=("evt_effect_first",),
        )
    ).evidence

    assert evidence == {"processing_count": 0, "effect_count": 1}
