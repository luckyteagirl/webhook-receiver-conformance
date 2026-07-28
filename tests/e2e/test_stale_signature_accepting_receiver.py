"""Detection contract for accepting signatures outside the replay window."""
# ruff: noqa: INP001, S105

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any, cast

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


def test_stale_signature_is_accepted_and_mutates_business_state(tmp_path: Path) -> None:
    module: Any = importlib.import_module(
        "reference_receivers.flawed.stale-signature-accepting-receiver.receiver"
    )
    receiver_type = cast("type[Any]", module.StaleSignatureAcceptingReceiver)
    now = 2_000_000_000
    token = "isolated-observer-token"
    key = ReferenceSigningKey("test", b"reference-secret-material")
    receiver = receiver_type(
        database_path=tmp_path / "stale.sqlite3",
        signature_configurations=(
            ReferenceSignatureConfiguration(
                SignatureProfile.GENERIC_HMAC_SHA256,
                (key,),
                replay_window_seconds=300,
            ),
        ),
        observer_token=token,
        clock=MutableReferenceClock(now),
    )
    body = json.dumps(
        {"id": "evt_stale", "type": "payment.succeeded", "data": {"order_id": "order_1"}},
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
            event_id="evt_stale",
            timestamp=now - 301,
        ),
    )

    response = receiver.handle(request)
    evidence = receiver.probe(
        ReferenceProbeRequest(
            token=token,
            capabilities=("processing_count", "effect_count"),
            evidence_names=(
                ObserverEvidenceName.PROCESSING_COUNT,
                ObserverEvidenceName.EFFECT_COUNT,
            ),
            event_ids=("evt_stale",),
        )
    ).evidence

    assert response.outcome is ReferenceOutcome.ACCEPTED
    assert evidence == {"processing_count": 1, "effect_count": 1}
