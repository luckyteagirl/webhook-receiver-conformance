"""Detection contract for assuming prerequisite event order."""
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


def test_refund_before_success_is_rejected_instead_of_staged(tmp_path: Path) -> None:
    module: Any = importlib.import_module(
        "reference_receivers.flawed.order-assuming-receiver.receiver"
    )
    receiver_type = cast("type[Any]", module.OrderAssumingReceiver)
    now = 2_000_000_000
    token = "isolated-observer-token"
    key = ReferenceSigningKey("test", b"reference-secret-material")
    receiver = receiver_type(
        database_path=tmp_path / "order-assuming.sqlite3",
        signature_configurations=(
            ReferenceSignatureConfiguration(SignatureProfile.GENERIC_HMAC_SHA256, (key,)),
        ),
        observer_token=token,
        clock=MutableReferenceClock(now),
    )
    body = json.dumps(
        {"id": "evt_refund", "type": "payment.refunded", "data": {"order_id": "order_1"}},
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
            event_id="evt_refund",
            timestamp=now,
        ),
    )

    response = receiver.handle(request)
    evidence = receiver.probe(
        ReferenceProbeRequest(
            token=token,
            capabilities=("processing_count", "effect_count", "inbox_state"),
            evidence_names=(
                ObserverEvidenceName.PROCESSING_COUNT,
                ObserverEvidenceName.EFFECT_COUNT,
                ObserverEvidenceName.INBOX_STATE,
            ),
        )
    ).evidence

    assert response.outcome is ReferenceOutcome.CONFLICT
    assert evidence == {
        "processing_count": 0,
        "effect_count": 0,
        "inbox_state": {},
    }
