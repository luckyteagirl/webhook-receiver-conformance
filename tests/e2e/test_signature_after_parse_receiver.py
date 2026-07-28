"""Detection contract for signature verification after JSON parsing."""
# ruff: noqa: INP001, S106

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from reference_receivers.correct import (
    MutableReferenceClock,
    ReferenceOutcome,
    ReferenceRequest,
    ReferenceSignatureConfiguration,
    ReferenceSigningKey,
    SignatureProfile,
    sign_reference_request,
)


def test_signature_over_reserialized_bytes_accepts_different_wire_bytes(tmp_path: Path) -> None:
    module: Any = importlib.import_module(
        "reference_receivers.flawed.signature-after-parse-receiver.receiver"
    )
    receiver_type = cast("type[Any]", module.SignatureAfterParseReceiver)
    now = 2_000_000_000
    key = ReferenceSigningKey("test", b"reference-secret-material")
    receiver = receiver_type(
        database_path=tmp_path / "signature-after-parse.sqlite3",
        signature_configurations=(
            ReferenceSignatureConfiguration(SignatureProfile.GENERIC_HMAC_SHA256, (key,)),
        ),
        observer_token="isolated-observer-token",
        clock=MutableReferenceClock(now),
    )
    event = {
        "id": "evt_noncanonical",
        "type": "payment.succeeded",
        "data": {"order_id": "order_1"},
    }
    wire_body = json.dumps(event, indent=2).encode()
    canonical_body = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert wire_body != canonical_body
    request = ReferenceRequest(
        SignatureProfile.GENERIC_HMAC_SHA256,
        "acct_test",
        wire_body,
        sign_reference_request(
            profile=SignatureProfile.GENERIC_HMAC_SHA256,
            key=key,
            body=canonical_body,
            event_id="evt_noncanonical",
            timestamp=now,
        ),
    )

    response = receiver.handle(request)

    assert response.outcome is ReferenceOutcome.ACCEPTED
