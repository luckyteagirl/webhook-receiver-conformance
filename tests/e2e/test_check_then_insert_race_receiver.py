"""Detection contract for the check-then-insert race reference receiver."""
# ruff: noqa: INP001, S105

from __future__ import annotations

import importlib
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

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


def test_concurrent_deliveries_pass_split_check_twice(tmp_path: Path) -> None:
    module: Any = importlib.import_module(
        "reference_receivers.flawed.check-then-insert-race-receiver.receiver"
    )
    receiver_type = cast("type[Any]", module.CheckThenInsertRaceReceiver)
    now = 2_000_000_000
    token = "isolated-observer-token"
    key = ReferenceSigningKey("test", b"reference-secret-material")
    receiver = receiver_type(
        database_path=tmp_path / "race.sqlite3",
        signature_configurations=(
            ReferenceSignatureConfiguration(SignatureProfile.GENERIC_HMAC_SHA256, (key,)),
        ),
        observer_token=token,
        clock=MutableReferenceClock(now),
        race_barrier=threading.Barrier(2),
    )
    body = json.dumps(
        {"id": "evt_race", "type": "payment.succeeded", "data": {"order_id": "order_1"}},
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
            event_id="evt_race",
            timestamp=now,
        ),
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        tuple(pool.map(receiver.handle, (request, request)))
    evidence = receiver.probe(
        ReferenceProbeRequest(
            token=token,
            capabilities=("processing_count", "effect_count"),
            evidence_names=(
                ObserverEvidenceName.PROCESSING_COUNT,
                ObserverEvidenceName.EFFECT_COUNT,
            ),
            event_ids=("evt_race",),
        )
    ).evidence

    assert evidence == {"processing_count": 1, "effect_count": 2}
