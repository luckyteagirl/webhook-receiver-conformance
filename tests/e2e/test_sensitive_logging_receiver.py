"""Detection contract for sensitive fixture data in ordinary logs."""
# ruff: noqa: INP001, S106, TC002

from __future__ import annotations

import importlib
import json
import logging
import sys
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from reference_receivers.correct import (
    MutableReferenceClock,
    ReferenceRequest,
    ReferenceSignatureConfiguration,
    ReferenceSigningKey,
    SignatureProfile,
    sign_reference_request,
)


def test_body_pii_and_key_material_are_written_to_warning_log(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    module: Any = importlib.import_module(
        "reference_receivers.flawed.sensitive-logging-receiver.receiver"
    )
    receiver_type = cast("type[Any]", module.SensitiveLoggingReceiver)
    now = 2_000_000_000
    secret = b"fixture-only-sensitive-key"
    email = "private-fixture@example.test"
    key = ReferenceSigningKey("test", secret)
    receiver = receiver_type(
        database_path=tmp_path / "sensitive-log.sqlite3",
        signature_configurations=(
            ReferenceSignatureConfiguration(SignatureProfile.GENERIC_HMAC_SHA256, (key,)),
        ),
        observer_token="isolated-observer-token",
        clock=MutableReferenceClock(now),
    )
    body = json.dumps(
        {
            "id": "evt_sensitive",
            "type": "payment.succeeded",
            "data": {"order_id": "order_1", "customer_email": email},
        },
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
            event_id="evt_sensitive",
            timestamp=now,
        ),
    )
    caplog.set_level(logging.WARNING, logger="reference_receivers.flawed.sensitive_logging")

    receiver.handle(request)

    assert email in caplog.text
    assert secret.decode() in caplog.text
    assert "x-webhook-signature" in caplog.text
