"""Standard Webhooks compatibility and golden-vector tests."""
# ruff: noqa: INP001

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import cast

from webhook_receiver_conformance.config.models import EnvironmentSecretRef
from webhook_receiver_conformance.secrets import SecretHandle, SecretResolver
from webhook_receiver_conformance.signatures.base import SignatureHeader, SigningInput
from webhook_receiver_conformance.signatures.standard_webhooks import (
    WEBHOOK_SIGNATURE_HEADER,
    StandardWebhooksHmacSigner,
)

GOLDEN_PATH = Path(__file__).parents[2] / "golden" / "signatures" / "standard-webhooks.json"


def _handle(raw: bytes, name: str) -> SecretHandle:
    encoded = "whsec_" + base64.b64encode(raw).decode("ascii")
    return SecretResolver(environ={name: encoded}).resolve(EnvironmentSecretRef(env=name))


def test_golden_rotation_signatures_are_ordered_and_independently_verifiable() -> None:
    golden = cast("dict[str, object]", json.loads(GOLDEN_PATH.read_text(encoding="utf-8")))
    vector = cast("dict[str, object]", golden["vector"])
    primary = _handle(bytes(range(32)), "PRIMARY")
    rotation = _handle(bytes(range(32, 64)), "ROTATION")
    signer = StandardWebhooksHmacSigner(primary, additional_secrets=(rotation,))
    signing_input = SigningInput(
        body=base64.b64decode(cast("str", vector["body_base64"]), validate=True),
        event_id=cast("str", vector["event_id"]),
        logical_time_ns=cast("int", vector["logical_time_ns"]),
    )

    result = signer.sign(signing_input)
    assert golden["compatibility_review"] == {
        "status": "approved",
        "contract": "SIG-013,SIG-015",
        "marker": "standard-webhooks-hmac-v1-reviewed-2026-07-27",
    }
    assert signer.canonical_message(signing_input) == base64.b64decode(
        cast("str", vector["covered_bytes_base64"]), validate=True
    )
    assert result.headers[2].value == vector["webhook_signature"]
    first, second = result.headers[2].value.split(" ")
    metadata = result.headers[:2]
    assert signer.verify(
        signing_input,
        (*metadata, SignatureHeader(name=WEBHOOK_SIGNATURE_HEADER, value=first)),
    ).valid
    assert signer.verify(
        signing_input,
        (*metadata, SignatureHeader(name=WEBHOOK_SIGNATURE_HEADER, value=second)),
    ).valid


def test_exact_raw_bytes_and_header_metadata_are_covered() -> None:
    signer = StandardWebhooksHmacSigner(_handle(bytes(range(32)), "KEY"))
    first = SigningInput(body=b"\x00\xff\r\n", event_id="msg_a", logical_time_ns=1_999_999_999)
    second = SigningInput(body=b"\x00\xff\r\n ", event_id="msg_a", logical_time_ns=1_999_999_999)

    assert signer.canonical_message(first) == b"msg_a.1.\x00\xff\r\n"
    assert signer.sign(first).headers != signer.sign(second).headers
    assert signer.verify(first, signer.sign(first).headers).valid


def test_webhook_id_with_full_stop_is_signed_exactly_and_verifies() -> None:
    signer = StandardWebhooksHmacSigner(_handle(bytes(range(32)), "DOTTED_ID_KEY"))
    signing_input = SigningInput(
        body=b'{"ok":true}',
        event_id="tenant.example.msg_123",
        logical_time_ns=1_700_000_000_000_000_000,
    )

    result = signer.sign(signing_input)

    assert (
        signer.canonical_message(signing_input) == b'tenant.example.msg_123.1700000000.{"ok":true}'
    )
    assert result.headers[0].value == "tenant.example.msg_123"
    assert signer.verify(signing_input, result.headers).valid
