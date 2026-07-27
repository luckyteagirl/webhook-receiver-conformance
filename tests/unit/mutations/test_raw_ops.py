"""Contract tests for raw-body and signature-state mutation operators."""
# ruff: noqa: INP001

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from webhook_receiver_conformance.config.models import EnvironmentSecretRef, GeneratedSecretRef
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.mutations.base import (
    MutationError,
    MutationStage,
    RealizedMutation,
    StaticMutationRegistry,
)
from webhook_receiver_conformance.mutations.pipeline import (
    MutationPipeline,
    MutationPipelineLimits,
    MutationPipelineResult,
)
from webhook_receiver_conformance.mutations.raw_ops import (
    ALTER_AFTER_SIGNING_V1,
    CONTENT_TYPE_MISMATCH_V1,
    INVALID_JSON_CASES,
    INVALID_JSON_V1,
    OVERSIZED_BODY_V1,
    RAW_MUTATION_REGISTRATIONS,
    TRUNCATE_BYTES_V1,
)
from webhook_receiver_conformance.mutations.signature_ops import (
    MALFORMED_SIGNATURE_CASES,
    MALFORMED_SIGNATURE_V1,
    MISSING_SIGNATURE_V1,
    SIGNATURE_MUTATION_REGISTRATIONS,
    STALE_SIGNATURE_TIMESTAMP_V1,
    WRONG_SIGNING_KEY_V1,
)
from webhook_receiver_conformance.secrets import SecretHandle, SecretResolver
from webhook_receiver_conformance.signatures.base import Signer, SigningInput
from webhook_receiver_conformance.signatures.hmac_generic import GenericHmacSha256Signer
from webhook_receiver_conformance.signatures.standard_webhooks import (
    StandardWebhooksHmacSigner,
)
from webhook_receiver_conformance.signatures.stripe import StripeV1Signer

_REGISTRY = StaticMutationRegistry((*RAW_MUTATION_REGISTRATIONS, *SIGNATURE_MUTATION_REGISTRATIONS))
_PIPELINE = MutationPipeline(_REGISTRY)
_BODY = b'{"id":"evt_1","ok":true}'
_TIME = 5_000_000_000


def _mutation(
    operator_id: str,
    stage: MutationStage,
    parameters: dict[str, object],
) -> RealizedMutation:
    return RealizedMutation(
        operator_id=operator_id,
        operator_version=1,
        stage=stage,
        parameters=parameters,
        parameters_safe=parameters,
    )


def _signer() -> GenericHmacSha256Signer:
    return GenericHmacSha256Signer(_handle())


def _handle() -> SecretHandle:
    return _handle_with_octet(0)


def _handle_with_octet(octet: int) -> SecretHandle:
    reference = GeneratedSecretRef.model_validate({"generated": "hmac-256"})
    return SecretResolver(token_bytes=lambda length: bytes([octet]) * length).resolve(reference)


def _standard_handle() -> SecretHandle:
    return _standard_handle_with_octet(0)


def _standard_handle_with_octet(octet: int) -> SecretHandle:
    encoded = "whsec_" + base64.b64encode(bytes([octet]) * 32).decode("ascii")
    return SecretResolver(environ={"STANDARD_KEY": encoded}).resolve(
        EnvironmentSecretRef(env="STANDARD_KEY")
    )


def _run(
    *mutations: RealizedMutation,
    body: bytes = _BODY,
    signer: Signer | None = None,
    pipeline: MutationPipeline = _PIPELINE,
) -> MutationPipelineResult:
    return pipeline.execute(
        body=body,
        headers=(),
        event_id="evt_contract_1",
        logical_time_ns=_TIME,
        media_type="application/json",
        signer=signer,
        mutations=mutations,
    )


@pytest.mark.parametrize("retained", [0, 1, len(_BODY)])
def test_vt_mut_012_truncation_boundaries_are_exact_and_deterministic(retained: int) -> None:
    mutation = _mutation(
        TRUNCATE_BYTES_V1,
        MutationStage.RAW_PRE_SIGN,
        {"length": retained},
    )
    first = _run(mutation)
    second = _run(mutation)
    assert first.body == _BODY[:retained] == second.body
    assert first.delivered_body_sha256 == sha256_digest(_BODY[:retained])
    assert first.mutation_evidence[0].operator_id == TRUNCATE_BYTES_V1


def test_truncation_rejects_length_beyond_body() -> None:
    mutation = _mutation(
        TRUNCATE_BYTES_V1,
        MutationStage.RAW_PRE_SIGN,
        {"length": len(_BODY) + 1},
    )
    with pytest.raises(MutationError) as captured:
        _run(mutation)
    assert str(captured.value.diagnostic.code) == "MUT_TRUNCATE_LENGTH_INVALID"


@pytest.mark.parametrize("strategy", INVALID_JSON_CASES)
def test_vt_mut_013_invalid_json_catalog_is_named_replayable_and_invalid(
    strategy: str,
) -> None:
    mutation = _mutation(
        INVALID_JSON_V1,
        MutationStage.RAW_PRE_SIGN,
        {"strategy": strategy},
    )
    first = _run(mutation)
    second = _run(mutation)
    assert first.body == second.body
    with pytest.raises(json.JSONDecodeError):
        json.loads(first.body)
    assert first.mutation_evidence[0].parameters_safe["strategy"] == strategy


def test_invalid_json_rejects_unknown_catalog_case() -> None:
    mutation = _mutation(
        INVALID_JSON_V1,
        MutationStage.RAW_PRE_SIGN,
        {"strategy": "unknown"},
    )
    with pytest.raises(MutationError) as captured:
        _run(mutation)
    assert str(captured.value.diagnostic.code) == "MUT_INVALID_JSON_CASE_INVALID"


def test_vt_mut_014_content_type_changes_without_changing_body() -> None:
    mutation = _mutation(
        CONTENT_TYPE_MISMATCH_V1,
        MutationStage.HEADER_PRE_SIGN,
        {"media_type": "text/plain"},
    )
    result = _run(mutation)
    assert result.body == _BODY
    assert tuple((item.name, item.value) for item in result.headers) == (
        ("content-type", "text/plain"),
    )
    evidence = result.mutation_evidence[0]
    assert evidence.input_body_sha256 == evidence.output_body_sha256


def test_content_type_rejects_non_ascii_header_value_deterministically() -> None:
    mutation = _mutation(
        CONTENT_TYPE_MISMATCH_V1,
        MutationStage.HEADER_PRE_SIGN,
        {"media_type": "text/pl\u00e4in"},
    )
    with pytest.raises(MutationError) as captured:
        _run(mutation)
    assert str(captured.value.diagnostic.code) == "MUT_CONTENT_TYPE_INVALID"


def test_vt_mut_015_and_vt_sig_010_post_sign_alter_preserves_signature() -> None:
    signer = _signer()
    baseline = _run(signer=signer)
    mutation = _mutation(
        ALTER_AFTER_SIGNING_V1,
        MutationStage.RAW_POST_SIGN,
        {"offset": 0, "xor": 1},
    )
    result = _run(mutation, signer=signer)
    assert result.headers == baseline.headers
    assert result.signed_body_sha256 == sha256_digest(_BODY)
    assert result.delivered_body_sha256 != result.signed_body_sha256
    assert result.mutation_evidence[0].input_body_sha256 == result.signed_body_sha256


@pytest.mark.parametrize(
    ("parameters", "code"),
    [
        ({"offset": len(_BODY), "xor": 1}, "MUT_ALTER_OFFSET_INVALID"),
        ({"offset": 0, "xor": 0}, "MUT_ALTER_XOR_INVALID"),
    ],
)
def test_post_sign_alter_rejects_invalid_ranges(
    parameters: dict[str, object],
    code: str,
) -> None:
    mutation = _mutation(
        ALTER_AFTER_SIGNING_V1,
        MutationStage.RAW_POST_SIGN,
        parameters,
    )
    with pytest.raises(MutationError) as captured:
        _run(mutation, signer=_signer())
    assert str(captured.value.diagnostic.code) == code


def test_vt_sig_007_missing_signature_removes_only_owned_header() -> None:
    content_type = _mutation(
        CONTENT_TYPE_MISMATCH_V1,
        MutationStage.HEADER_PRE_SIGN,
        {"media_type": "text/plain"},
    )
    mutation = _mutation(
        MISSING_SIGNATURE_V1,
        MutationStage.HEADER_POST_SIGN,
        {},
    )
    result = _run(content_type, mutation, signer=_signer())
    assert result.body == _BODY
    assert tuple((header.name, header.value) for header in result.headers) == (
        ("content-type", "text/plain"),
    )
    assert result.mutation_evidence[-1].operator_id == MISSING_SIGNATURE_V1


@pytest.mark.parametrize("case", MALFORMED_SIGNATURE_CASES)
def test_vt_sig_008_malformed_cases_remain_distinct_and_deterministic(case: str) -> None:
    mutation = _mutation(
        MALFORMED_SIGNATURE_V1,
        MutationStage.HEADER_POST_SIGN,
        {"case": case},
    )
    first = _run(mutation, signer=_signer())
    second = _run(mutation, signer=_signer())
    assert first.headers == second.headers
    assert first.mutation_evidence[0].operator_id == MALFORMED_SIGNATURE_V1
    assert first.mutation_evidence[0].parameters_safe["case"] == case


def test_malformed_catalog_outputs_are_not_collapsed() -> None:
    outputs = {
        case: _run(
            _mutation(
                MALFORMED_SIGNATURE_V1,
                MutationStage.HEADER_POST_SIGN,
                {"case": case},
            ),
            signer=_signer(),
        )
        .headers[0]
        .value
        for case in MALFORMED_SIGNATURE_CASES
    }
    assert len(set(outputs.values())) == len(MALFORMED_SIGNATURE_CASES)


def test_vt_sig_009_wrong_key_has_distinct_fingerprint_and_is_rejected() -> None:
    signer = _signer()
    baseline = _run(signer=signer)
    mutation = _mutation(
        WRONG_SIGNING_KEY_V1,
        MutationStage.SIGNING,
        {"context": "negative-case-1"},
    )
    wrong = _run(mutation, signer=signer)
    assert baseline.signing_evidence is not None
    assert wrong.signing_evidence is not None
    assert wrong.signing_evidence.key_fingerprint != baseline.signing_evidence.key_fingerprint
    assert wrong.headers != baseline.headers
    verification = signer.verify(
        signing_input=SigningInput(
            body=_BODY,
            event_id="evt_contract_1",
            logical_time_ns=_TIME,
        ),
        headers=wrong.headers,
    )
    assert not verification.valid


@pytest.mark.parametrize(
    "signer",
    [
        GenericHmacSha256Signer(_handle()),
        StripeV1Signer(_handle()),
        StandardWebhooksHmacSigner(_standard_handle()),
    ],
)
def test_wrong_key_supports_every_keyed_builtin_signer(signer: Signer) -> None:
    baseline = _run(signer=signer)
    mutation = _mutation(
        WRONG_SIGNING_KEY_V1,
        MutationStage.SIGNING,
        {"context": "all-builtins-case"},
    )
    wrong = _run(mutation, signer=signer)
    assert baseline.signing_evidence is not None
    assert wrong.signing_evidence is not None
    assert baseline.signing_evidence.key_fingerprint != wrong.signing_evidence.key_fingerprint
    assert not signer.verify(
        SigningInput(body=_BODY, event_id="evt_contract_1", logical_time_ns=_TIME),
        wrong.headers,
    ).valid


@pytest.mark.parametrize(
    "signer",
    [
        StripeV1Signer(
            _handle_with_octet(1),
            additional_secrets=(_handle_with_octet(2),),
        ),
        StandardWebhooksHmacSigner(
            _standard_handle_with_octet(1),
            additional_secrets=(_standard_handle_with_octet(2),),
        ),
    ],
)
def test_wrong_key_preserves_rotated_builtin_key_count(signer: Signer) -> None:
    expected_key_count = 2
    mutation = _mutation(
        WRONG_SIGNING_KEY_V1,
        MutationStage.SIGNING,
        {"context": "rotated-key-case"},
    )
    wrong = _run(mutation, signer=signer)
    assert not signer.verify(
        SigningInput(body=_BODY, event_id="evt_contract_1", logical_time_ns=_TIME),
        wrong.headers,
    ).valid
    signature_value = wrong.headers[-1].value
    assert (
        signature_value.count("v1=") == expected_key_count
        or signature_value.count("v1,") == expected_key_count
    )


@pytest.mark.parametrize("context", ["\ud800", "\U0001f680" * 1025])
def test_wrong_key_rejects_non_utf8_or_oversized_utf8_context(context: str) -> None:
    mutation = _mutation(
        WRONG_SIGNING_KEY_V1,
        MutationStage.SIGNING,
        {"context": context},
    )
    with pytest.raises(MutationError) as captured:
        _run(mutation, signer=_signer())
    assert str(captured.value.diagnostic.code) == "MUT_WRONG_KEY_CONTEXT_INVALID"


def test_stale_timestamp_changes_signing_time_before_signature() -> None:
    mutation = _mutation(
        STALE_SIGNATURE_TIMESTAMP_V1,
        MutationStage.SIGNING,
        {"age_ns": 1_000_000_000},
    )
    result = _run(mutation, signer=StripeV1Signer(_handle()))
    assert result.signing_evidence is not None
    assert result.signing_evidence.logical_time_ns == _TIME - 1_000_000_000


def test_vt_mut_016_signature_state_operators_are_distinct() -> None:
    assert {item.operator_id for item in SIGNATURE_MUTATION_REGISTRATIONS} == {
        STALE_SIGNATURE_TIMESTAMP_V1,
        WRONG_SIGNING_KEY_V1,
        MISSING_SIGNATURE_V1,
        MALFORMED_SIGNATURE_V1,
    }


def test_vt_mut_017_pipeline_preserves_fixed_stage_order() -> None:
    mutations = (
        _mutation(
            TRUNCATE_BYTES_V1,
            MutationStage.RAW_PRE_SIGN,
            {"length": len(_BODY) - 1},
        ),
        _mutation(
            CONTENT_TYPE_MISMATCH_V1,
            MutationStage.HEADER_PRE_SIGN,
            {"media_type": "text/plain"},
        ),
        _mutation(
            ALTER_AFTER_SIGNING_V1,
            MutationStage.RAW_POST_SIGN,
            {"offset": 0, "xor": 1},
        ),
    )
    result = _run(*mutations, signer=_signer())
    assert tuple(item.stage for item in result.mutation_evidence) == (
        MutationStage.RAW_PRE_SIGN,
        MutationStage.HEADER_PRE_SIGN,
        MutationStage.RAW_POST_SIGN,
    )


def test_oversized_body_rejects_above_hard_limit_before_allocation() -> None:
    mutation = _mutation(
        OVERSIZED_BODY_V1,
        MutationStage.RAW_PRE_SIGN,
        {"target_bytes": 16_777_217, "fill": "ascii-space"},
    )
    with pytest.raises(MutationError) as captured:
        _run(mutation)
    assert str(captured.value.diagnostic.code) == "MUT_OVERSIZED_TARGET_INVALID"


def test_oversized_body_hits_configured_pipeline_limit() -> None:
    pipeline = MutationPipeline(
        _REGISTRY,
        MutationPipelineLimits(max_body_bytes=32),
    )
    mutation = _mutation(
        OVERSIZED_BODY_V1,
        MutationStage.RAW_PRE_SIGN,
        {"target_bytes": 33, "fill": "ascii-space"},
    )
    with pytest.raises(MutationError) as captured:
        _run(mutation, pipeline=pipeline)
    assert str(captured.value.diagnostic.code) == "MUT_BODY_LIMIT"


def test_operator_repr_and_diagnostics_do_not_leak_context_canary() -> None:
    canary = "wrong-key-secret-canary"
    mutation = _mutation(
        WRONG_SIGNING_KEY_V1,
        MutationStage.SIGNING,
        {"context": canary},
    )
    assert canary not in repr(mutation)
    with pytest.raises(MutationError) as captured:
        _run(mutation)
    assert canary not in repr(captured.value)
    assert canary not in str(captured.value.diagnostic.safe_details)


def test_golden_operator_catalog_is_stable() -> None:
    golden = {
        "raw": [item.operator_id for item in RAW_MUTATION_REGISTRATIONS],
        "signature": [item.operator_id for item in SIGNATURE_MUTATION_REGISTRATIONS],
        "invalid_json_cases": list(INVALID_JSON_CASES),
        "malformed_signature_cases": list(MALFORMED_SIGNATURE_CASES),
    }
    expected = {
        "raw": [
            "truncate-bytes-v1",
            "invalid-json-v1",
            "content-type-mismatch-v1",
            "alter-after-signing-v1",
            "oversized-body-v1",
        ],
        "signature": [
            "stale-signature-timestamp-v1",
            "wrong-signing-key-v1",
            "missing-signature-v1",
            "malformed-signature-v1",
        ],
        "invalid_json_cases": ["truncated-object", "bad-escape", "trailing-comma"],
        "malformed_signature_cases": [
            "invalid-encoding",
            "missing-component",
            "invalid-delimiter",
            "duplicate-component",
        ],
    }
    assert golden == expected
    assert Path("tests/unit/mutations/test_raw_ops.py").is_file()
