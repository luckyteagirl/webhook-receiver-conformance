"""Mutation compatibility and one-fault baseline semantic contracts."""
# ruff: noqa: INP001, PLR0913, PLR0917, PLR2004

from __future__ import annotations

import json

import pytest

from webhook_receiver_conformance.config.models import FaultClass
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.scenario.models import (
    DeliveryUserHeaders,
    ScenarioValidationContext,
)
from webhook_receiver_conformance.scenario.validate import validate_project_semantics

from ._support import ConfigObject, diagnostic_codes, make_project, make_scenario


def test_structural_json_after_invalid_json_has_operator_specific_diagnostic() -> None:
    scenario = make_scenario(
        mutations=[
            {"type": "invalid-json-v1", "strategy": "trailing-comma"},
            {
                "type": "remove-json-pointer-v1",
                "pointer": "/data",
            },
        ],
    )

    result = validate_project_semantics(
        make_project([scenario], fixture_media_type="application/json")
    )

    matching = [
        diagnostic
        for diagnostic in result.diagnostics
        if diagnostic.code == "MUT_INVALID_JSON_BEFORE_STRUCTURAL"
    ]
    assert len(matching) == 1
    assert matching[0].category is ErrorCategory.CONFLICTING_MUTATION
    assert matching[0].safe_details == {
        "operator": "remove-json-pointer-v1",
        "prior_operator": "invalid-json-v1",
    }


def test_structural_json_before_invalid_json_is_compatible() -> None:
    scenario = make_scenario(
        mutations=[
            {
                "type": "remove-json-pointer-v1",
                "pointer": "/data",
            },
            {"type": "invalid-json-v1", "strategy": "trailing-comma"},
        ],
    )

    codes = diagnostic_codes(
        validate_project_semantics(make_project([scenario], fixture_media_type="application/json"))
    )

    assert "MUT_INVALID_JSON_BEFORE_STRUCTURAL" not in codes
    assert "MUT_RAW_BYTES_BEFORE_STRUCTURAL" not in codes


@pytest.mark.parametrize(
    (
        "prior",
        "current",
        "prior_fault",
        "current_fault",
        "expected_code",
        "prior_stage",
        "current_stage",
    ),
    [
        (
            {"type": "content-type-mismatch-v1", "media_type": "text/plain"},
            {"type": "remove-json-pointer-v1", "pointer": "/data"},
            "mutation:content-type-mismatch-v1",
            "mutation:remove-json-pointer-v1",
            "MUT_REMOVE_JSON_POINTER_STAGE_ORDER",
            "header-pre-sign",
            "structural",
        ),
        (
            {"type": "wrong-signing-key-v1", "context": "wrong"},
            {"type": "truncate-bytes-v1", "length": 1},
            "mutation:wrong-signing-key-v1",
            "mutation:truncate-bytes-v1",
            "MUT_TRUNCATE_BYTES_STAGE_ORDER",
            "signing",
            "raw-pre-sign",
        ),
        (
            {"type": "alter-after-signing-v1", "offset": 0, "xor": 1},
            {"type": "content-type-mismatch-v1", "media_type": "text/plain"},
            "mutation:alter-after-signing-v1",
            "mutation:content-type-mismatch-v1",
            "MUT_CONTENT_TYPE_MISMATCH_STAGE_ORDER",
            "raw-post-sign",
            "header-pre-sign",
        ),
        (
            {"type": "missing-signature-v1"},
            {"type": "wrong-signing-key-v1", "context": "wrong"},
            "mutation:missing-signature-v1",
            "mutation:wrong-signing-key-v1",
            "MUT_WRONG_SIGNING_KEY_STAGE_ORDER",
            "header-post-sign",
            "signing",
        ),
    ],
)
def test_backward_mutation_stage_transition_fails_with_exact_baselines(
    prior: ConfigObject,
    current: ConfigObject,
    prior_fault: str,
    current_fault: str,
    expected_code: str,
    prior_stage: str,
    current_stage: str,
) -> None:
    prior_baseline = make_scenario("prior", mutations=[prior])
    current_baseline = make_scenario("current", mutations=[current])
    combined = make_scenario(
        "combined",
        mutations=[prior, current],
        baselines=[
            {"fault_class": prior_fault, "scenario": "prior"},
            {"fault_class": current_fault, "scenario": "current"},
        ],
    )

    result = validate_project_semantics(
        make_project(
            [prior_baseline, current_baseline, combined],
            fixture_media_type="application/json",
        )
    )

    assert diagnostic_codes(result) == [expected_code]
    assert result.diagnostics[0].safe_details == {
        "operator": str(current["type"]),
        "operator_stage": current_stage,
        "prior_operator": str(prior["type"]),
        "prior_stage": prior_stage,
    }


@pytest.mark.parametrize(
    ("mutations", "expected_code"),
    [
        (
            [
                {"type": "missing-signature-v1"},
                {"type": "missing-signature-v1"},
            ],
            "MUT_MISSING_SIGNATURE_CONFLICT",
        ),
        (
            [
                {"type": "missing-signature-v1"},
                {"type": "malformed-signature-v1", "case": "invalid-encoding"},
            ],
            "MUT_MALFORMED_SIGNATURE_CONFLICT",
        ),
        (
            [
                {"type": "malformed-signature-v1", "case": "invalid-delimiter"},
                {"type": "missing-signature-v1"},
            ],
            "MUT_MISSING_SIGNATURE_CONFLICT",
        ),
    ],
)
def test_signature_header_operations_conflict_with_operator_specific_code(
    mutations: list[ConfigObject],
    expected_code: str,
) -> None:
    result = validate_project_semantics(make_project([make_scenario(mutations=mutations)]))

    diagnostic = next(
        diagnostic for diagnostic in result.diagnostics if diagnostic.code == expected_code
    )
    assert diagnostic.category is ErrorCategory.CONFLICTING_MUTATION
    assert diagnostic.safe_details["operator"] == mutations[1]["type"]
    assert diagnostic.safe_details["prior_operator"] == mutations[0]["type"]


def test_same_structural_pointer_requires_explicit_later_override() -> None:
    mutations: list[ConfigObject] = [
        {"type": "remove-json-pointer-v1", "pointer": "/data"},
        {
            "type": "replace-json-value-v1",
            "pointer": "/data",
            "value": "replacement",
        },
    ]
    project = make_project(
        [make_scenario(mutations=mutations)],
        fixture_media_type="application/json",
    )

    assert "MUT_STRUCTURAL_POINTER_CONFLICT" in diagnostic_codes(
        validate_project_semantics(project)
    )

    mutations[1]["accept_prior_mutation"] = True
    overridden = make_project(
        [make_scenario(mutations=mutations)],
        fixture_media_type="application/json",
    )
    assert "MUT_STRUCTURAL_POINTER_CONFLICT" not in diagnostic_codes(
        validate_project_semantics(overridden)
    )


def test_structural_ancestor_overwrite_is_rejected() -> None:
    scenario = make_scenario(
        mutations=[
            {
                "type": "replace-json-value-v1",
                "pointer": "/data",
                "value": "scalar",
            },
            {
                "type": "replace-json-value-v1",
                "pointer": "/data/id",
                "value": "new",
            },
        ]
    )

    assert "MUT_STRUCTURAL_DEPENDENCY_CONFLICT" in diagnostic_codes(
        validate_project_semantics(make_project([scenario], fixture_media_type="application/json"))
    )


def test_add_field_same_target_requires_acceptance_and_overwrite() -> None:
    mutations: list[ConfigObject] = [
        {
            "type": "add-json-field-v1",
            "pointer": "/data",
            "name": "new",
            "value": 1,
        },
        {
            "type": "add-json-field-v1",
            "pointer": "/data",
            "name": "new",
            "value": 2,
            "accept_prior_mutation": True,
        },
    ]
    project = make_project(
        [make_scenario(mutations=mutations)],
        fixture_media_type="application/json",
    )

    assert "MUT_ADD_JSON_FIELD_COLLISION" in diagnostic_codes(validate_project_semantics(project))

    mutations[1]["overwrite"] = True
    accepted = make_project(
        [make_scenario(mutations=mutations)],
        fixture_media_type="application/json",
    )
    assert "MUT_ADD_JSON_FIELD_COLLISION" not in diagnostic_codes(
        validate_project_semantics(accepted)
    )


def test_repeated_remove_requires_missing_ignore_on_later_operation() -> None:
    mutations: list[ConfigObject] = [
        {"type": "remove-json-pointer-v1", "pointer": "/data"},
        {
            "type": "remove-json-pointer-v1",
            "pointer": "/data",
            "accept_prior_mutation": True,
        },
    ]
    project = make_project(
        [make_scenario(mutations=mutations)],
        fixture_media_type="application/json",
    )

    assert "MUT_REMOVE_JSON_POINTER_CONFLICT" in diagnostic_codes(
        validate_project_semantics(project)
    )

    mutations[1]["if_missing"] = "ignore"
    accepted = make_project(
        [make_scenario(mutations=mutations)],
        fixture_media_type="application/json",
    )
    assert "MUT_REMOVE_JSON_POINTER_CONFLICT" not in diagnostic_codes(
        validate_project_semantics(accepted)
    )


def test_structural_mutation_rejects_raw_fixture_but_raw_signing_does_not() -> None:
    structural = make_scenario(
        mutations=[
            {
                "type": "replace-json-value-v1",
                "pointer": "/id",
                "value": "changed",
            }
        ]
    )

    result = validate_project_semantics(make_project([structural]))

    assert diagnostic_codes(result) == ["MUT_STRUCTURAL_REQUIRES_JSON_FIXTURE"]
    assert result.diagnostics[0].category is ErrorCategory.MUTATION_NOT_APPLICABLE


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (
            {"type": "alter-after-signing-v1", "offset": 0, "xor": 1},
            "MUT_ALTER_AFTER_SIGNING_REQUIRES_SIGNER",
        ),
        (
            {"type": "stale-signature-timestamp-v1", "age": "1m"},
            "MUT_STALE_SIGNATURE_REQUIRES_SIGNER",
        ),
        (
            {"type": "wrong-signing-key-v1", "context": "wrong"},
            "MUT_WRONG_SIGNING_KEY_REQUIRES_SIGNER",
        ),
        (
            {"type": "missing-signature-v1"},
            "MUT_MISSING_SIGNATURE_REQUIRES_SIGNER",
        ),
        (
            {"type": "malformed-signature-v1", "case": "missing-component"},
            "MUT_MALFORMED_SIGNATURE_REQUIRES_SIGNER",
        ),
    ],
)
def test_signer_mutations_require_a_selected_signer(
    mutation: ConfigObject,
    expected_code: str,
) -> None:
    scenario = make_scenario(mutations=[mutation], signer=None)

    assert expected_code in diagnostic_codes(validate_project_semantics(make_project([scenario])))


def test_stale_timestamp_rejects_nontimestamped_generic_signer() -> None:
    scenario = make_scenario(mutations=[{"type": "stale-signature-timestamp-v1", "age": "1m"}])

    result = validate_project_semantics(make_project([scenario]))

    assert diagnostic_codes(result) == ["MUT_STALE_SIGNATURE_TIMESTAMP_NOT_APPLICABLE"]


def test_oversized_body_obeys_configured_request_cap() -> None:
    scenario = make_scenario(
        mutations=[
            {
                "type": "oversized-body-v1",
                "target_bytes": 1025,
                "fill": "ascii-space",
            }
        ]
    )

    result = validate_project_semantics(make_project([scenario], max_request_bytes=1024))

    assert diagnostic_codes(result) == ["MUT_OVERSIZED_BODY_EXCEEDS_REQUEST_LIMIT"]
    assert result.diagnostics[0].category is ErrorCategory.INVALID_PARAMETER


def test_post_sign_offset_must_survive_truncation() -> None:
    scenario = make_scenario(
        mutations=[
            {"type": "truncate-bytes-v1", "length": 4},
            {"type": "alter-after-signing-v1", "offset": 4, "xor": 1},
        ]
    )

    assert "MUT_ALTER_AFTER_TRUNCATION_RANGE" in diagnostic_codes(
        validate_project_semantics(make_project([scenario]))
    )


@pytest.mark.parametrize(
    ("later", "expected_code"),
    [
        (
            {"type": "invalid-json-v1", "strategy": "bad-escape"},
            "MUT_INVALID_JSON_AFTER_TRUNCATION",
        ),
        (
            {
                "type": "oversized-body-v1",
                "target_bytes": 8,
                "fill": "ascii-space",
            },
            "MUT_OVERSIZED_BODY_AFTER_TRUNCATION",
        ),
    ],
)
def test_later_raw_operator_cannot_require_bytes_removed_by_truncation(
    later: ConfigObject,
    expected_code: str,
) -> None:
    scenario = make_scenario(
        mutations=[
            {"type": "truncate-bytes-v1", "length": 4},
            later,
        ]
    )

    assert expected_code in diagnostic_codes(
        validate_project_semantics(make_project([scenario], fixture_media_type="application/json"))
    )


def test_wrong_key_plus_post_sign_alter_requires_named_purpose() -> None:
    scenario = make_scenario(
        mutations=[
            {"type": "wrong-signing-key-v1", "context": "wrong"},
            {"type": "alter-after-signing-v1", "offset": 0, "xor": 1},
        ]
    )

    assert "MUT_WRONG_KEY_ALTER_REQUIRES_PURPOSE" in diagnostic_codes(
        validate_project_semantics(make_project([scenario]))
    )

    described = make_scenario(
        mutations=[
            {"type": "wrong-signing-key-v1", "context": "wrong"},
            {"type": "alter-after-signing-v1", "offset": 0, "xor": 1},
        ],
        description="Distinguish wrong-key rejection from exact-byte coverage.",
    )
    assert "MUT_WRONG_KEY_ALTER_REQUIRES_PURPOSE" not in diagnostic_codes(
        validate_project_semantics(make_project([described]))
    )


def test_exact_multi_fault_baselines_validate() -> None:
    truncate = make_scenario(
        "truncate",
        mutations=[{"type": "truncate-bytes-v1", "length": 1}],
    )
    mismatch = make_scenario(
        "content_type",
        mutations=[
            {
                "type": "content-type-mismatch-v1",
                "media_type": "text/plain",
            }
        ],
    )
    combined = make_scenario(
        "combined",
        mutations=[
            {"type": "truncate-bytes-v1", "length": 1},
            {
                "type": "content-type-mismatch-v1",
                "media_type": "text/plain",
            },
        ],
        baselines=[
            {
                "fault_class": "mutation:truncate-bytes-v1",
                "scenario": "truncate",
            },
            {
                "fault_class": "mutation:content-type-mismatch-v1",
                "scenario": "content_type",
            },
        ],
    )

    result = validate_project_semantics(make_project([truncate, mismatch, combined]))

    assert result.ok
    assert result.scenarios[2].fault_classes == (
        FaultClass.MUTATION_TRUNCATE_BYTES,
        FaultClass.MUTATION_CONTENT_TYPE_MISMATCH,
    )


def test_multi_fault_scenario_reports_each_missing_one_fault_baseline() -> None:
    combined = make_scenario(
        mutations=[
            {"type": "truncate-bytes-v1", "length": 1},
            {
                "type": "content-type-mismatch-v1",
                "media_type": "text/plain",
            },
        ],
    )

    result = validate_project_semantics(make_project([combined]))
    required = [
        diagnostic
        for diagnostic in result.diagnostics
        if diagnostic.code == "SCENARIO_BASELINE_REQUIRED"
    ]

    assert [item.safe_details["fault_class"] for item in required] == [
        "mutation:truncate-bytes-v1",
        "mutation:content-type-mismatch-v1",
    ]


def test_baseline_reference_must_resolve_and_match_exactly_one_fault() -> None:
    no_fault = make_scenario("no_fault")
    truncate = make_scenario(
        "truncate",
        mutations=[{"type": "truncate-bytes-v1", "length": 1}],
        baselines=[
            {
                "fault_class": "mutation:truncate-bytes-v1",
                "scenario": "no_fault",
            }
        ],
    )
    wrong_match = make_scenario(
        "wrong_match",
        mutations=[
            {
                "type": "content-type-mismatch-v1",
                "media_type": "text/plain",
            }
        ],
    )
    mismatch = make_scenario(
        "mismatch",
        mutations=[{"type": "truncate-bytes-v1", "length": 1}],
        baselines=[
            {
                "fault_class": "mutation:truncate-bytes-v1",
                "scenario": "wrong_match",
            }
        ],
    )
    missing = make_scenario(
        "missing",
        mutations=[{"type": "truncate-bytes-v1", "length": 1}],
        baselines=[
            {
                "fault_class": "mutation:truncate-bytes-v1",
                "scenario": "absent",
            }
        ],
    )

    codes = diagnostic_codes(
        validate_project_semantics(
            make_project([no_fault, truncate, wrong_match, mismatch, missing])
        )
    )

    assert "SCENARIO_BASELINE_NOT_ONE_FAULT" in codes
    assert "SCENARIO_BASELINE_FAULT_MISMATCH" in codes
    assert "SCENARIO_BASELINE_NOT_FOUND" in codes


def test_baseline_self_reference_and_cycle_are_rejected() -> None:
    self_reference = make_scenario(
        "self_ref",
        mutations=[{"type": "truncate-bytes-v1", "length": 1}],
        baselines=[
            {
                "fault_class": "mutation:truncate-bytes-v1",
                "scenario": "self_ref",
            }
        ],
    )
    first = make_scenario(
        "first",
        mutations=[{"type": "truncate-bytes-v1", "length": 1}],
        baselines=[
            {
                "fault_class": "mutation:truncate-bytes-v1",
                "scenario": "second",
            }
        ],
    )
    second = make_scenario(
        "second",
        mutations=[{"type": "truncate-bytes-v1", "length": 1}],
        baselines=[
            {
                "fault_class": "mutation:truncate-bytes-v1",
                "scenario": "first",
            }
        ],
    )

    codes = diagnostic_codes(
        validate_project_semantics(make_project([self_reference, first, second]))
    )

    assert "SCENARIO_BASELINE_SELF_REFERENCE" in codes
    assert codes.count("SCENARIO_BASELINE_CYCLE") == 2


def test_diagnostics_do_not_serialize_user_header_or_description_canaries() -> None:
    canary = "x-secret-canary"
    project = make_project(
        [make_scenario(description="description-secret-canary")],
        signers={
            "generic": {
                "profile": "generic-hmac-sha256",
                "secret": {"generated": "hmac-256"},
                "header_name": canary,
            }
        },
    )
    context = ScenarioValidationContext(
        user_headers=(
            DeliveryUserHeaders(
                scenario_index=0,
                step_index=0,
                names=(canary,),
            ),
        )
    )

    result = validate_project_semantics(project, context=context)
    encoded = json.dumps([diagnostic.model_dump(mode="json") for diagnostic in result.diagnostics])

    assert "SIG_SIGNER_HEADER_CONFLICT" in diagnostic_codes(result)
    assert canary not in encoded
    assert "description-secret-canary" not in encoded
