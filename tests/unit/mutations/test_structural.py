"""Golden, semantic, boundary, and privacy tests for structural mutations."""
# ruff: noqa: INP001, S105

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from webhook_receiver_conformance.config.models import EnvironmentSecretRef
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.mutations.base import (
    REDACTED_PARAMETER_VALUE,
    MutationError,
    MutationStage,
    RealizedMutation,
    thaw_parameter_object,
)
from webhook_receiver_conformance.mutations.pipeline import (
    MutationPipeline,
    MutationPipelineResult,
)
from webhook_receiver_conformance.mutations.structural import (
    ADD_JSON_FIELD_V1,
    CHANGE_EVENT_ID_FIELD_V1,
    CHANGE_EVENT_TYPE_FIELD_V1,
    JSON_COMPACT_UTF8_V1,
    REMOVE_JSON_POINTER_V1,
    REPLACE_JSON_TYPE_V1,
    REPLACE_JSON_VALUE_V1,
    STRUCTURAL_MUTATION_REGISTRATIONS,
    STRUCTURAL_MUTATION_REGISTRY,
    serialize_json_compact_utf8_v1,
)
from webhook_receiver_conformance.secrets import SecretResolver
from webhook_receiver_conformance.signatures.base import (
    SignatureHeader,
    Signer,
    SigningInput,
)
from webhook_receiver_conformance.signatures.hmac_generic import (
    GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_V1,
    GenericHmacSha256Settings,
    GenericHmacSha256Signer,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from webhook_receiver_conformance.types import JsonValue

EVENT_ID = "evt_harness_logical_1"
LOGICAL_TIME_NS = 1_700_000_000_123_456_789
SECRET_CANARY = "structural-mutation-secret-canary"
GOLDEN_PATH = Path(__file__).parents[2] / "golden" / "json-compact-utf8-v1.json"


def _realized(
    operator_id: str,
    parameters: dict[str, object],
    *,
    parameters_safe: dict[str, object] | None = None,
) -> RealizedMutation:
    return RealizedMutation(
        operator_id=operator_id,
        operator_version=1,
        stage=MutationStage.STRUCTURAL,
        parameters=parameters,
        parameters_safe=parameters_safe,
    )


def _run(  # noqa: PLR0913
    operator_id: str,
    parameters: dict[str, object],
    *,
    body: bytes = b'{"a":1}',
    media_type: str = "application/json",
    event_id: str = EVENT_ID,
    signer: Signer | None = None,
    headers: Sequence[SignatureHeader] = (),
) -> MutationPipelineResult:
    return MutationPipeline(STRUCTURAL_MUTATION_REGISTRY).execute(
        body=body,
        headers=headers,
        event_id=event_id,
        logical_time_ns=LOGICAL_TIME_NS,
        media_type=media_type,
        signer=signer,
        mutations=(_realized(operator_id, parameters),),
    )


def _caught(
    operator_id: str,
    parameters: dict[str, object],
    *,
    body: bytes = b'{"a":1}',
    media_type: str = "application/json",
) -> MutationError:
    with pytest.raises(MutationError) as caught:
        _run(operator_id, parameters, body=body, media_type=media_type)
    return caught.value


def _json_body(result: MutationPipelineResult) -> JsonValue:
    return cast("JsonValue", json.loads(result.body))


def _golden() -> dict[str, object]:
    return cast("dict[str, object]", json.loads(GOLDEN_PATH.read_text(encoding="utf-8")))


def _test_signer() -> GenericHmacSha256Signer:
    handle = SecretResolver(environ={"STRUCTURAL_TEST_SIGNING_KEY": "structural-test-key"}).resolve(
        EnvironmentSecretRef(env="STRUCTURAL_TEST_SIGNING_KEY")
    )
    return GenericHmacSha256Signer(
        handle,
        GenericHmacSha256Settings(template=GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_V1),
    )


def test_structural_registry_has_exact_normative_id_version_stage_and_effects() -> None:
    expected_ids = (
        REMOVE_JSON_POINTER_V1,
        REPLACE_JSON_VALUE_V1,
        REPLACE_JSON_TYPE_V1,
        ADD_JSON_FIELD_V1,
        CHANGE_EVENT_ID_FIELD_V1,
        CHANGE_EVENT_TYPE_FIELD_V1,
    )
    assert STRUCTURAL_MUTATION_REGISTRY.operator_versions == tuple(
        (operator_id, 1) for operator_id in expected_ids
    )
    assert (
        tuple(registration.operator_id for registration in STRUCTURAL_MUTATION_REGISTRATIONS)
        == expected_ids
    )
    for registration in STRUCTURAL_MUTATION_REGISTRATIONS:
        assert registration.operator_version == 1
        assert registration.stage is MutationStage.STRUCTURAL
        assert registration.changes_body is True
        assert registration.requires_valid_json is True
        assert registration.invalidates_json is False
        assert registration.written_headers == ()
        assert registration.removed_headers == ()
        assert registration.may_change_signing_time is False
        assert registration.may_replace_signer is False


def test_json_compact_utf8_v1_golden_contract_metadata() -> None:
    golden = _golden()
    assert golden["serializer_id"] == JSON_COMPACT_UTF8_V1
    assert golden["encoding"] == "UTF-8 without BOM"
    assert golden["key_order"] == "ascending UTF-16 big-endian code units"
    assert golden["duplicate_member_names"] == "rejected"
    numeric = cast("dict[str, object]", golden["numeric_domain"])
    assert numeric == {
        "kind": "safe-integer-only",
        "minimum": -9_007_199_254_740_991,
        "maximum": 9_007_199_254_740_991,
        "fractional_or_exponent_lexemes": "rejected",
    }


def test_json_compact_utf8_v1_golden_vectors() -> None:
    vectors = cast("list[dict[str, object]]", _golden()["vectors"])
    for vector in vectors:
        if "input_json_text" in vector:
            value: object = json.loads(cast("str", vector["input_json_text"]))
        else:
            value = vector["input_value"]
        expected = cast("str", vector["expected_json_text"]).encode()
        actual = serialize_json_compact_utf8_v1(value)
        assert actual == expected, vector["name"]
        if "expected_utf8_hex" in vector:
            assert actual.hex() == vector["expected_utf8_hex"], vector["name"]


def test_json_compact_utf8_v1_is_deterministic_and_emits_no_bom() -> None:
    value = {"z": [3, 2, 1], "é": "雪", "a": {"b": True}}
    first = serialize_json_compact_utf8_v1(value)
    second = serialize_json_compact_utf8_v1(value)
    assert first == second
    assert not first.startswith(b"\xef\xbb\xbf")
    assert b" " not in first
    assert first.decode("utf-8") == '{"a":{"b":true},"z":[3,2,1],"é":"雪"}'


@pytest.mark.parametrize(
    ("value", "exception_type"),
    [
        (1.0, ValueError),
        (float("nan"), ValueError),
        (float("inf"), ValueError),
        (9_007_199_254_740_992, ValueError),
        ("\ud800", ValueError),
        ({"bad": object()}, ValueError),
    ],
)
def test_serializer_rejects_values_outside_the_lossless_domain(
    value: object,
    exception_type: type[Exception],
) -> None:
    with pytest.raises(exception_type):
        serialize_json_compact_utf8_v1(value)


def test_serializer_rejects_reference_cycles() -> None:
    value: list[object] = []
    value.append(value)
    with pytest.raises(ValueError, match=r"^$"):
        serialize_json_compact_utf8_v1(value)


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b'{"a":', "MUT_STRUCTURAL_INPUT_INVALID_JSON"),
        (b"\xff", "MUT_STRUCTURAL_INPUT_INVALID_JSON"),
        (b"\xef\xbb\xbf{}", "MUT_STRUCTURAL_INPUT_INVALID_JSON"),
        (b'{"n":NaN}', "MUT_STRUCTURAL_INPUT_INVALID_JSON"),
        (b'{"n":Infinity}', "MUT_STRUCTURAL_INPUT_INVALID_JSON"),
    ],
)
def test_invalid_rfc_json_is_rejected_before_the_operator(
    body: bytes,
    code: str,
) -> None:
    error = _caught(REPLACE_JSON_VALUE_V1, {"pointer": "", "value": None}, body=body)
    assert error.diagnostic.category is ErrorCategory.MUTATION_NOT_APPLICABLE
    assert error.diagnostic.code == code


def test_golden_rejected_structural_inputs_are_classified_without_coercion() -> None:
    cases = cast("list[dict[str, object]]", _golden()["rejected_inputs"])
    for case in cases:
        body = cast("str", case["input_json_text"]).encode()
        error = _caught(
            REPLACE_JSON_VALUE_V1,
            {"pointer": "", "value": None},
            body=body,
        )
        assert error.diagnostic.category is ErrorCategory.MUTATION_NOT_APPLICABLE
        assert error.diagnostic.code == case["diagnostic_code"], case["name"]


def test_duplicate_member_detection_uses_decoded_names_at_every_depth() -> None:
    error = _caught(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "", "value": None},
        body=b'{"outer":{"a":1,"\\u0061":2}}',
    )
    assert error.diagnostic.category is ErrorCategory.MUTATION_NOT_APPLICABLE
    assert error.diagnostic.code == "MUT_STRUCTURAL_JSON_DUPLICATE_MEMBER"


def test_safe_integer_boundaries_are_accepted_and_negative_zero_is_canonicalized() -> None:
    body = b"[-9007199254740991,9007199254740991,-0]"
    result = _run(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/3", "if_missing": "ignore"},
        body=body,
    )
    assert result.body == b"[-9007199254740991,9007199254740991,0]"


@pytest.mark.parametrize(
    "body",
    [
        json.dumps([0] * 1_001, separators=(",", ":")).encode(),
        json.dumps("x" * 4_097).encode(),
        json.dumps({"k" * 257: 1}).encode(),
    ],
)
def test_structural_json_collection_and_text_limits_are_classified(
    body: bytes,
) -> None:
    error = _caught(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/missing", "if_missing": "ignore"},
        body=body,
    )
    assert error.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert error.diagnostic.code == "MUT_STRUCTURAL_JSON_RESOURCE_LIMIT"


def test_structural_json_accepts_depth_64_and_rejects_depth_65() -> None:
    accepted: object = 0
    for _index in range(63):
        accepted = [accepted]
    accepted_body = json.dumps(accepted, separators=(",", ":")).encode()
    assert (
        _run(
            REMOVE_JSON_POINTER_V1,
            {"pointer": "/1", "if_missing": "ignore"},
            body=accepted_body,
        ).body
        == accepted_body
    )

    rejected: object = [accepted]
    rejected_body = json.dumps(rejected, separators=(",", ":")).encode()
    error = _caught(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/1", "if_missing": "ignore"},
        body=rejected_body,
    )
    assert error.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert error.diagnostic.code == "MUT_STRUCTURAL_JSON_RESOURCE_LIMIT"


def test_structural_json_rejects_more_than_100000_nodes() -> None:
    value = [[0] * 100 for _index in range(1_000)]
    body = json.dumps(value, separators=(",", ":")).encode()
    error = _caught(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/1000", "if_missing": "ignore"},
        body=body,
    )
    assert error.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert error.diagnostic.code == "MUT_STRUCTURAL_JSON_RESOURCE_LIMIT"


def test_structural_output_is_measured_before_exceeding_the_body_cap() -> None:
    chunk = "x" * 4_096
    replacement = [[chunk] * 5 for _index in range(1_000)]
    error = _caught(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "", "value": replacement},
        body=b"null",
    )
    assert error.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert error.diagnostic.code == "MUT_STRUCTURAL_JSON_OUTPUT_LIMIT"


def test_remove_json_pointer_decodes_rfc6901_escapes_and_empty_tokens() -> None:
    body = b'{"a/b":{"~key":{"":1,"keep":2}},"other":3}'
    result = _run(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/a~1b/~0key/"},
        body=body,
    )
    assert result.body == b'{"a/b":{"~key":{"keep":2}},"other":3}'


def test_json_pointer_decodes_tilde_zero_before_following_one() -> None:
    result = _run(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "/~01", "value": 2},
        body=b'{"~1":1}',
    )
    assert result.body == b'{"~1":2}'


def test_object_member_that_looks_like_an_array_index_remains_a_member() -> None:
    result = _run(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/01"},
        body=b'{"01":1,"keep":2}',
    )
    assert result.body == b'{"keep":2}'


def test_remove_json_pointer_removes_array_element_and_compacts_indices() -> None:
    result = _run(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/items/1"},
        body=b'{"items":["a","b","c"]}',
    )
    assert result.body == b'{"items":["a","c"]}'


def test_remove_missing_pointer_error_and_ignore_policies() -> None:
    error = _caught(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/missing", "if_missing": "error"},
        body=b'{"z":1,"a":2}',
    )
    assert error.diagnostic.category is ErrorCategory.MUTATION_NOT_APPLICABLE
    assert error.diagnostic.code == "MUT_JSON_POINTER_MISSING"

    ignored = _run(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/missing", "if_missing": "ignore"},
        body=b'{ "z": 1, "a": 2 }',
    )
    assert ignored.body == b'{"a":2,"z":1}'


def test_remove_document_root_is_rejected_even_when_missing_is_ignored() -> None:
    error = _caught(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "", "if_missing": "ignore"},
    )
    assert error.diagnostic.category is ErrorCategory.INVALID_PARAMETER
    assert error.diagnostic.code == "MUT_JSON_POINTER_ROOT_OPERATION_INVALID"


@pytest.mark.parametrize(
    "pointer",
    ["not-a-pointer", "/~", "/~2", "/a/~x", "/\ud800"],
)
def test_malformed_json_pointer_is_invalid_parameter(pointer: str) -> None:
    error = _caught(REMOVE_JSON_POINTER_V1, {"pointer": pointer})
    assert error.diagnostic.category is ErrorCategory.INVALID_PARAMETER
    assert error.diagnostic.code == "MUT_JSON_POINTER_INVALID"


def test_pointer_segment_count_is_resource_bounded() -> None:
    pointer = "/" + "/".join("a" for _index in range(65))
    error = _caught(REMOVE_JSON_POINTER_V1, {"pointer": pointer})
    assert error.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert error.diagnostic.code == "MUT_JSON_POINTER_LIMIT"


@pytest.mark.parametrize(
    "pointer",
    ["/01", "/00", "/-", "/-1", "/+1", "/\N{ARABIC-INDIC DIGIT ONE}"],
)
def test_noncanonical_array_indices_are_invalid_parameter(pointer: str) -> None:
    error = _caught(REMOVE_JSON_POINTER_V1, {"pointer": pointer}, body=b"[1,2]")
    assert error.diagnostic.category is ErrorCategory.INVALID_PARAMETER
    assert error.diagnostic.code == "MUT_JSON_POINTER_ARRAY_INDEX_INVALID"


def test_out_of_bounds_array_index_obeys_remove_missing_policy() -> None:
    error = _caught(
        REMOVE_JSON_POINTER_V1,
        {"pointer": "/2"},
        body=b"[1,2]",
    )
    assert error.diagnostic.code == "MUT_JSON_POINTER_MISSING"
    assert (
        _run(
            REMOVE_JSON_POINTER_V1,
            {"pointer": "/2", "if_missing": "ignore"},
            body=b"[1,2]",
        ).body
        == b"[1,2]"
    )


def test_replace_json_value_supports_root_array_and_empty_object_keys() -> None:
    exact = {"": [False, None, {"x": 7}]}
    result = _run(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "", "value": exact},
        body=b'{"old":true}',
    )
    assert result.body == b'{"":[false,null,{"x":7}]}'

    array_result = _run(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "/1", "value": {"z": 2, "a": 1}},
        body=b"[0,1,2]",
    )
    assert array_result.body == b'[0,{"a":1,"z":2},2]'


def test_realized_manifest_parameters_preserve_exact_replacement_json() -> None:
    parameters: dict[str, object] = {
        "pointer": "/target",
        "value": {"": [False, None, {"nested": 9_007_199_254_740_991}]},
        "accept_prior_mutation": True,
    }
    realized = _realized(REPLACE_JSON_VALUE_V1, parameters)
    assert thaw_parameter_object(realized.parameters) == parameters


def test_replace_json_value_requires_existing_target() -> None:
    error = _caught(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "/missing", "value": 1},
    )
    assert error.diagnostic.category is ErrorCategory.MUTATION_NOT_APPLICABLE
    assert error.diagnostic.code == "MUT_JSON_POINTER_MISSING"


@pytest.mark.parametrize(
    ("source", "target_type", "representative"),
    [
        (1, "null", None),
        (1, "boolean", False),
        ("old", "integer", 0),
        (1, "string", ""),
        (1, "array", []),
        (1, "object", {}),
    ],
)
def test_replace_json_type_uses_documented_deterministic_representatives(
    source: JsonValue,
    target_type: str,
    representative: JsonValue,
) -> None:
    body = json.dumps({"value": source}, separators=(",", ":")).encode()
    result = _run(
        REPLACE_JSON_TYPE_V1,
        {"pointer": "/value", "target_type": target_type},
        body=body,
    )
    assert _json_body(result) == {"value": representative}


def test_replace_number_with_string_has_exact_documented_bytes() -> None:
    result = _run(
        REPLACE_JSON_TYPE_V1,
        {"pointer": "/amount", "target_type": "string"},
        body=b'{"other":true,"amount":42}',
    )
    assert result.body == b'{"amount":"","other":true}'


def test_replace_json_type_rejects_same_or_unknown_type() -> None:
    same = _caught(
        REPLACE_JSON_TYPE_V1,
        {"pointer": "/a", "target_type": "integer"},
    )
    assert same.diagnostic.category is ErrorCategory.INVALID_PARAMETER
    assert same.diagnostic.code == "MUT_REPLACE_JSON_TYPE_UNCHANGED"

    unknown = _caught(
        REPLACE_JSON_TYPE_V1,
        {"pointer": "/a", "target_type": "number"},
    )
    assert unknown.diagnostic.category is ErrorCategory.INVALID_PARAMETER
    assert unknown.diagnostic.code == "MUT_REPLACE_JSON_TYPE_INVALID"


def test_add_json_field_adds_nested_exact_value() -> None:
    result = _run(
        ADD_JSON_FIELD_V1,
        {
            "pointer": "/data",
            "name": "unknown",
            "value": {"": 1, "nested": [True, None]},
        },
        body=b'{"data":{"known":2},"id":"evt"}',
    )
    assert result.body == (b'{"data":{"known":2,"unknown":{"":1,"nested":[true,null]}},"id":"evt"}')


def test_add_json_field_collision_requires_explicit_overwrite() -> None:
    error = _caught(
        ADD_JSON_FIELD_V1,
        {"pointer": "", "name": "a", "value": 2},
    )
    assert error.diagnostic.category is ErrorCategory.CONFLICTING_MUTATION
    assert error.diagnostic.code == "MUT_ADD_JSON_FIELD_COLLISION"

    overwritten = _run(
        ADD_JSON_FIELD_V1,
        {"pointer": "", "name": "a", "value": 2, "overwrite": True},
    )
    assert overwritten.body == b'{"a":2}'


def test_add_json_field_requires_an_existing_object_target() -> None:
    scalar = _caught(
        ADD_JSON_FIELD_V1,
        {"pointer": "/a", "name": "x", "value": 2},
    )
    assert scalar.diagnostic.category is ErrorCategory.MUTATION_NOT_APPLICABLE
    assert scalar.diagnostic.code == "MUT_ADD_JSON_FIELD_TARGET_NOT_OBJECT"

    missing = _caught(
        ADD_JSON_FIELD_V1,
        {"pointer": "/missing", "name": "x", "value": 2},
    )
    assert missing.diagnostic.code == "MUT_JSON_POINTER_MISSING"


@pytest.mark.parametrize("name", ["", "x" * 257, "\ud800"])
def test_add_json_field_rejects_invalid_member_name(name: str) -> None:
    error = _caught(
        ADD_JSON_FIELD_V1,
        {"pointer": "", "name": name, "value": 2},
    )
    assert error.diagnostic.category is ErrorCategory.INVALID_PARAMETER
    assert error.diagnostic.code == "MUT_ADD_JSON_FIELD_NAME_INVALID"


def test_change_event_id_field_changes_payload_but_not_harness_signing_identity() -> None:
    signer = _test_signer()
    result = _run(
        CHANGE_EVENT_ID_FIELD_V1,
        {"pointer": "/payload/id", "value": "evt_provider_changed"},
        body=b'{"payload":{"id":"evt_provider_original"},"keep":1}',
        signer=signer,
    )
    assert result.body == b'{"keep":1,"payload":{"id":"evt_provider_changed"}}'

    expected = signer.sign(
        SigningInput(
            body=result.body,
            event_id=EVENT_ID,
            logical_time_ns=LOGICAL_TIME_NS,
        )
    )
    changed_logical_identity = signer.sign(
        SigningInput(
            body=result.body,
            event_id="evt_provider_changed",
            logical_time_ns=LOGICAL_TIME_NS,
        )
    )
    assert result.headers == expected.headers
    assert result.headers != changed_logical_identity.headers
    assert result.signing_evidence == expected.evidence


def test_change_event_type_field_changes_only_configured_pointer() -> None:
    before = {
        "id": "evt_1",
        "type": "created",
        "nested": {"type": "unrelated"},
        "items": [1, 2],
    }
    result = _run(
        CHANGE_EVENT_TYPE_FIELD_V1,
        {"pointer": "/type", "value": "deleted"},
        body=json.dumps(before, separators=(",", ":")).encode(),
    )
    after = _json_body(result)
    assert after == {
        "id": "evt_1",
        "type": "deleted",
        "nested": {"type": "unrelated"},
        "items": [1, 2],
    }


@pytest.mark.parametrize(
    ("operator_id", "parameters"),
    [
        (REMOVE_JSON_POINTER_V1, {}),
        (REMOVE_JSON_POINTER_V1, {"pointer": "/a", "unknown": True}),
        (REMOVE_JSON_POINTER_V1, {"pointer": "/a", "if_missing": "skip"}),
        (REPLACE_JSON_VALUE_V1, {"pointer": "/a"}),
        (
            REPLACE_JSON_VALUE_V1,
            {"pointer": "/a", "value": 2, "accept_prior_mutation": 0},
        ),
        (
            ADD_JSON_FIELD_V1,
            {"pointer": "", "name": "x", "value": 2, "overwrite": 0},
        ),
        (
            CHANGE_EVENT_ID_FIELD_V1,
            {"pointer": "/a", "value": ""},
        ),
    ],
)
def test_structural_operators_enforce_strict_parameter_schemas(
    operator_id: str,
    parameters: dict[str, object],
) -> None:
    error = _caught(operator_id, parameters)
    assert error.diagnostic.category is ErrorCategory.INVALID_PARAMETER


def test_structural_mutation_requires_a_json_media_type() -> None:
    error = _caught(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "/a", "value": 2},
        media_type="text/plain",
    )
    assert error.diagnostic.category is ErrorCategory.MUTATION_NOT_APPLICABLE
    assert error.diagnostic.code == "MUT_STRUCTURAL_REQUIRES_JSON"

    result = _run(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "/a", "value": 2},
        media_type="application/vnd.example+json; charset=utf-8",
    )
    assert result.body == b'{"a":2}'


def test_realized_replacement_is_detached_from_mutable_source() -> None:
    source_value = {"nested": [1]}
    realized = _realized(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "/a", "value": source_value},
    )
    source_value["nested"][0] = 9
    result = MutationPipeline(STRUCTURAL_MUTATION_REGISTRY).execute(
        body=b'{"a":0}',
        headers=(),
        event_id=EVENT_ID,
        logical_time_ns=LOGICAL_TIME_NS,
        media_type="application/json",
        signer=None,
        mutations=(realized,),
    )
    assert result.body == b'{"a":{"nested":[1]}}'


def test_structural_evidence_records_exact_hashes_without_parameter_leakage() -> None:
    realized = _realized(
        REPLACE_JSON_VALUE_V1,
        {"pointer": "/a", "value": SECRET_CANARY},
    )
    result = MutationPipeline(STRUCTURAL_MUTATION_REGISTRY).execute(
        body=b'{"a":"old"}',
        headers=(SignatureHeader(name="x-public", value="visible"),),
        event_id=EVENT_ID,
        logical_time_ns=LOGICAL_TIME_NS,
        media_type="application/json",
        signer=None,
        mutations=(realized,),
    )
    evidence = result.mutation_evidence[0]
    assert evidence.input_body_sha256 == sha256_digest(b'{"a":"old"}')
    assert evidence.output_body_sha256 == sha256_digest(result.body)
    assert evidence.parameters_safe["pointer"] == REDACTED_PARAMETER_VALUE
    assert evidence.parameters_safe["value"] == REDACTED_PARAMETER_VALUE
    assert result.headers == (SignatureHeader(name="x-public", value="visible"),)

    rendered = " ".join(
        (
            repr(realized),
            repr(evidence),
            repr(result),
            json.dumps(evidence.log_safe_dict()),
            json.dumps(result.log_safe_dict()),
        )
    )
    assert SECRET_CANARY not in rendered
    assert "visible" not in rendered


def test_failure_diagnostic_does_not_leak_raw_replacement_or_pointer() -> None:
    pointer_canary = f"/missing-{SECRET_CANARY}"
    error = _caught(
        REPLACE_JSON_VALUE_V1,
        {"pointer": pointer_canary, "value": SECRET_CANARY},
    )
    rendered = " ".join(
        (
            str(error),
            repr(error),
            json.dumps(error.diagnostic.model_dump(mode="json")),
        )
    )
    assert SECRET_CANARY not in rendered
    assert pointer_canary not in rendered


def test_identical_realizations_produce_identical_bytes_and_evidence() -> None:
    parameters: dict[str, object] = {
        "pointer": "/value",
        "value": {"z": 2, "a": [1, True]},
    }
    first = _run(
        REPLACE_JSON_VALUE_V1,
        parameters,
        body=b'{ "value": 0, "keep": null }',
    )
    second = _run(
        REPLACE_JSON_VALUE_V1,
        parameters,
        body=b'{ "value": 0, "keep": null }',
    )
    assert first.body == second.body == b'{"keep":null,"value":{"a":[1,true],"z":2}}'
    assert first.mutation_evidence == second.mutation_evidence
    assert first.delivered_body_sha256 == second.delivered_body_sha256
