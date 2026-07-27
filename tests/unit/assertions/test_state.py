"""Type-strict receiver-state assertion evaluator tests."""
# ruff: noqa: ANN202, INP001

from __future__ import annotations

from typing import cast

import pytest

from webhook_receiver_conformance.assertions.state import (
    StateAssertionCode,
    StateAssertionEvaluation,
    evaluate_state_assertion,
)
from webhook_receiver_conformance.config.models import (
    CallbackCountAssertion,
    JournalCountAssertion,
    ProcessingCountAssertion,
    ResourceAbsentAssertion,
    ResourceExistsAssertion,
    ResourceFieldAssertion,
)
from webhook_receiver_conformance.domain.enums import AssertionResult, EvidenceValueType
from webhook_receiver_conformance.observers.protocol import ObserverEvidence


def _query(key: str) -> dict[str, object]:
    return {
        "observer": "receiver_state",
        "key": key,
        "parameters": {"event": "payment"},
    }


def _count(
    kind: str = "processing-count",
    *,
    comparator: str = "eq",
    expected: int = 1,
    key: str = "processing_count",
):
    model = {
        "id": f"{kind}-assertion",
        "type": kind,
        "query": _query(key),
        "comparator": comparator,
        "expected": expected,
    }
    types = {
        "processing-count": ProcessingCountAssertion,
        "callback-count": CallbackCountAssertion,
        "journal-count": JournalCountAssertion,
    }
    return types[kind].model_validate(model)


def _exists(kind: str = "resource-exists", *, key: str = "resource"):
    model = {
        "id": f"{kind}-assertion",
        "type": kind,
        "query": _query(key),
    }
    return (
        ResourceExistsAssertion.model_validate(model)
        if kind == "resource-exists"
        else ResourceAbsentAssertion.model_validate(model)
    )


def _field(
    *,
    path: str = "/status",
    comparator: str = "eq",
    value_type: str = "string",
    value: object = "processed",
    missing_pointer: str = "error",
):
    return ResourceFieldAssertion.model_validate(
        {
            "id": "resource-field-assertion",
            "type": "resource-field",
            "query": _query("resource"),
            "path": path,
            "comparator": comparator,
            "expected": {"value_type": value_type, "value": value},
            "missing_pointer": missing_pointer,
        }
    )


def _evidence(
    key: str,
    value_type: str,
    value: object,
    *,
    sensitive: bool = False,
) -> ObserverEvidence:
    return ObserverEvidence.model_validate(
        {
            "key": key,
            "value_type": value_type,
            "value": value,
            "sensitive": sensitive,
        }
    )


@pytest.mark.parametrize(
    ("comparator", "actual", "expected", "result"),
    [
        ("eq", 1, 1, AssertionResult.PASS),
        ("ne", 2, 1, AssertionResult.PASS),
        ("lt", -1, 0, AssertionResult.PASS),
        ("lte", 0, 0, AssertionResult.PASS),
        ("gt", 9_007_199_254_740_991, 1, AssertionResult.PASS),
        ("gte", 1, 2, AssertionResult.FAIL),
    ],
)
def test_processing_count_uses_exact_integer_comparators(
    comparator: str,
    actual: int,
    expected: int,
    result: AssertionResult,
) -> None:
    evaluation = evaluate_state_assertion(
        _count(comparator=comparator, expected=expected),
        (_evidence("processing_count", "integer", actual),),
    )
    assert evaluation.result is result
    assert evaluation.code is (
        StateAssertionCode.COMPARISON_MATCH
        if result is AssertionResult.PASS
        else StateAssertionCode.COMPARISON_MISMATCH
    )
    assert evaluation.actual is not None
    assert evaluation.actual.value == actual
    assert evaluation.expected is not None
    assert evaluation.expected.value == expected


@pytest.mark.parametrize(
    ("kind", "key"),
    [
        ("processing-count", "processing_count"),
        ("callback-count", "callback_count"),
        ("journal-count", "journal_count"),
    ],
)
def test_all_named_count_assertions_share_strict_semantics(kind: str, key: str) -> None:
    evaluation = evaluate_state_assertion(
        _count(kind, key=key),
        (_evidence(key, "integer", 1),),
    )
    assert evaluation.result is AssertionResult.PASS
    assert evaluation.evidence_key == key


@pytest.mark.parametrize(
    ("value_type", "value"),
    [
        ("boolean", True),
        ("string", "1"),
        ("null", None),
        ("object", {"count": 1}),
    ],
)
def test_noninteger_count_is_error_not_receiver_failure(
    value_type: str,
    value: object,
) -> None:
    evaluation = evaluate_state_assertion(
        _count(),
        (_evidence("processing_count", value_type, value),),
    )
    assert evaluation.result is AssertionResult.ERROR
    assert evaluation.code is StateAssertionCode.EVIDENCE_TYPE_MISMATCH
    assert evaluation.actual is None


def test_missing_and_duplicate_named_evidence_are_explicit_errors() -> None:
    assertion = _count()
    missing = evaluate_state_assertion(
        assertion,
        (_evidence("another_key", "integer", 1),),
    )
    assert (missing.result, missing.code) == (
        AssertionResult.ERROR,
        StateAssertionCode.EVIDENCE_MISSING,
    )

    duplicate = evaluate_state_assertion(
        assertion,
        (
            _evidence("processing_count", "integer", 1),
            _evidence("processing_count", "integer", 1),
        ),
    )
    assert (duplicate.result, duplicate.code) == (
        AssertionResult.ERROR,
        StateAssertionCode.EVIDENCE_DUPLICATE,
    )


@pytest.mark.parametrize(
    ("assertion_kind", "value_type", "value", "expected"),
    [
        ("resource-exists", "boolean", True, AssertionResult.PASS),
        ("resource-exists", "boolean", False, AssertionResult.FAIL),
        ("resource-absent", "boolean", False, AssertionResult.PASS),
        ("resource-absent", "boolean", True, AssertionResult.FAIL),
        ("resource-exists", "object", {}, AssertionResult.PASS),
        ("resource-absent", "object", {"id": 1}, AssertionResult.FAIL),
    ],
)
def test_resource_existence_is_strict_boolean_or_object(
    assertion_kind: str,
    value_type: str,
    value: object,
    expected: AssertionResult,
) -> None:
    evaluation = evaluate_state_assertion(
        _exists(assertion_kind),
        (_evidence("resource", value_type, value),),
    )
    assert evaluation.result is expected


@pytest.mark.parametrize(
    ("value_type", "value"),
    [("null", None), ("integer", 1), ("string", "yes"), ("array", [])],
)
def test_resource_existence_rejects_undeclared_evidence_types(
    value_type: str,
    value: object,
) -> None:
    evaluation = evaluate_state_assertion(
        _exists(),
        (_evidence("resource", value_type, value),),
    )
    assert (evaluation.result, evaluation.code) == (
        AssertionResult.ERROR,
        StateAssertionCode.EVIDENCE_TYPE_MISMATCH,
    )


def test_typed_field_equality_never_coerces_integer_and_string() -> None:
    integer_actual = evaluate_state_assertion(
        _field(value_type="string", value="1"),
        (_evidence("resource", "object", {"status": 1}),),
    )
    string_actual = evaluate_state_assertion(
        _field(value_type="integer", value=1),
        (_evidence("resource", "object", {"status": "1"}),),
    )
    for evaluation in (integer_actual, string_actual):
        assert evaluation.result is AssertionResult.FAIL
        assert evaluation.code is StateAssertionCode.COMPARISON_MISMATCH


def test_decimal_comparison_retains_lexemes_and_uses_decimal_semantics() -> None:
    evaluation = evaluate_state_assertion(
        _field(value_type="decimal-string", value="0.1"),
        (_evidence("resource", "object", {"status": "0.10"}),),
    )
    assert evaluation.result is AssertionResult.PASS
    assert evaluation.actual is not None
    assert evaluation.actual.value_type is EvidenceValueType.DECIMAL_STRING
    assert evaluation.actual.value == "0.10"
    assert evaluation.expected is not None
    assert evaluation.expected.value == "0.1"

    ordered = evaluate_state_assertion(
        _field(comparator="gt", value_type="decimal-string", value="9.99"),
        (_evidence("resource", "object", {"status": "10.0"}),),
    )
    assert ordered.result is AssertionResult.PASS


def test_nonnumeric_field_ordering_is_an_assertion_error() -> None:
    evaluation = evaluate_state_assertion(
        _field(comparator="lt", value_type="string", value="z"),
        (_evidence("resource", "object", {"status": "a"}),),
    )
    assert (evaluation.result, evaluation.code) == (
        AssertionResult.ERROR,
        StateAssertionCode.COMPARATOR_UNSUPPORTED,
    )


def test_resource_field_requires_object_evidence() -> None:
    evaluation = evaluate_state_assertion(
        _field(),
        (_evidence("resource", "string", "processed"),),
    )
    assert (evaluation.result, evaluation.code) == (
        AssertionResult.ERROR,
        StateAssertionCode.EVIDENCE_TYPE_MISMATCH,
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/a~1b/~0key/1", "second"),
        ("/array/0", "first"),
        ("", {"a/b": {"~key": ["first", "second"]}, "array": ["first"]}),
    ],
)
def test_json_pointer_root_escaping_and_array_indices(path: str, expected: object) -> None:
    payload = {
        "a/b": {"~key": ["first", "second"]},
        "array": ["first"],
    }
    value_type = "object" if path == "" else "string"
    evaluation = evaluate_state_assertion(
        _field(path=path, value_type=value_type, value=expected),
        (_evidence("resource", "object", payload),),
    )
    assert evaluation.result is AssertionResult.PASS


@pytest.mark.parametrize("path", ["/missing", "/array/01", "/array/-", "/array/9"])
@pytest.mark.parametrize(
    ("policy", "result"),
    [("fail", AssertionResult.FAIL), ("error", AssertionResult.ERROR)],
)
def test_missing_pointer_policy_is_exact(
    path: str,
    policy: str,
    result: AssertionResult,
) -> None:
    evaluation = evaluate_state_assertion(
        _field(path=path, missing_pointer=policy),
        (_evidence("resource", "object", {"array": ["first"]}),),
    )
    assert (evaluation.result, evaluation.code) == (
        result,
        StateAssertionCode.POINTER_MISSING,
    )


def test_array_and_object_equality_are_deep_type_strict_and_ordered() -> None:
    object_result = evaluate_state_assertion(
        _field(
            path="/nested",
            value_type="object",
            value={"a": 1, "b": [True, "x"]},
        ),
        (_evidence("resource", "object", {"nested": {"b": [True, "x"], "a": 1}}),),
    )
    ordered_array = evaluate_state_assertion(
        _field(path="/values", value_type="array", value=[1, 2]),
        (_evidence("resource", "object", {"values": [2, 1]}),),
    )
    boolean_integer = evaluate_state_assertion(
        _field(path="/values", value_type="array", value=[1]),
        (_evidence("resource", "object", {"values": [True]}),),
    )
    assert object_result.result is AssertionResult.PASS
    assert ordered_array.result is AssertionResult.FAIL
    assert boolean_integer.result is AssertionResult.FAIL


def test_bytes_digest_field_compares_metadata_without_bytes() -> None:
    metadata = {
        "sha256": f"sha256:{'a' * 64}",
        "byte_length": 42,
        "media_type": "application/octet-stream",
    }
    evaluation = evaluate_state_assertion(
        _field(path="/payload", value_type="bytes-digest", value=metadata),
        (_evidence("resource", "object", {"payload": metadata}),),
    )
    assert evaluation.result is AssertionResult.PASS
    assert "payload bytes" not in repr(evaluation)


def test_sensitive_values_never_appear_in_fact_or_evaluation_repr() -> None:
    secret = "sensitive-receiver-value"  # noqa: S105
    evaluation = evaluate_state_assertion(
        _field(value=secret),
        (_evidence("resource", "object", {"status": secret}, sensitive=True),),
    )
    assert evaluation.result is AssertionResult.PASS
    assert evaluation.actual is not None
    assert evaluation.actual.sensitive is True
    assert secret not in repr(evaluation)
    assert secret not in repr(evaluation.actual)
    assert secret not in repr(evaluation.source_evidence)


def test_evaluator_rejects_wrong_assertion_and_collection_boundaries() -> None:
    assertion = _count()
    item = _evidence("processing_count", "integer", 1)
    with pytest.raises(TypeError, match="tuple"):
        evaluate_state_assertion(assertion, [item])  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match="ObserverEvidence"):
        evaluate_state_assertion(assertion, (cast("ObserverEvidence", object()),))
    with pytest.raises(TypeError, match="supported receiver-state"):
        evaluate_state_assertion(
            cast("ProcessingCountAssertion", object()),
            (item,),
        )


def test_evaluation_records_are_immutable_and_message_independent() -> None:
    evaluation = evaluate_state_assertion(
        _count(),
        (_evidence("processing_count", "integer", 1),),
    )
    assert type(evaluation) is StateAssertionEvaluation
    assert evaluation.code.value == "comparison_match"
    with pytest.raises(AttributeError):
        evaluation.code = StateAssertionCode.COMPARISON_MISMATCH  # pyright: ignore[reportAttributeAccessIssue]
