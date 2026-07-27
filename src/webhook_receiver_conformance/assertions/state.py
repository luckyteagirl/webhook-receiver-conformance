"""Pure, type-strict receiver-state assertion evaluation."""
# ruff: noqa: D105, EM101, FBT001, INP001, PLR0911, PLR0913, TRY003

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import cast

from webhook_receiver_conformance.config.models import (
    CallbackCountAssertion,
    Comparator,
    JournalCountAssertion,
    MissingPointer,
    ProcessingCountAssertion,
    ResourceAbsentAssertion,
    ResourceExistsAssertion,
    ResourceFieldAssertion,
    TypedValue,
)
from webhook_receiver_conformance.domain.enums import AssertionResult, EvidenceValueType
from webhook_receiver_conformance.observers.protocol import (
    BytesDigestMetadata,
    FrozenJsonObject,
    ObserverEvidence,
)

_DECIMAL_STRING = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_ARRAY_INDEX = re.compile(r"(?:0|[1-9][0-9]*)")

type StateAssertion = (
    ProcessingCountAssertion
    | CallbackCountAssertion
    | JournalCountAssertion
    | ResourceExistsAssertion
    | ResourceAbsentAssertion
    | ResourceFieldAssertion
)


class StateAssertionCode(StrEnum):
    """Stable, message-independent receiver-state evaluation facts."""

    COMPARISON_MATCH = "comparison_match"
    COMPARISON_MISMATCH = "comparison_mismatch"
    EVIDENCE_MISSING = "evidence_missing"
    EVIDENCE_DUPLICATE = "evidence_duplicate"
    EVIDENCE_TYPE_MISMATCH = "evidence_type_mismatch"
    POINTER_MISSING = "pointer_missing"
    COMPARATOR_UNSUPPORTED = "comparator_unsupported"


@dataclass(frozen=True, slots=True, repr=False)
class StateAssertionFact:
    """One typed comparison value whose contents stay out of diagnostics."""

    value_type: EvidenceValueType
    value: object = field(repr=False)
    sensitive: bool = False

    def __post_init__(self) -> None:
        if type(self.value_type) is not EvidenceValueType:
            raise TypeError("value_type must be an EvidenceValueType")
        if type(self.sensitive) is not bool:
            raise TypeError("sensitive must be a bool")
        _require_fact_shape(self.value_type, self.value)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(value_type={self.value_type!r}, "
            f"sensitive={self.sensitive!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class StateAssertionEvaluation:
    """Deterministic pass/fail/error facts for later journal integration."""

    assertion_id: str
    result: AssertionResult
    code: StateAssertionCode
    evidence_key: str
    expected: StateAssertionFact | None = field(default=None, repr=False)
    actual: StateAssertionFact | None = field(default=None, repr=False)
    source_evidence: ObserverEvidence | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.assertion_id) is not str or not self.assertion_id:
            raise ValueError("assertion_id must be a nonempty string")
        if type(self.result) is not AssertionResult:
            raise TypeError("result must be an AssertionResult")
        if self.result not in {
            AssertionResult.PASS,
            AssertionResult.FAIL,
            AssertionResult.ERROR,
        }:
            raise ValueError("state assertion result must be pass, fail, or error")
        if type(self.code) is not StateAssertionCode:
            raise TypeError("code must be a StateAssertionCode")
        if type(self.evidence_key) is not str or not self.evidence_key:
            raise ValueError("evidence_key must be a nonempty string")
        for fact, name in ((self.expected, "expected"), (self.actual, "actual")):
            if fact is not None and type(fact) is not StateAssertionFact:
                message = f"{name} must be a StateAssertionFact or None"
                raise TypeError(message)
        if self.source_evidence is not None and type(self.source_evidence) is not ObserverEvidence:
            raise TypeError("source_evidence must be an ObserverEvidence or None")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(assertion_id={self.assertion_id!r}, "
            f"result={self.result!r}, code={self.code!r}, "
            f"evidence_key={self.evidence_key!r})"
        )


def evaluate_state_assertion(
    assertion: StateAssertion,
    evidence: tuple[ObserverEvidence, ...],
) -> StateAssertionEvaluation:
    """Evaluate one supported receiver-state assertion against one snapshot."""
    if type(assertion) not in {
        ProcessingCountAssertion,
        CallbackCountAssertion,
        JournalCountAssertion,
        ResourceExistsAssertion,
        ResourceAbsentAssertion,
        ResourceFieldAssertion,
    }:
        raise TypeError("assertion must be a supported receiver-state assertion")
    if type(evidence) is not tuple or any(type(item) is not ObserverEvidence for item in evidence):
        raise TypeError("evidence must be a tuple of ObserverEvidence values")

    matching = tuple(item for item in evidence if item.key == assertion.query.key)
    if not matching:
        return _evaluation(
            assertion,
            AssertionResult.ERROR,
            StateAssertionCode.EVIDENCE_MISSING,
        )
    if len(matching) != 1:
        return _evaluation(
            assertion,
            AssertionResult.ERROR,
            StateAssertionCode.EVIDENCE_DUPLICATE,
        )
    observed = matching[0]
    if isinstance(
        assertion,
        (ProcessingCountAssertion, CallbackCountAssertion, JournalCountAssertion),
    ):
        return _evaluate_count(assertion, observed)
    if isinstance(assertion, (ResourceExistsAssertion, ResourceAbsentAssertion)):
        return _evaluate_existence(assertion, observed)
    return _evaluate_resource_field(assertion, observed)


def _evaluate_count(
    assertion: ProcessingCountAssertion | CallbackCountAssertion | JournalCountAssertion,
    evidence: ObserverEvidence,
) -> StateAssertionEvaluation:
    expected = StateAssertionFact(EvidenceValueType.INTEGER, assertion.expected)
    value = evidence.typed_value
    if evidence.value_type is not EvidenceValueType.INTEGER or type(value) is not int:
        return _evaluation(
            assertion,
            AssertionResult.ERROR,
            StateAssertionCode.EVIDENCE_TYPE_MISMATCH,
            expected=expected,
            source=evidence,
        )
    actual = StateAssertionFact(
        EvidenceValueType.INTEGER,
        value,
        sensitive=evidence.sensitive,
    )
    matched = _compare_numeric(
        Decimal(value),
        Decimal(assertion.expected),
        assertion.comparator,
    )
    return _comparison_evaluation(assertion, evidence, expected, actual, matched)


def _evaluate_existence(
    assertion: ResourceExistsAssertion | ResourceAbsentAssertion,
    evidence: ObserverEvidence,
) -> StateAssertionEvaluation:
    value = evidence.typed_value
    if evidence.value_type is EvidenceValueType.BOOLEAN and type(value) is bool:
        exists = value
    elif evidence.value_type is EvidenceValueType.OBJECT and isinstance(
        value,
        FrozenJsonObject,
    ):
        exists = True
    else:
        expected_exists = type(assertion) is ResourceExistsAssertion
        return _evaluation(
            assertion,
            AssertionResult.ERROR,
            StateAssertionCode.EVIDENCE_TYPE_MISMATCH,
            expected=StateAssertionFact(EvidenceValueType.BOOLEAN, expected_exists),
            source=evidence,
        )
    expected_exists = type(assertion) is ResourceExistsAssertion
    expected = StateAssertionFact(EvidenceValueType.BOOLEAN, expected_exists)
    actual = StateAssertionFact(
        EvidenceValueType.BOOLEAN,
        exists,
        sensitive=evidence.sensitive,
    )
    return _comparison_evaluation(
        assertion,
        evidence,
        expected,
        actual,
        exists is expected_exists,
    )


def _evaluate_resource_field(
    assertion: ResourceFieldAssertion,
    evidence: ObserverEvidence,
) -> StateAssertionEvaluation:
    expected = _expected_fact(assertion.expected)
    if evidence.value_type is not EvidenceValueType.OBJECT or not isinstance(
        evidence.typed_value,
        FrozenJsonObject,
    ):
        return _evaluation(
            assertion,
            AssertionResult.ERROR,
            StateAssertionCode.EVIDENCE_TYPE_MISMATCH,
            expected=expected,
            source=evidence,
        )
    found, raw_actual = _resolve_json_pointer(evidence.typed_value, assertion.path)
    if not found:
        result = (
            AssertionResult.FAIL
            if assertion.missing_pointer is MissingPointer.FAIL
            else AssertionResult.ERROR
        )
        return _evaluation(
            assertion,
            result,
            StateAssertionCode.POINTER_MISSING,
            expected=expected,
            source=evidence,
        )
    actual = _actual_fact(
        raw_actual,
        expected_type=expected.value_type,
        sensitive=evidence.sensitive,
    )
    matched = _compare_facts(actual, expected, assertion.comparator)
    if matched is None:
        return _evaluation(
            assertion,
            AssertionResult.ERROR,
            StateAssertionCode.COMPARATOR_UNSUPPORTED,
            expected=expected,
            actual=actual,
            source=evidence,
        )
    return _comparison_evaluation(assertion, evidence, expected, actual, matched)


def _comparison_evaluation(
    assertion: StateAssertion,
    evidence: ObserverEvidence,
    expected: StateAssertionFact,
    actual: StateAssertionFact,
    matched: bool,
) -> StateAssertionEvaluation:
    return _evaluation(
        assertion,
        AssertionResult.PASS if matched else AssertionResult.FAIL,
        (
            StateAssertionCode.COMPARISON_MATCH
            if matched
            else StateAssertionCode.COMPARISON_MISMATCH
        ),
        expected=expected,
        actual=actual,
        source=evidence,
    )


def _evaluation(
    assertion: StateAssertion,
    result: AssertionResult,
    code: StateAssertionCode,
    *,
    expected: StateAssertionFact | None = None,
    actual: StateAssertionFact | None = None,
    source: ObserverEvidence | None = None,
) -> StateAssertionEvaluation:
    return StateAssertionEvaluation(
        assertion_id=assertion.id,
        result=result,
        code=code,
        evidence_key=assertion.query.key,
        expected=expected,
        actual=actual,
        source_evidence=source,
    )


def _expected_fact(expected: TypedValue) -> StateAssertionFact:
    projection = expected.to_wire()
    raw_type = projection.get("value_type")
    if type(raw_type) is not str:
        raise TypeError("typed expected value lacks a value_type")
    return _validated_fact(
        EvidenceValueType(raw_type),
        projection.get("value"),
        sensitive=False,
    )


def _actual_fact(
    value: object,
    *,
    expected_type: EvidenceValueType,
    sensitive: bool,
) -> StateAssertionFact:
    inferred = _infer_value_type(value)
    if (
        inferred is EvidenceValueType.STRING
        and expected_type is EvidenceValueType.DECIMAL_STRING
        and type(value) is str
        and _DECIMAL_STRING.fullmatch(value) is not None
    ):
        inferred = EvidenceValueType.DECIMAL_STRING
    elif (
        inferred is EvidenceValueType.STRING
        and expected_type is EvidenceValueType.TIMESTAMP
        and type(value) is str
    ):
        try:
            return _validated_fact(expected_type, value, sensitive=sensitive)
        except (TypeError, ValueError):
            inferred = EvidenceValueType.STRING
    elif (
        inferred is EvidenceValueType.OBJECT
        and expected_type is EvidenceValueType.BYTES_DIGEST
    ):
        try:
            mapping = cast("Mapping[str, object]", value)
            return _validated_fact(
                expected_type,
                dict(mapping.items()),
                sensitive=sensitive,
            )
        except (TypeError, ValueError):
            inferred = EvidenceValueType.OBJECT
    return _validated_fact(inferred, value, sensitive=sensitive)


def _validated_fact(
    value_type: EvidenceValueType,
    value: object,
    *,
    sensitive: bool,
) -> StateAssertionFact:
    probe = ObserverEvidence.model_validate(
        {
            "key": "assertion_value",
            "value_type": value_type.value,
            "value": value,
            "sensitive": sensitive,
        }
    )
    return StateAssertionFact(probe.value_type, probe.typed_value, sensitive=sensitive)


def _infer_value_type(value: object) -> EvidenceValueType:
    if value is None:
        return EvidenceValueType.NULL
    if type(value) is bool:
        return EvidenceValueType.BOOLEAN
    if type(value) is int:
        return EvidenceValueType.INTEGER
    if type(value) is str:
        return EvidenceValueType.STRING
    if type(value) is tuple:
        return EvidenceValueType.ARRAY
    if isinstance(value, Mapping):
        return EvidenceValueType.OBJECT
    raise TypeError("observer object contains an unsupported field value")


def _compare_facts(
    actual: StateAssertionFact,
    expected: StateAssertionFact,
    comparator: Comparator,
) -> bool | None:
    if actual.value_type is not expected.value_type:
        if comparator is Comparator.EQ:
            return False
        if comparator is Comparator.NE:
            return True
        return None
    if actual.value_type is EvidenceValueType.INTEGER:
        return _compare_numeric(
            Decimal(cast("int", actual.value)),
            Decimal(cast("int", expected.value)),
            comparator,
        )
    if actual.value_type is EvidenceValueType.DECIMAL_STRING:
        try:
            left = Decimal(cast("str", actual.value))
            right = Decimal(cast("str", expected.value))
        except InvalidOperation:
            return None
        return _compare_numeric(left, right, comparator)
    if comparator not in {Comparator.EQ, Comparator.NE}:
        return None
    equal = _deep_exact_equal(actual.value, expected.value)
    return equal if comparator is Comparator.EQ else not equal


def _compare_numeric(left: Decimal, right: Decimal, comparator: Comparator) -> bool:
    return {
        Comparator.EQ: left == right,
        Comparator.NE: left != right,
        Comparator.LT: left < right,
        Comparator.LTE: left <= right,
        Comparator.GT: left > right,
        Comparator.GTE: left >= right,
    }[comparator]


def _deep_exact_equal(left: object, right: object) -> bool:
    if type(left) is BytesDigestMetadata or type(right) is BytesDigestMetadata:
        return type(left) is type(right) and left == right
    if type(left) is bool or type(right) is bool:
        return type(left) is type(right) and left == right
    if type(left) is int or type(right) is int:
        return type(left) is type(right) and left == right
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        left_mapping = cast("Mapping[object, object]", left)
        right_mapping = cast("Mapping[object, object]", right)
        if set(left_mapping) != set(right_mapping):
            return False
        return all(
            _deep_exact_equal(left_mapping[key], right_mapping[key])
            for key in left_mapping
        )
    if isinstance(left, Sequence) and not isinstance(left, (str, bytes)):
        if not isinstance(right, Sequence) or isinstance(right, (str, bytes)):
            return False
        left_sequence = cast("Sequence[object]", left)
        right_sequence = cast("Sequence[object]", right)
        return len(left_sequence) == len(right_sequence) and all(
            _deep_exact_equal(left_item, right_item)
            for left_item, right_item in zip(left_sequence, right_sequence, strict=True)
        )
    if left is None or right is None:
        return left is right
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    return False


def _resolve_json_pointer(root: FrozenJsonObject, pointer: str) -> tuple[bool, object]:
    if pointer == "":
        return True, root
    current: object = root
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            mapping = cast("Mapping[str, object]", current)
            if token not in mapping:
                return False, None
            current = mapping[token]
            continue
        if type(current) is tuple:
            if _ARRAY_INDEX.fullmatch(token) is None:
                return False, None
            index = int(token)
            sequence = cast("tuple[object, ...]", current)
            if index >= len(sequence):
                return False, None
            current = sequence[index]
            continue
        return False, None
    return True, current


def _require_fact_shape(value_type: EvidenceValueType, value: object) -> None:
    if value_type is EvidenceValueType.NULL and value is None:
        return
    if value_type is EvidenceValueType.BOOLEAN and type(value) is bool:
        return
    if value_type is EvidenceValueType.INTEGER and type(value) is int:
        return
    if value_type in {
        EvidenceValueType.DECIMAL_STRING,
        EvidenceValueType.STRING,
        EvidenceValueType.TIMESTAMP,
    } and type(value) is str:
        return
    if value_type is EvidenceValueType.BYTES_DIGEST and type(value) is BytesDigestMetadata:
        return
    if value_type is EvidenceValueType.ARRAY and type(value) is tuple:
        return
    if value_type is EvidenceValueType.OBJECT and isinstance(value, FrozenJsonObject):
        return
    raise TypeError("fact value does not match its declared evidence type")


__all__ = [
    "StateAssertionCode",
    "StateAssertionEvaluation",
    "StateAssertionFact",
    "evaluate_state_assertion",
]
