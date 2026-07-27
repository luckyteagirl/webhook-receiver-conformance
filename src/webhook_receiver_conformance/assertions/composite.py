"""Pure all-or-none evaluation over one normalized observer snapshot."""
# ruff: noqa: INP001

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import cast

from webhook_receiver_conformance.config.models import (
    Comparator,
    MissingPointer,
    NoPartialSideEffectAssertion,
    OnUnsupported,
    Predicate,
    TypedValue,
)
from webhook_receiver_conformance.domain.enums import AssertionResult, EvidenceValueType
from webhook_receiver_conformance.observers.protocol import (
    BytesDigestMetadata,
    FrozenJsonObject,
    ObserverEvidence,
    ObserverResponse,
    ObserverResponseStatus,
)

from .state import StateAssertionFact

_DECIMAL_STRING = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_ARRAY_INDEX = re.compile(r"(?:0|[1-9][0-9]*)")
_MIN_COMPOSITE_PREDICATES = 2


class EvidencePredicateCode(StrEnum):
    """Stable, value-independent facts from one typed evidence predicate."""

    MATCH = "predicate_match"
    MISMATCH = "predicate_mismatch"
    EVIDENCE_MISSING = "evidence_missing"
    EVIDENCE_DUPLICATE = "evidence_duplicate"
    EVIDENCE_TYPE_MISMATCH = "evidence_type_mismatch"
    POINTER_MISSING = "pointer_missing"
    COMPARATOR_UNSUPPORTED = "comparator_unsupported"


class CompositeAssertionCode(StrEnum):
    """Stable terminal facts for an all-or-none assertion."""

    ALL_PRESENT = "all_side_effects_present"
    NONE_PRESENT = "no_side_effects_present"
    PARTIAL_SIDE_EFFECT = "partial_side_effect"
    PREDICATE_ERROR = "predicate_error"
    SNAPSHOT_SCOPE_MISMATCH = "snapshot_scope_mismatch"
    OBSERVER_PENDING = "observer_pending"
    OBSERVER_UNSUPPORTED = "observer_unsupported"
    OBSERVER_ERROR = "observer_error"


@dataclass(frozen=True, slots=True, repr=False)
class EvidencePredicateEvaluation:
    """One named predicate result with secret-safe typed comparison facts."""

    predicate_name: str
    evidence_key: str
    result: AssertionResult
    code: EvidencePredicateCode
    truth_value: bool | None
    expected: StateAssertionFact | None = field(default=None, repr=False)
    actual: StateAssertionFact | None = field(default=None, repr=False)
    source_evidence: ObserverEvidence | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Validate the internal result invariants."""
        for value, name in (
            (self.predicate_name, "predicate_name"),
            (self.evidence_key, "evidence_key"),
        ):
            if type(value) is not str or not value:
                message = f"{name} must be a nonempty string"
                raise ValueError(message)
        if type(self.result) is not AssertionResult:
            message = "result must be an AssertionResult"
            raise TypeError(message)
        if self.result not in {
            AssertionResult.PASS,
            AssertionResult.FAIL,
            AssertionResult.ERROR,
        }:
            message = "predicate result must be pass, fail, or error"
            raise ValueError(message)
        if type(self.code) is not EvidencePredicateCode:
            message = "code must be an EvidencePredicateCode"
            raise TypeError(message)
        expected_truth = {
            AssertionResult.PASS: True,
            AssertionResult.FAIL: False,
            AssertionResult.ERROR: None,
        }[self.result]
        if self.truth_value is not expected_truth:
            message = "truth_value must agree with the predicate result"
            raise ValueError(message)
        for fact, name in ((self.expected, "expected"), (self.actual, "actual")):
            if fact is not None and type(fact) is not StateAssertionFact:
                message = f"{name} must be a StateAssertionFact or None"
                raise TypeError(message)
        if self.source_evidence is not None and type(self.source_evidence) is not ObserverEvidence:
            message = "source_evidence must be an ObserverEvidence or None"
            raise TypeError(message)

    def __repr__(self) -> str:
        """Return a representation that excludes evidence values."""
        return (
            f"{type(self).__name__}(predicate_name={self.predicate_name!r}, "
            f"evidence_key={self.evidence_key!r}, result={self.result!r}, "
            f"code={self.code!r}, truth_value={self.truth_value!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class NoPartialSideEffectEvaluation:
    """One deterministic all-or-none result bound to one observer snapshot."""

    assertion_id: str
    result: AssertionResult
    code: CompositeAssertionCode
    predicates: tuple[EvidencePredicateEvaluation, ...]
    snapshot_id: str | None = None

    def __post_init__(self) -> None:
        """Validate the terminal result and configured predicate identities."""
        if type(self.assertion_id) is not str or not self.assertion_id:
            message = "assertion_id must be a nonempty string"
            raise ValueError(message)
        if type(self.result) is not AssertionResult:
            message = "result must be an AssertionResult"
            raise TypeError(message)
        if self.result not in {
            AssertionResult.PASS,
            AssertionResult.FAIL,
            AssertionResult.ERROR,
            AssertionResult.SKIPPED,
        }:
            message = "composite result must be pass, fail, error, or skipped"
            raise ValueError(message)
        if type(self.code) is not CompositeAssertionCode:
            message = "code must be a CompositeAssertionCode"
            raise TypeError(message)
        if (
            type(self.predicates) is not tuple
            or len(self.predicates) < _MIN_COMPOSITE_PREDICATES
            or any(type(item) is not EvidencePredicateEvaluation for item in self.predicates)
        ):
            message = "predicates must contain at least two predicate evaluations"
            raise TypeError(message)
        names = tuple(item.predicate_name for item in self.predicates)
        if len(set(names)) != len(names):
            message = "predicate evaluation names must be unique"
            raise ValueError(message)
        if self.snapshot_id is not None and (
            type(self.snapshot_id) is not str or not self.snapshot_id
        ):
            message = "snapshot_id must be a nonempty string or None"
            raise ValueError(message)

    @property
    def predicate_values(self) -> tuple[tuple[str, bool | None], ...]:
        """Return every named truth value in configured order."""
        return tuple((item.predicate_name, item.truth_value) for item in self.predicates)

    def __repr__(self) -> str:
        """Return a representation that excludes predicate evidence values."""
        return (
            f"{type(self).__name__}(assertion_id={self.assertion_id!r}, "
            f"result={self.result!r}, code={self.code!r}, "
            f"predicate_count={len(self.predicates)}, "
            f"snapshot_id={self.snapshot_id!r})"
        )


def evaluate_evidence_predicate(
    predicate: Predicate,
    evidence: tuple[ObserverEvidence, ...],
) -> EvidencePredicateEvaluation:
    """Evaluate one named, typed predicate against a normalized snapshot."""
    if type(predicate) is not Predicate:
        message = "predicate must be a Predicate"
        raise TypeError(message)
    if type(evidence) is not tuple or any(type(item) is not ObserverEvidence for item in evidence):
        message = "evidence must be a tuple of ObserverEvidence values"
        raise TypeError(message)

    expected = _expected_fact(predicate.expected)
    matching = tuple(item for item in evidence if item.key == predicate.query.key)
    if not matching:
        return _predicate_result(
            predicate,
            AssertionResult.ERROR,
            EvidencePredicateCode.EVIDENCE_MISSING,
            _PredicateFacts(expected=expected),
        )
    if len(matching) != 1:
        return _predicate_result(
            predicate,
            AssertionResult.ERROR,
            EvidencePredicateCode.EVIDENCE_DUPLICATE,
            _PredicateFacts(expected=expected),
        )
    observed = matching[0]
    actual = _predicate_actual(predicate, observed, expected)
    if isinstance(actual, EvidencePredicateEvaluation):
        return actual
    matched = _compare_facts(actual, expected, predicate.comparator)
    if matched is None:
        return _predicate_result(
            predicate,
            AssertionResult.ERROR,
            EvidencePredicateCode.COMPARATOR_UNSUPPORTED,
            _PredicateFacts(expected=expected, actual=actual, source=observed),
        )
    return _predicate_result(
        predicate,
        AssertionResult.PASS if matched else AssertionResult.FAIL,
        (EvidencePredicateCode.MATCH if matched else EvidencePredicateCode.MISMATCH),
        _PredicateFacts(expected=expected, actual=actual, source=observed),
    )


def evaluate_no_partial_side_effect_assertion(
    assertion: NoPartialSideEffectAssertion,
    response: ObserverResponse,
) -> NoPartialSideEffectEvaluation:
    """Require every named side effect to be present together or absent together."""
    if type(assertion) is not NoPartialSideEffectAssertion:
        message = "assertion must be a NoPartialSideEffectAssertion"
        raise TypeError(message)
    if type(response) is not ObserverResponse:
        message = "response must be an ObserverResponse"
        raise TypeError(message)

    evaluations = tuple(
        evaluate_evidence_predicate(predicate, response.evidence)
        for predicate in assertion.predicates
    )
    observer_ids = {predicate.query.observer for predicate in assertion.predicates}
    if len(observer_ids) != 1:
        return _composite_result(
            assertion,
            AssertionResult.ERROR,
            CompositeAssertionCode.SNAPSHOT_SCOPE_MISMATCH,
            evaluations,
            snapshot_id=response.snapshot_id,
        )
    if response.status is not ObserverResponseStatus.OK:
        if (
            response.status is ObserverResponseStatus.UNSUPPORTED
            and assertion.on_unsupported is OnUnsupported.SKIP
        ):
            result = AssertionResult.SKIPPED
        else:
            result = AssertionResult.ERROR
        return _composite_result(
            assertion,
            result,
            {
                ObserverResponseStatus.PENDING: CompositeAssertionCode.OBSERVER_PENDING,
                ObserverResponseStatus.UNSUPPORTED: (CompositeAssertionCode.OBSERVER_UNSUPPORTED),
                ObserverResponseStatus.ERROR: CompositeAssertionCode.OBSERVER_ERROR,
            }[response.status],
            evaluations,
        )
    if any(item.result is AssertionResult.ERROR for item in evaluations):
        return _composite_result(
            assertion,
            AssertionResult.ERROR,
            CompositeAssertionCode.PREDICATE_ERROR,
            evaluations,
            snapshot_id=response.snapshot_id,
        )
    values = tuple(item.truth_value for item in evaluations)
    if all(value is True for value in values):
        return _composite_result(
            assertion,
            AssertionResult.PASS,
            CompositeAssertionCode.ALL_PRESENT,
            evaluations,
            snapshot_id=response.snapshot_id,
        )
    if all(value is False for value in values):
        return _composite_result(
            assertion,
            AssertionResult.PASS,
            CompositeAssertionCode.NONE_PRESENT,
            evaluations,
            snapshot_id=response.snapshot_id,
        )
    return _composite_result(
        assertion,
        AssertionResult.FAIL,
        CompositeAssertionCode.PARTIAL_SIDE_EFFECT,
        evaluations,
        snapshot_id=response.snapshot_id,
    )


def evaluate_composite_assertion(
    assertion: NoPartialSideEffectAssertion,
    response: ObserverResponse,
) -> NoPartialSideEffectEvaluation:
    """Evaluate the supported v0.1 composite assertion."""
    return evaluate_no_partial_side_effect_assertion(assertion, response)


def _predicate_actual(
    predicate: Predicate,
    observed: ObserverEvidence,
    expected: StateAssertionFact,
) -> StateAssertionFact | EvidencePredicateEvaluation:
    if predicate.path is None:
        return StateAssertionFact(
            observed.value_type,
            observed.typed_value,
            sensitive=observed.sensitive,
        )
    if observed.value_type is not EvidenceValueType.OBJECT or not isinstance(
        observed.typed_value, FrozenJsonObject
    ):
        return _predicate_result(
            predicate,
            AssertionResult.ERROR,
            EvidencePredicateCode.EVIDENCE_TYPE_MISMATCH,
            _PredicateFacts(expected=expected, source=observed),
        )
    found, raw_actual = _resolve_json_pointer(observed.typed_value, predicate.path)
    if not found:
        return _predicate_result(
            predicate,
            (
                AssertionResult.FAIL
                if predicate.missing_pointer is MissingPointer.FAIL
                else AssertionResult.ERROR
            ),
            EvidencePredicateCode.POINTER_MISSING,
            _PredicateFacts(expected=expected, source=observed),
        )
    try:
        return _actual_fact(
            raw_actual,
            expected_type=expected.value_type,
            sensitive=observed.sensitive,
        )
    except (TypeError, ValueError):
        return _predicate_result(
            predicate,
            AssertionResult.ERROR,
            EvidencePredicateCode.EVIDENCE_TYPE_MISMATCH,
            _PredicateFacts(expected=expected, source=observed),
        )


@dataclass(frozen=True, slots=True)
class _PredicateFacts:
    expected: StateAssertionFact | None = None
    actual: StateAssertionFact | None = None
    source: ObserverEvidence | None = None


def _predicate_result(
    predicate: Predicate,
    result: AssertionResult,
    code: EvidencePredicateCode,
    facts: _PredicateFacts | None = None,
) -> EvidencePredicateEvaluation:
    selected_facts = facts if facts is not None else _PredicateFacts()
    return EvidencePredicateEvaluation(
        predicate_name=predicate.name,
        evidence_key=predicate.query.key,
        result=result,
        code=code,
        truth_value={
            AssertionResult.PASS: True,
            AssertionResult.FAIL: False,
            AssertionResult.ERROR: None,
        }[result],
        expected=selected_facts.expected,
        actual=selected_facts.actual,
        source_evidence=selected_facts.source,
    )


def _composite_result(
    assertion: NoPartialSideEffectAssertion,
    result: AssertionResult,
    code: CompositeAssertionCode,
    predicates: tuple[EvidencePredicateEvaluation, ...],
    *,
    snapshot_id: str | None = None,
) -> NoPartialSideEffectEvaluation:
    return NoPartialSideEffectEvaluation(
        assertion_id=assertion.id,
        result=result,
        code=code,
        predicates=predicates,
        snapshot_id=snapshot_id,
    )


def _expected_fact(expected: TypedValue) -> StateAssertionFact:
    projection = expected.to_wire()
    raw_type = projection.get("value_type")
    if type(raw_type) is not str:
        message = "typed expected value lacks a value_type"
        raise TypeError(message)
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
    elif inferred is EvidenceValueType.OBJECT and expected_type is EvidenceValueType.BYTES_DIGEST:
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
    message = "observer object contains an unsupported field value"
    raise TypeError(message)


def _compare_facts(  # noqa: PLR0911
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


def _deep_exact_equal(left: object, right: object) -> bool:  # noqa: PLR0911
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
        return all(_deep_exact_equal(left_mapping[key], right_mapping[key]) for key in left_mapping)
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


__all__ = [
    "CompositeAssertionCode",
    "EvidencePredicateCode",
    "EvidencePredicateEvaluation",
    "NoPartialSideEffectEvaluation",
    "evaluate_composite_assertion",
    "evaluate_evidence_predicate",
    "evaluate_no_partial_side_effect_assertion",
]
