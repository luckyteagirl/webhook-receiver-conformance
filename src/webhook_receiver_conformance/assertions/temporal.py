"""Ordered-transition and eventual-state assertion evaluation."""
# ruff: noqa: INP001

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from webhook_receiver_conformance.config.models import (
    EventualStateAssertion,
    OnUnsupported,
    OrderedTransitionAssertion,
    Predicate,
    TypedValue,
)
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    EvidenceValueType,
    ObservationState,
)
from webhook_receiver_conformance.observers.polling import (
    ObservationPollOutcome,
    ObservationPollResult,
)
from webhook_receiver_conformance.observers.protocol import (
    FrozenJsonObject,
    ObserverEvidence,
    ObserverResponse,
    ObserverResponseStatus,
)

from .composite import (
    EvidencePredicateCode,
    EvidencePredicateEvaluation,
    evaluate_evidence_predicate,
)
from .state import StateAssertionFact


class TemporalAssertionCode(StrEnum):
    """Stable, message-independent temporal evaluation facts."""

    ORDER_MATCH = "order_match"
    ORDER_MISMATCH = "order_mismatch"
    EVIDENCE_MISSING = "evidence_missing"
    EVIDENCE_DUPLICATE = "evidence_duplicate"
    EVIDENCE_TYPE_MISMATCH = "evidence_type_mismatch"
    EVENTUAL_MATCH = "eventual_match"
    EVENTUAL_MISMATCH = "eventual_mismatch"
    EVENTUAL_DEADLINE_MISMATCH = "eventual_deadline_mismatch"
    EVENTUAL_TIMEOUT_ERROR = "eventual_timeout_error"
    PREDICATE_ERROR = "predicate_error"
    OBSERVER_PENDING = "observer_pending"
    OBSERVER_UNSUPPORTED = "observer_unsupported"
    OBSERVER_ERROR = "observer_error"
    POLL_RESULT_INCONSISTENT = "poll_result_inconsistent"


class TemporalPredicateError(RuntimeError):
    """Safe classified failure raised from a poller's typed predicate callback."""

    code: TemporalAssertionCode | EvidencePredicateCode

    def __init__(
        self,
        code: TemporalAssertionCode | EvidencePredicateCode,
    ) -> None:
        """Build a stable error without embedding evidence or observer detail."""
        if type(code) not in {TemporalAssertionCode, EvidencePredicateCode}:
            message = "code must classify a temporal predicate error"
            raise TypeError(message)
        self.code = code
        super().__init__("The temporal predicate could not evaluate normalized evidence.")


@dataclass(frozen=True, slots=True, repr=False)
class OrderedTransitionEvaluation:
    """One deterministic ordered-sequence comparison."""

    assertion_id: str
    result: AssertionResult
    code: TemporalAssertionCode
    evidence_key: str
    expected: StateAssertionFact | None = field(default=None, repr=False)
    actual: StateAssertionFact | None = field(default=None, repr=False)
    source_evidence: ObserverEvidence | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Validate the ordered-transition result invariants."""
        for value, name in (
            (self.assertion_id, "assertion_id"),
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
            message = "ordered transition result must be pass, fail, or error"
            raise ValueError(message)
        if type(self.code) is not TemporalAssertionCode:
            message = "code must be a TemporalAssertionCode"
            raise TypeError(message)
        for fact, name in ((self.expected, "expected"), (self.actual, "actual")):
            if fact is not None and type(fact) is not StateAssertionFact:
                message = f"{name} must be a StateAssertionFact or None"
                raise TypeError(message)
        if self.source_evidence is not None and type(self.source_evidence) is not ObserverEvidence:
            message = "source_evidence must be an ObserverEvidence or None"
            raise TypeError(message)

    def __repr__(self) -> str:
        """Return a representation that excludes transition values."""
        return (
            f"{type(self).__name__}(assertion_id={self.assertion_id!r}, "
            f"result={self.result!r}, code={self.code!r}, "
            f"evidence_key={self.evidence_key!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EventualStateEvaluation:
    """Terminal eventual-state result retaining every durable sample identity."""

    assertion_id: str
    result: AssertionResult
    code: TemporalAssertionCode
    poll_outcome: ObservationPollOutcome
    sample_ids: tuple[str, ...]
    expected: StateAssertionFact = field(repr=False)
    actual: StateAssertionFact | None = field(default=None, repr=False)
    source_evidence: ObserverEvidence | None = field(default=None, repr=False)

    def __post_init__(self) -> None:  # noqa: C901
        """Validate the terminal outcome and evidence-reference invariants."""
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
            message = "eventual result must be pass, fail, error, or skipped"
            raise ValueError(message)
        if type(self.code) is not TemporalAssertionCode:
            message = "code must be a TemporalAssertionCode"
            raise TypeError(message)
        if type(self.poll_outcome) is not ObservationPollOutcome:
            message = "poll_outcome must be an ObservationPollOutcome"
            raise TypeError(message)
        if (
            type(self.sample_ids) is not tuple
            or not self.sample_ids
            or any(type(sample_id) is not str or not sample_id for sample_id in self.sample_ids)
        ):
            message = "sample_ids must contain every nonempty sample ID"
            raise ValueError(message)
        if len(set(self.sample_ids)) != len(self.sample_ids):
            message = "sample_ids must be unique"
            raise ValueError(message)
        if type(self.expected) is not StateAssertionFact:
            message = "expected must be a StateAssertionFact"
            raise TypeError(message)
        if self.actual is not None and type(self.actual) is not StateAssertionFact:
            message = "actual must be a StateAssertionFact or None"
            raise TypeError(message)
        if self.source_evidence is not None and type(self.source_evidence) is not ObserverEvidence:
            message = "source_evidence must be an ObserverEvidence or None"
            raise TypeError(message)

    @property
    def terminal(self) -> str:
        """Return the report-facing terminal pass/timeout label."""
        if self.poll_outcome is ObservationPollOutcome.TIMED_OUT:
            return "timeout"
        return self.result.value

    def __repr__(self) -> str:
        """Return a representation that excludes sampled evidence values."""
        return (
            f"{type(self).__name__}(assertion_id={self.assertion_id!r}, "
            f"result={self.result!r}, code={self.code!r}, "
            f"poll_outcome={self.poll_outcome!r}, "
            f"sample_count={len(self.sample_ids)})"
        )


@dataclass(frozen=True, slots=True)
class OrderedTransitionPredicate:
    """Callable adapter for optional observer polling."""

    assertion: OrderedTransitionAssertion

    def __post_init__(self) -> None:
        """Validate the immutable predicate configuration."""
        if type(self.assertion) is not OrderedTransitionAssertion:
            message = "assertion must be an OrderedTransitionAssertion"
            raise TypeError(message)

    def __call__(self, response: ObserverResponse) -> bool:
        """Evaluate one normalized observer response for the poller."""
        if type(response) is not ObserverResponse:
            message = "response must be an ObserverResponse"
            raise TypeError(message)
        if response.status is not ObserverResponseStatus.OK:
            raise TemporalPredicateError(_observer_code(response.status))
        evaluation = evaluate_ordered_transition_assertion(
            self.assertion,
            response.evidence,
        )
        if evaluation.result is AssertionResult.ERROR:
            raise TemporalPredicateError(evaluation.code)
        return evaluation.result is AssertionResult.PASS


@dataclass(frozen=True, slots=True)
class EventualStatePredicate:
    """Callable typed predicate consumed by the bounded observation poller."""

    assertion: EventualStateAssertion

    def __post_init__(self) -> None:
        """Validate the immutable predicate configuration."""
        if type(self.assertion) is not EventualStateAssertion:
            message = "assertion must be an EventualStateAssertion"
            raise TypeError(message)

    def __call__(self, response: ObserverResponse) -> bool:
        """Evaluate one normalized observer response for the poller."""
        if type(response) is not ObserverResponse:
            message = "response must be an ObserverResponse"
            raise TypeError(message)
        if response.status is not ObserverResponseStatus.OK:
            raise TemporalPredicateError(_observer_code(response.status))
        evaluation = evaluate_evidence_predicate(
            _eventual_predicate(self.assertion),
            response.evidence,
        )
        if evaluation.result is AssertionResult.ERROR:
            raise TemporalPredicateError(evaluation.code)
        return evaluation.result is AssertionResult.PASS


@dataclass(frozen=True, slots=True)
class _OrderedFacts:
    expected: StateAssertionFact | None = None
    actual: StateAssertionFact | None = None
    source: ObserverEvidence | None = None


@dataclass(frozen=True, slots=True)
class _EventualFacts:
    expected: StateAssertionFact
    detail: EvidencePredicateEvaluation | None


def evaluate_ordered_transition_assertion(
    assertion: OrderedTransitionAssertion,
    evidence: tuple[ObserverEvidence, ...],
) -> OrderedTransitionEvaluation:
    """Verify contiguous order or an explicitly configured ordered subsequence."""
    if type(assertion) is not OrderedTransitionAssertion:
        message = "assertion must be an OrderedTransitionAssertion"
        raise TypeError(message)
    if type(evidence) is not tuple or any(type(item) is not ObserverEvidence for item in evidence):
        message = "evidence must be a tuple of ObserverEvidence values"
        raise TypeError(message)

    expected = StateAssertionFact(EvidenceValueType.ARRAY, assertion.states)
    matching = tuple(item for item in evidence if item.key == assertion.query.key)
    if not matching:
        return _ordered_result(
            assertion,
            AssertionResult.ERROR,
            TemporalAssertionCode.EVIDENCE_MISSING,
            _OrderedFacts(expected=expected),
        )
    if len(matching) != 1:
        return _ordered_result(
            assertion,
            AssertionResult.ERROR,
            TemporalAssertionCode.EVIDENCE_DUPLICATE,
            _OrderedFacts(expected=expected),
        )
    observed = matching[0]
    raw = observed.typed_value
    if observed.value_type is not EvidenceValueType.ARRAY or type(raw) is not tuple:
        return _ordered_result(
            assertion,
            AssertionResult.ERROR,
            TemporalAssertionCode.EVIDENCE_TYPE_MISMATCH,
            _OrderedFacts(expected=expected, source=observed),
        )
    raw_values = cast("tuple[object, ...]", raw)
    actual = StateAssertionFact(
        EvidenceValueType.ARRAY,
        raw_values,
        sensitive=observed.sensitive,
    )
    states = _transition_states(raw_values)
    if states is None:
        return _ordered_result(
            assertion,
            AssertionResult.ERROR,
            TemporalAssertionCode.EVIDENCE_TYPE_MISMATCH,
            _OrderedFacts(expected=expected, actual=actual, source=observed),
        )
    matched = (
        _is_ordered_subsequence(states, assertion.states)
        if assertion.allow_intermediate
        else _contains_contiguous_sequence(states, assertion.states)
    )
    return _ordered_result(
        assertion,
        AssertionResult.PASS if matched else AssertionResult.FAIL,
        (TemporalAssertionCode.ORDER_MATCH if matched else TemporalAssertionCode.ORDER_MISMATCH),
        _OrderedFacts(expected=expected, actual=actual, source=observed),
    )


def ordered_transition_predicate(
    assertion: OrderedTransitionAssertion,
) -> OrderedTransitionPredicate:
    """Build the optional-polling adapter for an ordered assertion."""
    return OrderedTransitionPredicate(assertion)


def eventual_state_predicate(
    assertion: EventualStateAssertion,
) -> EventualStatePredicate:
    """Build the typed callback for a bounded eventual-state poll."""
    return EventualStatePredicate(assertion)


def evaluate_eventual_state_assertion(  # noqa: C901, PLR0911, PLR0912
    assertion: EventualStateAssertion,
    poll_result: ObservationPollResult,
) -> EventualStateEvaluation:
    """Reduce one complete polling series without dropping sample identities."""
    if type(assertion) is not EventualStateAssertion:
        message = "assertion must be an EventualStateAssertion"
        raise TypeError(message)
    if type(poll_result) is not ObservationPollResult:
        message = "poll_result must be an ObservationPollResult"
        raise TypeError(message)

    expected = _expected_fact(assertion.expected)
    detail = _eventual_detail(assertion, poll_result.last_response)
    facts = _EventualFacts(expected, detail)
    if not _poll_result_consistent(poll_result):
        return _eventual_result(
            assertion,
            poll_result,
            AssertionResult.ERROR,
            TemporalAssertionCode.POLL_RESULT_INCONSISTENT,
            facts,
        )
    if poll_result.outcome is ObservationPollOutcome.MATCHED:
        if detail is None or detail.result is not AssertionResult.PASS:
            return _eventual_result(
                assertion,
                poll_result,
                AssertionResult.ERROR,
                TemporalAssertionCode.POLL_RESULT_INCONSISTENT,
                facts,
            )
        return _eventual_result(
            assertion,
            poll_result,
            AssertionResult.PASS,
            TemporalAssertionCode.EVENTUAL_MATCH,
            facts,
        )
    if poll_result.outcome is ObservationPollOutcome.MISMATCH:
        if detail is None:
            return _eventual_result(
                assertion,
                poll_result,
                AssertionResult.ERROR,
                TemporalAssertionCode.POLL_RESULT_INCONSISTENT,
                facts,
            )
        if detail.result is AssertionResult.ERROR:
            return _eventual_result(
                assertion,
                poll_result,
                AssertionResult.ERROR,
                TemporalAssertionCode.PREDICATE_ERROR,
                facts,
            )
        if detail.result is AssertionResult.PASS:
            return _eventual_result(
                assertion,
                poll_result,
                AssertionResult.ERROR,
                TemporalAssertionCode.POLL_RESULT_INCONSISTENT,
                facts,
            )
        return _eventual_result(
            assertion,
            poll_result,
            AssertionResult.FAIL,
            TemporalAssertionCode.EVENTUAL_MISMATCH,
            facts,
        )
    if poll_result.outcome is ObservationPollOutcome.TIMED_OUT:
        if detail is not None and detail.result is AssertionResult.PASS:
            return _eventual_result(
                assertion,
                poll_result,
                AssertionResult.ERROR,
                TemporalAssertionCode.POLL_RESULT_INCONSISTENT,
                facts,
            )
        if detail is not None and detail.result is AssertionResult.ERROR:
            return _eventual_result(
                assertion,
                poll_result,
                AssertionResult.ERROR,
                TemporalAssertionCode.PREDICATE_ERROR,
                facts,
            )
        valid_deadline_mismatch = poll_result.valid_evidence_seen and poll_result.deadline_elapsed
        return _eventual_result(
            assertion,
            poll_result,
            (AssertionResult.FAIL if valid_deadline_mismatch else AssertionResult.ERROR),
            (
                TemporalAssertionCode.EVENTUAL_DEADLINE_MISMATCH
                if valid_deadline_mismatch
                else TemporalAssertionCode.EVENTUAL_TIMEOUT_ERROR
            ),
            facts,
        )
    if poll_result.outcome is ObservationPollOutcome.UNSUPPORTED:
        return _eventual_result(
            assertion,
            poll_result,
            (
                AssertionResult.SKIPPED
                if assertion.on_unsupported is OnUnsupported.SKIP
                else AssertionResult.ERROR
            ),
            TemporalAssertionCode.OBSERVER_UNSUPPORTED,
            facts,
        )
    error_code = (
        TemporalAssertionCode.PREDICATE_ERROR
        if (
            poll_result.outcome is ObservationPollOutcome.ERROR
            and detail is not None
            and detail.result is AssertionResult.ERROR
        )
        else (
            TemporalAssertionCode.OBSERVER_PENDING
            if poll_result.outcome is ObservationPollOutcome.PENDING
            else TemporalAssertionCode.OBSERVER_ERROR
        )
    )
    return _eventual_result(
        assertion,
        poll_result,
        AssertionResult.ERROR,
        error_code,
        facts,
    )


def evaluate_temporal_assertion(
    assertion: OrderedTransitionAssertion | EventualStateAssertion,
    evidence: tuple[ObserverEvidence, ...] | ObservationPollResult,
) -> OrderedTransitionEvaluation | EventualStateEvaluation:
    """Evaluate either supported temporal assertion at a strict typed boundary."""
    if type(assertion) is OrderedTransitionAssertion:
        if type(evidence) is not tuple:
            message = "ordered transition evidence must be an evidence tuple"
            raise TypeError(message)
        return evaluate_ordered_transition_assertion(assertion, evidence)
    if type(assertion) is EventualStateAssertion:
        if type(evidence) is not ObservationPollResult:
            message = "eventual state evidence must be an ObservationPollResult"
            raise TypeError(message)
        return evaluate_eventual_state_assertion(assertion, evidence)
    message = "assertion must be a supported temporal assertion"
    raise TypeError(message)


def _expected_fact(expected: TypedValue) -> StateAssertionFact:
    projection = expected.to_wire()
    raw_type = projection.get("value_type")
    if type(raw_type) is not str:
        message = "typed expected value lacks a value_type"
        raise TypeError(message)
    probe = ObserverEvidence.model_validate(
        {
            "key": "assertion_value",
            "value_type": raw_type,
            "value": projection.get("value"),
            "sensitive": False,
        }
    )
    return StateAssertionFact(probe.value_type, probe.typed_value)


def _eventual_predicate(assertion: EventualStateAssertion) -> Predicate:
    payload: dict[str, object] = {
        "name": assertion.id,
        "query": assertion.query.to_wire(),
        "comparator": assertion.comparator.value,
        "expected": assertion.expected.to_wire(),
    }
    if assertion.path is not None:
        payload["path"] = assertion.path
        payload["missing_pointer"] = assertion.missing_pointer.value
    return Predicate.model_validate(payload)


def _eventual_detail(
    assertion: EventualStateAssertion,
    response: ObserverResponse | None,
) -> EvidencePredicateEvaluation | None:
    if response is None or response.status is not ObserverResponseStatus.OK:
        return None
    return evaluate_evidence_predicate(
        _eventual_predicate(assertion),
        response.evidence,
    )


def _poll_result_consistent(result: ObservationPollResult) -> bool:
    expected_state = {
        ObservationPollOutcome.MATCHED: ObservationState.OK,
        ObservationPollOutcome.MISMATCH: ObservationState.OK,
        ObservationPollOutcome.PENDING: ObservationState.PENDING,
        ObservationPollOutcome.UNSUPPORTED: ObservationState.UNSUPPORTED,
        ObservationPollOutcome.ERROR: ObservationState.ERROR,
        ObservationPollOutcome.TIMED_OUT: ObservationState.TIMED_OUT,
    }[result.outcome]
    if result.final_state is not expected_state:
        return False
    if result.outcome is ObservationPollOutcome.MATCHED:
        return (
            result.predicate_matched
            and result.valid_evidence_seen
            and result.last_response is not None
        )
    if result.outcome is ObservationPollOutcome.MISMATCH:
        return (
            not result.predicate_matched
            and result.valid_evidence_seen
            and result.last_response is not None
        )
    return not result.predicate_matched


def _transition_states(values: tuple[object, ...]) -> tuple[str, ...] | None:
    states: list[str] = []
    for value in values:
        if type(value) is str:
            if not value:
                return None
            states.append(value)
            continue
        if not isinstance(value, FrozenJsonObject):
            return None
        transition = value
        if not set(transition) <= {"state", "timestamp"}:
            return None
        state = transition.get("state")
        if type(state) is not str or not state:
            return None
        if "timestamp" in transition:
            timestamp = transition["timestamp"]
            try:
                ObserverEvidence.model_validate(
                    {
                        "key": "transition_timestamp",
                        "value_type": "timestamp",
                        "value": timestamp,
                    }
                )
            except ValueError:
                return None
        states.append(state)
    return tuple(states)


def _contains_contiguous_sequence(
    actual: tuple[str, ...],
    expected: tuple[str, ...],
) -> bool:
    if len(expected) > len(actual):
        return False
    return any(
        actual[index : index + len(expected)] == expected
        for index in range(len(actual) - len(expected) + 1)
    )


def _is_ordered_subsequence(
    actual: tuple[str, ...],
    expected: tuple[str, ...],
) -> bool:
    expected_index = 0
    for state in actual:
        if state == expected[expected_index]:
            expected_index += 1
            if expected_index == len(expected):
                return True
    return False


def _observer_code(status: ObserverResponseStatus) -> TemporalAssertionCode:
    return {
        ObserverResponseStatus.PENDING: TemporalAssertionCode.OBSERVER_PENDING,
        ObserverResponseStatus.UNSUPPORTED: TemporalAssertionCode.OBSERVER_UNSUPPORTED,
        ObserverResponseStatus.ERROR: TemporalAssertionCode.OBSERVER_ERROR,
        ObserverResponseStatus.OK: TemporalAssertionCode.POLL_RESULT_INCONSISTENT,
    }[status]


def _ordered_result(
    assertion: OrderedTransitionAssertion,
    result: AssertionResult,
    code: TemporalAssertionCode,
    facts: _OrderedFacts | None = None,
) -> OrderedTransitionEvaluation:
    selected_facts = facts if facts is not None else _OrderedFacts()
    return OrderedTransitionEvaluation(
        assertion_id=assertion.id,
        result=result,
        code=code,
        evidence_key=assertion.query.key,
        expected=selected_facts.expected,
        actual=selected_facts.actual,
        source_evidence=selected_facts.source,
    )


def _eventual_result(
    assertion: EventualStateAssertion,
    poll_result: ObservationPollResult,
    result: AssertionResult,
    code: TemporalAssertionCode,
    facts: _EventualFacts,
) -> EventualStateEvaluation:
    return EventualStateEvaluation(
        assertion_id=assertion.id,
        result=result,
        code=code,
        poll_outcome=poll_result.outcome,
        sample_ids=poll_result.sample_ids,
        expected=facts.expected,
        actual=facts.detail.actual if facts.detail is not None else None,
        source_evidence=(facts.detail.source_evidence if facts.detail is not None else None),
    )


__all__ = [
    "EventualStateEvaluation",
    "EventualStatePredicate",
    "OrderedTransitionEvaluation",
    "OrderedTransitionPredicate",
    "TemporalAssertionCode",
    "TemporalPredicateError",
    "evaluate_eventual_state_assertion",
    "evaluate_ordered_transition_assertion",
    "evaluate_temporal_assertion",
    "eventual_state_predicate",
    "ordered_transition_predicate",
]
