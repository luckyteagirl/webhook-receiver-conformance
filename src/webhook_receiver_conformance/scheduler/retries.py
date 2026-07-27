"""Pure retry-policy evaluation over manifest-fixed conditional templates."""
# ruff: noqa: D105, EM101, EM102, INP001, PLR0913, PLR2004, TRY003

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.enums import AttemptClassification
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    planned_id,
    validate_fresh_id,
    validate_planned_id,
)
from webhook_receiver_conformance.manifest.models import (
    MAX_SAFE_INTEGER,
    AttemptTemplate,
    DeliveryPlan,
)

JITTER_POLICY_VERSION: Final = "retry-jitter-v1"
MAX_ATTEMPTS: Final = 32


class RetryPredicate(StrEnum):
    """Closed manifest predicate vocabulary."""

    TIMED_OUT = "timed_out"
    CONNECTION_FAILED = "connection_failed"
    RETRYABLE_STATUS = "retryable_status"


class RetryDisposition(StrEnum):
    """Stable result of evaluating one predecessor against one delivery plan."""

    SCHEDULED = "scheduled"
    INELIGIBLE = "ineligible"
    EXHAUSTED = "exhausted"
    AMBIGUOUS_BLOCKED = "ambiguous_blocked"


class RetryPolicyError(ValueError):
    """Malformed or internally inconsistent retry input."""


@dataclass(frozen=True, slots=True)
class ClassifiedPredecessor:
    """The terminal fact consumed by retry policy, not raw transport evidence."""

    attempt_id: str
    attempt_ordinal: int
    classification: AttemptClassification
    predicate: RetryPredicate | None
    logical_time_ns: int
    status_code: int | None = None

    def __post_init__(self) -> None:
        validate_fresh_id(self.attempt_id, expected_kind=FreshIdKind.ATTEMPT)
        _ordinal(self.attempt_ordinal, "predecessor attempt ordinal")
        _logical_time(self.logical_time_ns, "predecessor logical time")
        if type(self.classification) is not AttemptClassification:
            raise TypeError("classification must be an AttemptClassification")
        if self.predicate is not None and type(self.predicate) is not RetryPredicate:
            raise TypeError("predicate must be a RetryPredicate or None")
        if self.status_code is not None and (
            type(self.status_code) is not int or not 100 <= self.status_code <= 599
        ):
            raise RetryPolicyError("status_code must be an integer from 100 through 599")
        self._validate_relationships()

    def _validate_relationships(self) -> None:
        if self.classification is AttemptClassification.AMBIGUOUS:
            if self.predicate is not None or self.status_code is not None:
                raise RetryPolicyError("ambiguous predecessors cannot claim retry eligibility")
            return
        if self.predicate is RetryPredicate.RETRYABLE_STATUS:
            if (
                self.classification is not AttemptClassification.RECEIVER_REJECTED
                or self.status_code is None
            ):
                raise RetryPolicyError(
                    "retryable_status requires a classified receiver rejection status"
                )
            return
        if self.status_code is not None:
            raise RetryPolicyError("status_code is valid only for retryable_status")
        if self.predicate in {
            RetryPredicate.TIMED_OUT,
            RetryPredicate.CONNECTION_FAILED,
        }:
            if self.classification is not AttemptClassification.ENVIRONMENT_FAILURE:
                raise RetryPolicyError("transport retry predicates require environment_failure")
            return
        if (
            self.predicate is None
            and self.classification is AttemptClassification.ENVIRONMENT_FAILURE
        ):
            return
        if self.predicate is not None:
            raise RetryPolicyError("classification cannot carry this retry predicate")


@dataclass(frozen=True, slots=True)
class RetryDecision:
    """Pure, replay-stable input for an atomic terminal-outcome journal commit."""

    disposition: RetryDisposition
    predecessor_attempt_id: str
    predecessor_attempt_ordinal: int
    next_attempt_ordinal: int | None
    attempt_plan_id: str | None
    schedule_entry_id: str | None
    schedule_idempotency_key: str | None
    logical_due_ns: int | None
    predicate: RetryPredicate | None
    condition_json: bytes
    template: AttemptTemplate | None

    @property
    def should_schedule(self) -> bool:
        """Return whether the scheduler must create the next physical attempt later."""
        return self.disposition is RetryDisposition.SCHEDULED


def derive_signed_jitter_ns(
    generator: ContextGenerator,
    *,
    scenario_id: str,
    planned_delivery_id: str,
    attempt_ordinal: int,
    magnitude_bound_ns: int,
    jitter_policy_version: str = JITTER_POLICY_VERSION,
) -> int:
    """Derive the frozen inclusive signed jitter using the committed generator."""
    if type(generator) is not ContextGenerator:
        raise TypeError("generator must be a ContextGenerator")
    return generator.signed_retry_jitter(
        scenario_id=scenario_id,
        planned_delivery_id=planned_delivery_id,
        attempt_ordinal=_ordinal(attempt_ordinal, "attempt ordinal"),
        jitter_policy_version=jitter_policy_version,
        magnitude_bound=magnitude_bound_ns,
    )


def derive_retry_delay_ns(
    generator: ContextGenerator,
    *,
    scenario_id: str,
    planned_delivery_id: str,
    attempt_ordinal: int,
    base_delay_ns: int,
    magnitude_bound_ns: int,
    jitter_policy_version: str = JITTER_POLICY_VERSION,
) -> tuple[int, int]:
    """Return ``(clamped_delay, signed_jitter)`` with exact integer arithmetic."""
    base = _nonnegative_int64(base_delay_ns, "base delay")
    jitter = derive_signed_jitter_ns(
        generator,
        scenario_id=scenario_id,
        planned_delivery_id=planned_delivery_id,
        attempt_ordinal=attempt_ordinal,
        magnitude_bound_ns=magnitude_bound_ns,
        jitter_policy_version=jitter_policy_version,
    )
    delay = max(0, base + jitter)
    if delay > MAX_SAFE_INTEGER:
        raise OverflowError("jittered retry delay exceeds the safe-integer boundary")
    return delay, jitter


def evaluate_retry(
    delivery: DeliveryPlan,
    predecessor: ClassifiedPredecessor,
    *,
    generator: ContextGenerator,
    scenario_id: str,
) -> RetryDecision:
    """Evaluate only the next conditional template committed in ``delivery``."""
    if type(delivery) is not DeliveryPlan:
        raise TypeError("delivery must be a DeliveryPlan")
    if type(predecessor) is not ClassifiedPredecessor:
        raise TypeError("predecessor must be a ClassifiedPredecessor")
    if type(generator) is not ContextGenerator:
        raise TypeError("generator must be a ContextGenerator")
    validate_planned_id(scenario_id, expected_kind=PlannedIdKind.SCENARIO)
    _validate_attempt_plan(delivery)

    next_ordinal = predecessor.attempt_ordinal + 1
    if next_ordinal > len(delivery.attempt_plan) or next_ordinal > MAX_ATTEMPTS:
        return _terminal_decision(RetryDisposition.EXHAUSTED, predecessor)
    template = delivery.attempt_plan[next_ordinal - 1]
    if template.ordinal != next_ordinal:
        raise RetryPolicyError("next template ordinal does not follow its predecessor")
    if predecessor.classification is AttemptClassification.AMBIGUOUS:
        return _terminal_decision(RetryDisposition.AMBIGUOUS_BLOCKED, predecessor)

    predicates = _template_predicates(template)
    if predecessor.predicate is None or predecessor.predicate not in predicates:
        return _terminal_decision(RetryDisposition.INELIGIBLE, predecessor)
    if template.not_before_logical_ns < predecessor.logical_time_ns:
        raise RetryPolicyError("retry logical time cannot precede its predecessor")
    _logical_time(template.not_before_logical_ns, "retry logical time")

    attempt_plan_id = planned_id(
        generator,
        PlannedIdKind.ATTEMPT_PLAN,
        (scenario_id, delivery.delivery_id, str(next_ordinal)),
    )
    identity_root = f"{scenario_id}|{delivery.delivery_id}|{predecessor.attempt_id}|{next_ordinal}"
    schedule_entry_id = f"retry.{hashlib.sha256(identity_root.encode()).hexdigest()}"
    idempotency_key = (
        f"retry.schedule.{hashlib.sha256(('idempotency|' + identity_root).encode()).hexdigest()}"
    )
    condition = _condition_bytes(
        disposition=RetryDisposition.SCHEDULED,
        predecessor=predecessor,
        next_ordinal=next_ordinal,
        predicate=predecessor.predicate,
        logical_due_ns=template.not_before_logical_ns,
    )
    return RetryDecision(
        disposition=RetryDisposition.SCHEDULED,
        predecessor_attempt_id=predecessor.attempt_id,
        predecessor_attempt_ordinal=predecessor.attempt_ordinal,
        next_attempt_ordinal=next_ordinal,
        attempt_plan_id=attempt_plan_id,
        schedule_entry_id=schedule_entry_id,
        schedule_idempotency_key=idempotency_key,
        logical_due_ns=template.not_before_logical_ns,
        predicate=predecessor.predicate,
        condition_json=condition,
        template=template,
    )


def _terminal_decision(
    disposition: RetryDisposition,
    predecessor: ClassifiedPredecessor,
) -> RetryDecision:
    return RetryDecision(
        disposition=disposition,
        predecessor_attempt_id=predecessor.attempt_id,
        predecessor_attempt_ordinal=predecessor.attempt_ordinal,
        next_attempt_ordinal=None,
        attempt_plan_id=None,
        schedule_entry_id=None,
        schedule_idempotency_key=None,
        logical_due_ns=None,
        predicate=predecessor.predicate,
        condition_json=_condition_bytes(
            disposition=disposition,
            predecessor=predecessor,
            next_ordinal=None,
            predicate=predecessor.predicate,
            logical_due_ns=None,
        ),
        template=None,
    )


def _condition_bytes(
    *,
    disposition: RetryDisposition,
    predecessor: ClassifiedPredecessor,
    next_ordinal: int | None,
    predicate: RetryPredicate | None,
    logical_due_ns: int | None,
) -> bytes:
    payload = {
        "classification": predecessor.classification.value,
        "disposition": disposition.value,
        "logical_due_ns": logical_due_ns,
        "next_attempt_ordinal": next_ordinal,
        "predecessor_attempt_id": predecessor.attempt_id,
        "predecessor_attempt_ordinal": predecessor.attempt_ordinal,
        "predicate": predicate.value if predicate is not None else None,
        "status_code": predecessor.status_code,
    }
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _template_predicates(template: AttemptTemplate) -> frozenset[RetryPredicate]:
    condition = template.conditional_on
    if condition is None:
        raise RetryPolicyError("later attempt templates require a predecessor condition")
    pieces = condition.split("|")
    if not pieces or any(not piece for piece in pieces) or len(set(pieces)) != len(pieces):
        raise RetryPolicyError("retry template condition is empty or duplicated")
    try:
        return frozenset(RetryPredicate(piece) for piece in pieces)
    except ValueError:
        raise RetryPolicyError("retry template contains an unknown predicate") from None


def _validate_attempt_plan(delivery: DeliveryPlan) -> None:
    plan = delivery.attempt_plan
    if not 1 <= len(plan) <= MAX_ATTEMPTS:
        raise RetryPolicyError("attempt plan must contain between 1 and 32 templates")
    previous_time: int | None = None
    for index, template in enumerate(plan, start=1):
        if template.ordinal != index:
            raise RetryPolicyError("attempt template ordinals must be contiguous")
        _logical_time(template.not_before_logical_ns, "attempt template logical time")
        if previous_time is not None and template.not_before_logical_ns < previous_time:
            raise RetryPolicyError("attempt template logical times must be monotonic")
        if index == 1 and template.conditional_on is not None:
            raise RetryPolicyError("first attempt template cannot be conditional")
        if index > 1:
            _template_predicates(template)
        previous_time = template.not_before_logical_ns


def _ordinal(value: object, name: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        raise RetryPolicyError(f"{name} must be a positive safe integer")
    return value


def _logical_time(value: object, name: str) -> int:
    if type(value) is not int or not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise RetryPolicyError(f"{name} must be a signed safe integer")
    return value


def _nonnegative_int64(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= (2**63) - 1:
        raise RetryPolicyError(f"{name} must be a nonnegative signed-int64 integer")
    return value


__all__ = [
    "JITTER_POLICY_VERSION",
    "ClassifiedPredecessor",
    "RetryDecision",
    "RetryDisposition",
    "RetryPolicyError",
    "RetryPredicate",
    "derive_retry_delay_ns",
    "derive_signed_jitter_ns",
    "evaluate_retry",
]
