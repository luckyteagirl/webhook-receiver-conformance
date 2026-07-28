"""Conservative observer-assisted reconciliation of ambiguous deliveries."""
# ruff: noqa: BLE001, C901, D105, EM101, INP001, PLR0911, TRY003

from __future__ import annotations

from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import anyio

from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    ObservationStatus,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    validate_fresh_id,
    validate_planned_id,
)
from webhook_receiver_conformance.errors import (
    ExitCode,
    ResultCategory,
    exit_for_result,
)
from webhook_receiver_conformance.observers.protocol import (
    ObservationRecord,
    ObserverCapabilities,
    resume_reconciliation_allowed,
)
from webhook_receiver_conformance.recovery.policy import (
    ObservationReconciliationPlan,
)

MAX_RECONCILIATION_RECORDS: Final = 1_000
MAX_RECONCILIATION_ASSERTIONS: Final = 1_000
MAX_SNAPSHOT_ID_LENGTH: Final = 512

type ReconciliationEvidenceSupplier = Callable[[], Awaitable["ReconciliationEvidence"]]


class ReconciliationOutcome(StrEnum):
    """Whether observer evidence uniquely established the configured result."""

    RECONCILED = "reconciled"
    AMBIGUOUS = "ambiguous"


class ReconciliationReason(StrEnum):
    """Stable, secret-free reason for one reconciliation decision."""

    DECISIVE_ASSERTIONS_PASSED = "decisive_assertions_passed"
    OBSERVER_INELIGIBLE = "observer_ineligible"
    OBSERVER_ERROR = "observer_error"
    OBSERVATION_MISSING = "observation_missing"
    OBSERVATION_INCONCLUSIVE = "observation_inconclusive"
    EVIDENCE_SCOPE_MISMATCH = "evidence_scope_mismatch"
    SNAPSHOT_MISMATCH = "snapshot_mismatch"
    ASSERTION_SET_INCOMPLETE = "assertion_set_incomplete"
    ASSERTION_SET_CONTRADICTORY = "assertion_set_contradictory"
    ASSERTION_PENDING = "assertion_pending"
    ASSERTION_UNSUPPORTED = "assertion_unsupported"
    ASSERTION_ERROR = "assertion_error"
    ASSERTION_CONTRARY = "assertion_contrary"


@dataclass(frozen=True, slots=True)
class ReconciliationAssertionFact:
    """One immutable assertion result bound to an observer snapshot."""

    assertion_id: str
    evaluation_id: str
    state: AssertionState
    result: AssertionResult
    observation_id: str
    sample_id: str
    snapshot_id: str

    def __post_init__(self) -> None:
        validate_planned_id(
            self.assertion_id,
            expected_kind=PlannedIdKind.ASSERTION,
        )
        validate_fresh_id(
            self.evaluation_id,
            expected_kind=FreshIdKind.EVALUATION,
        )
        if type(self.state) is not AssertionState:
            raise TypeError("state must be an AssertionState")
        if type(self.result) is not AssertionResult:
            raise TypeError("result must be an AssertionResult")
        validate_planned_id(
            self.observation_id,
            expected_kind=PlannedIdKind.OBSERVATION,
        )
        validate_fresh_id(
            self.sample_id,
            expected_kind=FreshIdKind.SAMPLE,
        )
        if (
            type(self.snapshot_id) is not str
            or not self.snapshot_id
            or len(self.snapshot_id) > MAX_SNAPSHOT_ID_LENGTH
            or any(character in "\r\n\x00" for character in self.snapshot_id)
        ):
            raise ValueError("snapshot_id must be bounded and line-safe")


@dataclass(frozen=True, slots=True)
class ReconciliationEvidence:
    """Bounded durable observations and evaluations offered for reconciliation."""

    observations: tuple[ObservationRecord, ...]
    assertions: tuple[ReconciliationAssertionFact, ...]

    def __post_init__(self) -> None:
        if type(self.observations) is not tuple or any(
            type(item) is not ObservationRecord for item in self.observations
        ):
            raise TypeError("observations must contain ObservationRecord values")
        if type(self.assertions) is not tuple or any(
            type(item) is not ReconciliationAssertionFact for item in self.assertions
        ):
            raise TypeError("assertions must contain ReconciliationAssertionFact values")
        if len(self.observations) > MAX_RECONCILIATION_RECORDS:
            raise ValueError("observation evidence exceeds the reconciliation limit")
        if len(self.assertions) > MAX_RECONCILIATION_ASSERTIONS:
            raise ValueError("assertion evidence exceeds the reconciliation limit")


@dataclass(frozen=True, slots=True)
class ReconciliationDecision:
    """One classified decision that never mutates historical attempt state."""

    attempt_id: str
    outcome: ReconciliationOutcome
    reason: ReconciliationReason
    result_category: ResultCategory
    exit_code: ExitCode
    observation_record_ids: tuple[str, ...] = ()
    evaluation_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_fresh_id(
            self.attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
        if type(self.outcome) is not ReconciliationOutcome:
            raise TypeError("outcome must be a ReconciliationOutcome")
        if type(self.reason) is not ReconciliationReason:
            raise TypeError("reason must be a ReconciliationReason")
        if type(self.result_category) is not ResultCategory:
            raise TypeError("result_category must be a ResultCategory")
        if type(self.exit_code) is not ExitCode:
            raise TypeError("exit_code must be an ExitCode")
        expected_category = (
            ResultCategory.PASS
            if self.outcome is ReconciliationOutcome.RECONCILED
            else ResultCategory.AMBIGUOUS
        )
        if self.result_category is not expected_category:
            raise ValueError("reconciliation outcome and result category disagree")
        if exit_for_result(self.result_category)[1] is not self.exit_code:
            raise ValueError("reconciliation category and exit code disagree")
        _fresh_id_tuple(
            self.observation_record_ids,
            kind=FreshIdKind.RECORD,
            name="observation record",
        )
        _fresh_id_tuple(
            self.evaluation_ids,
            kind=FreshIdKind.EVALUATION,
            name="evaluation",
        )

    @property
    def reconciled(self) -> bool:
        """Return whether the configured business result was established."""
        return self.outcome is ReconciliationOutcome.RECONCILED


class AmbiguityReconciler:
    """Preflight observer safety and reduce one decisive assertion set."""

    async def reconcile(
        self,
        plan: ObservationReconciliationPlan,
        capabilities: ObserverCapabilities,
        evidence_supplier: ReconciliationEvidenceSupplier,
    ) -> ReconciliationDecision:
        """Collect evidence only from an eligible observer, then assess it."""
        _require_inputs(plan, capabilities, evidence_supplier)
        if not resume_reconciliation_allowed(capabilities):
            return _decision(plan, ReconciliationReason.OBSERVER_INELIGIBLE)
        try:
            evidence = await evidence_supplier()
        except anyio.get_cancelled_exc_class():
            raise
        except Exception:
            return _decision(plan, ReconciliationReason.OBSERVER_ERROR)
        if type(evidence) is not ReconciliationEvidence:
            return _decision(plan, ReconciliationReason.OBSERVER_ERROR)
        return self.assess(plan, capabilities, evidence)

    @staticmethod
    def assess(
        plan: ObservationReconciliationPlan,
        capabilities: ObserverCapabilities,
        evidence: ReconciliationEvidence,
    ) -> ReconciliationDecision:
        """Reduce already-durable evidence without contacting an observer."""
        _require_assessment_inputs(plan, capabilities, evidence)
        if not resume_reconciliation_allowed(capabilities):
            return _decision(plan, ReconciliationReason.OBSERVER_INELIGIBLE)
        if not evidence.observations:
            return _decision(plan, ReconciliationReason.OBSERVATION_MISSING)

        scoped = tuple(
            record
            for record in evidence.observations
            if record.observation_id == plan.observation_id
            and record.scenario_id == plan.scenario_id
        )
        if len(scoped) != len(evidence.observations):
            return _decision(
                plan,
                ReconciliationReason.EVIDENCE_SCOPE_MISMATCH,
                observations=evidence.observations,
            )
        if _observation_identities_conflict(scoped):
            return _decision(
                plan,
                ReconciliationReason.EVIDENCE_SCOPE_MISMATCH,
                observations=scoped,
            )
        terminal = max(scoped, key=lambda record: record.sample_sequence)
        if terminal.status is not ObservationStatus.OK or terminal.snapshot_id is None:
            return _decision(
                plan,
                ReconciliationReason.OBSERVATION_INCONCLUSIVE,
                observations=scoped,
            )

        selected = tuple(
            fact for fact in evidence.assertions if fact.sample_id == terminal.sample_id
        )
        if any(
            fact.assertion_id not in plan.assertion_ids
            or fact.observation_id != plan.observation_id
            for fact in evidence.assertions
        ):
            return _decision(
                plan,
                ReconciliationReason.EVIDENCE_SCOPE_MISMATCH,
                observations=scoped,
                assertions=evidence.assertions,
            )
        if any(
            fact.observation_id != terminal.observation_id
            or fact.snapshot_id != terminal.snapshot_id
            for fact in selected
        ):
            return _decision(
                plan,
                ReconciliationReason.SNAPSHOT_MISMATCH,
                observations=scoped,
                assertions=selected,
            )

        counts = Counter(fact.assertion_id for fact in selected)
        if set(counts) != set(plan.assertion_ids):
            return _decision(
                plan,
                ReconciliationReason.ASSERTION_SET_INCOMPLETE,
                observations=scoped,
                assertions=selected,
            )
        if any(count != 1 for count in counts.values()):
            return _decision(
                plan,
                ReconciliationReason.ASSERTION_SET_CONTRADICTORY,
                observations=scoped,
                assertions=selected,
            )

        ordered = tuple(
            next(fact for fact in selected if fact.assertion_id == assertion_id)
            for assertion_id in plan.assertion_ids
        )
        nonpassing = next(
            (
                fact
                for fact in ordered
                if fact.state is not AssertionState.PASSED
                or fact.result is not AssertionResult.PASS
            ),
            None,
        )
        if nonpassing is not None:
            return _decision(
                plan,
                _nonpassing_reason(nonpassing),
                observations=scoped,
                assertions=ordered,
            )
        return _decision(
            plan,
            ReconciliationReason.DECISIVE_ASSERTIONS_PASSED,
            observations=scoped,
            assertions=ordered,
            reconciled=True,
        )


def _require_inputs(
    plan: object,
    capabilities: object,
    supplier: object,
) -> None:
    if type(plan) is not ObservationReconciliationPlan:
        raise TypeError("plan must be an ObservationReconciliationPlan")
    if type(capabilities) is not ObserverCapabilities:
        raise TypeError("capabilities must be ObserverCapabilities")
    if not callable(supplier):
        raise TypeError("evidence_supplier must be callable")


def _require_assessment_inputs(
    plan: object,
    capabilities: object,
    evidence: object,
) -> None:
    if type(plan) is not ObservationReconciliationPlan:
        raise TypeError("plan must be an ObservationReconciliationPlan")
    if type(capabilities) is not ObserverCapabilities:
        raise TypeError("capabilities must be ObserverCapabilities")
    if type(evidence) is not ReconciliationEvidence:
        raise TypeError("evidence must be ReconciliationEvidence")


def _observation_identities_conflict(
    observations: tuple[ObservationRecord, ...],
) -> bool:
    sample_ids = tuple(record.sample_id for record in observations)
    sequences = tuple(record.sample_sequence for record in observations)
    record_ids = tuple(record.record_id for record in observations)
    return (
        len(set(sample_ids)) != len(sample_ids)
        or len(set(sequences)) != len(sequences)
        or len(set(record_ids)) != len(record_ids)
    )


def _nonpassing_reason(
    fact: ReconciliationAssertionFact,
) -> ReconciliationReason:
    if (
        fact.state in {AssertionState.PENDING, AssertionState.RUNNING}
        or fact.result is AssertionResult.PENDING
    ):
        return ReconciliationReason.ASSERTION_PENDING
    if fact.state is AssertionState.UNSUPPORTED or fact.result is AssertionResult.SKIPPED:
        return ReconciliationReason.ASSERTION_UNSUPPORTED
    if fact.state in {AssertionState.ERROR, AssertionState.CANCELLED}:
        return ReconciliationReason.ASSERTION_ERROR
    return ReconciliationReason.ASSERTION_CONTRARY


def _decision(
    plan: ObservationReconciliationPlan,
    reason: ReconciliationReason,
    *,
    observations: tuple[ObservationRecord, ...] = (),
    assertions: tuple[ReconciliationAssertionFact, ...] = (),
    reconciled: bool = False,
) -> ReconciliationDecision:
    category = ResultCategory.PASS if reconciled else ResultCategory.AMBIGUOUS
    return ReconciliationDecision(
        attempt_id=plan.attempt_id,
        outcome=(
            ReconciliationOutcome.RECONCILED if reconciled else ReconciliationOutcome.AMBIGUOUS
        ),
        reason=reason,
        result_category=category,
        exit_code=exit_for_result(category)[1],
        observation_record_ids=_unique_ordered(tuple(record.record_id for record in observations)),
        evaluation_ids=_unique_ordered(tuple(fact.evaluation_id for fact in assertions)),
    )


def _fresh_id_tuple(
    values: tuple[str, ...],
    *,
    kind: FreshIdKind,
    name: str,
) -> None:
    if type(values) is not tuple:
        message = f"{name} IDs must be a tuple"
        raise TypeError(message)
    for value in values:
        validate_fresh_id(value, expected_kind=kind)
    if len(set(values)) != len(values):
        message = f"{name} IDs must be unique"
        raise ValueError(message)


def _unique_ordered(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


__all__ = [
    "AmbiguityReconciler",
    "ReconciliationAssertionFact",
    "ReconciliationDecision",
    "ReconciliationEvidence",
    "ReconciliationOutcome",
    "ReconciliationReason",
]
