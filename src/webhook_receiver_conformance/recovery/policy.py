"""Conservative resume-policy planning over verified recovery evidence."""
# ruff: noqa: D105, D107, INP001, PLR0913

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Hashable, Iterable

from webhook_receiver_conformance.domain.enums import AttemptState
from webhook_receiver_conformance.domain.hashing import validate_sha256_digest
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    new_fresh_id,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.errors import (
    ErrorCategory,
    ExitCode,
    ResultCategory,
    exit_for_result,
)
from webhook_receiver_conformance.journal.transitions import MAX_SAFE_INTEGER
from webhook_receiver_conformance.recovery.models import (
    AttemptRecoveryItem,
    RecoveryAmbiguity,
    RecoveryPlan,
    RecoveryScanContext,
)
from webhook_receiver_conformance.scheduler.clocks import (
    TransitionTimestamp,
    validate_logical_nanoseconds,
)
from webhook_receiver_conformance.scheduler.queue import (
    MAX_SCHEDULE_ITEMS,
    PersistentPriorityQueue,
    ScheduleItem,
    ScheduleQueueError,
)
from webhook_receiver_conformance.types import DiagnosticCode

MAX_POLICY_ITEMS = MAX_SCHEDULE_ITEMS
MAX_EVIDENCE_REFERENCES = 1_000
MAX_REASON_BYTES = 4_096
MAX_TIE_KEY_BYTES = 200
MAX_CONDITION_BYTES = 1_048_576
_C0_CONTROL_LIMIT = 32
_DELETE_CONTROL_CODEPOINT = 127
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]+")
_LOWER_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")


class AmbiguityPolicy(StrEnum):
    """Closed resume policies for unresolved physical attempts."""

    STOP = "stop"
    OBSERVE = "observe"
    REDELIVER = "redeliver"
    OPERATOR_DECISION = "operator_decision"


class ResumeDisposition(StrEnum):
    """Whether policy permits execution to continue."""

    CONTINUE = "continue"
    AWAIT_OBSERVATION = "await_observation"
    STOP_AMBIGUOUS = "stop_ambiguous"
    CANCELLED = "cancelled"


class OperatorVerdict(StrEnum):
    """Closed operator claims that never rewrite attempt history."""

    PROCESSED = "processed"
    NOT_PROCESSED = "not_processed"
    STILL_UNKNOWN = "still_unknown"


class RecoveryDecisionKind(StrEnum):
    """Typed append-only decision values for the recovery journal adapter."""

    STOPPED_AMBIGUOUS = "stopped_ambiguous"
    OBSERVATION_REQUESTED = "observation_requested"
    REDELIVERY_CREATED = "redelivery_created"
    OPERATOR_PROCESSED = "operator_processed"
    OPERATOR_NOT_PROCESSED = "operator_not_processed"
    OPERATOR_STILL_UNKNOWN = "operator_still_unknown"


class ResumePolicyError(RuntimeError):
    """A classified, privacy-safe resume-policy failure."""

    category: ErrorCategory = ErrorCategory.INTEGRITY_ERROR
    result_category: ResultCategory = ResultCategory.HARNESS_ERROR
    exit_code: ExitCode = ExitCode.HARNESS_FAILURE
    code: DiagnosticCode = DiagnosticCode("RESUME_POLICY_ERROR")


class ResumePolicyIntegrityError(ResumePolicyError):
    """Verified inputs or a consumed adapter contract disagree."""

    code = DiagnosticCode("RESUME_POLICY_INTEGRITY")


class ResumePolicyInputError(ResumePolicyError):
    """An explicit resume policy input is malformed."""

    category = ErrorCategory.CONFIGURATION_ERROR
    result_category = ResultCategory.INVALID_INPUT
    exit_code = ExitCode.INVALID_INPUT
    code = DiagnosticCode("RESUME_POLICY_INPUT")


class ResumePolicyResourceLimitError(ResumePolicyError):
    """A bounded recovery or scheduler projection was exceeded."""

    category = ErrorCategory.RESOURCE_LIMIT
    code = DiagnosticCode("RESUME_POLICY_LIMIT")


@dataclass(frozen=True, slots=True)
class RecoveryEvidenceReference:
    """One bounded, non-secret reference attached to a recovery decision."""

    evidence_kind: str
    evidence_id: str

    def __post_init__(self) -> None:
        _lower_identifier(
            self.evidence_kind,
            name="evidence_kind",
            maximum=64,
        )
        _token(self.evidence_id, name="evidence_id", maximum=96)


@dataclass(frozen=True, slots=True)
class RedeliveryTemplate:
    """Immutable bundle authorization for one delivery's explicit redelivery."""

    scenario_id: str
    event_id: str
    delivery_id: str
    attempt_plan_id: str
    logical_due_ns: int
    deterministic_tie_key: str

    def __post_init__(self) -> None:
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)
        validate_planned_id(
            self.delivery_id,
            expected_kind=PlannedIdKind.DELIVERY,
        )
        validate_planned_id(
            self.attempt_plan_id,
            expected_kind=PlannedIdKind.ATTEMPT_PLAN,
        )
        validate_logical_nanoseconds(self.logical_due_ns)
        _token(
            self.deterministic_tie_key,
            name="redelivery deterministic_tie_key",
            maximum=MAX_TIE_KEY_BYTES,
        )


@dataclass(frozen=True, slots=True)
class ObservationReconciliationRule:
    """Configured observer and decisive assertion set for one delivery."""

    scenario_id: str
    delivery_id: str
    observation_id: str
    assertion_ids: tuple[str, ...]
    read_only: bool
    idempotent: bool

    def __post_init__(self) -> None:
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_planned_id(
            self.delivery_id,
            expected_kind=PlannedIdKind.DELIVERY,
        )
        validate_planned_id(
            self.observation_id,
            expected_kind=PlannedIdKind.OBSERVATION,
        )
        if type(self.assertion_ids) is not tuple or not self.assertion_ids:
            message = "observation reconciliation requires a decisive assertion tuple"
            raise ValueError(message)
        if len(self.assertion_ids) >= MAX_EVIDENCE_REFERENCES:
            message = "observation assertions exceed the policy reference limit"
            raise ResumePolicyResourceLimitError(message)
        for assertion_id in self.assertion_ids:
            validate_planned_id(
                assertion_id,
                expected_kind=PlannedIdKind.ASSERTION,
            )
        if len(set(self.assertion_ids)) != len(self.assertion_ids):
            message = "observation assertion identities must be unique"
            raise ValueError(message)
        if type(self.read_only) is not bool or type(self.idempotent) is not bool:
            message = "observer capabilities must be exact booleans"
            raise TypeError(message)

    @property
    def eligible_for_resume(self) -> bool:
        """Require both automatic-reconciliation capability promises."""
        return self.read_only and self.idempotent


@dataclass(frozen=True, slots=True)
class BundleRecoveryPolicy:
    """Trusted policy material extracted from the immutable run bundle."""

    redelivery_templates: tuple[RedeliveryTemplate, ...] = ()
    observation_rules: tuple[ObservationReconciliationRule, ...] = ()

    def __post_init__(self) -> None:
        _exact_tuple(
            self.redelivery_templates,
            RedeliveryTemplate,
            name="redelivery_templates",
        )
        _exact_tuple(
            self.observation_rules,
            ObservationReconciliationRule,
            name="observation_rules",
        )
        if (
            len(self.redelivery_templates) > MAX_POLICY_ITEMS
            or len(self.observation_rules) > MAX_POLICY_ITEMS
        ):
            message = "bundle recovery policy exceeds the policy item limit"
            raise ResumePolicyResourceLimitError(message)
        _unique_scope(
            ((item.scenario_id, item.delivery_id) for item in self.redelivery_templates),
            name="redelivery template",
        )
        _unique_scope(
            ((item.scenario_id, item.delivery_id) for item in self.observation_rules),
            name="observation rule",
        )


@dataclass(frozen=True, slots=True)
class OperatorDecisionDirective:
    """One explicit operator decision, never an attempt-state mutation."""

    attempt_id: str
    verdict: OperatorVerdict
    reason: str = field(repr=False)
    operator_identity_fingerprint: str
    operator_input_digest: str
    evidence: tuple[RecoveryEvidenceReference, ...]
    signed_policy_verified: bool = False

    def __post_init__(self) -> None:
        validate_fresh_id(
            self.attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
        if type(self.verdict) is not OperatorVerdict:
            message = "operator verdict must be an OperatorVerdict"
            raise TypeError(message)
        _bounded_text(self.reason, name="operator reason", maximum=MAX_REASON_BYTES)
        validate_sha256_digest(self.operator_identity_fingerprint)
        validate_sha256_digest(self.operator_input_digest)
        _exact_tuple(
            self.evidence,
            RecoveryEvidenceReference,
            name="operator evidence",
        )
        if not self.evidence:
            message = "operator decisions require at least one evidence reference"
            raise ValueError(message)
        if len(self.evidence) > MAX_EVIDENCE_REFERENCES:
            message = "operator evidence exceeds the policy reference limit"
            raise ValueError(message)
        if len(set(self.evidence)) != len(self.evidence):
            message = "operator evidence references must be unique"
            raise ValueError(message)
        if type(self.signed_policy_verified) is not bool:
            message = "signed_policy_verified must be an exact boolean"
            raise TypeError(message)


@dataclass(frozen=True, slots=True)
class ResumeInvocationPolicy:
    """Per-invocation choices kept separate from trusted bundle policy."""

    on_ambiguous: AmbiguityPolicy | None = None
    noninteractive: bool = True
    cancel_requested: bool = False
    operator_decisions: tuple[OperatorDecisionDirective, ...] = ()

    def __post_init__(self) -> None:
        if self.on_ambiguous is not None and type(self.on_ambiguous) is not AmbiguityPolicy:
            message = "on_ambiguous must be an AmbiguityPolicy or None"
            raise TypeError(message)
        if type(self.noninteractive) is not bool or type(self.cancel_requested) is not bool:
            message = "invocation flags must be exact booleans"
            raise TypeError(message)
        _exact_tuple(
            self.operator_decisions,
            OperatorDecisionDirective,
            name="operator_decisions",
        )
        if len(self.operator_decisions) > MAX_POLICY_ITEMS:
            message = "operator decisions exceed the policy item limit"
            raise ResumePolicyResourceLimitError(message)
        if self.operator_decisions and self.on_ambiguous is not AmbiguityPolicy.OPERATOR_DECISION:
            message = "operator decisions require the operator_decision policy"
            raise ValueError(message)
        _unique_values(
            (item.attempt_id for item in self.operator_decisions),
            name="operator attempt",
        )


@dataclass(frozen=True, slots=True)
class PersistedScheduleSnapshot:
    """Bounded schedule rows and their durably consumed identity set."""

    entries: tuple[ScheduleItem, ...]
    consumed_entry_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _exact_tuple(self.entries, ScheduleItem, name="schedule entries")
        if type(self.consumed_entry_ids) is not frozenset:
            message = "consumed_entry_ids must be an immutable frozenset"
            raise TypeError(message)
        if len(self.entries) > MAX_POLICY_ITEMS or len(self.consumed_entry_ids) > MAX_POLICY_ITEMS:
            message = "persisted schedule snapshot exceeds the policy item limit"
            raise ResumePolicyResourceLimitError(message)
        entry_ids = tuple(item.schedule_entry_id for item in self.entries)
        _unique_values(entry_ids, name="schedule entry")
        for entry_id in self.consumed_entry_ids:
            _token(entry_id, name="consumed schedule entry ID", maximum=96)
        if not self.consumed_entry_ids.issubset(entry_ids):
            message = "consumed schedule identity is absent from its persisted snapshot"
            raise ResumePolicyIntegrityError(message)


@dataclass(frozen=True, slots=True)
class ResumePolicyContext:
    """Verified scanner evidence bound to the same run and owner epoch."""

    scan_context: RecoveryScanContext
    recovery_plan: RecoveryPlan

    def __post_init__(self) -> None:
        if type(self.scan_context) is not RecoveryScanContext:
            message = "resume policy requires verified RecoveryScanContext"
            raise ResumePolicyIntegrityError(message)
        if type(self.recovery_plan) is not RecoveryPlan:
            message = "resume policy requires a RecoveryPlan"
            raise ResumePolicyIntegrityError(message)
        if (
            self.scan_context.run_id != self.recovery_plan.run_id
            or self.scan_context.owner_epoch != self.recovery_plan.owner_epoch
        ):
            message = "recovery plan and verified owner context disagree"
            raise ResumePolicyIntegrityError(message)


@dataclass(frozen=True, slots=True)
class ObservationReconciliationPlan:
    """One later-owned observer reconciliation request."""

    attempt_id: str
    scenario_id: str
    delivery_id: str
    observation_id: str
    assertion_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_fresh_id(
            self.attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_planned_id(
            self.delivery_id,
            expected_kind=PlannedIdKind.DELIVERY,
        )
        validate_planned_id(
            self.observation_id,
            expected_kind=PlannedIdKind.OBSERVATION,
        )
        if type(self.assertion_ids) is not tuple or not self.assertion_ids:
            message = "observation plan requires decisive assertion identities"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class RedeliveryAttemptPlan:
    """A new physical attempt linked to, but never replacing, an unknown one."""

    run_id: str
    scenario_id: str
    event_id: str
    delivery_id: str
    predecessor_attempt_id: str
    attempt_id: str
    attempt_plan_id: str
    attempt_ordinal: int
    schedule_item: ScheduleItem
    schedule_idempotency_key: str
    condition_json: bytes

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)
        validate_planned_id(
            self.delivery_id,
            expected_kind=PlannedIdKind.DELIVERY,
        )
        validate_fresh_id(
            self.predecessor_attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
        validate_fresh_id(
            self.attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
        if self.attempt_id == self.predecessor_attempt_id:
            message = "redelivery must use a distinct physical attempt identity"
            raise ValueError(message)
        validate_planned_id(
            self.attempt_plan_id,
            expected_kind=PlannedIdKind.ATTEMPT_PLAN,
        )
        _nonnegative_safe_integer(self.attempt_ordinal, name="attempt_ordinal")
        if type(self.schedule_item) is not ScheduleItem:
            message = "redelivery schedule_item must be a ScheduleItem"
            raise TypeError(message)
        if (
            self.schedule_item.entity_id != self.attempt_plan_id
            or self.schedule_item.attempt_ordinal != self.attempt_ordinal
        ):
            message = "redelivery schedule and physical attempt plan disagree"
            raise ValueError(message)
        _token(
            self.schedule_idempotency_key,
            name="schedule_idempotency_key",
            maximum=256,
        )
        if type(self.condition_json) is not bytes or len(self.condition_json) > MAX_CONDITION_BYTES:
            message = "redelivery condition_json must be bounded bytes"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class RecoveryDecisionPlan:
    """One append-only recovery decision for an atomic journal adapter."""

    decision_id: str
    run_id: str
    scenario_id: str
    attempt_id: str
    policy: AmbiguityPolicy
    decision: RecoveryDecisionKind
    reason: str = field(repr=False)
    timestamp: TransitionTimestamp
    evidence: tuple[RecoveryEvidenceReference, ...] = ()
    operator_identity_fingerprint: str | None = None
    operator_input_digest: str | None = None

    def __post_init__(self) -> None:
        _token(self.decision_id, name="decision_id", maximum=96)
        validate_run_id(self.run_id)
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_fresh_id(
            self.attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
        if type(self.policy) is not AmbiguityPolicy:
            message = "decision policy must be an AmbiguityPolicy"
            raise TypeError(message)
        if type(self.decision) is not RecoveryDecisionKind:
            message = "decision must be a RecoveryDecisionKind"
            raise TypeError(message)
        _bounded_text(self.reason, name="decision reason", maximum=MAX_REASON_BYTES)
        if type(self.timestamp) is not TransitionTimestamp or not self.timestamp.is_live:
            message = "resume decisions require a live transition timestamp"
            raise ValueError(message)
        _exact_tuple(
            self.evidence,
            RecoveryEvidenceReference,
            name="decision evidence",
        )
        if len(self.evidence) > MAX_EVIDENCE_REFERENCES:
            message = "decision evidence exceeds the reference limit"
            raise ValueError(message)
        if len(set(self.evidence)) != len(self.evidence):
            message = "decision evidence references must be unique"
            raise ValueError(message)
        self._validate_operator_fields()

    def _validate_operator_fields(self) -> None:
        is_operator = self.policy is AmbiguityPolicy.OPERATOR_DECISION
        has_operator = (
            self.operator_identity_fingerprint is not None
            and self.operator_input_digest is not None
        )
        if is_operator != has_operator:
            message = "operator decision fingerprint fields are incomplete or misplaced"
            raise ValueError(message)
        if has_operator:
            fingerprint = self.operator_identity_fingerprint
            input_digest = self.operator_input_digest
            if fingerprint is None or input_digest is None:
                message = "operator fingerprint narrowing failed"
                raise AssertionError(message)
            validate_sha256_digest(fingerprint)
            validate_sha256_digest(input_digest)


@dataclass(frozen=True, slots=True)
class ResumePolicyPlan:
    """Immutable policy result; constructing it performs no I/O."""

    run_id: str
    owner_epoch: int
    requested_policy: AmbiguityPolicy | None
    effective_policy: AmbiguityPolicy
    disposition: ResumeDisposition
    result_category: ResultCategory | None
    exit_code: ExitCode | None
    ambiguous_attempt_ids: tuple[str, ...]
    decisions: tuple[RecoveryDecisionPlan, ...]
    redeliveries: tuple[RedeliveryAttemptPlan, ...]
    observations: tuple[ObservationReconciliationPlan, ...]
    runnable_schedule: tuple[ScheduleItem, ...]
    deferred_schedule: tuple[ScheduleItem, ...]

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        _nonnegative_integer(self.owner_epoch, name="owner_epoch", maximum=(2**63) - 1)
        if self.requested_policy is not None and type(self.requested_policy) is not AmbiguityPolicy:
            message = "requested_policy must be an AmbiguityPolicy or None"
            raise TypeError(message)
        if type(self.effective_policy) is not AmbiguityPolicy:
            message = "effective_policy must be an AmbiguityPolicy"
            raise TypeError(message)
        if type(self.disposition) is not ResumeDisposition:
            message = "disposition must be a ResumeDisposition"
            raise TypeError(message)
        _validate_plan_result(self)
        _validate_policy_plan_collections(self)

    @property
    def requires_journal_commit(self) -> bool:
        """Return whether decisions or new physical attempts must commit."""
        return bool(self.decisions or self.redeliveries)

    @property
    def delivery_execution_allowed(self) -> bool:
        """Return whether the scheduler may expose runnable delivery work."""
        return self.disposition is ResumeDisposition.CONTINUE

    @property
    def observer_contact_allowed(self) -> bool:
        """Return whether explicit configured observer work was planned."""
        return bool(self.observations)

    @property
    def performs_io(self) -> bool:
        """Policy planning itself never performs receiver, observer, or file I/O."""
        return False


@dataclass(frozen=True, slots=True)
class PolicyApplication:
    """Result of the single atomic policy-journal boundary."""

    plan: ResumePolicyPlan
    commit_attempted: bool
    newly_committed: bool

    @property
    def idempotent_replay(self) -> bool:
        """Return whether an attempted commit already existed exactly."""
        return self.commit_attempted and not self.newly_committed


class FreshAttemptIdFactory(Protocol):
    """Injectable fresh physical-attempt identity boundary."""

    def __call__(self) -> str:
        """Return one separately generated attempt ID."""
        ...


@runtime_checkable
class AtomicResumePolicyJournal(Protocol):
    """Later-provided local adapter for one atomic policy transaction."""

    async def commit_policy(self, plan: ResumePolicyPlan) -> bool:
        """Append decisions and create redeliveries/schedules atomically.

        Return true for a new commit and false only for an exact idempotent replay.
        Implementations must verify owner epoch and must not perform network I/O.
        """
        ...


class ResumePolicyEngine:
    """Build and apply explicit recovery policy without implicit delivery."""

    __slots__ = ("_fresh_attempt_id",)

    def __init__(
        self,
        *,
        fresh_attempt_id: FreshAttemptIdFactory | None = None,
    ) -> None:
        factory = _new_attempt_id if fresh_attempt_id is None else fresh_attempt_id
        if not callable(factory):
            message = "fresh_attempt_id must be callable"
            raise TypeError(message)
        self._fresh_attempt_id = factory

    def build_plan(  # noqa: PLR0911
        self,
        context: ResumePolicyContext,
        *,
        bundle_policy: BundleRecoveryPolicy,
        invocation: ResumeInvocationPolicy,
        schedule: PersistedScheduleSnapshot,
        timestamp: TransitionTimestamp,
    ) -> ResumePolicyPlan:
        """Build one bounded plan after integrity and scanner verification."""
        _require_build_inputs(
            context,
            bundle_policy=bundle_policy,
            invocation=invocation,
            schedule=schedule,
            timestamp=timestamp,
        )
        pending = _pending_schedule(schedule)
        ambiguous = tuple(
            item
            for item in context.recovery_plan.attempts
            if item.ambiguity is not RecoveryAmbiguity.NONE
        )
        _policy_item_limit(ambiguous, pending)
        if invocation.cancel_requested:
            if ambiguous:
                return _stop_plan(
                    context,
                    requested=invocation.on_ambiguous,
                    ambiguous=ambiguous,
                    pending=pending,
                    timestamp=timestamp,
                    reason="cancellation_preserved_unresolved_ambiguity",
                )
            return _cancelled_plan(context, invocation, pending)
        if not ambiguous:
            return _continue_without_ambiguity(context, invocation, pending)
        requested = invocation.on_ambiguous
        policy = AmbiguityPolicy.STOP if requested is None else requested
        if policy is AmbiguityPolicy.STOP:
            return _stop_plan(
                context,
                requested=requested,
                ambiguous=ambiguous,
                pending=pending,
                timestamp=timestamp,
                reason="default_stop" if requested is None else "explicit_stop",
            )
        if policy is AmbiguityPolicy.OBSERVE:
            return _observe_plan(
                context,
                bundle_policy=bundle_policy,
                ambiguous=ambiguous,
                pending=pending,
                timestamp=timestamp,
            )
        if policy is AmbiguityPolicy.OPERATOR_DECISION:
            return _operator_plan(
                context,
                invocation=invocation,
                ambiguous=ambiguous,
                pending=pending,
                timestamp=timestamp,
            )
        return self._redelivery_plan(
            context,
            bundle_policy=bundle_policy,
            ambiguous=ambiguous,
            pending=pending,
            snapshot=schedule,
            timestamp=timestamp,
        )

    def _redelivery_plan(
        self,
        context: ResumePolicyContext,
        *,
        bundle_policy: BundleRecoveryPolicy,
        ambiguous: tuple[AttemptRecoveryItem, ...],
        pending: tuple[ScheduleItem, ...],
        snapshot: PersistedScheduleSnapshot,
        timestamp: TransitionTimestamp,
    ) -> ResumePolicyPlan:
        templates = {
            (item.scenario_id, item.delivery_id): item
            for item in bundle_policy.redelivery_templates
        }
        reason = _redelivery_block_reason(ambiguous, templates)
        if reason is not None:
            return _stop_plan(
                context,
                requested=AmbiguityPolicy.REDELIVER,
                ambiguous=ambiguous,
                pending=pending,
                timestamp=timestamp,
                reason=reason,
            )
        return self._authorized_redelivery_plan(
            context,
            ambiguous=ambiguous,
            pending=pending,
            snapshot=snapshot,
            timestamp=timestamp,
            templates=templates,
        )

    def _authorized_redelivery_plan(
        self,
        context: ResumePolicyContext,
        *,
        ambiguous: tuple[AttemptRecoveryItem, ...],
        pending: tuple[ScheduleItem, ...],
        snapshot: PersistedScheduleSnapshot,
        timestamp: TransitionTimestamp,
        templates: dict[tuple[str, str], RedeliveryTemplate],
    ) -> ResumePolicyPlan:
        existing_attempt_ids = {item.attempt_id for item in context.recovery_plan.attempts}
        generated_ids: set[str] = set()
        schedule_ids = {item.schedule_entry_id for item in snapshot.entries} | set(
            snapshot.consumed_entry_ids
        )
        redeliveries: list[RedeliveryAttemptPlan] = []
        for item in ambiguous:
            template = templates[(item.scenario_id, item.delivery_id)]
            attempt_id = _fresh_redelivery_id(
                self._fresh_attempt_id,
                existing=existing_attempt_ids | generated_ids,
            )
            generated_ids.add(attempt_id)
            redelivery = _redelivery_from(
                context,
                item=item,
                template=template,
                attempt_id=attempt_id,
            )
            if redelivery.schedule_item.schedule_entry_id in schedule_ids:
                message = "redelivery schedule identity collides with persisted state"
                raise ResumePolicyIntegrityError(message)
            schedule_ids.add(redelivery.schedule_item.schedule_entry_id)
            redeliveries.append(redelivery)
        if len(pending) + len(redeliveries) > MAX_POLICY_ITEMS:
            message = "redelivery would exceed the scheduler item limit"
            raise ResumePolicyResourceLimitError(message)
        runnable, deferred = _partition_linked_schedule(pending, ambiguous)
        decisions = tuple(
            _decision_for(
                context,
                item=item,
                policy=AmbiguityPolicy.REDELIVER,
                decision=RecoveryDecisionKind.REDELIVERY_CREATED,
                reason="explicit_bundle_and_invocation_redelivery",
                timestamp=timestamp,
                evidence=(RecoveryEvidenceReference("attempt", redelivery.attempt_id),),
            )
            for item, redelivery in zip(ambiguous, redeliveries, strict=True)
        )
        runnable_with_redelivery = tuple(
            sorted(
                (
                    *runnable,
                    *(item.schedule_item for item in redeliveries),
                ),
                key=lambda item: item.order_key,
            )
        )
        return ResumePolicyPlan(
            run_id=context.recovery_plan.run_id,
            owner_epoch=context.recovery_plan.owner_epoch,
            requested_policy=AmbiguityPolicy.REDELIVER,
            effective_policy=AmbiguityPolicy.REDELIVER,
            disposition=ResumeDisposition.CONTINUE,
            result_category=None,
            exit_code=None,
            ambiguous_attempt_ids=tuple(item.attempt_id for item in ambiguous),
            decisions=decisions,
            redeliveries=tuple(redeliveries),
            observations=(),
            runnable_schedule=runnable_with_redelivery,
            deferred_schedule=deferred,
        )

    async def apply(
        self,
        plan: ResumePolicyPlan,
        *,
        journal: AtomicResumePolicyJournal,
    ) -> PolicyApplication:
        """Commit policy data through one local atomic adapter boundary."""
        if type(plan) is not ResumePolicyPlan:
            message = "plan must be a ResumePolicyPlan"
            raise TypeError(message)
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            journal,
            AtomicResumePolicyJournal,
        ):
            message = "journal must implement AtomicResumePolicyJournal"
            raise TypeError(message)
        if not plan.requires_journal_commit:
            return PolicyApplication(
                plan=plan,
                commit_attempted=False,
                newly_committed=False,
            )
        committed = await journal.commit_policy(plan)
        if type(committed) is not bool:
            message = "policy journal returned a non-boolean commit result"
            raise ResumePolicyIntegrityError(message)
        return PolicyApplication(
            plan=plan,
            commit_attempted=True,
            newly_committed=committed,
        )

    @staticmethod
    def reconstruct_queue(
        plan: ResumePolicyPlan,
    ) -> PersistentPriorityQueue:
        """Rebuild the scheduler projection without duplicating an identity."""
        if type(plan) is not ResumePolicyPlan:
            message = "plan must be a ResumePolicyPlan"
            raise TypeError(message)
        try:
            return PersistentPriorityQueue.reconstruct(
                plan.runnable_schedule,
                maximum_items=MAX_POLICY_ITEMS,
            )
        except ScheduleQueueError as error:
            message = "resume schedule reconstruction failed integrity checks"
            raise ResumePolicyIntegrityError(message) from error

    @classmethod
    def due_schedule(
        cls,
        plan: ResumePolicyPlan,
        logical_now_ns: int,
        *,
        limit: int,
    ) -> tuple[ScheduleItem, ...]:
        """Return the scheduler's stable, bounded due projection."""
        return cls.reconstruct_queue(plan).due(logical_now_ns, limit=limit)


def _require_build_inputs(
    context: object,
    *,
    bundle_policy: object,
    invocation: object,
    schedule: object,
    timestamp: object,
) -> None:
    if type(context) is not ResumePolicyContext:
        message = "context must be a verified ResumePolicyContext"
        raise ResumePolicyIntegrityError(message)
    if type(bundle_policy) is not BundleRecoveryPolicy:
        message = "bundle_policy must be a BundleRecoveryPolicy"
        raise ResumePolicyInputError(message)
    if type(invocation) is not ResumeInvocationPolicy:
        message = "invocation must be a ResumeInvocationPolicy"
        raise ResumePolicyInputError(message)
    if type(schedule) is not PersistedScheduleSnapshot:
        message = "schedule must be a PersistedScheduleSnapshot"
        raise ResumePolicyIntegrityError(message)
    if type(timestamp) is not TransitionTimestamp or not timestamp.is_live:
        message = "resume policy planning requires a live clock timestamp"
        raise ResumePolicyIntegrityError(message)


def _pending_schedule(
    snapshot: PersistedScheduleSnapshot,
) -> tuple[ScheduleItem, ...]:
    try:
        queue = PersistentPriorityQueue.reconstruct(
            snapshot.entries,
            consumed_entry_ids=snapshot.consumed_entry_ids,
            maximum_items=MAX_POLICY_ITEMS,
        )
    except ScheduleQueueError as error:
        message = "persisted schedule snapshot failed reconstruction"
        raise ResumePolicyIntegrityError(message) from error
    return queue.snapshot()


def _continue_without_ambiguity(
    context: ResumePolicyContext,
    invocation: ResumeInvocationPolicy,
    pending: tuple[ScheduleItem, ...],
) -> ResumePolicyPlan:
    effective = AmbiguityPolicy.STOP if invocation.on_ambiguous is None else invocation.on_ambiguous
    return ResumePolicyPlan(
        run_id=context.recovery_plan.run_id,
        owner_epoch=context.recovery_plan.owner_epoch,
        requested_policy=invocation.on_ambiguous,
        effective_policy=effective,
        disposition=ResumeDisposition.CONTINUE,
        result_category=None,
        exit_code=None,
        ambiguous_attempt_ids=(),
        decisions=(),
        redeliveries=(),
        observations=(),
        runnable_schedule=pending,
        deferred_schedule=(),
    )


def _cancelled_plan(
    context: ResumePolicyContext,
    invocation: ResumeInvocationPolicy,
    pending: tuple[ScheduleItem, ...],
) -> ResumePolicyPlan:
    result = ResultCategory.CANCELLED
    return ResumePolicyPlan(
        run_id=context.recovery_plan.run_id,
        owner_epoch=context.recovery_plan.owner_epoch,
        requested_policy=invocation.on_ambiguous,
        effective_policy=AmbiguityPolicy.STOP,
        disposition=ResumeDisposition.CANCELLED,
        result_category=result,
        exit_code=exit_for_result(result)[1],
        ambiguous_attempt_ids=(),
        decisions=(),
        redeliveries=(),
        observations=(),
        runnable_schedule=(),
        deferred_schedule=pending,
    )


def _stop_plan(
    context: ResumePolicyContext,
    *,
    requested: AmbiguityPolicy | None,
    ambiguous: tuple[AttemptRecoveryItem, ...],
    pending: tuple[ScheduleItem, ...],
    timestamp: TransitionTimestamp,
    reason: str,
) -> ResumePolicyPlan:
    result = ResultCategory.AMBIGUOUS
    decisions = tuple(
        _decision_for(
            context,
            item=item,
            policy=AmbiguityPolicy.STOP,
            decision=RecoveryDecisionKind.STOPPED_AMBIGUOUS,
            reason=reason,
            timestamp=timestamp,
        )
        for item in ambiguous
    )
    return ResumePolicyPlan(
        run_id=context.recovery_plan.run_id,
        owner_epoch=context.recovery_plan.owner_epoch,
        requested_policy=requested,
        effective_policy=AmbiguityPolicy.STOP,
        disposition=ResumeDisposition.STOP_AMBIGUOUS,
        result_category=result,
        exit_code=exit_for_result(result)[1],
        ambiguous_attempt_ids=tuple(item.attempt_id for item in ambiguous),
        decisions=decisions,
        redeliveries=(),
        observations=(),
        runnable_schedule=(),
        deferred_schedule=pending,
    )


def _observe_plan(
    context: ResumePolicyContext,
    *,
    bundle_policy: BundleRecoveryPolicy,
    ambiguous: tuple[AttemptRecoveryItem, ...],
    pending: tuple[ScheduleItem, ...],
    timestamp: TransitionTimestamp,
) -> ResumePolicyPlan:
    rules = {(item.scenario_id, item.delivery_id): item for item in bundle_policy.observation_rules}
    selected: list[ObservationReconciliationRule] = []
    for item in ambiguous:
        rule = rules.get((item.scenario_id, item.delivery_id))
        if rule is None or not rule.eligible_for_resume:
            return _stop_plan(
                context,
                requested=AmbiguityPolicy.OBSERVE,
                ambiguous=ambiguous,
                pending=pending,
                timestamp=timestamp,
                reason="observe_requires_read_only_idempotent_decisive_rule",
            )
        selected.append(rule)
    observations = tuple(
        ObservationReconciliationPlan(
            attempt_id=item.attempt_id,
            scenario_id=item.scenario_id,
            delivery_id=item.delivery_id,
            observation_id=rule.observation_id,
            assertion_ids=rule.assertion_ids,
        )
        for item, rule in zip(ambiguous, selected, strict=True)
    )
    decisions = tuple(
        _decision_for(
            context,
            item=item,
            policy=AmbiguityPolicy.OBSERVE,
            decision=RecoveryDecisionKind.OBSERVATION_REQUESTED,
            reason="configured_read_only_observer_and_decisive_assertions",
            timestamp=timestamp,
            evidence=(
                RecoveryEvidenceReference(
                    "observation",
                    observation.observation_id,
                ),
                *(
                    RecoveryEvidenceReference("assertion", assertion_id)
                    for assertion_id in observation.assertion_ids
                ),
            ),
        )
        for item, observation in zip(ambiguous, observations, strict=True)
    )
    return ResumePolicyPlan(
        run_id=context.recovery_plan.run_id,
        owner_epoch=context.recovery_plan.owner_epoch,
        requested_policy=AmbiguityPolicy.OBSERVE,
        effective_policy=AmbiguityPolicy.OBSERVE,
        disposition=ResumeDisposition.AWAIT_OBSERVATION,
        result_category=None,
        exit_code=None,
        ambiguous_attempt_ids=tuple(item.attempt_id for item in ambiguous),
        decisions=decisions,
        redeliveries=(),
        observations=observations,
        runnable_schedule=(),
        deferred_schedule=pending,
    )


def _operator_plan(
    context: ResumePolicyContext,
    *,
    invocation: ResumeInvocationPolicy,
    ambiguous: tuple[AttemptRecoveryItem, ...],
    pending: tuple[ScheduleItem, ...],
    timestamp: TransitionTimestamp,
) -> ResumePolicyPlan:
    directives = {item.attempt_id: item for item in invocation.operator_decisions}
    if set(directives) != {item.attempt_id for item in ambiguous}:
        return _stop_plan(
            context,
            requested=AmbiguityPolicy.OPERATOR_DECISION,
            ambiguous=ambiguous,
            pending=pending,
            timestamp=timestamp,
            reason="operator_decision_set_is_incomplete",
        )
    selected = tuple(directives[item.attempt_id] for item in ambiguous)
    if invocation.noninteractive and any(not item.signed_policy_verified for item in selected):
        return _stop_plan(
            context,
            requested=AmbiguityPolicy.OPERATOR_DECISION,
            ambiguous=ambiguous,
            pending=pending,
            timestamp=timestamp,
            reason="noninteractive_operator_policy_is_unsigned",
        )
    decisions = tuple(
        _operator_decision_for(
            context,
            item=item,
            directive=directive,
            timestamp=timestamp,
        )
        for item, directive in zip(ambiguous, selected, strict=True)
    )
    unresolved = any(item.verdict is OperatorVerdict.STILL_UNKNOWN for item in selected)
    runnable, linked = _partition_linked_schedule(pending, ambiguous)
    result = ResultCategory.AMBIGUOUS if unresolved else None
    return ResumePolicyPlan(
        run_id=context.recovery_plan.run_id,
        owner_epoch=context.recovery_plan.owner_epoch,
        requested_policy=AmbiguityPolicy.OPERATOR_DECISION,
        effective_policy=AmbiguityPolicy.OPERATOR_DECISION,
        disposition=(
            ResumeDisposition.STOP_AMBIGUOUS if unresolved else ResumeDisposition.CONTINUE
        ),
        result_category=result,
        exit_code=None if result is None else exit_for_result(result)[1],
        ambiguous_attempt_ids=tuple(item.attempt_id for item in ambiguous),
        decisions=decisions,
        redeliveries=(),
        observations=(),
        runnable_schedule=() if unresolved else runnable,
        deferred_schedule=pending if unresolved else linked,
    )


def _operator_decision_for(
    context: ResumePolicyContext,
    *,
    item: AttemptRecoveryItem,
    directive: OperatorDecisionDirective,
    timestamp: TransitionTimestamp,
) -> RecoveryDecisionPlan:
    kinds = {
        OperatorVerdict.PROCESSED: RecoveryDecisionKind.OPERATOR_PROCESSED,
        OperatorVerdict.NOT_PROCESSED: (RecoveryDecisionKind.OPERATOR_NOT_PROCESSED),
        OperatorVerdict.STILL_UNKNOWN: (RecoveryDecisionKind.OPERATOR_STILL_UNKNOWN),
    }
    return _decision_for(
        context,
        item=item,
        policy=AmbiguityPolicy.OPERATOR_DECISION,
        decision=kinds[directive.verdict],
        reason=directive.reason,
        timestamp=timestamp,
        evidence=directive.evidence,
        operator_identity_fingerprint=(directive.operator_identity_fingerprint),
        operator_input_digest=directive.operator_input_digest,
    )


def _decision_for(
    context: ResumePolicyContext,
    *,
    item: AttemptRecoveryItem,
    policy: AmbiguityPolicy,
    decision: RecoveryDecisionKind,
    reason: str,
    timestamp: TransitionTimestamp,
    evidence: tuple[RecoveryEvidenceReference, ...] = (),
    operator_identity_fingerprint: str | None = None,
    operator_input_digest: str | None = None,
) -> RecoveryDecisionPlan:
    return RecoveryDecisionPlan(
        decision_id=(
            f"resume.{context.recovery_plan.owner_epoch}.{policy.value}.{item.attempt_id}"
        ),
        run_id=context.recovery_plan.run_id,
        scenario_id=item.scenario_id,
        attempt_id=item.attempt_id,
        policy=policy,
        decision=decision,
        reason=reason,
        timestamp=timestamp,
        evidence=evidence,
        operator_identity_fingerprint=operator_identity_fingerprint,
        operator_input_digest=operator_input_digest,
    )


def _redelivery_block_reason(
    ambiguous: tuple[AttemptRecoveryItem, ...],
    templates: dict[tuple[str, str], RedeliveryTemplate],
) -> str | None:
    delivery_scopes = tuple((item.scenario_id, item.delivery_id) for item in ambiguous)
    if len(set(delivery_scopes)) != len(delivery_scopes):
        return "multiple_unresolved_attempts_share_one_delivery"
    for item in ambiguous:
        if not _is_redeliverable(item):
            return "ambiguity_is_not_a_terminal_unknown_outcome"
        template = templates.get((item.scenario_id, item.delivery_id))
        if template is None:
            return "scenario_redelivery_authorization_is_missing"
        if (
            template.scenario_id != item.scenario_id
            or template.event_id != item.event_id
            or template.delivery_id != item.delivery_id
        ):
            return "scenario_redelivery_authorization_identity_mismatch"
    return None


def _is_redeliverable(item: AttemptRecoveryItem) -> bool:
    return (
        item.prior_state is AttemptState.UNKNOWN_OUTCOME
        or item.target_state is AttemptState.UNKNOWN_OUTCOME
    )


def _fresh_redelivery_id(
    factory: FreshAttemptIdFactory,
    *,
    existing: set[str],
) -> str:
    try:
        attempt_id = factory()
        validate_fresh_id(
            attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
    except (TypeError, ValueError) as error:
        message = "fresh attempt identity factory returned an invalid value"
        raise ResumePolicyIntegrityError(message) from error
    if attempt_id in existing:
        message = "fresh attempt identity collides with recovery history"
        raise ResumePolicyIntegrityError(message)
    return attempt_id


def _redelivery_from(
    context: ResumePolicyContext,
    *,
    item: AttemptRecoveryItem,
    template: RedeliveryTemplate,
    attempt_id: str,
) -> RedeliveryAttemptPlan:
    attempt_ordinal = item.attempt_ordinal + 1
    if attempt_ordinal > MAX_SAFE_INTEGER:
        message = "redelivery attempt ordinal exceeds the safe-integer limit"
        raise ResumePolicyResourceLimitError(message)
    schedule_id = f"resume.redelivery.{attempt_id}"
    schedule = ScheduleItem(
        schedule_entry_id=schedule_id,
        entity_id=template.attempt_plan_id,
        logical_due_ns=template.logical_due_ns,
        scenario_ordinal=item.scenario_ordinal,
        step_ordinal=item.step_ordinal,
        delivery_ordinal=item.delivery_ordinal,
        attempt_ordinal=attempt_ordinal,
        deterministic_tie_key=(f"{template.deterministic_tie_key}.{attempt_id}"),
    )
    condition = json.dumps(
        {
            "attempt_id": attempt_id,
            "next_attempt_ordinal": attempt_ordinal,
            "policy": AmbiguityPolicy.REDELIVER.value,
            "predecessor_attempt_id": item.attempt_id,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return RedeliveryAttemptPlan(
        run_id=context.recovery_plan.run_id,
        scenario_id=item.scenario_id,
        event_id=item.event_id,
        delivery_id=item.delivery_id,
        predecessor_attempt_id=item.attempt_id,
        attempt_id=attempt_id,
        attempt_plan_id=template.attempt_plan_id,
        attempt_ordinal=attempt_ordinal,
        schedule_item=schedule,
        schedule_idempotency_key=f"resume.redelivery.schedule.{attempt_id}",
        condition_json=condition,
    )


def _partition_linked_schedule(
    pending: tuple[ScheduleItem, ...],
    ambiguous: tuple[AttemptRecoveryItem, ...],
) -> tuple[tuple[ScheduleItem, ...], tuple[ScheduleItem, ...]]:
    scopes = {
        (
            item.scenario_ordinal,
            item.step_ordinal,
            item.delivery_ordinal,
        )
        for item in ambiguous
    }
    runnable: list[ScheduleItem] = []
    deferred: list[ScheduleItem] = []
    for item in pending:
        scope = (
            item.scenario_ordinal,
            item.step_ordinal,
            item.delivery_ordinal,
        )
        (deferred if scope in scopes else runnable).append(item)
    return (tuple(runnable), tuple(deferred))


def _policy_item_limit(
    ambiguous: tuple[AttemptRecoveryItem, ...],
    pending: tuple[ScheduleItem, ...],
) -> None:
    if len(ambiguous) > MAX_POLICY_ITEMS or len(pending) > MAX_POLICY_ITEMS:
        message = "resume policy input exceeds the bounded item limit"
        raise ResumePolicyResourceLimitError(message)


def _validate_plan_result(plan: ResumePolicyPlan) -> None:
    if (plan.result_category is None) != (plan.exit_code is None):
        message = "result_category and exit_code must be present together"
        raise ValueError(message)
    if plan.result_category is not None:
        if type(plan.result_category) is not ResultCategory:
            message = "result_category must be a ResultCategory"
            raise TypeError(message)
        if type(plan.exit_code) is not ExitCode:
            message = "exit_code must be an ExitCode"
            raise TypeError(message)
        if exit_for_result(plan.result_category)[1] is not plan.exit_code:
            message = "policy result and exit code disagree"
            raise ValueError(message)
    if (
        plan.disposition in {ResumeDisposition.STOP_AMBIGUOUS, ResumeDisposition.CANCELLED}
        and plan.result_category is None
    ):
        message = "terminal policy disposition requires a result category"
        raise ValueError(message)


def _validate_policy_plan_collections(plan: ResumePolicyPlan) -> None:
    _exact_tuple(
        plan.ambiguous_attempt_ids,
        str,
        name="ambiguous_attempt_ids",
    )
    for attempt_id in plan.ambiguous_attempt_ids:
        validate_fresh_id(
            attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
    _unique_values(plan.ambiguous_attempt_ids, name="ambiguous attempt")
    for values, expected, name in (
        (plan.decisions, RecoveryDecisionPlan, "decisions"),
        (plan.redeliveries, RedeliveryAttemptPlan, "redeliveries"),
        (plan.observations, ObservationReconciliationPlan, "observations"),
        (plan.runnable_schedule, ScheduleItem, "runnable_schedule"),
        (plan.deferred_schedule, ScheduleItem, "deferred_schedule"),
    ):
        _exact_tuple(values, expected, name=name)
        if len(values) > MAX_POLICY_ITEMS:
            message = f"{name} exceeds the policy item limit"
            raise ResumePolicyResourceLimitError(message)
    if len(plan.runnable_schedule) + len(plan.deferred_schedule) > MAX_POLICY_ITEMS:
        message = "combined policy schedule exceeds the policy item limit"
        raise ResumePolicyResourceLimitError(message)
    if any(item.run_id != plan.run_id for item in plan.decisions) or any(
        item.run_id != plan.run_id for item in plan.redeliveries
    ):
        message = "policy plan contains another run's mutation"
        raise ValueError(message)
    runnable_ids = {item.schedule_entry_id for item in plan.runnable_schedule}
    deferred_ids = {item.schedule_entry_id for item in plan.deferred_schedule}
    if (
        len(runnable_ids) != len(plan.runnable_schedule)
        or len(deferred_ids) != len(plan.deferred_schedule)
        or runnable_ids & deferred_ids
    ):
        message = "policy schedule projections contain duplicate identities"
        raise ValueError(message)


def _new_attempt_id() -> str:
    return new_fresh_id(FreshIdKind.ATTEMPT)


def _exact_tuple(
    value: object,
    expected: type[object],
    *,
    name: str,
) -> None:
    if type(value) is not tuple:
        message = f"{name} must be an immutable tuple of exact {expected.__name__} values"
        raise TypeError(message)
    items = cast("tuple[object, ...]", value)
    if any(type(item) is not expected for item in items):
        message = f"{name} must be an immutable tuple of exact {expected.__name__} values"
        raise TypeError(message)


def _unique_scope(
    values: Iterable[tuple[str, str]],
    *,
    name: str,
) -> None:
    scopes = tuple(values)
    if len(scopes) != len(set(scopes)):
        message = f"{name} scopes must be unique"
        raise ValueError(message)


def _unique_values[T: Hashable](
    values: Iterable[T],
    *,
    name: str,
) -> None:
    items = tuple(values)
    if len(items) != len(set(items)):
        message = f"{name} identities must be unique"
        raise ValueError(message)


def _token(value: object, *, name: str, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _TOKEN.fullmatch(value) is None:
        message = f"{name} must be a bounded ASCII token"
        raise ValueError(message)
    return value


def _lower_identifier(value: object, *, name: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or _LOWER_IDENTIFIER.fullmatch(value) is None
    ):
        message = f"{name} must be a bounded lower identifier"
        raise ValueError(message)
    return value


def _bounded_text(value: object, *, name: str, maximum: int) -> str:
    if type(value) is not str or not value:
        message = f"{name} must be nonempty text"
        raise ValueError(message)
    if any(
        ord(character) < _C0_CONTROL_LIMIT or ord(character) == _DELETE_CONTROL_CODEPOINT
        for character in value
    ):
        message = f"{name} must be control-free"
        raise ValueError(message)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        message = f"{name} must contain Unicode scalar values"
        raise ValueError(message) from error
    if len(encoded) > maximum:
        message = f"{name} exceeds its byte limit"
        raise ValueError(message)
    return value


def _nonnegative_safe_integer(value: object, *, name: str) -> int:
    return _nonnegative_integer(value, name=name, maximum=MAX_SAFE_INTEGER)


def _nonnegative_integer(
    value: object,
    *,
    name: str,
    maximum: int,
) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        message = f"{name} must be a bounded nonnegative integer"
        raise ValueError(message)
    return value


__all__ = [
    "MAX_POLICY_ITEMS",
    "AmbiguityPolicy",
    "AtomicResumePolicyJournal",
    "BundleRecoveryPolicy",
    "ObservationReconciliationPlan",
    "ObservationReconciliationRule",
    "OperatorDecisionDirective",
    "OperatorVerdict",
    "PersistedScheduleSnapshot",
    "PolicyApplication",
    "RecoveryDecisionKind",
    "RecoveryDecisionPlan",
    "RecoveryEvidenceReference",
    "RedeliveryAttemptPlan",
    "RedeliveryTemplate",
    "ResumeDisposition",
    "ResumeInvocationPolicy",
    "ResumePolicyContext",
    "ResumePolicyEngine",
    "ResumePolicyError",
    "ResumePolicyInputError",
    "ResumePolicyIntegrityError",
    "ResumePolicyPlan",
    "ResumePolicyResourceLimitError",
]
