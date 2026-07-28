"""Atomic transition/projection operations over the sole journal writer."""
# ruff: noqa: C901, D105, D107, EM101, INP001, PLR2004, S608, TRY003

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, cast

from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    AttemptClassification,
    AttemptEvidenceState,
    AttemptState,
    DeliveryState,
    ObservationState,
    ObservationStatus,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.domain.models import (
    AssertionEvaluation,
    AttemptEvidence,
    RequestMetadata,
    ResponseMetadata,
    TransportError,
)
from webhook_receiver_conformance.observers.protocol import (
    ObservationRecord,
    ObservationRecordError,
    ObserverEvidence,
)
from webhook_receiver_conformance.scheduler.clocks import TransitionTimestamp

from .service import (
    JournalService,
    JournalStatement,
    JournalTransaction,
    SqlValue,
)
from .transitions import (
    MAX_CONDITION_BYTES,
    MAX_REPLAY_TRANSITIONS,
    MAX_SAFE_INTEGER,
    AttemptPhaseEvidence,
    AttemptPhaseEvidenceCommand,
    AttemptScheduleClaim,
    AttemptTransportEvidenceCommand,
    CausalReference,
    CommittedTransition,
    CrossRunReferenceError,
    DeliverySatisfactionEvidence,
    DeliverySatisfactionKind,
    EntityType,
    IdempotencyConflictError,
    IllegalTransitionError,
    LifecycleState,
    ProjectionAudit,
    ProjectionIntegrityError,
    ProjectionState,
    RetrySchedule,
    StaleOwnerEpochError,
    TransitionCommand,
    TransitionRecord,
    canonical_request_header_names_json,
    compare_projection_inventories,
    parse_state,
    replay_transition_records,
    state_machine,
    transition_allowed,
    validate_entity_id,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

INVENTORY_PAGE_SIZE = 1_000
MAX_POLICY_JSON_DEPTH = 64
_ENTITY_PROJECTION_COLUMN_COUNT = 10
_ASSERTION_GUARD_COLUMN_COUNT = 3
_TRANSITION_COLUMN_COUNT = 15
_PROJECTION_COLUMN_COUNT = 2
_ATTEMPT_RECORD_COLUMN_COUNT = 26
_OBSERVATION_SERIES_COLUMN_COUNT = 6
_OBSERVATION_SAMPLE_COLUMN_COUNT = 13
_ASSERTION_EVALUATION_COLUMN_COUNT = 12

TRIGGER_ATTEMPT_OUTCOME = "attempt_outcome"
TRIGGER_ASSERTION_POLICY = "assertion_policy"
TRIGGER_RETRY_ELIGIBLE = "retry_eligible"

_TERMINAL_ATTEMPT_STATES = frozenset(
    {
        AttemptState.NOT_SENT,
        AttemptState.SUCCEEDED,
        AttemptState.REJECTED,
        AttemptState.TRANSPORT_FAILED,
        AttemptState.UNKNOWN_OUTCOME,
        AttemptState.CANCELLED,
    }
)
_RETRY_PREDECESSOR_STATES = frozenset(
    {
        AttemptState.NOT_SENT,
        AttemptState.REJECTED,
        AttemptState.TRANSPORT_FAILED,
        AttemptState.UNKNOWN_OUTCOME,
    }
)
_ATOMIC_RETRY_STATES = frozenset(
    {
        AttemptState.NOT_SENT,
        AttemptState.REJECTED,
        AttemptState.TRANSPORT_FAILED,
    }
)
_CLASSIFICATIONS_BY_TERMINAL_STATE: Mapping[
    AttemptState,
    frozenset[AttemptClassification],
] = MappingProxyType(
    {
        AttemptState.NOT_SENT: frozenset(
            {
                AttemptClassification.ENVIRONMENT_FAILURE,
                AttemptClassification.HARNESS_FAILURE,
            }
        ),
        AttemptState.SUCCEEDED: frozenset({AttemptClassification.RECEIVER_ACCEPTED}),
        AttemptState.REJECTED: frozenset({AttemptClassification.RECEIVER_REJECTED}),
        AttemptState.TRANSPORT_FAILED: frozenset(
            {
                AttemptClassification.ENVIRONMENT_FAILURE,
                AttemptClassification.HARNESS_FAILURE,
            }
        ),
        AttemptState.UNKNOWN_OUTCOME: frozenset({AttemptClassification.AMBIGUOUS}),
        AttemptState.CANCELLED: frozenset({AttemptClassification.CANCELLED}),
    }
)
_EVIDENCE_STATES_BY_TERMINAL_STATE: Mapping[
    AttemptState,
    frozenset[AttemptEvidenceState],
] = MappingProxyType(
    {
        AttemptState.NOT_SENT: frozenset(
            {
                AttemptEvidenceState.CONNECTION_FAILED,
                AttemptEvidenceState.PROTOCOL_FAILED,
            }
        ),
        AttemptState.SUCCEEDED: frozenset({AttemptEvidenceState.ACKNOWLEDGED}),
        AttemptState.REJECTED: frozenset({AttemptEvidenceState.REJECTED}),
        AttemptState.TRANSPORT_FAILED: frozenset(
            {
                AttemptEvidenceState.TIMED_OUT,
                AttemptEvidenceState.CONNECTION_FAILED,
                AttemptEvidenceState.PROTOCOL_FAILED,
            }
        ),
        AttemptState.UNKNOWN_OUTCOME: frozenset({AttemptEvidenceState.UNKNOWN_OUTCOME}),
        AttemptState.CANCELLED: frozenset({AttemptEvidenceState.CANCELLED}),
    }
)


@dataclass(frozen=True, slots=True)
class _ProjectionTable:
    table: str
    identifier_column: str


_PROJECTION_TABLES: Mapping[EntityType, _ProjectionTable] = MappingProxyType(
    {
        EntityType.RUN: _ProjectionTable("runs", "run_id"),
        EntityType.SCENARIO: _ProjectionTable("scenarios", "scenario_id"),
        EntityType.DELIVERY: _ProjectionTable("deliveries", "delivery_id"),
        EntityType.ATTEMPT: _ProjectionTable("attempts", "attempt_id"),
        EntityType.OBSERVATION: _ProjectionTable(
            "observer_series",
            "observation_id",
        ),
        EntityType.ASSERTION: _ProjectionTable("assertions", "assertion_id"),
    }
)


class TransitionMutationPhase(StrEnum):
    """Injectable boundaries inside one atomic transition operation."""

    AFTER_APPEND = "after_append"
    AFTER_PROJECTION = "after_projection"
    AFTER_DERIVED_SCHEDULE = "after_derived_schedule"


class AttemptMutationPhase(StrEnum):
    """Injectable boundaries specific to attempt schedule/evidence operations."""

    AFTER_SCHEDULE_CONSUMED = "after_schedule_consumed"
    AFTER_ATTEMPT_INSERT = "after_attempt_insert"
    AFTER_PHASE_EVIDENCE = "after_phase_evidence"
    AFTER_ATTEMPT_RECORD = "after_attempt_record"


class ObservationMutationPhase(StrEnum):
    """Injectable boundaries specific to observation persistence."""

    AFTER_SERIES_INSERT = "after_series_insert"
    AFTER_SAMPLE_INSERT = "after_sample_insert"


class AssertionEvidenceKind(StrEnum):
    """Typed evidence-link categories supported by the journal schema."""

    ATTEMPT = "attempt"
    OBSERVATION = "observation"
    RECORD = "record"
    ARTIFACT = "artifact"
    TRANSITION = "transition"
    RECOVERY_DECISION = "recovery_decision"


class TransitionCrashHook(Protocol):
    """Synchronous failpoint callback executed inside the writer transaction."""

    def __call__(self, phase: TransitionMutationPhase | AttemptMutationPhase) -> None:
        """Observe or fail one exact transaction boundary."""
        ...


class ObservationCrashHook(Protocol):
    """Failpoint callback covering series/sample and nested transition phases."""

    def __call__(
        self,
        phase: TransitionMutationPhase | AttemptMutationPhase | ObservationMutationPhase,
    ) -> None:
        """Observe or fail one exact observation transaction boundary."""
        ...


@dataclass(frozen=True, slots=True)
class _EntityProjection:
    run_id: str
    state: LifecycleState
    scenario_id: str | None = None
    delivery_id: str | None = None
    outcome_category: str | None = None
    terminal_recorded_at: str | None = None
    attempt_ordinal: int | None = None
    scenario_ordinal: int | None = None
    step_ordinal: int | None = None
    delivery_ordinal: int | None = None


@dataclass(frozen=True, slots=True)
class _ApplyTransitionOperation:
    command: TransitionCommand[LifecycleState]
    crash_hook: TransitionCrashHook | None
    phase_evidence: AttemptPhaseEvidenceCommand | None = None
    transport_evidence: AttemptTransportEvidenceCommand | None = None

    def execute(self, transaction: JournalTransaction) -> CommittedTransition:
        _validate_payload_scope(self.command)
        _validate_transport_evidence_presence(
            self.command,
            self.transport_evidence,
        )
        _require_current_owner(transaction, self.command)
        existing = _transition_by_idempotency_key(
            transaction,
            self.command.run_id,
            self.command.idempotency_key,
        )
        if existing is not None:
            _verify_idempotent_replay(transaction, self.command, existing)
            if self.phase_evidence is not None:
                _verify_attempt_phase_evidence(
                    transaction,
                    command=self.command,
                    evidence=self.phase_evidence,
                )
            if self.transport_evidence is not None:
                _verify_existing_attempt_record(
                    transaction,
                    command=self.command,
                    transition=existing,
                    evidence=self.transport_evidence,
                )
            return CommittedTransition(record=existing, idempotent_replay=True)
        if _transition_id_exists(transaction, self.command.transition_id):
            message = "transition_id already names a different command"
            raise IdempotencyConflictError(message)

        projection = _load_entity_projection(
            transaction,
            self.command.entity_type,
            self.command.entity_id,
        )
        if projection is None:
            message = "transition entity does not exist"
            raise IllegalTransitionError(message)
        if projection.run_id != self.command.run_id:
            message = "transition entity belongs to a different run"
            raise CrossRunReferenceError(message)
        _validate_projection_and_edge(transaction, self.command, projection)
        _validate_transition_guards(transaction, self.command, projection)
        if self.transport_evidence is not None:
            _validate_transport_evidence_identity(
                transaction,
                command=self.command,
                evidence=self.transport_evidence,
            )

        sequence = _next_transition_sequence(transaction, self.command.run_id)
        record = _record_from_command(self.command, sequence=sequence)
        _insert_transition(transaction, record)
        _call_crash_hook(self.crash_hook, TransitionMutationPhase.AFTER_APPEND)

        if self.command.expected_state is not None:
            _update_projection(transaction, self.command, projection)
        _call_crash_hook(self.crash_hook, TransitionMutationPhase.AFTER_PROJECTION)
        if self.phase_evidence is not None:
            _persist_attempt_phase_evidence(
                transaction,
                command=self.command,
                evidence=self.phase_evidence,
            )
            _call_crash_hook(
                self.crash_hook,
                AttemptMutationPhase.AFTER_PHASE_EVIDENCE,
            )
        if self.transport_evidence is not None:
            evidence_sequence = _next_attempt_record_sequence(
                transaction,
                self.command.run_id,
            )
            attempt_record = _attempt_record_from_command(
                self.command,
                evidence=self.transport_evidence,
                sequence=evidence_sequence,
            )
            _insert_attempt_record(
                transaction,
                attempt_record,
                response_headers_elapsed_ns=(self.transport_evidence.response_headers_elapsed_ns),
            )
            _call_crash_hook(
                self.crash_hook,
                AttemptMutationPhase.AFTER_ATTEMPT_RECORD,
            )

        retry_schedule = (
            self.command.attempt_outcome.retry_schedule
            if self.command.attempt_outcome is not None
            else None
        )
        if retry_schedule is not None:
            _insert_retry_schedule(
                transaction,
                run_id=self.command.run_id,
                schedule=retry_schedule,
            )
        _call_crash_hook(
            self.crash_hook,
            TransitionMutationPhase.AFTER_DERIVED_SCHEDULE,
        )
        return CommittedTransition(record=record, idempotent_replay=False)


@dataclass(frozen=True, slots=True)
class _ClaimAttemptScheduleOperation:
    claim: AttemptScheduleClaim
    crash_hook: TransitionCrashHook | None

    def execute(self, transaction: JournalTransaction) -> CommittedTransition:
        command = cast("TransitionCommand[LifecycleState]", self.claim.claim_transition)
        _require_current_owner(transaction, command)
        schedule = _load_attempt_schedule(transaction, self.claim.schedule_entry_id)
        if schedule is None:
            raise IllegalTransitionError("attempt schedule does not exist")
        _validate_attempt_schedule_claim(transaction, self.claim, schedule)
        consumed_at = schedule[10]
        consumed_epoch = schedule[11]
        if consumed_at is None:
            result = transaction.execute(
                JournalStatement(
                    """
                    UPDATE schedule_entries
                    SET consumed_at = ?, consumed_by_owner_epoch = ?
                    WHERE schedule_entry_id = ? AND run_id = ?
                      AND consumed_at IS NULL AND consumed_by_owner_epoch IS NULL
                    """,
                    (
                        _format_wall_time(command.timestamp),
                        command.owner_epoch,
                        self.claim.schedule_entry_id,
                        command.run_id,
                    ),
                )
            )
            if result.rowcount != 1:
                raise ProjectionIntegrityError("attempt schedule consumption lost its guard")
            _call_crash_hook(
                self.crash_hook,
                AttemptMutationPhase.AFTER_SCHEDULE_CONSUMED,
            )
            _insert_claimed_attempt(transaction, self.claim, schedule)
            _call_crash_hook(
                self.crash_hook,
                AttemptMutationPhase.AFTER_ATTEMPT_INSERT,
            )
        else:
            if consumed_epoch != command.owner_epoch:
                raise IdempotencyConflictError("attempt schedule was consumed by another owner")
            _verify_claimed_attempt(transaction, self.claim, schedule)
        return _ApplyTransitionOperation(command, self.crash_hook).execute(transaction)


@dataclass(frozen=True, slots=True)
class _HistoryOperation:
    run_id: str
    entity_type: EntityType | None = None
    entity_id: str | None = None

    def execute(self, transaction: JournalTransaction) -> tuple[TransitionRecord, ...]:
        _require_run_exists(transaction, self.run_id)
        return _load_transition_history(
            transaction,
            run_id=self.run_id,
            entity_type=self.entity_type,
            entity_id=self.entity_id,
        )


@dataclass(frozen=True, slots=True)
class _ProjectionInventoryOperation:
    run_id: str

    def execute(self, transaction: JournalTransaction) -> tuple[ProjectionState, ...]:
        _require_run_exists(transaction, self.run_id)
        return _load_projection_inventory(transaction, self.run_id)


@dataclass(frozen=True, slots=True)
class _ProjectionAuditOperation:
    run_id: str

    def execute(self, transaction: JournalTransaction) -> ProjectionAudit:
        _require_run_exists(transaction, self.run_id)
        projected = _load_projection_inventory(transaction, self.run_id)
        history = _load_transition_history(transaction, run_id=self.run_id)
        replayed = replay_transition_records(history)
        return compare_projection_inventories(projected, replayed)


@dataclass(frozen=True, slots=True)
class _AttemptRecordIdOperation:
    run_id: str
    attempt_id: str

    def execute(self, transaction: JournalTransaction) -> str | None:
        _require_run_exists(transaction, self.run_id)
        result = transaction.execute(
            JournalStatement(
                """
                SELECT record_id
                FROM attempt_records
                WHERE run_id = ? AND attempt_id = ?
                """,
                (self.run_id, self.attempt_id),
            )
        )
        if len(result.rows) > 1:
            message = "attempt record identity is duplicated"
            raise ProjectionIntegrityError(message)
        if not result.rows:
            return None
        if len(result.rows[0]) != 1:
            message = "attempt record identity row has an invalid shape"
            raise ProjectionIntegrityError(message)
        record_id = _text(result.rows[0][0], name="attempt record_id")
        validate_fresh_id(record_id, expected_kind=FreshIdKind.RECORD)
        return record_id


@dataclass(frozen=True, slots=True)
class PersistedAttemptEvidence:
    """One public attempt record plus internal authoritative header latency."""

    attempt: AttemptEvidence
    response_headers_elapsed_ns: int | None

    def __post_init__(self) -> None:
        if type(self.attempt) is not AttemptEvidence:
            raise TypeError("attempt must be an AttemptEvidence")
        if self.response_headers_elapsed_ns is not None and (
            type(self.response_headers_elapsed_ns) is not int
            or not 0 <= self.response_headers_elapsed_ns <= MAX_SAFE_INTEGER
        ):
            raise ValueError(
                "response_headers_elapsed_ns must be a nonnegative I-JSON integer or None"
            )


@dataclass(frozen=True, slots=True)
class _AttemptEvidenceOperation:
    run_id: str
    attempt_id: str

    def execute(
        self,
        transaction: JournalTransaction,
    ) -> PersistedAttemptEvidence | None:
        _require_run_exists(transaction, self.run_id)
        result = transaction.execute(
            JournalStatement(
                f"""
                SELECT {_ATTEMPT_RECORD_COLUMNS}
                FROM attempt_records
                WHERE run_id = ? AND attempt_id = ?
                """,
                (self.run_id, self.attempt_id),
            )
        )
        if len(result.rows) > 1:
            raise ProjectionIntegrityError("attempt evidence identity is duplicated")
        if not result.rows:
            return None
        return _persisted_attempt_evidence_from_row(result.rows[0])


class TransitionRepository:
    """Typed async facade over atomic single-writer transition operations."""

    __slots__ = ("_crash_hook", "_service")

    def __init__(
        self,
        service: JournalService,
        *,
        crash_hook: TransitionCrashHook | None = None,
    ) -> None:
        """Bind the repository to one structured writer and optional failpoint."""
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            service,
            JournalService,
        ):
            message = "service must be a JournalService"
            raise TypeError(message)
        if crash_hook is not None and not callable(crash_hook):
            message = "crash_hook must be callable"
            raise TypeError(message)
        self._service = service
        self._crash_hook = crash_hook

    async def apply[S: LifecycleState](
        self,
        command: TransitionCommand[S],
    ) -> CommittedTransition:
        """Commit one guarded transition or expose no state."""
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            command,
            TransitionCommand,
        ):
            message = "command must be a TransitionCommand"
            raise TypeError(message)
        return await self._service.execute(
            _ApplyTransitionOperation(
                command=cast("TransitionCommand[LifecycleState]", command),
                crash_hook=self._crash_hook,
            )
        )

    async def apply_attempt[S: LifecycleState](
        self,
        command: TransitionCommand[S],
        evidence: AttemptPhaseEvidenceCommand | None = None,
        *,
        transport_evidence: AttemptTransportEvidenceCommand | None = None,
    ) -> CommittedTransition:
        """Commit one attempt edge with its exact phase/final sanitized evidence."""
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            command,
            TransitionCommand,
        ):
            raise TypeError("command must be a TransitionCommand")
        if command.entity_type is not EntityType.ATTEMPT:
            raise TypeError("command must be an attempt TransitionCommand")
        if evidence is not None:
            if type(evidence) is not AttemptPhaseEvidenceCommand:
                raise TypeError("evidence must be an AttemptPhaseEvidenceCommand or None")
            _validate_phase_edge(
                cast("TransitionCommand[LifecycleState]", command),
                evidence,
            )
        if (
            transport_evidence is not None
            and type(transport_evidence) is not AttemptTransportEvidenceCommand
        ):
            raise TypeError("transport_evidence must be an AttemptTransportEvidenceCommand or None")
        _validate_transport_evidence_presence(
            cast("TransitionCommand[LifecycleState]", command),
            transport_evidence,
        )
        return await self._service.execute(
            _ApplyTransitionOperation(
                command=cast("TransitionCommand[LifecycleState]", command),
                crash_hook=self._crash_hook,
                phase_evidence=evidence,
                transport_evidence=transport_evidence,
            )
        )

    async def claim_attempt_schedule(
        self,
        claim: AttemptScheduleClaim,
    ) -> CommittedTransition:
        """Atomically consume one schedule, insert a fresh attempt, and claim it."""
        if type(claim) is not AttemptScheduleClaim:
            raise TypeError("claim must be an AttemptScheduleClaim")
        return await self._service.execute(_ClaimAttemptScheduleOperation(claim, self._crash_hook))

    async def history(
        self,
        run_id: str,
        *,
        entity_type: EntityType | None = None,
        entity_id: str | None = None,
    ) -> tuple[TransitionRecord, ...]:
        """Return bounded ordered history for a run or one entity."""
        validate_run_id(run_id)
        if (entity_type is None) != (entity_id is None):
            message = "entity_type and entity_id must be provided together"
            raise ValueError(message)
        if entity_type is not None and entity_id is not None:
            validate_entity_id(entity_type, entity_id, run_id=run_id)
        return await self._service.execute(
            _HistoryOperation(
                run_id=run_id,
                entity_type=entity_type,
                entity_id=entity_id,
            )
        )

    async def projection_inventory(
        self,
        run_id: str,
    ) -> tuple[ProjectionState, ...]:
        """Return live lifecycle identity/state rows only."""
        validate_run_id(run_id)
        return await self._service.execute(_ProjectionInventoryOperation(run_id))

    async def audit_projections(self, run_id: str) -> ProjectionAudit:
        """Replay history and compare it with live lifecycle projections."""
        validate_run_id(run_id)
        return await self._service.execute(_ProjectionAuditOperation(run_id))

    async def attempt_record_id(
        self,
        run_id: str,
        attempt_id: str,
    ) -> str | None:
        """Return the durable evidence identity for one terminal attempt, if any."""
        validate_run_id(run_id)
        validate_fresh_id(attempt_id, expected_kind=FreshIdKind.ATTEMPT)
        return await self._service.execute(
            _AttemptRecordIdOperation(
                run_id=run_id,
                attempt_id=attempt_id,
            )
        )

    async def attempt_evidence(
        self,
        run_id: str,
        attempt_id: str,
    ) -> PersistedAttemptEvidence | None:
        """Load one sanitized terminal attempt and its authoritative header latency."""
        validate_run_id(run_id)
        validate_fresh_id(attempt_id, expected_kind=FreshIdKind.ATTEMPT)
        return await self._service.execute(
            _AttemptEvidenceOperation(
                run_id=run_id,
                attempt_id=attempt_id,
            )
        )


@dataclass(frozen=True, slots=True)
class ObservationSeriesCommand:
    """Create one planned observation series and start its first invocation."""

    run_id: str
    scenario_id: str
    observation_id: str
    observer_id: str
    checkpoint: str
    event_id: str | None
    initial_transition: TransitionCommand[ObservationState]
    running_transition: TransitionCommand[ObservationState]

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        validate_planned_id(self.scenario_id, expected_kind=PlannedIdKind.SCENARIO)
        validate_planned_id(
            self.observation_id,
            expected_kind=PlannedIdKind.OBSERVATION,
        )
        if self.event_id is not None:
            validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)
        _bounded_control_free_text(
            self.observer_id,
            name="observer_id",
            maximum=256,
        )
        _bounded_control_free_text(
            self.checkpoint,
            name="observation checkpoint",
            maximum=128,
        )
        if type(self.initial_transition) is not TransitionCommand:
            raise TypeError("initial_transition must be a TransitionCommand")
        if type(self.running_transition) is not TransitionCommand:
            raise TypeError("running_transition must be a TransitionCommand")
        initial = self.initial_transition
        running = self.running_transition
        if (
            initial.run_id != self.run_id
            or initial.entity_type is not EntityType.OBSERVATION
            or initial.entity_id != self.observation_id
            or initial.expected_state is not None
            or initial.new_state is not ObservationState.SCHEDULED
            or initial.causal_reference is not None
            or initial.attempt_outcome is not None
        ):
            raise ValueError("initial observation transition has a different identity or edge")
        if (
            running.run_id != self.run_id
            or running.entity_type is not EntityType.OBSERVATION
            or running.entity_id != self.observation_id
            or running.expected_state is not ObservationState.SCHEDULED
            or running.new_state is not ObservationState.RUNNING
            or running.owner_epoch != initial.owner_epoch
            or running.attempt_outcome is not None
        ):
            raise ValueError("running observation transition has a different identity or edge")


@dataclass(frozen=True, slots=True)
class ObservationSampleCommand:
    """Append one sanitized sample and optionally terminate its series."""

    record: ObservationRecord
    owner_epoch: int
    terminal_transition: TransitionCommand[ObservationState] | None = None

    def __post_init__(self) -> None:
        if type(self.record) is not ObservationRecord:
            raise TypeError("record must be an ObservationRecord")
        if type(self.owner_epoch) is not int or not 0 <= self.owner_epoch <= MAX_SAFE_INTEGER:
            raise ValueError("owner_epoch must be a nonnegative I-JSON integer")
        transition = self.terminal_transition
        if transition is None:
            if self.record.status not in {
                ObservationStatus.OK,
                ObservationStatus.PENDING,
                ObservationStatus.ERROR,
            }:
                raise ValueError("unsupported and timeout samples must terminate their series")
            return
        if type(transition) is not TransitionCommand:
            raise TypeError("terminal_transition must be a TransitionCommand or None")
        if (
            transition.run_id != self.record.run_id
            or transition.entity_type is not EntityType.OBSERVATION
            or transition.entity_id != self.record.observation_id
            or transition.expected_state is not ObservationState.RUNNING
            or transition.owner_epoch != self.owner_epoch
            or transition.causal_reference is None
            or transition.causal_reference.record_id != self.record.record_id
            or transition.attempt_outcome is not None
        ):
            raise ValueError("terminal observation transition differs from its sample")
        allowed_states: Mapping[ObservationStatus, frozenset[ObservationState]] = {
            ObservationStatus.OK: frozenset({ObservationState.OK}),
            ObservationStatus.PENDING: frozenset({ObservationState.PENDING}),
            ObservationStatus.UNSUPPORTED: frozenset({ObservationState.UNSUPPORTED}),
            ObservationStatus.ERROR: frozenset(
                {
                    ObservationState.ERROR,
                    ObservationState.CANCELLED,
                }
            ),
            ObservationStatus.TIMEOUT: frozenset({ObservationState.TIMED_OUT}),
        }
        if transition.new_state not in allowed_states[self.record.status]:
            raise ValueError("sample status and terminal observation state disagree")


@dataclass(frozen=True, slots=True)
class CommittedObservationSample:
    """One durable sample append and its optional terminal transition."""

    record: ObservationRecord
    idempotent_replay: bool
    transition: CommittedTransition | None


@dataclass(frozen=True, slots=True)
class AssertionEvidenceReference:
    """One typed immutable evidence identifier linked to an evaluation."""

    kind: AssertionEvidenceKind
    evidence_id: str

    def __post_init__(self) -> None:
        if type(self.kind) is not AssertionEvidenceKind:
            raise TypeError("kind must be an AssertionEvidenceKind")
        _bounded_evidence_identifier(self.evidence_id)


@dataclass(frozen=True, slots=True)
class AssertionEvaluationCommand:
    """Append one evaluation and its terminal assertion edge atomically."""

    evaluation_id: str
    evaluation: AssertionEvaluation
    evidence: tuple[AssertionEvidenceReference, ...]
    terminal_transition: TransitionCommand[AssertionState]

    def __post_init__(self) -> None:
        validate_fresh_id(
            self.evaluation_id,
            expected_kind=FreshIdKind.EVALUATION,
        )
        if type(self.evaluation) is not AssertionEvaluation:
            raise TypeError("evaluation must be an AssertionEvaluation")
        if (
            type(self.evidence) is not tuple
            or not self.evidence
            or any(type(item) is not AssertionEvidenceReference for item in self.evidence)
        ):
            raise TypeError("evidence must be a nonempty tuple of AssertionEvidenceReference")
        if len({(item.kind, item.evidence_id) for item in self.evidence}) != len(self.evidence):
            raise ValueError("assertion evidence references must be unique")
        if self.evaluation.evidence_refs != tuple(item.evidence_id for item in self.evidence):
            raise ValueError("evaluation evidence_refs differ from typed evidence links")
        transition = self.terminal_transition
        if type(transition) is not TransitionCommand:
            raise TypeError("terminal_transition must be a TransitionCommand")
        evaluation = self.evaluation
        if (
            transition.run_id != evaluation.run_id
            or transition.entity_type is not EntityType.ASSERTION
            or transition.entity_id != evaluation.assertion_id
            or transition.expected_state is not AssertionState.RUNNING
            or transition.trigger_category != "assertion_evaluation"
            or transition.causal_reference
            != CausalReference(evaluation.run_id, evaluation.record_id)
            or transition.attempt_outcome is not None
            or transition.timestamp.wall_time != evaluation.recorded_at
        ):
            raise ValueError("terminal assertion transition differs from its evaluation")
        allowed_states: Mapping[AssertionResult, frozenset[AssertionState]] = {
            AssertionResult.PASS: frozenset({AssertionState.PASSED}),
            AssertionResult.FAIL: frozenset({AssertionState.FAILED}),
            AssertionResult.ERROR: frozenset(
                {
                    AssertionState.ERROR,
                    AssertionState.UNSUPPORTED,
                }
            ),
            AssertionResult.SKIPPED: frozenset({AssertionState.UNSUPPORTED}),
            AssertionResult.PENDING: frozenset[AssertionState](),
        }
        if transition.new_state not in allowed_states[evaluation.result]:
            raise ValueError("evaluation result and terminal assertion state disagree")


@dataclass(frozen=True, slots=True)
class CommittedAssertionEvaluation:
    """One durable evaluation append and its terminal lifecycle edge."""

    evaluation_id: str
    evaluation: AssertionEvaluation
    evidence: tuple[AssertionEvidenceReference, ...]
    idempotent_replay: bool
    transition: CommittedTransition


@dataclass(frozen=True, slots=True)
class _BeginObservationSeriesOperation:
    command: ObservationSeriesCommand
    crash_hook: ObservationCrashHook | None

    def execute(
        self,
        transaction: JournalTransaction,
    ) -> tuple[CommittedTransition, CommittedTransition]:
        command = self.command
        _require_current_owner(
            transaction,
            cast("TransitionCommand[LifecycleState]", command.initial_transition),
        )
        _require_current_owner(
            transaction,
            cast("TransitionCommand[LifecycleState]", command.running_transition),
        )
        existing = _load_observation_series(transaction, command.observation_id)
        if existing is None:
            _reject_conflicting_observation_scope(transaction, command)
            result = transaction.execute(
                JournalStatement(
                    """
                    INSERT INTO observer_series (
                        observation_id, run_id, scenario_id, event_id,
                        checkpoint, observer_id, state
                    ) VALUES (?, ?, ?, ?, ?, ?, 'scheduled')
                    """,
                    (
                        command.observation_id,
                        command.run_id,
                        command.scenario_id,
                        command.event_id,
                        command.checkpoint,
                        command.observer_id,
                    ),
                )
            )
            if result.rowcount != 1:
                raise ProjectionIntegrityError(
                    "observation series insertion did not affect one row"
                )
            _call_observation_crash_hook(
                self.crash_hook,
                ObservationMutationPhase.AFTER_SERIES_INSERT,
            )
        else:
            expected = (
                command.run_id,
                command.scenario_id,
                command.event_id,
                command.checkpoint,
                command.observer_id,
            )
            if existing[:5] != expected:
                raise IdempotencyConflictError(
                    "observation series identity differs from its replay"
                )
        initial = _ApplyTransitionOperation(
            cast("TransitionCommand[LifecycleState]", command.initial_transition),
            self.crash_hook,
        ).execute(transaction)
        running = _ApplyTransitionOperation(
            cast("TransitionCommand[LifecycleState]", command.running_transition),
            self.crash_hook,
        ).execute(transaction)
        return (initial, running)


@dataclass(frozen=True, slots=True)
class _AppendObservationSampleOperation:
    command: ObservationSampleCommand
    crash_hook: ObservationCrashHook | None

    def execute(self, transaction: JournalTransaction) -> CommittedObservationSample:
        command = self.command
        record = command.record
        _require_owner_epoch(
            transaction,
            run_id=record.run_id,
            owner_epoch=command.owner_epoch,
        )
        series = _load_observation_series(transaction, record.observation_id)
        if series is None:
            raise IllegalTransitionError("observation sample series does not exist")
        expected_series = (
            record.run_id,
            record.scenario_id,
            record.event_id,
            series[3],
            record.observer_id,
        )
        if series[:5] != expected_series:
            raise CrossRunReferenceError("observation sample scope differs from its series")

        existing = _load_observation_sample_identity(
            transaction,
            sample_id=record.sample_id,
            record_id=record.record_id,
        )
        if existing is not None:
            _verify_observation_sample_row(existing, record)
            transition = _apply_observation_terminal_transition(
                transaction,
                command,
                self.crash_hook,
            )
            return CommittedObservationSample(
                record=record,
                idempotent_replay=True,
                transition=transition,
            )
        if series[5] != ObservationState.RUNNING.value:
            raise IllegalTransitionError("new samples require a running observation series")
        _require_next_observation_sequence(transaction, record)
        result = transaction.execute(
            JournalStatement(
                """
                INSERT INTO observation_samples (
                    sample_id, record_id, run_id, scenario_id, observation_id,
                    sample_sequence, status, recorded_at, snapshot_id,
                    evidence_json, error_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _observation_sample_insert_values(record),
            )
        )
        if result.rowcount != 1:
            raise ProjectionIntegrityError("observation sample append did not insert one row")
        _call_observation_crash_hook(
            self.crash_hook,
            ObservationMutationPhase.AFTER_SAMPLE_INSERT,
        )
        transition = _apply_observation_terminal_transition(
            transaction,
            command,
            self.crash_hook,
        )
        return CommittedObservationSample(
            record=record,
            idempotent_replay=False,
            transition=transition,
        )


@dataclass(frozen=True, slots=True)
class _ObservationSamplesOperation:
    run_id: str
    observation_id: str

    def execute(self, transaction: JournalTransaction) -> tuple[ObservationRecord, ...]:
        _require_run_exists(transaction, self.run_id)
        result = transaction.execute(
            JournalStatement(
                """
                SELECT
                    observation_samples.record_id,
                    observation_samples.run_id,
                    observation_samples.scenario_id,
                    observation_samples.observation_id,
                    observation_samples.sample_id,
                    observer_series.observer_id,
                    observation_samples.sample_sequence,
                    observation_samples.recorded_at,
                    observation_samples.status,
                    observer_series.event_id,
                    observation_samples.snapshot_id,
                    observation_samples.evidence_json,
                    observation_samples.error_json
                FROM observation_samples
                JOIN observer_series
                  ON observer_series.run_id = observation_samples.run_id
                 AND observer_series.scenario_id = observation_samples.scenario_id
                 AND observer_series.observation_id = observation_samples.observation_id
                WHERE observation_samples.run_id = ?
                  AND observation_samples.observation_id = ?
                ORDER BY observation_samples.sample_sequence
                LIMIT ?
                """,
                (self.run_id, self.observation_id, MAX_REPLAY_TRANSITIONS + 1),
            )
        )
        if len(result.rows) > MAX_REPLAY_TRANSITIONS:
            raise ProjectionIntegrityError(
                "observation sample history exceeds the bounded replay limit"
            )
        return tuple(_observation_record_from_row(row) for row in result.rows)


@dataclass(frozen=True, slots=True)
class _AppendAssertionEvaluationOperation:
    command: AssertionEvaluationCommand
    crash_hook: TransitionCrashHook | None

    def execute(self, transaction: JournalTransaction) -> CommittedAssertionEvaluation:
        command = self.command
        transition = cast(
            "TransitionCommand[LifecycleState]",
            command.terminal_transition,
        )
        _require_current_owner(transaction, transition)
        existing = _load_assertion_evaluation_identity(
            transaction,
            evaluation_id=command.evaluation_id,
            record_id=command.evaluation.record_id,
        )
        if existing is not None:
            _verify_assertion_evaluation_row(transaction, command, existing)
            committed = _ApplyTransitionOperation(
                transition,
                self.crash_hook,
            ).execute(transaction)
            return CommittedAssertionEvaluation(
                evaluation_id=command.evaluation_id,
                evaluation=command.evaluation,
                evidence=command.evidence,
                idempotent_replay=True,
                transition=committed,
            )

        _validate_assertion_evaluation_identity(transaction, command)
        _require_next_assertion_evaluation_sequence(transaction, command)
        for reference in command.evidence:
            _require_assertion_evidence_reference(
                transaction,
                run_id=command.evaluation.run_id,
                reference=reference,
            )
        result = transaction.execute(
            JournalStatement(
                """
                INSERT INTO assertion_evaluations (
                    evaluation_id, record_id, run_id, scenario_id, assertion_id,
                    evaluation_sequence, result, recorded_at,
                    expected_json, actual_json, comparison, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _assertion_evaluation_row_values(command),
            )
        )
        if result.rowcount != 1:
            raise ProjectionIntegrityError(
                "assertion evaluation append did not insert exactly one record"
            )
        for ordinal, reference in enumerate(command.evidence):
            result = transaction.execute(
                JournalStatement(
                    """
                    INSERT INTO evidence_links (
                        evaluation_id, run_id, ordinal, evidence_kind, evidence_id
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        command.evaluation_id,
                        command.evaluation.run_id,
                        ordinal,
                        reference.kind.value,
                        reference.evidence_id,
                    ),
                )
            )
            if result.rowcount != 1:
                raise ProjectionIntegrityError(
                    "assertion evidence link append did not insert exactly one record"
                )
        committed = _ApplyTransitionOperation(
            transition,
            self.crash_hook,
        ).execute(transaction)
        return CommittedAssertionEvaluation(
            evaluation_id=command.evaluation_id,
            evaluation=command.evaluation,
            evidence=command.evidence,
            idempotent_replay=False,
            transition=committed,
        )


class AssertionRepository:
    """Atomic single-writer persistence for assertion lifecycle and evidence."""

    __slots__ = ("_crash_hook", "_service")

    def __init__(
        self,
        service: JournalService,
        *,
        crash_hook: TransitionCrashHook | None = None,
    ) -> None:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            service,
            JournalService,
        ):
            raise TypeError("service must be a JournalService")
        if crash_hook is not None and not callable(crash_hook):
            raise TypeError("crash_hook must be callable")
        self._service = service
        self._crash_hook = crash_hook

    async def transition(
        self,
        command: TransitionCommand[AssertionState],
    ) -> CommittedTransition:
        """Commit one assertion-only lifecycle edge."""
        if type(command) is not TransitionCommand:
            raise TypeError("command must be a TransitionCommand")
        if command.entity_type is not EntityType.ASSERTION:
            raise TypeError("command must be an assertion TransitionCommand")
        return await self._service.execute(
            _ApplyTransitionOperation(
                command=cast("TransitionCommand[LifecycleState]", command),
                crash_hook=self._crash_hook,
            )
        )

    async def append_evaluation(
        self,
        command: AssertionEvaluationCommand,
    ) -> CommittedAssertionEvaluation:
        """Append evaluation, typed evidence links, and terminal edge atomically."""
        if type(command) is not AssertionEvaluationCommand:
            raise TypeError("command must be an AssertionEvaluationCommand")
        return await self._service.execute(
            _AppendAssertionEvaluationOperation(command, self._crash_hook)
        )


class ObservationRepository:
    """Atomic single-writer persistence for observation series and samples."""

    __slots__ = ("_crash_hook", "_service")

    def __init__(
        self,
        service: JournalService,
        *,
        crash_hook: ObservationCrashHook | None = None,
    ) -> None:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            service,
            JournalService,
        ):
            raise TypeError("service must be a JournalService")
        if crash_hook is not None and not callable(crash_hook):
            raise TypeError("crash_hook must be callable")
        self._service = service
        self._crash_hook = crash_hook

    async def begin_series(
        self,
        command: ObservationSeriesCommand,
    ) -> tuple[CommittedTransition, CommittedTransition]:
        """Create and start one series in one transaction."""
        if type(command) is not ObservationSeriesCommand:
            raise TypeError("command must be an ObservationSeriesCommand")
        return await self._service.execute(
            _BeginObservationSeriesOperation(command, self._crash_hook)
        )

    async def append_sample(
        self,
        command: ObservationSampleCommand,
    ) -> CommittedObservationSample:
        """Append one sanitized sample and optional terminal edge atomically."""
        if type(command) is not ObservationSampleCommand:
            raise TypeError("command must be an ObservationSampleCommand")
        return await self._service.execute(
            _AppendObservationSampleOperation(command, self._crash_hook)
        )

    async def samples(
        self,
        run_id: str,
        observation_id: str,
    ) -> tuple[ObservationRecord, ...]:
        """Load one bounded append-ordered sample series."""
        validate_run_id(run_id)
        validate_planned_id(
            observation_id,
            expected_kind=PlannedIdKind.OBSERVATION,
        )
        return await self._service.execute(_ObservationSamplesOperation(run_id, observation_id))


def _bounded_evidence_identifier(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 96
        or any(
            not (character.isascii() and (character.isalnum() or character in {"_", ".", ":", "-"}))
            for character in value
        )
    ):
        raise ValueError("evidence_id must be a bounded portable identifier")
    return value


def _load_assertion_evaluation_identity(
    transaction: JournalTransaction,
    *,
    evaluation_id: str,
    record_id: str,
) -> tuple[object, ...] | None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT
                evaluation_id, record_id, run_id, scenario_id, assertion_id,
                evaluation_sequence, result, recorded_at,
                expected_json, actual_json, comparison, message
            FROM assertion_evaluations
            WHERE evaluation_id = ? OR record_id = ?
            ORDER BY evaluation_id
            """,
            (evaluation_id, record_id),
        )
    )
    if len(result.rows) > 1:
        raise IdempotencyConflictError(
            "evaluation_id and record_id name different assertion evaluations"
        )
    if not result.rows:
        return None
    row = cast("tuple[object, ...]", result.rows[0])
    if len(row) != _ASSERTION_EVALUATION_COLUMN_COUNT:
        raise ProjectionIntegrityError("assertion evaluation row has an invalid shape")
    return row


def _validate_assertion_evaluation_identity(
    transaction: JournalTransaction,
    command: AssertionEvaluationCommand,
) -> None:
    evaluation = command.evaluation
    result = transaction.execute(
        JournalStatement(
            """
            SELECT run_id, scenario_id, type, state
            FROM assertions
            WHERE assertion_id = ?
            """,
            (evaluation.assertion_id,),
        )
    )
    if not result.rows:
        raise IllegalTransitionError("assertion evaluation target does not exist")
    row = result.rows[0]
    if (
        _text(row[0], name="assertion run_id") != evaluation.run_id
        or _text(row[1], name="assertion scenario_id") != evaluation.scenario_id
    ):
        raise CrossRunReferenceError("assertion evaluation target has a different scope")
    if _text(row[2], name="assertion type") != evaluation.type:
        raise IdempotencyConflictError("assertion evaluation type differs from its projection")
    if parse_state(EntityType.ASSERTION, row[3]) is not AssertionState.RUNNING:
        raise IllegalTransitionError("new assertion evaluations require a running assertion")


def _require_next_assertion_evaluation_sequence(
    transaction: JournalTransaction,
    command: AssertionEvaluationCommand,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT COALESCE(MAX(evaluation_sequence), 0) + 1
            FROM assertion_evaluations
            WHERE run_id = ? AND assertion_id = ?
            """,
            (
                command.evaluation.run_id,
                command.evaluation.assertion_id,
            ),
        )
    )
    if len(result.rows) != 1 or len(result.rows[0]) != 1:
        raise ProjectionIntegrityError(
            "assertion evaluation sequence query returned an invalid shape"
        )
    expected = _integer(result.rows[0][0], name="assertion evaluation sequence")
    if command.evaluation.evaluation_sequence != expected:
        raise IdempotencyConflictError("assertion evaluation sequence is not the next value")


def _require_assertion_evidence_reference(
    transaction: JournalTransaction,
    *,
    run_id: str,
    reference: AssertionEvidenceReference,
) -> None:
    statements: Mapping[AssertionEvidenceKind, JournalStatement] = {
        AssertionEvidenceKind.ATTEMPT: JournalStatement(
            """
            SELECT 1 FROM attempts
            WHERE run_id = ? AND attempt_id = ?
            LIMIT 1
            """,
            (run_id, reference.evidence_id),
        ),
        AssertionEvidenceKind.OBSERVATION: JournalStatement(
            """
            SELECT 1 FROM observer_series
            WHERE run_id = ? AND observation_id = ?
            UNION ALL
            SELECT 1 FROM observation_samples
            WHERE run_id = ? AND sample_id = ?
            LIMIT 1
            """,
            (
                run_id,
                reference.evidence_id,
                run_id,
                reference.evidence_id,
            ),
        ),
        AssertionEvidenceKind.RECORD: JournalStatement(
            """
            SELECT 1 FROM attempt_records
            WHERE run_id = ? AND record_id = ?
            UNION ALL
            SELECT 1 FROM observation_samples
            WHERE run_id = ? AND record_id = ?
            UNION ALL
            SELECT 1 FROM assertion_evaluations
            WHERE run_id = ? AND record_id = ?
            LIMIT 1
            """,
            (
                run_id,
                reference.evidence_id,
                run_id,
                reference.evidence_id,
                run_id,
                reference.evidence_id,
            ),
        ),
        AssertionEvidenceKind.ARTIFACT: JournalStatement(
            """
            SELECT 1 FROM artifacts
            WHERE run_id = ? AND artifact_id = ?
            LIMIT 1
            """,
            (run_id, reference.evidence_id),
        ),
        AssertionEvidenceKind.TRANSITION: JournalStatement(
            """
            SELECT 1 FROM transitions
            WHERE run_id = ? AND transition_id = ?
            LIMIT 1
            """,
            (run_id, reference.evidence_id),
        ),
        AssertionEvidenceKind.RECOVERY_DECISION: JournalStatement(
            """
            SELECT 1 FROM recovery_decisions
            WHERE run_id = ? AND decision_id = ?
            LIMIT 1
            """,
            (run_id, reference.evidence_id),
        ),
    }
    result = transaction.execute(statements[reference.kind])
    if not result.rows:
        raise CrossRunReferenceError(
            "assertion evaluation references missing or cross-run evidence"
        )


def _assertion_evaluation_row_values(
    command: AssertionEvaluationCommand,
) -> tuple[SqlValue, ...]:
    evaluation = command.evaluation
    return (
        command.evaluation_id,
        evaluation.record_id,
        evaluation.run_id,
        evaluation.scenario_id,
        evaluation.assertion_id,
        evaluation.evaluation_sequence,
        evaluation.result.value,
        _format_utc_datetime(evaluation.recorded_at),
        _optional_canonical_json_bytes(evaluation.expected),
        _optional_canonical_json_bytes(evaluation.actual),
        evaluation.comparison,
        evaluation.message,
    )


def _optional_canonical_json_bytes(value: object) -> bytes | None:
    return None if value is None else _canonical_json_bytes(value)


def _verify_assertion_evaluation_row(
    transaction: JournalTransaction,
    command: AssertionEvaluationCommand,
    row: tuple[object, ...],
) -> None:
    if tuple(row) != _assertion_evaluation_row_values(command):
        raise IdempotencyConflictError("assertion evaluation replay differs")
    result = transaction.execute(
        JournalStatement(
            """
            SELECT evidence_kind, evidence_id
            FROM evidence_links
            WHERE run_id = ? AND evaluation_id = ?
            ORDER BY ordinal
            """,
            (
                command.evaluation.run_id,
                command.evaluation_id,
            ),
        )
    )
    expected = tuple(
        (reference.kind.value, reference.evidence_id) for reference in command.evidence
    )
    if tuple(result.rows) != expected:
        raise IdempotencyConflictError("assertion evidence-link replay differs")


def _load_observation_series(
    transaction: JournalTransaction,
    observation_id: str,
) -> tuple[object, ...] | None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT run_id, scenario_id, event_id, checkpoint, observer_id, state
            FROM observer_series
            WHERE observation_id = ?
            """,
            (observation_id,),
        )
    )
    if not result.rows:
        return None
    row = cast("tuple[object, ...]", result.rows[0])
    if len(row) != _OBSERVATION_SERIES_COLUMN_COUNT:
        raise ProjectionIntegrityError("observation series row has an invalid shape")
    return row


def _reject_conflicting_observation_scope(
    transaction: JournalTransaction,
    command: ObservationSeriesCommand,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT observation_id
            FROM observer_series
            WHERE run_id = ? AND scenario_id = ?
              AND checkpoint = ? AND observer_id = ?
              AND (
                    (event_id IS NULL AND ? IS NULL)
                    OR event_id = ?
              )
            LIMIT 1
            """,
            (
                command.run_id,
                command.scenario_id,
                command.checkpoint,
                command.observer_id,
                command.event_id,
                command.event_id,
            ),
        )
    )
    if result.rows:
        raise IdempotencyConflictError(
            "observation scope already belongs to a different observation_id"
        )


def _require_owner_epoch(
    transaction: JournalTransaction,
    *,
    run_id: str,
    owner_epoch: int,
) -> None:
    result = transaction.execute(
        JournalStatement(
            "SELECT owner_epoch FROM runs WHERE run_id = ?",
            (run_id,),
        )
    )
    if not result.rows:
        raise CrossRunReferenceError("observation run does not exist")
    current = _integer(result.rows[0][0], name="run owner_epoch")
    if current != owner_epoch:
        raise StaleOwnerEpochError("observation owner epoch is stale")


def _load_observation_sample_identity(
    transaction: JournalTransaction,
    *,
    sample_id: str,
    record_id: str,
) -> tuple[object, ...] | None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT
                observation_samples.record_id,
                observation_samples.run_id,
                observation_samples.scenario_id,
                observation_samples.observation_id,
                observation_samples.sample_id,
                observer_series.observer_id,
                observation_samples.sample_sequence,
                observation_samples.recorded_at,
                observation_samples.status,
                observer_series.event_id,
                observation_samples.snapshot_id,
                observation_samples.evidence_json,
                observation_samples.error_json
            FROM observation_samples
            JOIN observer_series
              ON observer_series.run_id = observation_samples.run_id
             AND observer_series.scenario_id = observation_samples.scenario_id
             AND observer_series.observation_id = observation_samples.observation_id
            WHERE observation_samples.sample_id = ?
               OR observation_samples.record_id = ?
            """,
            (sample_id, record_id),
        )
    )
    if len(result.rows) > 1:
        raise IdempotencyConflictError("sample_id and record_id name different samples")
    if not result.rows:
        return None
    row = cast("tuple[object, ...]", result.rows[0])
    if len(row) != _OBSERVATION_SAMPLE_COLUMN_COUNT:
        raise ProjectionIntegrityError("observation sample row has an invalid shape")
    return row


def _verify_observation_sample_row(
    row: tuple[object, ...],
    record: ObservationRecord,
) -> None:
    if row != _observation_sample_row_values(record):
        raise IdempotencyConflictError("observation sample replay differs from durable evidence")


def _require_next_observation_sequence(
    transaction: JournalTransaction,
    record: ObservationRecord,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT COALESCE(MAX(sample_sequence), 0) + 1
            FROM observation_samples
            WHERE run_id = ? AND observation_id = ?
            """,
            (record.run_id, record.observation_id),
        )
    )
    expected = _integer(result.rows[0][0], name="observation sample sequence")
    if record.sample_sequence != expected:
        raise IdempotencyConflictError("observation sample sequence is not the next value")


def _apply_observation_terminal_transition(
    transaction: JournalTransaction,
    command: ObservationSampleCommand,
    crash_hook: ObservationCrashHook | None,
) -> CommittedTransition | None:
    transition = command.terminal_transition
    if transition is None:
        return None
    return _ApplyTransitionOperation(
        cast("TransitionCommand[LifecycleState]", transition),
        crash_hook,
    ).execute(transaction)


def _observation_sample_insert_values(
    record: ObservationRecord,
) -> tuple[SqlValue, ...]:
    row = _observation_sample_row_values(record)
    return (
        cast("str", row[4]),
        cast("str", row[0]),
        cast("str", row[1]),
        cast("str", row[2]),
        cast("str", row[3]),
        cast("int", row[6]),
        cast("str", row[8]),
        cast("str", row[7]),
        cast("str | None", row[10]),
        cast("bytes", row[11]),
        cast("bytes | None", row[12]),
    )


def _observation_sample_row_values(
    record: ObservationRecord,
) -> tuple[object, ...]:
    evidence_json = _canonical_json_bytes([item.wire_dict() for item in record.evidence])
    error_json = None if record.error is None else _canonical_json_bytes(record.error.wire_dict())
    return (
        record.record_id,
        record.run_id,
        record.scenario_id,
        record.observation_id,
        record.sample_id,
        record.observer_id,
        record.sample_sequence,
        record.recorded_at,
        record.status.value,
        record.event_id,
        record.snapshot_id,
        evidence_json,
        error_json,
    )


def _observation_record_from_row(row: Sequence[object]) -> ObservationRecord:
    if len(row) != _OBSERVATION_SAMPLE_COLUMN_COUNT:
        raise ProjectionIntegrityError("observation sample row has an invalid shape")
    evidence_raw = _json_blob(row[11], name="observation evidence", allow_null=False)
    error_raw = _json_blob(row[12], name="observation error", allow_null=True)
    if not isinstance(evidence_raw, list):
        raise ProjectionIntegrityError("observation evidence is not an array")
    try:
        evidence_items = cast("list[object]", evidence_raw)
        evidence = tuple(ObserverEvidence.model_validate(item) for item in evidence_items)
        error = None if error_raw is None else ObservationRecordError.model_validate(error_raw)
        return ObservationRecord(
            schema_version="1.0",
            record_id=_text(row[0], name="observation record_id"),
            run_id=_text(row[1], name="observation run_id"),
            scenario_id=_text(row[2], name="observation scenario_id"),
            observation_id=_text(row[3], name="observation_id"),
            sample_id=_text(row[4], name="sample_id"),
            observer_id=_text(row[5], name="observer_id"),
            sample_sequence=_integer(row[6], name="sample sequence"),
            recorded_at=_text(row[7], name="observation recorded_at"),
            status=ObservationStatus(_text(row[8], name="observation status")),
            event_id=_optional_text(row[9], name="observation event_id"),
            snapshot_id=_optional_text(row[10], name="observation snapshot_id"),
            evidence=evidence,
            error=error,
        )
    except (TypeError, ValueError) as error:
        raise ProjectionIntegrityError(
            "observation sample contains invalid persisted evidence"
        ) from error


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError("observation evidence is not canonical JSON") from error


def _json_blob(
    value: object,
    *,
    name: str,
    allow_null: bool,
) -> object:
    if value is None:
        if allow_null:
            return None
        message = f"{name} is missing"
        raise ProjectionIntegrityError(message)
    if not isinstance(value, bytes):
        message = f"{name} is not a BLOB"
        raise ProjectionIntegrityError(message)
    try:
        return json.loads(
            value.decode("ascii"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        message = f"{name} is malformed"
        raise ProjectionIntegrityError(message) from error


def _bounded_control_free_text(value: object, *, name: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        message = f"{name} must be bounded control-free text"
        raise ValueError(message)
    return value


def _load_attempt_schedule(
    transaction: JournalTransaction,
    schedule_entry_id: str,
) -> tuple[object, ...] | None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT run_id, scenario_id, entity_type, entity_id,
                   scenario_ordinal, step_ordinal, delivery_ordinal,
                   attempt_ordinal, condition_json, logical_time_ns,
                   consumed_at, consumed_by_owner_epoch
            FROM schedule_entries
            WHERE schedule_entry_id = ?
            """,
            (schedule_entry_id,),
        )
    )
    return None if not result.rows else cast("tuple[object, ...]", result.rows[0])


def _validate_attempt_schedule_claim(
    transaction: JournalTransaction,
    claim: AttemptScheduleClaim,
    schedule: tuple[object, ...],
) -> None:
    command = claim.claim_transition
    run_id = _text(schedule[0], name="schedule run_id")
    scenario_id = _text(schedule[1], name="schedule scenario_id")
    entity_type = _text(schedule[2], name="schedule entity_type")
    attempt_plan_id = _text(schedule[3], name="schedule entity_id")
    scenario_ordinal = _integer(schedule[4], name="schedule scenario ordinal")
    step_ordinal = _integer(schedule[5], name="schedule step ordinal")
    delivery_ordinal = _integer(schedule[6], name="schedule delivery ordinal")
    attempt_ordinal = _integer(schedule[7], name="schedule attempt ordinal")
    condition = schedule[8]
    logical_time_ns = _integer(schedule[9], name="schedule logical time")
    if run_id != command.run_id:
        raise CrossRunReferenceError("attempt schedule is outside the claim scope")
    if (
        entity_type != "attempt"
        or attempt_plan_id != claim.attempt_plan_id
        or command.logical_time_ns != logical_time_ns
        or condition != claim.condition_json
    ):
        raise IdempotencyConflictError("attempt schedule semantics differ from claim")
    validate_planned_id(attempt_plan_id, expected_kind=PlannedIdKind.ATTEMPT_PLAN)
    result = transaction.execute(
        JournalStatement(
            """
            SELECT deliveries.scenario_id, deliveries.event_id,
                   scenarios.ordinal, deliveries.step_ordinal, deliveries.ordinal
            FROM deliveries
            JOIN scenarios
              ON scenarios.run_id = deliveries.run_id
             AND scenarios.scenario_id = deliveries.scenario_id
            WHERE deliveries.run_id = ? AND deliveries.delivery_id = ?
            """,
            (run_id, claim.delivery_id),
        )
    )
    if not result.rows:
        raise IllegalTransitionError("attempt schedule delivery does not exist")
    row = result.rows[0]
    if (
        _text(row[0], name="delivery scenario_id") != scenario_id
        or _text(row[1], name="delivery event_id") != claim.event_id
        or _integer(row[2], name="scenario ordinal") != scenario_ordinal
        or _integer(row[3], name="step ordinal") != step_ordinal
        or _integer(row[4], name="delivery ordinal") != delivery_ordinal
    ):
        raise IllegalTransitionError("attempt schedule ordering or delivery identity differs")
    if claim.predecessor_attempt_id is None:
        if condition is not None or attempt_ordinal != 1:
            raise IllegalTransitionError("only an initial attempt schedule may omit predecessor")
        return
    if condition is None or attempt_ordinal < 1:
        raise IllegalTransitionError("retry schedule requires condition and next ordinal")
    if claim.predecessor_attempt_id == claim.attempt_id:
        raise IllegalTransitionError("physical retry attempt must be distinct")
    _validate_retry_condition(
        cast("bytes", condition),
        predecessor_attempt_id=claim.predecessor_attempt_id,
        next_attempt_ordinal=attempt_ordinal,
    )
    predecessor = transaction.execute(
        JournalStatement(
            """
            SELECT run_id, scenario_id, event_id, delivery_id, ordinal, state,
                   outcome_category, terminal_recorded_at
            FROM attempts WHERE attempt_id = ?
            """,
            (claim.predecessor_attempt_id,),
        )
    )
    if not predecessor.rows:
        raise IllegalTransitionError("retry predecessor does not exist")
    prior = predecessor.rows[0]
    if (
        _text(prior[0], name="predecessor run_id") != run_id
        or _text(prior[1], name="predecessor scenario_id") != scenario_id
        or _text(prior[2], name="predecessor event_id") != claim.event_id
        or _text(prior[3], name="predecessor delivery_id") != claim.delivery_id
        or _integer(prior[4], name="predecessor ordinal") + 1 != attempt_ordinal
        or _text(prior[5], name="predecessor state")
        not in {state.value for state in _RETRY_PREDECESSOR_STATES}
        or prior[6] is None
        or prior[7] is None
    ):
        raise IllegalTransitionError("retry predecessor identity or terminal outcome differs")


def _validate_retry_condition(
    value: bytes,
    *,
    predecessor_attempt_id: str,
    next_attempt_ordinal: int,
) -> None:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate retry condition key")
            result[key] = item
        return result

    try:
        decoded = value.decode("ascii")
        parsed = json.loads(
            decoded,
            object_pairs_hook=unique_pairs,
            parse_int=lambda raw: (
                int(raw)
                if -MAX_SAFE_INTEGER <= int(raw) <= MAX_SAFE_INTEGER
                else (_ for _ in ()).throw(ValueError())
            ),
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (RecursionError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise IllegalTransitionError("retry condition must be canonical JSON") from None
    condition = cast("dict[str, object]", parsed) if isinstance(parsed, dict) else None
    if condition is not None:
        pending: list[tuple[object, int]] = [(condition, 1)]
        nodes = 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if depth > 64 or nodes > 10_000:
                raise IllegalTransitionError("retry condition exceeds structural bounds")
            if isinstance(item, dict):
                mapping = cast("dict[object, object]", item)
                pending.extend((child, depth + 1) for child in mapping.values())
            elif isinstance(item, list):
                sequence = cast("list[object]", item)
                pending.extend((child, depth + 1) for child in sequence)
    if (
        condition is None
        or condition.get("predecessor_attempt_id") != predecessor_attempt_id
        or condition.get("next_attempt_ordinal") != next_attempt_ordinal
        or json.dumps(
            condition,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        != value
    ):
        raise IllegalTransitionError("retry condition identity differs from claim")


def _insert_claimed_attempt(
    transaction: JournalTransaction,
    claim: AttemptScheduleClaim,
    schedule: tuple[object, ...],
) -> None:
    command = claim.claim_transition
    result = transaction.execute(
        JournalStatement(
            """
            INSERT INTO attempts (
                attempt_id, run_id, scenario_id, event_id, delivery_id,
                attempt_plan_id, ordinal, state, predecessor_attempt_id, owner_epoch
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'scheduled', ?, ?)
            """,
            (
                claim.attempt_id,
                command.run_id,
                _text(schedule[1], name="schedule scenario_id"),
                claim.event_id,
                claim.delivery_id,
                _text(schedule[3], name="schedule attempt_plan_id"),
                _integer(schedule[7], name="schedule attempt ordinal"),
                claim.predecessor_attempt_id,
                command.owner_epoch,
            ),
        )
    )
    if result.rowcount != 1:
        raise ProjectionIntegrityError("physical attempt insertion did not affect one row")


def _verify_claimed_attempt(
    transaction: JournalTransaction,
    claim: AttemptScheduleClaim,
    schedule: tuple[object, ...],
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT run_id, scenario_id, event_id, delivery_id, attempt_plan_id,
                   ordinal, predecessor_attempt_id, owner_epoch
            FROM attempts WHERE attempt_id = ?
            """,
            (claim.attempt_id,),
        )
    )
    expected = (
        claim.claim_transition.run_id,
        schedule[1],
        claim.event_id,
        claim.delivery_id,
        schedule[3],
        schedule[7],
        claim.predecessor_attempt_id,
        claim.claim_transition.owner_epoch,
    )
    if not result.rows or tuple(result.rows[0]) != expected:
        raise IdempotencyConflictError("consumed schedule attempt differs from replay")


_PHASE_EDGES: Mapping[
    AttemptPhaseEvidence,
    frozenset[tuple[AttemptState, AttemptState]],
] = MappingProxyType(
    {
        AttemptPhaseEvidence.CONTROLLED_PRE_TRANSPORT: frozenset(
            {
                (AttemptState.CLAIMED, AttemptState.PRE_SEND_COMMITTED),
                (AttemptState.CLAIMED, AttemptState.NOT_SENT),
                (AttemptState.PRE_SEND_COMMITTED, AttemptState.NOT_SENT),
            }
        ),
        AttemptPhaseEvidence.NO_CONNECTION_ESTABLISHED: frozenset(
            {(AttemptState.CONNECTING, AttemptState.NOT_SENT)}
        ),
        AttemptPhaseEvidence.CONNECTION_ATTEMPT_STARTED: frozenset(
            {
                (AttemptState.PRE_SEND_COMMITTED, AttemptState.CONNECTING),
                (AttemptState.CONNECTING, AttemptState.UNKNOWN_OUTCOME),
            }
        ),
        AttemptPhaseEvidence.REQUEST_SEND_STARTED: frozenset(
            {
                (AttemptState.CONNECTING, AttemptState.SENDING),
                (AttemptState.SENDING, AttemptState.UNKNOWN_OUTCOME),
            }
        ),
        AttemptPhaseEvidence.AWAITING_RESPONSE: frozenset(
            {
                (AttemptState.SENDING, AttemptState.AWAITING_RESPONSE),
                (AttemptState.AWAITING_RESPONSE, AttemptState.UNKNOWN_OUTCOME),
            }
        ),
        AttemptPhaseEvidence.RESPONSE_OBSERVED: frozenset(
            {
                (AttemptState.AWAITING_RESPONSE, AttemptState.RESPONSE_OBSERVED),
                (AttemptState.RESPONSE_OBSERVED, AttemptState.SUCCEEDED),
                (AttemptState.RESPONSE_OBSERVED, AttemptState.REJECTED),
                (AttemptState.RESPONSE_OBSERVED, AttemptState.TRANSPORT_FAILED),
            }
        ),
    }
)


def _validate_phase_edge(
    command: TransitionCommand[LifecycleState],
    evidence: AttemptPhaseEvidenceCommand,
) -> None:
    if (
        not isinstance(command.expected_state, AttemptState)
        or not isinstance(command.new_state, AttemptState)
        or (command.expected_state, command.new_state) not in _PHASE_EDGES[evidence.phase]
    ):
        raise IllegalTransitionError("phase evidence is incompatible with attempt edge")
    if (
        command.expected_state is AttemptState.CLAIMED
        and command.new_state is AttemptState.PRE_SEND_COMMITTED
        and (evidence.request_blob_hash is None or evidence.request_headers_hash is None)
    ):
        raise IllegalTransitionError("pre-send commit requires both request digests")


def _persist_attempt_phase_evidence(
    transaction: JournalTransaction,
    *,
    command: TransitionCommand[LifecycleState],
    evidence: AttemptPhaseEvidenceCommand,
) -> None:
    _validate_phase_edge(command, evidence)
    result = transaction.execute(
        JournalStatement(
            """
            UPDATE attempts
            SET phase = ?,
                request_blob_hash = COALESCE(?, request_blob_hash),
                request_headers_hash = COALESCE(?, request_headers_hash)
            WHERE attempt_id = ? AND run_id = ? AND state = ?
              AND (
                phase IS NULL OR phase IN (
                    'controlled_pre_transport', 'no_connection_established',
                    'connection_attempt_started', 'request_send_started',
                    'awaiting_response', 'response_observed'
                )
              )
              AND (request_blob_hash IS NULL OR request_blob_hash = ? OR ? IS NULL)
              AND (request_headers_hash IS NULL OR request_headers_hash = ? OR ? IS NULL)
            """,
            (
                evidence.phase.value,
                evidence.request_blob_hash,
                evidence.request_headers_hash,
                command.entity_id,
                command.run_id,
                command.new_state.value,
                evidence.request_blob_hash,
                evidence.request_blob_hash,
                evidence.request_headers_hash,
                evidence.request_headers_hash,
            ),
        )
    )
    if result.rowcount != 1:
        raise IdempotencyConflictError("attempt phase evidence conflicts with durable evidence")


def _verify_attempt_phase_evidence(
    transaction: JournalTransaction,
    *,
    command: TransitionCommand[LifecycleState],
    evidence: AttemptPhaseEvidenceCommand,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT state, phase, request_blob_hash, request_headers_hash
            FROM attempts WHERE attempt_id = ? AND run_id = ?
            """,
            (command.entity_id, command.run_id),
        )
    )
    if not result.rows:
        raise IdempotencyConflictError("attempt phase evidence replay differs")
    row = result.rows[0]
    _validate_phase_edge(command, evidence)
    if (
        (row[0] == command.new_state.value and row[1] != evidence.phase.value)
        or (evidence.request_blob_hash is not None and row[2] != evidence.request_blob_hash)
        or (evidence.request_headers_hash is not None and row[3] != evidence.request_headers_hash)
    ):
        raise IdempotencyConflictError("attempt phase evidence replay differs")


def _require_current_owner(
    transaction: JournalTransaction,
    command: TransitionCommand[LifecycleState],
) -> None:
    result = transaction.execute(
        JournalStatement(
            "SELECT owner_epoch FROM runs WHERE run_id = ?",
            (command.run_id,),
        )
    )
    if not result.rows:
        message = "transition run does not exist in this journal"
        raise CrossRunReferenceError(message)
    current_epoch = _integer(result.rows[0][0], name="run owner_epoch")
    if current_epoch != command.owner_epoch:
        message = "transition owner epoch is stale"
        raise StaleOwnerEpochError(message)
    cause = command.causal_reference
    if cause is not None and cause.run_id != command.run_id:
        message = "transition cause belongs to a different run"
        raise CrossRunReferenceError(message)


def _require_run_exists(transaction: JournalTransaction, run_id: str) -> None:
    result = transaction.execute(JournalStatement("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)))
    if not result.rows:
        message = "run does not exist in this journal"
        raise CrossRunReferenceError(message)


def _load_entity_projection(
    transaction: JournalTransaction,
    entity_type: EntityType,
    entity_id: str,
) -> _EntityProjection | None:
    if entity_type is EntityType.ATTEMPT:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT
                    attempts.run_id,
                    attempts.state,
                    attempts.scenario_id,
                    attempts.delivery_id,
                    attempts.outcome_category,
                    attempts.terminal_recorded_at,
                    attempts.ordinal,
                    scenarios.ordinal,
                    deliveries.step_ordinal,
                    deliveries.ordinal
                FROM attempts
                JOIN scenarios
                    ON scenarios.run_id = attempts.run_id
                    AND scenarios.scenario_id = attempts.scenario_id
                JOIN deliveries
                    ON deliveries.run_id = attempts.run_id
                    AND deliveries.scenario_id = attempts.scenario_id
                    AND deliveries.event_id = attempts.event_id
                    AND deliveries.delivery_id = attempts.delivery_id
                WHERE attempts.attempt_id = ?
                """,
                (entity_id,),
            )
        )
    elif entity_type is EntityType.DELIVERY:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT run_id, state, scenario_id, NULL, NULL, NULL,
                       NULL, NULL, step_ordinal, ordinal
                FROM deliveries
                WHERE delivery_id = ?
                """,
                (entity_id,),
            )
        )
    elif entity_type in {
        EntityType.SCENARIO,
        EntityType.OBSERVATION,
        EntityType.ASSERTION,
    }:
        table = _PROJECTION_TABLES[entity_type]
        scenario_expression = (
            "scenario_id" if entity_type is not EntityType.SCENARIO else table.identifier_column
        )
        result = transaction.execute(
            JournalStatement(
                f"""
                SELECT run_id, state, {scenario_expression}, NULL, NULL, NULL,
                       NULL, NULL, NULL, NULL
                FROM {table.table}
                WHERE {table.identifier_column} = ?
                """,
                (entity_id,),
            )
        )
    else:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT run_id, state, NULL, NULL, NULL, NULL,
                       NULL, NULL, NULL, NULL
                FROM runs
                WHERE run_id = ?
                """,
                (entity_id,),
            )
        )
    if not result.rows:
        return None
    row = result.rows[0]
    if len(row) != _ENTITY_PROJECTION_COLUMN_COUNT:
        message = "projection query returned an invalid shape"
        raise ProjectionIntegrityError(message)
    return _EntityProjection(
        run_id=_text(row[0], name="projection run_id"),
        state=parse_state(entity_type, row[1]),
        scenario_id=_optional_text(row[2], name="projection scenario_id"),
        delivery_id=_optional_text(row[3], name="projection delivery_id"),
        outcome_category=_optional_text(row[4], name="attempt outcome_category"),
        terminal_recorded_at=_optional_text(
            row[5],
            name="attempt terminal_recorded_at",
        ),
        attempt_ordinal=_optional_integer(row[6], name="attempt ordinal"),
        scenario_ordinal=_optional_integer(row[7], name="scenario ordinal"),
        step_ordinal=_optional_integer(row[8], name="step ordinal"),
        delivery_ordinal=_optional_integer(row[9], name="delivery ordinal"),
    )


def _validate_projection_and_edge(
    transaction: JournalTransaction,
    command: TransitionCommand[LifecycleState],
    projection: _EntityProjection,
) -> None:
    if command.expected_state is None:
        machine = state_machine(command.entity_type)
        if (
            command.new_state.value != machine.initial_state
            or projection.state != command.new_state
        ):
            message = "initial transition does not match the existing initial projection"
            raise IllegalTransitionError(message)
        prior = transaction.execute(
            JournalStatement(
                """
                SELECT 1
                FROM transitions
                WHERE run_id = ? AND entity_type = ? AND entity_id = ?
                LIMIT 1
                """,
                (
                    command.run_id,
                    command.entity_type.value,
                    command.entity_id,
                ),
            )
        )
        if prior.rows:
            message = "initial transition history already exists for this entity"
            raise IllegalTransitionError(message)
        return
    if projection.state != command.expected_state:
        message = "transition expected prior state differs from the projection"
        raise IllegalTransitionError(message)
    if not transition_allowed(
        command.entity_type,
        command.expected_state,
        command.new_state,
    ):
        message = "transition edge is absent from the authoritative state table"
        raise IllegalTransitionError(message)


def _validate_transition_guards(
    transaction: JournalTransaction,
    command: TransitionCommand[LifecycleState],
    projection: _EntityProjection,
) -> None:
    if (
        command.entity_type is EntityType.RUN
        and command.expected_state is RunState.RUNNING
        and command.new_state is RunState.COMPLETED
    ):
        _guard_run_completion(transaction, command.run_id)
    if command.entity_type is EntityType.SCENARIO and command.new_state is ScenarioState.PASSED:
        _guard_scenario_pass(transaction, command.run_id, command.entity_id)
    if command.entity_type is EntityType.DELIVERY:
        if command.new_state is DeliveryState.SATISFIED:
            _guard_delivery_satisfaction(transaction, command, projection)
        elif (
            command.expected_state is DeliveryState.ACTIVE
            and command.new_state is DeliveryState.ELIGIBLE
        ):
            _guard_retry_predecessor(transaction, command, projection)
    if (
        command.entity_type is EntityType.ATTEMPT
        and isinstance(command.new_state, AttemptState)
        and command.new_state in _TERMINAL_ATTEMPT_STATES
    ):
        _guard_terminal_attempt(command, projection)


def _validate_payload_scope(command: TransitionCommand[LifecycleState]) -> None:
    cause = command.causal_reference
    if cause is not None and cause.run_id != command.run_id:
        message = "transition cause belongs to a different run"
        raise CrossRunReferenceError(message)
    is_delivery_satisfaction = (
        command.entity_type is EntityType.DELIVERY and command.new_state is DeliveryState.SATISFIED
    )
    if is_delivery_satisfaction != (command.delivery_satisfaction is not None):
        message = "delivery satisfaction evidence is required only for satisfied entry"
        raise IllegalTransitionError(message)
    if command.delivery_satisfaction is not None:
        evidence = command.delivery_satisfaction
        if command.causal_reference != evidence.cause:
            message = "delivery satisfaction evidence must equal the transition cause"
            raise IllegalTransitionError(message)
        expected_trigger = (
            TRIGGER_ATTEMPT_OUTCOME
            if evidence.kind is DeliverySatisfactionKind.ATTEMPT
            else TRIGGER_ASSERTION_POLICY
        )
        if command.trigger_category != expected_trigger:
            message = "delivery satisfaction kind and trigger category disagree"
            raise IllegalTransitionError(message)
    is_terminal_attempt = (
        command.entity_type is EntityType.ATTEMPT
        and isinstance(command.new_state, AttemptState)
        and command.new_state in _TERMINAL_ATTEMPT_STATES
    )
    if is_terminal_attempt != (command.attempt_outcome is not None):
        message = "terminal attempt transitions require exact outcome projection fields"
        raise IllegalTransitionError(message)
    if (
        command.attempt_outcome is not None
        and command.attempt_outcome.retry_schedule is not None
        and command.attempt_outcome.retry_schedule.predecessor_attempt_id != command.entity_id
    ):
        message = "derived retry schedule predecessor must equal the terminal attempt"
        raise IllegalTransitionError(message)


def _validate_transport_evidence_presence(
    command: TransitionCommand[LifecycleState],
    evidence: AttemptTransportEvidenceCommand | None,
) -> None:
    is_terminal_attempt = (
        command.entity_type is EntityType.ATTEMPT
        and isinstance(command.new_state, AttemptState)
        and command.new_state in _TERMINAL_ATTEMPT_STATES
    )
    if is_terminal_attempt != (evidence is not None):
        raise IllegalTransitionError(
            "terminal attempt transitions require exactly one sanitized transport record"
        )
    if evidence is None:
        return
    outcome = command.attempt_outcome
    terminal_state = cast("AttemptState", command.new_state)
    if outcome is None:
        raise IllegalTransitionError("terminal transport evidence requires an attempt outcome")
    if evidence.run_id != command.run_id:
        raise CrossRunReferenceError("transport evidence belongs to a different run")
    if evidence.attempt_id != command.entity_id:
        raise IllegalTransitionError("transport evidence belongs to a different attempt")
    if evidence.classification is not outcome.classification:
        raise IllegalTransitionError(
            "transport evidence classification differs from the terminal outcome"
        )
    if evidence.state not in _EVIDENCE_STATES_BY_TERMINAL_STATE[terminal_state]:
        raise IllegalTransitionError(
            "serialized evidence state is incompatible with terminal attempt state"
        )


def _validate_transport_evidence_identity(
    transaction: JournalTransaction,
    *,
    command: TransitionCommand[LifecycleState],
    evidence: AttemptTransportEvidenceCommand,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT run_id, scenario_id, event_id, delivery_id
            FROM attempts
            WHERE attempt_id = ?
            """,
            (command.entity_id,),
        )
    )
    if not result.rows:
        raise IllegalTransitionError("transport evidence attempt does not exist")
    expected = (
        evidence.run_id,
        evidence.scenario_id,
        evidence.event_id,
        evidence.delivery_id,
    )
    if tuple(result.rows[0]) != expected:
        raise CrossRunReferenceError(
            "transport evidence identity differs from the physical attempt"
        )
    existing_attempt = transaction.execute(
        JournalStatement(
            """
            SELECT record_id
            FROM attempt_records
            WHERE run_id = ? AND attempt_id = ?
            """,
            (command.run_id, command.entity_id),
        )
    )
    if existing_attempt.rows:
        raise ProjectionIntegrityError(
            "physical attempt already has a final record without this transition"
        )
    existing_record = transaction.execute(
        JournalStatement(
            "SELECT run_id, attempt_id FROM attempt_records WHERE record_id = ?",
            (evidence.record_id,),
        )
    )
    if existing_record.rows:
        raise IdempotencyConflictError(
            "transport record_id already names another final attempt record"
        )


def _guard_run_completion(
    transaction: JournalTransaction,
    run_id: str,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT delivery_id
            FROM deliveries
            WHERE run_id = ?
              AND required = 1
              AND state IN ('pending', 'eligible', 'active', 'ambiguous')
            LIMIT 1
            """,
            (run_id,),
        )
    )
    if result.rows:
        message = "run completion requires every required delivery to be terminal and unambiguous"
        raise IllegalTransitionError(message)


def _guard_scenario_pass(
    transaction: JournalTransaction,
    run_id: str,
    scenario_id: str,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT assertion_id, state, policy_json
            FROM assertions
            WHERE run_id = ? AND scenario_id = ? AND required = 1
            ORDER BY assertion_id
            """,
            (run_id, scenario_id),
        )
    )
    for row in result.rows:
        if len(row) != _ASSERTION_GUARD_COLUMN_COUNT:
            message = "required assertion projection query returned an invalid shape"
            raise ProjectionIntegrityError(message)
        state = parse_state(EntityType.ASSERTION, row[1])
        if state is AssertionState.PASSED:
            continue
        if state is AssertionState.UNSUPPORTED and _unsupported_policy_allows_skip(row[2]):
            continue
        message = "scenario pass requires every required assertion to pass or explicitly skip"
        raise IllegalTransitionError(message)


def _guard_delivery_satisfaction(
    transaction: JournalTransaction,
    command: TransitionCommand[LifecycleState],
    projection: _EntityProjection,
) -> None:
    evidence = cast("DeliverySatisfactionEvidence", command.delivery_satisfaction)
    cause = evidence.cause
    if (
        cause.run_id != command.run_id
        or command.causal_reference != cause
        or projection.scenario_id is None
    ):
        message = "delivery satisfaction evidence and transition cause must match this run"
        raise CrossRunReferenceError(message)
    if evidence.kind is DeliverySatisfactionKind.ATTEMPT:
        if command.trigger_category != TRIGGER_ATTEMPT_OUTCOME:
            message = "attempt satisfaction requires the attempt_outcome trigger"
            raise IllegalTransitionError(message)
        _require_related_attempt(
            transaction,
            cause=cause,
            scenario_id=projection.scenario_id,
            delivery_id=command.entity_id,
            allowed_states=frozenset({AttemptState.SUCCEEDED}),
        )
        return
    if command.trigger_category != TRIGGER_ASSERTION_POLICY:
        message = "assertion satisfaction requires the assertion_policy trigger"
        raise IllegalTransitionError(message)
    result = transaction.execute(
        JournalStatement(
            """
            SELECT run_id, scenario_id, state
            FROM assertions
            WHERE assertion_id = ?
            """,
            (cause.record_id,),
        )
    )
    if not result.rows:
        message = "delivery assertion-policy cause does not exist"
        raise IllegalTransitionError(message)
    row = result.rows[0]
    if (
        _text(row[0], name="assertion run_id") != command.run_id
        or _text(row[1], name="assertion scenario_id") != projection.scenario_id
    ):
        message = "delivery assertion-policy cause is outside its scenario"
        raise CrossRunReferenceError(message)
    if parse_state(EntityType.ASSERTION, row[2]) is not AssertionState.PASSED:
        message = "delivery assertion-policy cause is not passed"
        raise IllegalTransitionError(message)


def _guard_retry_predecessor(
    transaction: JournalTransaction,
    command: TransitionCommand[LifecycleState],
    projection: _EntityProjection,
) -> None:
    cause = command.causal_reference
    if (
        cause is None
        or projection.scenario_id is None
        or command.trigger_category != TRIGGER_RETRY_ELIGIBLE
    ):
        message = "retry eligibility requires an explicit predecessor outcome cause"
        raise IllegalTransitionError(message)
    _require_related_attempt(
        transaction,
        cause=cause,
        scenario_id=projection.scenario_id,
        delivery_id=command.entity_id,
        allowed_states=_RETRY_PREDECESSOR_STATES,
    )


def _require_related_attempt(
    transaction: JournalTransaction,
    *,
    cause: CausalReference,
    scenario_id: str,
    delivery_id: str,
    allowed_states: frozenset[AttemptState],
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT
                run_id,
                scenario_id,
                delivery_id,
                state,
                outcome_category,
                terminal_recorded_at
            FROM attempts
            WHERE attempt_id = ?
            """,
            (cause.record_id,),
        )
    )
    if not result.rows:
        message = "causal attempt does not exist"
        raise IllegalTransitionError(message)
    row = result.rows[0]
    if (
        _text(row[0], name="attempt run_id") != cause.run_id
        or _text(row[1], name="attempt scenario_id") != scenario_id
        or _text(row[2], name="attempt delivery_id") != delivery_id
    ):
        message = "causal attempt is outside the delivery identity"
        raise CrossRunReferenceError(message)
    state = parse_state(EntityType.ATTEMPT, row[3])
    if not isinstance(state, AttemptState) or state not in allowed_states:
        message = "causal attempt outcome does not qualify for this transition"
        raise IllegalTransitionError(message)
    outcome_value = _optional_text(row[4], name="causal attempt outcome_category")
    terminal_at = _optional_text(row[5], name="causal attempt terminal_recorded_at")
    if outcome_value is None or terminal_at is None:
        message = "causal terminal attempt is missing durable outcome evidence"
        raise ProjectionIntegrityError(message)
    try:
        classification = AttemptClassification(outcome_value)
    except ValueError as error:
        message = "causal terminal attempt has an undeclared outcome classification"
        raise ProjectionIntegrityError(message) from error
    if classification not in _CLASSIFICATIONS_BY_TERMINAL_STATE[state]:
        message = "causal terminal attempt state and outcome classification disagree"
        raise ProjectionIntegrityError(message)
    _parse_wall_time(terminal_at)


def _guard_terminal_attempt(
    command: TransitionCommand[LifecycleState],
    projection: _EntityProjection,
) -> None:
    state = cast("AttemptState", command.new_state)
    outcome = command.attempt_outcome
    if outcome is None or outcome.classification not in _CLASSIFICATIONS_BY_TERMINAL_STATE[state]:
        message = "attempt terminal classification is incompatible with its state"
        raise IllegalTransitionError(message)
    if projection.outcome_category is not None or projection.terminal_recorded_at is not None:
        message = "attempt already contains terminal outcome projection fields"
        raise ProjectionIntegrityError(message)
    _validate_retry_schedule_identity(command, projection)


def _validate_retry_schedule_identity(
    command: TransitionCommand[LifecycleState],
    projection: _EntityProjection,
) -> None:
    state = cast("AttemptState", command.new_state)
    outcome = command.attempt_outcome
    if outcome is None:
        message = "terminal attempt replay is missing its outcome"
        raise IdempotencyConflictError(message)
    schedule = outcome.retry_schedule
    if schedule is None:
        return
    if (
        state not in _ATOMIC_RETRY_STATES
        or projection.scenario_id is None
        or projection.attempt_ordinal is None
        or projection.scenario_ordinal is None
        or projection.step_ordinal is None
        or projection.delivery_ordinal is None
        or schedule.predecessor_attempt_id != command.entity_id
        or schedule.scenario_id != projection.scenario_id
        or schedule.entity_type != "attempt"
        or schedule.scenario_ordinal != projection.scenario_ordinal
        or schedule.step_ordinal != projection.step_ordinal
        or schedule.delivery_ordinal != projection.delivery_ordinal
        or schedule.attempt_ordinal != projection.attempt_ordinal + 1
    ):
        message = "derived retry schedule does not match the terminal attempt identity"
        raise IllegalTransitionError(message)
    try:
        validate_planned_id(
            schedule.entity_id,
            expected_kind=PlannedIdKind.ATTEMPT_PLAN,
        )
    except ValueError as error:
        message = "derived retry schedule must target a planned attempt template"
        raise IllegalTransitionError(message) from error


def _update_projection(
    transaction: JournalTransaction,
    command: TransitionCommand[LifecycleState],
    projection: _EntityProjection,
) -> None:
    table = _PROJECTION_TABLES[command.entity_type]
    expected_state = cast("LifecycleState", command.expected_state)
    if command.entity_type is EntityType.ATTEMPT and command.attempt_outcome is not None:
        result = transaction.execute(
            JournalStatement(
                """
                UPDATE attempts
                SET state = ?, outcome_category = ?, terminal_recorded_at = ?
                WHERE attempt_id = ? AND run_id = ? AND state = ?
                  AND outcome_category IS NULL AND terminal_recorded_at IS NULL
                """,
                (
                    command.new_state.value,
                    command.attempt_outcome.classification.value,
                    _format_wall_time(command.timestamp),
                    command.entity_id,
                    command.run_id,
                    expected_state.value,
                ),
            )
        )
    else:
        result = transaction.execute(
            JournalStatement(
                f"""
                UPDATE {table.table}
                SET state = ?
                WHERE {table.identifier_column} = ? AND run_id = ? AND state = ?
                """,
                (
                    command.new_state.value,
                    command.entity_id,
                    command.run_id,
                    expected_state.value,
                ),
            )
        )
    if result.rowcount != 1:
        message = "projection update lost its expected-state compare-and-swap"
        raise ProjectionIntegrityError(message)
    del projection


def _next_transition_sequence(
    transaction: JournalTransaction,
    run_id: str,
) -> int:
    result = transaction.execute(
        JournalStatement(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM transitions WHERE run_id = ?",
            (run_id,),
        )
    )
    sequence = _integer(result.rows[0][0], name="transition sequence")
    if not 1 <= sequence <= MAX_SAFE_INTEGER:
        message = "transition sequence exceeds the journal boundary"
        raise ProjectionIntegrityError(message)
    return sequence


def _record_from_command(
    command: TransitionCommand[LifecycleState],
    *,
    sequence: int,
) -> TransitionRecord:
    return TransitionRecord(
        transition_id=command.transition_id,
        run_id=command.run_id,
        sequence=sequence,
        entity_type=command.entity_type,
        entity_id=command.entity_id,
        from_state=command.expected_state,
        to_state=command.new_state,
        trigger_category=command.trigger_category,
        causal_record_id=(
            command.causal_reference.record_id if command.causal_reference is not None else None
        ),
        timestamp=command.timestamp,
        logical_time_ns=command.logical_time_ns,
        owner_epoch=command.owner_epoch,
        idempotency_key=command.idempotency_key,
    )


def _insert_transition(
    transaction: JournalTransaction,
    record: TransitionRecord,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            INSERT INTO transitions (
                transition_id,
                run_id,
                sequence,
                entity_type,
                entity_id,
                from_state,
                to_state,
                trigger_category,
                causal_record_id,
                wall_time,
                monotonic_elapsed_ns,
                monotonic_unavailable,
                logical_time_ns,
                owner_epoch,
                idempotency_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.transition_id,
                record.run_id,
                record.sequence,
                record.entity_type.value,
                record.entity_id,
                record.from_state.value if record.from_state is not None else None,
                record.to_state.value,
                record.trigger_category,
                record.causal_record_id,
                _format_wall_time(record.timestamp),
                record.timestamp.monotonic_elapsed_ns,
                0 if record.timestamp.is_live else 1,
                record.logical_time_ns,
                record.owner_epoch,
                record.idempotency_key,
            ),
        )
    )
    if result.rowcount != 1:
        message = "transition append did not insert exactly one record"
        raise ProjectionIntegrityError(message)


def _next_attempt_record_sequence(
    transaction: JournalTransaction,
    run_id: str,
) -> int:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT COALESCE(MAX(sequence), 0) + 1
            FROM attempt_records
            WHERE run_id = ?
            """,
            (run_id,),
        )
    )
    sequence = _integer(result.rows[0][0], name="attempt record sequence")
    if not 1 <= sequence <= MAX_SAFE_INTEGER:
        raise ProjectionIntegrityError("attempt record sequence exceeds the journal boundary")
    return sequence


def _attempt_record_from_command(
    command: TransitionCommand[LifecycleState],
    *,
    evidence: AttemptTransportEvidenceCommand,
    sequence: int,
) -> AttemptEvidence:
    return AttemptEvidence(
        record_id=evidence.record_id,
        run_id=evidence.run_id,
        scenario_id=evidence.scenario_id,
        event_id=evidence.event_id,
        delivery_id=evidence.delivery_id,
        attempt_id=evidence.attempt_id,
        sequence=sequence,
        recorded_at=command.timestamp.wall_time,
        logical_time_ns=command.logical_time_ns,
        monotonic_elapsed_ns=command.timestamp.monotonic_elapsed_ns,
        state=evidence.state,
        classification=evidence.classification,
        request=evidence.request,
        response=evidence.response,
        error=evidence.error,
    )


def _insert_attempt_record(
    transaction: JournalTransaction,
    record: AttemptEvidence,
    *,
    response_headers_elapsed_ns: int | None,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            INSERT INTO attempt_records (
                record_id,
                schema_version,
                run_id,
                scenario_id,
                event_id,
                delivery_id,
                attempt_id,
                sequence,
                recorded_at,
                logical_time_ns,
                monotonic_elapsed_ns,
                state,
                classification,
                request_method,
                request_url_redacted,
                request_body_sha256,
                request_byte_length,
                request_header_names_json,
                response_status,
                response_body_sha256,
                response_captured_bytes,
                response_truncated,
                error_category,
                error_message_redacted,
                error_phase,
                response_headers_elapsed_ns
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            _attempt_record_values(
                record,
                response_headers_elapsed_ns=response_headers_elapsed_ns,
            ),
        )
    )
    if result.rowcount != 1:
        raise ProjectionIntegrityError("attempt evidence append did not insert exactly one record")


def _attempt_record_values(
    record: AttemptEvidence,
    *,
    response_headers_elapsed_ns: int | None,
) -> tuple[SqlValue, ...]:
    request = record.request
    response = record.response
    error = record.error
    return (
        record.record_id,
        record.schema_version,
        record.run_id,
        record.scenario_id,
        record.event_id,
        record.delivery_id,
        record.attempt_id,
        record.sequence,
        _format_utc_datetime(record.recorded_at),
        record.logical_time_ns,
        record.monotonic_elapsed_ns,
        record.state.value,
        record.classification.value,
        request.method if request is not None else None,
        request.url_redacted if request is not None else None,
        request.body_sha256 if request is not None else None,
        request.byte_length if request is not None else None,
        canonical_request_header_names_json(request),
        response.status if response is not None else None,
        response.body_sha256 if response is not None else None,
        response.captured_bytes if response is not None else None,
        int(response.truncated) if response is not None else None,
        error.category if error is not None else None,
        error.message_redacted if error is not None else None,
        error.phase if error is not None else None,
        response_headers_elapsed_ns,
    )


def _insert_retry_schedule(
    transaction: JournalTransaction,
    *,
    run_id: str,
    schedule: RetrySchedule,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            INSERT INTO schedule_entries (
                schedule_entry_id,
                run_id,
                scenario_id,
                entity_type,
                entity_id,
                logical_time_ns,
                scenario_ordinal,
                step_ordinal,
                delivery_ordinal,
                attempt_ordinal,
                deterministic_tie_key,
                condition_json,
                idempotency_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                schedule.schedule_entry_id,
                run_id,
                schedule.scenario_id,
                schedule.entity_type,
                schedule.entity_id,
                schedule.logical_time_ns,
                schedule.scenario_ordinal,
                schedule.step_ordinal,
                schedule.delivery_ordinal,
                schedule.attempt_ordinal,
                schedule.deterministic_tie_key,
                schedule.condition_json,
                schedule.idempotency_key,
            ),
        )
    )
    if result.rowcount != 1:
        message = "derived retry schedule did not insert exactly one row"
        raise ProjectionIntegrityError(message)


def _transition_by_idempotency_key(
    transaction: JournalTransaction,
    run_id: str,
    idempotency_key: str,
) -> TransitionRecord | None:
    result = transaction.execute(
        JournalStatement(
            f"""
            SELECT {_TRANSITION_COLUMNS}
            FROM transitions
            WHERE run_id = ? AND idempotency_key = ?
            """,
            (run_id, idempotency_key),
        )
    )
    return _record_from_row(result.rows[0]) if result.rows else None


def _transition_id_exists(
    transaction: JournalTransaction,
    transition_id: str,
) -> bool:
    result = transaction.execute(
        JournalStatement(
            "SELECT 1 FROM transitions WHERE transition_id = ?",
            (transition_id,),
        )
    )
    return bool(result.rows)


def _verify_idempotent_replay(
    transaction: JournalTransaction,
    command: TransitionCommand[LifecycleState],
    existing: TransitionRecord,
) -> None:
    # A replay can be issued later with a freshly sampled local timestamp. The
    # first durable timestamp remains authoritative and is returned unchanged.
    expected_cause = (
        command.causal_reference.record_id if command.causal_reference is not None else None
    )
    if (
        existing.transition_id != command.transition_id
        or existing.run_id != command.run_id
        or existing.entity_type is not command.entity_type
        or existing.entity_id != command.entity_id
        or existing.from_state != command.expected_state
        or existing.to_state != command.new_state
        or existing.trigger_category != command.trigger_category
        or existing.causal_record_id != expected_cause
        or existing.logical_time_ns != command.logical_time_ns
        or existing.owner_epoch != command.owner_epoch
    ):
        message = "idempotency key was reused for different transition semantics"
        raise IdempotencyConflictError(message)
    if command.attempt_outcome is not None:
        _verify_existing_attempt_outcome(transaction, command, existing)


def _verify_existing_attempt_outcome(
    transaction: JournalTransaction,
    command: TransitionCommand[LifecycleState],
    existing: TransitionRecord,
) -> None:
    outcome = command.attempt_outcome
    if outcome is None:
        message = "idempotent terminal outcome is malformed"
        raise IdempotencyConflictError(message)
    terminal = outcome.classification
    projection = _load_entity_projection(
        transaction,
        EntityType.ATTEMPT,
        command.entity_id,
    )
    if projection is None or projection.run_id != command.run_id:
        message = "idempotent terminal attempt projection is missing"
        raise ProjectionIntegrityError(message)
    if (
        projection.state != existing.to_state
        or projection.outcome_category != terminal.value
        or projection.terminal_recorded_at != _format_wall_time(existing.timestamp)
    ):
        message = "idempotent terminal attempt projection differs from history"
        raise ProjectionIntegrityError(message)
    _validate_retry_schedule_identity(command, projection)
    schedule = outcome.retry_schedule
    if schedule is None:
        if projection.state in _ATOMIC_RETRY_STATES and _derived_next_attempt_schedule_exists(
            transaction,
            run_id=command.run_id,
            projection=projection,
        ):
            message = "idempotent terminal outcome omitted its derived retry schedule"
            raise IdempotencyConflictError(message)
        return
    _verify_existing_retry_schedule(
        transaction,
        run_id=command.run_id,
        schedule=schedule,
    )


def _verify_existing_attempt_record(
    transaction: JournalTransaction,
    *,
    command: TransitionCommand[LifecycleState],
    transition: TransitionRecord,
    evidence: AttemptTransportEvidenceCommand,
) -> None:
    result = transaction.execute(
        JournalStatement(
            f"""
            SELECT {_ATTEMPT_RECORD_COLUMNS}
            FROM attempt_records
            WHERE run_id = ? AND attempt_id = ?
            """,
            (command.run_id, command.entity_id),
        )
    )
    if len(result.rows) != 1:
        raise ProjectionIntegrityError(
            "idempotent terminal transition is missing its unique attempt record"
        )
    row = result.rows[0]
    if len(row) != _ATTEMPT_RECORD_COLUMN_COUNT:
        raise ProjectionIntegrityError("attempt record replay query returned an invalid shape")
    sequence = _integer(row[7], name="attempt record sequence")
    expected = AttemptEvidence(
        record_id=evidence.record_id,
        run_id=evidence.run_id,
        scenario_id=evidence.scenario_id,
        event_id=evidence.event_id,
        delivery_id=evidence.delivery_id,
        attempt_id=evidence.attempt_id,
        sequence=sequence,
        recorded_at=transition.timestamp.wall_time,
        logical_time_ns=transition.logical_time_ns,
        monotonic_elapsed_ns=transition.timestamp.monotonic_elapsed_ns,
        state=evidence.state,
        classification=evidence.classification,
        request=evidence.request,
        response=evidence.response,
        error=evidence.error,
    )
    if tuple(row) != _attempt_record_values(
        expected,
        response_headers_elapsed_ns=evidence.response_headers_elapsed_ns,
    ):
        raise IdempotencyConflictError("idempotent terminal transition transport evidence differs")


def _derived_next_attempt_schedule_exists(
    transaction: JournalTransaction,
    *,
    run_id: str,
    projection: _EntityProjection,
) -> bool:
    if (
        projection.scenario_id is None
        or projection.scenario_ordinal is None
        or projection.step_ordinal is None
        or projection.delivery_ordinal is None
        or projection.attempt_ordinal is None
    ):
        message = "terminal attempt projection is missing retry ordering coordinates"
        raise ProjectionIntegrityError(message)
    result = transaction.execute(
        JournalStatement(
            """
            SELECT 1
            FROM schedule_entries
            WHERE run_id = ?
              AND scenario_id = ?
              AND entity_type = 'attempt'
              AND scenario_ordinal = ?
              AND step_ordinal = ?
              AND delivery_ordinal = ?
              AND attempt_ordinal = ?
            LIMIT 1
            """,
            (
                run_id,
                projection.scenario_id,
                projection.scenario_ordinal,
                projection.step_ordinal,
                projection.delivery_ordinal,
                projection.attempt_ordinal + 1,
            ),
        )
    )
    return bool(result.rows)


def _verify_existing_retry_schedule(
    transaction: JournalTransaction,
    *,
    run_id: str,
    schedule: RetrySchedule,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT
                schedule_entry_id,
                scenario_id,
                entity_type,
                entity_id,
                logical_time_ns,
                scenario_ordinal,
                step_ordinal,
                delivery_ordinal,
                attempt_ordinal,
                deterministic_tie_key,
                condition_json
            FROM schedule_entries
            WHERE run_id = ? AND idempotency_key = ?
            """,
            (run_id, schedule.idempotency_key),
        )
    )
    expected: tuple[object, ...] = (
        schedule.schedule_entry_id,
        schedule.scenario_id,
        schedule.entity_type,
        schedule.entity_id,
        schedule.logical_time_ns,
        schedule.scenario_ordinal,
        schedule.step_ordinal,
        schedule.delivery_ordinal,
        schedule.attempt_ordinal,
        schedule.deterministic_tie_key,
        schedule.condition_json,
    )
    if not result.rows or tuple(result.rows[0]) != expected:
        message = "idempotent terminal outcome retry schedule is missing or different"
        raise ProjectionIntegrityError(message)


_ATTEMPT_RECORD_COLUMNS = """
    record_id,
    schema_version,
    run_id,
    scenario_id,
    event_id,
    delivery_id,
    attempt_id,
    sequence,
    recorded_at,
    logical_time_ns,
    monotonic_elapsed_ns,
    state,
    classification,
    request_method,
    request_url_redacted,
    request_body_sha256,
    request_byte_length,
    request_header_names_json,
    response_status,
    response_body_sha256,
    response_captured_bytes,
    response_truncated,
    error_category,
    error_message_redacted,
    error_phase,
    response_headers_elapsed_ns
"""


def _persisted_attempt_evidence_from_row(
    row: Sequence[object],
) -> PersistedAttemptEvidence:
    if len(row) != _ATTEMPT_RECORD_COLUMN_COUNT:
        raise ProjectionIntegrityError("attempt evidence row has an invalid shape")
    request: RequestMetadata | None = None
    if row[13] is not None:
        header_values = _json_blob(
            row[17],
            name="attempt request header names",
            allow_null=False,
        )
        if not isinstance(header_values, list):
            raise ProjectionIntegrityError("attempt request header names are invalid")
        header_items = cast("list[object]", header_values)
        if any(type(item) is not str for item in header_items):
            raise ProjectionIntegrityError("attempt request header names are invalid")
        method = _text(row[13], name="attempt request method")
        if method != "POST":
            raise ProjectionIntegrityError("attempt request method is invalid")
        request = RequestMetadata(
            method="POST",
            url_redacted=_text(row[14], name="attempt request URL"),
            body_sha256=_text(row[15], name="attempt request body digest"),
            byte_length=_integer(row[16], name="attempt request byte length"),
            header_names=tuple(cast("list[str]", header_items)),
        )
    response: ResponseMetadata | None = None
    if row[18] is not None:
        truncated = _integer(row[21], name="attempt response truncated")
        if truncated not in {0, 1}:
            raise ProjectionIntegrityError("attempt response truncated flag is invalid")
        response = ResponseMetadata(
            status=_integer(row[18], name="attempt response status"),
            body_sha256=_optional_text(
                row[19],
                name="attempt response body digest",
            ),
            captured_bytes=_integer(
                row[20],
                name="attempt response captured bytes",
            ),
            truncated=bool(truncated),
        )
    error: TransportError | None = None
    if row[22] is not None:
        error = TransportError(
            category=_text(row[22], name="attempt error category"),
            message_redacted=_text(
                row[23],
                name="attempt redacted error message",
            ),
            phase=_optional_text(row[24], name="attempt error phase"),
        )
    schema_version = _text(row[1], name="attempt schema version")
    if schema_version != "1.0":
        raise ProjectionIntegrityError("attempt schema version is unsupported")
    try:
        attempt = AttemptEvidence(
            schema_version="1.0",
            record_id=_text(row[0], name="attempt record_id"),
            run_id=_text(row[2], name="attempt run_id"),
            scenario_id=_text(row[3], name="attempt scenario_id"),
            event_id=_text(row[4], name="attempt event_id"),
            delivery_id=_text(row[5], name="attempt delivery_id"),
            attempt_id=_text(row[6], name="attempt_id"),
            sequence=_integer(row[7], name="attempt sequence"),
            recorded_at=_parse_wall_time(_text(row[8], name="attempt recorded_at")),
            logical_time_ns=_optional_integer(
                row[9],
                name="attempt logical_time_ns",
            ),
            monotonic_elapsed_ns=_optional_integer(
                row[10],
                name="attempt monotonic_elapsed_ns",
            ),
            state=AttemptEvidenceState(_text(row[11], name="attempt evidence state")),
            classification=AttemptClassification(_text(row[12], name="attempt classification")),
            request=request,
            response=response,
            error=error,
        )
        return PersistedAttemptEvidence(
            attempt=attempt,
            response_headers_elapsed_ns=_optional_integer(
                row[25],
                name="response_headers_elapsed_ns",
            ),
        )
    except (TypeError, ValueError) as caught:
        raise ProjectionIntegrityError(
            "attempt record contains invalid persisted evidence"
        ) from caught


_TRANSITION_COLUMNS = """
    transition_id,
    run_id,
    sequence,
    entity_type,
    entity_id,
    from_state,
    to_state,
    trigger_category,
    causal_record_id,
    wall_time,
    monotonic_elapsed_ns,
    monotonic_unavailable,
    logical_time_ns,
    owner_epoch,
    idempotency_key
"""


def _load_transition_history(
    transaction: JournalTransaction,
    *,
    run_id: str,
    entity_type: EntityType | None = None,
    entity_id: str | None = None,
) -> tuple[TransitionRecord, ...]:
    records: list[TransitionRecord] = []
    last_sequence = 0
    while True:
        if entity_type is None:
            statement = JournalStatement(
                f"""
                SELECT {_TRANSITION_COLUMNS}
                FROM transitions
                WHERE run_id = ? AND sequence > ?
                ORDER BY sequence
                LIMIT ?
                """,
                (run_id, last_sequence, INVENTORY_PAGE_SIZE),
            )
        else:
            statement = JournalStatement(
                f"""
                SELECT {_TRANSITION_COLUMNS}
                FROM transitions
                WHERE run_id = ? AND entity_type = ? AND entity_id = ?
                  AND sequence > ?
                ORDER BY sequence
                LIMIT ?
                """,
                (
                    run_id,
                    entity_type.value,
                    cast("str", entity_id),
                    last_sequence,
                    INVENTORY_PAGE_SIZE,
                ),
            )
        result = transaction.execute(statement)
        if not result.rows:
            break
        for row in result.rows:
            record = _record_from_row(row)
            records.append(record)
            last_sequence = record.sequence
        if len(records) > MAX_REPLAY_TRANSITIONS:
            message = "transition history exceeds the bounded replay limit"
            raise ProjectionIntegrityError(message)
        if len(result.rows) < INVENTORY_PAGE_SIZE:
            break
    return tuple(records)


def _record_from_row(row: Sequence[object]) -> TransitionRecord:
    if len(row) != _TRANSITION_COLUMN_COUNT:
        message = "transition row has an invalid shape"
        raise ProjectionIntegrityError(message)
    try:
        entity_type = EntityType(_text(row[3], name="transition entity_type"))
    except ValueError as error:
        message = "transition row has an undeclared entity_type"
        raise ProjectionIntegrityError(message) from error
    unavailable = _integer(row[11], name="monotonic_unavailable")
    monotonic = _optional_integer(row[10], name="monotonic_elapsed_ns")
    if (unavailable == 0) != (monotonic is not None):
        message = "transition monotonic availability fields disagree"
        raise ProjectionIntegrityError(message)
    timestamp = TransitionTimestamp(
        wall_time=_parse_wall_time(_text(row[9], name="transition wall_time")),
        monotonic_elapsed_ns=monotonic,
    )
    return TransitionRecord(
        transition_id=_text(row[0], name="transition_id"),
        run_id=_text(row[1], name="transition run_id"),
        sequence=_integer(row[2], name="transition sequence"),
        entity_type=entity_type,
        entity_id=_text(row[4], name="transition entity_id"),
        from_state=(parse_state(entity_type, row[5]) if row[5] is not None else None),
        to_state=parse_state(entity_type, row[6]),
        trigger_category=_text(row[7], name="transition trigger_category"),
        causal_record_id=_optional_text(row[8], name="causal_record_id"),
        timestamp=timestamp,
        logical_time_ns=_optional_integer(row[12], name="logical_time_ns"),
        owner_epoch=_integer(row[13], name="transition owner_epoch"),
        idempotency_key=_text(row[14], name="transition idempotency_key"),
    )


def _load_projection_inventory(
    transaction: JournalTransaction,
    run_id: str,
) -> tuple[ProjectionState, ...]:
    projections: list[ProjectionState] = []
    for entity_type in EntityType:
        table = _PROJECTION_TABLES[entity_type]
        last_identifier = ""
        while True:
            result = transaction.execute(
                JournalStatement(
                    f"""
                    SELECT {table.identifier_column}, state
                    FROM {table.table}
                    WHERE run_id = ? AND {table.identifier_column} > ?
                    ORDER BY {table.identifier_column}
                    LIMIT ?
                    """,
                    (run_id, last_identifier, INVENTORY_PAGE_SIZE),
                )
            )
            if not result.rows:
                break
            for row in result.rows:
                if len(row) != _PROJECTION_COLUMN_COUNT:
                    message = "projection inventory row has an invalid shape"
                    raise ProjectionIntegrityError(message)
                identifier = _text(row[0], name="projection entity_id")
                projections.append(
                    ProjectionState(
                        run_id=run_id,
                        entity_type=entity_type,
                        entity_id=identifier,
                        state=parse_state(entity_type, row[1]),
                    )
                )
                last_identifier = identifier
            if len(projections) > MAX_REPLAY_TRANSITIONS:
                message = "projection inventory exceeds the bounded replay limit"
                raise ProjectionIntegrityError(message)
            if len(result.rows) < INVENTORY_PAGE_SIZE:
                break
    return tuple(projections)


def _unsupported_policy_allows_skip(value: object) -> bool:
    if value is None:
        return False
    if not isinstance(value, bytes):
        message = "assertion policy_json is not a BLOB"
        raise ProjectionIntegrityError(message)
    if len(value) > MAX_CONDITION_BYTES:
        message = "assertion policy_json exceeds its schema boundary"
        raise ProjectionIntegrityError(message)
    try:
        decoded = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        message = "assertion policy_json is malformed"
        raise ProjectionIntegrityError(message) from error
    if not isinstance(decoded, dict):
        message = "assertion policy_json is not an object"
        raise ProjectionIntegrityError(message)
    policy = cast("dict[str, object]", decoded)
    _require_bounded_json_depth(policy)
    return policy.get("on_unsupported") == "skip"


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = "assertion policy_json contains a duplicate object key"
            raise ValueError(message)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    message = f"assertion policy_json contains non-RFC constant {value}"
    raise ValueError(message)


def _require_bounded_json_depth(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > MAX_POLICY_JSON_DEPTH:
            message = "assertion policy_json exceeds the nesting boundary"
            raise ProjectionIntegrityError(message)
        if isinstance(current, dict):
            mapping = cast("dict[object, object]", current)
            pending.extend((child, depth + 1) for child in mapping.values())
        elif isinstance(current, list):
            items = cast("list[object]", current)
            pending.extend((child, depth + 1) for child in items)


def _format_wall_time(timestamp: TransitionTimestamp) -> str:
    return _format_utc_datetime(timestamp.wall_time)


def _format_utc_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_wall_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        message = "transition wall_time is malformed"
        raise ProjectionIntegrityError(message) from error
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        message = "transition wall_time is not UTC"
        raise ProjectionIntegrityError(message)
    return parsed.astimezone(UTC)


def _call_crash_hook(
    hook: TransitionCrashHook | None,
    phase: TransitionMutationPhase | AttemptMutationPhase,
) -> None:
    if hook is not None:
        hook(phase)


def _call_observation_crash_hook(
    hook: ObservationCrashHook | None,
    phase: ObservationMutationPhase,
) -> None:
    if hook is not None:
        hook(phase)


def _text(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        message = f"{name} is not text"
        raise ProjectionIntegrityError(message)
    return value


def _optional_text(value: object, *, name: str) -> str | None:
    if value is None:
        return None
    return _text(value, name=name)


def _integer(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"{name} is not an integer"
        raise ProjectionIntegrityError(message)
    return value


def _optional_integer(value: object, *, name: str) -> int | None:
    if value is None:
        return None
    return _integer(value, name=name)
