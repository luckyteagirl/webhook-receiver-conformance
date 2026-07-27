"""Atomic transition/projection operations over the sole journal writer."""
# ruff: noqa: INP001, S608

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, cast

from webhook_receiver_conformance.domain.enums import (
    AssertionState,
    AttemptClassification,
    AttemptState,
    DeliveryState,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.domain.identifiers import (
    PlannedIdKind,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.scheduler.clocks import TransitionTimestamp

from .service import (
    JournalService,
    JournalStatement,
    JournalTransaction,
)
from .transitions import (
    MAX_CONDITION_BYTES,
    MAX_REPLAY_TRANSITIONS,
    MAX_SAFE_INTEGER,
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


class TransitionCrashHook(Protocol):
    """Synchronous failpoint callback executed inside the writer transaction."""

    def __call__(self, phase: TransitionMutationPhase) -> None:
        """Observe or fail one exact transaction boundary."""
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

    def execute(self, transaction: JournalTransaction) -> CommittedTransition:
        _validate_payload_scope(self.command)
        _require_current_owner(transaction, self.command)
        existing = _transition_by_idempotency_key(
            transaction,
            self.command.run_id,
            self.command.idempotency_key,
        )
        if existing is not None:
            _verify_idempotent_replay(transaction, self.command, existing)
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

        sequence = _next_transition_sequence(transaction, self.command.run_id)
        record = _record_from_command(self.command, sequence=sequence)
        _insert_transition(transaction, record)
        _call_crash_hook(self.crash_hook, TransitionMutationPhase.AFTER_APPEND)

        if self.command.expected_state is not None:
            _update_projection(transaction, self.command, projection)
        _call_crash_hook(self.crash_hook, TransitionMutationPhase.AFTER_PROJECTION)

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
    return (
        timestamp.wall_time.astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


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
    phase: TransitionMutationPhase,
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
