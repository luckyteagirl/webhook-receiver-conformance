"""Executable lifecycle, guard, atomicity, and replay tests for TASK-0203."""
# ruff: noqa: INP001, ISC004, PLR0913, S608, SLF001

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from hypothesis import given, note, settings
from hypothesis import strategies as st

from webhook_receiver_conformance.domain.enums import (
    AssertionState,
    AttemptClassification,
    AttemptState,
    DeliveryState,
    ObservationState,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.journal import repositories as repository_module
from webhook_receiver_conformance.journal.connection import connect_writer_database
from webhook_receiver_conformance.journal.repositories import (
    TRIGGER_ASSERTION_POLICY,
    TRIGGER_ATTEMPT_OUTCOME,
    TRIGGER_RETRY_ELIGIBLE,
    AttemptMutationPhase,
    TransitionMutationPhase,
    TransitionRepository,
)
from webhook_receiver_conformance.journal.schema import create_run_database
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
    JournalWriteIntegrityError,
    StatementOperation,
)
from webhook_receiver_conformance.journal.transitions import (
    AttemptPhaseEvidence,
    AttemptPhaseEvidenceCommand,
    AttemptScheduleClaim,
    AttemptTerminalOutcome,
    CausalReference,
    CrossRunReferenceError,
    DeliverySatisfactionEvidence,
    DeliverySatisfactionKind,
    EntityType,
    IdempotencyConflictError,
    IllegalTransitionError,
    LifecycleState,
    ProjectionIntegrityError,
    RetrySchedule,
    StaleOwnerEpochError,
    StateEdge,
    TransitionCommand,
    TransitionRecord,
    compare_state_machine_definition,
    replay_transition_records,
    state_machine,
    transition_allowed,
)
from webhook_receiver_conformance.scheduler.clocks import TransitionTimestamp

if TYPE_CHECKING:
    import os
    import sqlite3
    from enum import StrEnum

    from webhook_receiver_conformance.journal.service import SqlValue

RUN_ID = "00000000-0000-4000-8000-000000000001"
OTHER_RUN_ID = "00000000-0000-4000-8000-000000000002"
MANIFEST_ID = "a" * 64
WALL_TIME = datetime(2026, 7, 27, 19, 34, 56, tzinfo=UTC)
TIMESTAMP = "2026-07-27T19:34:56.000000Z"
OWNER_EPOCH = 7
LIVE_TIMESTAMP = TransitionTimestamp(WALL_TIME, 123_456)
HISTORICAL_TIMESTAMP = TransitionTimestamp.historical(WALL_TIME)
FIXTURE_HASH = f"sha256:{'b' * 64}"


def _planned(prefix: str, ordinal: int) -> str:
    return f"{prefix}{ordinal:026d}"


SCENARIO_ID = _planned("scenario_", 1)
OTHER_SCENARIO_ID = _planned("scenario_", 2)
EVENT_ID = _planned("event_", 1)
OTHER_EVENT_ID = _planned("event_", 2)
DELIVERY_ID = _planned("delivery_", 1)
OTHER_DELIVERY_ID = _planned("delivery_", 2)
ATTEMPT_ID = _planned("attempt_", 1)
SECOND_ATTEMPT_ID = _planned("attempt_", 2)
OTHER_ATTEMPT_ID = _planned("attempt_", 3)
OBSERVATION_ID = _planned("observation_", 1)
ASSERTION_ID = _planned("assertion_", 1)
OTHER_ASSERTION_ID = _planned("assertion_", 2)
ATTEMPT_PLAN_ID = _planned("attempt_plan_", 1)
CREATED_ATTEMPT_ID = _planned("attempt_", 4)

settings.register_profile(
    "task_0203_deterministic_ci",
    max_examples=300,
    derandomize=True,
    database=None,
    print_blob=True,
)
TASK_0203_DETERMINISTIC_CI = settings.get_profile("task_0203_deterministic_ci")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass(slots=True)
class _RecordingFactory:
    trace: list[str] = field(default_factory=list[str])

    def __call__(
        self,
        database_path: str | os.PathLike[str],
        *,
        create: bool,
        busy_timeout_ms: int,
    ) -> sqlite3.Connection:
        connection = connect_writer_database(
            database_path,
            create=create,
            busy_timeout_ms=busy_timeout_ms,
        )
        connection.set_trace_callback(self.trace.append)
        return connection


class _InjectedCrashError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _CrashAt:
    target: TransitionMutationPhase | AttemptMutationPhase

    def __call__(self, phase: TransitionMutationPhase | AttemptMutationPhase) -> None:
        if phase is self.target:
            raise _InjectedCrashError(phase.value)


def _statements(*, assertion_required: bool = False) -> tuple[JournalStatement, ...]:
    return (
        JournalStatement(
            """
            INSERT INTO runs (
                run_id, manifest_id, state, owner_epoch, created_at
            ) VALUES (?, ?, 'planned', ?, ?)
            """,
            (RUN_ID, MANIFEST_ID, OWNER_EPOCH, TIMESTAMP),
        ),
        JournalStatement(
            """
            INSERT INTO scenarios (
                scenario_id, run_id, ordinal, name, state
            ) VALUES (?, ?, 0, 'primary', 'pending')
            """,
            (SCENARIO_ID, RUN_ID),
        ),
        JournalStatement(
            """
            INSERT INTO scenarios (
                scenario_id, run_id, ordinal, name, state
            ) VALUES (?, ?, 1, 'secondary', 'pending')
            """,
            (OTHER_SCENARIO_ID, RUN_ID),
        ),
        JournalStatement(
            """
            INSERT INTO events (
                event_id, run_id, scenario_id, ordinal, event_type,
                fixture_blob_hash
            ) VALUES (?, ?, ?, 0, 'fixture.created', ?)
            """,
            (EVENT_ID, RUN_ID, SCENARIO_ID, FIXTURE_HASH),
        ),
        JournalStatement(
            """
            INSERT INTO events (
                event_id, run_id, scenario_id, ordinal, event_type,
                fixture_blob_hash
            ) VALUES (?, ?, ?, 0, 'fixture.created', ?)
            """,
            (OTHER_EVENT_ID, RUN_ID, OTHER_SCENARIO_ID, FIXTURE_HASH),
        ),
        JournalStatement(
            """
            INSERT INTO deliveries (
                delivery_id, run_id, scenario_id, event_id, ordinal,
                step_ordinal, logical_time_ns, state
            ) VALUES (?, ?, ?, ?, 0, 0, 0, 'pending')
            """,
            (DELIVERY_ID, RUN_ID, SCENARIO_ID, EVENT_ID),
        ),
        JournalStatement(
            """
            INSERT INTO deliveries (
                delivery_id, run_id, scenario_id, event_id, ordinal,
                step_ordinal, logical_time_ns, state
            ) VALUES (?, ?, ?, ?, 0, 0, 0, 'pending')
            """,
            (OTHER_DELIVERY_ID, RUN_ID, OTHER_SCENARIO_ID, OTHER_EVENT_ID),
        ),
        JournalStatement(
            """
            INSERT INTO attempts (
                attempt_id, run_id, scenario_id, event_id, delivery_id,
                ordinal, state, owner_epoch
            ) VALUES (?, ?, ?, ?, ?, 0, 'scheduled', ?)
            """,
            (
                ATTEMPT_ID,
                RUN_ID,
                SCENARIO_ID,
                EVENT_ID,
                DELIVERY_ID,
                OWNER_EPOCH,
            ),
        ),
        JournalStatement(
            """
            INSERT INTO attempts (
                attempt_id, run_id, scenario_id, event_id, delivery_id,
                ordinal, state, predecessor_attempt_id, owner_epoch
            ) VALUES (?, ?, ?, ?, ?, 1, 'scheduled', ?, ?)
            """,
            (
                SECOND_ATTEMPT_ID,
                RUN_ID,
                SCENARIO_ID,
                EVENT_ID,
                DELIVERY_ID,
                ATTEMPT_ID,
                OWNER_EPOCH,
            ),
        ),
        JournalStatement(
            """
            INSERT INTO attempts (
                attempt_id, run_id, scenario_id, event_id, delivery_id,
                ordinal, state, owner_epoch
            ) VALUES (?, ?, ?, ?, ?, 0, 'scheduled', ?)
            """,
            (
                OTHER_ATTEMPT_ID,
                RUN_ID,
                OTHER_SCENARIO_ID,
                OTHER_EVENT_ID,
                OTHER_DELIVERY_ID,
                OWNER_EPOCH,
            ),
        ),
        JournalStatement(
            """
            INSERT INTO observer_series (
                observation_id, run_id, scenario_id, checkpoint,
                observer_id, state
            ) VALUES (?, ?, ?, 'after_delivery', 'test-observer', 'scheduled')
            """,
            (OBSERVATION_ID, RUN_ID, SCENARIO_ID),
        ),
        JournalStatement(
            """
            INSERT INTO assertions (
                assertion_id, run_id, scenario_id, type, required, state
            ) VALUES (?, ?, ?, 'response_status', ?, 'pending')
            """,
            (ASSERTION_ID, RUN_ID, SCENARIO_ID, int(assertion_required)),
        ),
        JournalStatement(
            """
            INSERT INTO assertions (
                assertion_id, run_id, scenario_id, type, required, state
            ) VALUES (?, ?, ?, 'receiver_state', 0, 'pending')
            """,
            (OTHER_ASSERTION_ID, RUN_ID, OTHER_SCENARIO_ID),
        ),
    )


async def _seed(
    service: JournalService,
    *,
    assertion_required: bool = False,
) -> None:
    await service.execute(BatchOperation(_statements(assertion_required=assertion_required)))


async def _rows(
    service: JournalService,
    sql: str,
    parameters: tuple[SqlValue, ...] = (),
) -> tuple[tuple[SqlValue, ...], ...]:
    result = await service.execute(StatementOperation(JournalStatement(sql, parameters)))
    return result.rows


async def _execute(
    service: JournalService,
    sql: str,
    parameters: tuple[SqlValue, ...] = (),
) -> None:
    await service.execute(StatementOperation(JournalStatement(sql, parameters)))


async def _seed_attempt_schedule(service: JournalService) -> None:
    await _execute(
        service,
        """
        INSERT INTO schedule_entries (
            schedule_entry_id, run_id, scenario_id, entity_type, entity_id,
            logical_time_ns, scenario_ordinal, step_ordinal, delivery_ordinal,
            attempt_ordinal, deterministic_tie_key, idempotency_key
        ) VALUES ('schedule.initial', ?, ?, 'attempt', ?, 0, 0, 0, 0, 1,
                  'attempt.initial', 'schedule.initial.idempotency')
        """,
        (RUN_ID, SCENARIO_ID, ATTEMPT_PLAN_ID),
    )


def _test_database(tmp_path: Path, name: str) -> Path:
    directory = tmp_path / name
    directory.mkdir()
    return directory


def _command(
    entity_type: EntityType,
    entity_id: str,
    expected_state: LifecycleState | None,
    new_state: LifecycleState,
    *,
    tag: str,
    trigger: str = "test_action",
    timestamp: TransitionTimestamp = LIVE_TIMESTAMP,
    owner_epoch: int = OWNER_EPOCH,
    cause: CausalReference | None = None,
    satisfaction: DeliverySatisfactionEvidence | None = None,
    outcome: AttemptTerminalOutcome | None = None,
    logical_time_ns: int | None = None,
) -> TransitionCommand[LifecycleState]:
    return TransitionCommand(
        run_id=RUN_ID,
        transition_id=f"transition_{tag}",
        entity_type=entity_type,
        entity_id=entity_id,
        expected_state=expected_state,
        new_state=new_state,
        trigger_category=trigger,
        timestamp=timestamp,
        owner_epoch=owner_epoch,
        idempotency_key=f"idempotency_{tag}",
        causal_reference=cause,
        logical_time_ns=logical_time_ns,
        delivery_satisfaction=satisfaction,
        attempt_outcome=outcome,
    )


def _schedule_claim() -> AttemptScheduleClaim:
    return AttemptScheduleClaim(
        schedule_entry_id="schedule.initial",
        attempt_id=CREATED_ATTEMPT_ID,
        attempt_plan_id=ATTEMPT_PLAN_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        predecessor_attempt_id=None,
        condition_json=None,
        claim_transition=cast(
            "TransitionCommand[AttemptState]",
            _command(
                EntityType.ATTEMPT,
                CREATED_ATTEMPT_ID,
                AttemptState.SCHEDULED,
                AttemptState.CLAIMED,
                tag="claim_created",
                logical_time_ns=0,
            ),
        ),
    )


@pytest.mark.parametrize(
    "condition",
    [
        b'{"next_attempt_ordinal":2,"next_attempt_ordinal":2,'
        b'"predecessor_attempt_id":"attempt_00000000000000000000000001"}',
        b'{"next_attempt_ordinal":999999999999999999999999999999999,'
        b'"predecessor_attempt_id":"attempt_00000000000000000000000001"}',
        (
            b'{"next_attempt_ordinal":2,"predecessor_attempt_id":'
            b'"attempt_00000000000000000000000001","nested":'
            + (b"[" * 70)
            + b"0"
            + (b"]" * 70)
            + b"}"
        ),
    ],
)
def test_retry_condition_parser_rejects_hostile_structures(condition: bytes) -> None:
    with pytest.raises(IllegalTransitionError):
        repository_module._validate_retry_condition(  # pyright: ignore[reportPrivateUsage]
            condition,
            predecessor_attempt_id=ATTEMPT_ID,
            next_attempt_ordinal=2,
        )


async def _append_initial_history(repository: TransitionRepository) -> None:
    for ordinal, projection in enumerate(
        await repository.projection_inventory(RUN_ID),
        start=1,
    ):
        await repository.apply(
            _command(
                projection.entity_type,
                projection.entity_id,
                None,
                projection.state,
                tag=f"initial_{ordinal}",
                trigger="initial_projection",
            )
        )


def _diagram_definition(
    path: Path,
) -> tuple[
    frozenset[str],
    frozenset[StateEdge],
    frozenset[str],
    frozenset[str],
]:
    states: set[str] = set()
    edges: set[StateEdge] = set()
    initial_states: set[str] = set()
    terminal_states: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*(\[\*\]|[a-z_]+)\s+-->\s+(\[\*\]|[a-z_]+)", line)
        if match is None:
            continue
        source, target = match.groups()
        states.update(value for value in (source, target) if value != "[*]")
        if source != "[*]" and target != "[*]":
            edges.add((source, target))
        elif source == "[*]" and target != "[*]":
            initial_states.add(target)
        elif source != "[*]" and target == "[*]":
            terminal_states.add(source)
    return (
        frozenset(states),
        frozenset(edges),
        frozenset(initial_states),
        frozenset(terminal_states),
    )


def _retry_schedule(*, suffix: str = "one") -> RetrySchedule:
    return RetrySchedule(
        schedule_entry_id=f"schedule.retry.{suffix}",
        scenario_id=SCENARIO_ID,
        entity_type="attempt",
        entity_id=ATTEMPT_PLAN_ID,
        logical_time_ns=10,
        scenario_ordinal=0,
        step_ordinal=0,
        delivery_ordinal=0,
        attempt_ordinal=1,
        deterministic_tie_key=f"retry.{suffix}",
        idempotency_key=f"schedule.idempotency.{suffix}",
        predecessor_attempt_id=ATTEMPT_ID,
        condition_json=b'{"cause":"receiver_rejected"}',
    )


@pytest.mark.anyio
async def test_claim_attempt_schedule_is_atomic_and_idempotent(tmp_path: Path) -> None:
    database = create_run_database(_test_database(tmp_path, "claim"), run_id=RUN_ID).database_path
    async with JournalService.open(database) as service:
        await _seed(service)
        await _execute(service, "DELETE FROM attempts WHERE attempt_id = ?", (SECOND_ATTEMPT_ID,))
        await _seed_attempt_schedule(service)
        repository = TransitionRepository(service)
        first = await repository.claim_attempt_schedule(_schedule_claim())
        replay = await repository.claim_attempt_schedule(_schedule_claim())
        assert not first.idempotent_replay
        assert replay.idempotent_replay
        assert await _rows(
            service,
            """
            SELECT state, attempt_plan_id, ordinal, predecessor_attempt_id, owner_epoch
            FROM attempts WHERE attempt_id = ?
            """,
            (CREATED_ATTEMPT_ID,),
        ) == (("claimed", ATTEMPT_PLAN_ID, 1, None, OWNER_EPOCH),)
        assert await _rows(
            service,
            "SELECT consumed_by_owner_epoch FROM schedule_entries WHERE schedule_entry_id = ?",
            ("schedule.initial",),
        ) == ((OWNER_EPOCH,),)
        assert (
            len(
                await repository.history(
                    RUN_ID,
                    entity_type=EntityType.ATTEMPT,
                    entity_id=CREATED_ATTEMPT_ID,
                )
            )
            == 1
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "phase",
    [
        AttemptMutationPhase.AFTER_SCHEDULE_CONSUMED,
        AttemptMutationPhase.AFTER_ATTEMPT_INSERT,
        TransitionMutationPhase.AFTER_APPEND,
        TransitionMutationPhase.AFTER_PROJECTION,
    ],
)
async def test_claim_attempt_schedule_crash_rolls_back_every_mutation(
    tmp_path: Path,
    phase: TransitionMutationPhase | AttemptMutationPhase,
) -> None:
    database = create_run_database(
        _test_database(tmp_path, f"claim-{phase.value}"), run_id=RUN_ID
    ).database_path
    async with JournalService.open(database) as service:
        await _seed(service)
        await _execute(service, "DELETE FROM attempts WHERE attempt_id = ?", (SECOND_ATTEMPT_ID,))
        await _seed_attempt_schedule(service)
        repository = TransitionRepository(service, crash_hook=_CrashAt(phase))
        with pytest.raises(_InjectedCrashError):
            await repository.claim_attempt_schedule(_schedule_claim())
        assert await _rows(
            service,
            "SELECT consumed_at FROM schedule_entries WHERE schedule_entry_id = ?",
            ("schedule.initial",),
        ) == ((None,),)
        assert await _rows(
            service,
            "SELECT count(*) FROM attempts WHERE attempt_id = ?",
            (CREATED_ATTEMPT_ID,),
        ) == ((0,),)


@pytest.mark.anyio
@pytest.mark.parametrize("conflict", ["plan", "logical_time", "condition", "owner"])
async def test_claim_attempt_schedule_mismatch_fails_before_consumption(
    tmp_path: Path,
    conflict: str,
) -> None:
    database = create_run_database(
        _test_database(tmp_path, f"claim-conflict-{conflict}"), run_id=RUN_ID
    ).database_path
    async with JournalService.open(database) as service:
        await _seed(service)
        await _execute(service, "DELETE FROM attempts WHERE attempt_id = ?", (SECOND_ATTEMPT_ID,))
        await _seed_attempt_schedule(service)
        claim = _schedule_claim()
        if conflict == "plan":
            claim = replace(
                claim,
                attempt_plan_id=_planned("attempt_plan_", 2),
            )
        elif conflict == "logical_time":
            claim = replace(
                claim,
                claim_transition=replace(claim.claim_transition, logical_time_ns=1),
            )
        elif conflict == "condition":
            claim = replace(claim, condition_json=b"{}")
        else:
            claim = replace(
                claim,
                claim_transition=replace(
                    claim.claim_transition,
                    owner_epoch=OWNER_EPOCH + 1,
                ),
            )
        repository = TransitionRepository(service)
        with pytest.raises(
            (
                CrossRunReferenceError,
                IdempotencyConflictError,
                IllegalTransitionError,
                StaleOwnerEpochError,
            )
        ):
            await repository.claim_attempt_schedule(claim)
        assert await _rows(
            service,
            "SELECT consumed_at FROM schedule_entries WHERE schedule_entry_id = ?",
            ("schedule.initial",),
        ) == ((None,),)
        assert await _rows(
            service,
            "SELECT count(*) FROM attempts WHERE attempt_id = ?",
            (CREATED_ATTEMPT_ID,),
        ) == ((0,),)


@pytest.mark.anyio
async def test_attempt_transition_persists_only_closed_digest_evidence(
    tmp_path: Path,
) -> None:
    database = create_run_database(_test_database(tmp_path, "phase"), run_id=RUN_ID).database_path
    async with JournalService.open(database) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        await repository.apply(
            _command(
                EntityType.ATTEMPT,
                ATTEMPT_ID,
                AttemptState.SCHEDULED,
                AttemptState.CLAIMED,
                tag="phase_claim",
            )
        )
        digest = f"sha256:{'c' * 64}"
        command = _command(
            EntityType.ATTEMPT,
            ATTEMPT_ID,
            AttemptState.CLAIMED,
            AttemptState.PRE_SEND_COMMITTED,
            tag="phase_pre_send",
        )
        evidence = AttemptPhaseEvidenceCommand(
            AttemptPhaseEvidence.CONTROLLED_PRE_TRANSPORT,
            request_blob_hash=digest,
            request_headers_hash=FIXTURE_HASH,
        )
        committed = await repository.apply_attempt(command, evidence)
        replay = await repository.apply_attempt(command, evidence)
        assert not committed.idempotent_replay
        assert replay.idempotent_replay
        assert await _rows(
            service,
            """
            SELECT state, phase, request_blob_hash, request_headers_hash
            FROM attempts WHERE attempt_id = ?
            """,
            (ATTEMPT_ID,),
        ) == (("pre_send_committed", "controlled_pre_transport", digest, FIXTURE_HASH),)
        await repository.apply_attempt(
            _command(
                EntityType.ATTEMPT,
                ATTEMPT_ID,
                AttemptState.PRE_SEND_COMMITTED,
                AttemptState.CONNECTING,
                tag="phase_connecting",
            ),
            AttemptPhaseEvidenceCommand(AttemptPhaseEvidence.CONNECTION_ATTEMPT_STARTED),
        )
        old_replay = await repository.apply_attempt(command, evidence)
        assert old_replay.idempotent_replay
        with pytest.raises(IdempotencyConflictError):
            await repository.apply_attempt(
                command,
                replace(evidence, request_blob_hash=f"sha256:{'d' * 64}"),
            )
    assert b"secret-canary-value" not in database.read_bytes()


@pytest.mark.anyio
async def test_attempt_phase_crash_and_conflicting_replay_fail_closed(
    tmp_path: Path,
) -> None:
    database = create_run_database(
        _test_database(tmp_path, "phase-crash"), run_id=RUN_ID
    ).database_path
    async with JournalService.open(database) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        await repository.apply(
            _command(
                EntityType.ATTEMPT,
                ATTEMPT_ID,
                AttemptState.SCHEDULED,
                AttemptState.CLAIMED,
                tag="phase_crash_claim",
            )
        )
        command = _command(
            EntityType.ATTEMPT,
            ATTEMPT_ID,
            AttemptState.CLAIMED,
            AttemptState.PRE_SEND_COMMITTED,
            tag="phase_crash_pre_send",
        )
        crashing = TransitionRepository(
            service,
            crash_hook=_CrashAt(AttemptMutationPhase.AFTER_PHASE_EVIDENCE),
        )
        with pytest.raises(_InjectedCrashError):
            await crashing.apply_attempt(
                command,
                AttemptPhaseEvidenceCommand(
                    AttemptPhaseEvidence.CONTROLLED_PRE_TRANSPORT,
                    request_blob_hash=FIXTURE_HASH,
                    request_headers_hash=FIXTURE_HASH,
                ),
            )
        assert await _rows(
            service,
            "SELECT state, phase FROM attempts WHERE attempt_id = ?",
            (ATTEMPT_ID,),
        ) == (("claimed", None),)
        await repository.apply_attempt(
            command,
            AttemptPhaseEvidenceCommand(
                AttemptPhaseEvidence.CONTROLLED_PRE_TRANSPORT,
                request_blob_hash=FIXTURE_HASH,
                request_headers_hash=FIXTURE_HASH,
            ),
        )
        with pytest.raises(IllegalTransitionError):
            await repository.apply_attempt(
                command,
                AttemptPhaseEvidenceCommand(
                    AttemptPhaseEvidence.NO_CONNECTION_ESTABLISHED,
                    request_blob_hash=FIXTURE_HASH,
                    request_headers_hash=FIXTURE_HASH,
                ),
            )


def _terminal_outcome(
    state: AttemptState,
    *,
    schedule: RetrySchedule | None = None,
) -> AttemptTerminalOutcome:
    classification = {
        AttemptState.NOT_SENT: AttemptClassification.ENVIRONMENT_FAILURE,
        AttemptState.SUCCEEDED: AttemptClassification.RECEIVER_ACCEPTED,
        AttemptState.REJECTED: AttemptClassification.RECEIVER_REJECTED,
        AttemptState.TRANSPORT_FAILED: AttemptClassification.ENVIRONMENT_FAILURE,
        AttemptState.UNKNOWN_OUTCOME: AttemptClassification.AMBIGUOUS,
        AttemptState.CANCELLED: AttemptClassification.CANCELLED,
    }[state]
    return AttemptTerminalOutcome(classification, schedule)


def test_executable_tables_match_all_six_normative_diagrams() -> None:
    root = Path(__file__).parents[3]
    for entity_type in EntityType:
        states, edges, initial_states, terminal_states = _diagram_definition(
            root / "diagrams" / f"state-{entity_type.value}.mmd"
        )
        comparison = compare_state_machine_definition(
            entity_type,
            states=states,
            edges=edges,
            initial_states=initial_states,
            terminal_states=terminal_states,
        )
        assert comparison.matches, (entity_type, comparison)

        removed = next(iter(edges))
        changed = compare_state_machine_definition(
            entity_type,
            states=states | {"undeclared"},
            edges=edges - {removed},
            initial_states={"undeclared"},
            terminal_states=terminal_states - {next(iter(terminal_states))},
        )
        assert changed.unexpected_states == frozenset({"undeclared"})
        assert changed.missing_edges == frozenset({removed})
        assert changed.missing_initial_states
        assert changed.unexpected_initial_states == frozenset({"undeclared"})
        assert changed.missing_terminal_states
        assert not changed.matches


_ALL_TYPED_PAIRS = tuple(
    (entity_type, source, target)
    for entity_type in EntityType
    for source in state_machine(entity_type).state_type
    for target in state_machine(entity_type).state_type
)


@TASK_0203_DETERMINISTIC_CI
@given(st.sampled_from(_ALL_TYPED_PAIRS))
def test_property_only_declared_state_pairs_are_allowed(
    case: tuple[EntityType, StrEnum, StrEnum],
) -> None:
    entity_type, source, target = case
    machine = state_machine(entity_type)
    assert transition_allowed(
        entity_type,
        cast("LifecycleState", source),
        cast("LifecycleState", target),
    ) is ((source.value, target.value) in machine.edges)


@TASK_0203_DETERMINISTIC_CI
@given(
    st.lists(
        st.sampled_from(tuple(ScenarioState)),
        min_size=0,
        max_size=80,
    )
)
def test_random_action_lists_replay_to_the_same_model(
    actions: list[ScenarioState],
) -> None:
    note(f"replayable actions: {[action.value for action in actions]}")
    records = [
        TransitionRecord(
            transition_id="random_initial",
            run_id=RUN_ID,
            sequence=1,
            entity_type=EntityType.SCENARIO,
            entity_id=SCENARIO_ID,
            from_state=None,
            to_state=ScenarioState.PENDING,
            trigger_category="initial_projection",
            causal_record_id=None,
            timestamp=LIVE_TIMESTAMP,
            logical_time_ns=None,
            owner_epoch=OWNER_EPOCH,
            idempotency_key="random_initial",
        )
    ]
    current = ScenarioState.PENDING
    for action_index, target in enumerate(actions, start=2):
        if not transition_allowed(EntityType.SCENARIO, current, target):
            continue
        records.append(
            TransitionRecord(
                transition_id=f"random_{action_index}",
                run_id=RUN_ID,
                sequence=len(records) + 1,
                entity_type=EntityType.SCENARIO,
                entity_id=SCENARIO_ID,
                from_state=current,
                to_state=target,
                trigger_category="generated_action",
                causal_record_id=None,
                timestamp=LIVE_TIMESTAMP,
                logical_time_ns=None,
                owner_epoch=OWNER_EPOCH,
                idempotency_key=f"random_{action_index}",
            )
        )
        current = target
    replayed = replay_transition_records(records)
    assert len(replayed) == 1
    assert replayed[0].state is current


@pytest.mark.anyio
async def test_database_boundary_rejects_invalid_state_and_duplicate_scope(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        with pytest.raises(JournalWriteIntegrityError):
            await _execute(
                service,
                "UPDATE scenarios SET state = 'invented' WHERE scenario_id = ?",
                (SCENARIO_ID,),
            )
        with pytest.raises(JournalWriteIntegrityError):
            await _execute(
                service,
                """
                INSERT INTO scenarios (
                    scenario_id, run_id, ordinal, name, state
                ) VALUES (?, ?, 0, 'duplicate ordinal', 'pending')
                """,
                (_planned("scenario_", 9), RUN_ID),
            )
        assert await _rows(
            service,
            "SELECT state FROM scenarios WHERE scenario_id = ?",
            (SCENARIO_ID,),
        ) == (("pending",),)


@pytest.mark.anyio
async def test_every_scenario_state_pair_commits_exactly_when_declared(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    pairs = tuple((source, target) for source in ScenarioState for target in ScenarioState)
    extra_scenarios = tuple(
        JournalStatement(
            """
            INSERT INTO scenarios (
                scenario_id, run_id, ordinal, name, state, required
            ) VALUES (?, ?, ?, ?, ?, 0)
            """,
            (
                _planned("scenario_", index + 100),
                RUN_ID,
                index + 100,
                f"pair-{index}",
                source.value,
            ),
        )
        for index, (source, _target) in enumerate(pairs)
    )
    async with JournalService.open(run.database_path) as service:
        await service.execute(BatchOperation((_statements()[0], *extra_scenarios)))
        repository = TransitionRepository(service)
        for index, (source, target) in enumerate(pairs):
            scenario_id = _planned("scenario_", index + 100)
            command = _command(
                EntityType.SCENARIO,
                scenario_id,
                source,
                target,
                tag=f"scenario_pair_{index}",
            )
            if (source.value, target.value) in state_machine(EntityType.SCENARIO).edges:
                committed = await repository.apply(command)
                assert not committed.idempotent_replay
                expected = target.value
            else:
                with pytest.raises(IllegalTransitionError):
                    await repository.apply(command)
                expected = source.value
            assert await _rows(
                service,
                "SELECT state FROM scenarios WHERE scenario_id = ?",
                (scenario_id,),
            ) == ((expected,),)


@pytest.mark.anyio
async def test_observation_and_assertion_cover_every_terminal_classification(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    observation_terminals = state_machine(EntityType.OBSERVATION).terminal_states
    assertion_terminals = state_machine(EntityType.ASSERTION).terminal_states
    statements: list[JournalStatement] = [
        _statements()[0],
        _statements()[1],
    ]
    for index, _terminal in enumerate(sorted(observation_terminals), start=10):
        statements.append(
            JournalStatement(
                """
                INSERT INTO observer_series (
                    observation_id, run_id, scenario_id, checkpoint,
                    observer_id, state
                ) VALUES (?, ?, ?, ?, ?, 'running')
                """,
                (
                    _planned("observation_", index),
                    RUN_ID,
                    SCENARIO_ID,
                    f"checkpoint-{index}",
                    f"observer-{index}",
                ),
            )
        )
    for index, terminal in enumerate(sorted(assertion_terminals), start=20):
        statements.append(
            JournalStatement(
                """
                INSERT INTO assertions (
                    assertion_id, run_id, scenario_id, type, required, state
                ) VALUES (?, ?, ?, ?, 0, 'running')
                """,
                (
                    _planned("assertion_", index),
                    RUN_ID,
                    SCENARIO_ID,
                    f"assertion-{terminal}",
                ),
            )
        )
    async with JournalService.open(run.database_path) as service:
        await service.execute(BatchOperation(tuple(statements)))
        repository = TransitionRepository(service)
        for index, terminal in enumerate(sorted(observation_terminals), start=10):
            state = ObservationState(terminal)
            await repository.apply(
                _command(
                    EntityType.OBSERVATION,
                    _planned("observation_", index),
                    ObservationState.RUNNING,
                    state,
                    tag=f"observation_{terminal}",
                )
            )
        for index, terminal in enumerate(sorted(assertion_terminals), start=20):
            state = AssertionState(terminal)
            await repository.apply(
                _command(
                    EntityType.ASSERTION,
                    _planned("assertion_", index),
                    AssertionState.RUNNING,
                    state,
                    tag=f"assertion_{terminal}",
                )
            )
        assert {
            cast("str", row[0])
            for row in await _rows(
                service,
                "SELECT state FROM observer_series WHERE state <> 'running'",
            )
        } == observation_terminals
        assert {
            cast("str", row[0])
            for row in await _rows(
                service,
                "SELECT state FROM assertions WHERE state <> 'running'",
            )
        } == assertion_terminals


@pytest.mark.anyio
async def test_owner_expected_state_and_cross_run_guards_leave_no_partial_write(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        with pytest.raises(StaleOwnerEpochError):
            await repository.apply(
                _command(
                    EntityType.RUN,
                    RUN_ID,
                    RunState.PLANNED,
                    RunState.RUNNING,
                    tag="stale_owner",
                    owner_epoch=OWNER_EPOCH - 1,
                )
            )
        with pytest.raises(IllegalTransitionError):
            await repository.apply(
                _command(
                    EntityType.SCENARIO,
                    SCENARIO_ID,
                    ScenarioState.ELIGIBLE,
                    ScenarioState.RUNNING,
                    tag="wrong_prior",
                )
            )
        with pytest.raises(CrossRunReferenceError):
            await repository.apply(
                _command(
                    EntityType.SCENARIO,
                    SCENARIO_ID,
                    ScenarioState.PENDING,
                    ScenarioState.ELIGIBLE,
                    tag="cross_run_cause",
                    cause=CausalReference(OTHER_RUN_ID, "external.cause"),
                )
            )
        assert await _rows(service, "SELECT count(*) FROM transitions") == ((0,),)
        assert await _rows(
            service,
            "SELECT state FROM runs WHERE run_id = ?",
            (RUN_ID,),
        ) == (("planned",),)


@pytest.mark.anyio
async def test_idempotency_replays_exact_command_and_rejects_reuse(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        command = _command(
            EntityType.SCENARIO,
            SCENARIO_ID,
            ScenarioState.PENDING,
            ScenarioState.ELIGIBLE,
            tag="idempotent",
            logical_time_ns=42,
            cause=CausalReference(RUN_ID, "cause.same_record"),
        )
        first = await repository.apply(command)
        replay = await repository.apply(command)
        assert not first.idempotent_replay
        assert replay.idempotent_replay
        assert replay.record == first.record
        later_replay = await repository.apply(
            replace(
                command,
                timestamp=TransitionTimestamp(
                    datetime(2026, 7, 27, 19, 35, tzinfo=UTC),
                    999_999,
                ),
            )
        )
        assert later_replay.idempotent_replay
        assert later_replay.record.timestamp == LIVE_TIMESTAMP
        assert await _rows(service, "SELECT count(*) FROM transitions") == ((1,),)

        with pytest.raises(IdempotencyConflictError):
            await repository.apply(
                replace(
                    command,
                    transition_id="transition_changed_only",
                )
            )
        with pytest.raises(IdempotencyConflictError):
            await repository.apply(
                replace(
                    command,
                    transition_id="transition_changed",
                    new_state=ScenarioState.SKIPPED,
                )
            )
        with pytest.raises(IdempotencyConflictError):
            await repository.apply(
                replace(
                    command,
                    transition_id="transition_idempotent",
                    idempotency_key="idempotency_other",
                )
            )
        with pytest.raises(CrossRunReferenceError):
            await repository.apply(
                replace(
                    command,
                    causal_reference=CausalReference(
                        OTHER_RUN_ID,
                        "cause.same_record",
                    ),
                )
            )
        await _execute(
            service,
            "UPDATE runs SET owner_epoch = ? WHERE run_id = ?",
            (OWNER_EPOCH + 1, RUN_ID),
        )
        with pytest.raises(StaleOwnerEpochError):
            await repository.apply(command)


@pytest.mark.anyio
async def test_every_terminal_to_nonterminal_pair_is_rejected_atomically(
    tmp_path: Path,
) -> None:
    for entity_type in EntityType:
        machine = state_machine(entity_type)
        nonterminal = machine.states - machine.terminal_states
        for terminal in machine.terminal_states:
            for target in nonterminal:
                source_state = cast("LifecycleState", machine.state_type(terminal))
                target_state = cast("LifecycleState", machine.state_type(target))
                assert not transition_allowed(entity_type, source_state, target_state)

    run = create_run_database(tmp_path, run_id=RUN_ID)
    representatives = (
        (
            EntityType.RUN,
            RUN_ID,
            RunState.COMPLETED,
            RunState.RUNNING,
            "runs",
            "run_id",
        ),
        (
            EntityType.SCENARIO,
            SCENARIO_ID,
            ScenarioState.PASSED,
            ScenarioState.RUNNING,
            "scenarios",
            "scenario_id",
        ),
        (
            EntityType.DELIVERY,
            DELIVERY_ID,
            DeliveryState.SATISFIED,
            DeliveryState.ACTIVE,
            "deliveries",
            "delivery_id",
        ),
        (
            EntityType.ATTEMPT,
            ATTEMPT_ID,
            AttemptState.UNKNOWN_OUTCOME,
            AttemptState.SUCCEEDED,
            "attempts",
            "attempt_id",
        ),
        (
            EntityType.OBSERVATION,
            OBSERVATION_ID,
            ObservationState.OK,
            ObservationState.RUNNING,
            "observer_series",
            "observation_id",
        ),
        (
            EntityType.ASSERTION,
            ASSERTION_ID,
            AssertionState.PASSED,
            AssertionState.RUNNING,
            "assertions",
            "assertion_id",
        ),
    )
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        for index, (
            entity_type,
            entity_id,
            terminal,
            target,
            table,
            id_column,
        ) in enumerate(representatives):
            await _execute(
                service,
                f"UPDATE {table} SET state = ? WHERE {id_column} = ?",
                (terminal.value, entity_id),
            )
            with pytest.raises(IllegalTransitionError):
                await repository.apply(
                    _command(
                        entity_type,
                        entity_id,
                        terminal,
                        target,
                        tag=f"terminal_{index}",
                    )
                )
            assert await _rows(
                service,
                f"SELECT state FROM {table} WHERE {id_column} = ?",
                (entity_id,),
            ) == ((terminal.value,),)
        assert await _rows(service, "SELECT count(*) FROM transitions") == ((0,),)


@pytest.mark.anyio
async def test_run_completion_waits_for_every_required_delivery(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        await repository.apply(
            _command(
                EntityType.RUN,
                RUN_ID,
                RunState.PLANNED,
                RunState.RUNNING,
                tag="run_started",
            )
        )
        completion = _command(
            EntityType.RUN,
            RUN_ID,
            RunState.RUNNING,
            RunState.COMPLETED,
            tag="run_completed",
        )
        for blocked in (
            DeliveryState.PENDING,
            DeliveryState.ELIGIBLE,
            DeliveryState.ACTIVE,
            DeliveryState.AMBIGUOUS,
        ):
            await _execute(
                service,
                "UPDATE deliveries SET state = ? WHERE required = 1",
                (blocked.value,),
            )
            with pytest.raises(IllegalTransitionError):
                await repository.apply(completion)
        await _execute(
            service,
            "UPDATE deliveries SET state = 'satisfied' WHERE required = 1",
        )
        committed = await repository.apply(completion)
        assert committed.record.to_state is RunState.COMPLETED


@pytest.mark.anyio
async def test_scenario_pass_requires_required_assertion_policy(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service, assertion_required=True)
        await _execute(
            service,
            "UPDATE scenarios SET state = 'running' WHERE scenario_id = ?",
            (SCENARIO_ID,),
        )
        repository = TransitionRepository(service)
        passing = _command(
            EntityType.SCENARIO,
            SCENARIO_ID,
            ScenarioState.RUNNING,
            ScenarioState.PASSED,
            tag="scenario_passed",
        )
        for blocked in (
            AssertionState.PENDING,
            AssertionState.RUNNING,
            AssertionState.FAILED,
            AssertionState.ERROR,
            AssertionState.CANCELLED,
            AssertionState.UNSUPPORTED,
        ):
            await _execute(
                service,
                """
                UPDATE assertions
                SET state = ?, policy_json = NULL
                WHERE assertion_id = ?
                """,
                (blocked.value, ASSERTION_ID),
            )
            with pytest.raises(IllegalTransitionError):
                await repository.apply(passing)
        malformed_policies = (
            b'{"on_unsupported":NaN}',
            b'{"on_unsupported":"skip","on_unsupported":"unsupported"}',
            b'{"nested":' + (b"[" * 70) + b"0" + (b"]" * 70) + b"}",
            b'{"nested":' + (b"[" * 2_000) + b"0" + (b"]" * 2_000) + b"}",
            b"\xff",
        )
        for policy in malformed_policies:
            await _execute(
                service,
                """
                UPDATE assertions
                SET state = 'unsupported', policy_json = ?
                WHERE assertion_id = ?
                """,
                (policy, ASSERTION_ID),
            )
            with pytest.raises(ProjectionIntegrityError):
                await repository.apply(passing)
        await _execute(
            service,
            """
            UPDATE assertions
            SET state = 'unsupported', policy_json = ?
            WHERE assertion_id = ?
            """,
            (b'{"on_unsupported":"skip"}', ASSERTION_ID),
        )
        committed = await repository.apply(passing)
        assert committed.record.to_state is ScenarioState.PASSED


@pytest.mark.anyio
async def test_delivery_satisfaction_requires_typed_qualifying_evidence(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        await service.execute(
            BatchOperation(
                (
                    JournalStatement("UPDATE deliveries SET state = 'active'"),
                    JournalStatement(
                        """
                        UPDATE attempts
                        SET state = 'succeeded',
                            outcome_category = 'receiver_accepted',
                            terminal_recorded_at = ?
                        WHERE attempt_id = ?
                        """,
                        (TIMESTAMP, ATTEMPT_ID),
                    ),
                    JournalStatement(
                        "UPDATE assertions SET state = 'passed' WHERE assertion_id = ?",
                        (OTHER_ASSERTION_ID,),
                    ),
                )
            )
        )
        repository = TransitionRepository(service)
        attempt_cause = CausalReference(RUN_ID, ATTEMPT_ID)
        attempt_evidence = DeliverySatisfactionEvidence(
            DeliverySatisfactionKind.ATTEMPT,
            attempt_cause,
        )
        with pytest.raises(IllegalTransitionError):
            await repository.apply(
                _command(
                    EntityType.DELIVERY,
                    DELIVERY_ID,
                    DeliveryState.ACTIVE,
                    DeliveryState.SATISFIED,
                    tag="missing_satisfaction",
                )
            )
        with pytest.raises(IllegalTransitionError):
            await repository.apply(
                _command(
                    EntityType.DELIVERY,
                    DELIVERY_ID,
                    DeliveryState.ACTIVE,
                    DeliveryState.SATISFIED,
                    tag="wrong_trigger",
                    cause=attempt_cause,
                    satisfaction=attempt_evidence,
                )
            )
        await _execute(
            service,
            "UPDATE attempts SET terminal_recorded_at = NULL WHERE attempt_id = ?",
            (ATTEMPT_ID,),
        )
        with pytest.raises(ProjectionIntegrityError):
            await repository.apply(
                _command(
                    EntityType.DELIVERY,
                    DELIVERY_ID,
                    DeliveryState.ACTIVE,
                    DeliveryState.SATISFIED,
                    tag="missing_attempt_outcome_evidence",
                    trigger=TRIGGER_ATTEMPT_OUTCOME,
                    cause=attempt_cause,
                    satisfaction=attempt_evidence,
                )
            )
        await _execute(
            service,
            "UPDATE attempts SET terminal_recorded_at = ? WHERE attempt_id = ?",
            (TIMESTAMP, ATTEMPT_ID),
        )
        satisfaction_command = _command(
            EntityType.DELIVERY,
            DELIVERY_ID,
            DeliveryState.ACTIVE,
            DeliveryState.SATISFIED,
            tag="attempt_satisfaction",
            trigger=TRIGGER_ATTEMPT_OUTCOME,
            cause=attempt_cause,
            satisfaction=attempt_evidence,
        )
        first = await repository.apply(satisfaction_command)
        assert first.record.to_state is DeliveryState.SATISFIED
        assert (await repository.apply(satisfaction_command)).idempotent_replay
        with pytest.raises(IllegalTransitionError):
            await repository.apply(
                replace(
                    satisfaction_command,
                    delivery_satisfaction=DeliverySatisfactionEvidence(
                        DeliverySatisfactionKind.ASSERTION_POLICY,
                        attempt_cause,
                    ),
                )
            )

        assertion_cause = CausalReference(RUN_ID, OTHER_ASSERTION_ID)
        second = await repository.apply(
            _command(
                EntityType.DELIVERY,
                OTHER_DELIVERY_ID,
                DeliveryState.ACTIVE,
                DeliveryState.SATISFIED,
                tag="assertion_satisfaction",
                trigger=TRIGGER_ASSERTION_POLICY,
                cause=assertion_cause,
                satisfaction=DeliverySatisfactionEvidence(
                    DeliverySatisfactionKind.ASSERTION_POLICY,
                    assertion_cause,
                ),
            )
        )
        assert second.record.to_state is DeliveryState.SATISFIED


@pytest.mark.anyio
async def test_retry_eligibility_names_the_same_delivery_predecessor_outcome(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        await service.execute(
            BatchOperation(
                (
                    JournalStatement(
                        "UPDATE deliveries SET state = 'active' WHERE delivery_id = ?",
                        (DELIVERY_ID,),
                    ),
                    JournalStatement(
                        """
                        UPDATE attempts
                        SET state = 'rejected',
                            outcome_category = 'receiver_rejected',
                            terminal_recorded_at = ?
                        WHERE attempt_id = ?
                        """,
                        (TIMESTAMP, ATTEMPT_ID),
                    ),
                )
            )
        )
        repository = TransitionRepository(service)
        cause = CausalReference(RUN_ID, ATTEMPT_ID)
        retry = _command(
            EntityType.DELIVERY,
            DELIVERY_ID,
            DeliveryState.ACTIVE,
            DeliveryState.ELIGIBLE,
            tag="retry_eligible",
            trigger=TRIGGER_RETRY_ELIGIBLE,
            cause=cause,
        )
        with pytest.raises(IllegalTransitionError):
            await repository.apply(replace(retry, causal_reference=None))
        with pytest.raises(IllegalTransitionError):
            await repository.apply(replace(retry, trigger_category="timer"))
        with pytest.raises(CrossRunReferenceError):
            await repository.apply(
                replace(
                    retry,
                    causal_reference=CausalReference(RUN_ID, OTHER_ATTEMPT_ID),
                )
            )
        committed = await repository.apply(retry)
        assert committed.record.causal_record_id == ATTEMPT_ID


@pytest.mark.anyio
async def test_attempt_state_set_matches_sql_check_and_terminal_outcome_mapping(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        schema_rows = await _rows(
            service,
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'attempts'",
        )
        schema_sql = cast("str", schema_rows[0][0])
        match = re.search(
            r"state TEXT NOT NULL\s*CHECK\s*\(\s*state IN\s*\((.*?)\)\s*\)",
            schema_sql,
            re.DOTALL,
        )
        assert match is not None
        sql_states = frozenset(re.findall(r"'([a-z_]+)'", match.group(1)))
        assert sql_states == frozenset(state.value for state in AttemptState)

        repository = TransitionRepository(service)
        terminal_cases = (
            (
                ATTEMPT_ID,
                AttemptState.RESPONSE_OBSERVED,
                AttemptState.SUCCEEDED,
            ),
            (
                SECOND_ATTEMPT_ID,
                AttemptState.RESPONSE_OBSERVED,
                AttemptState.REJECTED,
            ),
            (
                OTHER_ATTEMPT_ID,
                AttemptState.CONNECTING,
                AttemptState.UNKNOWN_OUTCOME,
            ),
        )
        for attempt_id, source, target in terminal_cases:
            await _execute(
                service,
                "UPDATE attempts SET state = ? WHERE attempt_id = ?",
                (source.value, attempt_id),
            )
            committed = await repository.apply(
                _command(
                    EntityType.ATTEMPT,
                    attempt_id,
                    source,
                    target,
                    tag=f"attempt_{target.value}",
                    outcome=_terminal_outcome(target),
                )
            )
            assert committed.record.to_state is target


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("source", "target"),
    [
        (AttemptState.CLAIMED, AttemptState.NOT_SENT),
        (AttemptState.RESPONSE_OBSERVED, AttemptState.SUCCEEDED),
        (AttemptState.RESPONSE_OBSERVED, AttemptState.REJECTED),
        (AttemptState.CONNECTING, AttemptState.TRANSPORT_FAILED),
        (AttemptState.CONNECTING, AttemptState.UNKNOWN_OUTCOME),
        (AttemptState.SCHEDULED, AttemptState.CANCELLED),
    ],
)
async def test_every_terminal_attempt_state_persists_compatible_outcome(
    tmp_path: Path,
    source: AttemptState,
    target: AttemptState,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    schedule = None
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        await _execute(
            service,
            "UPDATE attempts SET state = ? WHERE attempt_id = ?",
            (source.value, ATTEMPT_ID),
        )
        committed = await TransitionRepository(service).apply(
            _command(
                EntityType.ATTEMPT,
                ATTEMPT_ID,
                source,
                target,
                tag=f"terminal_case_{target.value}",
                trigger=TRIGGER_ATTEMPT_OUTCOME,
                outcome=_terminal_outcome(target, schedule=schedule),
            )
        )
        assert committed.record.to_state is target
        assert await _rows(
            service,
            """
            SELECT state, outcome_category, terminal_recorded_at
            FROM attempts
            WHERE attempt_id = ?
            """,
            (ATTEMPT_ID,),
        ) == ((target.value, _terminal_outcome(target).classification.value, TIMESTAMP),)
        assert await _rows(
            service,
            "SELECT count(*) FROM schedule_entries",
        ) == ((int(schedule is not None),),)


@pytest.mark.anyio
async def test_unknown_outcome_replay_ignores_later_explicit_redelivery_schedule(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    later = replace(
        _retry_schedule(suffix="later_redelivery"),
        condition_json=b'{"ambiguity_policy":"redeliver"}',
    )
    command = _command(
        EntityType.ATTEMPT,
        ATTEMPT_ID,
        AttemptState.CONNECTING,
        AttemptState.UNKNOWN_OUTCOME,
        tag="unknown_before_redelivery",
        trigger=TRIGGER_ATTEMPT_OUTCOME,
        outcome=_terminal_outcome(AttemptState.UNKNOWN_OUTCOME),
    )
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        await _execute(
            service,
            "UPDATE attempts SET state = 'connecting' WHERE attempt_id = ?",
            (ATTEMPT_ID,),
        )
        repository = TransitionRepository(service)
        await repository.apply(command)
        await _execute(
            service,
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
                later.schedule_entry_id,
                RUN_ID,
                later.scenario_id,
                later.entity_type,
                later.entity_id,
                later.logical_time_ns,
                later.scenario_ordinal,
                later.step_ordinal,
                later.delivery_ordinal,
                later.attempt_ordinal,
                later.deterministic_tie_key,
                later.condition_json,
                later.idempotency_key,
            ),
        )
        replay = await repository.apply(command)
        assert replay.idempotent_replay
        with pytest.raises(IllegalTransitionError):
            await repository.apply(
                replace(
                    command,
                    attempt_outcome=AttemptTerminalOutcome(
                        AttemptClassification.AMBIGUOUS,
                        later,
                    ),
                )
            )


@pytest.mark.anyio
async def test_live_and_historical_monotonic_availability_is_explicit(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        await repository.apply(
            _command(
                EntityType.RUN,
                RUN_ID,
                None,
                RunState.PLANNED,
                tag="live_initial",
                timestamp=LIVE_TIMESTAMP,
            )
        )
        await repository.apply(
            _command(
                EntityType.RUN,
                RUN_ID,
                RunState.PLANNED,
                RunState.RUNNING,
                tag="historical_running",
                timestamp=HISTORICAL_TIMESTAMP,
            )
        )
        assert await _rows(
            service,
            """
            SELECT monotonic_elapsed_ns, monotonic_unavailable
            FROM transitions
            ORDER BY sequence
            """,
        ) == ((123_456, 0), (None, 1))
        history = await repository.history(RUN_ID)
        assert history[0].timestamp.is_live
        assert not history[1].timestamp.is_live


@pytest.mark.anyio
async def test_terminal_attempt_and_derived_retry_schedule_are_one_operation(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        await _execute(
            service,
            "UPDATE attempts SET state = 'response_observed' WHERE attempt_id = ?",
            (ATTEMPT_ID,),
        )
        schedule = _retry_schedule()
        command = _command(
            EntityType.ATTEMPT,
            ATTEMPT_ID,
            AttemptState.RESPONSE_OBSERVED,
            AttemptState.REJECTED,
            tag="terminal_retry",
            trigger=TRIGGER_ATTEMPT_OUTCOME,
            outcome=AttemptTerminalOutcome(
                AttemptClassification.RECEIVER_REJECTED,
                schedule,
            ),
        )
        repository = TransitionRepository(service)
        first = await repository.apply(command)
        replay = await repository.apply(command)
        assert not first.idempotent_replay
        assert replay.idempotent_replay
        with pytest.raises(IdempotencyConflictError):
            await repository.apply(
                replace(
                    command,
                    attempt_outcome=AttemptTerminalOutcome(
                        AttemptClassification.RECEIVER_REJECTED,
                    ),
                )
            )
        with pytest.raises(IllegalTransitionError):
            await repository.apply(
                replace(
                    command,
                    attempt_outcome=AttemptTerminalOutcome(
                        AttemptClassification.RECEIVER_REJECTED,
                        replace(
                            schedule,
                            predecessor_attempt_id=SECOND_ATTEMPT_ID,
                        ),
                    ),
                )
            )
        with pytest.raises(IllegalTransitionError):
            await repository.apply(
                replace(
                    command,
                    attempt_outcome=AttemptTerminalOutcome(
                        AttemptClassification.RECEIVER_REJECTED,
                        replace(schedule, attempt_ordinal=2),
                    ),
                )
            )
        assert await _rows(
            service,
            """
            SELECT state, outcome_category, terminal_recorded_at
            FROM attempts
            WHERE attempt_id = ?
            """,
            (ATTEMPT_ID,),
        ) == (("rejected", "receiver_rejected", TIMESTAMP),)
        assert await _rows(
            service,
            "SELECT count(*) FROM schedule_entries WHERE run_id = ?",
            (RUN_ID,),
        ) == ((1,),)
        assert await _rows(service, "SELECT count(*) FROM transitions") == ((1,),)


@pytest.mark.anyio
async def test_completed_attempt_history_reconstructs_its_current_state(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    path = (
        (AttemptState.SCHEDULED, AttemptState.CLAIMED),
        (AttemptState.CLAIMED, AttemptState.PRE_SEND_COMMITTED),
        (AttemptState.PRE_SEND_COMMITTED, AttemptState.CONNECTING),
        (AttemptState.CONNECTING, AttemptState.SENDING),
        (AttemptState.SENDING, AttemptState.AWAITING_RESPONSE),
        (AttemptState.AWAITING_RESPONSE, AttemptState.RESPONSE_OBSERVED),
        (AttemptState.RESPONSE_OBSERVED, AttemptState.SUCCEEDED),
    )
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        await _append_initial_history(repository)
        for ordinal, (source, target) in enumerate(path, start=1):
            await repository.apply(
                _command(
                    EntityType.ATTEMPT,
                    ATTEMPT_ID,
                    source,
                    target,
                    tag=f"completed_attempt_{ordinal}",
                    trigger=TRIGGER_ATTEMPT_OUTCOME,
                    outcome=(
                        _terminal_outcome(target) if target is AttemptState.SUCCEEDED else None
                    ),
                )
            )
        history = await repository.history(
            RUN_ID,
            entity_type=EntityType.ATTEMPT,
            entity_id=ATTEMPT_ID,
        )
        sequences = tuple(record.sequence for record in history)
        assert sequences == tuple(sorted(sequences))
        assert replay_transition_records(history)[0].state is AttemptState.SUCCEEDED
        assert await _rows(
            service,
            "SELECT state FROM attempts WHERE attempt_id = ?",
            (ATTEMPT_ID,),
        ) == (("succeeded",),)


@pytest.mark.anyio
@pytest.mark.parametrize("phase", tuple(TransitionMutationPhase))
async def test_crash_at_each_atomic_boundary_rolls_back_every_write(
    tmp_path: Path,
    phase: TransitionMutationPhase,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        await _execute(
            service,
            "UPDATE attempts SET state = 'response_observed' WHERE attempt_id = ?",
            (ATTEMPT_ID,),
        )
        repository = TransitionRepository(service, crash_hook=_CrashAt(phase))
        with pytest.raises(_InjectedCrashError):
            await repository.apply(
                _command(
                    EntityType.ATTEMPT,
                    ATTEMPT_ID,
                    AttemptState.RESPONSE_OBSERVED,
                    AttemptState.REJECTED,
                    tag=f"crash_{phase.value}",
                    trigger=TRIGGER_ATTEMPT_OUTCOME,
                    outcome=AttemptTerminalOutcome(
                        AttemptClassification.RECEIVER_REJECTED,
                        _retry_schedule(suffix=phase.value),
                    ),
                )
            )
        assert await _rows(
            service,
            """
            SELECT state, outcome_category, terminal_recorded_at
            FROM attempts
            WHERE attempt_id = ?
            """,
            (ATTEMPT_ID,),
        ) == (("response_observed", None, None),)
        assert await _rows(service, "SELECT count(*) FROM transitions") == ((0,),)
        assert await _rows(service, "SELECT count(*) FROM schedule_entries") == ((0,),)


@pytest.mark.anyio
async def test_ordered_history_rebuilds_identical_lifecycle_projections(
    tmp_path: Path,
) -> None:
    primary_root = tmp_path / "primary"
    rebuilt_root = tmp_path / "rebuilt"
    primary_root.mkdir()
    rebuilt_root.mkdir()
    primary = create_run_database(primary_root, run_id=RUN_ID)
    rebuilt = create_run_database(rebuilt_root, run_id=RUN_ID)

    async with JournalService.open(primary.database_path) as primary_service:
        await _seed(primary_service)
        primary_repository = TransitionRepository(primary_service)
        await _append_initial_history(primary_repository)
        await primary_repository.apply(
            _command(
                EntityType.SCENARIO,
                SCENARIO_ID,
                ScenarioState.PENDING,
                ScenarioState.ELIGIBLE,
                tag="rebuild_scenario",
            )
        )
        expected = await primary_repository.projection_inventory(RUN_ID)
        history = await primary_repository.history(RUN_ID)
        initial_attempt_history = await primary_repository.history(
            RUN_ID,
            entity_type=EntityType.ATTEMPT,
            entity_id=ATTEMPT_ID,
        )
        assert replay_transition_records(initial_attempt_history)[0].state is AttemptState.SCHEDULED
        assert (await primary_repository.audit_projections(RUN_ID)).matches

        async with JournalService.open(rebuilt.database_path) as rebuilt_service:
            await _seed(rebuilt_service)
            rebuilt_repository = TransitionRepository(rebuilt_service)
            for record in history:
                await rebuilt_repository.apply(
                    TransitionCommand(
                        run_id=record.run_id,
                        transition_id=record.transition_id,
                        entity_type=record.entity_type,
                        entity_id=record.entity_id,
                        expected_state=record.from_state,
                        new_state=record.to_state,
                        trigger_category=record.trigger_category,
                        timestamp=record.timestamp,
                        owner_epoch=record.owner_epoch,
                        idempotency_key=record.idempotency_key,
                        causal_reference=(
                            CausalReference(record.run_id, record.causal_record_id)
                            if record.causal_record_id is not None
                            else None
                        ),
                        logical_time_ns=record.logical_time_ns,
                    )
                )
            assert await rebuilt_repository.projection_inventory(RUN_ID) == expected
            assert (await rebuilt_repository.audit_projections(RUN_ID)).matches

        await _execute(
            primary_service,
            "UPDATE scenarios SET state = 'running' WHERE scenario_id = ?",
            (SCENARIO_ID,),
        )
        audit = await primary_repository.audit_projections(RUN_ID)
        assert not audit.matches
        assert any(
            mismatch.entity_id == SCENARIO_ID
            and mismatch.projected_state is ScenarioState.RUNNING
            and mismatch.replayed_state is ScenarioState.ELIGIBLE
            for mismatch in audit.mismatches
        )


@pytest.mark.anyio
async def test_repository_uses_one_explicit_write_transaction(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    factory = _RecordingFactory()
    async with JournalService.open(
        run.database_path,
        connection_factory=factory,
    ) as service:
        await _seed(service)
        factory.trace.clear()
        repository = TransitionRepository(service)
        await repository.apply(
            _command(
                EntityType.SCENARIO,
                SCENARIO_ID,
                ScenarioState.PENDING,
                ScenarioState.ELIGIBLE,
                tag="trace",
            )
        )
    transaction_lines = [
        statement.strip().upper()
        for statement in factory.trace
        if statement.strip().upper().startswith(("BEGIN", "COMMIT", "ROLLBACK"))
    ]
    assert transaction_lines == ["BEGIN IMMEDIATE", "COMMIT"]


def test_replay_rejects_missing_initial_discontinuity_and_duplicate_identity() -> None:
    base = TransitionRecord(
        transition_id="replay_one",
        run_id=RUN_ID,
        sequence=1,
        entity_type=EntityType.RUN,
        entity_id=RUN_ID,
        from_state=None,
        to_state=RunState.PLANNED,
        trigger_category="initial_projection",
        causal_record_id=None,
        timestamp=LIVE_TIMESTAMP,
        logical_time_ns=None,
        owner_epoch=OWNER_EPOCH,
        idempotency_key="replay_one",
    )
    with pytest.raises(ProjectionIntegrityError):
        replay_transition_records(
            [replace(base, from_state=RunState.PLANNED, to_state=RunState.RUNNING)]
        )
    with pytest.raises(ProjectionIntegrityError):
        replay_transition_records(
            [
                base,
                replace(
                    base,
                    transition_id="replay_two",
                    sequence=2,
                    from_state=RunState.PAUSED,
                    to_state=RunState.RUNNING,
                    idempotency_key="replay_two",
                ),
            ]
        )
    with pytest.raises(ProjectionIntegrityError):
        replay_transition_records([base, replace(base, sequence=2)])
