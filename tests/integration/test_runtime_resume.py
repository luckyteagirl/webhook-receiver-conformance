"""Focused integration coverage for production resume orchestration."""
# ruff: noqa: INP001

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from webhook_receiver_conformance.domain.enums import AttemptState, RunState
from webhook_receiver_conformance.journal.resume import ResumeJournalProjectionError
from webhook_receiver_conformance.journal.run_lock import (
    FilesystemKind,
    ProcessProbe,
    ProcessState,
    RunLockActiveError,
    RunLockMetadata,
    acquire_run_lock,
)
from webhook_receiver_conformance.journal.schedules import PersistentScheduleRepository
from webhook_receiver_conformance.journal.schema import MIGRATIONS, create_run_database
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
)
from webhook_receiver_conformance.journal.transitions import (
    AttemptScheduleClaim,
    EntityType,
    TransitionCommand,
)
from webhook_receiver_conformance.recovery.policy import (
    AmbiguityPolicy,
    BundleRecoveryPolicy,
    ObservationReconciliationPlan,
    ObservationReconciliationRule,
    RedeliveryAttemptPlan,
    RedeliveryTemplate,
    ResumeInvocationPolicy,
    ResumePolicyEngine,
)
from webhook_receiver_conformance.runtime.resume import (
    ResumeRequest,
    ResumeService,
    ResumeStatus,
)
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from webhook_receiver_conformance.journal.resume import ResumeJournalPreflight
    from webhook_receiver_conformance.journal.run_lock import RunLock
    from webhook_receiver_conformance.runtime.resume import ResumeResult

RUN_ID = "00000000-0000-4000-8000-000000008090"
MANIFEST_ID = "a" * 64
OWNER_EPOCH = 7
WALL_TIME = datetime(2026, 7, 27, 20, 30, tzinfo=UTC)
WALL_TEXT = "2026-07-27T20:30:00.000000Z"
FIXTURE_HASH = f"sha256:{'b' * 64}"
SCENARIO_ID = f"scenario_{'0' * 25}1"
EVENT_ID = f"event_{'0' * 25}1"
DELIVERY_ID = f"delivery_{'0' * 25}1"
ATTEMPT_ID = f"attempt_{'0' * 25}1"
REDELIVERY_ID = f"attempt_{'0' * 25}2"
ATTEMPT_PLAN_ID = f"attempt_plan_{'0' * 25}2"
OBSERVATION_ID = f"observation_{'0' * 25}1"
ASSERTION_ID = f"assertion_{'0' * 25}1"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass(frozen=True, slots=True)
class _LocalFilesystem:
    def classify(self, path: Path) -> FilesystemKind:
        del path
        return FilesystemKind.LOCAL


@dataclass(frozen=True, slots=True)
class _AbsentProcess:
    def current_process_fingerprint(self) -> str:
        return "new-process"

    def inspect(self, pid: int) -> ProcessProbe:
        del pid
        return ProcessProbe(ProcessState.ABSENT, None)


class _PrepareError(ValueError):
    """Injected pre-mutation validation failure."""


@dataclass(slots=True)
class _RedeliveryRecorder:
    plans: list[RedeliveryAttemptPlan] = field(default_factory=list[RedeliveryAttemptPlan])

    async def __call__(self, plan: RedeliveryAttemptPlan) -> None:
        self.plans.append(plan)


@dataclass(slots=True)
class _ObservationRecorder:
    plans: list[ObservationReconciliationPlan] = field(
        default_factory=list[ObservationReconciliationPlan]
    )

    async def __call__(self, plan: ObservationReconciliationPlan) -> None:
        self.plans.append(plan)


def _clock() -> RuntimeClock:
    return RuntimeClock(
        ClockPolicy(ClockMode.REAL),
        wall_now=lambda: WALL_TIME,
        monotonic_now=lambda: 123_456,
    )


async def _seed_run(
    root: Path,
    *,
    state: AttemptState,
    run_state: RunState = RunState.RUNNING,
) -> Path:
    run = create_run_database(root, run_id=RUN_ID)
    outcome = "ambiguous" if state is AttemptState.UNKNOWN_OUTCOME else None
    terminal = WALL_TEXT if outcome is not None else None
    statements = (
        JournalStatement(
            """
            INSERT INTO runs (
                run_id, manifest_id, state, owner_epoch, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (RUN_ID, MANIFEST_ID, run_state.value, OWNER_EPOCH, WALL_TEXT),
        ),
        JournalStatement(
            """
            INSERT INTO scenarios (
                scenario_id, run_id, ordinal, name, state
            ) VALUES (?, ?, 0, 'resume', 'running')
            """,
            (SCENARIO_ID, RUN_ID),
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
            INSERT INTO deliveries (
                delivery_id, run_id, scenario_id, event_id, ordinal,
                step_ordinal, logical_time_ns, state
            ) VALUES (?, ?, ?, ?, 0, 0, 0, 'active')
            """,
            (DELIVERY_ID, RUN_ID, SCENARIO_ID, EVENT_ID),
        ),
        JournalStatement(
            """
            INSERT INTO attempts (
                attempt_id, run_id, scenario_id, event_id, delivery_id,
                attempt_plan_id, ordinal, state, outcome_category,
                owner_epoch, terminal_recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (
                ATTEMPT_ID,
                RUN_ID,
                SCENARIO_ID,
                EVENT_ID,
                DELIVERY_ID,
                ATTEMPT_PLAN_ID,
                state.value,
                outcome,
                OWNER_EPOCH,
                terminal,
            ),
        ),
    )
    async with JournalService.open(run.database_path) as service:
        await service.execute(BatchOperation(statements))
    return run.run_directory


def _seed_v3_run(
    root: Path,
    *,
    attempt_state: AttemptState = AttemptState.SCHEDULED,
) -> Path:
    run = create_run_database(root, run_id=RUN_ID, migrations=MIGRATIONS[:3])
    with sqlite3.connect(run.database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO runs (
                run_id, manifest_id, state, owner_epoch, created_at
            ) VALUES (?, ?, 'running', ?, ?)
            """,
            (RUN_ID, MANIFEST_ID, OWNER_EPOCH, WALL_TEXT),
        )
        connection.execute(
            """
            INSERT INTO scenarios (
                scenario_id, run_id, ordinal, name, state
            ) VALUES (?, ?, 0, 'resume', 'running')
            """,
            (SCENARIO_ID, RUN_ID),
        )
        connection.execute(
            """
            INSERT INTO events (
                event_id, run_id, scenario_id, ordinal, event_type,
                fixture_blob_hash
            ) VALUES (?, ?, ?, 0, 'fixture.created', ?)
            """,
            (EVENT_ID, RUN_ID, SCENARIO_ID, FIXTURE_HASH),
        )
        connection.execute(
            """
            INSERT INTO deliveries (
                delivery_id, run_id, scenario_id, event_id, ordinal,
                step_ordinal, logical_time_ns, state
            ) VALUES (?, ?, ?, ?, 0, 0, 0, 'active')
            """,
            (DELIVERY_ID, RUN_ID, SCENARIO_ID, EVENT_ID),
        )
        connection.execute(
            """
            INSERT INTO attempts (
                attempt_id, run_id, scenario_id, event_id, delivery_id,
                attempt_plan_id, ordinal, state, owner_epoch
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                ATTEMPT_ID,
                RUN_ID,
                SCENARIO_ID,
                EVENT_ID,
                DELIVERY_ID,
                ATTEMPT_PLAN_ID,
                attempt_state.value,
                OWNER_EPOCH,
            ),
        )
        connection.execute(
            """
            INSERT INTO schedule_entries (
                schedule_entry_id, run_id, scenario_id, entity_type,
                entity_id, logical_time_ns, scenario_ordinal,
                step_ordinal, delivery_ordinal, attempt_ordinal,
                deterministic_tie_key, idempotency_key
            ) VALUES (
                'resume.initial', ?, ?, 'attempt', ?, 0, 0, 0, 0, 1,
                'resume.initial', 'resume.initial'
            )
            """,
            (RUN_ID, SCENARIO_ID, ATTEMPT_PLAN_ID),
        )
    return run.run_directory


async def _add_attempt_schedule(
    run_directory: Path,
    *,
    consumed: bool,
) -> None:
    async with JournalService.open(run_directory / "journal.sqlite3") as service:
        await service.execute(
            BatchOperation(
                (
                    JournalStatement(
                        """
                        INSERT INTO schedule_entries (
                            schedule_entry_id, run_id, scenario_id, entity_type,
                            entity_id, logical_time_ns, scenario_ordinal,
                            step_ordinal, delivery_ordinal, attempt_ordinal,
                            deterministic_tie_key, idempotency_key,
                            consumed_at, consumed_by_owner_epoch
                        ) VALUES (
                            'resume.initial', ?, ?, 'attempt', ?, 0, 0, 0, 0, 1,
                            'resume.initial', 'resume.initial', ?, ?
                        )
                        """,
                        (
                            RUN_ID,
                            SCENARIO_ID,
                            ATTEMPT_PLAN_ID,
                            WALL_TEXT if consumed else None,
                            OWNER_EPOCH if consumed else None,
                        ),
                    ),
                )
            )
        )


def _initial_claim(owner_epoch: int) -> AttemptScheduleClaim:
    return AttemptScheduleClaim(
        schedule_entry_id="resume.initial",
        attempt_id=ATTEMPT_ID,
        attempt_plan_id=ATTEMPT_PLAN_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        predecessor_attempt_id=None,
        condition_json=None,
        claim_transition=TransitionCommand(
            run_id=RUN_ID,
            transition_id=f"attempt.claim.{ATTEMPT_ID}",
            entity_type=EntityType.ATTEMPT,
            entity_id=ATTEMPT_ID,
            expected_state=AttemptState.SCHEDULED,
            new_state=AttemptState.CLAIMED,
            trigger_category="attempt_claimed",
            timestamp=_clock().transition_timestamp(),
            owner_epoch=owner_epoch,
            idempotency_key=f"attempt.claim.{ATTEMPT_ID}",
            logical_time_ns=0,
        ),
    )


def _rows(
    run_directory: Path,
    sql: str,
    parameters: Sequence[object] = (),
) -> tuple[tuple[object, ...], ...]:
    connection = sqlite3.connect(run_directory / "journal.sqlite3")
    try:
        return tuple(connection.execute(sql, tuple(parameters)).fetchall())
    finally:
        connection.close()


def _write_stale_lock(run_directory: Path) -> None:
    metadata = RunLockMetadata(
        run_id=RUN_ID,
        pid=42,
        process_start_fingerprint="old-process",
        hostname="test-host",
        owner_epoch=OWNER_EPOCH,
        wall_timestamp=WALL_TEXT,
    )
    value = {
        "format_version": metadata.format_version,
        "hostname": metadata.hostname,
        "owner_epoch": metadata.owner_epoch,
        "pid": metadata.pid,
        "process_start_fingerprint": metadata.process_start_fingerprint,
        "run_id": metadata.run_id,
        "wall_timestamp": metadata.wall_timestamp,
    }
    payload = (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    (run_directory / "run.lock").write_bytes(payload.encode("ascii"))


@pytest.mark.anyio
async def test_no_policy_ambiguity_is_strictly_read_only_and_offline(
    tmp_path: Path,
) -> None:
    run_directory = await _seed_run(tmp_path, state=AttemptState.SENDING)
    database_path = run_directory / "journal.sqlite3"
    before = database_path.stat()
    redelivery = _RedeliveryRecorder()

    result = await ResumeService(
        clock=_clock(),
        redelivery=redelivery,
    ).resume(ResumeRequest(run_directory))

    after = database_path.stat()
    assert result.status is ResumeStatus.AMBIGUOUS_READ_ONLY
    assert result.read_only is True
    assert result.owner_epoch == OWNER_EPOCH
    assert result.ambiguous_attempt_ids == (ATTEMPT_ID,)
    assert result.recovery_plan is None
    assert result.automatic_transitions == ()
    assert result.receiver_contact_possible is False
    assert result.observer_contact_possible is False
    assert redelivery.plans == []
    assert not (run_directory / "run.lock").exists()
    assert (after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    assert _rows(
        run_directory,
        "SELECT owner_epoch FROM runs WHERE run_id = ?",
        (RUN_ID,),
    ) == ((OWNER_EPOCH,),)
    assert _rows(
        run_directory,
        "SELECT state FROM attempts WHERE attempt_id = ?",
        (ATTEMPT_ID,),
    ) == ((AttemptState.SENDING.value,),)
    assert _rows(
        run_directory,
        "SELECT count(*) FROM recovery_decisions",
    ) == ((0,),)


@pytest.mark.anyio
async def test_resume_prepare_failure_is_byte_stable_and_precedes_epoch_mutation(
    tmp_path: Path,
) -> None:
    run_directory = await _seed_run(tmp_path, state=AttemptState.SCHEDULED)
    database_path = run_directory / "journal.sqlite3"
    before = database_path.read_bytes()

    async def fail_prepare(
        preflight: ResumeJournalPreflight,
        ownership: RunLock,
    ) -> object:
        del preflight, ownership
        raise _PrepareError

    async def forbidden_continuation(
        result: ResumeResult,
        ownership: RunLock,
        prepared: object,
    ) -> object:
        del result, ownership, prepared
        raise AssertionError

    with pytest.raises(_PrepareError):
        await ResumeService(clock=_clock()).resume_and_continue(
            ResumeRequest(run_directory),
            prepare=fail_prepare,
            continuation=forbidden_continuation,
        )

    assert database_path.read_bytes() == before
    assert not (run_directory / "run.lock").exists()
    assert _rows(
        run_directory,
        "SELECT owner_epoch FROM runs WHERE run_id = ?",
        (RUN_ID,),
    ) == ((OWNER_EPOCH,),)
    assert _rows(run_directory, "SELECT count(*) FROM recovery_decisions") == ((0,),)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "run_state",
    [RunState.COMPLETED, RunState.CANCELLED, RunState.FAILED],
)
async def test_terminal_run_is_rejected_before_lock_prepare_or_epoch_mutation(
    tmp_path: Path,
    run_state: RunState,
) -> None:
    run_directory = await _seed_run(
        tmp_path,
        state=AttemptState.SCHEDULED,
        run_state=run_state,
    )
    database_path = run_directory / "journal.sqlite3"
    before = database_path.read_bytes()
    prepare_called = False
    continuation_called = False

    async def forbidden_prepare(
        preflight: ResumeJournalPreflight,
        ownership: RunLock,
    ) -> object:
        nonlocal prepare_called
        del preflight, ownership
        prepare_called = True
        raise AssertionError

    async def forbidden_continuation(
        result: ResumeResult,
        ownership: RunLock,
        prepared: object,
    ) -> object:
        nonlocal continuation_called
        del result, ownership, prepared
        continuation_called = True
        raise AssertionError

    with pytest.raises(
        ResumeJournalProjectionError,
        match="terminal run cannot be resumed",
    ):
        await ResumeService(clock=_clock()).resume_and_continue(
            ResumeRequest(run_directory),
            prepare=forbidden_prepare,
            continuation=forbidden_continuation,
        )

    assert prepare_called is False
    assert continuation_called is False
    assert database_path.read_bytes() == before
    assert not (run_directory / "run.lock").exists()
    assert _rows(
        run_directory,
        "SELECT state, owner_epoch FROM runs WHERE run_id = ?",
        (RUN_ID,),
    ) == ((run_state.value, OWNER_EPOCH),)


@pytest.mark.anyio
async def test_resume_migrates_valid_v3_journal_then_validates_v4_projection(
    tmp_path: Path,
) -> None:
    run_directory = _seed_v3_run(tmp_path)
    assert _rows(run_directory, "PRAGMA user_version") == ((3,),)
    assert _rows(
        run_directory,
        """
        SELECT count(*)
        FROM sqlite_schema
        WHERE type = 'table' AND name = 'attempt_response_staging'
        """,
    ) == ((0,),)

    result = await ResumeService(clock=_clock()).resume(ResumeRequest(run_directory))

    assert result.status is ResumeStatus.CONTINUE
    assert result.owner_epoch == OWNER_EPOCH + 1
    assert result.preflight.run_state is RunState.RUNNING
    assert _rows(run_directory, "PRAGMA user_version") == ((4,),)
    assert _rows(
        run_directory,
        """
        SELECT count(*)
        FROM sqlite_schema
        WHERE type = 'table' AND name = 'attempt_response_staging'
        """,
    ) == ((1,),)
    assert _rows(
        run_directory,
        "SELECT state, owner_epoch FROM runs WHERE run_id = ?",
        (RUN_ID,),
    ) == ((RunState.RUNNING.value, OWNER_EPOCH + 1),)


@pytest.mark.anyio
async def test_v3_projection_failure_never_reaches_public_continuation(
    tmp_path: Path,
) -> None:
    run_directory = _seed_v3_run(
        tmp_path,
        attempt_state=AttemptState.RESPONSE_OBSERVED,
    )
    prepare_called = False
    public_continuation_called = False

    async def local_prepare(
        preflight: ResumeJournalPreflight,
        ownership: RunLock,
    ) -> object:
        nonlocal prepare_called
        del preflight, ownership
        prepare_called = True
        return object()

    async def forbidden_public_continuation(
        result: ResumeResult,
        ownership: RunLock,
        prepared: object,
    ) -> object:
        nonlocal public_continuation_called
        del result, ownership, prepared
        public_continuation_called = True
        raise AssertionError

    with pytest.raises(ExceptionGroup) as captured:
        await ResumeService(clock=_clock()).resume_and_continue(
            ResumeRequest(run_directory),
            prepare=local_prepare,
            continuation=forbidden_public_continuation,
        )

    assert captured.value.subgroup(ResumeJournalProjectionError) is not None
    assert prepare_called is True
    assert public_continuation_called is False
    assert not (run_directory / "run.lock").exists()
    assert _rows(run_directory, "PRAGMA user_version") == ((4,),)
    assert _rows(
        run_directory,
        "SELECT owner_epoch FROM runs WHERE run_id = ?",
        (RUN_ID,),
    ) == ((OWNER_EPOCH,),)


@pytest.mark.anyio
async def test_resume_continuation_retains_one_exclusive_owner_guard(
    tmp_path: Path,
) -> None:
    run_directory = await _seed_run(tmp_path, state=AttemptState.SCHEDULED)
    await _add_attempt_schedule(run_directory, consumed=False)
    sentinel = object()

    async def prepare(
        preflight: ResumeJournalPreflight,
        ownership: RunLock,
    ) -> object:
        del preflight
        assert ownership is not None
        return sentinel

    async def continue_under_lock(
        result: ResumeResult,
        ownership: RunLock,
        prepared: object,
    ) -> object:
        assert prepared is sentinel
        assert ownership.closed is False
        with pytest.raises(RunLockActiveError):
            acquire_run_lock(
                run_directory,
                run_id=result.run_id,
                owner_epoch=result.owner_epoch + 1,
                take_over=True,
            )
        return "continued"

    workflow = await ResumeService(clock=_clock()).resume_and_continue(
        ResumeRequest(run_directory),
        prepare=prepare,
        continuation=continue_under_lock,
    )

    assert workflow.recovery.status is ResumeStatus.CONTINUE
    assert workflow.continuation == "continued"
    assert not (run_directory / "run.lock").exists()


@pytest.mark.anyio
async def test_explicit_stop_takes_over_advances_epoch_and_appends_evidence(
    tmp_path: Path,
) -> None:
    run_directory = await _seed_run(tmp_path, state=AttemptState.SENDING)
    _write_stale_lock(run_directory)

    result = await ResumeService(
        clock=_clock(),
        filesystem_probe=_LocalFilesystem(),
        process_inspector=_AbsentProcess(),
        hostname="test-host",
    ).resume(
        ResumeRequest(
            run_directory,
            invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.STOP),
        )
    )

    assert result.status is ResumeStatus.STOP_AMBIGUOUS
    assert result.read_only is False
    assert result.owner_epoch == OWNER_EPOCH + 1
    assert result.takeover_event is not None
    assert result.takeover_event.previous_owner.owner_epoch == OWNER_EPOCH
    assert len(result.automatic_transitions) == 1
    assert not (run_directory / "run.lock").exists()
    assert _rows(
        run_directory,
        "SELECT owner_epoch FROM runs WHERE run_id = ?",
        (RUN_ID,),
    ) == ((OWNER_EPOCH + 1,),)
    assert _rows(
        run_directory,
        """
        SELECT attempt_id, ordinal, state, outcome_category
        FROM attempts
        WHERE delivery_id = ?
        ORDER BY ordinal
        """,
        (DELIVERY_ID,),
    ) == (
        (
            ATTEMPT_ID,
            1,
            AttemptState.UNKNOWN_OUTCOME.value,
            "ambiguous",
        ),
    )
    assert _rows(
        run_directory,
        """
        SELECT policy, decision, attempt_id
        FROM recovery_decisions
        """,
    ) == (("stop", "stopped_ambiguous", ATTEMPT_ID),)


@pytest.mark.anyio
async def test_explicit_redelivery_commits_new_attempt_before_injected_callback(
    tmp_path: Path,
) -> None:
    run_directory = await _seed_run(
        tmp_path,
        state=AttemptState.UNKNOWN_OUTCOME,
    )
    recorder = _RedeliveryRecorder()
    engine = ResumePolicyEngine(fresh_attempt_id=lambda: REDELIVERY_ID)
    bundle = BundleRecoveryPolicy(
        redelivery_templates=(
            RedeliveryTemplate(
                scenario_id=SCENARIO_ID,
                event_id=EVENT_ID,
                delivery_id=DELIVERY_ID,
                attempt_plan_id=ATTEMPT_PLAN_ID,
                logical_due_ns=0,
                deterministic_tie_key="explicit-redelivery",
            ),
        )
    )

    result = await ResumeService(
        clock=_clock(),
        policy_engine=engine,
        redelivery=recorder,
    ).resume(
        ResumeRequest(
            run_directory,
            invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
            bundle_policy=bundle,
        )
    )

    assert result.status is ResumeStatus.CONTINUE
    assert result.redeliveries_invoked == 1
    assert result.policy_plan is not None
    assert recorder.plans == [result.policy_plan.redeliveries[0]]
    assert _rows(
        run_directory,
        """
        SELECT attempt_id, ordinal, state, predecessor_attempt_id
        FROM attempts
        WHERE delivery_id = ?
        ORDER BY ordinal
        """,
        (DELIVERY_ID,),
    ) == (
        (
            ATTEMPT_ID,
            1,
            AttemptState.UNKNOWN_OUTCOME.value,
            None,
        ),
        (
            REDELIVERY_ID,
            2,
            AttemptState.SCHEDULED.value,
            ATTEMPT_ID,
        ),
    )
    assert _rows(
        run_directory,
        """
        SELECT entity_id, attempt_ordinal, consumed_at
        FROM schedule_entries
        """,
    ) == ((ATTEMPT_PLAN_ID, 2, None),)
    assert _rows(
        run_directory,
        "SELECT policy, decision FROM recovery_decisions",
    ) == (("redeliver", "redelivery_created"),)


@pytest.mark.anyio
async def test_fresh_resume_reuses_committed_redelivery_without_new_consent(
    tmp_path: Path,
) -> None:
    run_directory = await _seed_run(
        tmp_path,
        state=AttemptState.UNKNOWN_OUTCOME,
    )
    bundle = BundleRecoveryPolicy(
        redelivery_templates=(
            RedeliveryTemplate(
                scenario_id=SCENARIO_ID,
                event_id=EVENT_ID,
                delivery_id=DELIVERY_ID,
                attempt_plan_id=ATTEMPT_PLAN_ID,
                logical_due_ns=0,
                deterministic_tie_key="explicit-redelivery",
            ),
        )
    )
    first = await ResumeService(
        clock=_clock(),
        policy_engine=ResumePolicyEngine(fresh_attempt_id=lambda: REDELIVERY_ID),
    ).resume(
        ResumeRequest(
            run_directory,
            invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
            bundle_policy=bundle,
            defer_redeliveries=True,
        )
    )

    assert first.status is ResumeStatus.CONTINUE
    second = await ResumeService(clock=_clock()).resume(ResumeRequest(run_directory))

    assert second.status is ResumeStatus.CONTINUE
    assert second.owner_epoch == OWNER_EPOCH + 2
    assert second.ambiguous_attempt_ids == ()
    assert second.policy_plan is not None
    assert second.policy_plan.redeliveries == ()
    assert tuple(item.schedule_entry_id for item in second.policy_plan.runnable_schedule) == (
        f"resume.redelivery.{REDELIVERY_ID}",
    )
    assert _rows(
        run_directory,
        """
        SELECT attempt_id, state, predecessor_attempt_id, owner_epoch
        FROM attempts
        ORDER BY ordinal
        """,
    ) == (
        (
            ATTEMPT_ID,
            AttemptState.UNKNOWN_OUTCOME.value,
            None,
            OWNER_EPOCH,
        ),
        (
            REDELIVERY_ID,
            AttemptState.SCHEDULED.value,
            ATTEMPT_ID,
            OWNER_EPOCH + 2,
        ),
    )
    assert _rows(
        run_directory,
        "SELECT count(*) FROM recovery_decisions",
    ) == ((1,),)


@pytest.mark.anyio
async def test_fresh_resume_rebinds_consumed_claim_without_rewriting_history(
    tmp_path: Path,
) -> None:
    run_directory = await _seed_run(tmp_path, state=AttemptState.SCHEDULED)
    await _add_attempt_schedule(run_directory, consumed=False)
    async with JournalService.open(run_directory / "journal.sqlite3") as service:
        repository = PersistentScheduleRepository(service)
        original = await repository.lease_attempt(_initial_claim(OWNER_EPOCH))
    assert original.idempotent_replay is False

    result = await ResumeService(clock=_clock()).resume(ResumeRequest(run_directory))

    assert result.status is ResumeStatus.CONTINUE
    assert result.policy_plan is not None
    assert tuple(item.schedule_entry_id for item in result.policy_plan.runnable_schedule) == (
        "resume.initial",
    )
    assert _rows(
        run_directory,
        "SELECT state, owner_epoch FROM attempts WHERE attempt_id = ?",
        (ATTEMPT_ID,),
    ) == ((AttemptState.CLAIMED.value, OWNER_EPOCH + 1),)
    assert _rows(
        run_directory,
        """
        SELECT consumed_at, consumed_by_owner_epoch
        FROM schedule_entries
        WHERE schedule_entry_id = 'resume.initial'
        """,
    ) == ((WALL_TEXT, OWNER_EPOCH + 1),)
    assert _rows(
        run_directory,
        """
        SELECT from_state, to_state, owner_epoch
        FROM transitions
        WHERE entity_type = 'attempt' AND entity_id = ?
        """,
        (ATTEMPT_ID,),
    ) == ((AttemptState.SCHEDULED.value, AttemptState.CLAIMED.value, OWNER_EPOCH),)

    async with JournalService.open(run_directory / "journal.sqlite3") as service:
        repository = PersistentScheduleRepository(service)
        pending = await repository.pending(RUN_ID)
        replayed = await repository.lease_attempt(_initial_claim(OWNER_EPOCH + 1))
    assert len(pending) == 1
    assert pending[0].prepared_attempt_id == ATTEMPT_ID
    assert replayed.idempotent_replay is True
    assert replayed.record == original.record


@pytest.mark.anyio
async def test_fresh_resume_never_resends_unclassifiable_response_observed(
    tmp_path: Path,
) -> None:
    run_directory = await _seed_run(tmp_path, state=AttemptState.RESPONSE_OBSERVED)
    await _add_attempt_schedule(run_directory, consumed=True)
    database_path = run_directory / "journal.sqlite3"
    before = database_path.read_bytes()

    with pytest.raises(
        ResumeJournalProjectionError,
        match="response-observed attempt lacks durable response staging",
    ):
        await ResumeService(clock=_clock()).resume(ResumeRequest(run_directory))

    assert database_path.read_bytes() == before
    assert not (run_directory / "run.lock").exists()
    assert _rows(
        run_directory,
        "SELECT state, outcome_category, owner_epoch FROM attempts WHERE attempt_id = ?",
        (ATTEMPT_ID,),
    ) == (
        (
            AttemptState.RESPONSE_OBSERVED.value,
            None,
            OWNER_EPOCH,
        ),
    )
    assert _rows(
        run_directory,
        "SELECT owner_epoch FROM runs WHERE run_id = ?",
        (RUN_ID,),
    ) == ((OWNER_EPOCH,),)
    assert _rows(run_directory, "SELECT count(*) FROM attempt_records") == ((0,),)
    assert _rows(run_directory, "SELECT count(*) FROM recovery_decisions") == ((0,),)


@pytest.mark.anyio
async def test_explicit_observe_requires_and_invokes_only_injected_callback(
    tmp_path: Path,
) -> None:
    run_directory = await _seed_run(
        tmp_path,
        state=AttemptState.UNKNOWN_OUTCOME,
    )
    recorder = _ObservationRecorder()
    bundle = BundleRecoveryPolicy(
        observation_rules=(
            ObservationReconciliationRule(
                scenario_id=SCENARIO_ID,
                delivery_id=DELIVERY_ID,
                observation_id=OBSERVATION_ID,
                assertion_ids=(ASSERTION_ID,),
                read_only=True,
                idempotent=True,
            ),
        )
    )

    result = await ResumeService(
        clock=_clock(),
        observation=recorder,
    ).resume(
        ResumeRequest(
            run_directory,
            invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.OBSERVE),
            bundle_policy=bundle,
        )
    )

    assert result.status is ResumeStatus.AWAIT_OBSERVATION
    assert result.observations_invoked == 1
    assert result.policy_plan is not None
    assert recorder.plans == [result.policy_plan.observations[0]]
    assert _rows(
        run_directory,
        "SELECT attempt_id, state FROM attempts",
    ) == ((ATTEMPT_ID, AttemptState.UNKNOWN_OUTCOME.value),)
    assert _rows(
        run_directory,
        "SELECT policy, decision FROM recovery_decisions",
    ) == (("observe", "observation_requested"),)
