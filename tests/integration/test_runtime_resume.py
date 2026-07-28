"""Focused integration coverage for production resume orchestration."""
# ruff: noqa: INP001

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from webhook_receiver_conformance.domain.enums import AttemptState
from webhook_receiver_conformance.journal.run_lock import (
    FilesystemKind,
    ProcessProbe,
    ProcessState,
    RunLockMetadata,
)
from webhook_receiver_conformance.journal.schema import create_run_database
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
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
) -> Path:
    run = create_run_database(root, run_id=RUN_ID)
    outcome = "ambiguous" if state is AttemptState.UNKNOWN_OUTCOME else None
    terminal = WALL_TEXT if outcome is not None else None
    statements = (
        JournalStatement(
            """
            INSERT INTO runs (
                run_id, manifest_id, state, owner_epoch, created_at
            ) VALUES (?, ?, 'running', ?, ?)
            """,
            (RUN_ID, MANIFEST_ID, OWNER_EPOCH, WALL_TEXT),
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
