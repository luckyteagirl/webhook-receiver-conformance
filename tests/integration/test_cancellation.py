"""Structured cancellation integration for resumability and bounded cleanup."""
# ruff: noqa: INP001

from __future__ import annotations

import signal
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

import anyio
import pytest

from webhook_receiver_conformance.domain.enums import AttemptState
from webhook_receiver_conformance.domain.identifiers import FreshIdKind, new_fresh_id
from webhook_receiver_conformance.errors import ExitCode, ResultCategory
from webhook_receiver_conformance.journal.repositories import TransitionRepository
from webhook_receiver_conformance.journal.schema import create_run_database
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
    StatementOperation,
)
from webhook_receiver_conformance.journal.transitions import (
    AttemptPhaseEvidence,
    AttemptPhaseEvidenceCommand,
    EntityType,
    TransitionCommand,
)
from webhook_receiver_conformance.runtime.cancellation import (
    InterruptKind,
    run_interruptibly,
)
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
)

if TYPE_CHECKING:
    from pathlib import Path

RUN_ID = "00000000-0000-4000-8000-000000000310"
SCENARIO_ID = "scenario_00000000000000000000000001"
EVENT_ID = "event_00000000000000000000000001"
DELIVERY_ID = "delivery_00000000000000000000000001"
OWNER = 7
NOW = "2026-07-27T19:34:56.000000Z"
CANCELLED_EXIT_CODE = 130
COMPLETED_VALUE = 17


@dataclass(slots=True)
class _TrackedResource:
    entered: anyio.Event
    closed: bool = False

    async def __aenter__(self) -> Self:
        self.entered.set()
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        del exc_type, exc, traceback
        self.closed = True


async def _seed_attempt(service: JournalService, attempt_id: str) -> None:
    digest = f"sha256:{'b' * 64}"
    await service.execute(
        BatchOperation(
            (
                JournalStatement(
                    "INSERT INTO runs (run_id, manifest_id, state, owner_epoch, created_at) "
                    "VALUES (?, ?, 'running', ?, ?)",
                    (RUN_ID, "a" * 64, OWNER, NOW),
                ),
                JournalStatement(
                    "INSERT INTO scenarios (scenario_id, run_id, ordinal, name, state) "
                    "VALUES (?, ?, 0, 'scenario', 'running')",
                    (SCENARIO_ID, RUN_ID),
                ),
                JournalStatement(
                    "INSERT INTO events (event_id, run_id, scenario_id, ordinal, "
                    "event_type, fixture_blob_hash) VALUES (?, ?, ?, 0, 'x', ?)",
                    (EVENT_ID, RUN_ID, SCENARIO_ID, digest),
                ),
                JournalStatement(
                    "INSERT INTO deliveries (delivery_id, run_id, scenario_id, event_id, "
                    "ordinal, step_ordinal, logical_time_ns, state) "
                    "VALUES (?, ?, ?, ?, 0, 0, 0, 'active')",
                    (DELIVERY_ID, RUN_ID, SCENARIO_ID, EVENT_ID),
                ),
                JournalStatement(
                    "INSERT INTO attempts (attempt_id, run_id, scenario_id, event_id, "
                    "delivery_id, ordinal, state, phase) "
                    "VALUES (?, ?, ?, ?, ?, 1, 'claimed', NULL)",
                    (attempt_id, RUN_ID, SCENARIO_ID, EVENT_ID, DELIVERY_ID),
                ),
            )
        )
    )


async def _rows(
    service: JournalService,
    sql: str,
) -> tuple[tuple[object, ...], ...]:
    result = await service.execute(StatementOperation(JournalStatement(sql)))
    return result.rows


@pytest.mark.anyio
async def test_sigint_cancels_task_group_closes_resource_and_returns_130() -> None:
    entered = anyio.Event()
    resource = _TrackedResource(entered)

    async def operation() -> str:
        async with resource:
            await anyio.sleep_forever()
        return "fabricated"

    async def interrupt() -> int:
        await entered.wait()
        return int(signal.SIGINT)

    result = await run_interruptibly(
        operation,
        interrupt,
        interrupt_kind=InterruptKind.SIGINT,
    )

    assert result.interrupted
    assert result.value is None
    assert result.category is ResultCategory.CANCELLED
    assert result.exit_code is ExitCode.CANCELLED
    assert int(result.exit_code) == CANCELLED_EXIT_CODE
    assert result.signal_number == int(signal.SIGINT)
    assert result.cleanup_completed
    assert resource.closed


@pytest.mark.anyio
async def test_known_transition_survives_cancellation_without_receiver_result(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    committed = anyio.Event()
    async with JournalService.open(run.database_path) as service:
        await _seed_attempt(service, attempt_id)
        repository = TransitionRepository(service)

        async def operation() -> str:
            await repository.apply_attempt(
                TransitionCommand(
                    run_id=RUN_ID,
                    transition_id=f"cancel.pre_send.{attempt_id}",
                    entity_type=EntityType.ATTEMPT,
                    entity_id=attempt_id,
                    expected_state=AttemptState.CLAIMED,
                    new_state=AttemptState.PRE_SEND_COMMITTED,
                    trigger_category="attempt_phase",
                    timestamp=clock.transition_timestamp(),
                    owner_epoch=OWNER,
                    idempotency_key=f"cancel.pre_send.{attempt_id}.key",
                    logical_time_ns=0,
                ),
                AttemptPhaseEvidenceCommand(
                    AttemptPhaseEvidence.CONTROLLED_PRE_TRANSPORT,
                    request_blob_hash=f"sha256:{'c' * 64}",
                    request_headers_hash=f"sha256:{'d' * 64}",
                ),
            )
            committed.set()
            await anyio.sleep_forever()
            return "receiver accepted"

        async def interrupt() -> None:
            await committed.wait()

        result = await run_interruptibly(operation, interrupt)
        assert result.exit_code is ExitCode.CANCELLED
        assert result.value is None
        assert await _rows(service, "SELECT state, phase FROM attempts") == (
            ("pre_send_committed", "controlled_pre_transport"),
        )
        assert await _rows(service, "SELECT COUNT(*) FROM attempt_records") == ((0,),)
        assert await _rows(
            service,
            "SELECT state FROM runs",
        ) == (("running",),)

    async with JournalService.open(run.database_path) as reopened:
        assert await _rows(reopened, "SELECT state FROM attempts") == (("pre_send_committed",),)


@pytest.mark.anyio
async def test_cleanup_callbacks_are_bounded_and_completion_is_preserved() -> None:
    cleaned = False

    async def operation() -> int:
        return COMPLETED_VALUE

    async def never_interrupt() -> None:
        await anyio.sleep_forever()

    async def cleanup() -> None:
        nonlocal cleaned
        cleaned = True

    completed = await run_interruptibly(
        operation,
        never_interrupt,
        cleanup_callbacks=(cleanup,),
    )
    assert completed.value == COMPLETED_VALUE
    assert not completed.interrupted
    assert completed.exit_code is ExitCode.PASS
    assert completed.cleanup_completed
    assert cleaned

    async def hanging_cleanup() -> None:
        await anyio.sleep_forever()

    started = time.monotonic()
    bounded = await run_interruptibly(
        operation,
        never_interrupt,
        cleanup_callbacks=(hanging_cleanup,),
        cleanup_timeout_seconds=0.01,
    )
    assert time.monotonic() - started < 1.0
    assert not bounded.cleanup_completed
