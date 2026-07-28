"""Single-writer journal connection and structured service tests."""
# ruff: noqa: INP001, PLR2004, SLF001

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import anyio
import pytest
from anyio.lowlevel import checkpoint

from webhook_receiver_conformance.journal.connection import (
    JournalConnectionPolicyError,
    UnsupportedSQLiteRuntimeError,
    WriterConnectionPolicy,
    connect_writer_database,
    validate_writer_connection,
)
from webhook_receiver_conformance.journal.schema import (
    DEFAULT_BUSY_TIMEOUT_MS,
    JOURNAL_FILENAME,
)
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalBusyError,
    JournalOperationDefinitionError,
    JournalReentrantOperationError,
    JournalResultLimitError,
    JournalService,
    JournalServiceClosedError,
    JournalServiceState,
    JournalStatement,
    JournalTransaction,
    JournalWriteIntegrityError,
    StatementOperation,
    _QueuedOperation,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    import os
    from pathlib import Path

RUN_ID = "00000000-0000-4000-8000-000000000001"
MANIFEST_ID = "a" * 64
TIMESTAMP = "2026-07-27T12:34:56.000000Z"
SCENARIO_ID = f"scenario_{'0' * 26}"
EVENT_ID = f"event_{'0' * 26}"
DELIVERY_ID = f"delivery_{'0' * 26}"
ATTEMPT_ID = f"attempt_{'0' * 26}"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass(slots=True)
class _RecordingFactory:
    calls: int = 0
    connections: list[sqlite3.Connection] = field(default_factory=list[sqlite3.Connection])
    trace: list[str] = field(default_factory=list[str])

    def __call__(
        self,
        database_path: str | os.PathLike[str],
        *,
        create: bool,
        busy_timeout_ms: int,
    ) -> sqlite3.Connection:
        self.calls += 1
        connection = connect_writer_database(
            database_path,
            create=create,
            busy_timeout_ms=busy_timeout_ms,
        )
        connection.set_trace_callback(self.trace.append)
        self.connections.append(connection)
        return connection


@dataclass(slots=True)
class _InvalidPolicyFactory:
    invalid_policy: str
    connections: list[sqlite3.Connection] = field(default_factory=list[sqlite3.Connection])

    def __call__(
        self,
        database_path: str | os.PathLike[str],
        *,
        create: bool,
        busy_timeout_ms: int,
    ) -> sqlite3.Connection:
        if not create:
            message = "invalid-policy test factory supports create mode only"
            raise AssertionError(message)
        target: str | os.PathLike[str] = (
            ":memory:" if self.invalid_policy == "journal_mode" else database_path
        )
        connection = sqlite3.connect(target, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        if self.invalid_policy == "journal_mode":
            connection.execute("PRAGMA synchronous = EXTRA")
        else:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = NORMAL")
        self.connections.append(connection)
        return connection


@dataclass(frozen=True, slots=True)
class _RaiseAfterWrite:
    statement: JournalStatement
    error: BaseException

    def execute(self, transaction: JournalTransaction) -> None:
        transaction.execute(self.statement)
        raise self.error


@dataclass(frozen=True, slots=True)
class _CancelCallerAfterWrite:
    statement: JournalStatement
    caller_scope: anyio.CancelScope

    def execute(self, transaction: JournalTransaction) -> None:
        transaction.execute(self.statement)
        self.caller_scope.cancel()


@dataclass(frozen=True, slots=True)
class _DirectCommit:
    statement: JournalStatement
    connection: sqlite3.Connection

    def execute(self, transaction: JournalTransaction) -> None:
        transaction.execute(self.statement)
        self.connection.commit()


@dataclass(frozen=True, slots=True)
class _ReturnAwaitable:
    service: JournalService

    def execute(self, transaction: JournalTransaction) -> object:
        del transaction
        return self.service.execute(StatementOperation(JournalStatement("SELECT 1")))


@dataclass(frozen=True, slots=True)
class _SubmitReentrantly:
    service: JournalService

    def execute(self, transaction: JournalTransaction) -> None:
        del transaction
        nested = self.service.execute(StatementOperation(JournalStatement("SELECT 1")))
        try:
            nested.send(None)
        finally:
            nested.close()


@dataclass(slots=True)
class _SerialState:
    active: int = 0
    maximum_active: int = 0
    execution_order: list[int] = field(default_factory=list[int])


@dataclass(frozen=True, slots=True)
class _SerialInsert:
    value: int
    state: _SerialState

    def execute(self, transaction: JournalTransaction) -> int:
        self.state.active += 1
        self.state.maximum_active = max(self.state.maximum_active, self.state.active)
        try:
            transaction.execute(
                JournalStatement(
                    "INSERT INTO service_probe (value) VALUES (?)",
                    (self.value,),
                )
            )
            self.state.execution_order.append(self.value)
            return self.value
        finally:
            self.state.active -= 1


def _insert_run_statement() -> JournalStatement:
    return JournalStatement(
        """
        INSERT INTO runs (run_id, manifest_id, state, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (RUN_ID, MANIFEST_ID, "planned", TIMESTAMP),
    )


async def _run_count(service: JournalService) -> int:
    result = await service.execute(
        StatementOperation(JournalStatement("SELECT count(*) FROM runs"))
    )
    value = result.rows[0][0]
    assert type(value) is int
    return value


def test_statement_rejects_connection_control_bypasses() -> None:
    unsafe = (
        "-- leading comment\nPRAGMA foreign_keys = OFF",
        "/* leading comment */ BEGIN DEFERRED",
        "EXPLAIN PRAGMA foreign_keys",
        "\n/* one */ -- two\nROLLBACK",
        "ATTACH DATABASE ':memory:' AS escaped",
    )

    for sql in unsafe:
        with pytest.raises(JournalOperationDefinitionError):
            JournalStatement(sql)


def test_statement_and_batch_boundaries_reject_malformed_inputs() -> None:
    with pytest.raises(JournalOperationDefinitionError):
        JournalStatement("")
    with pytest.raises(JournalOperationDefinitionError):
        JournalStatement("SELECT ?", [1])  # pyright: ignore[reportArgumentType]
    with pytest.raises(JournalOperationDefinitionError):
        JournalStatement("SELECT ?", (object(),))  # pyright: ignore[reportArgumentType]
    with pytest.raises(JournalOperationDefinitionError):
        BatchOperation(())


@pytest.mark.anyio
async def test_old_sqlite_is_rejected_before_factory_or_database_creation(
    tmp_path: Path,
) -> None:
    database = tmp_path / JOURNAL_FILENAME
    factory = _RecordingFactory()

    with pytest.raises(UnsupportedSQLiteRuntimeError):
        async with JournalService.create(
            database,
            sqlite_version_info=(3, 39, 4),
            connection_factory=factory,
        ):
            pass

    assert factory.calls == 0
    assert not database.exists()


@pytest.mark.parametrize("invalid_policy", ["journal_mode", "synchronous"])
@pytest.mark.anyio
async def test_startup_rejects_wrong_writer_policy(
    tmp_path: Path,
    invalid_policy: str,
) -> None:
    factory = _InvalidPolicyFactory(invalid_policy)

    with pytest.raises(JournalConnectionPolicyError):
        async with JournalService.create(
            tmp_path / f"{invalid_policy}.sqlite3",
            connection_factory=factory,
        ):
            pass

    assert len(factory.connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        factory.connections[0].execute("SELECT 1")


@pytest.mark.anyio
async def test_one_connection_uses_verified_policy_and_explicit_transactions(
    tmp_path: Path,
) -> None:
    factory = _RecordingFactory()
    database = tmp_path / JOURNAL_FILENAME

    async with JournalService.create(database, connection_factory=factory) as service:
        result = await service.execute(StatementOperation(_insert_run_statement()))
        assert result.rowcount == 1
        assert service.connection_policy == WriterConnectionPolicy(
            foreign_keys=1,
            trusted_schema=0,
            busy_timeout_ms=DEFAULT_BUSY_TIMEOUT_MS,
            journal_mode="delete",
            synchronous=3,
            explicit_transactions=True,
        )

    assert factory.calls == 1
    normalized = [statement.strip().upper() for statement in factory.trace]
    assert normalized.count("BEGIN IMMEDIATE") == 1
    assert normalized.count("COMMIT") == 1
    assert "BEGIN" not in normalized
    assert all(
        not statement.startswith("BEGIN ") or statement == "BEGIN IMMEDIATE"
        for statement in normalized
    )


@pytest.mark.anyio
async def test_orphan_attempt_is_rejected_and_rolled_back(tmp_path: Path) -> None:
    async with JournalService.create(tmp_path / JOURNAL_FILENAME) as service:
        orphan = JournalStatement(
            """
            INSERT INTO attempts (
                attempt_id,
                run_id,
                scenario_id,
                event_id,
                delivery_id,
                ordinal,
                state
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ATTEMPT_ID,
                RUN_ID,
                SCENARIO_ID,
                EVENT_ID,
                DELIVERY_ID,
                0,
                "scheduled",
            ),
        )

        with pytest.raises(JournalWriteIntegrityError):
            await service.execute(StatementOperation(orphan))

        result = await service.execute(
            StatementOperation(JournalStatement("SELECT count(*) FROM attempts"))
        )
        assert result.rows == ((0,),)


@pytest.mark.anyio
async def test_operation_error_rolls_back_without_partial_write(tmp_path: Path) -> None:
    async with JournalService.create(tmp_path / JOURNAL_FILENAME) as service:
        failure = RuntimeError("injected operation failure")

        with pytest.raises(RuntimeError, match="injected operation failure"):
            await service.execute(_RaiseAfterWrite(_insert_run_statement(), failure))

        assert await _run_count(service) == 0


@pytest.mark.anyio
async def test_operation_cancellation_rolls_back_without_partial_write(tmp_path: Path) -> None:
    cancelled_class = anyio.get_cancelled_exc_class()
    async with JournalService.create(tmp_path / JOURNAL_FILENAME) as service:
        with pytest.raises(cancelled_class):
            await service.execute(_RaiseAfterWrite(_insert_run_statement(), cancelled_class()))

        assert await _run_count(service) == 0


@pytest.mark.anyio
async def test_post_enqueue_caller_cancellation_returns_commit_before_checkpoint(
    tmp_path: Path,
) -> None:
    cancelled_class = anyio.get_cancelled_exc_class()
    async with JournalService.create(tmp_path / JOURNAL_FILENAME) as service:
        cancellation_observed = False
        commit_returned = False
        with anyio.CancelScope() as caller_scope:
            try:
                await service.execute(
                    _CancelCallerAfterWrite(_insert_run_statement(), caller_scope)
                )
                commit_returned = True
                await checkpoint()
            except cancelled_class:
                cancellation_observed = True

        assert commit_returned
        assert cancellation_observed
        assert await _run_count(service) == 1


@pytest.mark.anyio
async def test_direct_transaction_escape_is_denied_and_rolled_back(tmp_path: Path) -> None:
    factory = _RecordingFactory()
    async with JournalService.create(
        tmp_path / JOURNAL_FILENAME,
        connection_factory=factory,
    ) as service:
        with pytest.raises(JournalWriteIntegrityError):
            await service.execute(_DirectCommit(_insert_run_statement(), factory.connections[0]))

        assert await _run_count(service) == 0


@pytest.mark.anyio
async def test_returned_awaitable_is_rejected_without_reentrant_submission(
    tmp_path: Path,
) -> None:
    async with JournalService.create(tmp_path / JOURNAL_FILENAME) as service:
        with pytest.raises(JournalReentrantOperationError):
            await service.execute(_ReturnAwaitable(service))

        assert await _run_count(service) == 0


@pytest.mark.anyio
async def test_reentrant_submission_is_rejected_without_deadlock(tmp_path: Path) -> None:
    async with JournalService.create(tmp_path / JOURNAL_FILENAME) as service:
        with pytest.raises(JournalReentrantOperationError):
            await service.execute(_SubmitReentrantly(service))

        assert await _run_count(service) == 0


@pytest.mark.anyio
async def test_result_materialization_has_a_hard_row_limit(tmp_path: Path) -> None:
    too_many_rows = JournalStatement(
        """
        WITH RECURSIVE values_over_limit(value) AS (
            VALUES (1)
            UNION ALL
            SELECT value + 1 FROM values_over_limit WHERE value <= 10000
        )
        SELECT value FROM values_over_limit
        """
    )
    async with JournalService.create(tmp_path / JOURNAL_FILENAME) as service:
        with pytest.raises(JournalResultLimitError):
            await service.execute(StatementOperation(too_many_rows))

        assert await _run_count(service) == 0


@pytest.mark.anyio
async def test_concurrent_callers_are_fifo_serialized_on_one_writer(
    tmp_path: Path,
) -> None:
    factory = _RecordingFactory()
    state = _SerialState()
    results: list[int | None] = [None] * 32

    async with JournalService.create(
        tmp_path / JOURNAL_FILENAME,
        queue_capacity=4,
        connection_factory=factory,
    ) as service:
        await service.execute(
            StatementOperation(
                JournalStatement(
                    """
                    CREATE TABLE service_probe (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        value INTEGER NOT NULL UNIQUE
                    ) STRICT
                    """
                )
            )
        )

        async def submit(index: int) -> None:
            results[index] = await service.execute(_SerialInsert(index, state))

        async with anyio.create_task_group() as task_group:
            for index in range(len(results)):
                task_group.start_soon(submit, index)

        projection = await service.execute(
            StatementOperation(
                JournalStatement("SELECT value FROM service_probe ORDER BY sequence")
            )
        )

    assert factory.calls == 1
    assert state.maximum_active == 1
    assert state.active == 0
    assert state.execution_order == list(range(len(results)))
    assert results == list(range(len(results)))
    assert projection.rows == tuple((index,) for index in range(len(results)))


@pytest.mark.anyio
async def test_queue_is_bounded_and_shutdown_resolves_all_concurrent_callers(
    tmp_path: Path,
) -> None:
    outcomes: list[str] = []
    async with JournalService.create(
        tmp_path / JOURNAL_FILENAME,
        queue_capacity=2,
    ) as service:

        async def submit(index: int) -> None:
            try:
                await service.execute(StatementOperation(JournalStatement("SELECT ?", (index,))))
            except JournalServiceClosedError:
                outcomes.append("closed")
            else:
                outcomes.append("committed")

        async with anyio.create_task_group() as task_group:
            for index in range(64):
                task_group.start_soon(submit, index)
            await checkpoint()
            await service.aclose()

        statistics = service.queue_statistics()
        assert service.state is JournalServiceState.CLOSED
        assert statistics.capacity == 2
        assert statistics.buffered == 0
        assert statistics.accepted_operations == statistics.completed_operations

    assert len(outcomes) == 64
    assert "closed" in outcomes


@pytest.mark.anyio
async def test_clean_idle_close_is_terminal_and_idempotent(tmp_path: Path) -> None:
    async with JournalService.create(tmp_path / JOURNAL_FILENAME) as service:
        await service.aclose()
        await service.aclose()
        assert service.state is JournalServiceState.CLOSED


@pytest.mark.anyio
async def test_worker_task_cancellation_closes_stream_and_connection(
    tmp_path: Path,
) -> None:
    connection = connect_writer_database(
        tmp_path / JOURNAL_FILENAME,
        create=True,
    )
    policy = validate_writer_connection(connection)
    send, receive = anyio.create_memory_object_stream[_QueuedOperation](1)
    service = JournalService(
        connection=connection,
        policy=policy,
        queue_capacity=1,
        send_stream=send,
        receive_stream=receive,
    )
    queued = _QueuedOperation(
        operation=StatementOperation(JournalStatement("SELECT 1")),
        completed=anyio.Event(),
    )
    send.send_nowait(queued)

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(
            service._serve,  # pyright: ignore[reportPrivateUsage]
        )
        task_group.cancel_scope.cancel()

    assert service.state is JournalServiceState.CLOSED
    assert queued.completed.is_set()
    assert isinstance(queued.error, JournalServiceClosedError)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


@pytest.mark.anyio
async def test_context_cancellation_performs_structured_shutdown(tmp_path: Path) -> None:
    service: JournalService | None = None
    with anyio.CancelScope() as scope:
        async with JournalService.create(tmp_path / JOURNAL_FILENAME) as opened:
            service = opened
            scope.cancel()
            await anyio.sleep_forever()

    assert service is not None
    assert service.state is JournalServiceState.CLOSED


@pytest.mark.anyio
async def test_busy_timeout_is_classified_and_service_recovers(tmp_path: Path) -> None:
    database = tmp_path / JOURNAL_FILENAME
    async with JournalService.create(database, busy_timeout_ms=1) as service:
        competing_writer = sqlite3.connect(database, isolation_level=None)
        try:
            competing_writer.execute("BEGIN IMMEDIATE")
            with pytest.raises(JournalBusyError):
                await service.execute(
                    StatementOperation(JournalStatement("SELECT count(*) FROM runs"))
                )
            competing_writer.execute("ROLLBACK")
        finally:
            if competing_writer.in_transaction:
                competing_writer.execute("ROLLBACK")
            competing_writer.close()

        assert await _run_count(service) == 0


@pytest.mark.anyio
async def test_queue_capacity_rejects_malformed_and_accepts_boundary_values(
    tmp_path: Path,
) -> None:
    for invalid in (True, 0, 4_097):
        with pytest.raises(ValueError, match="queue_capacity"):
            async with JournalService.create(
                tmp_path / f"invalid-{invalid}.sqlite3",
                queue_capacity=invalid,  # pyright: ignore[reportArgumentType]
            ):
                pass

    for valid in (1, 4_096):
        directory = tmp_path / f"valid-{valid}"
        directory.mkdir()
        async with JournalService.create(
            directory / JOURNAL_FILENAME,
            queue_capacity=valid,
        ) as service:
            assert service.queue_capacity == valid
