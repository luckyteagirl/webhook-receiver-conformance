"""Structured, bounded, single-writer SQLite journal service."""
# ruff: noqa: INP001

from __future__ import annotations

import inspect
import math
import re
import sqlite3
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

import anyio

from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.types import DiagnosticCode

from .connection import (
    WriterConnectionFactory,
    WriterConnectionPolicy,
    connect_writer_database,
    require_supported_sqlite_runtime,
    validate_writer_connection,
)
from .schema import DEFAULT_BUSY_TIMEOUT_MS

if TYPE_CHECKING:
    import os
    from collections.abc import AsyncGenerator

    from anyio.streams.memory import (
        MemoryObjectReceiveStream,
        MemoryObjectSendStream,
    )

DEFAULT_QUEUE_CAPACITY = 64
MAX_QUEUE_CAPACITY = 4_096
MAX_OPERATION_STATEMENTS = 512
MAX_SQL_BYTES = 1_048_576
MAX_SQL_PARAMETERS = 1_024
MAX_PARAMETER_BYTES = 16_777_216
MAX_RESULT_ROWS = 10_000
MAX_RESULT_COLUMNS = 256
MAX_RESULT_BYTES = 16_777_216

_UNSAFE_SQL_PREFIX = re.compile(
    r"(?:BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE|PRAGMA|VACUUM|ATTACH|DETACH|EXPLAIN)\b",
    flags=re.IGNORECASE,
)
_CONNECTION_CONTROL_ACTIONS = frozenset(
    {
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_DETACH,
        sqlite3.SQLITE_PRAGMA,
        sqlite3.SQLITE_SAVEPOINT,
        sqlite3.SQLITE_TRANSACTION,
    }
)
_MISSING = object()

type SqlValue = int | float | str | bytes | None


class JournalServiceError(RuntimeError):
    """A classified journal writer service failure."""

    category: ErrorCategory = ErrorCategory.INTEGRITY_ERROR
    code: DiagnosticCode = DiagnosticCode("JOURNAL_SERVICE_ERROR")


class JournalServiceClosedError(JournalServiceError):
    """The service no longer accepts or starts queued operations."""

    category = ErrorCategory.CANCELLED
    code = DiagnosticCode("JOURNAL_SERVICE_CLOSED")


class JournalOperationDefinitionError(JournalServiceError):
    """An operation attempted unsafe or unbounded SQL behavior."""

    category = ErrorCategory.INVALID_PARAMETER
    code = DiagnosticCode("JOURNAL_OPERATION_INVALID")


class JournalReentrantOperationError(JournalOperationDefinitionError):
    """A writer operation attempted to submit nested async writer work."""

    code = DiagnosticCode("JOURNAL_OPERATION_REENTRANT")


class JournalResultLimitError(JournalServiceError):
    """A SQL result exceeded its in-process materialization boundary."""

    category = ErrorCategory.RESOURCE_LIMIT
    code = DiagnosticCode("JOURNAL_RESULT_LIMIT")


class JournalBusyError(JournalServiceError):
    """SQLite could not acquire the explicit immediate write transaction."""

    category = ErrorCategory.JOURNAL_BUSY
    code = DiagnosticCode("JOURNAL_BUSY")


class JournalWriteIntegrityError(JournalServiceError):
    """SQLite rejected a write or reported database inconsistency."""

    category = ErrorCategory.INTEGRITY_ERROR
    code = DiagnosticCode("JOURNAL_WRITE_INTEGRITY")


class JournalTransactionError(JournalServiceError):
    """An explicit transaction could not safely commit or roll back."""

    category = ErrorCategory.INTEGRITY_ERROR
    code = DiagnosticCode("JOURNAL_TRANSACTION_ERROR")


class JournalServiceState(StrEnum):
    """Lifecycle states for one structured writer service."""

    RUNNING = "running"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class JournalStatement:
    """One bounded SQL statement with immutable positional parameters."""

    sql: str
    parameters: tuple[SqlValue, ...] = ()

    def __post_init__(self) -> None:
        """Validate the immutable SQL and parameter resource boundaries."""
        if (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.sql,
                str,
            )
            or not self.sql.strip()
        ):
            message = "journal SQL must be a nonempty string"
            raise JournalOperationDefinitionError(message)
        if "\x00" in self.sql:
            message = "journal SQL must not contain NUL bytes"
            raise JournalOperationDefinitionError(message)
        try:
            sql_bytes = self.sql.encode("utf-8")
        except UnicodeEncodeError as error:
            message = "journal SQL must contain Unicode scalar values"
            raise JournalOperationDefinitionError(message) from error
        if len(sql_bytes) > MAX_SQL_BYTES:
            message = "journal SQL exceeds the byte limit"
            raise JournalOperationDefinitionError(message)
        if _statement_controls_connection(self.sql):
            message = "journal operations cannot control transactions or connection policy"
            raise JournalOperationDefinitionError(message)
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.parameters,
            tuple,
        ):
            message = "journal SQL parameters must be an immutable tuple"
            raise JournalOperationDefinitionError(message)
        if len(self.parameters) > MAX_SQL_PARAMETERS:
            message = "journal SQL contains too many parameters"
            raise JournalOperationDefinitionError(message)
        parameter_bytes = 0
        for value in self.parameters:
            parameter_bytes += _validate_sql_value(value, parameter=True)
        if parameter_bytes > MAX_PARAMETER_BYTES:
            message = "journal SQL parameters exceed the byte limit"
            raise JournalOperationDefinitionError(message)


@dataclass(frozen=True, slots=True)
class StatementResult:
    """Materialized, connection-free result of one SQL statement."""

    rows: tuple[tuple[SqlValue, ...], ...]
    rowcount: int
    lastrowid: int | None


class JournalTransaction:
    """Restricted synchronous SQL boundary inside one explicit transaction."""

    __slots__ = ("__connection", "__statement_count")

    def __init__(self, connection: sqlite3.Connection) -> None:
        """Bind the restricted boundary to one active writer transaction."""
        self.__connection = connection
        self.__statement_count = 0

    def execute(self, statement: JournalStatement) -> StatementResult:
        """Execute parameterized SQL and return a bounded detached result."""
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            statement,
            JournalStatement,
        ):
            message = "journal transactions accept only JournalStatement values"
            raise JournalOperationDefinitionError(message)
        self.__statement_count += 1
        if self.__statement_count > MAX_OPERATION_STATEMENTS:
            message = "journal operation contains too many SQL statements"
            raise JournalOperationDefinitionError(message)
        cursor = self.__connection.execute(statement.sql, statement.parameters)
        rows: tuple[tuple[SqlValue, ...], ...] = ()
        if cursor.description is not None:
            if len(cursor.description) > MAX_RESULT_COLUMNS:
                message = "journal result contains too many columns"
                raise JournalResultLimitError(message)
            fetched = cursor.fetchmany(MAX_RESULT_ROWS + 1)
            if len(fetched) > MAX_RESULT_ROWS:
                message = "journal result contains too many rows"
                raise JournalResultLimitError(message)
            detached_rows: list[tuple[SqlValue, ...]] = []
            result_bytes = 0
            for row in fetched:
                detached: list[SqlValue] = []
                for value in row:
                    result_bytes += _validate_sql_value(value, parameter=False)
                    detached.append(value)
                if result_bytes > MAX_RESULT_BYTES:
                    message = "journal result exceeds the byte limit"
                    raise JournalResultLimitError(message)
                detached_rows.append(tuple(detached))
            rows = tuple(detached_rows)
        lastrowid = cursor.lastrowid
        if lastrowid is not None and (
            isinstance(lastrowid, bool)
            or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                lastrowid,
                int,
            )
        ):
            message = "SQLite returned an invalid lastrowid"
            raise JournalWriteIntegrityError(message)
        return StatementResult(
            rows=rows,
            rowcount=cursor.rowcount,
            lastrowid=lastrowid,
        )


@runtime_checkable
class JournalOperation[T](Protocol):
    """Typed synchronous operation executed by the sole writer task."""

    def execute(self, transaction: JournalTransaction) -> T:
        """Run synchronously inside the service-owned transaction."""
        ...


@dataclass(frozen=True, slots=True)
class StatementOperation:
    """Convenience operation for one parameterized statement."""

    statement: JournalStatement

    def execute(self, transaction: JournalTransaction) -> StatementResult:
        """Execute the operation's sole statement."""
        return transaction.execute(self.statement)


@dataclass(frozen=True, slots=True)
class BatchOperation:
    """Convenience operation for one bounded atomic statement batch."""

    statements: tuple[JournalStatement, ...]

    def __post_init__(self) -> None:
        """Validate that the immutable batch is nonempty and bounded."""
        if (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.statements,
                tuple,
            )
            or not self.statements
            or len(self.statements) > MAX_OPERATION_STATEMENTS
            or not all(
                isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                    statement,
                    JournalStatement,
                )
                for statement in self.statements
            )
        ):
            message = "batch statements must be a bounded nonempty JournalStatement tuple"
            raise JournalOperationDefinitionError(message)

    def execute(
        self,
        transaction: JournalTransaction,
    ) -> tuple[StatementResult, ...]:
        """Execute every statement atomically and preserve input order."""
        return tuple(transaction.execute(statement) for statement in self.statements)


@dataclass(frozen=True, slots=True)
class JournalQueueStatistics:
    """Bounded queue observability without exposing the underlying stream."""

    capacity: int
    buffered: int
    waiting_senders: int
    accepted_operations: int
    completed_operations: int


@dataclass(slots=True)
class _QueuedOperation:
    operation: JournalOperation[object]
    completed: anyio.Event
    result: object = _MISSING
    error: BaseException | None = None


_ACTIVE_WRITER_SERVICE: ContextVar[JournalService | None] = ContextVar(
    "active_journal_writer_service",
    default=None,
)


class JournalService:
    """One structured AnyIO worker owning exactly one SQLite write connection."""

    __slots__ = (
        "_accepted_operations",
        "_closed",
        "_completed_operations",
        "_connection",
        "_policy",
        "_queue_capacity",
        "_receive",
        "_send",
        "_state",
    )

    def __init__(
        self,
        *,
        connection: sqlite3.Connection,
        policy: WriterConnectionPolicy,
        queue_capacity: int,
        send_stream: MemoryObjectSendStream[_QueuedOperation],
        receive_stream: MemoryObjectReceiveStream[_QueuedOperation],
    ) -> None:
        """Bind one validated connection to one bounded operation stream."""
        self._connection = connection
        self._policy = policy
        self._queue_capacity = queue_capacity
        self._send = send_stream
        self._receive = receive_stream
        self._closed = anyio.Event()
        self._state = JournalServiceState.RUNNING
        self._accepted_operations = 0
        self._completed_operations = 0

    @classmethod
    def create(
        cls,
        database_path: str | os.PathLike[str],
        *,
        queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        sqlite_version_info: object | None = None,
        connection_factory: WriterConnectionFactory = connect_writer_database,
    ) -> AbstractAsyncContextManager[JournalService]:
        """Return a structured context that creates one new journal writer."""
        return cls._managed(
            database_path,
            create=True,
            queue_capacity=queue_capacity,
            busy_timeout_ms=busy_timeout_ms,
            sqlite_version_info=sqlite_version_info,
            connection_factory=connection_factory,
        )

    @classmethod
    def open(
        cls,
        database_path: str | os.PathLike[str],
        *,
        queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        sqlite_version_info: object | None = None,
        connection_factory: WriterConnectionFactory = connect_writer_database,
    ) -> AbstractAsyncContextManager[JournalService]:
        """Return a structured context that opens one existing journal writer."""
        return cls._managed(
            database_path,
            create=False,
            queue_capacity=queue_capacity,
            busy_timeout_ms=busy_timeout_ms,
            sqlite_version_info=sqlite_version_info,
            connection_factory=connection_factory,
        )

    @classmethod
    @asynccontextmanager
    async def _managed(  # noqa: PLR0913
        cls,
        database_path: str | os.PathLike[str],
        *,
        create: bool,
        queue_capacity: int,
        busy_timeout_ms: int,
        sqlite_version_info: object | None,
        connection_factory: WriterConnectionFactory,
    ) -> AsyncGenerator[JournalService]:
        _validate_queue_capacity(queue_capacity)
        require_supported_sqlite_runtime(sqlite_version_info)
        connection: sqlite3.Connection | None = None
        service: JournalService | None = None
        try:
            connection = connection_factory(
                database_path,
                create=create,
                busy_timeout_ms=busy_timeout_ms,
            )
            connection.enable_load_extension(False)  # noqa: FBT003
            policy = validate_writer_connection(
                connection,
                expected_busy_timeout_ms=busy_timeout_ms,
            )
            send_stream, receive_stream = anyio.create_memory_object_stream[_QueuedOperation](
                queue_capacity
            )
            service = cls(
                connection=connection,
                policy=policy,
                queue_capacity=queue_capacity,
                send_stream=send_stream,
                receive_stream=receive_stream,
            )
            async with anyio.create_task_group() as task_group:
                task_group.start_soon(service._serve)
                try:
                    yield service
                finally:
                    await service.aclose()
        except BaseException:
            if connection is not None and (
                service is None or service.state is not JournalServiceState.CLOSED
            ):
                connection.close()
            raise

    @property
    def state(self) -> JournalServiceState:
        """Return the current service lifecycle state."""
        return self._state

    @property
    def connection_policy(self) -> WriterConnectionPolicy:
        """Return the immutable policy verified during startup."""
        return self._policy

    @property
    def queue_capacity(self) -> int:
        """Return the configured hard queue capacity."""
        return self._queue_capacity

    def queue_statistics(self) -> JournalQueueStatistics:
        """Return bounded stream counters and service operation totals."""
        statistics = self._send.statistics()
        return JournalQueueStatistics(
            capacity=self._queue_capacity,
            buffered=statistics.current_buffer_used,
            waiting_senders=statistics.tasks_waiting_send,
            accepted_operations=self._accepted_operations,
            completed_operations=self._completed_operations,
        )

    async def execute[T](self, operation: JournalOperation[T]) -> T:
        """Queue one typed operation and await its durable terminal outcome."""
        if _ACTIVE_WRITER_SERVICE.get() is self:
            message = "journal writer operations cannot submit reentrant work"
            raise JournalReentrantOperationError(message)
        if self._state is not JournalServiceState.RUNNING:
            message = "journal service is not accepting operations"
            raise JournalServiceClosedError(message)
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            operation,
            JournalOperation,
        ):
            message = "operation must implement the synchronous JournalOperation protocol"
            raise JournalOperationDefinitionError(message)
        request = _QueuedOperation(
            operation=cast("JournalOperation[object]", operation),
            completed=anyio.Event(),
        )
        with anyio.CancelScope(shield=True):
            try:
                await self._send.send(request)
            except (anyio.BrokenResourceError, anyio.ClosedResourceError) as error:
                message = "journal service closed before accepting the operation"
                raise JournalServiceClosedError(message) from error
            self._accepted_operations += 1
            await request.completed.wait()
        if request.error is not None:
            raise request.error
        if request.result is _MISSING:
            message = "journal operation completed without a terminal result"
            raise JournalTransactionError(message)
        return cast("T", request.result)

    async def aclose(self) -> None:
        """Stop acceptance, reject queued work, and close after the active transaction."""
        with anyio.CancelScope(shield=True):
            if self._state is JournalServiceState.CLOSED:
                return
            if self._state is JournalServiceState.RUNNING:
                self._state = JournalServiceState.CLOSING
                await self._send.aclose()
            await self._closed.wait()

    async def _serve(self) -> None:
        token = _ACTIVE_WRITER_SERVICE.set(self)
        try:
            async for request in self._receive:
                if self._state is not JournalServiceState.RUNNING:
                    request.error = _shutdown_error()
                else:
                    try:
                        request.result = _run_operation(
                            self._connection,
                            request.operation,
                        )
                    except BaseException as error:  # noqa: BLE001
                        request.error = error
                self._completed_operations += 1
                request.completed.set()
        finally:
            _ACTIVE_WRITER_SERVICE.reset(token)
            with anyio.CancelScope(shield=True):
                try:
                    await self._send.aclose()
                    self._completed_operations += _reject_buffered_operations(self._receive)
                finally:
                    try:
                        await self._receive.aclose()
                    finally:
                        try:
                            self._connection.close()
                        finally:
                            self._state = JournalServiceState.CLOSED
                            self._closed.set()


def _run_operation(
    connection: sqlite3.Connection,
    operation: JournalOperation[object],
) -> object:
    try:
        connection.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as error:
        raise _map_sqlite_error(error) from error
    try:
        connection.set_authorizer(_deny_connection_control)
        try:
            result = _require_synchronous_result(operation.execute(JournalTransaction(connection)))
        finally:
            connection.set_authorizer(None)
        _require_active_transaction(connection)
        connection.execute("COMMIT")
    except BaseException as error:
        connection.set_authorizer(None)
        _rollback_after_failure(connection)
        if isinstance(error, sqlite3.Error):
            raise _map_sqlite_error(error) from error
        raise
    return result


def _require_synchronous_result(result: object) -> object:
    if inspect.isawaitable(result):
        if inspect.iscoroutine(result):
            result.close()
        message = "journal operations must not return awaitable or reentrant work"
        raise JournalReentrantOperationError(message)
    return result


def _require_active_transaction(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        message = "journal operation escaped its explicit transaction"
        raise JournalTransactionError(message)


def _rollback_after_failure(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        return
    try:
        connection.execute("ROLLBACK")
    except sqlite3.Error as rollback_error:
        message = "journal transaction failed and could not roll back"
        raise JournalTransactionError(message) from rollback_error


def _deny_connection_control(
    action_code: int,
    _argument_one: str | None,
    _argument_two: str | None,
    _database_name: str | None,
    _trigger_name: str | None,
) -> int:
    if action_code in _CONNECTION_CONTROL_ACTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _map_sqlite_error(error: sqlite3.Error) -> JournalServiceError:
    sqlite_error_code = getattr(error, "sqlite_errorcode", None)
    if isinstance(sqlite_error_code, int) and sqlite_error_code & 0xFF in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }:
        return JournalBusyError("SQLite writer transaction is busy")
    if isinstance(error, sqlite3.IntegrityError):
        return JournalWriteIntegrityError("SQLite rejected journal integrity constraints")
    return JournalWriteIntegrityError("SQLite rejected the journal write transaction")


def _reject_buffered_operations(
    receive_stream: MemoryObjectReceiveStream[_QueuedOperation],
) -> int:
    rejected = 0
    while True:
        try:
            request = receive_stream.receive_nowait()
        except (anyio.ClosedResourceError, anyio.EndOfStream, anyio.WouldBlock):
            return rejected
        request.error = _shutdown_error()
        request.completed.set()
        rejected += 1


def _shutdown_error() -> JournalServiceClosedError:
    return JournalServiceClosedError("journal service shut down before the queued operation began")


def _statement_controls_connection(statement: str) -> bool:
    remainder = statement.lstrip()
    while remainder:
        if remainder.startswith("--"):
            newline = remainder.find("\n")
            if newline < 0:
                message = "journal SQL must contain an executable statement"
                raise JournalOperationDefinitionError(message)
            remainder = remainder[newline + 1 :].lstrip()
            continue
        if remainder.startswith("/*"):
            closing = remainder.find("*/", 2)
            if closing < 0:
                message = "journal SQL contains an unterminated comment"
                raise JournalOperationDefinitionError(message)
            remainder = remainder[closing + 2 :].lstrip()
            continue
        break
    if not remainder:
        message = "journal SQL must contain an executable statement"
        raise JournalOperationDefinitionError(message)
    return _UNSAFE_SQL_PREFIX.match(remainder) is not None


def _validate_sql_value(value: object, *, parameter: bool) -> int:
    if value is None:
        return 0
    if type(value) is int or type(value) is float:
        if isinstance(value, float) and not math.isfinite(value):
            message = "journal SQL values must not contain non-finite numbers"
            raise JournalOperationDefinitionError(message)
        return 8
    if isinstance(value, str):
        try:
            return len(value.encode("utf-8"))
        except UnicodeEncodeError as error:
            message = "journal SQL text values must contain Unicode scalar values"
            raise JournalOperationDefinitionError(message) from error
    if isinstance(value, bytes):
        return len(value)
    kind = "parameter" if parameter else "result"
    message = f"journal SQL {kind} contains an unsupported value type"
    raise JournalOperationDefinitionError(message)


def _validate_queue_capacity(value: int) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            value,
            int,
        )
        or not 1 <= value <= MAX_QUEUE_CAPACITY
    ):
        message = f"queue_capacity must be in the range 1..{MAX_QUEUE_CAPACITY}"
        raise ValueError(message)
