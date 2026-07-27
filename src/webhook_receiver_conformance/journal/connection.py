"""Version-gated, policy-verified SQLite writer connections."""
# ruff: noqa: INP001

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.types import DiagnosticCode

from .schema import (
    DEFAULT_BUSY_TIMEOUT_MS,
    MAX_BUSY_TIMEOUT_MS,
    SQLITE_SYNCHRONOUS_EXTRA,
    create_journal_database,
    open_journal_database,
)

if TYPE_CHECKING:
    import os

MINIMUM_SQLITE_VERSION = (3, 40, 0)


class JournalConnectionError(RuntimeError):
    """A classified failure to establish the sole journal writer connection."""

    category: ErrorCategory = ErrorCategory.INTEGRITY_ERROR
    code: DiagnosticCode = DiagnosticCode("JOURNAL_CONNECTION_ERROR")


class UnsupportedSQLiteRuntimeError(JournalConnectionError):
    """The linked SQLite runtime is older than the supported baseline."""

    category = ErrorCategory.UNSUPPORTED_CAPABILITY
    code = DiagnosticCode("SQLITE_RUNTIME_UNSUPPORTED")


class JournalConnectionPolicyError(JournalConnectionError):
    """A writer connection does not satisfy the mandatory SQLite policy."""

    code = DiagnosticCode("JOURNAL_CONNECTION_POLICY_INVALID")


@dataclass(frozen=True, slots=True)
class WriterConnectionPolicy:
    """Verified settings for the sole SQLite write connection."""

    foreign_keys: int
    trusted_schema: int
    busy_timeout_ms: int
    journal_mode: str
    synchronous: int
    explicit_transactions: bool


class WriterConnectionFactory(Protocol):
    """Injectable exact writer-connection factory used by the service."""

    def __call__(
        self,
        database_path: str | os.PathLike[str],
        *,
        create: bool,
        busy_timeout_ms: int,
    ) -> sqlite3.Connection:
        """Return one configured exact writer connection."""
        ...


def require_supported_sqlite_runtime(
    version_info: object | None = None,
) -> tuple[int, int, int]:
    """Return a supported SQLite version or fail before filesystem mutation."""
    candidate = sqlite3.sqlite_version_info if version_info is None else version_info
    if not isinstance(candidate, tuple):
        message = "SQLite runtime version metadata is malformed or unsupported"
        raise UnsupportedSQLiteRuntimeError(message)
    candidate_tuple = cast("tuple[object, ...]", candidate)
    if len(candidate_tuple) != len(MINIMUM_SQLITE_VERSION) or any(
        isinstance(component, bool) or not isinstance(component, int)
        for component in candidate_tuple
    ):
        message = "SQLite runtime version metadata is malformed or unsupported"
        raise UnsupportedSQLiteRuntimeError(message)
    normalized = cast("tuple[int, int, int]", candidate_tuple)
    if normalized < MINIMUM_SQLITE_VERSION:
        minimum = ".".join(str(component) for component in MINIMUM_SQLITE_VERSION)
        message = f"SQLite {minimum} or later is required"
        raise UnsupportedSQLiteRuntimeError(message)
    return normalized


def connect_writer_database(
    database_path: str | os.PathLike[str],
    *,
    create: bool,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    sqlite_version_info: object | None = None,
) -> sqlite3.Connection:
    """Create or open one bound writer connection and verify its full policy."""
    require_supported_sqlite_runtime(sqlite_version_info)
    if type(create) is not bool:
        message = "create must be a boolean writer-connection mode"
        raise TypeError(message)
    connection: sqlite3.Connection | None = None
    try:
        if create:
            connection = create_journal_database(
                database_path,
                busy_timeout_ms=busy_timeout_ms,
            )
        else:
            connection = open_journal_database(
                database_path,
                busy_timeout_ms=busy_timeout_ms,
            )
        validate_writer_connection(
            connection,
            expected_busy_timeout_ms=busy_timeout_ms,
        )
    except BaseException:
        if connection is not None:
            connection.close()
        raise
    return connection


def validate_writer_connection(
    connection: sqlite3.Connection,
    *,
    expected_busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> WriterConnectionPolicy:
    """Require DELETE/EXTRA/FK/trusted-schema and explicit transaction mode."""
    if (
        isinstance(expected_busy_timeout_ms, bool)
        or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            expected_busy_timeout_ms,
            int,
        )
        or not 1 <= expected_busy_timeout_ms <= MAX_BUSY_TIMEOUT_MS
    ):
        message = f"expected_busy_timeout_ms must be in the range 1..{MAX_BUSY_TIMEOUT_MS}"
        raise ValueError(message)
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        connection,
        sqlite3.Connection,
    ):
        message = "writer connection must be a sqlite3.Connection"
        raise TypeError(message)
    try:
        journal_mode_row = connection.execute("PRAGMA journal_mode").fetchone()
        journal_mode = (
            str(journal_mode_row[0]).casefold()
            if journal_mode_row is not None and journal_mode_row
            else ""
        )
        policy = WriterConnectionPolicy(
            foreign_keys=_pragma_integer(connection, "foreign_keys"),
            trusted_schema=_pragma_integer(connection, "trusted_schema"),
            busy_timeout_ms=_pragma_integer(connection, "busy_timeout"),
            journal_mode=journal_mode,
            synchronous=_pragma_integer(connection, "synchronous"),
            explicit_transactions=connection.isolation_level is None,
        )
    except (IndexError, TypeError, sqlite3.Error) as error:
        message = "SQLite writer connection policy could not be inspected"
        raise JournalConnectionPolicyError(message) from error
    expected = WriterConnectionPolicy(
        foreign_keys=1,
        trusted_schema=0,
        busy_timeout_ms=expected_busy_timeout_ms,
        journal_mode="delete",
        synchronous=SQLITE_SYNCHRONOUS_EXTRA,
        explicit_transactions=True,
    )
    if policy != expected or connection.in_transaction:
        message = "SQLite writer connection does not satisfy the mandatory policy"
        raise JournalConnectionPolicyError(message)
    return policy


def _pragma_integer(connection: sqlite3.Connection, name: str) -> int:
    if name not in {
        "busy_timeout",
        "foreign_keys",
        "synchronous",
        "trusted_schema",
    }:
        message = "unsupported writer-connection PRAGMA"
        raise JournalConnectionPolicyError(message)
    row = connection.execute(f"PRAGMA {name}").fetchone()
    if row is None or not row:
        message = f"SQLite did not return PRAGMA {name}"
        raise JournalConnectionPolicyError(message)
    value = row[0]
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"SQLite returned a noninteger PRAGMA {name}"
        raise JournalConnectionPolicyError(message)
    return value
