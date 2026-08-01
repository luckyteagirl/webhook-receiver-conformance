"""Secure SQLite bootstrap and append-only forward migration support."""
# ruff: noqa: INP001

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import re
import sqlite3
import stat
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Final, Protocol, cast

from webhook_receiver_conformance.domain.identifiers import new_run_id, validate_run_id
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.types import DiagnosticCode
from webhook_receiver_conformance.version import VERSION_METADATA

from .migrations.v0001_initial import (
    MIGRATION_ID as INITIAL_MIGRATION_ID,
)
from .migrations.v0001_initial import (
    MIGRATION_NAME as INITIAL_MIGRATION_NAME,
)
from .migrations.v0001_initial import (
    STATEMENTS as INITIAL_MIGRATION_STATEMENTS,
)
from .migrations.v0002_attempt_records import (
    MIGRATION_ID as ATTEMPT_RECORDS_MIGRATION_ID,
)
from .migrations.v0002_attempt_records import (
    MIGRATION_NAME as ATTEMPT_RECORDS_MIGRATION_NAME,
)
from .migrations.v0002_attempt_records import (
    STATEMENTS as ATTEMPT_RECORDS_MIGRATION_STATEMENTS,
)
from .migrations.v0003_attempt_response_timing import (
    MIGRATION_ID as ATTEMPT_RESPONSE_TIMING_MIGRATION_ID,
)
from .migrations.v0003_attempt_response_timing import (
    MIGRATION_NAME as ATTEMPT_RESPONSE_TIMING_MIGRATION_NAME,
)
from .migrations.v0003_attempt_response_timing import (
    STATEMENTS as ATTEMPT_RESPONSE_TIMING_MIGRATION_STATEMENTS,
)
from .migrations.v0004_attempt_response_staging import (
    MIGRATION_ID as ATTEMPT_RESPONSE_STAGING_MIGRATION_ID,
)
from .migrations.v0004_attempt_response_staging import (
    MIGRATION_NAME as ATTEMPT_RESPONSE_STAGING_MIGRATION_NAME,
)
from .migrations.v0004_attempt_response_staging import (
    STATEMENTS as ATTEMPT_RESPONSE_STAGING_MIGRATION_STATEMENTS,
)

JOURNAL_FILENAME: Final = "journal.sqlite3"
DEFAULT_BUSY_TIMEOUT_MS: Final = 5_000
MAX_BUSY_TIMEOUT_MS: Final = 60_000
MAX_MIGRATIONS: Final = 1_000
MAX_MIGRATION_STATEMENTS: Final = 512
MAX_MIGRATION_SQL_BYTES: Final = 1_048_576
MAX_PATH_CHARACTERS: Final = 4_096
MAX_BACKUP_CANDIDATES: Final = 1_000
SQLITE_SYNCHRONOUS_EXTRA: Final = 3
WINDOWS_DRIVE_REMOTE: Final = 4
WINDOWS_GENERIC_READ: Final = 0x80000000
WINDOWS_GENERIC_WRITE: Final = 0x40000000
WINDOWS_FILE_SHARE_READ: Final = 0x00000001
WINDOWS_FILE_SHARE_WRITE: Final = 0x00000002
WINDOWS_CREATE_NEW: Final = 1
WINDOWS_OPEN_EXISTING: Final = 3
WINDOWS_FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010
WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
MOUNTINFO_MINIMUM_LEFT_FIELDS: Final = 5
MAX_UTC_TIMESTAMP_CHARACTERS: Final = 32
DATABASE_LIST_MINIMUM_FIELDS: Final = 3
DATABASE_LIST_PATH_INDEX: Final = 2
MIGRATION_CHECKSUM_DOMAIN: Final = b"webhook-receiver-conformance:migration:v1\0"

_MIGRATION_NAME = re.compile(r"[a-z][a-z0-9_]{0,127}")
_CHECKSUM = re.compile(r"sha256:[0-9a-f]{64}")
_UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
_UNSAFE_STATEMENT_PREFIX = re.compile(
    r"\s*(?:BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE|VACUUM|ATTACH|DETACH|PRAGMA)\b",
    flags=re.IGNORECASE,
)
_NETWORK_FILESYSTEM_TYPES = frozenset(
    {
        "9p",
        "afs",
        "ceph",
        "cifs",
        "davfs",
        "fuse.rclone",
        "fuse.sshfs",
        "glusterfs",
        "lustre",
        "nfs",
        "nfs4",
        "smb3",
    }
)


class JournalSchemaError(RuntimeError):
    """A safe, classified journal bootstrap or migration failure."""

    category: ErrorCategory = ErrorCategory.MIGRATION_ERROR
    code: DiagnosticCode = DiagnosticCode("JOURNAL_MIGRATION_ERROR")


class JournalPathError(JournalSchemaError):
    """A journal path is not a contained local regular path."""

    category = ErrorCategory.INTEGRITY_ERROR
    code = DiagnosticCode("JOURNAL_PATH_INVALID")


class MigrationDefinitionError(JournalSchemaError):
    """A migration catalog is malformed or unsafe to execute."""

    code = DiagnosticCode("JOURNAL_MIGRATION_DEFINITION_INVALID")


class MigrationChecksumError(JournalSchemaError):
    """An applied migration no longer matches its immutable definition."""

    category = ErrorCategory.INTEGRITY_ERROR
    code = DiagnosticCode("JOURNAL_MIGRATION_CHECKSUM_MISMATCH")


class UnsupportedDatabaseVersionError(JournalSchemaError):
    """A journal version is newer than the supplied migration catalog."""

    category = ErrorCategory.INTEGRITY_ERROR
    code = DiagnosticCode("JOURNAL_VERSION_UNSUPPORTED")


class MigrationExecutionError(JournalSchemaError):
    """SQLite could not atomically apply a migration."""

    code = DiagnosticCode("JOURNAL_MIGRATION_EXECUTION_FAILED")


class JournalIntegrityError(JournalSchemaError):
    """A migrated journal failed an SQLite or ledger integrity check."""

    category = ErrorCategory.INTEGRITY_ERROR
    code = DiagnosticCode("JOURNAL_INTEGRITY_FAILED")


def _statement_controls_transaction(statement: str) -> bool:
    remainder = statement.lstrip()
    while remainder:
        if remainder.startswith("--"):
            newline = remainder.find("\n")
            if newline < 0:
                message = "migration SQL must contain an executable statement"
                raise MigrationDefinitionError(message)
            remainder = remainder[newline + 1 :].lstrip()
            continue
        if remainder.startswith("/*"):
            closing = remainder.find("*/", 2)
            if closing < 0:
                message = "migration SQL contains an unterminated comment"
                raise MigrationDefinitionError(message)
            remainder = remainder[closing + 2 :].lstrip()
            continue
        break
    if not remainder:
        message = "migration SQL must contain an executable statement"
        raise MigrationDefinitionError(message)
    return _UNSAFE_STATEMENT_PREFIX.match(remainder) is not None


class CrashPhase(StrEnum):
    """Deterministic failpoints surrounding migration durability boundaries."""

    BEFORE_STATEMENT = "before_statement"
    AFTER_STATEMENT = "after_statement"
    BEFORE_LEDGER_INSERT = "before_ledger_insert"
    AFTER_LEDGER_INSERT = "after_ledger_insert"
    BEFORE_USER_VERSION = "before_user_version"
    AFTER_USER_VERSION = "after_user_version"
    BEFORE_COMMIT = "before_commit"
    AFTER_COMMIT = "after_commit"


@dataclass(frozen=True, slots=True)
class MigrationCrashPoint:
    """One injectable migration boundary."""

    migration_id: int
    phase: CrashPhase
    statement_index: int | None = None


@dataclass(frozen=True, slots=True)
class Migration:
    """One immutable, ordered, transactional schema migration."""

    migration_id: int
    name: str
    statements: tuple[str, ...]

    def __post_init__(self) -> None:  # noqa: C901
        """Reject unsafe transaction escapes and unbounded migration content."""
        if (
            isinstance(self.migration_id, bool)
            or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.migration_id,
                int,
            )
            or self.migration_id < 1
            or self.migration_id > MAX_MIGRATIONS
        ):
            message = f"migration_id must be in the range 1..{MAX_MIGRATIONS}"
            raise MigrationDefinitionError(message)
        if (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.name,
                str,
            )
            or _MIGRATION_NAME.fullmatch(self.name) is None
        ):
            message = "migration name must be a bounded lowercase identifier"
            raise MigrationDefinitionError(message)
        if (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.statements,
                tuple,
            )
            or not self.statements
        ):
            message = "migration statements must be a nonempty tuple"
            raise MigrationDefinitionError(message)
        if len(self.statements) > MAX_MIGRATION_STATEMENTS:
            message = "migration contains too many statements"
            raise MigrationDefinitionError(message)
        total_bytes = 0
        for statement in self.statements:
            if (
                not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                    statement,
                    str,
                )
                or not statement.strip()
            ):
                message = "migration statements must be nonempty strings"
                raise MigrationDefinitionError(message)
            try:
                encoded = statement.encode("utf-8")
            except UnicodeEncodeError as error:
                message = "migration SQL must contain Unicode scalar values"
                raise MigrationDefinitionError(message) from error
            total_bytes += len(encoded)
            if "\x00" in statement:
                message = "migration SQL must not contain NUL bytes"
                raise MigrationDefinitionError(message)
            if _statement_controls_transaction(statement):
                message = "migration statements must not control transactions or pragmas"
                raise MigrationDefinitionError(message)
        if total_bytes > MAX_MIGRATION_SQL_BYTES:
            message = "migration SQL exceeds the byte limit"
            raise MigrationDefinitionError(message)

    @property
    def checksum(self) -> str:
        """Return the domain-separated checksum of every migration byte."""
        digest = hashlib.sha256()
        digest.update(MIGRATION_CHECKSUM_DOMAIN)
        digest.update(self.migration_id.to_bytes(4, "big"))
        _update_length_prefixed(digest, self.name.encode("utf-8"))
        for statement in self.statements:
            _update_length_prefixed(digest, statement.encode("utf-8"))
        return f"sha256:{digest.hexdigest()}"


@dataclass(frozen=True, slots=True)
class AppliedMigration:
    """One immutable migration-ledger projection."""

    migration_id: int
    name: str
    checksum: str
    applied_at: str


@dataclass(frozen=True, slots=True)
class RunDatabase:
    """Paths belonging to one newly initialized execution."""

    run_id: str
    run_directory: Path
    database_path: Path


class _WindowsFileTime(ctypes.Structure):
    _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))


class _WindowsByHandleFileInformation(ctypes.Structure):
    _fields_ = (
        ("file_attributes", ctypes.c_uint32),
        ("creation_time", _WindowsFileTime),
        ("last_access_time", _WindowsFileTime),
        ("last_write_time", _WindowsFileTime),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    )


class _CreateFileW(Protocol):
    argtypes: object
    restype: object

    def __call__(self, *args: object) -> int | None: ...


class _GetFileInformationByHandle(Protocol):
    argtypes: object
    restype: object

    def __call__(self, handle: ctypes.c_void_p, information: object) -> int: ...


class _CloseHandle(Protocol):
    argtypes: object
    restype: object

    def __call__(self, handle: ctypes.c_void_p) -> int: ...


class _EnableLoadExtension(Protocol):
    def __call__(self, enabled: bool, /) -> None: ...  # noqa: FBT001


class _GetDriveTypeW(Protocol):
    argtypes: object
    restype: object

    def __call__(self, root_path: str) -> int: ...


@dataclass(slots=True)
class _FileGuard:
    """An exact open-file identity retained for the SQLite connection lifetime."""

    path: Path
    connect_target: str
    identity: tuple[int, int]
    path_identity: tuple[int, int]
    descriptor: int | None = None
    windows_handle: int | None = None

    def verify(self) -> None:
        """Require both the retained object and pathname to remain the same file."""
        path_metadata = _require_regular_database_file(self.path)
        if _file_identity(path_metadata) != self.path_identity:
            message = "journal pathname changed while its file was bound"
            raise JournalPathError(message)
        if self.descriptor is not None:
            try:
                descriptor_metadata = os.fstat(self.descriptor)
            except OSError as error:
                message = "bound journal descriptor became unavailable"
                raise JournalPathError(message) from error
            if (
                not stat.S_ISREG(descriptor_metadata.st_mode)
                or descriptor_metadata.st_nlink != 1
                or _file_identity(descriptor_metadata) != self.identity
            ):
                message = "bound journal descriptor no longer names one private file"
                raise JournalPathError(message)
        elif self.windows_handle is not None:
            identity, link_count, attributes = _windows_handle_information(self.windows_handle)
            if (
                identity != self.identity
                or link_count != 1
                or attributes
                & (WINDOWS_FILE_ATTRIBUTE_DIRECTORY | WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)
            ):
                message = "bound journal handle no longer names one private file"
                raise JournalPathError(message)
        else:
            message = "journal file guard has already been released"
            raise JournalPathError(message)

    def close(self) -> None:
        """Release the retained descriptor or Windows handle exactly once."""
        descriptor = self.descriptor
        self.descriptor = None
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        windows_handle = self.windows_handle
        self.windows_handle = None
        if windows_handle is not None:
            _close_windows_handle(windows_handle)

    def __del__(self) -> None:
        self.close()


class _BoundConnection(sqlite3.Connection):
    """SQLite connection that retains and verifies one database file identity."""

    _journal_guard: _FileGuard | None = None
    _journal_path: Path | None = None

    def bind_journal_file(self, guard: _FileGuard) -> None:
        self._journal_guard = guard
        self._journal_path = guard.path

    def verify_journal_file(self) -> Path:
        guard = self._journal_guard
        path = self._journal_path
        if guard is None or path is None:
            message = "SQLite connection has no retained journal file binding"
            raise JournalPathError(message)
        guard.verify()
        return path

    def close(self) -> None:
        guard = self._journal_guard
        self._journal_guard = None
        self._journal_path = None
        try:
            super().close()
        finally:
            if guard is not None:
                guard.close()


CrashHook = Callable[[MigrationCrashPoint], None]
UtcClock = Callable[[], datetime]


class _DigestWriter(Protocol):
    def update(self, value: bytes, /) -> object:
        """Add bytes to the digest state."""


MIGRATIONS: Final = (
    Migration(
        migration_id=INITIAL_MIGRATION_ID,
        name=INITIAL_MIGRATION_NAME,
        statements=INITIAL_MIGRATION_STATEMENTS,
    ),
    Migration(
        migration_id=ATTEMPT_RECORDS_MIGRATION_ID,
        name=ATTEMPT_RECORDS_MIGRATION_NAME,
        statements=ATTEMPT_RECORDS_MIGRATION_STATEMENTS,
    ),
    Migration(
        migration_id=ATTEMPT_RESPONSE_TIMING_MIGRATION_ID,
        name=ATTEMPT_RESPONSE_TIMING_MIGRATION_NAME,
        statements=ATTEMPT_RESPONSE_TIMING_MIGRATION_STATEMENTS,
    ),
    Migration(
        migration_id=ATTEMPT_RESPONSE_STAGING_MIGRATION_ID,
        name=ATTEMPT_RESPONSE_STAGING_MIGRATION_NAME,
        statements=ATTEMPT_RESPONSE_STAGING_MIGRATION_STATEMENTS,
    ),
)

if MIGRATIONS[-1].migration_id != VERSION_METADATA.sqlite_user_version:
    message = "migration catalog and sqlite_user_version metadata differ"
    raise RuntimeError(message)


def _build_schema_contract(
    catalog: tuple[Migration, ...],
) -> tuple[tuple[str, str, str], ...]:
    """Compile an applied migration prefix into SQLite's canonical schema form."""
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        for migration in catalog:
            for statement in migration.statements:
                if _statement_changes_schema(statement):
                    connection.execute(statement)
        rows = connection.execute(
            """
            SELECT type, name, sql
            FROM sqlite_schema
            WHERE type IN ('table', 'index', 'trigger', 'view')
              AND sql IS NOT NULL
              AND name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
    except sqlite3.Error as error:
        message = "migration catalog cannot compile an exact schema contract"
        raise JournalIntegrityError(message) from error
    finally:
        connection.close()
    contract: list[tuple[str, str, str]] = []
    for object_type, name, sql in rows:
        if not all(isinstance(value, str) for value in (object_type, name, sql)):
            message = "SQLite returned a non-text migration schema definition"
            raise JournalIntegrityError(message)
        contract.append((object_type, name, sql))
    return tuple(contract)


def _statement_changes_schema(statement: str) -> bool:
    remainder = statement.lstrip()
    while remainder.startswith(("--", "/*")):
        if remainder.startswith("--"):
            newline = remainder.find("\n")
            remainder = "" if newline < 0 else remainder[newline + 1 :].lstrip()
        else:
            closing = remainder.find("*/", 2)
            remainder = "" if closing < 0 else remainder[closing + 2 :].lstrip()
    keyword_match = re.match(r"[A-Za-z]+", remainder)
    return keyword_match is not None and keyword_match.group(0).upper() in {
        "ALTER",
        "CREATE",
        "DROP",
    }


def validate_migration_catalog(migrations: Sequence[Migration]) -> tuple[Migration, ...]:
    """Return a bounded contiguous migration catalog."""
    if isinstance(migrations, (str, bytes)) or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        migrations,
        Sequence,
    ):
        message = "migrations must be a sequence of Migration values"
        raise MigrationDefinitionError(message)
    catalog = _materialize_migration_catalog(migrations)
    if not catalog:
        message = "migration catalog must not be empty"
        raise MigrationDefinitionError(message)
    if len(catalog) > MAX_MIGRATIONS:
        message = "migration catalog exceeds the migration limit"
        raise MigrationDefinitionError(message)
    for expected_id, migration in enumerate(catalog, start=1):
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            migration,
            Migration,
        ):
            message = "migration catalog entries must be Migration values"
            raise MigrationDefinitionError(message)
        if migration.migration_id != expected_id:
            message = "migration IDs must be contiguous, ordered, and forward-only"
            raise MigrationDefinitionError(message)
    return catalog


def _materialize_migration_catalog(
    migrations: Sequence[Migration],
) -> tuple[Migration, ...]:
    try:
        iterator = iter(migrations)
    except TypeError as error:
        message = "migrations must be an iterable sequence of Migration values"
        raise MigrationDefinitionError(message) from error
    materialized: list[Migration] = []
    for _ in range(MAX_MIGRATIONS + 1):
        try:
            migration = next(iterator)
        except StopIteration:
            break
        materialized.append(migration)
        if len(materialized) > MAX_MIGRATIONS:
            message = "migration catalog exceeds the migration limit"
            raise MigrationDefinitionError(message)
    return tuple(materialized)


def configure_connection(
    connection: sqlite3.Connection,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> None:
    """Set and verify the mandatory policy on one SQLite connection."""
    _validate_busy_timeout(busy_timeout_ms)
    if connection.in_transaction:
        message = "connection policy cannot be changed during a transaction"
        raise JournalSchemaError(message)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        journal_mode_row = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        connection.execute("PRAGMA synchronous = EXTRA")
        foreign_keys = _pragma_integer(connection, "foreign_keys")
        trusted_schema = _pragma_integer(connection, "trusted_schema")
        configured_timeout = _pragma_integer(connection, "busy_timeout")
        synchronous = _pragma_integer(connection, "synchronous")
    except sqlite3.Error as error:
        message = "SQLite rejected mandatory journal connection policy"
        raise JournalSchemaError(message) from error
    journal_mode = (
        str(journal_mode_row[0]).casefold()
        if journal_mode_row is not None and journal_mode_row
        else ""
    )
    if journal_mode != "delete":
        message = "SQLite did not enter DELETE journal mode"
        raise JournalSchemaError(message)
    if foreign_keys != 1:
        message = "SQLite foreign-key enforcement is not enabled"
        raise JournalSchemaError(message)
    if trusted_schema != 0:
        message = "SQLite trusted_schema is not disabled"
        raise JournalSchemaError(message)
    if configured_timeout != busy_timeout_ms:
        message = "SQLite busy_timeout differs from the bounded policy"
        raise JournalSchemaError(message)
    if synchronous != SQLITE_SYNCHRONOUS_EXTRA:
        message = "SQLite did not enter EXTRA synchronous mode"
        raise JournalSchemaError(message)


def create_journal_database(
    database_path: str | os.PathLike[str],
    *,
    migrations: Sequence[Migration] = MIGRATIONS,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    crash_hook: CrashHook | None = None,
    clock: UtcClock | None = None,
) -> sqlite3.Connection:
    """Create, migrate, and return one new owner-only journal database."""
    path = _validated_database_path(database_path)
    _require_local_filesystem(path.parent)
    guard = _secure_create_file(path)
    connection: sqlite3.Connection | None = None
    try:
        connection = _connect(
            path,
            busy_timeout_ms=busy_timeout_ms,
            guard=guard,
        )
        apply_migrations(
            connection,
            migrations=migrations,
            crash_hook=crash_hook,
            clock=clock,
        )
        validate_migration_output(connection, migrations=migrations)
        _verify_connection_binding(connection, expected_path=path)
    except BaseException:
        if connection is not None:
            connection.close()
        else:
            guard.close()
        raise
    return connection


def open_journal_database(  # noqa: PLR0913
    database_path: str | os.PathLike[str],
    *,
    migrations: Sequence[Migration] = MIGRATIONS,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    crash_hook: CrashHook | None = None,
    clock: UtcClock | None = None,
    no_backup: bool = False,
) -> sqlite3.Connection:
    """Open, verify, migrate, and return an existing local journal."""
    path = _validated_database_path(database_path)
    _require_local_filesystem(path.parent)
    connection: sqlite3.Connection | None = None
    try:
        connection = _connect(path, busy_timeout_ms=busy_timeout_ms)
        apply_migrations(
            connection,
            migrations=migrations,
            crash_hook=crash_hook,
            clock=clock,
            no_backup=no_backup,
        )
        validate_migration_output(connection, migrations=migrations)
        _verify_connection_binding(connection, expected_path=path)
    except BaseException:
        if connection is not None:
            connection.close()
        raise
    return connection


def create_run_database(
    artifact_directory: str | os.PathLike[str],
    *,
    run_id: str | None = None,
    migrations: Sequence[Migration] = MIGRATIONS,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    clock: UtcClock | None = None,
) -> RunDatabase:
    """Create a distinct owner-only run directory and initialized database."""
    artifact_root = _prepare_artifact_directory(artifact_directory)
    try:
        stable_run_id = new_run_id() if run_id is None else validate_run_id(run_id)
    except (TypeError, ValueError) as error:
        message = "run directory name must be a canonical UUIDv4"
        raise JournalPathError(message) from error
    run_directory = artifact_root / stable_run_id
    try:
        run_directory.mkdir(mode=0o700)
    except FileExistsError as error:
        message = "run directory already exists; executions cannot share a database"
        raise JournalPathError(message) from error
    except OSError as error:
        message = "run directory could not be created"
        raise JournalPathError(message) from error
    _tighten_directory_permissions(run_directory)
    database_path = run_directory / JOURNAL_FILENAME
    connection = create_journal_database(
        database_path,
        migrations=migrations,
        busy_timeout_ms=busy_timeout_ms,
        clock=clock,
    )
    connection.close()
    return RunDatabase(
        run_id=stable_run_id,
        run_directory=run_directory,
        database_path=database_path,
    )


def apply_migrations(
    connection: sqlite3.Connection,
    *,
    migrations: Sequence[Migration] = MIGRATIONS,
    crash_hook: CrashHook | None = None,
    clock: UtcClock | None = None,
    no_backup: bool = False,
) -> tuple[AppliedMigration, ...]:
    """Verify applied checksums and apply each pending migration exactly once."""
    catalog = validate_migration_catalog(migrations)
    _require_connection_policy(connection)
    applied = _verify_ledger(connection, catalog)
    first_pending = len(applied)
    if first_pending and first_pending < len(catalog) and not no_backup:
        _create_upgrade_backup(
            connection,
            catalog=catalog,
            current_version=first_pending,
            target_version=catalog[-1].migration_id,
        )
    for migration in catalog[first_pending:]:
        _apply_one_migration(
            connection,
            migration,
            catalog=catalog,
            crash_hook=crash_hook,
            clock=clock,
        )
    return _verify_ledger(connection, catalog)


def verify_migration_ledger(
    connection: sqlite3.Connection,
    *,
    migrations: Sequence[Migration] = MIGRATIONS,
) -> tuple[AppliedMigration, ...]:
    """Verify user_version, ordered ledger rows, names, and checksums."""
    catalog = validate_migration_catalog(migrations)
    _require_connection_policy(connection)
    return _verify_ledger(connection, catalog)


def validate_migration_output(
    connection: sqlite3.Connection,
    *,
    migrations: Sequence[Migration] = MIGRATIONS,
) -> None:
    """Require a valid ledger, SQLite image, and immediate foreign-key graph."""
    catalog = validate_migration_catalog(migrations)
    applied = verify_migration_ledger(connection, migrations=catalog)
    try:
        integrity_check = tuple(
            str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()
        )
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
    except sqlite3.Error as error:
        message = "SQLite integrity checks could not be completed"
        raise JournalIntegrityError(message) from error
    if integrity_check != ("ok",):
        message = "SQLite integrity_check reported journal corruption"
        raise JournalIntegrityError(message)
    if foreign_key_errors:
        message = "SQLite foreign_key_check reported invalid references"
        raise JournalIntegrityError(message)
    _verify_required_schema_objects(connection, catalog=catalog[: len(applied)])
    _verify_immediate_foreign_keys(connection)


def migration_crash_points(
    migration: Migration,
) -> tuple[MigrationCrashPoint, ...]:
    """Enumerate every injectable statement and commit boundary."""
    points: list[MigrationCrashPoint] = []
    for statement_index in range(len(migration.statements)):
        points.extend(
            (
                MigrationCrashPoint(
                    migration_id=migration.migration_id,
                    phase=CrashPhase.BEFORE_STATEMENT,
                    statement_index=statement_index,
                ),
                MigrationCrashPoint(
                    migration_id=migration.migration_id,
                    phase=CrashPhase.AFTER_STATEMENT,
                    statement_index=statement_index,
                ),
            )
        )
    points.append(
        MigrationCrashPoint(migration.migration_id, CrashPhase.BEFORE_LEDGER_INSERT),
    )
    points.append(
        MigrationCrashPoint(migration.migration_id, CrashPhase.AFTER_LEDGER_INSERT),
    )
    points.append(
        MigrationCrashPoint(migration.migration_id, CrashPhase.BEFORE_USER_VERSION),
    )
    points.append(
        MigrationCrashPoint(migration.migration_id, CrashPhase.AFTER_USER_VERSION),
    )
    points.append(MigrationCrashPoint(migration.migration_id, CrashPhase.BEFORE_COMMIT))
    points.append(MigrationCrashPoint(migration.migration_id, CrashPhase.AFTER_COMMIT))
    return tuple(points)


def _apply_one_migration(
    connection: sqlite3.Connection,
    migration: Migration,
    *,
    catalog: tuple[Migration, ...],
    crash_hook: CrashHook | None,
    clock: UtcClock | None,
) -> None:
    committed = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        applied = _verify_ledger(connection, catalog)
        if len(applied) >= migration.migration_id:
            connection.execute("COMMIT")
            return
        _require_expected_migration_prefix(applied, migration)
        for statement_index, statement in enumerate(migration.statements):
            _call_crash_hook(
                crash_hook,
                MigrationCrashPoint(
                    migration.migration_id,
                    CrashPhase.BEFORE_STATEMENT,
                    statement_index,
                ),
            )
            connection.execute(statement)
            _call_crash_hook(
                crash_hook,
                MigrationCrashPoint(
                    migration.migration_id,
                    CrashPhase.AFTER_STATEMENT,
                    statement_index,
                ),
            )
        _call_crash_hook(
            crash_hook,
            MigrationCrashPoint(migration.migration_id, CrashPhase.BEFORE_LEDGER_INSERT),
        )
        connection.execute(
            """
            INSERT INTO schema_migrations (
                migration_id,
                migration_name,
                checksum,
                applied_at
            ) VALUES (?, ?, ?, ?)
            """,
            (
                migration.migration_id,
                migration.name,
                migration.checksum,
                _migration_timestamp(clock),
            ),
        )
        _call_crash_hook(
            crash_hook,
            MigrationCrashPoint(migration.migration_id, CrashPhase.AFTER_LEDGER_INSERT),
        )
        _call_crash_hook(
            crash_hook,
            MigrationCrashPoint(migration.migration_id, CrashPhase.BEFORE_USER_VERSION),
        )
        connection.execute(f"PRAGMA user_version = {migration.migration_id}")
        _call_crash_hook(
            crash_hook,
            MigrationCrashPoint(migration.migration_id, CrashPhase.AFTER_USER_VERSION),
        )
        _call_crash_hook(
            crash_hook,
            MigrationCrashPoint(migration.migration_id, CrashPhase.BEFORE_COMMIT),
        )
        connection.execute("COMMIT")
        committed = True
        _call_crash_hook(
            crash_hook,
            MigrationCrashPoint(migration.migration_id, CrashPhase.AFTER_COMMIT),
        )
    except BaseException as error:
        if not committed and connection.in_transaction:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error as rollback_error:
                message = "migration failed and SQLite could not roll back"
                raise MigrationExecutionError(message) from rollback_error
        if isinstance(error, sqlite3.Error):
            message = f"migration {migration.migration_id} failed atomically"
            raise MigrationExecutionError(message) from error
        raise


def _verify_ledger(  # noqa: C901, PLR0912
    connection: sqlite3.Connection,
    catalog: tuple[Migration, ...],
) -> tuple[AppliedMigration, ...]:
    user_version = _pragma_integer(connection, "user_version")
    latest_supported = catalog[-1].migration_id
    if user_version < 0:
        message = "SQLite user_version cannot be negative"
        raise JournalIntegrityError(message)
    if user_version > latest_supported:
        message = "journal user_version is newer than this migration catalog"
        raise UnsupportedDatabaseVersionError(message)
    if not _schema_object_exists(connection, "table", "schema_migrations"):
        if user_version != 0:
            message = "journal has a user_version but no migration ledger"
            raise JournalIntegrityError(message)
        unmanaged = connection.execute(
            """
            SELECT name
            FROM sqlite_schema
            WHERE type IN ('table', 'view', 'trigger')
              AND name NOT LIKE 'sqlite_%'
            LIMIT 1
            """
        ).fetchone()
        if unmanaged is not None:
            message = "unmanaged schema objects exist without a migration ledger"
            raise JournalIntegrityError(message)
        return ()
    try:
        rows = connection.execute(
            """
            SELECT migration_id, migration_name, checksum, applied_at
            FROM schema_migrations
            ORDER BY migration_id
            """
        ).fetchall()
    except sqlite3.Error as error:
        message = "migration ledger does not match the supported shape"
        raise JournalIntegrityError(message) from error
    if len(rows) > latest_supported:
        message = "migration ledger contains an unsupported future migration"
        raise UnsupportedDatabaseVersionError(message)
    if not rows:
        message = "migration ledger exists without its initial applied migration"
        raise JournalIntegrityError(message)
    applied: list[AppliedMigration] = []
    for expected_id, row in enumerate(rows, start=1):
        migration_id = row[0]
        name = row[1]
        checksum = row[2]
        applied_at = row[3]
        if migration_id != expected_id:
            message = "migration ledger IDs are not a contiguous prefix"
            raise JournalIntegrityError(message)
        expected = catalog[expected_id - 1]
        if name != expected.name:
            message = f"applied migration {expected_id} has a changed name"
            raise MigrationChecksumError(message)
        if (
            not isinstance(checksum, str)
            or _CHECKSUM.fullmatch(checksum) is None
            or not hmac.compare_digest(checksum, expected.checksum)
        ):
            message = f"applied migration {expected_id} checksum changed"
            raise MigrationChecksumError(message)
        if not isinstance(applied_at, str) or not _is_utc_timestamp(applied_at):
            message = f"applied migration {expected_id} has an invalid timestamp"
            raise JournalIntegrityError(message)
        applied.append(
            AppliedMigration(
                migration_id=migration_id,
                name=name,
                checksum=checksum,
                applied_at=applied_at,
            )
        )
    if user_version != len(applied):
        message = "SQLite user_version and migration ledger differ"
        raise JournalIntegrityError(message)
    return tuple(applied)


def _connect(
    path: Path,
    *,
    busy_timeout_ms: int,
    guard: _FileGuard | None = None,
) -> sqlite3.Connection:
    _validate_busy_timeout(busy_timeout_ms)
    retained_guard = _open_file_guard(path) if guard is None else guard
    connection: _BoundConnection | None = None
    try:
        connection = sqlite3.connect(
            retained_guard.connect_target,
            timeout=busy_timeout_ms / 1_000,
            isolation_level=None,
            check_same_thread=True,
            factory=_BoundConnection,
        )
        connection.bind_journal_file(retained_guard)
        _verify_sqlite_opened_bound_path(connection, retained_guard)
        retained_guard.verify()
        connection.row_factory = sqlite3.Row
        _disable_load_extension(connection)
        configure_connection(connection, busy_timeout_ms=busy_timeout_ms)
        retained_guard.verify()
    except (OSError, sqlite3.Error, JournalSchemaError) as error:
        if connection is not None:
            connection.close()
        else:
            retained_guard.close()
        if isinstance(error, JournalSchemaError):
            raise
        message = "journal database could not be opened securely"
        raise JournalPathError(message) from error
    return connection


def _disable_load_extension(connection: object) -> None:
    candidate = getattr(connection, "enable_load_extension", None)
    if candidate is None:
        return
    if not callable(candidate):
        message = "SQLite load-extension control is malformed"
        raise JournalSchemaError(message)
    cast("_EnableLoadExtension", candidate)(False)  # noqa: FBT003


def _verify_connection_binding(
    connection: sqlite3.Connection,
    *,
    expected_path: Path,
) -> None:
    if not isinstance(connection, _BoundConnection):
        message = "journal operation lost its exact database file binding"
        raise JournalPathError(message)
    bound_path = connection.verify_journal_file()
    if bound_path != expected_path:
        message = "journal operation is bound to an unexpected database path"
        raise JournalPathError(message)


def _create_upgrade_backup(
    connection: sqlite3.Connection,
    *,
    catalog: tuple[Migration, ...],
    current_version: int,
    target_version: int,
) -> Path:
    if not isinstance(connection, _BoundConnection):
        message = "pre-migration backup requires an exact bound database connection"
        raise MigrationExecutionError(message)
    database_path = connection.verify_journal_file()
    _require_local_filesystem(database_path.parent)
    backup_path, backup_guard = _create_backup_file(
        database_path,
        current_version=current_version,
        target_version=target_version,
    )
    destination: sqlite3.Connection | None = None
    try:
        destination = _connect(
            backup_path,
            busy_timeout_ms=_pragma_integer(connection, "busy_timeout"),
            guard=backup_guard,
        )
        _verify_connection_binding(connection, expected_path=database_path)
        _verify_connection_binding(destination, expected_path=backup_path)
        connection.backup(destination)
        _verify_connection_binding(connection, expected_path=database_path)
        _verify_connection_binding(destination, expected_path=backup_path)
        validate_migration_output(destination, migrations=catalog)
        _verify_connection_binding(connection, expected_path=database_path)
        _verify_connection_binding(destination, expected_path=backup_path)
    except (sqlite3.Error, JournalSchemaError) as error:
        message = "pre-migration backup could not be completed and verified"
        raise MigrationExecutionError(message) from error
    finally:
        if destination is not None:
            destination.close()
        else:
            backup_guard.close()
    return backup_path


def _create_backup_file(
    database_path: Path,
    *,
    current_version: int,
    target_version: int,
) -> tuple[Path, _FileGuard]:
    for counter in range(MAX_BACKUP_CANDIDATES):
        candidate = database_path.with_name(
            f"{database_path.name}.pre-v{current_version}-to-v{target_version}.{counter:03d}.bak"
        )
        if candidate.exists():
            continue
        try:
            guard = _secure_create_file(candidate)
        except JournalPathError:
            if candidate.exists():
                continue
            raise
        return candidate, guard
    message = "pre-migration backup file limit was reached"
    raise MigrationExecutionError(message)


def _require_connection_policy(connection: sqlite3.Connection) -> None:
    try:
        values = (
            _pragma_integer(connection, "foreign_keys"),
            _pragma_integer(connection, "trusted_schema"),
            _pragma_integer(connection, "synchronous"),
            str(connection.execute("PRAGMA journal_mode").fetchone()[0]).casefold(),
            _pragma_integer(connection, "busy_timeout"),
        )
    except (sqlite3.Error, TypeError, IndexError) as error:
        message = "journal connection policy could not be verified"
        raise JournalSchemaError(message) from error
    if values[:4] != (1, 0, SQLITE_SYNCHRONOUS_EXTRA, "delete"):
        message = "journal connection does not satisfy mandatory SQLite policy"
        raise JournalSchemaError(message)
    busy_timeout = values[4]
    if not 1 <= busy_timeout <= MAX_BUSY_TIMEOUT_MS:
        message = "journal connection busy_timeout is outside its boundary"
        raise JournalSchemaError(message)
    if connection.in_transaction:
        message = "migration startup requires no active transaction"
        raise JournalSchemaError(message)


def _validated_database_path(path_value: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(path_value)
    except TypeError as error:
        message = "journal database path must be path-like"
        raise JournalPathError(message) from error
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        raw,
        str,
    ):
        raw = os.fsdecode(raw)
    if not raw or "\x00" in raw or len(raw) > MAX_PATH_CHARACTERS:
        message = "journal database path is empty or exceeds its boundary"
        raise JournalPathError(message)
    if _looks_like_unc_path(raw):
        message = "network journal paths are unsupported"
        raise JournalPathError(message)
    try:
        candidate = Path(raw)
        parent = candidate.parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        message = "journal parent directory is unavailable"
        raise JournalPathError(message) from error
    if not parent.is_dir() or _is_link_like(candidate.parent):
        message = "journal parent must be a real local directory"
        raise JournalPathError(message)
    resolved = parent / candidate.name
    if resolved.name != JOURNAL_FILENAME:
        message = f"journal database must be named {JOURNAL_FILENAME}"
        raise JournalPathError(message)
    if resolved.parent != parent:
        message = "journal database escaped its run directory"
        raise JournalPathError(message)
    return resolved


def _prepare_artifact_directory(path_value: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(path_value)
    except TypeError as error:
        message = "artifact directory must be path-like"
        raise JournalPathError(message) from error
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        raw,
        str,
    ):
        raw = os.fsdecode(raw)
    if not raw or "\x00" in raw or len(raw) > MAX_PATH_CHARACTERS:
        message = "artifact directory is empty or exceeds its boundary"
        raise JournalPathError(message)
    if _looks_like_unc_path(raw):
        message = "network artifact directories are unsupported"
        raise JournalPathError(message)
    candidate = Path(raw)
    existed = candidate.exists()
    if existed and (_is_link_like(candidate) or not candidate.is_dir()):
        message = "artifact directory must be a real directory"
        raise JournalPathError(message)
    try:
        candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
        if _is_link_like(candidate):
            message = "artifact directory became a link during preparation"
            raise JournalPathError(message)
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        message = "artifact directory could not be prepared"
        raise JournalPathError(message) from error
    if not existed:
        _tighten_directory_permissions(resolved)
    _require_local_filesystem(resolved)
    return resolved


def _secure_create_file(path: Path) -> _FileGuard:
    if os.name == "nt":
        return _acquire_windows_file_guard(path, create=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    for optional_flag in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW"):
        flags |= int(getattr(os, optional_flag, 0))
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        message = "journal database already exists"
        raise JournalPathError(message) from error
    except OSError as error:
        message = "journal database could not be created"
        raise JournalPathError(message) from error
    try:
        os.fchmod(descriptor, 0o600)
        return _posix_file_guard(path, descriptor)
    except (AttributeError, OSError, JournalPathError) as error:
        os.close(descriptor)
        message = "journal file could not be bound with owner-only permissions"
        raise JournalPathError(message) from error


def _open_file_guard(path: Path) -> _FileGuard:
    if os.name == "nt":
        return _acquire_windows_file_guard(path, create=False)
    flags = os.O_RDWR
    for optional_flag in ("O_CLOEXEC", "O_NOFOLLOW"):
        flags |= int(getattr(os, optional_flag, 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        message = "journal database could not be opened as an exact file"
        raise JournalPathError(message) from error
    try:
        os.fchmod(descriptor, 0o600)
        return _posix_file_guard(path, descriptor)
    except (AttributeError, OSError, JournalPathError) as error:
        os.close(descriptor)
        message = "journal database could not be bound with owner-only permissions"
        raise JournalPathError(message) from error


def _posix_file_guard(path: Path, descriptor: int) -> _FileGuard:
    try:
        descriptor_metadata = os.fstat(descriptor)
        path_metadata = _require_regular_database_file(path)
    except OSError as error:
        message = "journal descriptor metadata could not be inspected"
        raise JournalPathError(message) from error
    identity = _file_identity(descriptor_metadata)
    if (
        not stat.S_ISREG(descriptor_metadata.st_mode)
        or descriptor_metadata.st_nlink != 1
        or _file_identity(path_metadata) != identity
    ):
        message = "journal descriptor is not the one private pathname file"
        raise JournalPathError(message)
    intended_path = str(path.resolve(strict=True))
    connect_target: str | None = None
    for descriptor_root in ("/proc/self/fd", "/dev/fd"):
        candidate = Path(descriptor_root) / str(descriptor)
        try:
            if candidate.exists() and candidate.samefile(path):
                connect_target = str(candidate)
                break
        except OSError:
            continue
    if connect_target is None:
        connect_target = intended_path
    return _FileGuard(
        path=Path(intended_path),
        connect_target=connect_target,
        identity=identity,
        path_identity=_file_identity(path_metadata),
        descriptor=descriptor,
    )


def _acquire_windows_file_guard(path: Path, *, create: bool) -> _FileGuard:
    create_file = cast("_CreateFileW", _windows_function("CreateFileW"))
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    disposition = WINDOWS_CREATE_NEW if create else WINDOWS_OPEN_EXISTING
    handle_value = create_file(
        str(path),
        WINDOWS_GENERIC_READ | WINDOWS_GENERIC_WRITE,
        WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE,
        None,
        disposition,
        WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle_value is None or handle_value == invalid_handle:
        error_code = _windows_last_error()
        if create and error_code in {80, 183}:
            message = "journal database already exists"
        elif create:
            message = "journal database could not be created"
        else:
            message = "journal database could not be opened as an exact file"
        raise JournalPathError(message) from OSError(error_code, message, str(path))
    handle = int(handle_value)
    try:
        identity, link_count, attributes = _windows_handle_information(handle)
        path_metadata = _require_regular_database_file(path)
        _require_private_windows_handle(link_count, attributes)
        guard = _FileGuard(
            path=path.resolve(strict=True),
            connect_target=str(path.resolve(strict=True)),
            identity=identity,
            path_identity=_file_identity(path_metadata),
            windows_handle=handle,
        )
    except BaseException:
        _close_windows_handle(handle)
        raise
    else:
        return guard


def _require_private_windows_handle(link_count: int, attributes: int) -> None:
    if link_count != 1 or attributes & (
        WINDOWS_FILE_ATTRIBUTE_DIRECTORY | WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    ):
        message = "journal handle must name one regular non-link file"
        raise JournalPathError(message)


def _windows_handle_information(handle: int) -> tuple[tuple[int, int], int, int]:
    get_information = cast(
        "_GetFileInformationByHandle",
        _windows_function("GetFileInformationByHandle"),
    )
    get_information.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsByHandleFileInformation),
    )
    get_information.restype = ctypes.c_int
    information = _WindowsByHandleFileInformation()
    if not get_information(ctypes.c_void_p(handle), ctypes.byref(information)):
        error_code = _windows_last_error()
        message = "bound journal handle metadata could not be inspected"
        raise JournalPathError(message) from OSError(error_code, message)
    file_index = (int(information.file_index_high) << 32) | int(information.file_index_low)
    return (
        (int(information.volume_serial_number), file_index),
        int(information.number_of_links),
        int(information.file_attributes),
    )


def _close_windows_handle(handle: int) -> None:
    try:
        close_handle = cast("_CloseHandle", _windows_function("CloseHandle"))
        close_handle.argtypes = (ctypes.c_void_p,)
        close_handle.restype = ctypes.c_int
        close_handle(ctypes.c_void_p(handle))
    except (AttributeError, OSError):
        pass


def _windows_function(name: str) -> object:
    loader_candidate = vars(ctypes).get("WinDLL")
    if not callable(loader_candidate):
        message = "Windows file APIs are unavailable on this platform"
        raise OSError(message)
    library = loader_candidate("kernel32", use_last_error=True)
    return getattr(library, name)


def _windows_last_error() -> int:
    function_candidate = vars(ctypes).get("get_last_error")
    if not callable(function_candidate):
        return 0
    function = cast("Callable[[], int]", function_candidate)
    return function()


def _verify_sqlite_opened_bound_path(
    connection: sqlite3.Connection,
    guard: _FileGuard,
) -> None:
    try:
        database_row = connection.execute("PRAGMA database_list").fetchone()
    except sqlite3.Error as error:
        message = "SQLite did not expose its bound database pathname"
        raise JournalPathError(message) from error
    if (
        database_row is None
        or len(database_row) < DATABASE_LIST_MINIMUM_FIELDS
        or not database_row[DATABASE_LIST_PATH_INDEX]
    ):
        message = "SQLite did not expose its bound database pathname"
        raise JournalPathError(message)
    opened_path = Path(str(database_row[DATABASE_LIST_PATH_INDEX]))
    try:
        opened_resolved = opened_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        message = "SQLite opened a database pathname that cannot be verified"
        raise JournalPathError(message) from error
    if opened_resolved != guard.path:
        message = "SQLite did not canonicalize the descriptor-bound journal file"
        raise JournalPathError(message)


def _require_regular_database_file(path: Path) -> os.stat_result:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        message = "journal database is unavailable"
        raise JournalPathError(message) from error
    if _is_link_like(path) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        message = "journal database must be one regular non-link file"
        raise JournalPathError(message)
    return metadata


def _tighten_directory_permissions(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        path.chmod(0o700, follow_symlinks=False)
    except OSError as error:
        message = "run directory permissions could not be restricted"
        raise JournalPathError(message) from error


def _require_local_filesystem(path: Path) -> None:
    if _looks_like_unc_path(str(path)) or _filesystem_is_remote(path):
        message = "SQLite journals on network filesystems are unsupported"
        raise JournalPathError(message)


def _filesystem_is_remote(path: Path) -> bool:
    if os.name == "nt":
        return _windows_drive_is_remote(path)
    mountinfo = Path("/proc/self/mountinfo")
    if not mountinfo.is_file():
        return False
    try:
        lines = mountinfo.read_text(encoding="utf-8", errors="strict").splitlines()
    except OSError:
        return False
    resolved = str(path.resolve(strict=True))
    selected_mount = ""
    selected_type = ""
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < MOUNTINFO_MINIMUM_LEFT_FIELDS or not right_fields:
            continue
        mount = _unescape_mountinfo(left_fields[4])
        if _path_is_within(resolved, mount) and len(mount) > len(selected_mount):
            selected_mount = mount
            selected_type = right_fields[0]
    return selected_type in _NETWORK_FILESYSTEM_TYPES


def _windows_drive_is_remote(path: Path) -> bool:
    try:
        root = PureWindowsPath(str(path)).anchor
        if not root:
            return True
        get_drive_type = cast("_GetDriveTypeW", _windows_function("GetDriveTypeW"))
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        drive_type = int(get_drive_type(root))
    except (AttributeError, OSError, ValueError):
        return False
    return drive_type == WINDOWS_DRIVE_REMOTE


def _looks_like_unc_path(value: str) -> bool:
    normalized = value.replace("/", "\\")
    return normalized.startswith("\\\\")


def _is_link_like(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(reparse_flag and file_attributes & reparse_flag)


def _file_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _path_is_within(path: str, root: str) -> bool:
    if path == root:
        return True
    prefix = root if root.endswith(os.sep) else f"{root}{os.sep}"
    return path.startswith(prefix)


def _unescape_mountinfo(value: str) -> str:
    return (
        value.replace(r"\040", " ")
        .replace(r"\011", "\t")
        .replace(r"\012", "\n")
        .replace(r"\134", "\\")
    )


def _validate_busy_timeout(value: int) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            value,
            int,
        )
        or value < 1
        or value > MAX_BUSY_TIMEOUT_MS
    ):
        message = f"busy_timeout_ms must be in the range 1..{MAX_BUSY_TIMEOUT_MS}"
        raise ValueError(message)


def _pragma_integer(connection: sqlite3.Connection, name: str) -> int:
    if name not in {
        "busy_timeout",
        "foreign_keys",
        "synchronous",
        "trusted_schema",
        "user_version",
    }:
        message = "unsupported internal PRAGMA name"
        raise JournalSchemaError(message)
    row = connection.execute(f"PRAGMA {name}").fetchone()
    if row is None or not row:
        message = f"SQLite did not return PRAGMA {name}"
        raise JournalSchemaError(message)
    value = row[0]
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"SQLite returned a noninteger PRAGMA {name}"
        raise JournalSchemaError(message)
    return value


def _schema_object_exists(
    connection: sqlite3.Connection,
    object_type: str,
    name: str,
) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = ? AND name = ?",
            (object_type, name),
        ).fetchone()
        is not None
    )


def _verify_required_schema_objects(
    connection: sqlite3.Connection,
    *,
    catalog: tuple[Migration, ...],
) -> None:
    expected = {
        (object_type, name): sql for object_type, name, sql in _build_schema_contract(catalog)
    }
    try:
        rows = connection.execute(
            """
            SELECT type, name, sql
            FROM sqlite_schema
            WHERE type IN ('table', 'index', 'trigger', 'view')
              AND sql IS NOT NULL
              AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    except sqlite3.Error as error:
        message = "migrated journal schema definitions could not be inspected"
        raise JournalIntegrityError(message) from error
    installed: dict[tuple[str, str], str] = {}
    for object_type, name, sql in rows:
        if not all(isinstance(value, str) for value in (object_type, name, sql)):
            message = "migrated journal contains an uninspectable schema definition"
            raise JournalIntegrityError(message)
        installed[(object_type, name)] = sql
    if installed.keys() != expected.keys():
        message = "migrated journal schema object set differs from its migration catalog"
        raise JournalIntegrityError(message)
    for (object_type, name), expected_sql in expected.items():
        actual_sql = installed[(object_type, name)]
        if actual_sql != expected_sql:
            message = f"migrated journal {object_type} {name!r} differs from migration SQL"
            raise JournalIntegrityError(message)


def _verify_immediate_foreign_keys(connection: sqlite3.Connection) -> None:
    tables = connection.execute(
        """
        SELECT name
        FROM sqlite_schema
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
        """
    ).fetchall()
    for table_row in tables:
        table_name = str(table_row[0])
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", table_name):
            message = "journal contains an unsafe table identifier"
            raise JournalIntegrityError(message)
        schema_row = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        if schema_row is None or not isinstance(schema_row[0], str):
            message = "journal table has no inspectable schema definition"
            raise JournalIntegrityError(message)
        if re.search(r"\bDEFERRABLE\b", schema_row[0], flags=re.IGNORECASE) is not None:
            message = "journal schema contains a deferred foreign key"
            raise JournalIntegrityError(message)


def _migration_timestamp(clock: UtcClock | None) -> str:
    value = datetime.now(UTC) if clock is None else clock()
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        value,
        datetime,
    ):
        message = "migration clock must return datetime"
        raise TypeError(message)
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        message = "migration clock must return a UTC-aware datetime"
        raise ValueError(message)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _is_utc_timestamp(value: str) -> bool:
    if len(value) > MAX_UTC_TIMESTAMP_CHARACTERS or _UTC_TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)


def _update_length_prefixed(digest: _DigestWriter, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _call_crash_hook(
    hook: CrashHook | None,
    point: MigrationCrashPoint,
) -> None:
    if hook is not None:
        hook(point)


def _require_expected_migration_prefix(
    applied: tuple[AppliedMigration, ...],
    migration: Migration,
) -> None:
    if len(applied) != migration.migration_id - 1:
        message = "migration ledger changed to a non-prefix state"
        raise JournalIntegrityError(message)
