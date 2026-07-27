"""Read-only, pre-open SQLite integrity checks for resume."""
# ruff: noqa: EM101, INP001, TRY003, TRY301

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from webhook_receiver_conformance.errors import ErrorCategory, ResultCategory
from webhook_receiver_conformance.types import DiagnosticCode

MAX_DATABASE_PATH_CHARACTERS: Final = 4_096
MAX_QUICK_CHECK_ROWS: Final = 100
_WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ResumeIntegrityError(RuntimeError):
    """A safe harness failure raised before resume may schedule work."""

    category: ErrorCategory = ErrorCategory.INTEGRITY_ERROR
    result_category: ResultCategory = ResultCategory.HARNESS_ERROR
    code: DiagnosticCode = DiagnosticCode("JOURNAL_RESUME_INTEGRITY_FAILED")

    def __init__(self, message: str, *, check: str) -> None:
        """Retain only a stable check name and privacy-safe message."""
        self.check = check
        super().__init__(message)


class ResumeDatabasePathError(ResumeIntegrityError):
    """The resume database is not one private local regular file."""

    code = DiagnosticCode("JOURNAL_RESUME_PATH_INVALID")


@dataclass(frozen=True, slots=True)
class ResumeIntegrityReport:
    """Bounded proof that both mandatory checks completed successfully."""

    database_bytes: int
    quick_check: str = "ok"
    foreign_key_violations: int = 0
    read_only: bool = True

    def __post_init__(self) -> None:
        """Require the only successful report shape."""
        if type(self.database_bytes) is not int or self.database_bytes < 0:
            message = "database byte count must be a nonnegative integer"
            raise ValueError(message)
        if (
            self.quick_check != "ok"
            or self.foreign_key_violations != 0
            or self.read_only is not True
        ):
            message = "successful resume integrity evidence is inconsistent"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    byte_length: int
    modified_ns: int
    changed_ns: int


def verify_resume_integrity(
    database_path: str | os.PathLike[str],
) -> ResumeIntegrityReport:
    """Run mandatory SQLite checks without modifying or replacing the database."""
    path, before = _validated_database_file(database_path)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"{path.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
            check_same_thread=True,
        )
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        quick_rows = connection.execute(f"PRAGMA quick_check({MAX_QUICK_CHECK_ROWS})").fetchmany(
            MAX_QUICK_CHECK_ROWS + 1
        )
        if quick_rows != [("ok",)]:
            raise ResumeIntegrityError(
                "SQLite quick_check reported journal corruption",
                check="quick_check",
            )
        foreign_key_row = connection.execute("PRAGMA foreign_key_check").fetchone()
        if foreign_key_row is not None:
            raise ResumeIntegrityError(
                "SQLite foreign_key_check reported invalid references",
                check="foreign_key_check",
            )
    except ResumeIntegrityError:
        raise
    except sqlite3.Error as error:
        raise ResumeIntegrityError(
            "SQLite resume integrity checks could not be completed",
            check="sqlite",
        ) from error
    finally:
        if connection is not None:
            connection.close()
    _, after = _validated_database_file(path)
    if after != before:
        raise ResumeDatabasePathError(
            "journal file identity changed during resume integrity checks",
            check="file_identity",
        )
    return ResumeIntegrityReport(database_bytes=after.byte_length)


def _validated_database_file(
    value: str | os.PathLike[str],
) -> tuple[Path, _FileIdentity]:
    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise ResumeDatabasePathError(
            "journal path must be filesystem text",
            check="path",
        ) from error
    if isinstance(raw, bytes):
        try:
            raw = os.fsdecode(raw)
        except UnicodeError as error:
            raise ResumeDatabasePathError(
                "journal path is not valid filesystem text",
                check="path",
            ) from error
    if type(raw) is not str or not raw or len(raw) > MAX_DATABASE_PATH_CHARACTERS or "\x00" in raw:
        raise ResumeDatabasePathError(
            "journal path is empty, malformed, or unbounded",
            check="path",
        )
    path = Path(raw).absolute()
    _reject_reparse_components(path)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ResumeDatabasePathError(
            "journal database is unavailable",
            check="path",
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or _is_reparse_point(metadata):
        raise ResumeDatabasePathError(
            "journal database must be one private regular file",
            check="path",
        )
    return path, _identity(metadata)


def _reject_reparse_components(path: Path) -> None:
    current = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        current /= part
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError as error:
            raise ResumeDatabasePathError(
                "journal path contains an unavailable component",
                check="path",
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise ResumeDatabasePathError(
                "journal path cannot traverse a link or reparse point",
                check="path",
            )


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & _WINDOWS_REPARSE_POINT)


def _identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        byte_length=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )
