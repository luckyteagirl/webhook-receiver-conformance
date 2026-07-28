"""Journal-owned preflight and atomic persistence support for runtime resume."""
# ruff: noqa: D105, D107, EM101, EM102, INP001, TRY003

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from webhook_receiver_conformance.domain.enums import AttemptState
from webhook_receiver_conformance.domain.identifiers import validate_run_id
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.recovery.policy import (
    MAX_POLICY_ITEMS,
    PersistedScheduleSnapshot,
    RecoveryDecisionPlan,
    RedeliveryAttemptPlan,
    ResumePolicyIntegrityError,
    ResumePolicyPlan,
)
from webhook_receiver_conformance.recovery.scanner import (
    PHASE_CONTROLLED_PRE_TRANSPORT,
    PHASE_NO_CONNECTION_ESTABLISHED,
)
from webhook_receiver_conformance.scheduler.queue import ScheduleItem
from webhook_receiver_conformance.types import DiagnosticCode

from .integrity import ResumeIntegrityReport, verify_resume_integrity
from .schema import (
    DEFAULT_BUSY_TIMEOUT_MS,
    JOURNAL_FILENAME,
    MAX_BUSY_TIMEOUT_MS,
    SQLITE_SYNCHRONOUS_EXTRA,
    validate_migration_output,
)
from .service import (
    MAX_RESULT_ROWS,
    JournalService,
    JournalStatement,
    JournalTransaction,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

_MAX_OWNER_EPOCH = (2**63) - 1
_RUN_ROW_COLUMNS = 2
_SCHEDULE_ROW_COLUMNS = 10
_DECISION_ROW_COLUMNS = 10


class ResumeJournalError(RuntimeError):
    """A classified resume-journal contract failure."""

    category: ErrorCategory = ErrorCategory.INTEGRITY_ERROR
    code: DiagnosticCode = DiagnosticCode("RESUME_JOURNAL_ERROR")


class ResumeJournalPathError(ResumeJournalError):
    """The requested run directory or journal path is invalid."""

    code = DiagnosticCode("RESUME_JOURNAL_PATH_INVALID")


class ResumeJournalEpochError(ResumeJournalError):
    """The durable owner epoch changed or did not advance exactly once."""

    category = ErrorCategory.ILLEGAL_TRANSITION
    code = DiagnosticCode("RESUME_JOURNAL_EPOCH_INVALID")


class ResumeJournalProjectionError(ResumeJournalError):
    """A persisted resume projection is malformed or inconsistent."""

    code = DiagnosticCode("RESUME_JOURNAL_PROJECTION_INVALID")


@dataclass(frozen=True, slots=True)
class ResumeJournalPreflight:
    """Read-only proof needed before a resume may mutate lock or journal state."""

    run_directory: Path
    database_path: Path
    run_id: str
    owner_epoch: int
    integrity: ResumeIntegrityReport
    ambiguous_attempt_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        _owner_epoch(self.owner_epoch)
        if type(self.integrity) is not ResumeIntegrityReport:
            raise TypeError("integrity must be a ResumeIntegrityReport")
        if type(self.ambiguous_attempt_ids) is not tuple:
            raise TypeError("ambiguous_attempt_ids must be a tuple")

    @property
    def contains_ambiguity(self) -> bool:
        """Return whether the read-only preview found unresolved send evidence."""
        return bool(self.ambiguous_attempt_ids)


def preflight_resume_journal(
    run_directory: str | os.PathLike[str],
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> ResumeJournalPreflight:
    """Verify file, migration, integrity, run, and ambiguity without mutation."""
    directory, database_path = _resume_paths(run_directory)
    _busy_timeout(busy_timeout_ms)
    before = _file_signature(database_path)
    integrity = verify_resume_integrity(database_path)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"{database_path.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
            check_same_thread=True,
        )
        _configure_read_only_connection(
            connection,
            busy_timeout_ms=busy_timeout_ms,
        )
        validate_migration_output(connection)
        run_id, owner_epoch = _load_run_identity(connection)
        ambiguous_attempt_ids = _load_ambiguous_attempt_ids(connection, run_id)
    except ResumeJournalError:
        raise
    except sqlite3.Error as error:
        raise ResumeJournalProjectionError(
            "resume journal preflight could not read required projections"
        ) from error
    finally:
        if connection is not None:
            connection.close()
    if _file_signature(database_path) != before:
        raise ResumeJournalProjectionError("journal file identity changed during resume preflight")
    return ResumeJournalPreflight(
        run_directory=directory,
        database_path=database_path,
        run_id=run_id,
        owner_epoch=owner_epoch,
        integrity=integrity,
        ambiguous_attempt_ids=ambiguous_attempt_ids,
    )


async def advance_resume_owner_epoch(
    service: JournalService,
    *,
    run_id: str,
    previous_owner_epoch: int,
    new_owner_epoch: int,
) -> None:
    """Atomically advance the authoritative run owner epoch exactly once."""
    if not isinstance(service, JournalService):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("service must be a JournalService")
    await service.execute(
        _AdvanceOwnerEpoch(
            run_id=validate_run_id(run_id),
            previous_owner_epoch=_owner_epoch(previous_owner_epoch),
            new_owner_epoch=_owner_epoch(new_owner_epoch),
        )
    )


async def load_resume_schedule(
    service: JournalService,
    *,
    run_id: str,
    owner_epoch: int,
) -> PersistedScheduleSnapshot:
    """Load one bounded schedule snapshot under the fresh owner epoch."""
    if not isinstance(service, JournalService):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("service must be a JournalService")
    return await service.execute(
        _LoadSchedule(
            run_id=validate_run_id(run_id),
            owner_epoch=_owner_epoch(owner_epoch),
        )
    )


class ResumePolicyJournal:
    """Atomic adapter for policy decisions, redeliveries, and schedules."""

    __slots__ = ("_service",)

    def __init__(self, service: JournalService) -> None:
        if not isinstance(service, JournalService):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("service must be a JournalService")
        self._service = service

    async def commit_policy(self, plan: ResumePolicyPlan) -> bool:
        """Commit a complete policy plan or verify an exact replay."""
        if type(plan) is not ResumePolicyPlan:
            raise TypeError("plan must be a ResumePolicyPlan")
        return await self._service.execute(_CommitPolicy(plan))


@dataclass(frozen=True, slots=True)
class _AdvanceOwnerEpoch:
    run_id: str
    previous_owner_epoch: int
    new_owner_epoch: int

    def execute(self, transaction: JournalTransaction) -> None:
        if self.new_owner_epoch != self.previous_owner_epoch + 1:
            raise ResumeJournalEpochError("resume owner epoch must advance exactly once")
        result = transaction.execute(
            JournalStatement(
                """
                UPDATE runs
                SET owner_epoch = ?
                WHERE run_id = ? AND owner_epoch = ?
                """,
                (
                    self.new_owner_epoch,
                    self.run_id,
                    self.previous_owner_epoch,
                ),
            )
        )
        if result.rowcount != 1:
            raise ResumeJournalEpochError(
                "durable owner epoch changed before resume acquisition committed"
            )


@dataclass(frozen=True, slots=True)
class _LoadSchedule:
    run_id: str
    owner_epoch: int

    def execute(self, transaction: JournalTransaction) -> PersistedScheduleSnapshot:
        _require_owner_epoch(
            transaction,
            run_id=self.run_id,
            owner_epoch=self.owner_epoch,
        )
        count = transaction.execute(
            JournalStatement(
                "SELECT count(*) FROM schedule_entries WHERE run_id = ?",
                (self.run_id,),
            )
        )
        if len(count.rows) != 1 or len(count.rows[0]) != 1:
            raise ResumeJournalProjectionError("schedule inventory count has an invalid shape")
        total = _integer(count.rows[0][0], name="schedule inventory count")
        if total > MAX_POLICY_ITEMS:
            raise ResumeJournalProjectionError("schedule inventory exceeds the policy item limit")
        entries: list[ScheduleItem] = []
        consumed: set[str] = set()
        last_entry_id = ""
        while len(entries) < total:
            result = transaction.execute(
                JournalStatement(
                    """
                    SELECT
                        schedule_entry_id,
                        entity_id,
                        logical_time_ns,
                        scenario_ordinal,
                        step_ordinal,
                        delivery_ordinal,
                        attempt_ordinal,
                        deterministic_tie_key,
                        consumed_at,
                        consumed_by_owner_epoch
                    FROM schedule_entries
                    WHERE run_id = ? AND schedule_entry_id > ?
                    ORDER BY schedule_entry_id
                    LIMIT ?
                    """,
                    (self.run_id, last_entry_id, MAX_RESULT_ROWS),
                )
            )
            if not result.rows:
                break
            for row in result.rows:
                item, is_consumed = _schedule_item(row)
                entries.append(item)
                if is_consumed:
                    consumed.add(item.schedule_entry_id)
                last_entry_id = item.schedule_entry_id
        if len(entries) != total:
            raise ResumeJournalProjectionError("schedule inventory changed during its transaction")
        return PersistedScheduleSnapshot(
            entries=tuple(entries),
            consumed_entry_ids=frozenset(consumed),
        )


@dataclass(frozen=True, slots=True)
class _CommitPolicy:
    plan: ResumePolicyPlan

    def execute(self, transaction: JournalTransaction) -> bool:
        _require_owner_epoch(
            transaction,
            run_id=self.plan.run_id,
            owner_epoch=self.plan.owner_epoch,
        )
        existing = _existing_decision_ids(transaction, self.plan)
        if existing:
            if existing != {item.decision_id for item in self.plan.decisions}:
                raise ResumePolicyIntegrityError(
                    "policy commit contains a partial idempotent replay"
                )
            _verify_policy_replay(transaction, self.plan)
            return False
        next_sequence = _next_recovery_sequence(transaction, self.plan.run_id)
        for offset, decision in enumerate(self.plan.decisions):
            _insert_decision(
                transaction,
                decision,
                sequence=next_sequence + offset,
            )
        for redelivery in self.plan.redeliveries:
            _insert_redelivery(
                transaction,
                redelivery,
                owner_epoch=self.plan.owner_epoch,
            )
        return True


def _resume_paths(
    run_directory: str | os.PathLike[str],
) -> tuple[Path, Path]:
    try:
        raw = os.fspath(run_directory)
    except TypeError as error:
        raise ResumeJournalPathError("run directory must be filesystem text") from error
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if type(raw) is not str or not raw or "\x00" in raw:
        raise ResumeJournalPathError("run directory path is malformed")
    try:
        directory = Path(raw).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ResumeJournalPathError("run directory is unavailable") from error
    if not directory.is_dir():
        raise ResumeJournalPathError("run directory must be a directory")
    database_path = directory / JOURNAL_FILENAME
    return directory, database_path


def _configure_read_only_connection(
    connection: sqlite3.Connection,
    *,
    busy_timeout_ms: int,
) -> None:
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    connection.execute(f"PRAGMA synchronous = {SQLITE_SYNCHRONOUS_EXTRA}")
    connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")


def _load_run_identity(connection: sqlite3.Connection) -> tuple[str, int]:
    rows = connection.execute(
        "SELECT run_id, owner_epoch FROM runs ORDER BY run_id LIMIT 2"
    ).fetchall()
    if len(rows) != 1 or len(rows[0]) != _RUN_ROW_COLUMNS:
        raise ResumeJournalProjectionError("resume journal must contain exactly one run projection")
    return (
        validate_run_id(_text(rows[0][0], name="run_id")),
        _owner_epoch(rows[0][1]),
    )


def _load_ambiguous_attempt_ids(
    connection: sqlite3.Connection,
    run_id: str,
) -> tuple[str, ...]:
    rows = connection.execute(
        """
        SELECT attempt_id
        FROM attempts
        WHERE run_id = ?
          AND (
              state IN ('sending', 'awaiting_response', 'unknown_outcome')
              OR (
                  state = 'pre_send_committed'
                  AND (phase IS NULL OR phase <> ?)
              )
              OR (
                  state = 'connecting'
                  AND (phase IS NULL OR phase <> ?)
              )
          )
        ORDER BY attempt_id
        LIMIT ?
        """,
        (
            run_id,
            PHASE_CONTROLLED_PRE_TRANSPORT,
            PHASE_NO_CONNECTION_ESTABLISHED,
            MAX_POLICY_ITEMS + 1,
        ),
    ).fetchall()
    if len(rows) > MAX_POLICY_ITEMS:
        raise ResumeJournalProjectionError(
            "ambiguous attempt inventory exceeds the policy item limit"
        )
    return tuple(_text(row[0], name="ambiguous attempt_id") for row in rows)


def _require_owner_epoch(
    transaction: JournalTransaction,
    *,
    run_id: str,
    owner_epoch: int,
) -> None:
    result = transaction.execute(
        JournalStatement(
            "SELECT owner_epoch FROM runs WHERE run_id = ?",
            (run_id,),
        )
    )
    if result.rows != ((owner_epoch,),):
        raise ResumeJournalEpochError("resume journal operation used a stale owner epoch")


def _schedule_item(
    row: Sequence[object],
) -> tuple[ScheduleItem, bool]:
    if len(row) != _SCHEDULE_ROW_COLUMNS:
        raise ResumeJournalProjectionError("schedule row has an invalid shape")
    consumed_at = row[8]
    consumed_epoch = row[9]
    if (consumed_at is None) != (consumed_epoch is None):
        raise ResumeJournalProjectionError("schedule consumption evidence is incomplete")
    return (
        ScheduleItem(
            schedule_entry_id=_text(row[0], name="schedule_entry_id"),
            entity_id=_text(row[1], name="schedule entity_id"),
            logical_due_ns=_integer(row[2], name="schedule logical_time_ns"),
            scenario_ordinal=_integer(row[3], name="schedule scenario_ordinal"),
            step_ordinal=_integer(row[4], name="schedule step_ordinal"),
            delivery_ordinal=_integer(row[5], name="schedule delivery_ordinal"),
            attempt_ordinal=_integer(row[6], name="schedule attempt_ordinal"),
            deterministic_tie_key=_text(
                row[7],
                name="schedule deterministic_tie_key",
            ),
        ),
        consumed_at is not None,
    )


def _existing_decision_ids(
    transaction: JournalTransaction,
    plan: ResumePolicyPlan,
) -> set[str]:
    existing: set[str] = set()
    for decision in plan.decisions:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT decision_id
                FROM recovery_decisions
                WHERE run_id = ? AND decision_id = ?
                """,
                (plan.run_id, decision.decision_id),
            )
        )
        if result.rows:
            existing.add(_text(result.rows[0][0], name="decision_id"))
    return existing


def _next_recovery_sequence(
    transaction: JournalTransaction,
    run_id: str,
) -> int:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT COALESCE(MAX(sequence), 0) + 1
            FROM recovery_decisions
            WHERE run_id = ?
            """,
            (run_id,),
        )
    )
    if len(result.rows) != 1 or len(result.rows[0]) != 1:
        raise ResumeJournalProjectionError("recovery decision sequence has an invalid shape")
    return _integer(result.rows[0][0], name="recovery decision sequence")


def _insert_decision(
    transaction: JournalTransaction,
    decision: object,
    *,
    sequence: int,
) -> None:
    if type(decision) is not RecoveryDecisionPlan:
        raise TypeError("decision must be a RecoveryDecisionPlan")
    result = transaction.execute(
        JournalStatement(
            """
            INSERT INTO recovery_decisions (
                decision_id, run_id, sequence, scenario_id, attempt_id,
                policy, decision, reason, operator_identity_fingerprint,
                operator_input_digest, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision.decision_id,
                decision.run_id,
                sequence,
                decision.scenario_id,
                decision.attempt_id,
                decision.policy.value,
                decision.decision.value,
                decision.reason,
                decision.operator_identity_fingerprint,
                decision.operator_input_digest,
                _wall_timestamp(decision.timestamp.wall_time),
            ),
        )
    )
    if result.rowcount != 1:
        raise ResumeJournalProjectionError("recovery decision insert did not affect one row")
    for ordinal, evidence in enumerate(decision.evidence):
        linked = transaction.execute(
            JournalStatement(
                """
                INSERT INTO recovery_decision_evidence (
                    decision_id, run_id, ordinal, evidence_kind, evidence_id
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    decision.decision_id,
                    decision.run_id,
                    ordinal,
                    evidence.evidence_kind,
                    evidence.evidence_id,
                ),
            )
        )
        if linked.rowcount != 1:
            raise ResumeJournalProjectionError(
                "recovery decision evidence insert did not affect one row"
            )


def _insert_redelivery(
    transaction: JournalTransaction,
    redelivery: object,
    *,
    owner_epoch: int,
) -> None:
    if type(redelivery) is not RedeliveryAttemptPlan:
        raise TypeError("redelivery must be a RedeliveryAttemptPlan")
    predecessor = transaction.execute(
        JournalStatement(
            """
            SELECT state
            FROM attempts
            WHERE run_id = ? AND scenario_id = ? AND attempt_id = ?
            """,
            (
                redelivery.run_id,
                redelivery.scenario_id,
                redelivery.predecessor_attempt_id,
            ),
        )
    )
    if predecessor.rows != ((AttemptState.UNKNOWN_OUTCOME.value,),):
        raise ResumePolicyIntegrityError(
            "redelivery predecessor is not a preserved unknown_outcome"
        )
    attempt = transaction.execute(
        JournalStatement(
            """
            INSERT INTO attempts (
                attempt_id, run_id, scenario_id, event_id, delivery_id,
                attempt_plan_id, ordinal, state, predecessor_attempt_id,
                owner_epoch
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'scheduled', ?, ?)
            """,
            (
                redelivery.attempt_id,
                redelivery.run_id,
                redelivery.scenario_id,
                redelivery.event_id,
                redelivery.delivery_id,
                redelivery.attempt_plan_id,
                redelivery.attempt_ordinal,
                redelivery.predecessor_attempt_id,
                owner_epoch,
            ),
        )
    )
    if attempt.rowcount != 1:
        raise ResumeJournalProjectionError("redelivery attempt insert did not affect one row")
    item = redelivery.schedule_item
    schedule = transaction.execute(
        JournalStatement(
            """
            INSERT INTO schedule_entries (
                schedule_entry_id, run_id, scenario_id, entity_type,
                entity_id, logical_time_ns, scenario_ordinal, step_ordinal,
                delivery_ordinal, attempt_ordinal, deterministic_tie_key,
                condition_json, idempotency_key
            ) VALUES (?, ?, ?, 'attempt', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item.schedule_entry_id,
                redelivery.run_id,
                redelivery.scenario_id,
                item.entity_id,
                item.logical_due_ns,
                item.scenario_ordinal,
                item.step_ordinal,
                item.delivery_ordinal,
                item.attempt_ordinal,
                item.deterministic_tie_key,
                redelivery.condition_json,
                redelivery.schedule_idempotency_key,
            ),
        )
    )
    if schedule.rowcount != 1:
        raise ResumeJournalProjectionError("redelivery schedule insert did not affect one row")


def _verify_policy_replay(
    transaction: JournalTransaction,
    plan: ResumePolicyPlan,
) -> None:
    for decision in plan.decisions:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT
                    run_id, scenario_id, attempt_id, policy, decision, reason,
                    operator_identity_fingerprint, operator_input_digest,
                    recorded_at, decision_id
                FROM recovery_decisions
                WHERE run_id = ? AND decision_id = ?
                """,
                (plan.run_id, decision.decision_id),
            )
        )
        expected = (
            decision.run_id,
            decision.scenario_id,
            decision.attempt_id,
            decision.policy.value,
            decision.decision.value,
            decision.reason,
            decision.operator_identity_fingerprint,
            decision.operator_input_digest,
            _wall_timestamp(decision.timestamp.wall_time),
            decision.decision_id,
        )
        if (
            len(result.rows) != 1
            or len(result.rows[0]) != _DECISION_ROW_COLUMNS
            or tuple(result.rows[0]) != expected
        ):
            raise ResumePolicyIntegrityError(
                "replayed recovery decision differs from durable evidence"
            )
        evidence = transaction.execute(
            JournalStatement(
                """
                SELECT evidence_kind, evidence_id
                FROM recovery_decision_evidence
                WHERE run_id = ? AND decision_id = ?
                ORDER BY ordinal
                """,
                (plan.run_id, decision.decision_id),
            )
        )
        expected_evidence = tuple(
            (item.evidence_kind, item.evidence_id) for item in decision.evidence
        )
        if evidence.rows != expected_evidence:
            raise ResumePolicyIntegrityError("replayed recovery decision evidence differs")
    for redelivery in plan.redeliveries:
        attempt = transaction.execute(
            JournalStatement(
                """
                SELECT
                    run_id, scenario_id, event_id, delivery_id,
                    attempt_plan_id, ordinal, state,
                    predecessor_attempt_id, owner_epoch
                FROM attempts
                WHERE attempt_id = ?
                """,
                (redelivery.attempt_id,),
            )
        )
        expected_attempt = (
            redelivery.run_id,
            redelivery.scenario_id,
            redelivery.event_id,
            redelivery.delivery_id,
            redelivery.attempt_plan_id,
            redelivery.attempt_ordinal,
            AttemptState.SCHEDULED.value,
            redelivery.predecessor_attempt_id,
            plan.owner_epoch,
        )
        if attempt.rows != (expected_attempt,):
            raise ResumePolicyIntegrityError("replayed redelivery attempt differs")
        item = redelivery.schedule_item
        schedule = transaction.execute(
            JournalStatement(
                """
                SELECT
                    run_id, scenario_id, entity_type, entity_id,
                    logical_time_ns, scenario_ordinal, step_ordinal,
                    delivery_ordinal, attempt_ordinal,
                    deterministic_tie_key, condition_json, idempotency_key
                FROM schedule_entries
                WHERE schedule_entry_id = ?
                """,
                (item.schedule_entry_id,),
            )
        )
        expected_schedule = (
            redelivery.run_id,
            redelivery.scenario_id,
            "attempt",
            item.entity_id,
            item.logical_due_ns,
            item.scenario_ordinal,
            item.step_ordinal,
            item.delivery_ordinal,
            item.attempt_ordinal,
            item.deterministic_tie_key,
            redelivery.condition_json,
            redelivery.schedule_idempotency_key,
        )
        if schedule.rows != (expected_schedule,):
            raise ResumePolicyIntegrityError("replayed redelivery schedule differs")


def _file_signature(path: Path) -> tuple[int, int, int, int, int]:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ResumeJournalPathError("journal database is unavailable") from error
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _wall_timestamp(value: object) -> str:
    if not isinstance(value, datetime):
        raise TypeError("wall timestamp must be a datetime")
    normalized = value.astimezone(UTC)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _busy_timeout(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_BUSY_TIMEOUT_MS:
        raise ValueError(f"busy_timeout_ms must be in the range 1..{MAX_BUSY_TIMEOUT_MS}")
    return value


def _owner_epoch(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_OWNER_EPOCH:
        raise ResumeJournalEpochError("owner_epoch must be a nonnegative SQLite int64")
    return value


def _integer(value: object, *, name: str) -> int:
    if type(value) is not int:
        raise ResumeJournalProjectionError(f"{name} is not an integer")
    return value


def _text(value: object, *, name: str) -> str:
    if type(value) is not str or not value:
        raise ResumeJournalProjectionError(f"{name} is not text")
    return value
