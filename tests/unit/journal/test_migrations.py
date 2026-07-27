"""Migration, initial-schema, crash, integrity, and permission tests."""
# ruff: noqa: INP001, PLR0913, PLR2004, S603, S608

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import stat
import subprocess
import sys
import zlib
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import webhook_receiver_conformance.journal.schema as journal_schema
from webhook_receiver_conformance.domain.enums import (
    AssertionState,
    AttemptState,
    DeliveryState,
    ObservationState,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.journal.schema import (
    DEFAULT_BUSY_TIMEOUT_MS,
    JOURNAL_FILENAME,
    MIGRATIONS,
    AppliedMigration,
    CrashPhase,
    JournalIntegrityError,
    JournalPathError,
    JournalSchemaError,
    Migration,
    MigrationChecksumError,
    MigrationCrashPoint,
    MigrationDefinitionError,
    MigrationExecutionError,
    UnsupportedDatabaseVersionError,
    apply_migrations,
    configure_connection,
    create_journal_database,
    create_run_database,
    migration_crash_points,
    open_journal_database,
    validate_migration_catalog,
    validate_migration_output,
    verify_migration_ledger,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator, Sequence

TIMESTAMP = "2026-07-27T12:34:56.000000Z"
FIXED_CLOCK = datetime(2026, 7, 27, 12, 34, 56, tzinfo=UTC)
RUN_ID = "00000000-0000-4000-8000-000000000001"
MANIFEST_ID = "a" * 64
DIGEST = f"sha256:{'b' * 64}"
INITIAL_CHECKSUM = "sha256:3c8fe9f0de7f3d6537a1f4086f321ed20c56e3e1907ccb8ccbcd4b957ce3300b"
GOLDEN_V0_SHA256 = "ac7fbf4732ec6b1a11c3af81cea48005c158e39d9043800a4d7895506a32b5b5"
GOLDEN_V0_IMAGE = zlib.decompress(
    base64.b64decode(
        "eNoLDvTJLElVSMsvyk0sUTBmEGBgZGRwUFBgYGBghGIYQGYTCxgZ9Mo6eUEs"
        "AYZRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBQMEAAAR1YHDw=="
    )
)
CRASH_PROCESS_EXIT_CODE = 91
CRASH_PROCESS_SCRIPT = r"""
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from webhook_receiver_conformance.journal.schema import (
    MIGRATIONS,
    CrashPhase,
    Migration,
    MigrationCrashPoint,
    apply_migrations,
    create_journal_database,
    open_journal_database,
)

database = Path(sys.argv[1])
phase = CrashPhase(sys.argv[2])
statement_index = None if sys.argv[3] == "none" else int(sys.argv[3])
target = MigrationCrashPoint(int(sys.argv[4]), phase, statement_index)
fixed_clock = datetime(2026, 7, 27, 12, 34, 56, tzinfo=UTC)

def crash(point: MigrationCrashPoint) -> None:
    if point == target:
        os._exit(91)

if target.migration_id == 1:
    create_journal_database(
        database,
        migrations=(MIGRATIONS[0],),
        crash_hook=crash,
        clock=lambda: fixed_clock,
    )
else:
    connection = create_journal_database(
        database,
        migrations=(MIGRATIONS[0],),
        clock=lambda: fixed_clock,
    )
    apply_migrations(
        connection,
        migrations=MIGRATIONS,
        crash_hook=crash,
        clock=lambda: fixed_clock,
        no_backup=True,
    )
"""


@pytest.fixture
def journal(tmp_path: Path) -> Generator[sqlite3.Connection, None, None]:
    connection = create_journal_database(
        tmp_path / JOURNAL_FILENAME,
        clock=lambda: FIXED_CLOCK,
    )
    try:
        yield connection
    finally:
        connection.close()


def _planned(prefix: str, suffix: int = 0) -> str:
    return f"{prefix}_{suffix:026d}"


def _fresh(prefix: str, suffix: int = 0) -> str:
    return f"{prefix}_{suffix:026d}"


SCENARIO_ID = _planned("scenario")
EVENT_ID = _planned("event")
DELIVERY_ID = _planned("delivery")
OBSERVATION_ID = _planned("observation")
ASSERTION_ID = _planned("assertion")
ATTEMPT_ID = _fresh("attempt")
SAMPLE_ID = _fresh("sample")
EVALUATION_ID = _fresh("evaluation")
OBSERVATION_RECORD_ID = _fresh("record")
ASSERTION_RECORD_ID = _fresh("record", 1)
ATTEMPT_RECORD_ID = _fresh("record", 2)

_ATTEMPT_RECORD_INSERT = """
    INSERT INTO attempt_records (
        record_id,
        schema_version,
        run_id,
        scenario_id,
        event_id,
        delivery_id,
        attempt_id,
        sequence,
        recorded_at,
        logical_time_ns,
        monotonic_elapsed_ns,
        state,
        classification,
        request_method,
        request_url_redacted,
        request_body_sha256,
        request_byte_length,
        request_header_names_json,
        response_status,
        response_body_sha256,
        response_captured_bytes,
        response_truncated,
        error_category,
        error_message_redacted,
        error_phase
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?
    )
"""


@contextmanager
def _write(connection: sqlite3.Connection) -> Generator[None, None, None]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        connection.execute("ROLLBACK")
        raise
    else:
        connection.execute("COMMIT")


def _reject(
    connection: sqlite3.Connection,
    sql: str,
    parameters: Sequence[object] = (),
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(sql, parameters)
    finally:
        connection.execute("ROLLBACK")


def _insert_run(
    connection: sqlite3.Connection,
    *,
    run_id: str = RUN_ID,
    state: str = RunState.PLANNED,
) -> None:
    connection.execute(
        """
        INSERT INTO runs (run_id, manifest_id, state, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (run_id, MANIFEST_ID, state, TIMESTAMP),
    )


def _insert_scenario(
    connection: sqlite3.Connection,
    *,
    scenario_id: str = SCENARIO_ID,
    ordinal: int = 0,
    state: str = ScenarioState.PENDING,
) -> None:
    connection.execute(
        """
        INSERT INTO scenarios (scenario_id, run_id, ordinal, name, state)
        VALUES (?, ?, ?, ?, ?)
        """,
        (scenario_id, RUN_ID, ordinal, "scenario", state),
    )


def _insert_event(
    connection: sqlite3.Connection,
    *,
    event_id: str = EVENT_ID,
    scenario_id: str = SCENARIO_ID,
    ordinal: int = 0,
) -> None:
    connection.execute(
        """
        INSERT INTO events (
            event_id,
            run_id,
            scenario_id,
            ordinal,
            event_type,
            fixture_blob_hash
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (event_id, RUN_ID, scenario_id, ordinal, "payment.succeeded", DIGEST),
    )


def _insert_delivery(
    connection: sqlite3.Connection,
    *,
    delivery_id: str = DELIVERY_ID,
    event_id: str = EVENT_ID,
    ordinal: int = 0,
    state: str = DeliveryState.PENDING,
) -> None:
    connection.execute(
        """
        INSERT INTO deliveries (
            delivery_id,
            run_id,
            scenario_id,
            event_id,
            ordinal,
            logical_time_ns,
            state
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (delivery_id, RUN_ID, SCENARIO_ID, event_id, ordinal, 0, state),
    )


def _insert_attempt(
    connection: sqlite3.Connection,
    *,
    attempt_id: str = ATTEMPT_ID,
    ordinal: int = 0,
    state: str = AttemptState.SCHEDULED,
) -> None:
    connection.execute(
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
            attempt_id,
            RUN_ID,
            SCENARIO_ID,
            EVENT_ID,
            DELIVERY_ID,
            ordinal,
            state,
        ),
    )


def _attempt_record_values(**overrides: object) -> tuple[object, ...]:
    names = (
        "record_id",
        "schema_version",
        "run_id",
        "scenario_id",
        "event_id",
        "delivery_id",
        "attempt_id",
        "sequence",
        "recorded_at",
        "logical_time_ns",
        "monotonic_elapsed_ns",
        "state",
        "classification",
        "request_method",
        "request_url_redacted",
        "request_body_sha256",
        "request_byte_length",
        "request_header_names_json",
        "response_status",
        "response_body_sha256",
        "response_captured_bytes",
        "response_truncated",
        "error_category",
        "error_message_redacted",
        "error_phase",
    )
    values: dict[str, object] = {
        "record_id": ATTEMPT_RECORD_ID,
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "scenario_id": SCENARIO_ID,
        "event_id": EVENT_ID,
        "delivery_id": DELIVERY_ID,
        "attempt_id": ATTEMPT_ID,
        "sequence": 1,
        "recorded_at": TIMESTAMP,
        "logical_time_ns": 0,
        "monotonic_elapsed_ns": 123,
        "state": "acknowledged",
        "classification": "receiver_accepted",
        "request_method": "POST",
        "request_url_redacted": "http://127.0.0.1/webhook",
        "request_body_sha256": DIGEST,
        "request_byte_length": 17,
        "request_header_names_json": b'["content-type","x-request-id"]',
        "response_status": 200,
        "response_body_sha256": DIGEST,
        "response_captured_bytes": 2,
        "response_truncated": 0,
        "error_category": None,
        "error_message_redacted": None,
        "error_phase": None,
    }
    unknown = set(overrides) - set(values)
    if unknown:
        message = f"unknown attempt-record fields: {sorted(unknown)}"
        raise AssertionError(message)
    values.update(overrides)
    return tuple(values[name] for name in names)


def _insert_attempt_record(
    connection: sqlite3.Connection,
    **overrides: object,
) -> None:
    connection.execute(
        _ATTEMPT_RECORD_INSERT,
        _attempt_record_values(**overrides),
    )


def _insert_observation(
    connection: sqlite3.Connection,
    *,
    observation_id: str = OBSERVATION_ID,
    state: str = ObservationState.SCHEDULED,
) -> None:
    connection.execute(
        """
        INSERT INTO observer_series (
            observation_id,
            run_id,
            scenario_id,
            event_id,
            checkpoint,
            observer_id,
            state
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            observation_id,
            RUN_ID,
            SCENARIO_ID,
            EVENT_ID,
            "after_delivery",
            "receiver_state",
            state,
        ),
    )


def _insert_assertion(
    connection: sqlite3.Connection,
    *,
    assertion_id: str = ASSERTION_ID,
    state: str = AssertionState.PENDING,
) -> None:
    connection.execute(
        """
        INSERT INTO assertions (
            assertion_id,
            run_id,
            scenario_id,
            type,
            state
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (assertion_id, RUN_ID, SCENARIO_ID, "delivery_count", state),
    )


def _seed_graph(connection: sqlite3.Connection) -> None:
    with _write(connection):
        _insert_run(connection)
        _insert_scenario(connection)
        _insert_event(connection)
        _insert_delivery(connection)
        _insert_attempt(connection)
        _insert_observation(connection)
        _insert_assertion(connection)


def _insert_transition(
    connection: sqlite3.Connection,
    *,
    sequence: int,
    entity_type: str,
    entity_id: str,
    from_state: str | None,
    to_state: str,
) -> None:
    connection.execute(
        """
        INSERT INTO transitions (
            transition_id,
            run_id,
            sequence,
            entity_type,
            entity_id,
            from_state,
            to_state,
            trigger_category,
            wall_time,
            monotonic_elapsed_ns,
            owner_epoch,
            idempotency_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"transition_{sequence}",
            RUN_ID,
            sequence,
            entity_type,
            entity_id,
            from_state,
            to_state,
            "import",
            TIMESTAMP,
            sequence,
            0,
            f"transition:{sequence}",
        ),
    )


def _raw_user_version(database: Path) -> tuple[int, bool, str]:
    connection = sqlite3.connect(database)
    try:
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        has_ledger = (
            connection.execute(
                """
                SELECT 1
                FROM sqlite_schema
                WHERE type = 'table' AND name = 'schema_migrations'
                """
            ).fetchone()
            is not None
        )
        integrity_check = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        return user_version, has_ledger, integrity_check
    finally:
        connection.close()


def _run_crash_process(database: Path, target: MigrationCrashPoint) -> None:
    statement_index = "none" if target.statement_index is None else str(target.statement_index)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            CRASH_PROCESS_SCRIPT,
            str(database),
            target.phase,
            statement_index,
            str(target.migration_id),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == CRASH_PROCESS_EXIT_CODE, (
        target,
        result.stdout,
        result.stderr,
    )


def _install_path_replacement_race(
    monkeypatch: pytest.MonkeyPatch,
    *,
    target: Path,
    displaced: Path,
    victim: Path,
) -> dict[str, bool]:
    original_connect: Callable[..., sqlite3.Connection] = sqlite3.connect
    state = {"attempted": False, "blocked": False}

    def racing_connect(
        database: str | bytes | os.PathLike[str],
        *args: object,
        **kwargs: object,
    ) -> sqlite3.Connection:
        state["attempted"] = True
        try:
            target.rename(displaced)
        except OSError:
            state["blocked"] = True
        else:
            victim.rename(target)
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", racing_connect)
    return state


def test_golden_empty_database_migrates_through_frozen_v1_to_v2(tmp_path: Path) -> None:
    database = tmp_path / JOURNAL_FILENAME
    assert len(GOLDEN_V0_IMAGE) == 4096
    assert hashlib.sha256(GOLDEN_V0_IMAGE).hexdigest() == GOLDEN_V0_SHA256
    database.write_bytes(GOLDEN_V0_IMAGE)
    frozen_before = database.read_bytes()
    assert frozen_before == GOLDEN_V0_IMAGE
    connection = open_journal_database(
        database,
        clock=lambda: FIXED_CLOCK,
    )
    try:
        ledger = verify_migration_ledger(connection)
        assert ledger == (
            AppliedMigration(
                migration_id=1,
                name="initial_journal",
                checksum=INITIAL_CHECKSUM,
                applied_at=TIMESTAMP,
            ),
            AppliedMigration(
                migration_id=2,
                name="add_attempt_records",
                checksum=MIGRATIONS[1].checksum,
                applied_at=TIMESTAMP,
            ),
        )
        assert MIGRATIONS[0].checksum == INITIAL_CHECKSUM
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()


def test_connection_policy_and_explicit_migration_transaction(tmp_path: Path) -> None:
    database = tmp_path / JOURNAL_FILENAME
    raw = sqlite3.connect(database, isolation_level=None)
    configure_connection(raw)
    trace: list[str] = []
    raw.set_trace_callback(trace.append)
    try:
        apply_migrations(raw, clock=lambda: FIXED_CLOCK)
        assert raw.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert raw.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert raw.execute("PRAGMA synchronous").fetchone()[0] == 3
        assert raw.execute("PRAGMA busy_timeout").fetchone()[0] == DEFAULT_BUSY_TIMEOUT_MS
    finally:
        raw.close()
    normalized = [statement.strip().upper() for statement in trace]
    assert "BEGIN IMMEDIATE" in normalized
    assert "COMMIT" in normalized
    assert "BEGIN " not in normalized
    assert all(statement != "BEGIN" for statement in normalized)


def test_required_tables_and_foreign_keys_are_immediate(
    journal: sqlite3.Connection,
) -> None:
    expected = {
        "schema_migrations",
        "runs",
        "scenarios",
        "events",
        "event_dependencies",
        "deliveries",
        "attempts",
        "attempt_records",
        "schedule_entries",
        "observer_series",
        "observation_samples",
        "assertions",
        "assertion_evaluations",
        "evidence_links",
        "transitions",
        "recovery_decisions",
        "recovery_decision_evidence",
        "redaction_events",
        "artifacts",
    }
    rows = journal.execute("SELECT name, sql FROM sqlite_schema WHERE type = 'table'").fetchall()
    assert {str(row[0]) for row in rows} == expected
    assert all(" STRICT" in str(row[1]).upper() for row in rows)
    assert all("DEFERRABLE" not in str(row[1]).upper() for row in rows)
    assert (
        sum(
            len(journal.execute(f'PRAGMA foreign_key_list("{table}")').fetchall())
            for table in expected
        )
        >= 20
    )


def test_attempt_record_boundary_is_normalized_bounded_and_identity_exact(
    journal: sqlite3.Connection,
) -> None:
    _seed_graph(journal)
    columns = {
        str(row[1]): str(row[2])
        for row in journal.execute("PRAGMA table_info(attempt_records)").fetchall()
    }
    assert columns["request_header_names_json"] == "BLOB"
    assert {
        "request_body",
        "request_headers",
        "response_body",
        "authorization",
    }.isdisjoint(columns)

    hostile_values = (
        {"record_id": "record_invalid"},
        {"schema_version": "2.0"},
        {"sequence": 0},
        {"sequence": 9_007_199_254_740_992},
        {"state": "scheduled", "classification": "planned"},
        {"classification": "harness_failure"},
        {"request_url_redacted": None},
        {"request_header_names_json": '["content-type"]'},
        {"request_header_names_json": b"x" * 16_385},
        {"response_status": None},
        {
            "error_category": "unsafe",
            "error_message_redacted": "must not accompany acknowledgement",
        },
        {
            "state": "connection_failed",
            "classification": "environment_failure",
            "response_status": None,
            "response_body_sha256": None,
            "response_captured_bytes": None,
            "response_truncated": None,
        },
        {
            "state": "cancelled",
            "classification": "cancelled",
        },
        {"scenario_id": _planned("scenario", 99)},
    )
    for overrides in hostile_values:
        _reject(
            journal,
            _ATTEMPT_RECORD_INSERT,
            _attempt_record_values(**overrides),
        )

    with _write(journal):
        _insert_attempt_record(journal)
    persisted = journal.execute(
        """
        SELECT
            typeof(request_header_names_json),
            request_header_names_json,
            state,
            classification
        FROM attempt_records
        """
    ).fetchone()
    assert persisted is not None
    assert tuple(persisted) == (
        "blob",
        b'["content-type","x-request-id"]',
        "acknowledged",
        "receiver_accepted",
    )
    _reject(
        journal,
        _ATTEMPT_RECORD_INSERT,
        _attempt_record_values(
            record_id=_fresh("record", 3),
            sequence=2,
        ),
    )


@pytest.mark.parametrize(
    ("table", "identifier_column", "identifier", "states"),
    [
        ("runs", "run_id", RUN_ID, tuple(RunState)),
        ("scenarios", "scenario_id", SCENARIO_ID, tuple(ScenarioState)),
        ("deliveries", "delivery_id", DELIVERY_ID, tuple(DeliveryState)),
        ("attempts", "attempt_id", ATTEMPT_ID, tuple(AttemptState)),
        (
            "observer_series",
            "observation_id",
            OBSERVATION_ID,
            tuple(ObservationState),
        ),
        ("assertions", "assertion_id", ASSERTION_ID, tuple(AssertionState)),
    ],
)
def test_projection_state_checks_match_closed_domain_vocabularies(
    journal: sqlite3.Connection,
    table: str,
    identifier_column: str,
    identifier: str,
    states: tuple[object, ...],
) -> None:
    _seed_graph(journal)
    for state in states:
        with _write(journal):
            journal.execute(
                f"UPDATE {table} SET state = ? WHERE {identifier_column} = ?",
                (str(state), identifier),
            )
    _reject(
        journal,
        f"UPDATE {table} SET state = ? WHERE {identifier_column} = ?",
        ("undeclared_state", identifier),
    )


@pytest.mark.parametrize(
    ("entity_type", "entity_id", "initial_state"),
    [
        ("run", RUN_ID, RunState.PLANNED),
        ("scenario", SCENARIO_ID, ScenarioState.PENDING),
        ("delivery", DELIVERY_ID, DeliveryState.PENDING),
        ("attempt", ATTEMPT_ID, AttemptState.SCHEDULED),
        ("observation", OBSERVATION_ID, ObservationState.SCHEDULED),
        ("assertion", ASSERTION_ID, AssertionState.PENDING),
    ],
)
def test_transition_rows_reject_undeclared_state_values(
    journal: sqlite3.Connection,
    entity_type: str,
    entity_id: str,
    initial_state: object,
) -> None:
    _seed_graph(journal)
    _reject(
        journal,
        """
        INSERT INTO transitions (
            transition_id, run_id, sequence, entity_type, entity_id,
            from_state, to_state, trigger_category, wall_time,
            monotonic_elapsed_ns, owner_epoch, idempotency_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"invalid_from_{entity_type}",
            RUN_ID,
            100,
            entity_type,
            entity_id,
            "undeclared_state",
            str(initial_state),
            "test",
            TIMESTAMP,
            1,
            0,
            f"invalid:from:{entity_type}",
        ),
    )
    _reject(
        journal,
        """
        INSERT INTO transitions (
            transition_id, run_id, sequence, entity_type, entity_id,
            from_state, to_state, trigger_category, wall_time,
            monotonic_elapsed_ns, owner_epoch, idempotency_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"invalid_to_{entity_type}",
            RUN_ID,
            101,
            entity_type,
            entity_id,
            str(initial_state),
            "undeclared_state",
            "test",
            TIMESTAMP,
            1,
            0,
            f"invalid:to:{entity_type}",
        ),
    )


def test_scoped_uniqueness_is_enforced_at_database_boundary(
    journal: sqlite3.Connection,
) -> None:
    _seed_graph(journal)
    _reject(
        journal,
        """
        INSERT INTO scenarios (scenario_id, run_id, ordinal, name, state)
        VALUES (?, ?, 0, 'duplicate ordinal', 'pending')
        """,
        (_planned("scenario", 1), RUN_ID),
    )
    second_event = _planned("event", 1)
    with _write(journal):
        _insert_event(journal, event_id=second_event, ordinal=1)
    _reject(
        journal,
        """
        INSERT INTO deliveries (
            delivery_id, run_id, scenario_id, event_id, ordinal,
            logical_time_ns, state
        ) VALUES (?, ?, ?, ?, 0, 1, 'pending')
        """,
        (_planned("delivery", 1), RUN_ID, SCENARIO_ID, second_event),
    )
    _reject(
        journal,
        """
        INSERT INTO attempts (
            attempt_id, run_id, scenario_id, event_id, delivery_id, ordinal, state
        ) VALUES (?, ?, ?, ?, ?, 0, 'scheduled')
        """,
        (_fresh("attempt", 1), RUN_ID, SCENARIO_ID, EVENT_ID, DELIVERY_ID),
    )


def test_orphan_and_cross_scenario_references_are_rejected(
    journal: sqlite3.Connection,
) -> None:
    _reject(
        journal,
        """
        INSERT INTO attempts (
            attempt_id, run_id, scenario_id, event_id, delivery_id, ordinal, state
        ) VALUES (?, ?, ?, ?, ?, 0, 'scheduled')
        """,
        (ATTEMPT_ID, RUN_ID, SCENARIO_ID, EVENT_ID, DELIVERY_ID),
    )
    with _write(journal):
        _insert_run(journal)
        _insert_scenario(journal)
        _insert_event(journal)
        second_scenario = _planned("scenario", 1)
        second_event = _planned("event", 1)
        _insert_scenario(journal, scenario_id=second_scenario, ordinal=1)
        _insert_event(
            journal,
            event_id=second_event,
            scenario_id=second_scenario,
            ordinal=0,
        )
    _reject(
        journal,
        """
        INSERT INTO event_dependencies (
            run_id, scenario_id, event_id, dependency_event_id
        ) VALUES (?, ?, ?, ?)
        """,
        (RUN_ID, SCENARIO_ID, EVENT_ID, second_event),
    )
    _reject(
        journal,
        """
        INSERT INTO event_dependencies (
            run_id, scenario_id, event_id, dependency_event_id
        ) VALUES (?, ?, ?, ?)
        """,
        (RUN_ID, SCENARIO_ID, EVENT_ID, EVENT_ID),
    )


def test_sample_and_evaluation_sequence_scopes_are_unique(
    journal: sqlite3.Connection,
) -> None:
    _seed_graph(journal)
    with _write(journal):
        journal.execute(
            """
            INSERT INTO observation_samples (
                sample_id, record_id, run_id, scenario_id, observation_id,
                sample_sequence, status, recorded_at, snapshot_id
            ) VALUES (?, ?, ?, ?, ?, 1, 'ok', ?, 'snapshot-1')
            """,
            (
                SAMPLE_ID,
                OBSERVATION_RECORD_ID,
                RUN_ID,
                SCENARIO_ID,
                OBSERVATION_ID,
                TIMESTAMP,
            ),
        )
        journal.execute(
            """
            INSERT INTO assertion_evaluations (
                evaluation_id, record_id, run_id, scenario_id, assertion_id,
                evaluation_sequence, result, recorded_at
            ) VALUES (?, ?, ?, ?, ?, 1, 'pass', ?)
            """,
            (
                EVALUATION_ID,
                ASSERTION_RECORD_ID,
                RUN_ID,
                SCENARIO_ID,
                ASSERTION_ID,
                TIMESTAMP,
            ),
        )
    _reject(
        journal,
        """
        INSERT INTO observation_samples (
            sample_id, record_id, run_id, scenario_id, observation_id,
            sample_sequence, status, recorded_at
        ) VALUES (?, ?, ?, ?, ?, 1, 'pending', ?)
        """,
        (
            _fresh("sample", 1),
            _fresh("record", 2),
            RUN_ID,
            SCENARIO_ID,
            OBSERVATION_ID,
            TIMESTAMP,
        ),
    )
    _reject(
        journal,
        """
        INSERT INTO assertion_evaluations (
            evaluation_id, record_id, run_id, scenario_id, assertion_id,
            evaluation_sequence, result, recorded_at
        ) VALUES (?, ?, ?, ?, ?, 1, 'pending', ?)
        """,
        (
            _fresh("evaluation", 1),
            _fresh("record", 3),
            RUN_ID,
            SCENARIO_ID,
            ASSERTION_ID,
            TIMESTAMP,
        ),
    )


def test_append_only_ledger_and_evidence_tables_reject_rewrites(
    journal: sqlite3.Connection,
) -> None:
    _seed_graph(journal)
    with _write(journal):
        for sequence, entity_type, entity_id, initial_state in (
            (1, "run", RUN_ID, RunState.PLANNED),
            (2, "scenario", SCENARIO_ID, ScenarioState.PENDING),
            (3, "delivery", DELIVERY_ID, DeliveryState.PENDING),
            (4, "attempt", ATTEMPT_ID, AttemptState.SCHEDULED),
            (5, "observation", OBSERVATION_ID, ObservationState.SCHEDULED),
            (6, "assertion", ASSERTION_ID, AssertionState.PENDING),
        ):
            _insert_transition(
                journal,
                sequence=sequence,
                entity_type=entity_type,
                entity_id=entity_id,
                from_state=None,
                to_state=str(initial_state),
            )
        journal.execute(
            """
            INSERT INTO observation_samples (
                sample_id, record_id, run_id, scenario_id, observation_id,
                sample_sequence, status, recorded_at, snapshot_id
            ) VALUES (?, ?, ?, ?, ?, 1, 'ok', ?, 'snapshot-1')
            """,
            (
                SAMPLE_ID,
                OBSERVATION_RECORD_ID,
                RUN_ID,
                SCENARIO_ID,
                OBSERVATION_ID,
                TIMESTAMP,
            ),
        )
        journal.execute(
            """
            INSERT INTO assertion_evaluations (
                evaluation_id, record_id, run_id, scenario_id, assertion_id,
                evaluation_sequence, result, recorded_at
            ) VALUES (?, ?, ?, ?, ?, 1, 'pass', ?)
            """,
            (
                EVALUATION_ID,
                ASSERTION_RECORD_ID,
                RUN_ID,
                SCENARIO_ID,
                ASSERTION_ID,
                TIMESTAMP,
            ),
        )
        journal.execute(
            """
            INSERT INTO evidence_links (
                evaluation_id, run_id, ordinal, evidence_kind, evidence_id
            ) VALUES (?, ?, 0, 'attempt', ?)
            """,
            (EVALUATION_ID, RUN_ID, ATTEMPT_ID),
        )
        journal.execute(
            """
            INSERT INTO recovery_decisions (
                decision_id, run_id, sequence, scenario_id, attempt_id,
                policy, decision, reason, recorded_at
            ) VALUES (
                'decision_1', ?, 1, ?, ?, 'stop', 'preserve_ambiguity',
                'insufficient evidence', ?
            )
            """,
            (RUN_ID, SCENARIO_ID, ATTEMPT_ID, TIMESTAMP),
        )
        journal.execute(
            """
            INSERT INTO recovery_decision_evidence (
                decision_id, run_id, ordinal, evidence_kind, evidence_id
            ) VALUES ('decision_1', ?, 0, 'attempt', ?)
            """,
            (RUN_ID, ATTEMPT_ID),
        )
        journal.execute(
            """
            INSERT INTO redaction_events (
                redaction_id, run_id, sequence, source_type, source_id,
                rule_id, replacement_type, recorded_at
            ) VALUES (
                'redaction_1', ?, 1, 'response', ?, 'authorization',
                'digest', ?
            )
            """,
            (RUN_ID, ATTEMPT_ID, TIMESTAMP),
        )
        _insert_attempt_record(journal)
    immutable_operations = (
        ("UPDATE schema_migrations SET migration_name = 'changed'", ()),
        ("DELETE FROM schema_migrations", ()),
        ("UPDATE transitions SET trigger_category = 'changed'", ()),
        ("DELETE FROM transitions", ()),
        ("UPDATE observation_samples SET status = 'pending'", ()),
        ("DELETE FROM observation_samples", ()),
        ("UPDATE assertion_evaluations SET result = 'fail'", ()),
        ("DELETE FROM assertion_evaluations", ()),
        ("UPDATE evidence_links SET evidence_kind = 'record'", ()),
        ("DELETE FROM evidence_links", ()),
        ("UPDATE recovery_decisions SET decision = 'changed'", ()),
        ("DELETE FROM recovery_decisions", ()),
        ("UPDATE recovery_decision_evidence SET evidence_kind = 'record'", ()),
        ("DELETE FROM recovery_decision_evidence", ()),
        ("UPDATE redaction_events SET replacement_type = 'removed'", ()),
        ("DELETE FROM redaction_events", ()),
        ("UPDATE attempt_records SET sequence = 2", ()),
        ("DELETE FROM attempt_records", ()),
    )
    for sql, parameters in immutable_operations:
        _reject(journal, sql, parameters)


def test_bounded_blob_text_identifier_and_artifact_path_constraints(
    journal: sqlite3.Connection,
) -> None:
    _seed_graph(journal)
    oversized_condition = b"x" * (1_048_576 + 1)
    _reject(
        journal,
        """
        INSERT INTO schedule_entries (
            schedule_entry_id, run_id, scenario_id, entity_type, entity_id,
            logical_time_ns, scenario_ordinal, step_ordinal, delivery_ordinal,
            attempt_ordinal, deterministic_tie_key, condition_json,
            idempotency_key
        ) VALUES (?, ?, ?, ?, ?, 0, 0, 0, 0, 0, ?, ?, ?)
        """,
        (
            "schedule_1",
            RUN_ID,
            SCENARIO_ID,
            "attempt",
            ATTEMPT_ID,
            "tie:1",
            oversized_condition,
            "schedule:1",
        ),
    )
    for unsafe_path in (
        "../secret",
        "reports/../secret",
        "/absolute/report.json",
        r"reports\report.json",
        "C:/report.json",
    ):
        _reject(
            journal,
            """
            INSERT INTO artifacts (
                artifact_id, run_id, relative_path, media_type, byte_length,
                sha256, generated_at
            ) VALUES (?, ?, ?, 'application/json', 0, ?, ?)
            """,
            (
                f"artifact_{len(unsafe_path)}",
                RUN_ID,
                unsafe_path,
                DIGEST,
                TIMESTAMP,
            ),
        )
    _reject(
        journal,
        """
        INSERT INTO artifacts (
            artifact_id, run_id, relative_path, media_type, byte_length,
            sha256, generated_at
        ) VALUES (?, ?, 'reports/result.json', 'application/json', 0, ?, ?)
        """,
        ("x" * 97, RUN_ID, DIGEST, TIMESTAMP),
    )


def test_projection_rows_rebuild_from_latest_ordered_transitions(
    journal: sqlite3.Connection,
) -> None:
    _seed_graph(journal)
    projections = (
        ("run", "runs", "run_id", RUN_ID, RunState.PLANNED),
        (
            "scenario",
            "scenarios",
            "scenario_id",
            SCENARIO_ID,
            ScenarioState.PENDING,
        ),
        (
            "delivery",
            "deliveries",
            "delivery_id",
            DELIVERY_ID,
            DeliveryState.PENDING,
        ),
        (
            "attempt",
            "attempts",
            "attempt_id",
            ATTEMPT_ID,
            AttemptState.SCHEDULED,
        ),
        (
            "observation",
            "observer_series",
            "observation_id",
            OBSERVATION_ID,
            ObservationState.SCHEDULED,
        ),
        (
            "assertion",
            "assertions",
            "assertion_id",
            ASSERTION_ID,
            AssertionState.PENDING,
        ),
    )
    with _write(journal):
        for sequence, (entity_type, _, _, entity_id, state) in enumerate(
            projections,
            start=1,
        ):
            _insert_transition(
                journal,
                sequence=sequence,
                entity_type=entity_type,
                entity_id=entity_id,
                from_state=None,
                to_state=str(state),
            )
    rebuilt = {
        (str(row[0]), str(row[1])): str(row[2])
        for row in journal.execute(
            """
            SELECT entity_type, entity_id, to_state
            FROM transitions AS candidate
            WHERE sequence = (
                SELECT MAX(latest.sequence)
                FROM transitions AS latest
                WHERE latest.run_id = candidate.run_id
                  AND latest.entity_type = candidate.entity_type
                  AND latest.entity_id = candidate.entity_id
            )
            """
        ).fetchall()
    }
    expected = {}
    for entity_type, table, id_column, entity_id, _ in projections:
        state = journal.execute(
            f"SELECT state FROM {table} WHERE {id_column} = ?",
            (entity_id,),
        ).fetchone()[0]
        expected[(entity_type, entity_id)] = str(state)
    assert rebuilt == expected


def test_changed_applied_migration_checksum_aborts_before_side_effect(
    journal: sqlite3.Connection,
) -> None:
    changed = Migration(
        migration_id=1,
        name=MIGRATIONS[0].name,
        statements=(*MIGRATIONS[0].statements, "SELECT 1"),
    )
    before = tuple(
        journal.execute("SELECT migration_id, checksum FROM schema_migrations").fetchall()
    )
    with pytest.raises(MigrationChecksumError):
        apply_migrations(journal, migrations=(changed, MIGRATIONS[1]))
    after = tuple(
        journal.execute("SELECT migration_id, checksum FROM schema_migrations").fetchall()
    )
    assert after == before
    assert journal.execute("PRAGMA user_version").fetchone()[0] == 2


def test_new_migration_applies_once_and_records_checksum(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / JOURNAL_FILENAME
    journal = create_journal_database(
        database_path,
        migrations=(MIGRATIONS[0],),
        clock=lambda: FIXED_CLOCK,
    )
    trace: list[str] = []
    journal.set_trace_callback(trace.append)
    first = apply_migrations(journal, migrations=MIGRATIONS, clock=lambda: FIXED_CLOCK)
    second_open = apply_migrations(
        journal,
        migrations=MIGRATIONS,
        clock=lambda: FIXED_CLOCK,
    )
    journal.set_trace_callback(None)
    assert first == second_open
    assert [record.migration_id for record in first] == [1, 2]
    assert first[-1].checksum == MIGRATIONS[1].checksum
    assert journal.execute("PRAGMA user_version").fetchone()[0] == 2
    assert sum("CREATE TABLE attempt_records" in statement for statement in trace) == 1
    backups = list(database_path.parent.glob(f"{database_path.name}.pre-v1-to-v2.*.bak"))
    assert len(backups) == 1
    backup = sqlite3.connect(backups[0])
    try:
        assert backup.execute("PRAGMA user_version").fetchone()[0] == 1
        assert (
            backup.execute(
                """
                SELECT 1 FROM sqlite_schema
                WHERE type = 'table' AND name = 'attempt_records'
                """
            ).fetchone()
            is None
        )
        assert backup.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        backup.close()
        journal.close()


def test_upgrade_backup_binds_created_file_across_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / JOURNAL_FILENAME
    connection = create_journal_database(
        database,
        migrations=(MIGRATIONS[0],),
        clock=lambda: FIXED_CLOCK,
    )
    victim = tmp_path / "backup-victim.sqlite3"
    victim_bytes = b"backup-victim-must-not-change"
    victim.write_bytes(victim_bytes)
    displaced = tmp_path / "displaced-backup.sqlite3"
    original_connect: Callable[..., sqlite3.Connection] = sqlite3.connect
    state = {"attempted": False, "blocked": False}

    def racing_backup_connect(
        database_value: str | bytes | os.PathLike[str],
        *args: object,
        **kwargs: object,
    ) -> sqlite3.Connection:
        candidates = list(tmp_path.glob(f"{JOURNAL_FILENAME}.pre-v1-to-v2.*.bak"))
        assert len(candidates) == 1
        candidate = candidates[0]
        state["attempted"] = True
        try:
            candidate.rename(displaced)
        except OSError:
            state["blocked"] = True
        else:
            victim.rename(candidate)
        return original_connect(database_value, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", racing_backup_connect)
    if os.name == "nt":
        apply_migrations(
            connection,
            migrations=MIGRATIONS,
            clock=lambda: FIXED_CLOCK,
        )
        assert state == {"attempted": True, "blocked": True}
        assert victim.read_bytes() == victim_bytes
        assert not displaced.exists()
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
    else:
        with pytest.raises(MigrationExecutionError):
            apply_migrations(
                connection,
                migrations=MIGRATIONS,
                clock=lambda: FIXED_CLOCK,
            )
        assert state == {"attempted": True, "blocked": False}
        candidate = next(tmp_path.glob(f"{JOURNAL_FILENAME}.pre-v1-to-v2.*.bak"))
        assert candidate.read_bytes() == victim_bytes
        assert displaced.is_file()
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
    connection.close()


def test_explicit_disposable_upgrade_can_skip_backup(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / JOURNAL_FILENAME
    journal = create_journal_database(
        database_path,
        migrations=(MIGRATIONS[0],),
        clock=lambda: FIXED_CLOCK,
    )
    apply_migrations(
        journal,
        migrations=MIGRATIONS,
        no_backup=True,
        clock=lambda: FIXED_CLOCK,
    )
    assert list(database_path.parent.glob(f"{database_path.name}.pre-v1-to-v2.*.bak")) == []
    journal.close()


def test_catalog_rejects_gaps_transaction_escape_and_resource_overflow() -> None:
    second = Migration(2, "second", ("CREATE TABLE second (id INTEGER) STRICT",))
    with pytest.raises(MigrationDefinitionError):
        validate_migration_catalog((MIGRATIONS[0], Migration(3, "third", ("SELECT 1",))))
    with pytest.raises(MigrationDefinitionError):
        validate_migration_catalog((second,))
    with pytest.raises(MigrationDefinitionError):
        Migration(1, "unsafe", ("BEGIN IMMEDIATE",))
    with pytest.raises(MigrationDefinitionError):
        Migration(1, "unsafe", ("END TRANSACTION",))
    with pytest.raises(MigrationDefinitionError):
        Migration(1, "unsafe", ("PRAGMA user_version = 1",))
    with pytest.raises(MigrationDefinitionError):
        Migration(1, "commented_unsafe", ("-- hidden\nBEGIN IMMEDIATE",))
    with pytest.raises(MigrationDefinitionError):
        Migration(1, "commented_unsafe", ("/* hidden */ PRAGMA user_version = 1",))
    with pytest.raises(MigrationDefinitionError):
        Migration(1, "unterminated_comment", ("/* hidden",))
    with pytest.raises(MigrationDefinitionError):
        Migration(1, "comment_only", ("-- hidden",))
    with pytest.raises(MigrationDefinitionError):
        Migration(1, "comment_only", ("/* hidden */",))
    with pytest.raises(MigrationDefinitionError):
        Migration(1, "oversized", ("x" * (1_048_576 + 1),))
    with pytest.raises(MigrationDefinitionError):
        Migration(
            migration_id=True,
            name="invalid_boolean_id",
            statements=("SELECT 1",),
        )

    class HostileCatalog(list[Migration]):
        def __iter__(self) -> Iterator[Migration]:
            while True:
                yield MIGRATIONS[0]

        def __len__(self) -> int:
            return 1

    with pytest.raises(MigrationDefinitionError, match="migration limit"):
        validate_migration_catalog(HostileCatalog([MIGRATIONS[0]]))


def test_unmanaged_and_future_databases_are_rejected_without_schema_changes(
    tmp_path: Path,
) -> None:
    unmanaged_path = tmp_path / "unmanaged" / JOURNAL_FILENAME
    unmanaged_path.parent.mkdir()
    unmanaged = sqlite3.connect(unmanaged_path, isolation_level=None)
    configure_connection(unmanaged)
    unmanaged.execute("CREATE TABLE foreign_table (id INTEGER)")
    before = tuple(unmanaged.execute("SELECT name FROM sqlite_schema").fetchall())
    with pytest.raises(JournalIntegrityError):
        apply_migrations(unmanaged)
    assert tuple(unmanaged.execute("SELECT name FROM sqlite_schema").fetchall()) == before
    unmanaged.close()

    future_path = tmp_path / "future" / JOURNAL_FILENAME
    future_path.parent.mkdir()
    future = sqlite3.connect(future_path, isolation_level=None)
    configure_connection(future)
    future.execute("PRAGMA user_version = 3")
    with pytest.raises(UnsupportedDatabaseVersionError):
        apply_migrations(future)
    assert future.execute("SELECT name FROM sqlite_schema").fetchall() == []
    future.close()


def test_empty_migration_ledger_is_rejected_as_interrupted_impossible_state(
    tmp_path: Path,
) -> None:
    database = tmp_path / JOURNAL_FILENAME
    connection = sqlite3.connect(database, isolation_level=None)
    configure_connection(connection)
    connection.execute(
        """
        CREATE TABLE schema_migrations (
            migration_id INTEGER PRIMARY KEY,
            migration_name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL
        ) STRICT
        """
    )
    try:
        with pytest.raises(JournalIntegrityError):
            apply_migrations(connection)
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 0
    finally:
        connection.close()


def test_every_v1_statement_crash_boundary_preserves_v0_or_committed_v1(
    tmp_path: Path,
) -> None:
    points = migration_crash_points(MIGRATIONS[0])
    statement_points = [
        point
        for point in points
        if point.phase in {CrashPhase.BEFORE_STATEMENT, CrashPhase.AFTER_STATEMENT}
    ]
    assert len(statement_points) == 2 * len(MIGRATIONS[0].statements)
    observed_hot_journal = False
    for index, target in enumerate(points):
        run_directory = tmp_path / f"crash-{index:03d}"
        run_directory.mkdir()
        database = run_directory / JOURNAL_FILENAME
        _run_crash_process(database, target)
        rollback_journal = Path(f"{database}-journal")
        observed_hot_journal |= rollback_journal.exists() and rollback_journal.stat().st_size > 0
        user_version, has_ledger, integrity_check = _raw_user_version(database)
        assert integrity_check == "ok", target
        if target.phase is CrashPhase.AFTER_COMMIT:
            assert (user_version, has_ledger) == (1, True), target
        else:
            assert (user_version, has_ledger) == (0, False), target
        reopened = open_journal_database(
            database,
            migrations=(MIGRATIONS[0],),
            clock=lambda: FIXED_CLOCK,
        )
        try:
            validate_migration_output(reopened, migrations=(MIGRATIONS[0],))
            assert reopened.execute("PRAGMA user_version").fetchone()[0] == 1
        finally:
            reopened.close()
    assert observed_hot_journal


def test_later_migration_crash_preserves_complete_prior_version(
    tmp_path: Path,
) -> None:
    second = MIGRATIONS[1]
    catalog = MIGRATIONS
    observed_hot_journal = False
    for index, target in enumerate(migration_crash_points(second)):
        run_directory = tmp_path / f"later-{index:02d}"
        run_directory.mkdir()
        database = run_directory / JOURNAL_FILENAME
        _run_crash_process(database, target)
        rollback_journal = Path(f"{database}-journal")
        observed_hot_journal |= rollback_journal.exists() and rollback_journal.stat().st_size > 0
        raw = sqlite3.connect(database)
        try:
            expected_version = 2 if target.phase is CrashPhase.AFTER_COMMIT else 1
            assert raw.execute("PRAGMA user_version").fetchone()[0] == expected_version
            ledger_ids = [
                int(row[0])
                for row in raw.execute(
                    "SELECT migration_id FROM schema_migrations ORDER BY migration_id"
                ).fetchall()
            ]
            assert ledger_ids == list(range(1, expected_version + 1))
            present = {
                str(row[0])
                for row in raw.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'table'"
                ).fetchall()
            }
            if expected_version == 1:
                assert "attempt_records" not in present
            else:
                assert "attempt_records" in present
            assert raw.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            raw.close()
        reopened = open_journal_database(
            database,
            migrations=catalog,
            no_backup=True,
            clock=lambda: FIXED_CLOCK,
        )
        try:
            validate_migration_output(reopened, migrations=catalog)
            assert reopened.execute("PRAGMA user_version").fetchone()[0] == 2
        finally:
            reopened.close()
    assert observed_hot_journal


def test_foreign_key_corruption_stops_open_and_preserves_database(
    tmp_path: Path,
) -> None:
    database = tmp_path / JOURNAL_FILENAME
    connection = create_journal_database(database)
    connection.close()
    corruptor = sqlite3.connect(database, isolation_level=None)
    corruptor.execute("PRAGMA foreign_keys = OFF")
    corruptor.execute(
        """
        INSERT INTO attempts (
            attempt_id, run_id, scenario_id, event_id, delivery_id, ordinal, state
        ) VALUES (?, ?, ?, ?, ?, 0, 'scheduled')
        """,
        (ATTEMPT_ID, RUN_ID, SCENARIO_ID, EVENT_ID, DELIVERY_ID),
    )
    corruptor.close()
    with pytest.raises(JournalIntegrityError):
        open_journal_database(database)
    preserved = sqlite3.connect(database)
    try:
        assert preserved.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 1
        assert preserved.execute("PRAGMA foreign_key_check").fetchall()
    finally:
        preserved.close()


def test_two_executions_create_distinct_run_directories_and_databases(
    tmp_path: Path,
) -> None:
    artifact_directory = tmp_path / "runs"
    first = create_run_database(artifact_directory)
    second = create_run_database(artifact_directory)
    assert first.run_id != second.run_id
    assert first.run_directory != second.run_directory
    assert first.database_path != second.database_path
    assert first.database_path.is_file()
    assert second.database_path.is_file()
    first_connection = open_journal_database(first.database_path)
    second_connection = open_journal_database(second.database_path)
    first_connection.close()
    second_connection.close()


def test_explicit_run_id_cannot_reuse_existing_database(tmp_path: Path) -> None:
    artifact_directory = tmp_path / "runs"
    first = create_run_database(artifact_directory, run_id=RUN_ID)
    before = first.database_path.read_bytes()
    with pytest.raises(JournalPathError):
        create_run_database(artifact_directory, run_id=RUN_ID)
    assert first.database_path.read_bytes() == before


def test_invalid_run_identifier_is_rejected_before_directory_creation(
    tmp_path: Path,
) -> None:
    artifact_directory = tmp_path / "runs"
    with pytest.raises(JournalPathError):
        create_run_database(artifact_directory, run_id="../escape")
    assert list(artifact_directory.iterdir()) == []


def test_database_path_is_fixed_contained_and_non_link(
    tmp_path: Path,
) -> None:
    with pytest.raises(JournalPathError):
        create_journal_database(tmp_path / "other.sqlite3")
    target = tmp_path / JOURNAL_FILENAME
    target.write_bytes(b"")
    link_directory = tmp_path / "link-run"
    link_directory.mkdir()
    link = link_directory / JOURNAL_FILENAME
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")
    with pytest.raises(JournalPathError):
        open_journal_database(link)


def test_hard_linked_database_is_rejected_without_touching_shared_inode(
    tmp_path: Path,
) -> None:
    source_directory = tmp_path / "source"
    source_directory.mkdir()
    source = source_directory / JOURNAL_FILENAME
    connection = create_journal_database(source, clock=lambda: FIXED_CLOCK)
    connection.close()
    source_before = source.read_bytes()
    linked_directory = tmp_path / "linked"
    linked_directory.mkdir()
    linked = linked_directory / JOURNAL_FILENAME
    try:
        os.link(source, linked)
    except OSError as error:
        pytest.skip(f"hard links unavailable: {error}")
    assert source.stat().st_nlink > 1
    with pytest.raises(JournalPathError):
        open_journal_database(linked)
    assert source.read_bytes() == source_before
    assert linked.read_bytes() == source_before


@pytest.mark.parametrize("operation", ["create", "open"])
def test_create_and_open_bind_exact_file_across_path_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    run_directory = tmp_path / operation
    run_directory.mkdir()
    database = run_directory / JOURNAL_FILENAME
    if operation == "open":
        initialized = create_journal_database(database, clock=lambda: FIXED_CLOCK)
        initialized.close()
    victim = run_directory / "victim.sqlite3"
    victim_bytes = b"do-not-overwrite-victim"
    victim.write_bytes(victim_bytes)
    displaced = run_directory / "guarded-original.sqlite3"
    race = _install_path_replacement_race(
        monkeypatch,
        target=database,
        displaced=displaced,
        victim=victim,
    )

    if os.name == "nt":
        connection = (
            create_journal_database(database, clock=lambda: FIXED_CLOCK)
            if operation == "create"
            else open_journal_database(database)
        )
        connection.close()
        assert race == {"attempted": True, "blocked": True}
        assert victim.read_bytes() == victim_bytes
        assert not displaced.exists()
    else:

        def create_operation() -> sqlite3.Connection:
            return create_journal_database(database, clock=lambda: FIXED_CLOCK)

        def open_operation() -> sqlite3.Connection:
            return open_journal_database(database)

        operation_call: Callable[[], sqlite3.Connection] = (
            create_operation if operation == "create" else open_operation
        )
        with pytest.raises(JournalPathError):
            operation_call()
        assert race == {"attempted": True, "blocked": False}
        assert database.read_bytes() == victim_bytes
        assert displaced.is_file()


@pytest.mark.parametrize("operation", ["create", "open"])
def test_create_and_open_reverify_binding_at_success_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    run_directory = tmp_path / f"late-{operation}"
    run_directory.mkdir()
    database = run_directory / JOURNAL_FILENAME
    if operation == "open":
        initialized = create_journal_database(database, clock=lambda: FIXED_CLOCK)
        initialized.close()
    victim = run_directory / "late-victim.sqlite3"
    victim_bytes = b"late-victim-must-not-be-opened"
    victim.write_bytes(victim_bytes)
    displaced = run_directory / "late-guarded-original.sqlite3"
    original_validate: Callable[..., None] = validate_migration_output
    state = {"attempted": False, "blocked": False}

    def validate_then_race(
        connection: sqlite3.Connection,
        *,
        migrations: Sequence[Migration] = MIGRATIONS,
    ) -> None:
        original_validate(connection, migrations=migrations)
        state["attempted"] = True
        try:
            database.rename(displaced)
        except OSError:
            state["blocked"] = True
        else:
            victim.rename(database)

    monkeypatch.setattr(journal_schema, "validate_migration_output", validate_then_race)
    if os.name == "nt":
        connection = (
            create_journal_database(database, clock=lambda: FIXED_CLOCK)
            if operation == "create"
            else open_journal_database(database)
        )
        connection.close()
        assert state == {"attempted": True, "blocked": True}
        assert victim.read_bytes() == victim_bytes
        assert not displaced.exists()
    else:

        def create_operation() -> sqlite3.Connection:
            return create_journal_database(database, clock=lambda: FIXED_CLOCK)

        def open_operation() -> sqlite3.Connection:
            return open_journal_database(database)

        operation_call: Callable[[], sqlite3.Connection] = (
            create_operation if operation == "create" else open_operation
        )
        with pytest.raises(JournalPathError):
            operation_call()
        assert state == {"attempted": True, "blocked": False}
        assert database.read_bytes() == victim_bytes
        assert displaced.is_file()


@pytest.mark.skipif(os.name != "nt", reason="UNC policy is Windows-specific")
def test_unc_artifact_directory_is_rejected_before_access() -> None:
    with pytest.raises(JournalPathError):
        create_run_database(r"\\invalid.example\share\runs")


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits only")
def test_new_run_directories_and_database_request_owner_only_modes(
    tmp_path: Path,
) -> None:
    created = create_run_database(
        tmp_path / "runs",
        migrations=(MIGRATIONS[0],),
    )
    directory_mode = stat.S_IMODE(created.run_directory.stat().st_mode)
    database_mode = stat.S_IMODE(created.database_path.stat().st_mode)
    assert directory_mode == 0o700
    assert database_mode == 0o600
    connection = open_journal_database(
        created.database_path,
        migrations=(MIGRATIONS[0],),
    )
    apply_migrations(connection, migrations=MIGRATIONS)
    connection.close()
    backups = list(created.run_directory.glob(f"{created.database_path.name}.pre-v1-to-v2.*.bak"))
    assert len(backups) == 1
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600


def test_invalid_connection_policy_refuses_migration_without_side_effect(
    tmp_path: Path,
) -> None:
    database = tmp_path / JOURNAL_FILENAME
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        with pytest.raises(JournalSchemaError):
            apply_migrations(connection)
        assert connection.execute("SELECT name FROM sqlite_schema").fetchall() == []
    finally:
        connection.close()


def test_unbounded_busy_timeout_refuses_migration_without_side_effect(
    tmp_path: Path,
) -> None:
    database = tmp_path / JOURNAL_FILENAME
    connection = sqlite3.connect(database, isolation_level=None)
    configure_connection(connection)
    connection.execute("PRAGMA busy_timeout = 60001")
    try:
        with pytest.raises(JournalSchemaError):
            apply_migrations(connection)
        assert connection.execute("SELECT name FROM sqlite_schema").fetchall() == []
    finally:
        connection.close()


def test_validate_migration_output_checks_integrity_and_required_shape(
    journal: sqlite3.Connection,
) -> None:
    validate_migration_output(journal)
    with _write(journal):
        journal.execute("DROP TABLE artifacts")
    with pytest.raises(JournalIntegrityError):
        validate_migration_output(journal)


@pytest.mark.parametrize(
    "replacement_statements",
    [
        (
            "DROP TABLE artifacts",
            "CREATE TABLE artifacts (artifact_id TEXT PRIMARY KEY) STRICT",
        ),
        (
            "DROP INDEX schedule_entries_due_idx",
            "CREATE INDEX schedule_entries_due_idx ON schedule_entries (run_id)",
        ),
        (
            "DROP TRIGGER schema_migrations_reject_update",
            """
            CREATE TRIGGER schema_migrations_reject_update
            BEFORE UPDATE ON schema_migrations
            BEGIN
                SELECT RAISE(ABORT, 'replacement trigger');
            END
            """,
        ),
    ],
    ids=["table", "index", "trigger"],
)
def test_validate_migration_output_rejects_same_name_sql_replacements(
    journal: sqlite3.Connection,
    replacement_statements: tuple[str, str],
) -> None:
    with _write(journal):
        for statement in replacement_statements:
            journal.execute(statement)
    assert journal.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with pytest.raises(JournalIntegrityError, match="migration SQL"):
        validate_migration_output(journal)


@pytest.mark.parametrize(
    "extra_schema_sql",
    [
        "CREATE TABLE injected_table (value TEXT) STRICT",
        """
        CREATE TRIGGER injected_trigger
        BEFORE UPDATE ON runs
        BEGIN
            SELECT 1;
        END
        """,
    ],
    ids=["extra-table", "extra-trigger"],
)
def test_validate_migration_output_rejects_unowned_schema_objects(
    journal: sqlite3.Connection,
    extra_schema_sql: str,
) -> None:
    with _write(journal):
        journal.execute(extra_schema_sql)
    assert journal.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with pytest.raises(JournalIntegrityError, match="schema object set"):
        validate_migration_output(journal)


def test_full_integrity_check_rejects_physically_inconsistent_btree(
    tmp_path: Path,
) -> None:
    database = tmp_path / JOURNAL_FILENAME
    connection = create_journal_database(database, clock=lambda: FIXED_CLOCK)
    connection.close()
    corruptor = sqlite3.connect(database, isolation_level=None)
    configure_connection(corruptor)
    runs_root_page = int(
        corruptor.execute("SELECT rootpage FROM sqlite_schema WHERE name = 'runs'").fetchone()[0]
    )
    schema_version = int(corruptor.execute("PRAGMA schema_version").fetchone()[0])
    corruptor.execute("PRAGMA writable_schema = ON")
    corruptor.execute(
        """
        UPDATE sqlite_schema
        SET rootpage = ?
        WHERE type = 'index' AND name = 'runs_manifest_id_idx'
        """,
        (runs_root_page,),
    )
    corruptor.execute("PRAGMA writable_schema = OFF")
    corruptor.execute(f"PRAGMA schema_version = {schema_version + 1}")
    integrity_rows = tuple(
        str(row[0]) for row in corruptor.execute("PRAGMA integrity_check").fetchall()
    )
    assert integrity_rows != ("ok",)
    with pytest.raises(JournalIntegrityError, match="integrity_check"):
        validate_migration_output(corruptor)
    corruptor.close()


@pytest.mark.parametrize(
    ("object_type", "name"),
    [
        ("TRIGGER", "schema_migrations_reject_update"),
        ("INDEX", "schedule_entries_due_idx"),
    ],
)
def test_validate_migration_output_requires_immutability_and_projection_objects(
    journal: sqlite3.Connection,
    object_type: str,
    name: str,
) -> None:
    with _write(journal):
        journal.execute(f"DROP {object_type} {name}")
    with pytest.raises(JournalIntegrityError):
        validate_migration_output(journal)
