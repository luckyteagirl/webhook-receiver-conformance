"""Production inspection adapter over verified journal and report evidence."""
# ruff: noqa: EM101, INP001, TRY003

from __future__ import annotations

import asyncio
import json
import socket
import sqlite3
import subprocess
from typing import TYPE_CHECKING, Final

import pytest

from webhook_receiver_conformance.cli.inspect import (
    InspectionError,
    InspectionIdentifierKind,
    InspectionNotFoundError,
    InspectionQuery,
    render_inspection_human,
    render_inspection_json,
)
from webhook_receiver_conformance.domain.hashing import compute_manifest_id
from webhook_receiver_conformance.fixtures.blobs import snapshot_blob
from webhook_receiver_conformance.journal.schema import create_run_database
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
)
from webhook_receiver_conformance.manifest.models import RunManifest
from webhook_receiver_conformance.runtime.inspection import (
    load_inspection_index,
)
from webhook_receiver_conformance.runtime.reporting import regenerate_run_reports

if TYPE_CHECKING:
    from pathlib import Path

RUN_ID: Final = "00000000-0000-4000-8000-000000000606"
SCENARIO_ID: Final = f"scenario_{1:026d}"
EVENT_ID: Final = f"event_{1:026d}"
DELIVERY_ID: Final = f"delivery_{1:026d}"
ATTEMPT_ID: Final = f"attempt_{1:026d}"
OBSERVATION_ID: Final = f"observation_{1:026d}"
SAMPLE_ID: Final = f"sample_{1:026d}"
ASSERTION_ID: Final = f"assertion_{1:026d}"
ATTEMPT_RECORD_ID: Final = f"record_{1:026d}"
OBSERVATION_RECORD_ID: Final = f"record_{2:026d}"
ASSERTION_RECORD_ID: Final = f"record_{3:026d}"
EVALUATION_ID: Final = f"evaluation_{1:026d}"
TIMESTAMP: Final = "2026-07-27T18:00:00.000000Z"
TERMINAL_TIMESTAMP: Final = "2026-07-27T18:00:01.000000Z"


def _manifest(
    blob_digest: str,
    blob_length: int,
    *,
    observer_backed: bool = True,
) -> RunManifest:
    assertion: dict[str, object] = {
        "assertion_id": ASSERTION_ID,
        "type": "processing-count" if observer_backed else "http-status",
    }
    if observer_backed:
        assertion["observer"] = "receiver_state"
    wire: dict[str, object] = {
        "schema_version": "1.0",
        "manifest_id": "0" * 64,
        "created_at": TIMESTAMP,
        "tool": {"version": "0.1.0", "python": "3.12"},
        "generator": {
            "algorithm": "hmac-sha256-context-v1",
            "seed_fingerprint": f"sha256:{'1' * 64}",
            "normalized_seed_hash_hex": "2" * 64,
        },
        "configuration_digest": f"sha256:{'3' * 64}",
        "environment": {
            "os": "test",
            "architecture": "test",
            "timezone": "UTC",
        },
        "target_policy": {
            "profile": "loopback",
            "authorized_host": "127.0.0.1",
            "authorized_port": 8080,
        },
        "blobs": [
            {
                "sha256": blob_digest,
                "byte_length": blob_length,
                "media_type": "application/json",
            }
        ],
        "scenarios": [
            {
                "scenario_id": SCENARIO_ID,
                "events": [
                    {
                        "event_id": EVENT_ID,
                        "event_type": "payment.created",
                        "fixture_blob": blob_digest,
                    }
                ],
                "deliveries": [
                    {
                        "delivery_id": DELIVERY_ID,
                        "event_id": EVENT_ID,
                        "logical_time_ns": 0,
                        "ordinal": 0,
                        "attempt_plan": [
                            {
                                "ordinal": 1,
                                "not_before_logical_ns": 0,
                                "request_blob": blob_digest,
                                "headers_sha256": f"sha256:{'4' * 64}",
                            }
                        ],
                    }
                ],
                "assertions": [assertion],
            }
        ],
    }
    wire["manifest_id"] = compute_manifest_id(wire)
    return RunManifest.from_wire(wire)


def _seed_statements(
    manifest: RunManifest,
    body_digest: str,
    *,
    observer_backed: bool = True,
) -> tuple[JournalStatement, ...]:
    assertion_type = "processing-count" if observer_backed else "http-status"
    observation_evidence = json.dumps(
        [
            {
                "key": "processing_count",
                "sensitive": False,
                "value": 0,
                "value_type": "integer",
            }
        ],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    statements = (
        JournalStatement(
            """
            INSERT INTO runs (
                run_id, manifest_id, state, owner_epoch, created_at,
                terminal_category, terminal_at
            ) VALUES (?, ?, 'completed', 0, ?, 'receiver_failure', ?)
            """,
            (RUN_ID, manifest.manifest_id, TIMESTAMP, TERMINAL_TIMESTAMP),
        ),
        JournalStatement(
            """
            INSERT INTO scenarios (
                scenario_id, run_id, ordinal, name, state, required
            ) VALUES (?, ?, 0, 'processing count', 'failed', 1)
            """,
            (SCENARIO_ID, RUN_ID),
        ),
        JournalStatement(
            """
            INSERT INTO events (
                event_id, run_id, scenario_id, ordinal,
                event_type, fixture_blob_hash
            ) VALUES (?, ?, ?, 0, 'payment.created', ?)
            """,
            (EVENT_ID, RUN_ID, SCENARIO_ID, body_digest),
        ),
        JournalStatement(
            """
            INSERT INTO deliveries (
                delivery_id, run_id, scenario_id, event_id, ordinal,
                step_ordinal, logical_time_ns, state, required
            ) VALUES (?, ?, ?, ?, 0, 0, 0, 'satisfied', 1)
            """,
            (DELIVERY_ID, RUN_ID, SCENARIO_ID, EVENT_ID),
        ),
        JournalStatement(
            """
            INSERT INTO attempts (
                attempt_id, run_id, scenario_id, event_id, delivery_id,
                attempt_plan_id, ordinal, state, phase, request_blob_hash,
                request_headers_hash, outcome_category, predecessor_attempt_id,
                owner_epoch, terminal_recorded_at
            ) VALUES (
                ?, ?, ?, ?, ?, NULL, 1, 'succeeded', 'response_observed',
                ?, ?, 'receiver_accepted', NULL, 0, ?
            )
            """,
            (
                ATTEMPT_ID,
                RUN_ID,
                SCENARIO_ID,
                EVENT_ID,
                DELIVERY_ID,
                body_digest,
                f"sha256:{'4' * 64}",
                TERMINAL_TIMESTAMP,
            ),
        ),
        JournalStatement(
            """
            INSERT INTO attempt_records (
                record_id, schema_version, run_id, scenario_id, event_id,
                delivery_id, attempt_id, sequence, recorded_at,
                logical_time_ns, monotonic_elapsed_ns, state, classification,
                request_method, request_url_redacted, request_body_sha256,
                request_byte_length, request_header_names_json,
                response_status, response_body_sha256,
                response_captured_bytes, response_truncated,
                error_category, error_message_redacted, error_phase,
                response_headers_elapsed_ns
            ) VALUES (
                ?, '1.0', ?, ?, ?, ?, ?, 1, ?, 0, 1000000,
                'acknowledged', 'receiver_accepted',
                'POST', 'http://127.0.0.1:8080/[REDACTED]', ?, 2, ?,
                200, ?, 2, 0, NULL, NULL, NULL, 900000
            )
            """,
            (
                ATTEMPT_RECORD_ID,
                RUN_ID,
                SCENARIO_ID,
                EVENT_ID,
                DELIVERY_ID,
                ATTEMPT_ID,
                TERMINAL_TIMESTAMP,
                body_digest,
                b'["content-type"]',
                body_digest,
            ),
        ),
        JournalStatement(
            """
            INSERT INTO observer_series (
                observation_id, run_id, scenario_id, event_id,
                checkpoint, observer_id, state
            ) VALUES (?, ?, ?, ?, 'after_delivery', 'receiver_state', 'ok')
            """,
            (OBSERVATION_ID, RUN_ID, SCENARIO_ID, EVENT_ID),
        ),
        JournalStatement(
            """
            INSERT INTO observation_samples (
                sample_id, record_id, run_id, scenario_id, observation_id,
                sample_sequence, status, recorded_at, snapshot_id,
                evidence_json, error_json
            ) VALUES (?, ?, ?, ?, ?, 1, 'ok', ?, 'snapshot-1', ?, NULL)
            """,
            (
                SAMPLE_ID,
                OBSERVATION_RECORD_ID,
                RUN_ID,
                SCENARIO_ID,
                OBSERVATION_ID,
                TERMINAL_TIMESTAMP,
                observation_evidence,
            ),
        ),
        JournalStatement(
            """
            INSERT INTO assertions (
                assertion_id, run_id, scenario_id, type,
                policy_json, required, state
            ) VALUES (?, ?, ?, ?, NULL, 1, 'failed')
            """,
            (ASSERTION_ID, RUN_ID, SCENARIO_ID, assertion_type),
        ),
        JournalStatement(
            """
            INSERT INTO assertion_evaluations (
                evaluation_id, record_id, run_id, scenario_id, assertion_id,
                evaluation_sequence, result, recorded_at,
                expected_json, actual_json, comparison, message
            ) VALUES (
                ?, ?, ?, ?, ?, 1, 'fail', ?, ?, ?, 'eq',
                'Receiver processed no matching event.'
            )
            """,
            (
                EVALUATION_ID,
                ASSERTION_RECORD_ID,
                RUN_ID,
                SCENARIO_ID,
                ASSERTION_ID,
                TERMINAL_TIMESTAMP,
                b"1",
                b"0",
            ),
        ),
        JournalStatement(
            """
            INSERT INTO evidence_links (
                evaluation_id, run_id, ordinal, evidence_kind, evidence_id
            ) VALUES (?, ?, 0, 'attempt', ?)
            """,
            (EVALUATION_ID, RUN_ID, ATTEMPT_ID),
        ),
        JournalStatement(
            """
            INSERT INTO evidence_links (
                evaluation_id, run_id, ordinal, evidence_kind, evidence_id
            ) VALUES (?, ?, 1, 'observation', ?)
            """,
            (EVALUATION_ID, RUN_ID, SAMPLE_ID),
        ),
    )
    if observer_backed:
        return statements
    return tuple(
        statement
        for statement in statements
        if "INSERT INTO observer_series" not in statement.sql
        and "INSERT INTO observation_samples" not in statement.sql
        and statement.parameters != (EVALUATION_ID, RUN_ID, SAMPLE_ID)
    )


async def _seeded_run(
    tmp_path: Path,
    *,
    observer_backed: bool = True,
) -> tuple[Path, str]:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    blob = snapshot_blob(
        run.run_directory,
        b'{"potentially":"sensitive"}',
        media_type="application/json",
    )
    manifest = _manifest(
        blob.sha256,
        blob.byte_length,
        observer_backed=observer_backed,
    )
    run.run_directory.joinpath("run-manifest.json").write_bytes(manifest.serialized_bytes())
    async with JournalService.open(run.database_path) as service:
        await service.execute(
            BatchOperation(
                _seed_statements(
                    manifest,
                    blob.sha256,
                    observer_backed=observer_backed,
                )
            )
        )
        await regenerate_run_reports(run.run_directory, service=service)
    return (
        run.run_directory,
        blob.path.relative_to(run.run_directory).as_posix(),
    )


def _deny_external_invocation(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("offline inspection attempted network or process invocation")


@pytest.mark.anyio
async def test_real_run_supports_every_exact_identifier_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_directory, raw_blob_path = await _seeded_run(tmp_path)
    monkeypatch.setattr(socket, "create_connection", _deny_external_invocation)
    monkeypatch.setattr(socket, "getaddrinfo", _deny_external_invocation)
    monkeypatch.setattr(subprocess, "Popen", _deny_external_invocation)
    monkeypatch.setattr(subprocess, "run", _deny_external_invocation)
    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        _deny_external_invocation,
    )

    index = await load_inspection_index(run_directory)
    queries = (
        (InspectionIdentifierKind.SCENARIO, SCENARIO_ID),
        (InspectionIdentifierKind.EVENT, EVENT_ID),
        (InspectionIdentifierKind.DELIVERY, DELIVERY_ID),
        (InspectionIdentifierKind.ATTEMPT, ATTEMPT_ID),
        (InspectionIdentifierKind.OBSERVATION, OBSERVATION_ID),
        (InspectionIdentifierKind.ASSERTION, ASSERTION_ID),
        (InspectionIdentifierKind.DIAGNOSTIC, ASSERTION_RECORD_ID),
    )
    for kind, identifier in queries:
        result = index.query(InspectionQuery(kind, identifier))
        assert len(result.chains) == 1
        trace = result.chains[0].trace
        assert trace.scenario_id == SCENARIO_ID
        assert trace.event_id == EVENT_ID
        assert trace.delivery_id == DELIVERY_ID
        assert trace.attempt_id == ATTEMPT_ID
        assert trace.observation_id == OBSERVATION_ID
        assert trace.assertion_id == ASSERTION_ID
    with pytest.raises(InspectionNotFoundError):
        index.query(
            InspectionQuery(
                InspectionIdentifierKind.SCENARIO,
                SCENARIO_ID[:-1],
            )
        )

    default = index.query(InspectionQuery(InspectionIdentifierKind.SCENARIO, SCENARIO_ID))
    explicit = index.query(
        InspectionQuery(InspectionIdentifierKind.SCENARIO, SCENARIO_ID),
        include_raw_artifacts=True,
    )
    assert raw_blob_path not in render_inspection_human(default)
    assert raw_blob_path.encode() not in render_inspection_json(default)
    assert raw_blob_path in render_inspection_human(
        explicit,
        include_raw_artifacts=True,
        stdout_is_tty=True,
    )
    assert raw_blob_path.encode() in render_inspection_json(
        explicit,
        include_raw_artifacts=True,
    )


@pytest.mark.anyio
async def test_transport_only_failed_assertion_is_valid_without_observation(
    tmp_path: Path,
) -> None:
    run_directory, _ = await _seeded_run(tmp_path, observer_backed=False)

    index = await load_inspection_index(run_directory)

    assert index.chains == ()
    with pytest.raises(InspectionNotFoundError):
        index.query(InspectionQuery(InspectionIdentifierKind.ATTEMPT, ATTEMPT_ID))


@pytest.mark.anyio
async def test_inspection_preserves_journal_bytes_metadata_and_directory_inventory(
    tmp_path: Path,
) -> None:
    run_directory, _ = await _seeded_run(tmp_path)
    journal_path = run_directory / "journal.sqlite3"
    before_bytes = journal_path.read_bytes()
    before_metadata = journal_path.stat(follow_symlinks=False)
    before_inventory = tuple(
        sorted(path.relative_to(run_directory).as_posix() for path in run_directory.rglob("*"))
    )

    await load_inspection_index(run_directory)

    after_metadata = journal_path.stat(follow_symlinks=False)
    after_inventory = tuple(
        sorted(path.relative_to(run_directory).as_posix() for path in run_directory.rglob("*"))
    )
    assert journal_path.read_bytes() == before_bytes
    assert after_metadata.st_size == before_metadata.st_size
    assert after_metadata.st_mtime_ns == before_metadata.st_mtime_ns
    assert after_metadata.st_ctime_ns == before_metadata.st_ctime_ns
    assert after_inventory == before_inventory
    assert not {
        "journal.sqlite3-journal",
        "journal.sqlite3-shm",
        "journal.sqlite3-wal",
        "run.lock",
    }.intersection(after_inventory)


@pytest.mark.anyio
async def test_missing_exact_journal_link_fails_closed(tmp_path: Path) -> None:
    run_directory, _ = await _seeded_run(tmp_path)
    connection = sqlite3.connect(run_directory / "journal.sqlite3")
    try:
        trigger_row = connection.execute(
            """
            SELECT sql
            FROM sqlite_schema
            WHERE type = 'trigger' AND name = 'evidence_links_reject_delete'
            """
        ).fetchone()
        assert trigger_row is not None
        trigger_sql = trigger_row[0]
        assert type(trigger_sql) is str
        connection.execute("DROP TRIGGER evidence_links_reject_delete")
        connection.execute(
            """
            DELETE FROM evidence_links
            WHERE run_id = ? AND evidence_kind = 'attempt'
            """,
            (RUN_ID,),
        )
        connection.execute(trigger_sql)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(InspectionError, match="integrity validation"):
        await load_inspection_index(run_directory)


@pytest.mark.anyio
async def test_corrupt_sanitized_artifact_fails_registry_verification(
    tmp_path: Path,
) -> None:
    run_directory, _ = await _seeded_run(tmp_path)
    assertions = run_directory / "assertions.jsonl"
    assertions.write_bytes(assertions.read_bytes().replace(ASSERTION_ID.encode(), b"corrupt"))

    with pytest.raises(InspectionError, match="registry verification"):
        await load_inspection_index(run_directory)
