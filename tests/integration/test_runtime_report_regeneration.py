"""Production report projection from verified manifest and journal truth."""
# ruff: noqa: EM101, INP001, TRY003

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from tests.helpers.schema_validation import (
    build_schema_registry,
    load_json,
    load_jsonl,
    load_xml,
    parse_html_bytes,
    validate_instance,
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
from webhook_receiver_conformance.runtime.reporting import (
    ReportFormat,
    regenerate_run_reports,
)

if TYPE_CHECKING:
    from referencing import Registry

RUN_ID = "00000000-0000-4000-8000-000000000719"
SCENARIO_ID = f"scenario_{1:026d}"
EVENT_ID = f"event_{1:026d}"
DELIVERY_ID = f"delivery_{1:026d}"
ATTEMPT_ID = f"attempt_{1:026d}"
OBSERVATION_ID = f"observation_{1:026d}"
SAMPLE_ID = f"sample_{1:026d}"
ASSERTION_ID = f"assertion_{1:026d}"
ATTEMPT_RECORD_ID = f"record_{1:026d}"
OBSERVATION_RECORD_ID = f"record_{2:026d}"
ASSERTION_RECORD_ID = f"record_{3:026d}"
EVALUATION_ID = f"evaluation_{1:026d}"
TIMESTAMP = "2026-07-27T18:00:00.000000Z"
TERMINAL_TIMESTAMP = "2026-07-27T18:00:01.000000Z"
REPORT_PATHS = (
    "assertions.jsonl",
    "deliveries.jsonl",
    "junit.xml",
    "observations.jsonl",
    "result-summary.json",
    "results.html",
    "run-manifest.json",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _manifest(blob_digest: str, blob_length: int) -> RunManifest:
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
                "assertions": [
                    {
                        "assertion_id": ASSERTION_ID,
                        "type": "processing-count",
                        "observer": "receiver_state",
                    }
                ],
            }
        ],
    }
    wire["manifest_id"] = compute_manifest_id(wire)
    return RunManifest.from_wire(wire)


def _seed_statements(manifest: RunManifest, body_digest: str) -> tuple[JournalStatement, ...]:
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
    return (
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
            ) VALUES (?, ?, ?, 'processing-count', NULL, 1, 'failed')
            """,
            (ASSERTION_ID, RUN_ID, SCENARIO_ID),
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


def _schemas() -> tuple[Registry[Any], dict[str, dict[str, Any]]]:
    documents = {
        path.name: cast(
            "dict[str, Any]",
            json.loads(path.read_text(encoding="utf-8")),
        )
        for path in Path("schemas").glob("*.schema.json")
    }
    return build_schema_registry(documents.values()), documents


def _assert_schema_valid(run_directory: Path) -> None:
    registry, schemas = _schemas()
    instances = (
        ("run-manifest.schema.json", (load_json(run_directory / "run-manifest.json"),)),
        (
            "delivery-record.schema.json",
            tuple(load_jsonl(run_directory / "deliveries.jsonl")),
        ),
        (
            "observation-record.schema.json",
            tuple(load_jsonl(run_directory / "observations.jsonl")),
        ),
        (
            "assertion-record.schema.json",
            tuple(load_jsonl(run_directory / "assertions.jsonl")),
        ),
        ("result-summary.schema.json", (load_json(run_directory / "result-summary.json"),)),
    )
    for schema_name, values in instances:
        for value in values:
            assert validate_instance(value, schemas[schema_name], registry=registry) == []
    assert load_xml(run_directory / "junit.xml").tag == "testsuites"
    parse_html_bytes((run_directory / "results.html").read_bytes())


@pytest.mark.anyio
async def test_runtime_regenerates_schema_valid_reports_offline_and_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    blob = snapshot_blob(run.run_directory, b"{}", media_type="application/json")
    manifest = _manifest(blob.sha256, blob.byte_length)
    run.run_directory.joinpath("run-manifest.json").write_bytes(manifest.serialized_bytes())

    def deny_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("offline report regeneration attempted network access")

    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)

    async with JournalService.open(run.database_path) as service:
        await service.execute(BatchOperation(_seed_statements(manifest, blob.sha256)))
        first = await regenerate_run_reports(
            run.run_directory,
            formats=(ReportFormat.JSON,),
            service=service,
        )

    assert first.outcome.verdict.value == "receiver_failure"
    assert tuple(item.relative_path for item in first.records) == (
        "assertions.jsonl",
        "deliveries.jsonl",
        "observations.jsonl",
        "result-summary.json",
        "run-manifest.json",
    )
    _assert_schema_valid(run.run_directory)
    original = {path: run.run_directory.joinpath(path).read_bytes() for path in REPORT_PATHS}

    for path in REPORT_PATHS:
        if path != "run-manifest.json":
            run.run_directory.joinpath(path).unlink()

    second = await regenerate_run_reports(
        run.run_directory,
        formats=(ReportFormat.HTML,),
    )

    assert tuple(item.relative_path for item in second.records) == ("results.html",)
    assert second.normalized_digest == first.normalized_digest
    assert {
        path: run.run_directory.joinpath(path).read_bytes() for path in REPORT_PATHS
    } == original
    _assert_schema_valid(run.run_directory)
