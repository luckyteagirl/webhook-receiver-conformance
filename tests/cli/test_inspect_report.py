"""Inspect/report CLI service and mountable command contracts."""
# ruff: noqa: ARG005, INP001, PLR2004

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

import pytest
import typer
from typer.testing import CliRunner

from webhook_receiver_conformance.cli.inspect import (
    INSPECT_COMMAND_HELP,
    RAW_ARTIFACT_WARNING,
    InspectionDiagnosticLink,
    InspectionError,
    InspectionIdentifierKind,
    InspectionIndex,
    InspectionQuery,
    build_inspection_index,
    register_inspect_command,
    render_inspection_human,
    render_inspection_json,
)
from webhook_receiver_conformance.cli.report import (
    REPORT_COMMAND_HELP,
    ReportCommandRequest,
    ReportCommandResult,
    ReportFormat,
    register_report_command,
    render_report_human,
    render_report_json,
    select_registered_artifacts,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.journal.artifacts import ArtifactRecord
from webhook_receiver_conformance.reporting.json_reports import (
    FailureCausalTrace,
    JsonReportArtifacts,
    ReportCausalIndex,
)

if TYPE_CHECKING:
    from pathlib import Path

RUN_ID: Final = "00000000-0000-4000-8000-000000000606"
MANIFEST_ID: Final = "a" * 64
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
DIAGNOSTIC_ID: Final = "diagnostic.signature-rejected"
RAW_BLOB_PATH: Final = "blobs/sha256/potentially-sensitive-payload"
MUTATION_REF: Final = "mutation.invalid-signature-v1"
CONTROL_CANARY: Final = "observer\x1b[31m-control"


def _document(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()


def _artifacts() -> JsonReportArtifacts:
    manifest = {
        "schema_version": "1.0",
        "scenarios": [
            {
                "scenario_id": SCENARIO_ID,
                "events": [{"event_id": EVENT_ID}],
                "deliveries": [
                    {
                        "delivery_id": DELIVERY_ID,
                        "event_id": EVENT_ID,
                    }
                ],
            }
        ],
    }
    delivery = {
        "schema_version": "1.0",
        "record_id": ATTEMPT_RECORD_ID,
        "scenario_id": SCENARIO_ID,
        "event_id": EVENT_ID,
        "delivery_id": DELIVERY_ID,
        "attempt_id": ATTEMPT_ID,
        "state": "rejected",
        "classification": "receiver_rejected",
        "request": {
            "body_sha256": f"sha256:{'1' * 64}",
            "byte_length": 123,
        },
        "response": {
            "status": 400,
            "body_sha256": f"sha256:{'2' * 64}",
            "captured_bytes": 17,
            "truncated": False,
        },
    }
    observation = {
        "schema_version": "1.0",
        "record_id": OBSERVATION_RECORD_ID,
        "scenario_id": SCENARIO_ID,
        "event_id": EVENT_ID,
        "observation_id": OBSERVATION_ID,
        "sample_id": SAMPLE_ID,
        "observer_id": CONTROL_CANARY,
        "status": "ok",
        "snapshot_id": "snapshot-no-processing",
        "evidence": [
            {
                "key": "processing_count",
                "value_type": "integer",
                "value": 0,
                "sensitive": False,
            }
        ],
    }
    assertion = {
        "schema_version": "1.0",
        "record_id": ASSERTION_RECORD_ID,
        "scenario_id": SCENARIO_ID,
        "assertion_id": ASSERTION_ID,
        "type": "processing-count",
        "result": "fail",
        "comparison": "eq",
        "expected": 1,
        "actual": 0,
        "evidence_refs": [ATTEMPT_ID, SAMPLE_ID],
        "message": CONTROL_CANARY,
    }
    trace = FailureCausalTrace(
        assertion_record_id=ASSERTION_RECORD_ID,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        attempt_id=ATTEMPT_ID,
        attempt_record_id=ATTEMPT_RECORD_ID,
        observation_id=OBSERVATION_ID,
        observation_record_id=OBSERVATION_RECORD_ID,
        assertion_id=ASSERTION_ID,
        classification=ResultCategory.RECEIVER_FAILURE,
        immediate_evidence_refs=(ATTEMPT_ID, SAMPLE_ID),
        mutation_refs=(MUTATION_REF,),
    )
    return JsonReportArtifacts(
        manifest_json=_document(manifest),
        deliveries_jsonl=_document(delivery),
        observations_jsonl=_document(observation),
        assertions_jsonl=_document(assertion),
        result_summary_json=_document(
            {
                "schema_version": "1.0",
                "run_id": RUN_ID,
                "manifest_id": MANIFEST_ID,
                "generated_at": "2026-07-27T12:34:56.000000Z",
                "verdict": "receiver_failure",
            }
        ),
        causal_index=ReportCausalIndex((trace,)),
    )


def _index() -> InspectionIndex:
    return build_inspection_index(
        _artifacts(),
        diagnostic_links=(
            InspectionDiagnosticLink(
                diagnostic_id=DIAGNOSTIC_ID,
                assertion_record_id=ASSERTION_RECORD_ID,
            ),
        ),
        raw_artifact_paths=(RAW_BLOB_PATH,),
    )


@pytest.mark.parametrize(
    ("kind", "identifier"),
    [
        (InspectionIdentifierKind.SCENARIO, SCENARIO_ID),
        (InspectionIdentifierKind.EVENT, EVENT_ID),
        (InspectionIdentifierKind.DELIVERY, DELIVERY_ID),
        (InspectionIdentifierKind.ATTEMPT, ATTEMPT_ID),
        (InspectionIdentifierKind.OBSERVATION, OBSERVATION_ID),
        (InspectionIdentifierKind.ASSERTION, ASSERTION_ID),
        (InspectionIdentifierKind.DIAGNOSTIC, DIAGNOSTIC_ID),
    ],
)
def test_every_identifier_kind_returns_the_same_exact_causal_chain(
    kind: InspectionIdentifierKind,
    identifier: str,
) -> None:
    result = _index().query(InspectionQuery(kind, identifier))
    document = cast("dict[str, object]", json.loads(render_inspection_json(result)))
    chains = cast("list[dict[str, object]]", document["chains"])

    assert len(chains) == 1
    chain = chains[0]
    assert chain["scenario_id"] == SCENARIO_ID
    assert chain["event_id"] == EVENT_ID
    assert chain["delivery_id"] == DELIVERY_ID
    assert chain["attempt_id"] == ATTEMPT_ID
    assert chain["observation_id"] == OBSERVATION_ID
    assert chain["assertion_id"] == ASSERTION_ID
    assert chain["diagnostic_ids"] == [DIAGNOSTIC_ID]


def test_signature_rejection_links_mutation_response_and_no_processing() -> None:
    result = _index().query(
        InspectionQuery(InspectionIdentifierKind.ASSERTION, ASSERTION_RECORD_ID)
    )
    human = render_inspection_human(result)
    document = cast("dict[str, object]", json.loads(render_inspection_json(result)))
    chain = cast("list[dict[str, object]]", document["chains"])[0]
    delivery = cast("dict[str, object]", chain["delivery_record"])
    response = cast("dict[str, object]", delivery["response"])
    observation = cast("dict[str, object]", chain["observation_record"])
    evidence = cast("list[dict[str, object]]", observation["evidence"])

    assert MUTATION_REF in human
    assert "status=400" in human
    assert "processing_count" in human
    assert "\x1b" not in human
    assert response["status"] == 400
    assert evidence[0]["value"] == 0
    assert chain["mutation_refs"] == [MUTATION_REF]


def test_raw_blob_paths_require_explicit_option_and_tty_warning() -> None:
    default = _index().query(InspectionQuery(InspectionIdentifierKind.SCENARIO, SCENARIO_ID))
    explicit = _index().query(
        InspectionQuery(InspectionIdentifierKind.SCENARIO, SCENARIO_ID),
        include_raw_artifacts=True,
    )

    assert RAW_BLOB_PATH not in render_inspection_human(default)
    assert b"raw_artifacts" not in render_inspection_json(default)
    tty_human = render_inspection_human(
        explicit,
        include_raw_artifacts=True,
        stdout_is_tty=True,
    )
    explicit_json = cast(
        "dict[str, object]",
        json.loads(
            render_inspection_json(
                explicit,
                include_raw_artifacts=True,
            )
        ),
    )
    assert RAW_ARTIFACT_WARNING in tty_human
    assert RAW_BLOB_PATH in tty_human
    assert explicit_json["raw_artifacts"] == {
        "paths": [RAW_BLOB_PATH],
        "potentially_sensitive": True,
    }


def test_broken_exact_causal_edge_fails_closed() -> None:
    artifacts = _artifacts()
    broken = JsonReportArtifacts(
        manifest_json=artifacts.manifest_json,
        deliveries_jsonl=artifacts.deliveries_jsonl.replace(
            ATTEMPT_ID.encode(),
            f"attempt_{9:026d}".encode(),
        ),
        observations_jsonl=artifacts.observations_jsonl,
        assertions_jsonl=artifacts.assertions_jsonl,
        result_summary_json=artifacts.result_summary_json,
        causal_index=artifacts.causal_index,
    )

    with pytest.raises(InspectionError, match="identifiers differ"):
        build_inspection_index(broken)


def _artifact_record(relative_path: str, media_type: str) -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id=f"artifact_{hashlib_sha(relative_path)[:32]}",
        run_id=RUN_ID,
        relative_path=relative_path,
        media_type=media_type,
        byte_length=10,
        sha256=f"sha256:{'b' * 64}",
        generated_at="2026-07-27T12:34:56.000000Z",
        input_watermark=f"sha256:{'c' * 64}",
        renderer_version="reporter-1.0",
    )


def hashlib_sha(value: str) -> str:
    import hashlib  # noqa: PLC0415

    return hashlib.sha256(value.encode()).hexdigest()


def _complete_records() -> tuple[ArtifactRecord, ...]:
    return tuple(
        _artifact_record(path, media_type)
        for path, media_type in (
            ("run-manifest.json", "application/json"),
            ("deliveries.jsonl", "application/x-ndjson"),
            ("observations.jsonl", "application/x-ndjson"),
            ("assertions.jsonl", "application/x-ndjson"),
            ("result-summary.json", "application/json"),
            ("junit.xml", "application/xml"),
            ("results.html", "text/html; charset=utf-8"),
        )
    )


def test_report_selection_and_views_include_only_requested_formats() -> None:
    records = select_registered_artifacts(
        _complete_records(),
        (ReportFormat.JUNIT, ReportFormat.HTML),
    )
    result = ReportCommandResult(
        run_id=RUN_ID,
        formats=(ReportFormat.JUNIT, ReportFormat.HTML),
        normalized_digest=f"sha256:{'d' * 64}",
        records=records,
    )
    human = render_report_human(result)
    machine = cast("dict[str, object]", json.loads(render_report_json(result)))

    assert "junit.xml" in human
    assert "results.html" in human
    assert "run-manifest.json" not in human
    assert machine["formats"] == ["junit", "html"]
    assert [
        value["relative_path"] for value in cast("list[dict[str, object]]", machine["artifacts"])
    ] == ["junit.xml", "results.html"]


def test_inspect_and_report_help_exit_zero_and_state_their_job(
    tmp_path: Path,
) -> None:
    app = typer.Typer()
    register_inspect_command(app, lambda run_directory: _index())

    @dataclass(slots=True)
    class Executor:
        last_request: ReportCommandRequest | None = None

        def __call__(self, request: ReportCommandRequest) -> ReportCommandResult:
            self.last_request = request
            records = select_registered_artifacts(
                _complete_records(),
                request.formats,
            )
            return ReportCommandResult(
                run_id=RUN_ID,
                formats=request.formats,
                normalized_digest=f"sha256:{'d' * 64}",
                records=records,
            )

    executor = Executor()
    register_report_command(app, executor)
    runner = CliRunner()

    inspect_help = runner.invoke(app, ["inspect", "--help"])
    report_help = runner.invoke(app, ["report", "--help"])
    report_result = runner.invoke(
        app,
        [
            "report",
            str(tmp_path),
            "--format",
            "junit",
            "--json",
        ],
    )
    inspect_help_text = " ".join(inspect_help.stdout.split())
    report_help_text = " ".join(report_help.stdout.split())
    assert report_result.exit_code == 0, repr(report_result.exception)
    report_document = cast(
        "dict[str, object]",
        json.loads(report_result.stdout),
    )

    assert inspect_help.exit_code == 0
    assert INSPECT_COMMAND_HELP in inspect_help_text
    assert "without network access" in inspect_help_text
    assert report_help.exit_code == 0
    assert REPORT_COMMAND_HELP in report_help_text
    assert "local run journal" in report_help_text
    assert report_document["formats"] == ["junit"]
    assert executor.last_request is not None
    assert executor.last_request.formats == (ReportFormat.JUNIT,)
