"""Stable JSON reports, causality, privacy, and structured-log contract."""
# ruff: noqa: INP001, PLR2004, S105

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from webhook_receiver_conformance.cli.exit_codes import CommandSurface
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AttemptClassification,
    AttemptEvidenceState,
    EvidenceValueType,
    ObservationStatus,
)
from webhook_receiver_conformance.domain.hashing import compute_manifest_id
from webhook_receiver_conformance.domain.models import (
    AggregateRunOutcome,
    ArtifactPaths,
    AssertionEvaluation,
    AttemptEvidence,
    RequestMetadata,
    ResponseMetadata,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.http.evidence import REDACTED_HEADER_VALUE
from webhook_receiver_conformance.manifest.models import RunManifest
from webhook_receiver_conformance.observers.protocol import (
    ObservationRecord,
    ObserverEvidence,
)
from webhook_receiver_conformance.reporting.json_reports import (
    AssertionReportRecord,
    DeliveryReportRecord,
    FailureCausalTrace,
    JsonReportArtifacts,
    ObservationReportRecord,
    correlate_value,
    redact_json_preview,
    redacted_header_fields,
    render_json_reports,
    structured_log_line,
)
from webhook_receiver_conformance.reporting.summary import (
    SummarySource,
    build_result_summary,
)
from webhook_receiver_conformance.secrets import RunCorrelationHasher

RUN_ID = "00000000-0000-4000-8000-000000000601"
MANIFEST_ID_PLACEHOLDER = "0" * 64
SCENARIO_ID = f"scenario_{1:026d}"
EVENT_ID = f"event_{1:026d}"
DELIVERY_ID = f"delivery_{1:026d}"
ATTEMPT_ONE = f"attempt_{1:026d}"
ATTEMPT_TWO = f"attempt_{2:026d}"
SAMPLE_ID = f"sample_{1:026d}"
OBSERVATION_ID = f"observation_{1:026d}"
ASSERTION_ID = f"assertion_{1:026d}"
ATTEMPT_RECORD_ONE = f"record_{1:026d}"
ATTEMPT_RECORD_TWO = f"record_{2:026d}"
OBSERVATION_RECORD = f"record_{3:026d}"
ASSERTION_RECORD = f"record_{4:026d}"
NOW = datetime(2026, 7, 27, 23, 30, tzinfo=UTC)
SECRET_CANARY = "sensitive-observer-canary-must-not-escape"
BODY_CANARY = "request-body-canary-must-not-escape"
RESPONSE_CANARY = "response-body-canary-must-not-escape"
CHILD_CANARY = "child-stderr-canary-must-not-escape"


def _manifest() -> RunManifest:
    wire: dict[str, object] = {
        "schema_version": "1.0",
        "manifest_id": MANIFEST_ID_PLACEHOLDER,
        "created_at": "2026-07-27T23:00:00.000000Z",
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
                "sha256": f"sha256:{'4' * 64}",
                "byte_length": 2,
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
                        "fixture_blob": f"sha256:{'4' * 64}",
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
                                "request_blob": f"sha256:{'4' * 64}",
                                "headers_sha256": f"sha256:{'5' * 64}",
                            },
                            {
                                "ordinal": 2,
                                "not_before_logical_ns": 1,
                                "request_blob": f"sha256:{'4' * 64}",
                                "headers_sha256": f"sha256:{'5' * 64}",
                            },
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


def _attempt(
    *,
    ordinal: int,
    ambiguous: bool = False,
) -> AttemptEvidence:
    return AttemptEvidence(
        record_id=ATTEMPT_RECORD_ONE if ordinal == 1 else ATTEMPT_RECORD_TWO,
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        attempt_id=ATTEMPT_ONE if ordinal == 1 else ATTEMPT_TWO,
        sequence=ordinal,
        recorded_at=NOW,
        logical_time_ns=ordinal,
        monotonic_elapsed_ns=ordinal * 100,
        state=(
            AttemptEvidenceState.UNKNOWN_OUTCOME if ambiguous else AttemptEvidenceState.REJECTED
        ),
        classification=(
            AttemptClassification.AMBIGUOUS
            if ambiguous
            else AttemptClassification.RECEIVER_REJECTED
        ),
        request=RequestMetadata(
            url_redacted="http://127.0.0.1:8080/[REDACTED]",
            body_sha256=f"sha256:{'6' * 64}",
            byte_length=len(BODY_CANARY),
            header_names=("authorization", "content-type", "x-signature"),
        ),
        response=(
            None
            if ambiguous
            else ResponseMetadata(
                status=400,
                body_sha256=f"sha256:{'7' * 64}",
                captured_bytes=len(RESPONSE_CANARY),
                truncated=False,
            )
        ),
    )


def _observation() -> ObservationRecord:
    return ObservationRecord(
        schema_version="1.0",
        record_id=OBSERVATION_RECORD,
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        observation_id=OBSERVATION_ID,
        sample_id=SAMPLE_ID,
        observer_id="receiver_state",
        sample_sequence=1,
        recorded_at="2026-07-27T23:30:00.000000Z",
        status=ObservationStatus.OK,
        snapshot_id="snapshot-1",
        evidence=(
            ObserverEvidence(
                key="private_value",
                value_type=EvidenceValueType.STRING,
                value=SECRET_CANARY,
                sensitive=True,
            ),
            ObserverEvidence(
                key="processing_count",
                value_type=EvidenceValueType.INTEGER,
                value=0,
            ),
        ),
    )


def _assertion() -> AssertionEvaluation:
    return AssertionEvaluation(
        record_id=ASSERTION_RECORD,
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        assertion_id=ASSERTION_ID,
        evaluation_sequence=1,
        recorded_at=NOW,
        type="processing-count",
        result=AssertionResult.FAIL,
        expected=1,
        actual=0,
        comparison="eq",
        evidence_refs=(ATTEMPT_ONE, SAMPLE_ID),
        message="Receiver processed no matching event.",
    )


def _records() -> tuple[
    tuple[DeliveryReportRecord, ...],
    tuple[ObservationReportRecord, ...],
    tuple[AssertionReportRecord, ...],
]:
    deliveries = (
        DeliveryReportRecord(_attempt(ordinal=2), 0, 0, 2),
        DeliveryReportRecord(_attempt(ordinal=1), 0, 0, 1),
    )
    observations = (ObservationReportRecord(_observation(), 0, 0),)
    assertions = (AssertionReportRecord(_assertion(), 0, 0),)
    return deliveries, observations, assertions


def _summary(
    manifest: RunManifest,
    *,
    deliveries: tuple[DeliveryReportRecord, ...],
    observations: tuple[ObservationReportRecord, ...],
    assertions: tuple[AssertionReportRecord, ...],
) -> AggregateRunOutcome:
    return build_result_summary(
        SummarySource(
            run_id=RUN_ID,
            manifest_id=manifest.manifest_id,
            generated_at=NOW,
            scenario_ids=(SCENARIO_ID,),
            attempts=tuple(item.record for item in deliveries),
            observations=tuple(item.record for item in observations),
            assertions=tuple(item.record for item in assertions),
            categories=(ResultCategory.RECEIVER_FAILURE,),
            failure_refs=(ASSERTION_RECORD,),
            artifacts=ArtifactPaths(
                manifest="run-manifest.json",
                deliveries="deliveries.jsonl",
                observations="observations.jsonl",
                assertions="assertions.jsonl",
            ),
            command_surface=CommandSurface.RUN,
        )
    )


def _trace() -> FailureCausalTrace:
    return FailureCausalTrace(
        assertion_record_id=ASSERTION_RECORD,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        attempt_id=ATTEMPT_ONE,
        attempt_record_id=ATTEMPT_RECORD_ONE,
        observation_id=OBSERVATION_ID,
        observation_record_id=OBSERVATION_RECORD,
        assertion_id=ASSERTION_ID,
        classification=ResultCategory.RECEIVER_FAILURE,
        immediate_evidence_refs=(ATTEMPT_ONE, SAMPLE_ID),
        mutation_refs=("mutation.malformed-signature-v1",),
    )


def _render() -> JsonReportArtifacts:
    manifest = _manifest()
    deliveries, observations, assertions = _records()
    summary = _summary(
        manifest,
        deliveries=deliveries,
        observations=observations,
        assertions=assertions,
    )
    return render_json_reports(
        manifest,
        summary,
        deliveries=deliveries,
        observations=observations,
        assertions=assertions,
        causal_traces=(_trace(),),
    )


def _jsonl(value: bytes) -> list[dict[str, Any]]:
    return [cast("dict[str, Any]", json.loads(line)) for line in value.splitlines()]


def _schema_registry() -> tuple[Registry[Any], dict[str, dict[str, Any]]]:
    registry: Registry[Any] = Registry()
    schemas: dict[str, dict[str, Any]] = {}
    for path in Path("schemas").glob("*.schema.json"):
        schema = cast("dict[str, Any]", json.loads(path.read_text(encoding="utf-8")))
        schemas[path.name] = schema
        schema_id = cast("str", schema["$id"])
        registry = registry.with_resource(schema_id, Resource.from_contents(schema))
    return registry, schemas


def test_records_render_in_manifest_order_and_reconcile_with_summary() -> None:
    artifacts = _render()
    deliveries = _jsonl(artifacts.deliveries_jsonl)
    observations = _jsonl(artifacts.observations_jsonl)
    assertions = _jsonl(artifacts.assertions_jsonl)
    summary = cast("dict[str, Any]", json.loads(artifacts.result_summary_json))

    assert [record["attempt_id"] for record in deliveries] == [
        ATTEMPT_ONE,
        ATTEMPT_TWO,
    ]
    assert summary["counts"] == {
        "scenarios": 1,
        "attempts": len(deliveries),
        "observations": len(observations),
        "assertions": len(assertions),
    }
    assert summary["verdict"] == "receiver_failure"
    assert summary["exit_code"] == 1
    assert all(record["schema_version"] == "1.0" for record in deliveries)
    assert all(record["schema_version"] == "1.0" for record in observations)
    assert all(record["schema_version"] == "1.0" for record in assertions)
    assert "expected" in assertions[0]
    assert "actual" in assertions[0]
    assert assertions[0]["evidence_refs"] == [ATTEMPT_ONE, SAMPLE_ID]


def test_every_generated_record_validates_against_its_selected_schema() -> None:
    artifacts = _render()
    registry, schemas = _schema_registry()
    instances = (
        (
            "run-manifest.schema.json",
            (cast("dict[str, Any]", json.loads(artifacts.manifest_json)),),
        ),
        ("delivery-record.schema.json", tuple(_jsonl(artifacts.deliveries_jsonl))),
        (
            "observation-record.schema.json",
            tuple(_jsonl(artifacts.observations_jsonl)),
        ),
        (
            "assertion-record.schema.json",
            tuple(_jsonl(artifacts.assertions_jsonl)),
        ),
        (
            "result-summary.schema.json",
            (cast("dict[str, Any]", json.loads(artifacts.result_summary_json)),),
        ),
    )
    for schema_name, values in instances:
        validator = Draft202012Validator(
            schemas[schema_name],
            registry=registry,
        )
        for value in values:
            assert (
                list(
                    validator.iter_errors(  # pyright: ignore[reportUnknownMemberType]
                        value
                    )
                )
                == []
            )

    missing_version = _jsonl(artifacts.deliveries_jsonl)[0]
    missing_version.pop("schema_version")
    assert list(
        Draft202012Validator(
            schemas["delivery-record.schema.json"],
            registry=registry,
        ).iter_errors(  # pyright: ignore[reportUnknownMemberType]
            missing_version
        )
    )


def test_sensitive_and_raw_body_material_is_absent_from_every_default_artifact() -> None:
    artifacts = _render()
    combined = b"".join(
        (
            artifacts.manifest_json,
            artifacts.deliveries_jsonl,
            artifacts.observations_jsonl,
            artifacts.assertions_jsonl,
            artifacts.result_summary_json,
        )
    )
    for canary in (
        SECRET_CANARY,
        BODY_CANARY,
        RESPONSE_CANARY,
        CHILD_CANARY,
    ):
        assert canary.encode() not in combined
    observation = _jsonl(artifacts.observations_jsonl)[0]
    sensitive = next(item for item in observation["evidence"] if item["key"] == "private_value")
    assert sensitive["value"] == REDACTED_HEADER_VALUE
    assert sensitive["sensitive"] is True


def test_regeneration_is_byte_identical_for_the_same_nonvolatile_facts() -> None:
    first = _render()
    second = _render()
    assert first.manifest_json == second.manifest_json
    assert first.deliveries_jsonl == second.deliveries_jsonl
    assert first.observations_jsonl == second.observations_jsonl
    assert first.assertions_jsonl == second.assertions_jsonl
    assert first.result_summary_json == second.result_summary_json


def test_failure_causal_index_traverses_exact_identifiers_without_matching() -> None:
    artifacts = _render()
    trace = artifacts.causal_index.trace_failure(ASSERTION_RECORD)
    assert trace.mutation_refs == ("mutation.malformed-signature-v1",)
    assert trace.scenario_id == SCENARIO_ID
    assert trace.event_id == EVENT_ID
    assert trace.delivery_id == DELIVERY_ID
    assert trace.attempt_id == ATTEMPT_ONE
    assert trace.observation_id == OBSERVATION_ID
    assert trace.assertion_id == ASSERTION_ID
    assert trace.immediate_evidence_refs == (ATTEMPT_ONE, SAMPLE_ID)
    with pytest.raises(KeyError, match="no causal trace"):
        artifacts.causal_index.trace_failure(f"record_{99:026d}")


def test_unknown_outcome_is_serialized_only_as_ambiguity() -> None:
    manifest = _manifest()
    ambiguous = (DeliveryReportRecord(_attempt(ordinal=1, ambiguous=True), 0, 0, 1),)
    summary = build_result_summary(
        SummarySource(
            run_id=RUN_ID,
            manifest_id=manifest.manifest_id,
            generated_at=NOW,
            scenario_ids=(SCENARIO_ID,),
            attempts=(ambiguous[0].record,),
            observations=(),
            assertions=(),
            categories=(ResultCategory.AMBIGUOUS,),
            failure_refs=(),
            artifacts=ArtifactPaths(
                manifest="run-manifest.json",
                deliveries="deliveries.jsonl",
                observations="observations.jsonl",
                assertions="assertions.jsonl",
            ),
        )
    )
    artifacts = render_json_reports(
        manifest,
        summary,
        deliveries=ambiguous,
        observations=(),
        assertions=(),
    )
    record = _jsonl(artifacts.deliveries_jsonl)[0]
    result = cast("dict[str, Any]", json.loads(artifacts.result_summary_json))
    assert record["state"] == "unknown_outcome"
    assert record["classification"] == "ambiguous"
    assert result["verdict"] == "ambiguous"
    assert result["exit_code"] == 4


def test_nested_json_pointer_redaction_changes_only_exact_paths() -> None:
    body = json.dumps(
        {
            "account": {
                "token": "private",
                "safe": "visible",
                "items": [{"secret": "first"}, {"secret": "second"}],
            }
        },
        separators=(",", ":"),
    ).encode()
    preview = redact_json_preview(
        body,
        json_pointers=(
            "/account/token",
            "/account/items/1/secret",
        ),
    )
    assert preview.preview_omitted is False
    assert preview.preview == {
        "account": {
            "token": REDACTED_HEADER_VALUE,
            "safe": "visible",
            "items": [
                {"secret": "first"},
                {"secret": REDACTED_HEADER_VALUE},
            ],
        }
    }
    assert preview.wire_dict()["byte_length"] == len(body)
    assert "private" not in json.dumps(preview.wire_dict())
    assert "second" not in json.dumps(preview.wire_dict())


@pytest.mark.parametrize(
    ("body", "pointers"),
    [
        (b'{"token":', ("/token",)),
        (b"\xff", ("/token",)),
        (b'{"token":"private"}', ("invalid",)),
        (b'{"token":"private"}', ("/bad~2escape",)),
    ],
)
def test_invalid_preview_or_pointer_fails_closed(
    body: bytes,
    pointers: tuple[str, ...],
) -> None:
    preview = redact_json_preview(body, json_pointers=pointers)
    assert preview.preview_omitted is True
    assert preview.preview is None
    assert "private" not in json.dumps(preview.wire_dict())


def test_default_header_projection_redacts_every_value_stably() -> None:
    fields = redacted_header_fields(("Authorization", "Cookie", "X-Signature", "Content-Type"))
    assert [item["name"] for item in fields] == [
        "Authorization",
        "Cookie",
        "X-Signature",
        "Content-Type",
    ]
    assert {item["value"] for item in fields} == {REDACTED_HEADER_VALUE}


def test_structured_log_is_one_bounded_record_and_omits_sensitive_fields() -> None:
    line = structured_log_line(
        "attempt.finished",
        {
            "message": "first line\nforged line",
            "request_body": BODY_CANARY,
            "response_body": RESPONSE_CANARY,
            "stderr": CHILD_CANARY,
            "headers": {
                "Authorization": "private",
                "Content-Type": "application/json",
            },
            "long": "x" * 10_000,
        },
        maximum_field_characters=128,
    )
    assert line.count(b"\n") == 1
    for canary in (BODY_CANARY, RESPONSE_CANARY, CHILD_CANARY, "private"):
        assert canary.encode() not in line
    parsed = cast("dict[str, Any]", json.loads(line))
    assert parsed["message"] == "first line\nforged line"
    assert parsed["request_body"] == REDACTED_HEADER_VALUE
    assert set(parsed["headers"].values()) == {REDACTED_HEADER_VALUE}
    assert len(parsed["long"]) == 128


def test_run_correlation_is_stable_within_run_and_distinct_across_runs() -> None:
    first = RunCorrelationHasher(token_bytes=lambda _size: b"a" * 32)
    second = RunCorrelationHasher(token_bytes=lambda _size: b"b" * 32)
    try:
        one = correlate_value(first, "same value")
        assert correlate_value(first, "same value") == one
        assert correlate_value(second, "same value") != one
        assert "a" * 32 not in repr(first)
        assert "b" * 32 not in repr(second)
    finally:
        first.close()
        second.close()


def test_summary_count_mismatch_is_rejected_before_rendering() -> None:
    manifest = _manifest()
    deliveries, observations, assertions = _records()
    summary = _summary(
        manifest,
        deliveries=deliveries,
        observations=observations,
        assertions=assertions,
    )
    with pytest.raises(ValueError, match="counts differ"):
        render_json_reports(
            manifest,
            summary,
            deliveries=deliveries[:-1],
            observations=observations,
            assertions=assertions,
            causal_traces=(_trace(),),
        )
