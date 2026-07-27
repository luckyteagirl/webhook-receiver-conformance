"""Schema-backed contracts for immutable domain value objects."""
# ruff: noqa: INP001

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError
from referencing import Registry, Resource

from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    AttemptClassification,
    AttemptEvidenceState,
    AttemptState,
    DeliveryState,
    EvidenceValueType,
    ObservationState,
    ObservationStatus,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    encode_crockford_ulid,
    planned_id,
)
from webhook_receiver_conformance.domain.models import (
    AggregateRunOutcome,
    ArtifactPaths,
    Assertion,
    AssertionEvaluation,
    AttemptEvidence,
    LogicalEvent,
    Observation,
    ObservationEvidence,
    ObservationSample,
    PhysicalAttempt,
    PlannedDelivery,
    RequestMetadata,
    ResultCounts,
    Run,
    Scenario,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory

ROOT = Path(__file__).parents[3]
NOW = datetime(2026, 1, 1, tzinfo=UTC)
RUN_ID = "00000000-0000-4000-8000-000000000001"
OTHER_RUN_ID = "00000000-0000-4000-8000-000000000002"
MANIFEST_ID = "a" * 64
DIGEST = "sha256:" + ("0" * 64)
GENERATOR = ContextGenerator.from_text_seed("domain model vectors")
ENTITY_TYPE_COUNT = 7

SCENARIO_ID = planned_id(GENERATOR, PlannedIdKind.SCENARIO, ("scenario", "0"))
EVENT_ID = planned_id(GENERATOR, PlannedIdKind.EVENT, ("scenario", "0", "event", "0"))
DELIVERY_ID = planned_id(
    GENERATOR,
    PlannedIdKind.DELIVERY,
    ("scenario", "0", "delivery", "0"),
)
OBSERVATION_ID = planned_id(
    GENERATOR,
    PlannedIdKind.OBSERVATION,
    ("scenario", "0", "observation", "0"),
)
ASSERTION_ID = planned_id(
    GENERATOR,
    PlannedIdKind.ASSERTION,
    ("scenario", "0", "assertion", "0"),
)


def _fresh_id(kind: FreshIdKind, ordinal: int) -> str:
    payload = ordinal.to_bytes(16, "big")
    return f"{kind.value}_{encode_crockford_ulid(payload)}"


ATTEMPT_ID = _fresh_id(FreshIdKind.ATTEMPT, 1)
SAMPLE_ID = _fresh_id(FreshIdKind.SAMPLE, 2)
RECORD_ID = _fresh_id(FreshIdKind.RECORD, 3)
OBSERVATION_RECORD_ID = _fresh_id(FreshIdKind.RECORD, 4)
ASSERTION_RECORD_ID = _fresh_id(FreshIdKind.RECORD, 5)


def _attempt() -> AttemptEvidence:
    return AttemptEvidence(
        record_id=RECORD_ID,
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        attempt_id=ATTEMPT_ID,
        sequence=1,
        recorded_at=NOW,
        logical_time_ns=0,
        monotonic_elapsed_ns=10,
        state=AttemptEvidenceState.ACKNOWLEDGED,
        classification=AttemptClassification.RECEIVER_ACCEPTED,
        request=RequestMetadata(
            url_redacted="http://127.0.0.1:8000/webhooks",
            body_sha256=DIGEST,
            byte_length=7,
            header_names=("content-type",),
        ),
    )


def _observation(
    *,
    status: ObservationStatus = ObservationStatus.OK,
    snapshot_id: str | None = "snapshot-1",
) -> ObservationSample:
    return ObservationSample(
        record_id=OBSERVATION_RECORD_ID,
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        observation_id=OBSERVATION_ID,
        sample_id=SAMPLE_ID,
        observer_id="receiver-state",
        sample_sequence=1,
        recorded_at=NOW,
        status=status,
        snapshot_id=snapshot_id,
        evidence=(
            ObservationEvidence(
                key="processing_count",
                value_type=EvidenceValueType.INTEGER,
                value=1,
            ),
        ),
    )


def _assertion() -> AssertionEvaluation:
    return AssertionEvaluation(
        record_id=ASSERTION_RECORD_ID,
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        assertion_id=ASSERTION_ID,
        evaluation_sequence=1,
        recorded_at=NOW,
        type="processing-count",
        result=AssertionResult.PASS,
        expected=1,
        actual=1,
        evidence_refs=(OBSERVATION_RECORD_ID,),
    )


def _outcome() -> AggregateRunOutcome:
    return AggregateRunOutcome(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        generated_at=NOW,
        verdict=ResultCategory.PASS,
        exit_code=ExitCode.PASS,
        counts=ResultCounts(scenarios=1, attempts=1, observations=1, assertions=1),
        artifacts=ArtifactPaths(
            manifest="manifest.json",
            deliveries="deliveries.jsonl",
            observations="observations.jsonl",
            assertions="assertions.jsonl",
            junit="junit.xml",
            html="report.html",
        ),
    )


def _schema(name: str) -> dict[str, Any]:
    return cast(
        "dict[str, Any]",
        json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8")),
    )


def _schema_registry() -> Registry[Any]:
    schemas = [_schema(path.name) for path in sorted((ROOT / "schemas").glob("*.schema.json"))]
    registry: Registry[Any] = Registry()
    for schema in schemas:
        identifier = schema.get("$id")
        if isinstance(identifier, str):
            registry = registry.with_resource(
                identifier,
                Resource.from_contents(schema),
            )
    return registry


def _schema_errors(
    instance: Any,  # noqa: ANN401
    schema: dict[str, Any],
    *,
    registry: Registry[Any] | None = None,
) -> list[str]:
    kwargs: dict[str, Any] = {}
    if registry is not None:
        kwargs["registry"] = registry
    validator: Any = Draft202012Validator(schema, **kwargs)
    return [error.message for error in validator.iter_errors(instance)]


def _json_projection(
    model: BaseModel,
    *,
    exclude_none: bool = True,
) -> dict[str, object]:
    return cast(
        "dict[str, object]",
        model.model_dump(mode="json", exclude_none=exclude_none),
    )


def test_entity_models_use_distinct_typed_ids_and_are_frozen() -> None:
    run = Run(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        state=RunState.PLANNED,
        created_at=NOW,
        scenario_ids=(SCENARIO_ID,),
    )
    scenario = Scenario(
        run_id=run.run_id,
        scenario_id=SCENARIO_ID,
        ordinal=0,
        name="baseline",
        state=ScenarioState.PENDING,
        event_ids=(EVENT_ID,),
        delivery_ids=(DELIVERY_ID,),
        observation_ids=(OBSERVATION_ID,),
        assertion_ids=(ASSERTION_ID,),
    )
    event = LogicalEvent(
        scenario_id=scenario.scenario_id,
        event_id=EVENT_ID,
        event_type="payment.succeeded",
        fixture_sha256=DIGEST,
        delivery_ids=(DELIVERY_ID,),
    )
    delivery = PlannedDelivery(
        scenario_id=scenario.scenario_id,
        event_id=event.event_id,
        delivery_id=DELIVERY_ID,
        ordinal=0,
        logical_time_ns=0,
        state=DeliveryState.PENDING,
        attempt_ids=(ATTEMPT_ID,),
    )
    attempt = PhysicalAttempt(
        run_id=run.run_id,
        scenario_id=scenario.scenario_id,
        event_id=event.event_id,
        delivery_id=delivery.delivery_id,
        attempt_id=ATTEMPT_ID,
        ordinal=0,
        state=AttemptState.SCHEDULED,
    )
    observation = Observation(
        run_id=run.run_id,
        scenario_id=scenario.scenario_id,
        observation_id=OBSERVATION_ID,
        observer_id="receiver-state",
        state=ObservationState.SCHEDULED,
        event_id=EVENT_ID,
    )
    assertion = Assertion(
        run_id=run.run_id,
        scenario_id=scenario.scenario_id,
        assertion_id=ASSERTION_ID,
        type="processing-count",
        state=AssertionState.PENDING,
    )
    assert (
        len(
            {
                type(item)
                for item in (run, scenario, event, delivery, attempt, observation, assertion)
            }
        )
        == ENTITY_TYPE_COUNT
    )
    with pytest.raises(ValidationError):
        run.state = RunState.RUNNING  # pyright: ignore[reportAttributeAccessIssue]


@pytest.mark.parametrize(
    ("model", "field", "wrong_id"),
    [
        (Run, "run_id", SCENARIO_ID),
        (Run, "manifest_id", DIGEST),
        (Scenario, "scenario_id", EVENT_ID),
        (LogicalEvent, "event_id", DELIVERY_ID),
        (PlannedDelivery, "delivery_id", EVENT_ID),
        (PhysicalAttempt, "attempt_id", DELIVERY_ID),
        (Observation, "observation_id", ASSERTION_ID),
        (Assertion, "assertion_id", OBSERVATION_ID),
    ],
)
def test_cross_type_identifiers_are_rejected(
    model: type[BaseModel],
    field: str,
    wrong_id: str,
) -> None:
    valid: dict[str, object]
    if model is Run:
        valid = {
            "run_id": RUN_ID,
            "manifest_id": MANIFEST_ID,
            "state": RunState.PLANNED,
            "created_at": NOW,
        }
    elif model is Scenario:
        valid = {
            "run_id": RUN_ID,
            "scenario_id": SCENARIO_ID,
            "ordinal": 0,
            "name": "baseline",
            "state": ScenarioState.PENDING,
        }
    elif model is LogicalEvent:
        valid = {
            "scenario_id": SCENARIO_ID,
            "event_id": EVENT_ID,
            "event_type": "payment.succeeded",
            "fixture_sha256": DIGEST,
        }
    elif model is PlannedDelivery:
        valid = {
            "scenario_id": SCENARIO_ID,
            "event_id": EVENT_ID,
            "delivery_id": DELIVERY_ID,
            "ordinal": 0,
            "logical_time_ns": 0,
            "state": DeliveryState.PENDING,
        }
    elif model is PhysicalAttempt:
        valid = {
            "run_id": RUN_ID,
            "scenario_id": SCENARIO_ID,
            "event_id": EVENT_ID,
            "delivery_id": DELIVERY_ID,
            "attempt_id": ATTEMPT_ID,
            "ordinal": 0,
            "state": AttemptState.SCHEDULED,
        }
    elif model is Observation:
        valid = {
            "run_id": RUN_ID,
            "scenario_id": SCENARIO_ID,
            "observation_id": OBSERVATION_ID,
            "observer_id": "receiver-state",
            "state": ObservationState.SCHEDULED,
        }
    else:
        valid = {
            "run_id": RUN_ID,
            "scenario_id": SCENARIO_ID,
            "assertion_id": ASSERTION_ID,
            "type": "processing-count",
            "state": AssertionState.PENDING,
        }
    valid[field] = wrong_id
    with pytest.raises(ValidationError):
        model.model_validate(valid)


@pytest.mark.parametrize(
    ("value_type", "value"),
    [
        (EvidenceValueType.NULL, None),
        (EvidenceValueType.BOOLEAN, True),
        (EvidenceValueType.INTEGER, -1),
        (EvidenceValueType.DECIMAL_STRING, "-123.4500e+6"),
        (EvidenceValueType.STRING, ""),
        (
            EvidenceValueType.BYTES_DIGEST,
            {"sha256": DIGEST, "byte_length": 7, "media_type": "application/octet-stream"},
        ),
        (EvidenceValueType.TIMESTAMP, "2026-01-01T00:00:00.123456789Z"),
        (EvidenceValueType.ARRAY, [1, "two", None]),
        (EvidenceValueType.OBJECT, {"nested": True}),
    ],
)
def test_observation_evidence_value_types_round_trip_and_match_schema(
    value_type: EvidenceValueType,
    value: object,
) -> None:
    evidence = ObservationEvidence.model_validate(
        {"key": "value", "value_type": value_type, "value": value}
    )
    assert ObservationEvidence.model_validate_json(evidence.model_dump_json()) == evidence
    registry = _schema_registry()
    assert (
        _schema_errors(
            _json_projection(evidence, exclude_none=False),
            _schema("observer-evidence.schema.json"),
            registry=registry,
        )
        == []
    )


@pytest.mark.parametrize(
    ("value_type", "value"),
    [
        (EvidenceValueType.NULL, False),
        (EvidenceValueType.BOOLEAN, 1),
        (EvidenceValueType.INTEGER, True),
        (EvidenceValueType.DECIMAL_STRING, "01"),
        (EvidenceValueType.DECIMAL_STRING, "1."),
        (EvidenceValueType.STRING, 1),
        (EvidenceValueType.BYTES_DIGEST, {"sha256": DIGEST}),
        (EvidenceValueType.BYTES_DIGEST, {"sha256": DIGEST, "byte_length": True}),
        (
            EvidenceValueType.BYTES_DIGEST,
            {"sha256": DIGEST, "byte_length": 1, "extra": "forbidden"},
        ),
        (EvidenceValueType.TIMESTAMP, "2026-01-01T00:00:00+00:00"),
        (EvidenceValueType.TIMESTAMP, "2026-02-30T00:00:00Z"),
        (EvidenceValueType.ARRAY, {}),
        (EvidenceValueType.OBJECT, []),
    ],
)
def test_observation_evidence_rejects_mismatched_shapes(
    value_type: EvidenceValueType,
    value: object,
) -> None:
    with pytest.raises(ValidationError, match="does not conform"):
        ObservationEvidence.model_validate(
            {"key": "value", "value_type": value_type, "value": value}
        )


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        [1, float("-inf")],
        {"nested": [float("nan")]},
    ],
)
def test_serialized_json_values_reject_nonfinite_numbers(value: object) -> None:
    with pytest.raises(ValidationError, match="non-finite"):
        ObservationEvidence.model_validate(
            {
                "key": "unsafe",
                "value_type": (
                    EvidenceValueType.ARRAY
                    if isinstance(value, list)
                    else EvidenceValueType.OBJECT
                    if isinstance(value, dict)
                    else EvidenceValueType.STRING
                ),
                "value": value,
            }
        )
    with pytest.raises(ValidationError, match="non-finite"):
        AssertionEvaluation.model_validate({**_json_projection(_assertion()), "actual": value})


def test_successful_observation_requires_nonempty_snapshot_id() -> None:
    assert _observation().snapshot_id == "snapshot-1"
    for snapshot_id in (None, "", " "):
        with pytest.raises(ValidationError, match="snapshot_id"):
            _observation(snapshot_id=snapshot_id)
    pending = _observation(status=ObservationStatus.PENDING, snapshot_id=None)
    assert pending.snapshot_id is None


def test_evidence_records_round_trip_and_validate_against_owned_schemas() -> None:
    registry = _schema_registry()
    cases = (
        (_attempt(), "delivery-record.schema.json"),
        (_observation(), "observation-record.schema.json"),
        (_assertion(), "assertion-record.schema.json"),
    )
    for model, schema_name in cases:
        assert type(model).model_validate_json(model.model_dump_json()) == model
        assert (
            _schema_errors(
                _json_projection(model),
                _schema(schema_name),
                registry=registry,
            )
            == []
        )


def test_transport_observation_and_assertion_records_remain_separate() -> None:
    attempt = _attempt()
    observation = _observation()
    assertion = _assertion()
    with pytest.raises(ValidationError):
        ObservationSample.model_validate(attempt.model_dump())
    with pytest.raises(ValidationError):
        AttemptEvidence.model_validate(observation.model_dump())
    with pytest.raises(ValidationError):
        AssertionEvaluation.model_validate(observation.model_dump())
    assert not hasattr(_outcome(), "attempts")
    assert not hasattr(_outcome(), "observations")
    assert not hasattr(_outcome(), "assertions")
    assert attempt.run_id == observation.run_id == assertion.run_id


def test_result_summary_exactly_matches_schema_and_exit_mapping() -> None:
    outcome = _outcome()
    outcome_data = outcome.model_dump(mode="python")
    assert AggregateRunOutcome.model_validate_json(outcome.model_dump_json()) == outcome
    assert (
        _schema_errors(
            _json_projection(outcome),
            _schema("result-summary.schema.json"),
        )
        == []
    )
    assert set(_json_projection(outcome)) == {
        "schema_version",
        "run_id",
        "manifest_id",
        "generated_at",
        "verdict",
        "exit_code",
        "counts",
        "failure_refs",
        "artifacts",
    }
    with pytest.raises(ValidationError, match="exit_code"):
        AggregateRunOutcome.model_validate({**outcome_data, "exit_code": ExitCode.HARNESS_FAILURE})
    with pytest.raises(ValidationError, match="failure_refs"):
        AggregateRunOutcome.model_validate(
            {
                **outcome_data,
                "failure_refs": (ASSERTION_RECORD_ID, ASSERTION_RECORD_ID),
            }
        )
    with pytest.raises(ValidationError):
        AggregateRunOutcome.model_validate(
            {**outcome_data, "attempts": [_json_projection(_attempt())]}
        )


def test_unknown_fields_bounds_digests_and_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError):
        AttemptEvidence.model_validate({"record_id": RECORD_ID, "unknown": True})
    with pytest.raises(ValidationError):
        ObservationSample.model_validate({**_json_projection(_observation()), "sample_sequence": 0})
    with pytest.raises(ValidationError):
        RequestMetadata(
            url_redacted="http://127.0.0.1/",
            body_sha256="sha256:ABC",
            byte_length=1,
        )
    for created_at in (
        NOW.replace(tzinfo=None),
        datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1))),
    ):
        with pytest.raises(ValidationError):
            Run(
                run_id=RUN_ID,
                manifest_id=MANIFEST_ID,
                state=RunState.PLANNED,
                created_at=created_at,
            )
    with pytest.raises(ValidationError):
        ResultCounts(scenarios=True, attempts=0, observations=0, assertions=0)


def test_state_vocabularies_match_state_requirements_and_evidence_is_separate() -> None:
    assert {state.value for state in RunState} == {
        "planned",
        "running",
        "paused",
        "completed",
        "cancelled",
        "failed",
    }
    assert {state.value for state in ScenarioState} == {
        "pending",
        "eligible",
        "running",
        "passed",
        "failed",
        "error",
        "skipped",
        "ambiguous",
        "cancelled",
    }
    assert {state.value for state in DeliveryState} == {
        "pending",
        "eligible",
        "active",
        "satisfied",
        "exhausted",
        "ambiguous",
        "cancelled",
        "skipped",
    }
    assert {state.value for state in AttemptState} == {
        "scheduled",
        "claimed",
        "pre_send_committed",
        "connecting",
        "sending",
        "awaiting_response",
        "response_observed",
        "not_sent",
        "succeeded",
        "rejected",
        "transport_failed",
        "unknown_outcome",
        "cancelled",
    }
    assert {state.value for state in ObservationState} == {
        "scheduled",
        "running",
        "ok",
        "pending",
        "unsupported",
        "error",
        "timed_out",
        "cancelled",
    }
    assert {state.value for state in AssertionState} == {
        "pending",
        "running",
        "passed",
        "failed",
        "error",
        "unsupported",
        "cancelled",
    }
    assert {state.value for state in AttemptEvidenceState} != {
        state.value for state in AttemptState
    }
    assert {value.value for value in EvidenceValueType} == {
        "null",
        "boolean",
        "integer",
        "decimal-string",
        "string",
        "bytes-digest",
        "timestamp",
        "array",
        "object",
    }
