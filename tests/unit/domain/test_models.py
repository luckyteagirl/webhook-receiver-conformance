"""Contract tests for immutable domain value objects."""
# ruff: noqa: INP001

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

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
from webhook_receiver_conformance.domain.models import (
    AggregateRunOutcome,
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
    Run,
    Scenario,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory
from webhook_receiver_conformance.types import EntityId, Sha256Digest

NOW = datetime(2026, 1, 1, tzinfo=UTC)
DIGEST = Sha256Digest("sha256:" + "0" * 64)
ENTITY_TYPE_COUNT = 7


def _id(prefix: str) -> EntityId:
    return EntityId(f"{prefix}_test")


def _attempt(*, run_id: EntityId | None = None) -> AttemptEvidence:
    return AttemptEvidence(
        record_id=_id("record"),
        run_id=_id("run") if run_id is None else run_id,
        scenario_id=_id("scenario"),
        event_id=_id("event"),
        delivery_id=_id("delivery"),
        attempt_id=_id("attempt"),
        sequence=1,
        recorded_at=NOW,
        state=AttemptEvidenceState.ACKNOWLEDGED,
        classification=AttemptClassification.RECEIVER_ACCEPTED,
        request=RequestMetadata(
            url_redacted="http://127.0.0.1:8000/webhooks",
            body_sha256=DIGEST,
            byte_length=7,
            header_names=("content-type",),
        ),
    )


def _observation(*, run_id: EntityId | None = None) -> ObservationSample:
    return ObservationSample(
        record_id=_id("observation_record"),
        run_id=_id("run") if run_id is None else run_id,
        scenario_id=_id("scenario"),
        observation_id=_id("observation"),
        sample_id=_id("sample"),
        observer_id="receiver-state",
        sample_sequence=1,
        recorded_at=NOW,
        status=ObservationStatus.OK,
        evidence=(
            ObservationEvidence(
                key="processing_count",
                value_type=EvidenceValueType.INTEGER,
                value=1,
            ),
        ),
    )


def _assertion(*, run_id: EntityId | None = None) -> AssertionEvaluation:
    return AssertionEvaluation(
        record_id=_id("assertion_record"),
        run_id=_id("run") if run_id is None else run_id,
        scenario_id=_id("scenario"),
        assertion_id=_id("assertion"),
        evaluation_sequence=1,
        recorded_at=NOW,
        type="processing-count",
        result=AssertionResult.PASS,
        expected=1,
        actual=1,
        evidence_refs=(_id("observation_record"),),
    )


def test_entity_models_are_distinct_strict_and_frozen() -> None:
    run = Run(
        run_id=_id("run"),
        manifest_id=_id("manifest"),
        state=RunState.PLANNED,
        created_at=NOW,
        scenario_ids=(_id("scenario"),),
    )
    scenario = Scenario(
        run_id=run.run_id,
        scenario_id=_id("scenario"),
        ordinal=0,
        name="baseline",
        state=ScenarioState.PENDING,
    )
    event = LogicalEvent(
        scenario_id=scenario.scenario_id,
        event_id=_id("event"),
        event_type="payment.succeeded",
        fixture_sha256=DIGEST,
    )
    delivery = PlannedDelivery(
        scenario_id=scenario.scenario_id,
        event_id=event.event_id,
        delivery_id=_id("delivery"),
        ordinal=0,
        logical_time_ns=0,
        state=DeliveryState.PENDING,
    )
    attempt = PhysicalAttempt(
        run_id=run.run_id,
        scenario_id=scenario.scenario_id,
        event_id=event.event_id,
        delivery_id=delivery.delivery_id,
        attempt_id=_id("attempt"),
        ordinal=0,
        state=AttemptState.SCHEDULED,
    )
    observation = Observation(
        run_id=run.run_id,
        scenario_id=scenario.scenario_id,
        observation_id=_id("observation"),
        observer_id="receiver-state",
        state=ObservationState.SCHEDULED,
    )
    assertion = Assertion(
        run_id=run.run_id,
        scenario_id=scenario.scenario_id,
        assertion_id=_id("assertion"),
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


def test_evidence_round_trips_across_strict_json_boundary() -> None:
    for model in (_attempt(), _observation(), _assertion()):
        assert type(model).model_validate_json(model.model_dump_json()) == model


def test_unknown_fields_invalid_bounds_digests_and_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError):
        AttemptEvidence.model_validate({"record_id": _id("record"), "unknown": True})
    with pytest.raises(ValidationError):
        _observation().model_copy(update={"sample_sequence": 0}).model_validate(
            {**_observation().model_dump(), "sample_sequence": 0}
        )
    with pytest.raises(ValidationError):
        RequestMetadata(
            url_redacted="http://127.0.0.1/",
            body_sha256=Sha256Digest("sha256:ABC"),
            byte_length=1,
        )
    with pytest.raises(ValidationError):
        Run(
            run_id=_id("run"),
            manifest_id=_id("manifest"),
            state=RunState.PLANNED,
            created_at=NOW.replace(tzinfo=None),
        )
    with pytest.raises(ValidationError):
        Run(
            run_id=_id("run"),
            manifest_id=_id("manifest"),
            state=RunState.PLANNED,
            created_at=datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1))),
        )


def test_transport_and_receiver_state_evidence_are_separate() -> None:
    attempt = _attempt()
    observation = _observation()
    with pytest.raises(ValidationError):
        ObservationSample.model_validate(attempt.model_dump())
    with pytest.raises(ValidationError):
        AttemptEvidence.model_validate(observation.model_dump())
    with pytest.raises(ValidationError):
        AggregateRunOutcome.model_validate(
            {
                "run_id": _id("run"),
                "manifest_id": _id("manifest"),
                "generated_at": NOW,
                "verdict": ResultCategory.PASS,
                "exit_code": ExitCode.PASS,
                "attempts": [observation.model_dump()],
            }
        )


def test_aggregate_enforces_exit_mapping_and_evidence_run_links() -> None:
    run_id = _id("run")
    outcome = AggregateRunOutcome(
        run_id=run_id,
        manifest_id=_id("manifest"),
        generated_at=NOW,
        verdict=ResultCategory.PASS,
        exit_code=ExitCode.PASS,
        attempts=(_attempt(run_id=run_id),),
        observations=(_observation(run_id=run_id),),
        assertions=(_assertion(run_id=run_id),),
    )
    assert AggregateRunOutcome.model_validate_json(outcome.model_dump_json()) == outcome
    with pytest.raises(ValidationError):
        AggregateRunOutcome(
            run_id=run_id,
            manifest_id=_id("manifest"),
            generated_at=NOW,
            verdict=ResultCategory.PASS,
            exit_code=ExitCode.HARNESS_FAILURE,
        )
    with pytest.raises(ValidationError):
        AggregateRunOutcome(
            run_id=run_id,
            manifest_id=_id("manifest"),
            generated_at=NOW,
            verdict=ResultCategory.PASS,
            exit_code=ExitCode.PASS,
            observations=(_observation(run_id=_id("other_run")),),
        )


def test_json_evidence_rejects_arbitrary_python_objects() -> None:
    with pytest.raises(ValidationError):
        ObservationEvidence.model_validate(
            {
                "key": "unsafe",
                "value_type": EvidenceValueType.OBJECT,
                "value": object(),
            }
        )


def test_state_vocabularies_follow_normative_machine_requirements() -> None:
    assert {state.value for state in RunState} == {
        "planned",
        "running",
        "paused",
        "completed",
        "cancelled",
        "failed",
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
