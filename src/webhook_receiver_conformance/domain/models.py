"""Immutable typed records for planned entities and observed run evidence."""
# ruff: noqa: INP001, TC001

from __future__ import annotations

import re
from datetime import timedelta
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from webhook_receiver_conformance.errors import ExitCode, ResultCategory, exit_for_result
from webhook_receiver_conformance.types import EntityId, JsonValue, Sha256Digest

from .enums import (
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

_MIN_SIGNED_64 = -(2**63)
_MAX_SIGNED_64 = 2**63 - 1
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


def _validate_sha256(value: Sha256Digest) -> Sha256Digest:
    if _SHA256.fullmatch(value) is None:
        message = "digest must use the sha256:<64 lowercase hexadecimal> form"
        raise ValueError(message)
    return value


def _validate_utc(value: AwareDatetime) -> AwareDatetime:
    if value.utcoffset() != timedelta(0):
        message = "timestamp must use UTC"
        raise ValueError(message)
    return value


type _Digest = Annotated[Sha256Digest, AfterValidator(_validate_sha256)]
type _UtcDateTime = Annotated[AwareDatetime, AfterValidator(_validate_utc)]


class DomainModel(BaseModel):
    """Shared strictness and immutability contract for domain records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RequestMetadata(DomainModel):
    """Sanitized request metadata retained with transport evidence."""

    method: Literal["POST"] = "POST"
    url_redacted: str = Field(min_length=1, max_length=2048)
    body_sha256: _Digest
    byte_length: int = Field(ge=0, le=_MAX_SIGNED_64)
    header_names: tuple[str, ...] = ()


class ResponseMetadata(DomainModel):
    """Bounded response metadata retained with transport evidence."""

    status: int = Field(ge=100, le=599)
    body_sha256: _Digest | None = None
    captured_bytes: int = Field(ge=0, le=_MAX_SIGNED_64)
    truncated: bool = False


class TransportError(DomainModel):
    """Redacted transport failure evidence."""

    category: str = Field(min_length=1, max_length=128)
    message_redacted: str = Field(min_length=1, max_length=4096)
    phase: str | None = Field(default=None, max_length=64)


class ObservationError(DomainModel):
    """Redacted receiver-state observation failure evidence."""

    category: str = Field(min_length=1, max_length=128)
    message_redacted: str = Field(min_length=1, max_length=4096)


class Run(DomainModel):
    """One execution bound to an immutable manifest."""

    run_id: EntityId
    manifest_id: EntityId
    state: RunState
    created_at: _UtcDateTime
    scenario_ids: tuple[EntityId, ...] = ()


class Scenario(DomainModel):
    """One ordered conformance scenario."""

    run_id: EntityId
    scenario_id: EntityId
    ordinal: int = Field(ge=0, le=_MAX_SIGNED_64)
    name: str = Field(min_length=1, max_length=256)
    state: ScenarioState
    event_ids: tuple[EntityId, ...] = ()
    delivery_ids: tuple[EntityId, ...] = ()
    observation_ids: tuple[EntityId, ...] = ()
    assertion_ids: tuple[EntityId, ...] = ()


class LogicalEvent(DomainModel):
    """A semantic event stable across its planned deliveries."""

    scenario_id: EntityId
    event_id: EntityId
    event_type: str = Field(min_length=1, max_length=256)
    fixture_sha256: _Digest
    delivery_ids: tuple[EntityId, ...] = ()


class PlannedDelivery(DomainModel):
    """One manifest-fixed delivery of a logical event."""

    scenario_id: EntityId
    event_id: EntityId
    delivery_id: EntityId
    ordinal: int = Field(ge=0, le=_MAX_SIGNED_64)
    logical_time_ns: int = Field(ge=_MIN_SIGNED_64, le=_MAX_SIGNED_64)
    state: DeliveryState
    attempt_ids: tuple[EntityId, ...] = ()


class PhysicalAttempt(DomainModel):
    """One physical network attempt for a planned delivery."""

    run_id: EntityId
    scenario_id: EntityId
    event_id: EntityId
    delivery_id: EntityId
    attempt_id: EntityId
    ordinal: int = Field(ge=0, le=_MAX_SIGNED_64)
    state: AttemptState
    classification: AttemptClassification | None = None


class Observation(DomainModel):
    """One observer polling series at a scenario checkpoint."""

    run_id: EntityId
    scenario_id: EntityId
    observation_id: EntityId
    observer_id: str = Field(min_length=1, max_length=256)
    state: ObservationState
    event_id: EntityId | None = None


class Assertion(DomainModel):
    """One declared invariant and its current lifecycle state."""

    run_id: EntityId
    scenario_id: EntityId
    assertion_id: EntityId
    type: str = Field(min_length=1, max_length=128)
    state: AssertionState


class AttemptEvidence(DomainModel):
    """Serialized transport-attempt evidence; never receiver-state evidence."""

    schema_version: Literal["1.0"] = "1.0"
    record_id: EntityId
    run_id: EntityId
    scenario_id: EntityId
    event_id: EntityId
    delivery_id: EntityId
    attempt_id: EntityId
    sequence: int = Field(ge=1, le=_MAX_SIGNED_64)
    recorded_at: _UtcDateTime
    logical_time_ns: int | None = Field(
        default=None,
        ge=_MIN_SIGNED_64,
        le=_MAX_SIGNED_64,
    )
    monotonic_elapsed_ns: int | None = Field(default=None, ge=0, le=_MAX_SIGNED_64)
    state: AttemptEvidenceState
    classification: AttemptClassification
    request: RequestMetadata | None = None
    response: ResponseMetadata | None = None
    error: TransportError | None = None


class ObservationEvidence(DomainModel):
    """One typed JSON-compatible receiver-state evidence value."""

    key: str = Field(min_length=1, max_length=256)
    value_type: EvidenceValueType
    value: JsonValue
    sensitive: bool = False


class ObservationSample(DomainModel):
    """Serialized receiver-state observation sample."""

    schema_version: Literal["1.0"] = "1.0"
    record_id: EntityId
    run_id: EntityId
    scenario_id: EntityId
    observation_id: EntityId
    sample_id: EntityId
    observer_id: str = Field(min_length=1, max_length=256)
    sample_sequence: int = Field(ge=1, le=_MAX_SIGNED_64)
    recorded_at: _UtcDateTime
    status: ObservationStatus
    event_id: EntityId | None = None
    snapshot_id: str | None = Field(default=None, max_length=512)
    evidence: tuple[ObservationEvidence, ...] = ()
    error: ObservationError | None = None


class AssertionEvaluation(DomainModel):
    """Serialized assertion evaluation linked to immutable evidence IDs."""

    schema_version: Literal["1.0"] = "1.0"
    record_id: EntityId
    run_id: EntityId
    scenario_id: EntityId
    assertion_id: EntityId
    evaluation_sequence: int = Field(ge=1, le=_MAX_SIGNED_64)
    recorded_at: _UtcDateTime
    type: str = Field(min_length=1, max_length=128)
    result: AssertionResult
    expected: JsonValue = None
    actual: JsonValue = None
    comparison: str | None = Field(default=None, max_length=256)
    evidence_refs: tuple[EntityId, ...] = Field(min_length=1)
    message: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def require_unique_evidence_refs(self) -> AssertionEvaluation:
        """Reject ambiguous duplicate evidence links."""
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            message = "evidence_refs must be unique"
            raise ValueError(message)
        return self


class AggregateRunOutcome(DomainModel):
    """Typed result projection with transport and receiver-state evidence separated."""

    run_id: EntityId
    manifest_id: EntityId
    generated_at: _UtcDateTime
    verdict: ResultCategory
    exit_code: ExitCode
    scenarios: tuple[Scenario, ...] = ()
    attempts: tuple[AttemptEvidence, ...] = ()
    observations: tuple[ObservationSample, ...] = ()
    assertions: tuple[AssertionEvaluation, ...] = ()

    @model_validator(mode="after")
    def require_consistent_result(self) -> AggregateRunOutcome:
        """Require the documented exit mapping and one run ID across evidence."""
        expected_exit = exit_for_result(self.verdict)[1]
        if self.exit_code is not expected_exit:
            message = "exit_code does not match verdict"
            raise ValueError(message)
        linked = (*self.attempts, *self.observations, *self.assertions)
        if any(record.run_id != self.run_id for record in linked):
            message = "all evidence must reference the aggregate run_id"
            raise ValueError(message)
        return self
