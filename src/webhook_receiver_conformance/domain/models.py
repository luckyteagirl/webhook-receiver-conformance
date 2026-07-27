"""Immutable typed records for planned entities and observed run evidence."""
# ruff: noqa: INP001

from __future__ import annotations

import math
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from webhook_receiver_conformance.domain.hashing import (
    validate_manifest_id,
    validate_sha256_digest,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory, exit_for_result
from webhook_receiver_conformance.types import JsonValue

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
_MAX_MEDIA_TYPE_LENGTH = 255
_DECIMAL_STRING = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_UTC_TIMESTAMP = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?Z"
)


def _validate_utc(value: AwareDatetime) -> AwareDatetime:
    if value.utcoffset() != timedelta(0):
        message = "timestamp must use UTC"
        raise ValueError(message)
    return value


def _scenario_id(value: str) -> str:
    return validate_planned_id(value, expected_kind=PlannedIdKind.SCENARIO)


def _event_id(value: str) -> str:
    return validate_planned_id(value, expected_kind=PlannedIdKind.EVENT)


def _delivery_id(value: str) -> str:
    return validate_planned_id(value, expected_kind=PlannedIdKind.DELIVERY)


def _observation_id(value: str) -> str:
    return validate_planned_id(value, expected_kind=PlannedIdKind.OBSERVATION)


def _assertion_id(value: str) -> str:
    return validate_planned_id(value, expected_kind=PlannedIdKind.ASSERTION)


def _attempt_id(value: str) -> str:
    return validate_fresh_id(value, expected_kind=FreshIdKind.ATTEMPT)


def _sample_id(value: str) -> str:
    return validate_fresh_id(value, expected_kind=FreshIdKind.SAMPLE)


def _record_id(value: str) -> str:
    return validate_fresh_id(value, expected_kind=FreshIdKind.RECORD)


def _serialized_id(value: str) -> str:
    try:
        return validate_planned_id(value)
    except ValueError:
        return validate_fresh_id(value)


def _safe_json(value: JsonValue) -> JsonValue:
    _reject_nonfinite_json(value)
    return value


def _reject_nonfinite_json(value: JsonValue) -> None:
    if isinstance(value, float):
        if not math.isfinite(value):
            message = "serialized JSON values must not contain non-finite numbers"
            raise ValueError(message)
        return
    if isinstance(value, list):
        for item in value:
            _reject_nonfinite_json(item)
        return
    if isinstance(value, dict):
        for item in value.values():
            _reject_nonfinite_json(item)


type _RunId = Annotated[str, AfterValidator(validate_run_id)]
type _ManifestId = Annotated[str, AfterValidator(validate_manifest_id)]
type _Digest = Annotated[str, AfterValidator(validate_sha256_digest)]
type _ScenarioId = Annotated[str, AfterValidator(_scenario_id)]
type _EventId = Annotated[str, AfterValidator(_event_id)]
type _DeliveryId = Annotated[str, AfterValidator(_delivery_id)]
type _ObservationId = Annotated[str, AfterValidator(_observation_id)]
type _AssertionId = Annotated[str, AfterValidator(_assertion_id)]
type _AttemptId = Annotated[str, AfterValidator(_attempt_id)]
type _SampleId = Annotated[str, AfterValidator(_sample_id)]
type _RecordId = Annotated[str, AfterValidator(_record_id)]
type _SerializedId = Annotated[str, AfterValidator(_serialized_id)]
type _SafeJson = Annotated[JsonValue, AfterValidator(_safe_json)]
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

    run_id: _RunId
    manifest_id: _ManifestId
    state: RunState
    created_at: _UtcDateTime
    scenario_ids: tuple[_ScenarioId, ...] = ()


class Scenario(DomainModel):
    """One ordered conformance scenario."""

    run_id: _RunId
    scenario_id: _ScenarioId
    ordinal: int = Field(ge=0, le=_MAX_SIGNED_64)
    name: str = Field(min_length=1, max_length=256)
    state: ScenarioState
    event_ids: tuple[_EventId, ...] = ()
    delivery_ids: tuple[_DeliveryId, ...] = ()
    observation_ids: tuple[_ObservationId, ...] = ()
    assertion_ids: tuple[_AssertionId, ...] = ()


class LogicalEvent(DomainModel):
    """A semantic event stable across its planned deliveries."""

    scenario_id: _ScenarioId
    event_id: _EventId
    event_type: str = Field(min_length=1, max_length=256)
    fixture_sha256: _Digest
    delivery_ids: tuple[_DeliveryId, ...] = ()


class PlannedDelivery(DomainModel):
    """One manifest-fixed delivery of a logical event."""

    scenario_id: _ScenarioId
    event_id: _EventId
    delivery_id: _DeliveryId
    ordinal: int = Field(ge=0, le=_MAX_SIGNED_64)
    logical_time_ns: int = Field(ge=_MIN_SIGNED_64, le=_MAX_SIGNED_64)
    state: DeliveryState
    attempt_ids: tuple[_AttemptId, ...] = ()


class PhysicalAttempt(DomainModel):
    """One physical network attempt for a planned delivery."""

    run_id: _RunId
    scenario_id: _ScenarioId
    event_id: _EventId
    delivery_id: _DeliveryId
    attempt_id: _AttemptId
    ordinal: int = Field(ge=0, le=_MAX_SIGNED_64)
    state: AttemptState
    classification: AttemptClassification | None = None


class Observation(DomainModel):
    """One observer polling series at a scenario checkpoint."""

    run_id: _RunId
    scenario_id: _ScenarioId
    observation_id: _ObservationId
    observer_id: str = Field(min_length=1, max_length=256)
    state: ObservationState
    event_id: _EventId | None = None


class Assertion(DomainModel):
    """One declared invariant and its current lifecycle state."""

    run_id: _RunId
    scenario_id: _ScenarioId
    assertion_id: _AssertionId
    type: str = Field(min_length=1, max_length=128)
    state: AssertionState


class AttemptEvidence(DomainModel):
    """Serialized transport-attempt evidence; never receiver-state evidence."""

    schema_version: Literal["1.0"] = "1.0"
    record_id: _RecordId
    run_id: _RunId
    scenario_id: _ScenarioId
    event_id: _EventId
    delivery_id: _DeliveryId
    attempt_id: _AttemptId
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
    """One receiver-state value conforming to its declared evidence type."""

    key: str = Field(min_length=1, max_length=256)
    value_type: EvidenceValueType
    value: _SafeJson
    sensitive: bool = False

    @model_validator(mode="after")
    def require_declared_value_shape(self) -> ObservationEvidence:
        """Enforce the observer-evidence conditional schema in Python."""
        if not _matches_evidence_type(self.value_type, self.value):
            message = f"value does not conform to value_type {self.value_type.value}"
            raise ValueError(message)
        return self


class ObservationSample(DomainModel):
    """Serialized receiver-state observation sample."""

    schema_version: Literal["1.0"] = "1.0"
    record_id: _RecordId
    run_id: _RunId
    scenario_id: _ScenarioId
    observation_id: _ObservationId
    sample_id: _SampleId
    observer_id: str = Field(min_length=1, max_length=256)
    sample_sequence: int = Field(ge=1, le=_MAX_SIGNED_64)
    recorded_at: _UtcDateTime
    status: ObservationStatus
    event_id: _EventId | None = None
    snapshot_id: str | None = Field(default=None, max_length=512)
    evidence: tuple[ObservationEvidence, ...] = ()
    error: ObservationError | None = None

    @model_validator(mode="after")
    def require_successful_snapshot(self) -> ObservationSample:
        """Require every successful observation to identify its snapshot."""
        if self.status is ObservationStatus.OK and (
            self.snapshot_id is None or not self.snapshot_id.strip()
        ):
            message = "an ok observation requires a nonempty snapshot_id"
            raise ValueError(message)
        return self


class AssertionEvaluation(DomainModel):
    """Serialized assertion evaluation linked to immutable evidence IDs."""

    schema_version: Literal["1.0"] = "1.0"
    record_id: _RecordId
    run_id: _RunId
    scenario_id: _ScenarioId
    assertion_id: _AssertionId
    evaluation_sequence: int = Field(ge=1, le=_MAX_SIGNED_64)
    recorded_at: _UtcDateTime
    type: str = Field(min_length=1, max_length=128)
    result: AssertionResult
    expected: _SafeJson = None
    actual: _SafeJson = None
    comparison: str | None = Field(default=None, max_length=256)
    evidence_refs: tuple[_SerializedId, ...] = Field(min_length=1)
    message: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def require_unique_evidence_refs(self) -> AssertionEvaluation:
        """Reject ambiguous duplicate evidence links."""
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            message = "evidence_refs must be unique"
            raise ValueError(message)
        return self


class ResultCounts(DomainModel):
    """Typed result-summary record counts."""

    scenarios: int = Field(ge=0)
    attempts: int = Field(ge=0)
    observations: int = Field(ge=0)
    assertions: int = Field(ge=0)


class ArtifactPaths(DomainModel):
    """Artifact paths named by result-summary.schema.json."""

    manifest: str
    deliveries: str
    observations: str
    assertions: str
    junit: str | None = None
    html: str | None = None


class AggregateRunOutcome(DomainModel):
    """Serialized projection conforming exactly to result-summary.schema.json."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: _RunId
    manifest_id: _ManifestId
    generated_at: _UtcDateTime
    verdict: ResultCategory
    exit_code: ExitCode
    counts: ResultCounts
    failure_refs: tuple[_SerializedId, ...] = ()
    artifacts: ArtifactPaths

    @model_validator(mode="after")
    def require_consistent_result(self) -> AggregateRunOutcome:
        """Require the documented exit mapping and unique failure links."""
        expected_exit = exit_for_result(self.verdict)[1]
        if self.exit_code is not expected_exit:
            message = "exit_code does not match verdict"
            raise ValueError(message)
        if len(set(self.failure_refs)) != len(self.failure_refs):
            message = "failure_refs must be unique"
            raise ValueError(message)
        return self


def _valid_bytes_digest(value: JsonValue) -> bool:
    if not isinstance(value, dict) or not set(value) <= {
        "sha256",
        "byte_length",
        "media_type",
    }:
        return False
    if set(value) < {"sha256", "byte_length"}:
        return False
    sha256 = value["sha256"]
    byte_length = value["byte_length"]
    if not isinstance(sha256, str):
        return False
    try:
        validate_sha256_digest(sha256)
    except ValueError:
        return False
    if type(byte_length) is not int or byte_length < 0:
        return False
    media_type = value.get("media_type")
    return media_type is None or (
        isinstance(media_type, str) and 1 <= len(media_type) <= _MAX_MEDIA_TYPE_LENGTH
    )


def _matches_evidence_type(  # noqa: PLR0911
    value_type: EvidenceValueType,
    value: JsonValue,
) -> bool:
    match value_type:
        case EvidenceValueType.NULL:
            return value is None
        case EvidenceValueType.BOOLEAN:
            return type(value) is bool
        case EvidenceValueType.INTEGER:
            return type(value) is int
        case EvidenceValueType.DECIMAL_STRING:
            return isinstance(value, str) and _DECIMAL_STRING.fullmatch(value) is not None
        case EvidenceValueType.STRING:
            return isinstance(value, str)
        case EvidenceValueType.BYTES_DIGEST:
            return _valid_bytes_digest(value)
        case EvidenceValueType.TIMESTAMP:
            return isinstance(value, str) and _valid_utc_timestamp(value)
        case EvidenceValueType.ARRAY:
            return isinstance(value, list)
        case EvidenceValueType.OBJECT:
            return isinstance(value, dict)


def _valid_utc_timestamp(value: str) -> bool:
    match = _UTC_TIMESTAMP.fullmatch(value)
    if match is None:
        return False
    try:
        datetime(
            int(match["year"]),
            int(match["month"]),
            int(match["day"]),
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
            tzinfo=UTC,
        )
    except ValueError:
        return False
    return True
