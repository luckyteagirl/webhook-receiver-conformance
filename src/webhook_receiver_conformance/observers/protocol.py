"""Strict, versioned observer wire models and pure capability policy."""
# ruff: noqa: C901, D102, D105, D107, EM101, INP001, PLR0911, PLR0912, PLR0915, PLR2004, SIM102

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path
from types import MappingProxyType
from typing import (
    Annotated,
    ClassVar,
    Final,
    Literal,
    Never,
    Protocol,
    cast,
    runtime_checkable,
)

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)

from webhook_receiver_conformance.domain.enums import (
    EvidenceValueType,
    ObservationStatus,
)
from webhook_receiver_conformance.domain.hashing import (
    CanonicalJson,
    canonical_json_bytes,
    validate_sha256_digest,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    decode_crockford_ulid,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.errors import (
    Diagnostic,
    ErrorCategory,
    ResultCategory,
)
from webhook_receiver_conformance.types import DiagnosticCode

OBSERVER_PROTOCOL_VERSION: Final = "1.0"
OBSERVATION_RECORD_SCHEMA_VERSION: Final = "1.0"
HTTP_OBSERVER_METHOD: Final = "POST"
HTTP_CAPABILITIES_PATH: Final = "/capabilities"
HTTP_OBSERVE_PATH: Final = "/observe"

MAX_OBSERVER_MESSAGE_BYTES: Final = 1_048_576
MAX_OBSERVER_QUERIES: Final = 64
MAX_CAPABILITY_EVIDENCE_KEYS: Final = 256
MAX_EVIDENCE_VALUES: Final = 64
MAX_QUERY_PARAMETERS: Final = 128
MAX_JSON_ARRAY_ITEMS: Final = 1000
MAX_JSON_OBJECT_PROPERTIES: Final = 1000
MAX_JSON_DEPTH: Final = 32
MAX_JSON_NODES: Final = 10_000
MAX_JSON_STRING_LENGTH: Final = 4096
MAX_JSON_OBJECT_KEY_LENGTH: Final = 256
MAX_SNAPSHOT_ID_LENGTH: Final = 512
MAX_CHECKPOINT_LENGTH: Final = 128
MAX_OBSERVER_ID_LENGTH: Final = 256
MAX_ERROR_CATEGORY_LENGTH: Final = 128
MAX_ERROR_MESSAGE_LENGTH: Final = 4096
MAX_DECIMAL_STRING_LENGTH: Final = 256
MAX_MEDIA_TYPE_LENGTH: Final = 255
MIN_IJSON_INTEGER: Final = -9_007_199_254_740_991
MAX_IJSON_INTEGER: Final = 9_007_199_254_740_991

_REQUEST_ID = re.compile(r"request_([0-7][0-9A-HJKMNP-TV-Z]{25})")
_ERROR_CATEGORY = re.compile(r"[a-z][a-z0-9_]{0,127}")
_DECIMAL_STRING = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_UTC_TIMESTAMP = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?Z"
)
_OBSERVER_PACKAGE_PREFIX: Final = "webhook_receiver_conformance.observers."
_OBSERVER_PACKAGE_MODULE: Final = _OBSERVER_PACKAGE_PREFIX.removesuffix(".")
_REQUIRED_BUILTIN_OBSERVER_CONTRACT: Final[Mapping[str, str]] = MappingProxyType(
    {
        "command": f"{_OBSERVER_PACKAGE_PREFIX}command",
        "http": f"{_OBSERVER_PACKAGE_PREFIX}http",
    }
)
_IMPORTABLE_OBSERVER_FILE_SUFFIXES: Final = tuple(
    sorted((".py", *EXTENSION_SUFFIXES), key=len, reverse=True)
)


class _ObserverJsonResourceLimitError(ValueError):
    """Content-free classification for one structural JSON resource cap."""

    __slots__ = ("code", "safe_message")

    code: str
    safe_message: str

    def __init__(self, code: str, safe_message: str) -> None:
        self.code = code
        self.safe_message = safe_message
        super().__init__(safe_message)


class ObserverOperation(StrEnum):
    """Closed observer request operations in protocol version 1.0."""

    CAPABILITIES = "capabilities"
    OBSERVE = "observe"


class ObserverResponseStatus(StrEnum):
    """The four response statuses that can arrive on the observer wire."""

    OK = "ok"
    PENDING = "pending"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class UnsupportedPolicy(StrEnum):
    """Assertion-level handling for an unavailable observer capability."""

    UNSUPPORTED = "unsupported"
    SKIP = "skip"


class AssertionUnsupportedDisposition(StrEnum):
    """Wire-neutral assertion fact selected by unsupported policy."""

    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"


class BuiltinObserverKind(StrEnum):
    """Closed first-party observer transport categories in v0.1."""

    COMMAND = "command"
    HTTP = "http"


class ProtocolModel(BaseModel):
    """Shared strictness, immutability, and safe wire projection."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )

    def wire_dict(self) -> dict[str, object]:
        """Return the JSON-compatible public projection without absent optionals."""
        return cast(
            "dict[str, object]",
            self.model_dump(mode="json", exclude_none=True),
        )


class FrozenJsonObject(Mapping[str, object]):
    """Small immutable mapping used for bounded observer JSON values."""

    __slots__ = ("_items", "_values")

    _items: tuple[tuple[str, object], ...]
    _values: Mapping[str, object]

    def __init__(self, items: tuple[tuple[str, object], ...] = ()) -> None:
        if type(items) is not tuple:
            message = "frozen JSON object items must be a tuple"
            raise TypeError(message)
        values: dict[str, object] = {}
        for entry in items:
            if type(entry) is not tuple or len(entry) != 2:
                message = "frozen JSON object entries must be key-value tuples"
                raise TypeError(message)
            key, value = entry
            if type(key) is not str:
                message = "frozen JSON object keys must be strings"
                raise TypeError(message)
            if key in values:
                message = "frozen JSON object keys must be unique"
                raise ValueError(message)
            values[key] = value
        object.__setattr__(self, "_items", items)
        object.__setattr__(self, "_values", MappingProxyType(values))

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return (key for key, _value in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(keys={tuple(self)!r})"

    def __setattr__(self, _name: str, _value: object) -> Never:
        message = "frozen JSON objects are immutable"
        raise AttributeError(message)

    def __delattr__(self, _name: str) -> Never:
        message = "frozen JSON objects are immutable"
        raise AttributeError(message)


type FrozenJsonValue = bool | int | str | tuple[object, ...] | FrozenJsonObject | None


def _operation_from_wire(value: object) -> object:
    if type(value) is str:
        return ObserverOperation(value)
    return value


def _response_status_from_wire(value: object) -> object:
    if type(value) is str:
        return ObserverResponseStatus(value)
    return value


def _evidence_type_from_wire(value: object) -> object:
    if type(value) is str:
        return EvidenceValueType(value)
    return value


def _record_status_from_wire(value: object) -> object:
    if type(value) is str:
        return ObservationStatus(value)
    return value


type _WireOperation = Annotated[
    ObserverOperation,
    BeforeValidator(_operation_from_wire),
]
type _WireResponseStatus = Annotated[
    ObserverResponseStatus,
    BeforeValidator(_response_status_from_wire),
]
type _WireEvidenceType = Annotated[
    EvidenceValueType,
    BeforeValidator(_evidence_type_from_wire),
]
type _WireRecordStatus = Annotated[
    ObservationStatus,
    BeforeValidator(_record_status_from_wire),
]


def _request_id(value: str) -> str:
    match = _REQUEST_ID.fullmatch(value)
    if match is None:
        message = "request_id must use the request_<ULID> encoding"
        raise ValueError(message)
    decode_crockford_ulid(match.group(1))
    return value


def _sample_id(value: str) -> str:
    return validate_fresh_id(value, expected_kind=FreshIdKind.SAMPLE)


def _record_id(value: str) -> str:
    return validate_fresh_id(value, expected_kind=FreshIdKind.RECORD)


def _scenario_id(value: str) -> str:
    return validate_planned_id(value, expected_kind=PlannedIdKind.SCENARIO)


def _event_id(value: str) -> str:
    return validate_planned_id(value, expected_kind=PlannedIdKind.EVENT)


def _observation_id(value: str) -> str:
    return validate_planned_id(value, expected_kind=PlannedIdKind.OBSERVATION)


type _RequestId = Annotated[str, AfterValidator(_request_id)]
type _SampleId = Annotated[str, AfterValidator(_sample_id)]
type _RecordId = Annotated[str, AfterValidator(_record_id)]
type _RunId = Annotated[str, AfterValidator(validate_run_id)]
type _ScenarioId = Annotated[str, AfterValidator(_scenario_id)]
type _EventId = Annotated[str, AfterValidator(_event_id)]
type _ObservationId = Annotated[str, AfterValidator(_observation_id)]
type _Digest = Annotated[str, AfterValidator(validate_sha256_digest)]


class BytesDigestMetadata(ProtocolModel):
    """Digest-only representation of binary evidence; no bytes are retained."""

    sha256: _Digest
    byte_length: int = Field(ge=0, le=MAX_IJSON_INTEGER)
    media_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_MEDIA_TYPE_LENGTH,
    )

    @field_validator("media_type")
    @classmethod
    def validate_media_type(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_bounded_text(
                value,
                field_name="media_type",
                maximum=MAX_MEDIA_TYPE_LENGTH,
                allow_empty=False,
            )
        return value


class ObserverEvidence(ProtocolModel):
    """One immutable, strictly tagged OBS-014 evidence value."""

    key: str = Field(min_length=1, max_length=MAX_JSON_OBJECT_KEY_LENGTH)
    value_type: _WireEvidenceType
    value: object | None = Field(repr=False)
    sensitive: bool = False

    @model_validator(mode="before")
    @classmethod
    def freeze_and_classify_value(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        source = cast("Mapping[object, object]", value)
        projected = dict(source)
        raw_type = projected.get("value_type")
        if raw_type in {EvidenceValueType.BYTES_DIGEST, EvidenceValueType.BYTES_DIGEST.value}:
            raw_value = projected.get("value")
            if type(raw_value) is not BytesDigestMetadata:
                projected["value"] = BytesDigestMetadata.model_validate(raw_value)
        elif "value" in projected:
            try:
                projected["value"] = _freeze_json(projected["value"])
            except TypeError as error:
                raise ValueError(str(error)) from None
        return projected

    @field_validator("key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            field_name="evidence key",
            maximum=MAX_JSON_OBJECT_KEY_LENGTH,
            allow_empty=False,
        )

    @model_validator(mode="after")
    def validate_declared_shape(self) -> ObserverEvidence:
        if not _matches_evidence_type(self.value_type, self.value):
            message = f"value does not conform to value_type {self.value_type.value}"
            raise ValueError(message)
        return self

    @field_serializer("value")
    def serialize_value(self, value: object | None) -> object:
        if type(value) is BytesDigestMetadata:
            return value.wire_dict()
        return _thaw_json(cast("FrozenJsonValue", value))

    def wire_dict(self) -> dict[str, object]:
        """Preserve the schema-required explicit null evidence value."""
        projection = super().wire_dict()
        if self.value is None:
            projection["value"] = None
        return projection

    @property
    def typed_value(self) -> object | None:
        """Return the deeply immutable typed value."""
        return self.value


def _empty_frozen_json_object() -> FrozenJsonObject:
    return FrozenJsonObject()


class ObserverQuery(ProtocolModel):
    """One named, typed, bounded receiver-state query."""

    key: str = Field(min_length=1, max_length=MAX_JSON_OBJECT_KEY_LENGTH)
    type: _WireEvidenceType
    parameters: object = Field(
        default_factory=_empty_frozen_json_object,
        repr=False,
    )

    @field_validator("key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            field_name="query key",
            maximum=MAX_JSON_OBJECT_KEY_LENGTH,
            allow_empty=False,
        )

    @field_validator("parameters", mode="before")
    @classmethod
    def freeze_parameters(cls, value: object) -> FrozenJsonObject:
        try:
            frozen = _freeze_json(value)
        except TypeError as error:
            raise ValueError(str(error)) from None
        if type(frozen) is not FrozenJsonObject:
            message = "query parameters must be a JSON object"
            raise ValueError(message)
        if len(frozen) > MAX_QUERY_PARAMETERS:
            message = "query parameters cannot contain more than 128 properties"
            raise ValueError(message)
        return frozen

    @field_serializer("parameters")
    def serialize_parameters(self, value: object) -> object:
        return _thaw_json(cast("FrozenJsonValue", value))

    @property
    def frozen_parameters(self) -> FrozenJsonObject:
        """Return the immutable parameter mapping."""
        return cast("FrozenJsonObject", self.parameters)


class ObserverCapabilities(ProtocolModel):
    """Version-1 capability declaration used before polling or recovery."""

    evidence_types: tuple[_WireEvidenceType, ...] = Field(min_length=1, max_length=9)
    evidence_keys: tuple[str, ...] = Field(max_length=MAX_CAPABILITY_EVIDENCE_KEYS)
    read_only: bool
    idempotent: bool
    max_queries: int = Field(default=MAX_OBSERVER_QUERIES, ge=1, le=MAX_OBSERVER_QUERIES)
    supports_pending: bool = False
    stable_snapshot_ids: bool = False

    @field_validator("evidence_types", "evidence_keys", mode="before")
    @classmethod
    def tuples_from_wire(cls, value: object) -> object:
        return _tuple_from_wire(value)

    @field_validator("evidence_keys")
    @classmethod
    def validate_evidence_keys(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for key in value:
            _validate_bounded_text(
                key,
                field_name="capability evidence key",
                maximum=MAX_JSON_OBJECT_KEY_LENGTH,
                allow_empty=False,
            )
        _require_unique(value, field_name="capability evidence keys")
        return value

    @field_validator("evidence_types")
    @classmethod
    def validate_evidence_types(
        cls,
        value: tuple[EvidenceValueType, ...],
    ) -> tuple[EvidenceValueType, ...]:
        _require_unique(value, field_name="capability evidence types")
        return value

    @property
    def automatic_reinvocation_safe(self) -> bool:
        """Return whether automatic retry is permitted by REL-009."""
        return self.read_only and self.idempotent

    @property
    def explicit_invocation_limit(self) -> int | None:
        """Limit a side-effecting observer to one explicit invocation."""
        return None if self.read_only else 1


class ObserverRequest(ProtocolModel):
    """One capability or observe request matching the public wire schema."""

    protocol_version: Literal["1.0"]
    request_id: _RequestId
    operation: _WireOperation
    sample_id: _SampleId | None = None
    run_id: _RunId | None = None
    scenario_id: _ScenarioId | None = None
    event_id: _EventId | None = None
    checkpoint: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_CHECKPOINT_LENGTH,
    )
    prior_snapshot_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_SNAPSHOT_ID_LENGTH,
    )
    queries: tuple[ObserverQuery, ...] = Field(default=(), max_length=MAX_OBSERVER_QUERIES)

    @field_validator("queries", mode="before")
    @classmethod
    def queries_from_wire(cls, value: object) -> object:
        return _tuple_from_wire(value)

    @field_validator("checkpoint")
    @classmethod
    def validate_checkpoint(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_bounded_text(
                value,
                field_name="checkpoint",
                maximum=MAX_CHECKPOINT_LENGTH,
                allow_empty=False,
            )
        return value

    @field_validator("prior_snapshot_id")
    @classmethod
    def validate_prior_snapshot_id(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_snapshot_id(value)
        return value

    @model_validator(mode="after")
    def validate_operation_shape(self) -> ObserverRequest:
        if self.operation is ObserverOperation.CAPABILITIES:
            if (
                any(
                    value is not None
                    for value in (
                        self.sample_id,
                        self.run_id,
                        self.scenario_id,
                        self.event_id,
                        self.checkpoint,
                        self.prior_snapshot_id,
                    )
                )
                or self.queries
            ):
                message = "capabilities requests cannot contain observe-only fields"
                raise ValueError(message)
            return self
        if self.sample_id is None or self.run_id is None or not self.queries:
            message = "observe requests require sample_id, run_id, and at least one query"
            raise ValueError(message)
        if self.event_id is not None and self.scenario_id is None:
            message = "event-scoped observe requests require scenario_id"
            raise ValueError(message)
        keys = tuple(query.key for query in self.queries)
        _require_unique(keys, field_name="observe query keys")
        return self


class ObserverWireError(ProtocolModel):
    """Stable observer-supplied category and retry fact with safe diagnostics."""

    category: str = Field(min_length=1, max_length=MAX_ERROR_CATEGORY_LENGTH)
    message: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_ERROR_MESSAGE_LENGTH,
        repr=False,
    )
    retryable: bool

    @field_validator("category")
    @classmethod
    def validate_category(cls, value: str) -> str:
        if _ERROR_CATEGORY.fullmatch(value) is None:
            message = "observer error category must be a bounded lowercase token"
            raise ValueError(message)
        return value

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_bounded_text(
                value,
                field_name="observer error message",
                maximum=MAX_ERROR_MESSAGE_LENGTH,
                allow_empty=False,
            )
        return value


class ObserverResponse(ProtocolModel):
    """One response with exactly one status and coherent terminal fields."""

    protocol_version: Literal["1.0"]
    request_id: _RequestId
    status: _WireResponseStatus
    capabilities: ObserverCapabilities
    snapshot_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_SNAPSHOT_ID_LENGTH,
    )
    evidence: tuple[ObserverEvidence, ...] = Field(max_length=MAX_EVIDENCE_VALUES)
    error: ObserverWireError | None

    @field_validator("evidence", mode="before")
    @classmethod
    def evidence_from_wire(cls, value: object) -> object:
        return _tuple_from_wire(value)

    @field_validator("snapshot_id")
    @classmethod
    def validate_snapshot_id(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_snapshot_id(value)
        return value

    @model_validator(mode="after")
    def validate_status_shape(self) -> ObserverResponse:
        keys = tuple(item.key for item in self.evidence)
        _require_unique(keys, field_name="response evidence keys")
        if self.status is ObserverResponseStatus.OK:
            if self.snapshot_id is None:
                message = "ok responses require a nonempty snapshot_id"
                raise ValueError(message)
            if self.error is not None:
                message = "ok responses cannot include an error"
                raise ValueError(message)
            return self
        if self.snapshot_id is not None or self.evidence:
            message = "non-ok responses cannot include a snapshot or evidence"
            raise ValueError(message)
        if self.status is ObserverResponseStatus.ERROR:
            if self.error is None:
                message = "error responses require an error object"
                raise ValueError(message)
        elif self.error is not None:
            message = "pending and unsupported responses cannot include an error"
            raise ValueError(message)
        return self

    def wire_dict(self) -> dict[str, object]:
        """Preserve the schema-required explicit null error field."""
        projection = super().wire_dict()
        if self.error is None:
            projection["error"] = None
        return projection


class ObservationRecordError(ProtocolModel):
    """Persisted redacted observation error metadata."""

    category: str = Field(min_length=1, max_length=MAX_ERROR_CATEGORY_LENGTH)
    message_redacted: str = Field(
        min_length=1,
        max_length=MAX_ERROR_MESSAGE_LENGTH,
        repr=False,
    )

    @field_validator("category")
    @classmethod
    def validate_category(cls, value: str) -> str:
        if _ERROR_CATEGORY.fullmatch(value) is None:
            message = "observation error category must be a bounded lowercase token"
            raise ValueError(message)
        return value

    @field_validator("message_redacted")
    @classmethod
    def validate_message(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            field_name="redacted observation error message",
            maximum=MAX_ERROR_MESSAGE_LENGTH,
            allow_empty=False,
        )


class ObservationRecord(ProtocolModel):
    """Immutable persisted projection matching observation-record.schema.json."""

    schema_version: Literal["1.0"]
    record_id: _RecordId
    run_id: _RunId
    scenario_id: _ScenarioId
    observation_id: _ObservationId
    sample_id: _SampleId
    observer_id: str = Field(min_length=1, max_length=MAX_OBSERVER_ID_LENGTH)
    sample_sequence: int = Field(ge=1, le=MAX_IJSON_INTEGER)
    recorded_at: str
    status: _WireRecordStatus
    event_id: _EventId | None = None
    snapshot_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_SNAPSHOT_ID_LENGTH,
    )
    evidence: tuple[ObserverEvidence, ...] = Field(default=(), max_length=MAX_EVIDENCE_VALUES)
    error: ObservationRecordError | None = None

    @field_validator("evidence", mode="before")
    @classmethod
    def evidence_from_wire(cls, value: object) -> object:
        return _tuple_from_wire(value)

    @field_validator("observer_id")
    @classmethod
    def validate_observer_id(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            field_name="observer_id",
            maximum=MAX_OBSERVER_ID_LENGTH,
            allow_empty=False,
        )

    @field_validator("recorded_at")
    @classmethod
    def validate_recorded_at(cls, value: str) -> str:
        return _validate_utc_timestamp(value)

    @field_validator("snapshot_id")
    @classmethod
    def validate_snapshot_id(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_snapshot_id(value)
        return value

    @model_validator(mode="after")
    def validate_status_shape(self) -> ObservationRecord:
        keys = tuple(item.key for item in self.evidence)
        _require_unique(keys, field_name="observation record evidence keys")
        if self.status is ObservationStatus.OK:
            if self.snapshot_id is None:
                message = "ok observation records require a nonempty snapshot_id"
                raise ValueError(message)
            if self.error is not None:
                message = "ok observation records cannot include an error"
                raise ValueError(message)
            return self
        if self.snapshot_id is not None or self.evidence:
            message = "non-ok observation records cannot include a snapshot or evidence"
            raise ValueError(message)
        if self.status in {ObservationStatus.ERROR, ObservationStatus.TIMEOUT}:
            if self.error is None:
                message = "error and timeout observation records require redacted error metadata"
                raise ValueError(message)
        return self


@dataclass(frozen=True, slots=True)
class ObserverHttpRoute:
    """Fixed HTTP method/path binding for one observer operation."""

    operation: ObserverOperation
    method: Literal["POST"]
    path: Literal["/capabilities", "/observe"]

    def __post_init__(self) -> None:
        if type(self.operation) is not ObserverOperation:
            message = "route operation must be an ObserverOperation"
            raise TypeError(message)
        expected_path = (
            HTTP_CAPABILITIES_PATH
            if self.operation is ObserverOperation.CAPABILITIES
            else HTTP_OBSERVE_PATH
        )
        if self.method != HTTP_OBSERVER_METHOD or self.path != expected_path:
            message = "observer HTTP route does not match its operation"
            raise ValueError(message)


CAPABILITIES_HTTP_ROUTE: Final = ObserverHttpRoute(
    operation=ObserverOperation.CAPABILITIES,
    method="POST",
    path="/capabilities",
)
OBSERVE_HTTP_ROUTE: Final = ObserverHttpRoute(
    operation=ObserverOperation.OBSERVE,
    method="POST",
    path="/observe",
)
OBSERVER_HTTP_ROUTES: Final[Mapping[ObserverOperation, ObserverHttpRoute]] = MappingProxyType(
    {
        ObserverOperation.CAPABILITIES: CAPABILITIES_HTTP_ROUTE,
        ObserverOperation.OBSERVE: OBSERVE_HTTP_ROUTE,
    }
)


@dataclass(frozen=True, slots=True)
class CapabilityNegotiation:
    """Pure, ordered facts describing whether requested evidence is supported."""

    missing_evidence_keys: tuple[str, ...] = ()
    unsupported_evidence_types: tuple[EvidenceValueType, ...] = ()
    query_limit_exceeded: bool = False
    stable_snapshot_unavailable: bool = False

    def __post_init__(self) -> None:
        if type(self.missing_evidence_keys) is not tuple:
            message = "missing_evidence_keys must be a tuple"
            raise TypeError(message)
        if type(self.unsupported_evidence_types) is not tuple:
            message = "unsupported_evidence_types must be a tuple"
            raise TypeError(message)
        if type(self.query_limit_exceeded) is not bool:
            message = "query_limit_exceeded must be a bool"
            raise TypeError(message)
        if type(self.stable_snapshot_unavailable) is not bool:
            message = "stable_snapshot_unavailable must be a bool"
            raise TypeError(message)
        _require_unique(self.missing_evidence_keys, field_name="missing evidence keys")
        _require_unique(
            self.unsupported_evidence_types,
            field_name="unsupported evidence types",
        )

    @property
    def supported(self) -> bool:
        """Return whether every pre-poll capability requirement is satisfied."""
        return not (
            self.missing_evidence_keys
            or self.unsupported_evidence_types
            or self.query_limit_exceeded
            or self.stable_snapshot_unavailable
        )

    @property
    def response_status(self) -> ObserverResponseStatus | None:
        """Return the deterministic mismatch status without reducing a CLI exit."""
        return None if self.supported else ObserverResponseStatus.UNSUPPORTED

    @property
    def error_category(self) -> ErrorCategory | None:
        """Return the stable mismatch category without invoking a verdict reducer."""
        return None if self.supported else ErrorCategory.UNSUPPORTED_CAPABILITY


@dataclass(frozen=True, slots=True)
class UnsupportedMapping:
    """Facts for assertion policy; intentionally contains no process exit code."""

    policy: UnsupportedPolicy
    observation_status: ObserverResponseStatus
    assertion_disposition: AssertionUnsupportedDisposition
    error_category: ErrorCategory
    result_category: ResultCategory
    polling_allowed: bool


@dataclass(frozen=True, slots=True)
class SnapshotBinding:
    """Opaque snapshot identity bound only to a state digest."""

    snapshot_id: str
    state_sha256: str

    def __post_init__(self) -> None:
        _validate_snapshot_id(self.snapshot_id)
        validate_sha256_digest(self.state_sha256)


@dataclass(frozen=True, slots=True)
class SnapshotIdentityLedger:
    """Immutable reference-observer guard against snapshot-ID reuse."""

    bindings: tuple[SnapshotBinding, ...] = ()

    def __post_init__(self) -> None:
        if type(self.bindings) is not tuple:
            message = "snapshot bindings must be a tuple"
            raise TypeError(message)
        identifiers: list[str] = []
        for binding in self.bindings:
            if type(binding) is not SnapshotBinding:
                message = "snapshot ledger entries must be SnapshotBinding values"
                raise TypeError(message)
            identifiers.append(binding.snapshot_id)
        _require_unique(tuple(identifiers), field_name="snapshot binding identifiers")

    def bind(self, snapshot_id: str, state_sha256: str) -> SnapshotIdentityLedger:
        """Return a ledger with one consistent ID-to-state binding."""
        candidate = SnapshotBinding(snapshot_id=snapshot_id, state_sha256=state_sha256)
        for existing in self.bindings:
            if existing.snapshot_id != candidate.snapshot_id:
                continue
            if existing.state_sha256 != candidate.state_sha256:
                raise ObserverProtocolError.protocol_violation(
                    "OBS_SNAPSHOT_ID_CONFLICT",
                    "An observer reused one snapshot ID for different state.",
                )
            return self
        return SnapshotIdentityLedger((*self.bindings, candidate))


@runtime_checkable
class Observer(Protocol):
    """Unstable internal protocol shared by every first-party observer adapter."""

    __slots__ = ()

    BUILTIN_KIND: ClassVar[BuiltinObserverKind]

    async def invoke(self, request: ObserverRequest) -> ObserverResponse:
        """Invoke one bounded observer request without implicit retry."""
        ...


BUILTIN_OBSERVER_MODULES: Final[Mapping[BuiltinObserverKind, str]] = MappingProxyType(
    {
        BuiltinObserverKind.COMMAND: _REQUIRED_BUILTIN_OBSERVER_CONTRACT["command"],
        BuiltinObserverKind.HTTP: _REQUIRED_BUILTIN_OBSERVER_CONTRACT["http"],
    }
)


@dataclass(frozen=True, slots=True)
class ObserverContractRegistration:
    """One static first-party observer category and its contract-suite facts."""

    kind: BuiltinObserverKind
    module_name: str
    contract_test_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.kind) is not BuiltinObserverKind:
            message = "observer registration kind must be BuiltinObserverKind"
            raise TypeError(message)
        if self.module_name != BUILTIN_OBSERVER_MODULES[self.kind]:
            message = "observer registration module conflicts with its closed category"
            raise ValueError(message)
        if type(self.contract_test_ids) is not tuple or not self.contract_test_ids:
            message = "observer registration requires contract test IDs"
            raise ValueError(message)
        for test_id in self.contract_test_ids:
            if type(test_id) is not str or not test_id.startswith("VT-"):
                message = "observer contract test IDs must be stable VT identifiers"
                raise ValueError(message)
        if len(set(self.contract_test_ids)) != len(self.contract_test_ids):
            message = "observer contract test IDs must be unique"
            raise ValueError(message)


class StaticObserverRegistry:
    """Immutable built-in registry with no plugin or dynamic loading behavior."""

    __slots__ = ("_by_kind", "_registration_snapshots")

    _by_kind: Mapping[BuiltinObserverKind, tuple[str, tuple[str, ...]]]
    _registration_snapshots: tuple[
        tuple[BuiltinObserverKind, str, tuple[str, ...]],
        ...,
    ]

    def __init__(self, registrations: tuple[ObserverContractRegistration, ...]) -> None:
        if type(registrations) is not tuple:
            message = "observer registrations must be a tuple"
            raise TypeError(message)
        by_kind: dict[BuiltinObserverKind, tuple[str, tuple[str, ...]]] = {}
        snapshots: list[tuple[BuiltinObserverKind, str, tuple[str, ...]]] = []
        for registration in registrations:
            if type(registration) is not ObserverContractRegistration:
                message = "observer registry entries must be contract registrations"
                raise TypeError(message)
            if registration.kind in by_kind:
                message = "a built-in observer category is registered more than once"
                raise ValueError(message)
            contract_test_ids = tuple(registration.contract_test_ids)
            snapshot = (
                registration.kind,
                registration.module_name,
                contract_test_ids,
            )
            snapshots.append(snapshot)
            by_kind[registration.kind] = (
                registration.module_name,
                contract_test_ids,
            )
        self._registration_snapshots = tuple(snapshots)
        self._by_kind = MappingProxyType(by_kind)

    @property
    def registrations(self) -> tuple[ObserverContractRegistration, ...]:
        """Return deterministic contract parametrization order."""
        return tuple(
            ObserverContractRegistration(
                kind=kind,
                module_name=module_name,
                contract_test_ids=contract_test_ids,
            )
            for kind, module_name, contract_test_ids in self._registration_snapshots
        )

    @property
    def kinds(self) -> tuple[BuiltinObserverKind, ...]:
        """Return the registered closed observer categories."""
        return tuple(kind for kind, _module, _tests in self._registration_snapshots)

    def registration(self, kind: BuiltinObserverKind) -> ObserverContractRegistration:
        """Return one static category registration."""
        if type(kind) is not BuiltinObserverKind:
            message = "observer kind must be BuiltinObserverKind"
            raise TypeError(message)
        module_name, contract_test_ids = self._by_kind[kind]
        return ObserverContractRegistration(
            kind=kind,
            module_name=module_name,
            contract_test_ids=contract_test_ids,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(kinds={self.kinds!r})"


_OBSERVER_CONTRACT_TEST_IDS: Final = (
    "VT-API-004",
    "VT-ASSERT-016",
    "VT-OBS-001",
    "VT-OBS-009",
    "VT-OBS-012",
    "VT-OBS-013",
    "VT-OBS-014",
    "VT-OBS-015",
    "VT-OBS-016",
    "VT-OBS-020",
    "VT-PRIV-009",
    "VT-REL-009",
    "VT-TEST-002",
)
BUILTIN_OBSERVER_REGISTRY: Final = StaticObserverRegistry(
    (
        ObserverContractRegistration(
            kind=BuiltinObserverKind.COMMAND,
            module_name=BUILTIN_OBSERVER_MODULES[BuiltinObserverKind.COMMAND],
            contract_test_ids=_OBSERVER_CONTRACT_TEST_IDS,
        ),
        ObserverContractRegistration(
            kind=BuiltinObserverKind.HTTP,
            module_name=BUILTIN_OBSERVER_MODULES[BuiltinObserverKind.HTTP],
            contract_test_ids=_OBSERVER_CONTRACT_TEST_IDS,
        ),
    )
)


class ObserverProtocolError(ValueError):
    """Classified, content-free observer boundary failure."""

    __slots__ = ("diagnostic",)

    diagnostic: Diagnostic

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.message)

    @classmethod
    def protocol_violation(
        cls,
        code: str,
        message: str,
    ) -> ObserverProtocolError:
        """Create a stable observer-protocol diagnostic."""
        return cls(
            Diagnostic(
                category=ErrorCategory.OBSERVER_PROTOCOL_ERROR,
                code=DiagnosticCode(code),
                message=message,
                retryable=False,
                result_category=ResultCategory.ENVIRONMENT_ERROR,
            )
        )

    @classmethod
    def resource_limit(
        cls,
        *,
        code: str = "OBS_PROTOCOL_MESSAGE_TOO_LARGE",
        message: str = "The observer protocol message exceeds its bounded size limit.",
    ) -> ObserverProtocolError:
        """Create a stable resource-limit diagnostic without input content."""
        return cls(
            Diagnostic(
                category=ErrorCategory.RESOURCE_LIMIT,
                code=DiagnosticCode(code),
                message=message,
                retryable=False,
                result_category=ResultCategory.ENVIRONMENT_ERROR,
            )
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"category={self.diagnostic.category.value!r}, "
            f"code={str(self.diagnostic.code)!r})"
        )


class ObserverRegistryError(ValueError):
    """Safe deterministic failure for incomplete static contract coverage."""

    __slots__ = ("code",)

    code: str

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


RESPONSE_TO_RECORD_STATUS: Final[Mapping[ObserverResponseStatus, ObservationStatus]] = (
    MappingProxyType(
        {
            ObserverResponseStatus.OK: ObservationStatus.OK,
            ObserverResponseStatus.PENDING: ObservationStatus.PENDING,
            ObserverResponseStatus.UNSUPPORTED: ObservationStatus.UNSUPPORTED,
            ObserverResponseStatus.ERROR: ObservationStatus.ERROR,
        }
    )
)


def http_route_for(operation: ObserverOperation) -> ObserverHttpRoute:
    """Return the fixed POST route for a validated operation."""
    if type(operation) is not ObserverOperation:
        message = "operation must be an ObserverOperation"
        raise TypeError(message)
    return OBSERVER_HTTP_ROUTES[operation]


def map_response_status(status: ObserverResponseStatus) -> ObservationStatus:
    """Map one wire status to its persisted sample status deterministically."""
    if type(status) is not ObserverResponseStatus:
        message = "status must be an ObserverResponseStatus"
        raise TypeError(message)
    return RESPONSE_TO_RECORD_STATUS[status]


def negotiate_capabilities(
    capabilities: ObserverCapabilities,
    queries: tuple[ObserverQuery, ...],
    *,
    requires_stable_snapshot: bool = False,
) -> CapabilityNegotiation:
    """Compare requested fields/types before any observer polling begins."""
    if type(capabilities) is not ObserverCapabilities:
        message = "capabilities must be ObserverCapabilities"
        raise TypeError(message)
    if type(queries) is not tuple:
        message = "queries must be a tuple"
        raise TypeError(message)
    if type(requires_stable_snapshot) is not bool:
        message = "requires_stable_snapshot must be a bool"
        raise TypeError(message)
    supported_keys = set(capabilities.evidence_keys)
    supported_types = set(capabilities.evidence_types)
    missing_keys: list[str] = []
    missing_types: list[EvidenceValueType] = []
    for query in queries:
        if type(query) is not ObserverQuery:
            message = "queries must contain ObserverQuery values"
            raise TypeError(message)
        if query.key not in supported_keys and query.key not in missing_keys:
            missing_keys.append(query.key)
        if query.type not in supported_types and query.type not in missing_types:
            missing_types.append(query.type)
    return CapabilityNegotiation(
        missing_evidence_keys=tuple(missing_keys),
        unsupported_evidence_types=tuple(missing_types),
        query_limit_exceeded=len(queries) > capabilities.max_queries,
        stable_snapshot_unavailable=(
            requires_stable_snapshot and not capabilities.stable_snapshot_ids
        ),
    )


def automatic_polling_allowed(
    capabilities: ObserverCapabilities,
    negotiation: CapabilityNegotiation,
) -> bool:
    """Return whether supported pending evidence may be polled automatically."""
    if type(capabilities) is not ObserverCapabilities:
        message = "capabilities must be ObserverCapabilities"
        raise TypeError(message)
    if type(negotiation) is not CapabilityNegotiation:
        message = "negotiation must be CapabilityNegotiation"
        raise TypeError(message)
    return (
        negotiation.supported
        and capabilities.automatic_reinvocation_safe
        and capabilities.supports_pending
    )


def resume_reconciliation_allowed(capabilities: ObserverCapabilities) -> bool:
    """Return whether recovery may safely compare stable observer snapshots."""
    if type(capabilities) is not ObserverCapabilities:
        message = "capabilities must be ObserverCapabilities"
        raise TypeError(message)
    return capabilities.automatic_reinvocation_safe and capabilities.stable_snapshot_ids


def automatic_retry_allowed(
    capabilities: ObserverCapabilities,
    response: ObserverResponse,
) -> bool:
    """Apply read-only, idempotent, and observer retryable facts conjunctively."""
    if type(capabilities) is not ObserverCapabilities:
        message = "capabilities must be ObserverCapabilities"
        raise TypeError(message)
    if type(response) is not ObserverResponse:
        message = "response must be ObserverResponse"
        raise TypeError(message)
    return (
        capabilities.automatic_reinvocation_safe
        and response.status is ObserverResponseStatus.ERROR
        and response.error is not None
        and response.error.retryable
    )


def map_unsupported_policy(policy: UnsupportedPolicy) -> UnsupportedMapping:
    """Return unsupported/skip facts without reducing a process exit code."""
    if type(policy) is not UnsupportedPolicy:
        message = "policy must be UnsupportedPolicy"
        raise TypeError(message)
    disposition = (
        AssertionUnsupportedDisposition.SKIPPED
        if policy is UnsupportedPolicy.SKIP
        else AssertionUnsupportedDisposition.UNSUPPORTED
    )
    return UnsupportedMapping(
        policy=policy,
        observation_status=ObserverResponseStatus.UNSUPPORTED,
        assertion_disposition=disposition,
        error_category=ErrorCategory.UNSUPPORTED_CAPABILITY,
        result_category=ResultCategory.UNSUPPORTED,
        polling_allowed=False,
    )


def retry_observe_request(
    request: ObserverRequest,
    fresh_sample_id: str,
) -> ObserverRequest:
    """Preserve logical request identity while replacing invocation identity."""
    if type(request) is not ObserverRequest:
        message = "request must be an ObserverRequest"
        raise TypeError(message)
    if request.operation is not ObserverOperation.OBSERVE or request.sample_id is None:
        message = "only observe requests can be retried"
        raise ValueError(message)
    sample_id = _sample_id(fresh_sample_id)
    if sample_id == request.sample_id:
        message = "an observe retry requires a fresh sample_id"
        raise ValueError(message)
    projection = request.model_dump(mode="python")
    projection["sample_id"] = sample_id
    return ObserverRequest.model_validate(projection)


def validate_response_for_request(
    request: ObserverRequest,
    response: ObserverResponse,
) -> ObserverResponse:
    """Validate correlation, negotiation, and requested-only evidence."""
    if type(request) is not ObserverRequest:
        message = "request must be an ObserverRequest"
        raise TypeError(message)
    if type(response) is not ObserverResponse:
        message = "response must be an ObserverResponse"
        raise TypeError(message)
    if response.request_id != request.request_id:
        raise ObserverProtocolError.protocol_violation(
            "OBS_RESPONSE_REQUEST_ID_MISMATCH",
            "The observer response request ID does not match the request.",
        )
    if request.operation is ObserverOperation.CAPABILITIES:
        if response.status is not ObserverResponseStatus.OK or response.evidence:
            raise ObserverProtocolError.protocol_violation(
                "OBS_CAPABILITIES_RESPONSE_INVALID",
                "A capability operation must return an ok response without evidence.",
            )
        return response

    negotiation = negotiate_capabilities(
        response.capabilities,
        request.queries,
        requires_stable_snapshot=request.prior_snapshot_id is not None,
    )
    if not negotiation.supported and response.status is not ObserverResponseStatus.UNSUPPORTED:
        raise ObserverProtocolError.protocol_violation(
            "OBS_CAPABILITY_MISMATCH",
            "The observer response conflicts with its declared capabilities.",
        )
    if (
        response.status is ObserverResponseStatus.PENDING
        and not response.capabilities.supports_pending
    ):
        raise ObserverProtocolError.protocol_violation(
            "OBS_PENDING_NOT_DECLARED",
            "The observer returned pending without declaring pending support.",
        )
    if response.status is not ObserverResponseStatus.OK:
        return response

    requested = {query.key: query.type for query in request.queries}
    actual = {item.key: item.value_type for item in response.evidence}
    if set(actual) - set(requested):
        raise ObserverProtocolError.protocol_violation(
            "OBS_UNREQUESTED_EVIDENCE",
            "The observer returned evidence that was not requested.",
        )
    if set(requested) - set(actual):
        raise ObserverProtocolError.protocol_violation(
            "OBS_EVIDENCE_MISSING",
            "The observer omitted requested evidence from an ok response.",
        )
    if any(actual[key] is not expected for key, expected in requested.items()):
        raise ObserverProtocolError.protocol_violation(
            "OBS_EVIDENCE_TYPE_MISMATCH",
            "The observer returned evidence with a different declared type.",
        )
    return response


def canonical_observer_wire_bytes(model: ProtocolModel) -> bytes:
    """Serialize one validated protocol model to deterministic canonical JSON."""
    if not isinstance(model, ProtocolModel):  # pyright: ignore[reportUnnecessaryIsInstance]
        message = "observer wire value must be a protocol model"
        raise TypeError(message)
    projection = cast("CanonicalJson", model.wire_dict())
    encoded = canonical_json_bytes(projection)
    if len(encoded) > MAX_OBSERVER_MESSAGE_BYTES:
        raise ObserverProtocolError.resource_limit()
    return encoded


def parse_observer_request(data: bytes) -> ObserverRequest:
    """Parse one bounded request without exposing invalid input in diagnostics."""
    return _parse_protocol_model(
        data,
        ObserverRequest,
        code="OBS_PROTOCOL_INVALID_REQUEST",
        message="The observer request is not a valid protocol 1.0 message.",
    )


def parse_observer_response(data: bytes) -> ObserverResponse:
    """Parse one bounded response without exposing invalid input in diagnostics."""
    return _parse_protocol_model(
        data,
        ObserverResponse,
        code="OBS_PROTOCOL_INVALID_RESPONSE",
        message="The observer response is not a valid protocol 1.0 message.",
    )


def parse_observer_evidence(data: bytes) -> ObserverEvidence:
    """Parse one bounded evidence value without exposing its content."""
    return _parse_protocol_model(
        data,
        ObserverEvidence,
        code="OBS_PROTOCOL_INVALID_EVIDENCE",
        message="The observer evidence value is invalid.",
    )


def parse_observation_record(data: bytes) -> ObservationRecord:
    """Parse one bounded persisted observation record."""
    return _parse_protocol_model(
        data,
        ObservationRecord,
        code="OBS_PROTOCOL_INVALID_RECORD",
        message="The observation record is invalid.",
    )


def _importable_module_stem(file_name: str) -> str | None:
    for suffix in _IMPORTABLE_OBSERVER_FILE_SUFFIXES:
        if not file_name.endswith(suffix):
            continue
        stem = file_name[: -len(suffix)]
        return stem if stem.isidentifier() else None
    return None


def discover_builtin_observer_modules(
    package_directory: Path | None = None,
    *,
    package_module: str = _OBSERVER_PACKAGE_MODULE,
) -> tuple[str, ...]:
    """Recursively inventory every importable package artifact without importing it."""
    directory = Path(__file__).resolve().parent if package_directory is None else package_directory
    if type(package_module) is not str:
        message = "package_module must be a string"
        raise TypeError(message)
    normalized_package = _validate_bounded_text(
        package_module,
        field_name="observer package module",
        maximum=MAX_JSON_STRING_LENGTH,
        allow_empty=False,
    )
    if any(not part.isidentifier() for part in normalized_package.split(".")):
        message = "observer package module must be a dotted Python identifier"
        raise ValueError(message)
    modules: list[str] = []
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        module_stem = _importable_module_stem(path.name)
        if module_stem is None:
            continue
        relative_parent = path.relative_to(directory).parent
        parent_parts = () if relative_parent == Path() else relative_parent.parts
        module_parts = parent_parts if module_stem == "__init__" else (*parent_parts, module_stem)
        module_name = ".".join((normalized_package, *module_parts))
        if module_name == f"{normalized_package}.protocol":
            continue
        modules.append(module_name)
    return tuple(sorted(modules))


def discover_builtin_observer_implementations() -> tuple[type[Observer], ...]:
    """Inventory loaded nominal built-in implementations deterministically."""
    pending: list[type[Observer]] = list(Observer.__subclasses__())
    seen: set[type[Observer]] = set()
    implementations: list[type[Observer]] = []
    while pending:
        implementation = pending.pop()
        if implementation in seen:
            continue
        seen.add(implementation)
        pending.extend(implementation.__subclasses__())
        if implementation.__module__.startswith(_OBSERVER_PACKAGE_PREFIX):
            implementations.append(implementation)
    return tuple(
        sorted(
            implementations,
            key=lambda implementation: (
                implementation.__module__,
                implementation.__qualname__,
            ),
        )
    )


def validate_builtin_registry_completeness(
    registry: StaticObserverRegistry,
    *,
    implementation_types: tuple[type[Observer], ...] | None = None,
    present_modules: tuple[str, ...] | None = None,
) -> None:
    """Prove closed categories, package modules, implementations, and tests agree."""
    if type(registry) is not StaticObserverRegistry:
        message = "registry must be a StaticObserverRegistry"
        raise TypeError(message)
    required_contract = dict(_REQUIRED_BUILTIN_OBSERVER_CONTRACT)
    enum_values = {kind.value for kind in BuiltinObserverKind}
    if enum_values != set(required_contract):
        raise ObserverRegistryError(
            "OBS_BUILTIN_REGISTRY_INCOMPLETE",
            "The built-in observer enum differs from the frozen v0.1 category contract.",
        )
    mapped_contract = {
        kind.value: module_name for kind, module_name in BUILTIN_OBSERVER_MODULES.items()
    }
    if mapped_contract != required_contract:
        raise ObserverRegistryError(
            "OBS_BUILTIN_REGISTRY_INCOMPLETE",
            "The built-in observer module map differs from the frozen v0.1 contract.",
        )
    registrations = registry.registrations
    registered_contract = {
        registration.kind.value: registration.module_name for registration in registrations
    }
    if registered_contract != required_contract or len(registrations) != len(required_contract):
        raise ObserverRegistryError(
            "OBS_BUILTIN_REGISTRY_INCOMPLETE",
            "The static observer registry differs from the frozen v0.1 contract.",
        )
    if any(
        registration.contract_test_ids != _OBSERVER_CONTRACT_TEST_IDS
        for registration in registrations
    ):
        raise ObserverRegistryError(
            "OBS_BUILTIN_REGISTRY_INCOMPLETE",
            "Each built-in observer must carry the complete shared contract suite.",
        )
    modules = discover_builtin_observer_modules() if present_modules is None else present_modules
    implementations = (
        discover_builtin_observer_implementations()
        if implementation_types is None
        else implementation_types
    )
    if type(modules) is not tuple:
        message = "present_modules must be a tuple"
        raise TypeError(message)
    if type(implementations) is not tuple:
        message = "implementation_types must be a tuple"
        raise TypeError(message)
    _require_unique(modules, field_name="present observer modules")

    kind_by_module = {registration.module_name: registration.kind for registration in registrations}
    for module_name in modules:
        if type(module_name) is not str:
            message = "present observer module names must be strings"
            raise TypeError(message)
        if module_name not in kind_by_module:
            raise ObserverRegistryError(
                "OBS_BUILTIN_MODULE_UNDECLARED",
                "An observer package module is absent from the closed registry.",
            )

    implementations_by_module: dict[str, list[type[Observer]]] = {}
    for implementation in implementations:
        if not isinstance(implementation, type):  # pyright: ignore[reportUnnecessaryIsInstance]
            message = "implementation_types entries must be classes"
            raise TypeError(message)
        if Observer not in implementation.__mro__:
            message = "built-in observer implementations must inherit Observer"
            raise TypeError(message)
        module_name = implementation.__module__
        kind = implementation.BUILTIN_KIND
        if type(kind) is not BuiltinObserverKind:
            raise ObserverRegistryError(
                "OBS_BUILTIN_CATEGORY_UNDECLARED",
                "A built-in observer implementation has no closed category.",
            )
        if module_name != BUILTIN_OBSERVER_MODULES[kind]:
            raise ObserverRegistryError(
                "OBS_BUILTIN_MODULE_CONFLICT",
                "A built-in observer implementation is outside its category module.",
            )
        if module_name not in modules:
            raise ObserverRegistryError(
                "OBS_BUILTIN_REGISTRY_INCOMPLETE",
                "A loaded observer implementation has no present package module.",
            )
        implementations_by_module.setdefault(module_name, []).append(implementation)

    for module_name in modules:
        module_implementations = implementations_by_module.get(module_name, [])
        if len(module_implementations) != 1:
            raise ObserverRegistryError(
                "OBS_BUILTIN_REGISTRY_INCOMPLETE",
                "Each present observer module must expose exactly one registered implementation.",
            )


def _parse_protocol_model[T: ProtocolModel](
    data: bytes,
    model_type: type[T],
    *,
    code: str,
    message: str,
) -> T:
    try:
        document = _load_bounded_json_object(data)
        return model_type.model_validate(document)
    except ObserverProtocolError:
        raise
    except (TypeError, ValueError, ValidationError):
        raise ObserverProtocolError.protocol_violation(code, message) from None


def _load_bounded_json_object(data: bytes) -> dict[str, object]:
    if type(data) is not bytes:
        message = "observer protocol input must be immutable bytes"
        raise TypeError(message)
    if len(data) > MAX_OBSERVER_MESSAGE_BYTES:
        raise ObserverProtocolError.resource_limit()
    try:
        text = data.decode("utf-8")
        document: object = json.loads(
            text,
            parse_float=_reject_json_float,
            parse_int=_parse_json_integer,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
    except RecursionError:
        raise ObserverProtocolError.resource_limit(
            code="OBS_PROTOCOL_JSON_DEPTH_LIMIT",
            message="The observer protocol message exceeds its JSON nesting-depth limit.",
        ) from None
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        raise ObserverProtocolError.protocol_violation(
            "OBS_PROTOCOL_INVALID_JSON",
            "The observer protocol message is not one bounded UTF-8 JSON object.",
        ) from None
    if type(document) is not dict:
        raise ObserverProtocolError.protocol_violation(
            "OBS_PROTOCOL_INVALID_JSON",
            "The observer protocol message is not one bounded UTF-8 JSON object.",
        )
    typed_document = cast("dict[str, object]", document)
    try:
        _freeze_json(typed_document)
    except _ObserverJsonResourceLimitError as error:
        raise ObserverProtocolError.resource_limit(
            code=error.code,
            message=error.safe_message,
        ) from None
    except (TypeError, ValueError):
        raise ObserverProtocolError.protocol_violation(
            "OBS_PROTOCOL_INVALID_JSON",
            "The observer protocol message is not one bounded UTF-8 JSON object.",
        ) from None
    return typed_document


def _reject_json_float(_value: str) -> Never:
    message = "observer protocol JSON does not permit floating-point values"
    raise ValueError(message)


def _reject_json_constant(_value: str) -> Never:
    message = "observer protocol JSON does not permit non-finite values"
    raise ValueError(message)


def _parse_json_integer(value: str) -> int:
    integer = int(value)
    if not MIN_IJSON_INTEGER <= integer <= MAX_IJSON_INTEGER:
        message = "observer protocol integer exceeds the I-JSON-safe range"
        raise ValueError(message)
    return integer


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = "observer protocol JSON contains a duplicate object key"
            raise ValueError(message)
        result[key] = value
    return result


def _freeze_json(value: object) -> FrozenJsonValue:
    nodes = [0]
    return _freeze_json_node(
        value,
        depth=1,
        nodes=nodes,
        active_containers=set(),
    )


def _freeze_json_node(
    value: object,
    *,
    depth: int,
    nodes: list[int],
    active_containers: set[int],
) -> FrozenJsonValue:
    nodes[0] += 1
    if nodes[0] > MAX_JSON_NODES:
        raise _ObserverJsonResourceLimitError(
            "OBS_PROTOCOL_JSON_NODE_LIMIT",
            "The observer protocol message exceeds its JSON node limit.",
        )
    if depth > MAX_JSON_DEPTH:
        raise _ObserverJsonResourceLimitError(
            "OBS_PROTOCOL_JSON_DEPTH_LIMIT",
            "The observer protocol message exceeds its JSON nesting-depth limit.",
        )
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not MIN_IJSON_INTEGER <= value <= MAX_IJSON_INTEGER:
            message = "observer JSON integer exceeds the I-JSON-safe range"
            raise ValueError(message)
        return value
    if type(value) is float:
        message = "observer JSON does not permit floating-point values"
        raise TypeError(message)
    if type(value) is str:
        if len(value) > MAX_JSON_STRING_LENGTH:
            raise _ObserverJsonResourceLimitError(
                "OBS_PROTOCOL_JSON_STRING_LIMIT",
                "The observer protocol message exceeds its JSON string-length limit.",
            )
        return _validate_bounded_text(
            value,
            field_name="observer JSON string",
            maximum=MAX_JSON_STRING_LENGTH,
            allow_empty=True,
        )
    if type(value) in {list, tuple}:
        sequence = cast("list[object] | tuple[object, ...]", value)
        if len(sequence) > MAX_JSON_ARRAY_ITEMS:
            raise _ObserverJsonResourceLimitError(
                "OBS_PROTOCOL_JSON_ARRAY_LIMIT",
                "The observer protocol message exceeds its JSON array-item limit.",
            )
        marker = id(sequence)
        if marker in active_containers:
            message = "observer JSON must not contain reference cycles"
            raise ValueError(message)
        active_containers.add(marker)
        try:
            return tuple(
                _freeze_json_node(
                    item,
                    depth=depth + 1,
                    nodes=nodes,
                    active_containers=active_containers,
                )
                for item in sequence
            )
        finally:
            active_containers.remove(marker)
    if type(value) is dict or type(value) is FrozenJsonObject:
        mapping = cast("Mapping[object, object]", value)
        if len(mapping) > MAX_JSON_OBJECT_PROPERTIES:
            raise _ObserverJsonResourceLimitError(
                "OBS_PROTOCOL_JSON_OBJECT_LIMIT",
                "The observer protocol message exceeds its JSON object-property limit.",
            )
        marker = id(mapping)
        if marker in active_containers:
            message = "observer JSON must not contain reference cycles"
            raise ValueError(message)
        active_containers.add(marker)
        frozen_items: list[tuple[str, object]] = []
        try:
            for key, item in mapping.items():
                if type(key) is not str:
                    message = "observer JSON object keys must be strings"
                    raise TypeError(message)
                if len(key) > MAX_JSON_OBJECT_KEY_LENGTH:
                    raise _ObserverJsonResourceLimitError(
                        "OBS_PROTOCOL_JSON_KEY_LIMIT",
                        "The observer protocol message exceeds its JSON key-length limit.",
                    )
                normalized_key = _validate_bounded_text(
                    key,
                    field_name="observer JSON object key",
                    maximum=MAX_JSON_OBJECT_KEY_LENGTH,
                    allow_empty=False,
                )
                frozen_items.append(
                    (
                        normalized_key,
                        _freeze_json_node(
                            item,
                            depth=depth + 1,
                            nodes=nodes,
                            active_containers=active_containers,
                        ),
                    )
                )
        finally:
            active_containers.remove(marker)
        return FrozenJsonObject(tuple(frozen_items))
    message = "observer values must contain only JSON-compatible types"
    raise TypeError(message)


def _thaw_json(value: FrozenJsonValue) -> object:
    if type(value) is tuple:
        return [_thaw_json(cast("FrozenJsonValue", item)) for item in value]
    if type(value) is FrozenJsonObject:
        return {key: _thaw_json(cast("FrozenJsonValue", item)) for key, item in value.items()}
    return value


def _matches_evidence_type(
    value_type: EvidenceValueType,
    value: object | None,
) -> bool:
    match value_type:
        case EvidenceValueType.NULL:
            return value is None
        case EvidenceValueType.BOOLEAN:
            return type(value) is bool
        case EvidenceValueType.INTEGER:
            return type(value) is int and MIN_IJSON_INTEGER <= value <= MAX_IJSON_INTEGER
        case EvidenceValueType.DECIMAL_STRING:
            return (
                type(value) is str
                and len(value) <= MAX_DECIMAL_STRING_LENGTH
                and _DECIMAL_STRING.fullmatch(value) is not None
            )
        case EvidenceValueType.STRING:
            return type(value) is str
        case EvidenceValueType.BYTES_DIGEST:
            return type(value) is BytesDigestMetadata
        case EvidenceValueType.TIMESTAMP:
            if type(value) is not str:
                return False
            try:
                _validate_utc_timestamp(value)
            except (TypeError, ValueError):
                return False
            return True
        case EvidenceValueType.ARRAY:
            return type(value) is tuple
        case EvidenceValueType.OBJECT:
            return type(value) is FrozenJsonObject


def _validate_utc_timestamp(value: str) -> str:
    if type(value) is not str:
        message = "timestamp must be a string"
        raise TypeError(message)
    match = _UTC_TIMESTAMP.fullmatch(value)
    if match is None:
        message = "timestamp must be a UTC RFC 3339 value ending in Z"
        raise ValueError(message)
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
    except ValueError as error:
        message = "timestamp must contain a valid UTC date and time"
        raise ValueError(message) from error
    return value


def _validate_snapshot_id(value: str) -> str:
    return _validate_bounded_text(
        value,
        field_name="snapshot_id",
        maximum=MAX_SNAPSHOT_ID_LENGTH,
        allow_empty=False,
    )


def _validate_bounded_text(
    value: str,
    *,
    field_name: str,
    maximum: int,
    allow_empty: bool,
) -> str:
    if type(value) is not str:
        message = f"{field_name} must be a string"
        raise TypeError(message)
    if (not allow_empty and not value) or len(value) > maximum:
        message = f"{field_name} exceeds its bounded length contract"
        raise ValueError(message)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        message = f"{field_name} must contain Unicode scalar values"
        raise ValueError(message) from None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        message = f"{field_name} must not contain control characters"
        raise ValueError(message)
    return value


def _tuple_from_wire(value: object) -> object:
    if type(value) is list:
        return tuple(cast("list[object]", value))
    return value


def _require_unique[T](values: tuple[T, ...], *, field_name: str) -> None:
    try:
        unique_count = len(set(values))
    except TypeError:
        unique_count = len({repr(value) for value in values})
    if unique_count != len(values):
        message = f"{field_name} must be unique"
        raise ValueError(message)
