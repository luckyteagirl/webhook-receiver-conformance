"""Strict immutable Stage A project-configuration value models."""
# ruff: noqa: ANN401, C901, D101, D102, D105, D107, INP001, PLR0912, PLR0915

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from enum import StrEnum
from fractions import Fraction
from typing import Annotated, Any, ClassVar, Literal, Self, cast
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    GetCoreSchemaHandler,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_core import CoreSchema, core_schema

MAX_SAFE_INTEGER = (2**53) - 1
MAX_DURATION_NANOSECONDS = (2**63) - 1
MINIMUM_POLL_NANOSECONDS = 10_000_000
MAX_CANONICAL_STRING_LENGTH = 4096
MAX_CANONICAL_COLLECTION_ITEMS = 1000
MAX_CANONICAL_OBJECT_KEY_LENGTH = 256
MAX_CANONICAL_DEPTH = 64
MAX_CANONICAL_NODES = 100_000
MAX_PATH_LENGTH = 4096
MAX_HEADER_NAME_LENGTH = 128
MAX_SECRET_ROOTS = 16
MAX_ALLOWED_HOSTS = 64
MAX_ARGV_ITEMS = 64
MAX_ENVIRONMENT_NAMES = 64
MAX_HTTP_PORT = 65_535
CONTROL_CHARACTER_LIMIT = 32
DELETE_CHARACTER_CODEPOINT = 127
MINIMUM_SCALE = Fraction(1, 1000)
MAXIMUM_SCALE = Fraction(100)

_DURATION = re.compile(r"(0|[1-9][0-9]*)(ns|us|ms|s|m|h)")
_SCALE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
_PROJECT_RELATIVE_PATH = re.compile(
    r"^(?![A-Za-z][A-Za-z0-9+.-]*:)"
    r"(?![\\/])"
    r"(?!\.\.(?:[\\/]|$))"
    r"(?!.*[\\/]\.\.(?:[\\/]|$))"
    r"(?!.*[\u0000-\u001F\u007F]).+$"
)
_JSON_POINTER = re.compile(r"(?:/(?:[^~/]|~0|~1)*)*")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_CHALLENGE_PATH = re.compile(r"/[^\r\n]*")
_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_PROFILE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_FORBIDDEN_HEADER_NAMES = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-authorization",
    }
)
_DURATION_MULTIPLIERS: Mapping[str, int] = {
    "ns": 1,
    "us": 1_000,
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60_000_000_000,
    "h": 3_600_000_000_000,
}


def _sequence_to_tuple(value: object) -> object:
    if isinstance(value, list):
        return tuple(cast("list[object]", value))
    if isinstance(value, tuple):
        sequence = cast("tuple[object, ...]", value)
        if sequence:
            msg = "configuration arrays must be provided as lists"
            raise ValueError(msg)
        return sequence
    return value


type FrozenSequence[T] = Annotated[tuple[T, ...], BeforeValidator(_sequence_to_tuple)]


class FrozenDict[T](Mapping[str, T]):
    """Small immutable mapping used for deeply frozen configuration values."""

    __items: tuple[tuple[str, T], ...]
    __slots__ = ("__items",)

    def __init__(self, values: Mapping[str, T] | Iterator[tuple[str, T]]) -> None:
        items = values.items() if isinstance(values, Mapping) else values
        object.__setattr__(self, "_FrozenDict__items", tuple(items))

    def __setattr__(self, _name: str, _value: object) -> None:
        msg = "FrozenDict is immutable"
        raise AttributeError(msg)

    def __delattr__(self, _name: str) -> None:
        msg = "FrozenDict is immutable"
        raise AttributeError(msg)

    def __getitem__(self, key: str) -> T:
        for candidate, value in self.__items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _value in self.__items)

    def __len__(self) -> int:
        return len(self.__items)

    def __repr__(self) -> str:
        return f"FrozenDict({dict(self.__items)!r})"

    def __hash__(self) -> int:
        return hash(frozenset(self.__items))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            other_mapping = cast("Mapping[object, object]", other)
            return dict(self.__items) == dict(other_mapping.items())
        return NotImplemented


type FrozenJsonScalar = bool | int | str | None
type FrozenJsonValue = (
    FrozenJsonScalar | tuple["FrozenJsonValue", ...] | FrozenDict["FrozenJsonValue"]
)


def freeze_canonical_json(value: object) -> FrozenJsonValue:
    """Validate and deeply freeze the bounded integer-only canonical JSON profile."""
    stack: list[tuple[object, int, bool]] = [(value, 1, isinstance(value, FrozenDict))]
    nodes = 0
    while stack:
        current, depth, internal = stack.pop()
        nodes += 1
        if nodes > MAX_CANONICAL_NODES:
            msg = "canonical JSON exceeds the node limit"
            raise ValueError(msg)
        if depth > MAX_CANONICAL_DEPTH:
            msg = "canonical JSON exceeds the depth limit"
            raise ValueError(msg)
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, int):
            if not -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER:
                msg = "canonical JSON integer is outside the safe range"
                raise ValueError(msg)
            continue
        if isinstance(current, str):
            if len(current) > MAX_CANONICAL_STRING_LENGTH:
                msg = "canonical JSON string exceeds the length limit"
                raise ValueError(msg)
            continue
        if isinstance(current, list):
            sequence = cast("Sequence[object]", current)
            if len(sequence) > MAX_CANONICAL_COLLECTION_ITEMS:
                msg = "canonical JSON array exceeds the item limit"
                raise ValueError(msg)
            stack.extend((item, depth + 1, False) for item in reversed(sequence))
            continue
        if isinstance(current, tuple):
            sequence = cast("tuple[object, ...]", current)
            if sequence and not internal:
                msg = "canonical JSON arrays must be provided as lists"
                raise TypeError(msg)
            stack.extend((item, depth + 1, True) for item in reversed(sequence))
            continue
        if isinstance(current, (dict, FrozenDict)):
            mapping = cast("Mapping[object, object]", current)
            if len(mapping) > MAX_CANONICAL_COLLECTION_ITEMS:
                msg = "canonical JSON object exceeds the property limit"
                raise ValueError(msg)
            for key, item in reversed(tuple(mapping.items())):
                if not isinstance(key, str):
                    msg = "canonical JSON object keys must be strings"
                    raise TypeError(msg)
                if len(key) > MAX_CANONICAL_OBJECT_KEY_LENGTH:
                    msg = "canonical JSON object key exceeds the length limit"
                    raise ValueError(msg)
                stack.append((item, depth + 1, isinstance(current, FrozenDict)))
            continue
        if isinstance(current, Mapping):
            msg = "canonical JSON objects must be provided as dictionaries"
            raise TypeError(msg)
        msg = "canonical JSON permits only null, booleans, integers, strings, arrays, and objects"
        raise TypeError(msg)

    return _freeze_validated_json(value)


def _freeze_validated_json(value: object) -> FrozenJsonValue:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, list):
        sequence = cast("Sequence[object]", value)
        return tuple(_freeze_validated_json(item) for item in sequence)
    if isinstance(value, tuple):
        sequence = cast("tuple[object, ...]", value)
        return tuple(_freeze_validated_json(item) for item in sequence)
    if isinstance(value, (dict, FrozenDict)):
        mapping = cast("Mapping[object, object]", value)
        return FrozenDict(
            (cast("str", key), _freeze_validated_json(item)) for key, item in mapping.items()
        )
    msg = "canonical JSON was not validated"
    raise AssertionError(msg)


def thaw_canonical_json(value: FrozenJsonValue) -> object:
    """Return an ordinary detached JSON-compatible representation."""
    if isinstance(value, tuple):
        return [thaw_canonical_json(item) for item in value]
    if isinstance(value, FrozenDict):
        return {key: thaw_canonical_json(item) for key, item in value.items()}
    return value


class CanonicalJsonValue:
    """Pydantic wire type for a deeply immutable canonical JSON value."""

    __value: FrozenJsonValue
    __slots__ = ("__value",)

    def __init__(self, value: object) -> None:
        object.__setattr__(self, "_CanonicalJsonValue__value", freeze_canonical_json(value))

    def __setattr__(self, _name: str, _value: object) -> None:
        msg = "CanonicalJsonValue is immutable"
        raise AttributeError(msg)

    def __delattr__(self, _name: str) -> None:
        msg = "CanonicalJsonValue is immutable"
        raise AttributeError(msg)

    @property
    def value(self) -> FrozenJsonValue:
        return self.__value

    def to_wire(self) -> object:
        return thaw_canonical_json(self.__value)

    def __repr__(self) -> str:
        return f"CanonicalJsonValue({self.__value!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CanonicalJsonValue):
            return self.__value == other.__value
        return False

    def __hash__(self) -> int:
        return hash(self.__value)

    @classmethod
    def _validate(cls, value: object) -> CanonicalJsonValue:
        if isinstance(value, cls):
            return value
        return cls(value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda value: value.to_wire(),
                return_schema=core_schema.any_schema(),
            ),
        )


class Duration(str):
    """Exact non-negative duration wire string with signed-int64 nanoseconds."""

    _minimum_nanoseconds: ClassVar[int] = 0
    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        match = _DURATION.fullmatch(value)
        if match is None:
            msg = "duration must be a canonical integer with an explicit unit"
            raise ValueError(msg)
        nanoseconds = int(match.group(1)) * _DURATION_MULTIPLIERS[match.group(2)]
        if nanoseconds > MAX_DURATION_NANOSECONDS:
            msg = "duration exceeds signed 64-bit nanoseconds"
            raise ValueError(msg)
        if nanoseconds < cls._minimum_nanoseconds:
            msg = "duration is below the permitted minimum"
            raise ValueError(msg)
        return str.__new__(cls, value)

    @property
    def nanoseconds(self) -> int:
        match = _DURATION.fullmatch(self)
        if match is None:
            msg = "validated duration became invalid"
            raise AssertionError(msg)
        return int(match.group(1)) * _DURATION_MULTIPLIERS[match.group(2)]

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls,
            core_schema.str_schema(strict=True),
            serialization=core_schema.to_string_ser_schema(),
        )


class PositiveDuration(Duration):
    """Exact duration greater than zero."""

    _minimum_nanoseconds = 1


class PollDuration(Duration):
    """Physical polling duration of at least ten milliseconds."""

    _minimum_nanoseconds = MINIMUM_POLL_NANOSECONDS


class Scale(str):
    """Exact decimal clock scale in the inclusive range 0.001 through 100."""

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if _SCALE.fullmatch(value) is None:
            msg = "scale must be a canonical decimal string"
            raise ValueError(msg)
        fraction = Fraction(value)
        if not MINIMUM_SCALE <= fraction <= MAXIMUM_SCALE:
            msg = "scale must be in the inclusive range 0.001 through 100"
            raise ValueError(msg)
        return str.__new__(cls, value)

    @property
    def fraction(self) -> Fraction:
        return Fraction(self)

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls,
            core_schema.str_schema(strict=True),
            serialization=core_schema.to_string_ser_schema(),
        )


class ProjectRelativePath(str):
    """Bounded project-relative path without traversal or control characters."""

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if len(value) > MAX_PATH_LENGTH or _PROJECT_RELATIVE_PATH.fullmatch(value) is None:
            msg = "path must be a bounded project-relative path"
            raise ValueError(msg)
        return str.__new__(cls, value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls,
            core_schema.str_schema(strict=True),
            serialization=core_schema.to_string_ser_schema(),
        )


class JsonPointer(str):
    """Bounded RFC 6901 JSON pointer."""

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if len(value) > MAX_PATH_LENGTH or _JSON_POINTER.fullmatch(value) is None:
            msg = "value must be a bounded RFC 6901 JSON pointer"
            raise ValueError(msg)
        return str.__new__(cls, value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls,
            core_schema.str_schema(strict=True),
            serialization=core_schema.to_string_ser_schema(),
        )


class ConfiguredHeaderName(str):
    """Valid signer header token excluding framing/routing headers."""

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if not 1 <= len(value) <= MAX_HEADER_NAME_LENGTH or _HEADER_NAME.fullmatch(value) is None:
            msg = "configured header name must use HTTP token syntax"
            raise ValueError(msg)
        if value.casefold() in _FORBIDDEN_HEADER_NAMES:
            msg = "configured header name is reserved by the transport"
            raise ValueError(msg)
        return str.__new__(cls, value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls,
            core_schema.str_schema(strict=True),
            serialization=core_schema.to_string_ser_schema(),
        )


BoundedString = Annotated[StrictStr, StringConstraints(max_length=4096)]
NonEmptyString = Annotated[StrictStr, StringConstraints(min_length=1, max_length=4096)]
ProjectName = Annotated[StrictStr, StringConstraints(min_length=1, max_length=128)]
ProfileName = Annotated[StrictStr, StringConstraints(pattern=_PROFILE_NAME.pattern)]
EnvironmentName = Annotated[StrictStr, StringConstraints(pattern=_ENVIRONMENT_NAME.pattern)]
MediaType = Annotated[StrictStr, StringConstraints(min_length=1, max_length=255)]
SafeInteger = Annotated[
    StrictInt,
    Field(ge=-MAX_SAFE_INTEGER, le=MAX_SAFE_INTEGER),
]


class ConfigModel(BaseModel):
    """Strict, closed, immutable base for all configuration objects."""

    explicit_null_fields: ClassVar[frozenset[str]] = frozenset()
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_null(cls, value: object) -> object:
        # Stage B canonical `value: null` models opt in by overriding
        # `explicit_null_fields`; every Stage A model intentionally keeps it empty.
        if isinstance(value, FrozenDict):
            frozen_mapping = cast("FrozenDict[object]", value)
            mapping: Mapping[object, object] = cast(
                "Mapping[object, object]",
                frozen_mapping,
            )
            result: object = dict(frozen_mapping.items())
        elif isinstance(value, dict):
            mapping = cast("dict[object, object]", value)
            result = cast("object", value)
        elif isinstance(value, Mapping):
            msg = "configuration objects must be provided as dictionaries"
            raise ValueError(msg)  # noqa: TRY004
        else:
            return value
        if mapping:
            null_fields = [
                str(key)
                for key, item in mapping.items()
                if item is None and key not in cls.explicit_null_fields
            ]
            if null_fields:
                msg = "configuration fields cannot be null"
                raise ValueError(msg)
        return result

    def to_wire(self) -> dict[str, object]:
        """Return a detached JSON-compatible object with absent optionals omitted."""
        dumped = cast(
            "dict[str, object]",
            self.model_dump(mode="json", exclude_none=False),
        )
        wire: dict[str, object] = {
            key: value
            for key, value in dumped.items()
            if value is not None or key in self.explicit_null_fields
        }
        return wire


def _require_unique[T](values: tuple[T, ...], *, field_name: str) -> tuple[T, ...]:
    if len(values) != len(set(values)):
        msg = f"{field_name} values must be unique"
        raise ValueError(msg)
    return values


class EnvironmentSecretRef(ConfigModel):
    env: EnvironmentName


class FileSecretRef(ConfigModel):
    file: NonEmptyString


class GeneratedSecretRef(ConfigModel):
    generated: Literal["hmac-256"]


type SecretRef = EnvironmentSecretRef | FileSecretRef | GeneratedSecretRef


class ProjectSettings(ConfigModel):
    name: ProjectName
    artifact_directory: NonEmptyString
    seed: Annotated[StrictStr, StringConstraints(min_length=1, max_length=1024)] | None = None
    secret_roots: FrozenSequence[ProjectRelativePath] = ()

    @field_validator("secret_roots")
    @classmethod
    def validate_secret_roots(
        cls,
        value: tuple[ProjectRelativePath, ...],
    ) -> tuple[ProjectRelativePath, ...]:
        if len(value) > MAX_SECRET_ROOTS:
            msg = "secret_roots cannot contain more than 16 paths"
            raise ValueError(msg)
        return _require_unique(value, field_name="secret_roots")


class ReceiverTimeouts(ConfigModel):
    connect: PositiveDuration
    write: PositiveDuration
    read: PositiveDuration
    pool: PositiveDuration
    total: PositiveDuration


class TargetProfile(StrEnum):
    """Closed receiver destination-profile vocabulary."""

    LOOPBACK = "loopback"
    PRIVATE_ALLOWLIST = "private-allowlist"
    PUBLIC_AUTHORIZED = "public-authorized"


def _target_profile_from_wire(value: object) -> object:
    if isinstance(value, str):
        return TargetProfile(value)
    return value


class ReceiverConfig(ConfigModel):
    url: StrictStr
    target_profile: Annotated[TargetProfile, BeforeValidator(_target_profile_from_wire)]
    allowed_hosts: FrozenSequence[Annotated[StrictStr, StringConstraints(min_length=1)]] = ()
    allowed_ports: FrozenSequence[Annotated[StrictInt, Field(ge=1, le=65535)]] = ()
    public_challenge_path: StrictStr = "/.well-known/webhook-conformance-challenge"
    test_ca_file: Annotated[StrictStr, StringConstraints(min_length=1, max_length=4096)] | None = (
        None
    )
    timeouts: ReceiverTimeouts

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        _validate_http_uri(value)
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_ALLOWED_HOSTS:
            msg = "allowed_hosts cannot contain more than 64 values"
            raise ValueError(msg)
        return _require_unique(value, field_name="allowed_hosts")

    @field_validator("allowed_ports")
    @classmethod
    def validate_allowed_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        return _require_unique(value, field_name="allowed_ports")

    @field_validator("public_challenge_path")
    @classmethod
    def validate_public_challenge_path(cls, value: str) -> str:
        if _CHALLENGE_PATH.fullmatch(value) is None:
            msg = "public_challenge_path must be an absolute path without controls"
            raise ValueError(msg)
        return value


class FixtureConfig(ConfigModel):
    id: ProfileName
    path: Annotated[StrictStr, StringConstraints(min_length=1)]
    media_type: MediaType
    event_id_pointer: StrictStr = "/id"
    event_type_pointer: StrictStr = "/type"
    schema_path: StrictStr | None = None


class SignerProfile(StrEnum):
    GENERIC_HMAC_SHA256 = "generic-hmac-sha256"
    STRIPE_V1 = "stripe-v1"
    STANDARD_WEBHOOKS_HMAC = "standard-webhooks-hmac"


class _SignerConfig(ConfigModel):
    secret: SecretRef
    header_name: ConfiguredHeaderName | None = None
    replay_window: PositiveDuration | None = None
    key_id: Annotated[StrictStr, StringConstraints(max_length=128)] | None = None


class GenericHmacSha256SignerConfig(_SignerConfig):
    profile: Literal[SignerProfile.GENERIC_HMAC_SHA256]


class StripeV1SignerConfig(_SignerConfig):
    profile: Literal[SignerProfile.STRIPE_V1]


class StandardWebhooksHmacSignerConfig(_SignerConfig):
    profile: Literal[SignerProfile.STANDARD_WEBHOOKS_HMAC]


type SignerConfig = Annotated[
    GenericHmacSha256SignerConfig | StripeV1SignerConfig | StandardWebhooksHmacSignerConfig,
    Field(discriminator="profile"),
]


class ObserverHttpTimeouts(ConfigModel):
    connect: PositiveDuration
    read: PositiveDuration
    total: PositiveDuration


class CommandObserverConfig(ConfigModel):
    type: Literal["command"]
    argv: FrozenSequence[NonEmptyString]
    timeout: PositiveDuration
    environment_allowlist: FrozenSequence[EnvironmentName] | None = None
    working_directory: NonEmptyString | None = None

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not 1 <= len(value) <= MAX_ARGV_ITEMS:
            msg = "argv must contain between 1 and 64 entries"
            raise ValueError(msg)
        return value

    @field_validator("environment_allowlist")
    @classmethod
    def validate_environment_allowlist(
        cls,
        value: tuple[str, ...] | None,
    ) -> tuple[str, ...] | None:
        if value is None:
            return None
        if len(value) > MAX_ENVIRONMENT_NAMES:
            msg = "environment_allowlist cannot contain more than 64 values"
            raise ValueError(msg)
        return _require_unique(value, field_name="environment_allowlist")


class HttpObserverConfig(ConfigModel):
    type: Literal["http"]
    base_url: Annotated[StrictStr, StringConstraints(max_length=2048)]
    token: SecretRef
    timeouts: ObserverHttpTimeouts

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        _validate_http_uri(value)
        return value


type ObserverConfig = Annotated[
    CommandObserverConfig | HttpObserverConfig,
    Field(discriminator="type"),
]


class LifecycleProfile(ConfigModel):
    enabled: bool = False
    stop_argv: FrozenSequence[NonEmptyString]
    start_argv: FrozenSequence[NonEmptyString]
    restart_argv: FrozenSequence[NonEmptyString]
    working_directory: NonEmptyString
    environment_allowlist: FrozenSequence[EnvironmentName]
    timeout: PositiveDuration
    readiness_observer: ProfileName

    @field_validator("stop_argv", "start_argv", "restart_argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not 1 <= len(value) <= MAX_ARGV_ITEMS:
            msg = "lifecycle argv must contain between 1 and 64 entries"
            raise ValueError(msg)
        return value

    @field_validator("environment_allowlist")
    @classmethod
    def validate_environment_allowlist(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) > MAX_ENVIRONMENT_NAMES:
            msg = "environment_allowlist cannot contain more than 64 values"
            raise ValueError(msg)
        return _require_unique(value, field_name="environment_allowlist")


class RealClockConfig(ConfigModel):
    mode: Literal["real"]
    minimum_physical_wait: Duration | None = None


class ScaledClockConfig(ConfigModel):
    mode: Literal["scaled"]
    scale: Scale
    minimum_physical_wait: Duration | None = None


type ClockConfig = Annotated[
    RealClockConfig | ScaledClockConfig,
    Field(discriminator="mode"),
]


class LimitsConfig(ConfigModel):
    max_events: Annotated[StrictInt, Field(ge=1, le=1000)]
    max_attempts: Annotated[StrictInt, Field(ge=1, le=5000)]
    max_concurrency: Annotated[StrictInt, Field(ge=1, le=50)] = 10
    max_request_bytes: Annotated[StrictInt, Field(ge=1, le=16_777_216)]
    max_response_capture_bytes: Annotated[StrictInt, Field(ge=1, le=1_048_576)]


class RedactionConfig(ConfigModel):
    headers: FrozenSequence[Annotated[StrictStr, StringConstraints(min_length=1)]]
    json_pointers: FrozenSequence[StrictStr]
    retain_raw_payloads: bool

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_unique(value, field_name="headers")

    @field_validator("json_pointers")
    @classmethod
    def validate_json_pointers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_unique(value, field_name="json_pointers")


class ReportFormat(StrEnum):
    """Closed report-format vocabulary."""

    JSON = "json"
    JSONL = "jsonl"
    JUNIT = "junit"
    HTML = "html"


def _report_format_from_wire(value: object) -> object:
    if isinstance(value, str):
        return ReportFormat(value)
    return value


class ReportsConfig(ConfigModel):
    formats: FrozenSequence[Annotated[ReportFormat, BeforeValidator(_report_format_from_wire)]]
    redaction: RedactionConfig

    @field_validator("formats")
    @classmethod
    def validate_formats(
        cls,
        value: tuple[ReportFormat, ...],
    ) -> tuple[ReportFormat, ...]:
        if not value:
            msg = "formats must contain at least one value"
            raise ValueError(msg)
        return _require_unique(value, field_name="formats")


def _validate_http_uri(value: str) -> None:
    if any(
        ord(character) <= CONTROL_CHARACTER_LIMIT or ord(character) == DELETE_CHARACTER_CODEPOINT
        for character in value
    ):
        msg = "HTTP URI cannot contain whitespace or control characters"
        raise ValueError(msg)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        msg = "HTTP URI is invalid"
        raise ValueError(msg) from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.hostname is None:
        msg = "URI must be an absolute HTTP or HTTPS URI"
        raise ValueError(msg)
    if port is not None and not 1 <= port <= MAX_HTTP_PORT:
        msg = "HTTP URI port is outside the valid range"
        raise ValueError(msg)
