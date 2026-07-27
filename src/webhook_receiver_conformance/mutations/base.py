"""Closed, versioned contracts for deterministic request mutations."""
# ruff: noqa: C901, D105, D107, EM101, FBT001, INP001, PLR0912, PLR0913, PLR2004, TRY003

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Protocol, cast, runtime_checkable

from webhook_receiver_conformance.domain.hashing import validate_sha256_digest
from webhook_receiver_conformance.errors import Diagnostic, ErrorCategory, ResultCategory
from webhook_receiver_conformance.scenario.models import MutationStage
from webhook_receiver_conformance.signatures.base import SignatureHeader, Signer
from webhook_receiver_conformance.types import DiagnosticCode, JsonObject, JsonValue

MAX_MUTATIONS_PER_PIPELINE: Final = 16
MAX_MUTATION_REGISTRATIONS: Final = 64
MAX_OPERATOR_ID_LENGTH: Final = 128
MAX_OPERATOR_VERSION: Final = (1 << 31) - 1
MAX_PARAMETER_DEPTH: Final = 64
MAX_PARAMETER_NODES: Final = 100_000
MAX_PARAMETER_COLLECTION_ITEMS: Final = 1_000
MAX_PARAMETER_KEY_LENGTH: Final = 256
MAX_PARAMETER_STRING_LENGTH: Final = 4_096
MAX_MUTATION_HEADERS: Final = 144
MAX_MEDIA_TYPE_LENGTH: Final = 256
MAX_EVENT_ID_BYTES: Final = 4_096
REDACTED_PARAMETER_VALUE: Final = "[REDACTED]"

_OPERATOR_ID = re.compile(r"[a-z][a-z0-9._-]{0,127}")
_MEDIA_TYPE = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(?:[ \t]*;[^\r\n]*)?")

PIPELINE_STAGE_ORDER: Final = (
    MutationStage.STRUCTURAL,
    MutationStage.RAW_PRE_SIGN,
    MutationStage.HEADER_PRE_SIGN,
    MutationStage.SIGNING,
    MutationStage.RAW_POST_SIGN,
    MutationStage.HEADER_POST_SIGN,
)
PIPELINE_STAGE_RANK: Final[Mapping[MutationStage, int]] = MappingProxyType(
    {stage: rank for rank, stage in enumerate(PIPELINE_STAGE_ORDER)}
)


class SignatureHeaderAction(StrEnum):
    """Closed post-sign operations over headers owned by the selected signer."""

    NONE = "none"
    REMOVE = "remove"
    REPLACE = "replace"


type FrozenParameterScalar = bool | int | str | None
type FrozenParameterValue = (
    FrozenParameterScalar | tuple["FrozenParameterValue", ...] | FrozenParameterObject
)


class FrozenParameterObject(Mapping[str, FrozenParameterValue]):
    """Deeply immutable bounded JSON object whose repr never reveals values."""

    __slots__ = ("__items",)

    __items: tuple[tuple[str, FrozenParameterValue], ...]

    def __init__(
        self,
        values: tuple[tuple[str, FrozenParameterValue], ...],
    ) -> None:
        if type(values) is not tuple:
            message = "frozen parameter values must be provided as a tuple"
            raise TypeError(message)
        seen: set[str] = set()
        for item in values:
            if type(item) is not tuple or len(item) != 2:
                message = "frozen parameter items must be key-value tuples"
                raise TypeError(message)
            key, _value = item
            if type(key) is not str:
                message = "frozen parameter keys must be strings"
                raise TypeError(message)
            if not key or len(key) > MAX_PARAMETER_KEY_LENGTH:
                message = "frozen parameter key is empty or too long"
                raise ValueError(message)
            if key in seen:
                message = "frozen parameter keys must be unique"
                raise ValueError(message)
            seen.add(key)
        _validate_frozen_parameter_values(values)
        object.__setattr__(self, "_FrozenParameterObject__items", values)

    def __setattr__(self, _name: str, _value: object) -> None:
        message = "FrozenParameterObject is immutable"
        raise AttributeError(message)

    def __delattr__(self, _name: str) -> None:
        message = "FrozenParameterObject is immutable"
        raise AttributeError(message)

    def __getitem__(self, key: str) -> FrozenParameterValue:
        for candidate, value in self.__items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _value in self.__items)

    def __len__(self) -> int:
        return len(self.__items)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(keys={tuple(self)!r})"


def _validate_frozen_parameter_values(
    root_items: tuple[tuple[str, FrozenParameterValue], ...],
) -> None:
    stack: list[tuple[object, int]] = [(value, 1) for _key, value in reversed(root_items)]
    nodes = 1
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_PARAMETER_NODES:
            message = "frozen mutation parameters exceed the node limit"
            raise ValueError(message)
        if depth > MAX_PARAMETER_DEPTH:
            message = "frozen mutation parameters exceed the depth limit"
            raise ValueError(message)
        if value is None or type(value) is bool:
            continue
        if type(value) is int:
            if not -((1 << 53) - 1) <= value <= (1 << 53) - 1:
                message = "frozen mutation parameter integer is outside the safe range"
                raise ValueError(message)
            continue
        if type(value) is str:
            if len(value) > MAX_PARAMETER_STRING_LENGTH:
                message = "frozen mutation parameter string exceeds the length limit"
                raise ValueError(message)
            continue
        if type(value) is tuple:
            sequence = cast("tuple[object, ...]", value)
            if len(sequence) > MAX_PARAMETER_COLLECTION_ITEMS:
                message = "frozen mutation parameter array exceeds the item limit"
                raise ValueError(message)
            stack.extend((item, depth + 1) for item in reversed(sequence))
            continue
        if type(value) is FrozenParameterObject:
            if len(value) > MAX_PARAMETER_COLLECTION_ITEMS:
                message = "frozen mutation parameter object exceeds the property limit"
                raise ValueError(message)
            stack.extend((item, depth + 1) for item in reversed(tuple(value.values())))
            continue
        message = "frozen mutation parameters must contain only frozen JSON values"
        raise TypeError(message)


def freeze_parameter_object(values: object) -> FrozenParameterObject:
    """Validate, bound, detach, and deeply freeze one realized JSON object."""
    if type(values) is not dict:
        message = "mutation parameters must be provided as a plain JSON object"
        raise TypeError(message)
    nodes = [0]
    mapping = cast("dict[object, object]", values)
    frozen = _freeze_parameter_value(mapping, depth=1, nodes=nodes)
    if type(frozen) is not FrozenParameterObject:
        raise AssertionError("root mutation parameters did not remain an object")
    return frozen


def thaw_parameter_object(values: FrozenParameterObject) -> JsonObject:
    """Return a detached JSON projection suitable for an explicitly safe sink."""
    if type(values) is not FrozenParameterObject:
        message = "safe mutation parameters must be a FrozenParameterObject"
        raise TypeError(message)
    return {key: _thaw_parameter_value(value) for key, value in values.items()}


def _freeze_parameter_value(
    value: object,
    *,
    depth: int,
    nodes: list[int],
) -> FrozenParameterValue:
    nodes[0] += 1
    if nodes[0] > MAX_PARAMETER_NODES:
        message = "mutation parameters exceed the node limit"
        raise ValueError(message)
    if depth > MAX_PARAMETER_DEPTH:
        message = "mutation parameters exceed the depth limit"
        raise ValueError(message)
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not -((1 << 53) - 1) <= value <= (1 << 53) - 1:
            message = "mutation parameter integer is outside the lossless JSON range"
            raise ValueError(message)
        return value
    if type(value) is str:
        if len(value) > MAX_PARAMETER_STRING_LENGTH:
            message = "mutation parameter string exceeds the length limit"
            raise ValueError(message)
        return value
    if type(value) is list:
        sequence = cast("list[object]", value)
        if len(sequence) > MAX_PARAMETER_COLLECTION_ITEMS:
            message = "mutation parameter array exceeds the item limit"
            raise ValueError(message)
        return tuple(
            _freeze_parameter_value(item, depth=depth + 1, nodes=nodes) for item in sequence
        )
    if type(value) is dict:
        mapping = cast("dict[object, object]", value)
        if len(mapping) > MAX_PARAMETER_COLLECTION_ITEMS:
            message = "mutation parameter object exceeds the property limit"
            raise ValueError(message)
        items: list[tuple[str, FrozenParameterValue]] = []
        for key, item in mapping.items():
            if type(key) is not str:
                message = "mutation parameter object keys must be strings"
                raise TypeError(message)
            if not key or len(key) > MAX_PARAMETER_KEY_LENGTH:
                message = "mutation parameter object key is empty or too long"
                raise ValueError(message)
            items.append(
                (
                    key,
                    _freeze_parameter_value(item, depth=depth + 1, nodes=nodes),
                )
            )
        return FrozenParameterObject(tuple(items))
    message = "mutation parameters must contain only JSON values"
    raise TypeError(message)


def _thaw_parameter_value(value: FrozenParameterValue) -> JsonValue:
    if type(value) is tuple:
        return [_thaw_parameter_value(item) for item in value]
    if type(value) is FrozenParameterObject:
        return {key: _thaw_parameter_value(item) for key, item in value.items()}
    return cast("JsonValue", value)


def _redacted_projection(value: FrozenParameterObject) -> FrozenParameterObject:
    return FrozenParameterObject(
        tuple((key, _redact_parameter_value(item)) for key, item in value.items())
    )


def _redact_parameter_value(value: FrozenParameterValue) -> FrozenParameterValue:
    if type(value) is tuple:
        return tuple(_redact_parameter_value(item) for item in value)
    if type(value) is FrozenParameterObject:
        return FrozenParameterObject(
            tuple((key, _redact_parameter_value(item)) for key, item in value.items())
        )
    return REDACTED_PARAMETER_VALUE


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RealizedMutation:
    """One manifest-realized invocation with a separate safe projection."""

    operator_id: str
    operator_version: int
    stage: MutationStage
    parameters: FrozenParameterObject
    parameters_safe: FrozenParameterObject

    def __init__(
        self,
        *,
        operator_id: str,
        operator_version: int,
        stage: MutationStage,
        parameters: dict[str, object],
        parameters_safe: dict[str, object] | None = None,
    ) -> None:
        _validate_operator_identity(operator_id, operator_version)
        if type(stage) is not MutationStage:
            message = "mutation stage must be a MutationStage member"
            raise TypeError(message)
        frozen_parameters = freeze_parameter_object(parameters)
        frozen_safe = (
            _redacted_projection(frozen_parameters)
            if parameters_safe is None
            else freeze_parameter_object(parameters_safe)
        )
        object.__setattr__(self, "operator_id", operator_id)
        object.__setattr__(self, "operator_version", operator_version)
        object.__setattr__(self, "stage", stage)
        object.__setattr__(self, "parameters", frozen_parameters)
        object.__setattr__(self, "parameters_safe", frozen_safe)

    def log_safe_dict(self) -> JsonObject:
        """Return only identity, stage, and the explicitly safe parameter view."""
        return {
            "operator_id": self.operator_id,
            "operator_version": self.operator_version,
            "stage": self.stage.value,
            "parameters": thaw_parameter_object(self.parameters_safe),
        }

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"operator_id={self.operator_id!r}, "
            f"operator_version={self.operator_version!r}, "
            f"stage={self.stage.value!r}, "
            f"safe_parameter_keys={tuple(self.parameters_safe)!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class MutationState:
    """Ephemeral exact request state shared only with trusted built-in operators."""

    body: bytes
    headers: tuple[SignatureHeader, ...]
    signing_time_ns: int
    signer: Signer | None

    def __post_init__(self) -> None:
        _validate_state_fields(
            body=self.body,
            headers=self.headers,
            signing_time_ns=self.signing_time_ns,
            signer=self.signer,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"body_length={len(self.body)}, "
            f"header_names={tuple(header.name for header in self.headers)!r}, "
            f"signing_time_ns={self.signing_time_ns!r}, "
            f"has_signer={self.signer is not None})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class MutationInput:
    """Typed immutable stage input and realized parameters for one operator."""

    realized: RealizedMutation
    state: MutationState
    event_id: str
    media_type: str

    def __post_init__(self) -> None:
        if type(self.realized) is not RealizedMutation:
            message = "realized mutation must be a RealizedMutation"
            raise TypeError(message)
        if type(self.state) is not MutationState:
            message = "mutation state must be a MutationState"
            raise TypeError(message)
        _validate_event_id(self.event_id)
        _validate_media_type(self.media_type)

    @property
    def parameters(self) -> FrozenParameterObject:
        """Expose only the immutable realized parameters to the operator."""
        return self.realized.parameters

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"operator_id={self.realized.operator_id!r}, "
            f"operator_version={self.realized.operator_version!r}, "
            f"stage={self.realized.stage.value!r}, "
            f"body_length={len(self.state.body)}, "
            f"header_names={tuple(header.name for header in self.state.headers)!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class MutationOutput:
    """One operator's complete proposed state; the pipeline validates all effects."""

    body: bytes
    headers: tuple[SignatureHeader, ...]
    signing_time_ns: int
    signer: Signer | None

    def __post_init__(self) -> None:
        _validate_state_fields(
            body=self.body,
            headers=self.headers,
            signing_time_ns=self.signing_time_ns,
            signer=self.signer,
        )

    @classmethod
    def unchanged(cls, state: MutationState) -> MutationOutput:
        """Create an explicitly detached no-op output from an immutable input."""
        if type(state) is not MutationState:
            message = "unchanged output requires a MutationState"
            raise TypeError(message)
        return cls(
            body=state.body,
            headers=tuple(state.headers),
            signing_time_ns=state.signing_time_ns,
            signer=state.signer,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"body_length={len(self.body)}, "
            f"header_names={tuple(header.name for header in self.headers)!r}, "
            f"signing_time_ns={self.signing_time_ns!r}, "
            f"has_signer={self.signer is not None})"
        )


@runtime_checkable
class MutationOperator(Protocol):
    """Internal protocol implemented only by registered first-party operators."""

    __slots__ = ()

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        """Apply one deterministic, manifest-realized mutation."""
        ...


@dataclass(frozen=True, slots=True, repr=False)
class MutationRegistration:
    """Static identity, stage, effects, and implementation for one operator version."""

    operator_id: str
    operator_version: int
    stage: MutationStage
    implementation: MutationOperator
    changes_body: bool = False
    requires_valid_json: bool = False
    invalidates_json: bool = False
    written_headers: tuple[str, ...] = ()
    removed_headers: tuple[str, ...] = ()
    signature_header_action: SignatureHeaderAction = SignatureHeaderAction.NONE
    may_change_signing_time: bool = False
    may_replace_signer: bool = False

    def __post_init__(self) -> None:
        _validate_operator_identity(self.operator_id, self.operator_version)
        if type(self.stage) is not MutationStage:
            message = "registered mutation stage must be a MutationStage member"
            raise TypeError(message)
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.implementation,
            MutationOperator,
        ):
            message = "registered mutation implementation must satisfy MutationOperator"
            raise TypeError(message)
        _require_exact_bool(self.changes_body, field_name="changes_body")
        _require_exact_bool(self.requires_valid_json, field_name="requires_valid_json")
        _require_exact_bool(self.invalidates_json, field_name="invalidates_json")
        _require_exact_bool(
            self.may_change_signing_time,
            field_name="may_change_signing_time",
        )
        _require_exact_bool(self.may_replace_signer, field_name="may_replace_signer")
        normalized_written = _normalize_declared_headers(
            self.written_headers,
            field_name="written_headers",
        )
        normalized_removed = _normalize_declared_headers(
            self.removed_headers,
            field_name="removed_headers",
        )
        if set(normalized_written) & set(normalized_removed):
            message = "one registration cannot both write and remove the same static header"
            raise ValueError(message)
        object.__setattr__(self, "written_headers", normalized_written)
        object.__setattr__(self, "removed_headers", normalized_removed)
        if type(self.signature_header_action) is not SignatureHeaderAction:
            message = "signature_header_action must be a SignatureHeaderAction member"
            raise TypeError(message)
        self._validate_stage_effects()

    def _validate_stage_effects(self) -> None:
        header_effect = bool(
            self.written_headers
            or self.removed_headers
            or self.signature_header_action is not SignatureHeaderAction.NONE
        )
        signing_effect = self.may_change_signing_time or self.may_replace_signer
        if self.stage is MutationStage.STRUCTURAL:
            if (
                not self.changes_body
                or not self.requires_valid_json
                or self.invalidates_json
                or header_effect
                or signing_effect
            ):
                _raise_invalid_registration_stage()
            return
        if self.stage in (MutationStage.RAW_PRE_SIGN, MutationStage.RAW_POST_SIGN):
            if not self.changes_body or header_effect or signing_effect:
                _raise_invalid_registration_stage()
            return
        if self.stage in (MutationStage.HEADER_PRE_SIGN, MutationStage.HEADER_POST_SIGN):
            if self.changes_body or self.invalidates_json or signing_effect or not header_effect:
                _raise_invalid_registration_stage()
            if (
                self.signature_header_action is not SignatureHeaderAction.NONE
                and self.stage is not MutationStage.HEADER_POST_SIGN
            ):
                _raise_invalid_registration_stage()
            return
        if (
            self.stage is not MutationStage.SIGNING
            or self.changes_body
            or self.requires_valid_json
            or self.invalidates_json
            or header_effect
            or not signing_effect
        ):
            _raise_invalid_registration_stage()

    @property
    def key(self) -> tuple[str, int]:
        """Return the stable registry key."""
        return self.operator_id, self.operator_version

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"operator_id={self.operator_id!r}, "
            f"operator_version={self.operator_version!r}, "
            f"stage={self.stage.value!r})"
        )


class StaticMutationRegistry:
    """Immutable registry with no entry-point or third-party loading behavior."""

    __slots__ = ("_by_key", "_known_versions", "_registrations")

    _by_key: Mapping[tuple[str, int], MutationRegistration]
    _known_versions: Mapping[str, tuple[int, ...]]
    _registrations: tuple[MutationRegistration, ...]

    def __init__(self, registrations: tuple[MutationRegistration, ...]) -> None:
        if type(registrations) is not tuple:
            message = "mutation registrations must be provided as a tuple"
            raise TypeError(message)
        if len(registrations) > MAX_MUTATION_REGISTRATIONS:
            raise MutationError.resource_limit(
                "MUT_REGISTRY_LIMIT",
                "The mutation registry exceeds its bounded entry limit.",
            )
        snapshots: list[MutationRegistration] = []
        by_key: dict[tuple[str, int], MutationRegistration] = {}
        known_versions: dict[str, list[int]] = {}
        for registration in registrations:
            if type(registration) is not MutationRegistration:
                message = "registry entries must be MutationRegistration values"
                raise TypeError(message)
            snapshot = _copy_registration(registration)
            if snapshot.key in by_key:
                raise MutationError.conflict(
                    "MUT_DUPLICATE_REGISTRATION",
                    "A mutation operator version is registered more than once.",
                    operator_id=snapshot.operator_id,
                    operator_version=snapshot.operator_version,
                )
            snapshots.append(snapshot)
            by_key[snapshot.key] = snapshot
            known_versions.setdefault(snapshot.operator_id, []).append(snapshot.operator_version)
        self._registrations = tuple(snapshots)
        self._by_key = MappingProxyType(by_key)
        self._known_versions = MappingProxyType(
            {
                operator_id: tuple(sorted(versions))
                for operator_id, versions in known_versions.items()
            }
        )

    @property
    def registrations(self) -> tuple[MutationRegistration, ...]:
        """Return detached registration snapshots in deterministic order."""
        return tuple(_copy_registration(registration) for registration in self._registrations)

    @property
    def operator_versions(self) -> tuple[tuple[str, int], ...]:
        """Return registered identities in deterministic registration order."""
        return tuple(registration.key for registration in self._registrations)

    def registration(self, realized: RealizedMutation) -> MutationRegistration:
        """Resolve one exact version and prove that its realized stage agrees."""
        if type(realized) is not RealizedMutation:
            message = "registry lookup requires a RealizedMutation"
            raise TypeError(message)
        registration = self._by_key.get((realized.operator_id, realized.operator_version))
        if registration is None:
            known_versions = self._known_versions.get(realized.operator_id)
            if known_versions is None:
                raise MutationError.not_applicable(
                    "MUT_OPERATOR_UNREGISTERED",
                    "The requested mutation operator is not registered.",
                    operator_id=realized.operator_id,
                    operator_version=realized.operator_version,
                )
            raise MutationError.not_applicable(
                "MUT_OPERATOR_VERSION_UNREGISTERED",
                "The requested mutation operator version is not registered.",
                operator_id=realized.operator_id,
                operator_version=realized.operator_version,
            )
        if registration.stage is not realized.stage:
            raise MutationError.conflict(
                "MUT_OPERATOR_STAGE_CONFLICT",
                "The realized mutation stage differs from its registered stage.",
                operator_id=realized.operator_id,
                operator_version=realized.operator_version,
                safe_details={
                    "realized_stage": realized.stage.value,
                    "registered_stage": registration.stage.value,
                },
            )
        return _copy_registration(registration)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(operator_versions={self.operator_versions!r})"


@dataclass(frozen=True, slots=True, repr=False)
class MutationEvidence:
    """Immutable secret-free evidence for one realized operator invocation."""

    operator_id: str
    operator_version: int
    stage: MutationStage
    parameters_safe: FrozenParameterObject
    input_body_sha256: str
    output_body_sha256: str

    def __post_init__(self) -> None:
        _validate_operator_identity(self.operator_id, self.operator_version)
        if type(self.stage) is not MutationStage:
            message = "mutation evidence stage must be a MutationStage member"
            raise TypeError(message)
        if type(self.parameters_safe) is not FrozenParameterObject:
            message = "mutation evidence requires frozen safe parameters"
            raise TypeError(message)
        validate_sha256_digest(self.input_body_sha256)
        validate_sha256_digest(self.output_body_sha256)

    def log_safe_dict(self) -> JsonObject:
        """Return the complete internal evidence projection for sanitized sinks."""
        return {
            "operator_id": self.operator_id,
            "operator_version": self.operator_version,
            "stage": self.stage.value,
            "parameters": thaw_parameter_object(self.parameters_safe),
            "input_body_sha256": self.input_body_sha256,
            "output_body_sha256": self.output_body_sha256,
        }

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"operator_id={self.operator_id!r}, "
            f"operator_version={self.operator_version!r}, "
            f"stage={self.stage.value!r}, "
            f"safe_parameter_keys={tuple(self.parameters_safe)!r}, "
            f"input_body_sha256={self.input_body_sha256!r}, "
            f"output_body_sha256={self.output_body_sha256!r})"
        )


class MutationError(RuntimeError):
    """Classified mutation failure whose text and repr contain only safe data."""

    __slots__ = ("diagnostic",)

    diagnostic: Diagnostic

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.message)

    @classmethod
    def not_applicable(
        cls,
        code: str,
        message: str,
        *,
        operator_id: str | None = None,
        operator_version: int | None = None,
        safe_details: JsonObject | None = None,
    ) -> MutationError:
        """Create a stable mutation-not-applicable diagnostic."""
        return cls._build(
            ErrorCategory.MUTATION_NOT_APPLICABLE,
            code,
            message,
            operator_id=operator_id,
            operator_version=operator_version,
            safe_details=safe_details,
        )

    @classmethod
    def conflict(
        cls,
        code: str,
        message: str,
        *,
        operator_id: str | None = None,
        operator_version: int | None = None,
        safe_details: JsonObject | None = None,
    ) -> MutationError:
        """Create a stable conflicting-mutation diagnostic."""
        return cls._build(
            ErrorCategory.CONFLICTING_MUTATION,
            code,
            message,
            operator_id=operator_id,
            operator_version=operator_version,
            safe_details=safe_details,
        )

    @classmethod
    def invalid_parameter(
        cls,
        code: str,
        message: str,
        *,
        operator_id: str | None = None,
        operator_version: int | None = None,
        safe_details: JsonObject | None = None,
    ) -> MutationError:
        """Create a stable invalid-parameter diagnostic."""
        return cls._build(
            ErrorCategory.INVALID_PARAMETER,
            code,
            message,
            operator_id=operator_id,
            operator_version=operator_version,
            safe_details=safe_details,
        )

    @classmethod
    def resource_limit(cls, code: str, message: str) -> MutationError:
        """Create a bounded-resource diagnostic."""
        return cls._build(ErrorCategory.RESOURCE_LIMIT, code, message)

    @classmethod
    def _build(
        cls,
        category: ErrorCategory,
        code: str,
        message: str,
        *,
        operator_id: str | None = None,
        operator_version: int | None = None,
        safe_details: JsonObject | None = None,
    ) -> MutationError:
        details: JsonObject = {} if safe_details is None else dict(safe_details)
        if operator_id is not None:
            details["operator_id"] = operator_id
        if operator_version is not None:
            details["operator_version"] = operator_version
        return cls(
            Diagnostic(
                category=category,
                code=DiagnosticCode(code),
                message=message,
                retryable=False,
                safe_details=details,
                result_category=ResultCategory.INVALID_INPUT,
            )
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"category={self.diagnostic.category.value!r}, "
            f"code={str(self.diagnostic.code)!r})"
        )


def _copy_registration(registration: MutationRegistration) -> MutationRegistration:
    return MutationRegistration(
        operator_id=registration.operator_id,
        operator_version=registration.operator_version,
        stage=registration.stage,
        implementation=registration.implementation,
        changes_body=registration.changes_body,
        requires_valid_json=registration.requires_valid_json,
        invalidates_json=registration.invalidates_json,
        written_headers=tuple(registration.written_headers),
        removed_headers=tuple(registration.removed_headers),
        signature_header_action=registration.signature_header_action,
        may_change_signing_time=registration.may_change_signing_time,
        may_replace_signer=registration.may_replace_signer,
    )


def _validate_operator_identity(operator_id: str, operator_version: int) -> None:
    if type(operator_id) is not str:
        message = "operator_id must be a string"
        raise TypeError(message)
    if (
        not 1 <= len(operator_id) <= MAX_OPERATOR_ID_LENGTH
        or _OPERATOR_ID.fullmatch(operator_id) is None
    ):
        message = "operator_id must be a bounded lowercase identifier"
        raise ValueError(message)
    if type(operator_version) is not int:
        message = "operator_version must be an integer"
        raise TypeError(message)
    if not 1 <= operator_version <= MAX_OPERATOR_VERSION:
        message = "operator_version must be a positive bounded integer"
        raise ValueError(message)


def _normalize_declared_headers(
    headers: tuple[str, ...],
    *,
    field_name: str,
) -> tuple[str, ...]:
    if type(headers) is not tuple:
        message = f"{field_name} must be provided as a tuple"
        raise TypeError(message)
    if len(headers) > MAX_MUTATION_HEADERS:
        message = f"{field_name} exceeds the bounded header limit"
        raise ValueError(message)
    normalized: list[str] = []
    for value in headers:
        try:
            normalized.append(SignatureHeader(name=value, value="").name)
        except (TypeError, ValueError):
            message = f"{field_name} contains an invalid HTTP header name"
            raise ValueError(message) from None
    if len(normalized) != len(set(normalized)):
        message = f"{field_name} contains a duplicate header name"
        raise ValueError(message)
    return tuple(normalized)


def _validate_state_fields(
    *,
    body: bytes,
    headers: tuple[SignatureHeader, ...],
    signing_time_ns: int,
    signer: Signer | None,
) -> None:
    if type(body) is not bytes:
        message = "mutation body must be immutable bytes"
        raise TypeError(message)
    if type(headers) is not tuple:
        message = "mutation headers must be provided as a tuple"
        raise TypeError(message)
    if len(headers) > MAX_MUTATION_HEADERS:
        message = "mutation headers exceed the bounded header limit"
        raise ValueError(message)
    names: list[str] = []
    for header in headers:
        if type(header) is not SignatureHeader:
            message = "mutation headers must contain SignatureHeader values"
            raise TypeError(message)
        names.append(header.name)
    if len(names) != len(set(names)):
        message = "mutation header names must be unique case-insensitively"
        raise ValueError(message)
    if type(signing_time_ns) is not int:
        message = "signing_time_ns must be an integer"
        raise TypeError(message)
    if not -(1 << 63) <= signing_time_ns <= (1 << 63) - 1:
        message = "signing_time_ns must fit a signed 64-bit integer"
        raise ValueError(message)
    if signer is not None and not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        signer,
        Signer,
    ):
        message = "mutation signer must satisfy the Signer protocol or be None"
        raise TypeError(message)


def _validate_event_id(event_id: str) -> None:
    if type(event_id) is not str:
        message = "event_id must be a string"
        raise TypeError(message)
    if not event_id or len(event_id.encode("utf-8")) > MAX_EVENT_ID_BYTES:
        message = "event_id must be nonempty and fit the bounded UTF-8 limit"
        raise ValueError(message)


def _validate_media_type(media_type: str) -> None:
    if type(media_type) is not str:
        message = "media_type must be a string"
        raise TypeError(message)
    if (
        not 1 <= len(media_type) <= MAX_MEDIA_TYPE_LENGTH
        or _MEDIA_TYPE.fullmatch(media_type) is None
    ):
        message = "media_type must be a bounded HTTP media type"
        raise ValueError(message)


def _require_exact_bool(value: bool, *, field_name: str) -> None:
    if type(value) is not bool:
        message = f"{field_name} must be a bool"
        raise TypeError(message)


def _raise_invalid_registration_stage() -> None:
    message = "registered mutation effects are incompatible with the declared stage"
    raise ValueError(message)
