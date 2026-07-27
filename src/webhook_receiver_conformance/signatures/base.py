"""Closed internal signer contract and exact-byte signing primitives."""
# ruff: noqa: BLE001, D105, D107, EM101, INP001, PLR0913, PLR2004

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar, Final, Protocol, cast, runtime_checkable

from webhook_receiver_conformance.domain.hashing import (
    sha256_digest,
    validate_sha256_digest,
)
from webhook_receiver_conformance.errors import (
    Diagnostic,
    ErrorCategory,
    ResultCategory,
)
from webhook_receiver_conformance.types import DiagnosticCode, JsonObject, Sha256Digest

MAX_SIGNING_BODY_BYTES: Final = 16_777_216
MAX_SIGNING_INPUT_BYTES: Final = MAX_SIGNING_BODY_BYTES + 8192
MAX_EVENT_ID_BYTES: Final = 4096
MAX_TEMPLATE_COMPONENTS: Final = 16
MAX_TEMPLATE_LITERAL_BYTES: Final = 1024
MAX_SIGNER_HEADERS: Final = 16
MAX_USER_HEADERS: Final = 128
MAX_HEADER_NAME_LENGTH: Final = 128
MAX_HEADER_VALUE_LENGTH: Final = 8192
MAX_KEY_ID_LENGTH: Final = 128
SIGNED_INT64_MIN: Final = -(1 << 63)
SIGNED_INT64_MAX: Final = (1 << 63) - 1
NANOSECONDS_PER_SECOND: Final = 1_000_000_000
LENGTH_PREFIXED_TEMPLATE_DOMAIN: Final = b"wrch-signing-input-frame-v1\x00"

_IDENTIFIER = re.compile(r"[a-z][a-z0-9._-]{0,127}")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_HARNESS_REQUEST_HEADERS: Final = frozenset(
    {
        "connection",
        "content-length",
        "content-type",
        "host",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
    }
)
_SIGNATURE_PACKAGE_PREFIX: Final = "webhook_receiver_conformance.signatures."
_SIGNATURE_PACKAGE_MODULE: Final = _SIGNATURE_PACKAGE_PREFIX.removesuffix(".")
_REQUIRED_BUILTIN_SIGNER_CONTRACT: Final[Mapping[str, str]] = MappingProxyType(
    {
        "generic-hmac-sha256": f"{_SIGNATURE_PACKAGE_PREFIX}hmac_generic",
        "stripe-v1": f"{_SIGNATURE_PACKAGE_PREFIX}stripe",
        "standard-webhooks-hmac": f"{_SIGNATURE_PACKAGE_PREFIX}standard_webhooks",
    }
)
_IMPORTABLE_SIGNATURE_FILE_SUFFIXES: Final = tuple(
    sorted((".py", *EXTENSION_SUFFIXES), key=len, reverse=True)
)
_FRAME_LITERAL_TAG: Final = b"\x00"
_FRAME_TIMESTAMP_TAG: Final = b"\x01"
_FRAME_EVENT_ID_TAG: Final = b"\x02"
_FRAME_BODY_TAG: Final = b"\x03"
_FRAME_VALUE_LENGTH_BYTES: Final = 8
_FRAME_VERSION_LENGTH_BYTES: Final = 2


class BuiltinSignerCategory(StrEnum):
    """Closed v0.1 first-party signer categories from ADR-024."""

    GENERIC_HMAC_SHA256 = "generic-hmac-sha256"
    STRIPE_V1 = "stripe-v1"
    STANDARD_WEBHOOKS_HMAC = "standard-webhooks-hmac"


BUILTIN_SIGNER_MODULES: Final[Mapping[BuiltinSignerCategory, str]] = MappingProxyType(
    {
        BuiltinSignerCategory.GENERIC_HMAC_SHA256: _REQUIRED_BUILTIN_SIGNER_CONTRACT[
            "generic-hmac-sha256"
        ],
        BuiltinSignerCategory.STRIPE_V1: _REQUIRED_BUILTIN_SIGNER_CONTRACT["stripe-v1"],
        BuiltinSignerCategory.STANDARD_WEBHOOKS_HMAC: _REQUIRED_BUILTIN_SIGNER_CONTRACT[
            "standard-webhooks-hmac"
        ],
    }
)


class SigningInputToken(StrEnum):
    """Authoritative fields available to versioned signing-input templates."""

    TIMESTAMP = "timestamp"
    EVENT_ID = "event_id"
    BODY = "body"


class TimestampEncoding(StrEnum):
    """Closed timestamp encodings for internal HMAC adapters."""

    ASCII_DECIMAL_NANOSECONDS = "ascii-decimal-nanoseconds"
    ASCII_DECIMAL_SECONDS_FLOOR = "ascii-decimal-seconds-floor"


class TemplateFraming(StrEnum):
    """Closed canonical framing rules for signing-input templates."""

    EXACT_BODY_V1 = "exact-body-v1"
    LENGTH_PREFIXED_V1 = "length-prefixed-v1"


class SignatureEncoding(StrEnum):
    """Closed generic signature output encodings."""

    HEX = "hex"
    BASE64 = "base64"


class VerificationReason(StrEnum):
    """Stable, non-secret result of strict signature-header verification."""

    VALID = "valid"
    MISSING_HEADER = "missing_header"
    DUPLICATE_HEADER = "duplicate_header"
    MALFORMED_HEADER = "malformed_header"
    SIGNATURE_MISMATCH = "signature_mismatch"


type SigningTemplateComponent = SigningInputToken | bytes


@dataclass(frozen=True, slots=True)
class SigningInput:
    """Immutable exact bytes and manifest-fixed identity/time supplied to a signer."""

    body: bytes
    event_id: str
    logical_time_ns: int

    def __post_init__(self) -> None:
        if type(self.body) is not bytes:
            message = "signing body must be immutable bytes"
            raise TypeError(message)
        if len(self.body) > MAX_SIGNING_BODY_BYTES:
            message = "signing body exceeds the 16777216-byte hard limit"
            raise ValueError(message)
        _encode_bounded_text(
            self.event_id,
            field_name="event_id",
            maximum_bytes=MAX_EVENT_ID_BYTES,
        )
        _validate_logical_time(self.logical_time_ns)


@dataclass(frozen=True, slots=True)
class CanonicalSigningTemplate:
    """Versioned sequence of exact literals and authoritative input tokens.

    ``exact-body-v1`` preserves the public body-only compatibility vector.
    Every other built-in template uses ``length-prefixed-v1``: a domain,
    version, component count, one-byte component tags, uint64 big-endian value
    lengths, and exact values. This framing is injective for the selected input
    fields and never decodes or reserializes body bytes.
    """

    version: str
    components: tuple[SigningTemplateComponent, ...]
    framing: TemplateFraming = TemplateFraming.LENGTH_PREFIXED_V1

    def __post_init__(self) -> None:
        _validate_identifier(self.version, field_name="template version")
        if type(self.framing) is not TemplateFraming:
            message = "template framing must be a TemplateFraming member"
            raise TypeError(message)
        _validate_template_components(self.components, framing=self.framing)

    def render(
        self,
        signing_input: SigningInput,
        *,
        timestamp_encoding: TimestampEncoding,
    ) -> bytes:
        """Render the canonical signing input without interpreting body bytes."""
        if type(signing_input) is not SigningInput:
            message = "signing_input must be a SigningInput"
            raise TypeError(message)
        if type(timestamp_encoding) is not TimestampEncoding:
            message = "timestamp_encoding must be a TimestampEncoding member"
            raise TypeError(message)
        if self.framing is TemplateFraming.EXACT_BODY_V1:
            return signing_input.body
        return _render_length_prefixed_template(
            self,
            signing_input,
            timestamp_encoding=timestamp_encoding,
        )


def _validate_template_components(
    components: tuple[SigningTemplateComponent, ...],
    *,
    framing: TemplateFraming,
) -> None:
    if type(components) is not tuple:
        message = "template components must be provided as a tuple"
        raise TypeError(message)
    if not 1 <= len(components) <= MAX_TEMPLATE_COMPONENTS:
        message = "template must contain between 1 and 16 components"
        raise ValueError(message)

    literal_bytes = 0
    tokens: list[SigningInputToken] = []
    for component in components:
        if type(component) is bytes:
            literal_bytes += len(component)
            continue
        if type(component) is not SigningInputToken:
            message = "template components must be immutable bytes or SigningInputToken"
            raise TypeError(message)
        tokens.append(component)
    if literal_bytes > MAX_TEMPLATE_LITERAL_BYTES:
        message = "template literal bytes exceed the 1024-byte limit"
        raise ValueError(message)
    if not tokens:
        message = "template must cover at least one authoritative input token"
        raise ValueError(message)
    if len(tokens) != len(set(tokens)):
        message = "an authoritative input token cannot occur more than once"
        raise ValueError(message)
    if framing is TemplateFraming.EXACT_BODY_V1 and components != (SigningInputToken.BODY,):
        message = "exact-body-v1 framing requires the body-only template"
        raise ValueError(message)


@dataclass(frozen=True, slots=True)
class SigningTemplateRegistration:
    """One immutable version-to-semantics binding for a signer profile."""

    template: CanonicalSigningTemplate
    timestamp_encoding: TimestampEncoding

    def __post_init__(self) -> None:
        if type(self.template) is not CanonicalSigningTemplate:
            message = "registered template must be a CanonicalSigningTemplate"
            raise TypeError(message)
        if type(self.timestamp_encoding) is not TimestampEncoding:
            message = "registered timestamp encoding must be a TimestampEncoding member"
            raise TypeError(message)

    @property
    def version(self) -> str:
        """Return the unique version key bound to these exact semantics."""
        return self.template.version


type _TemplateComponentFingerprint = tuple[str, bytes | str]
type _TemplateSemanticFingerprint = tuple[
    str,
    tuple[_TemplateComponentFingerprint, ...],
    str,
    str,
]


class StaticSigningTemplateRegistry:
    """Immutable signing-template registry enforcing one meaning per version."""

    __slots__ = ("_by_version", "_semantic_fingerprints")

    _by_version: Mapping[str, _TemplateSemanticFingerprint]
    _semantic_fingerprints: tuple[_TemplateSemanticFingerprint, ...]

    def __init__(self, registrations: tuple[SigningTemplateRegistration, ...]) -> None:
        if type(registrations) is not tuple:
            message = "template registrations must be provided as a tuple"
            raise TypeError(message)
        by_version: dict[str, _TemplateSemanticFingerprint] = {}
        semantic_fingerprints: list[_TemplateSemanticFingerprint] = []
        for registration in registrations:
            if type(registration) is not SigningTemplateRegistration:
                message = "template registry entries must be SigningTemplateRegistration values"
                raise TypeError(message)
            fingerprint = _template_semantic_fingerprint(
                registration.template,
                registration.timestamp_encoding,
            )
            version = fingerprint[0]
            if version in by_version:
                raise SignerError.configuration(
                    "SIG_TEMPLATE_VERSION_DUPLICATE",
                    "A signing-input template version is registered more than once.",
                )
            semantic_fingerprints.append(fingerprint)
            by_version[version] = fingerprint
        self._semantic_fingerprints = tuple(semantic_fingerprints)
        self._by_version = MappingProxyType(by_version)

    @property
    def registrations(self) -> tuple[SigningTemplateRegistration, ...]:
        """Return detached registrations in deterministic semantic order."""
        return tuple(
            _registration_from_semantic_fingerprint(fingerprint)
            for fingerprint in self._semantic_fingerprints
        )

    def validate(
        self,
        template: CanonicalSigningTemplate,
        timestamp_encoding: TimestampEncoding,
    ) -> SigningTemplateRegistration:
        """Validate semantics and return a detached registered snapshot."""
        if type(template) is not CanonicalSigningTemplate:
            message = "template must be a CanonicalSigningTemplate"
            raise TypeError(message)
        if type(timestamp_encoding) is not TimestampEncoding:
            message = "timestamp_encoding must be a TimestampEncoding member"
            raise TypeError(message)
        try:
            candidate = _template_semantic_fingerprint(template, timestamp_encoding)
        except (TypeError, ValueError):
            raise SignerError.configuration(
                "SIG_TEMPLATE_VERSION_CONFLICT",
                "The signing-input template version does not match its registered semantics.",
            ) from None
        registered = self._by_version.get(candidate[0])
        if registered is None:
            raise SignerError.configuration(
                "SIG_TEMPLATE_VERSION_UNREGISTERED",
                "The signing-input template version is not registered.",
            )
        if registered != candidate:
            raise SignerError.configuration(
                "SIG_TEMPLATE_VERSION_CONFLICT",
                "The signing-input template version does not match its registered semantics.",
            )
        return _registration_from_semantic_fingerprint(registered)


def _template_semantic_fingerprint(
    template: CanonicalSigningTemplate,
    timestamp_encoding: TimestampEncoding,
) -> _TemplateSemanticFingerprint:
    if type(template) is not CanonicalSigningTemplate:
        message = "template must be a CanonicalSigningTemplate"
        raise TypeError(message)
    if type(timestamp_encoding) is not TimestampEncoding:
        message = "timestamp_encoding must be a TimestampEncoding member"
        raise TypeError(message)
    detached = CanonicalSigningTemplate(
        version=template.version,
        components=template.components,
        framing=template.framing,
    )
    component_fingerprints: list[_TemplateComponentFingerprint] = []
    for component in detached.components:
        if type(component) is bytes:
            component_fingerprints.append(("literal", bytes(component)))
        elif type(component) is SigningInputToken:
            component_fingerprints.append(("token", component.value))
        else:
            message = "template components must be immutable bytes or SigningInputToken"
            raise TypeError(message)
    return (
        detached.version,
        tuple(component_fingerprints),
        detached.framing.value,
        timestamp_encoding.value,
    )


def _registration_from_semantic_fingerprint(
    fingerprint: _TemplateSemanticFingerprint,
) -> SigningTemplateRegistration:
    version, component_fingerprints, framing, timestamp_encoding = fingerprint
    components: list[SigningTemplateComponent] = []
    for kind, value in component_fingerprints:
        if kind == "literal":
            components.append(cast("bytes", value))
        else:
            components.append(SigningInputToken(cast("str", value)))
    return SigningTemplateRegistration(
        template=CanonicalSigningTemplate(
            version=version,
            components=tuple(components),
            framing=TemplateFraming(framing),
        ),
        timestamp_encoding=TimestampEncoding(timestamp_encoding),
    )


@dataclass(frozen=True, slots=True, repr=False)
class SignatureHeader:
    """One transport header whose value is deliberately hidden from repr."""

    name: str
    value: str

    def __post_init__(self) -> None:
        normalized = _validate_header_name(self.name)
        _validate_header_value(self.value)
        object.__setattr__(self, "name", normalized)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, value_length={len(self.value)})"


@dataclass(frozen=True, slots=True)
class SigningEvidence:
    """Secret-free evidence for one canonical input and key fingerprint."""

    adapter_id: str
    adapter_version: str
    template_version: str
    logical_time_ns: int
    body_sha256: str
    covered_bytes_sha256: str
    key_fingerprint: Sha256Digest
    key_id: str | None
    output_encoding: SignatureEncoding

    def __post_init__(self) -> None:
        _validate_identifier(self.adapter_id, field_name="adapter_id")
        _validate_identifier(self.adapter_version, field_name="adapter_version")
        _validate_identifier(self.template_version, field_name="template_version")
        _validate_logical_time(self.logical_time_ns)
        validate_sha256_digest(self.body_sha256)
        validate_sha256_digest(self.covered_bytes_sha256)
        _validate_sha256_fingerprint(self.key_fingerprint)
        _validate_key_id(self.key_id)
        if type(self.output_encoding) is not SignatureEncoding:
            message = "output_encoding must be a SignatureEncoding member"
            raise TypeError(message)

    def model_dump(self) -> dict[str, object]:
        """Return the complete public evidence projection and no secret material."""
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "template_version": self.template_version,
            "logical_time_ns": self.logical_time_ns,
            "body_sha256": self.body_sha256,
            "covered_bytes_sha256": self.covered_bytes_sha256,
            "key_fingerprint": str(self.key_fingerprint),
            "key_id": self.key_id,
            "output_encoding": self.output_encoding.value,
        }


@dataclass(frozen=True, slots=True, repr=False)
class SigningResult:
    """Ordered signer-owned headers plus a secret-free evidence projection."""

    headers: tuple[SignatureHeader, ...]
    evidence: SigningEvidence

    def __post_init__(self) -> None:
        _validate_result_headers(self.headers)
        if type(self.evidence) is not SigningEvidence:
            message = "signing evidence must be a SigningEvidence"
            raise TypeError(message)

    def __repr__(self) -> str:
        names = tuple(header.name for header in self.headers)
        return f"{type(self).__name__}(header_names={names!r}, evidence={self.evidence!r})"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Strict verification outcome that never retains a signature value."""

    valid: bool
    reason: VerificationReason
    evidence: SigningEvidence

    def __post_init__(self) -> None:
        if type(self.valid) is not bool:
            message = "verification validity must be a bool"
            raise TypeError(message)
        if type(self.reason) is not VerificationReason:
            message = "verification reason must be a VerificationReason member"
            raise TypeError(message)
        if self.valid is not (self.reason is VerificationReason.VALID):
            message = "verification validity and reason disagree"
            raise ValueError(message)
        if type(self.evidence) is not SigningEvidence:
            message = "verification evidence must be a SigningEvidence"
            raise TypeError(message)


class SignerError(RuntimeError):
    """A classified, secret-safe signer configuration or lookup failure."""

    __slots__ = ("diagnostic",)

    diagnostic: Diagnostic

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.message)

    @classmethod
    def configuration(
        cls,
        code: str,
        message: str,
        *,
        safe_details: JsonObject | None = None,
    ) -> SignerError:
        """Create a classified invalid-input signer error."""
        return cls(
            Diagnostic(
                category=ErrorCategory.CONFIGURATION_ERROR,
                code=DiagnosticCode(code),
                message=message,
                retryable=False,
                safe_details={} if safe_details is None else safe_details,
                result_category=ResultCategory.INVALID_INPUT,
            )
        )

    @classmethod
    def unsupported(cls) -> SignerError:
        """Create a classified unsupported-adapter error."""
        return cls(
            Diagnostic(
                category=ErrorCategory.UNSUPPORTED_ALGORITHM,
                code=DiagnosticCode("SIG_UNSUPPORTED_ADAPTER"),
                message="The requested signer adapter is not registered.",
                retryable=False,
                result_category=ResultCategory.UNSUPPORTED,
            )
        )

    @classmethod
    def signing(cls) -> SignerError:
        """Create a classified secret-safe signing-operation error."""
        return cls(
            Diagnostic(
                category=ErrorCategory.SIGNING_ERROR,
                code=DiagnosticCode("SIG_SIGNING_FAILED"),
                message="The signer could not produce an HMAC digest.",
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


@runtime_checkable
class Signer(Protocol):
    """Unstable internal protocol implemented nominally by every built-in signer."""

    __slots__ = ()

    BUILTIN_CATEGORY: ClassVar[BuiltinSignerCategory]

    @property
    def adapter_id(self) -> str:
        """Return the version-independent built-in adapter identifier."""
        ...

    @property
    def adapter_version(self) -> str:
        """Return the implementation/profile version."""
        ...

    @property
    def owned_headers(self) -> tuple[str, ...]:
        """Return normalized headers exclusively owned by this signer."""
        ...

    def sign(self, signing_input: SigningInput) -> SigningResult:
        """Sign one immutable realized input."""
        ...

    def verify(
        self,
        signing_input: SigningInput,
        headers: tuple[SignatureHeader, ...],
    ) -> VerificationResult:
        """Strictly verify this signer's header over one realized input."""
        ...


@dataclass(frozen=True, slots=True)
class SignerRegistration:
    """One statically declared first-party signer implementation."""

    category: BuiltinSignerCategory
    adapter_version: str
    implementation: type[Signer]

    def __post_init__(self) -> None:
        if type(self.category) is not BuiltinSignerCategory:
            message = "signer category must be a BuiltinSignerCategory member"
            raise TypeError(message)
        _validate_identifier(self.adapter_version, field_name="adapter_version")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.implementation,
            type,
        ):
            message = "signer implementation must be a class"
            raise TypeError(message)
        if Signer not in self.implementation.__mro__:
            message = "built-in signer implementations must inherit the Signer protocol"
            raise TypeError(message)
        if self.implementation.BUILTIN_CATEGORY is not self.category:
            raise SignerError.configuration(
                "SIG_BUILTIN_CATEGORY_CONFLICT",
                "A built-in signer implementation declares a different closed category.",
            )
        if self.implementation.__module__ != BUILTIN_SIGNER_MODULES[self.category]:
            raise SignerError.configuration(
                "SIG_BUILTIN_MODULE_CONFLICT",
                "A built-in signer implementation is outside its declared category module.",
            )

    @property
    def adapter_id(self) -> str:
        """Return the wire identifier fixed by the closed built-in category."""
        return self.category.value


class StaticSignerRegistry:
    """Immutable registry with no entry-point or third-party loading behavior."""

    __slots__ = ("_by_id", "_registrations")

    _by_id: Mapping[str, SignerRegistration]
    _registrations: tuple[SignerRegistration, ...]

    def __init__(self, registrations: tuple[SignerRegistration, ...]) -> None:
        if type(registrations) is not tuple:
            message = "signer registrations must be provided as a tuple"
            raise TypeError(message)
        by_id: dict[str, SignerRegistration] = {}
        for registration in registrations:
            if type(registration) is not SignerRegistration:
                message = "registry entries must be SignerRegistration values"
                raise TypeError(message)
            if registration.adapter_id in by_id:
                raise SignerError.configuration(
                    "SIG_DUPLICATE_ADAPTER",
                    "A built-in signer adapter is registered more than once.",
                )
            by_id[registration.adapter_id] = registration
        self._registrations = registrations
        self._by_id = MappingProxyType(by_id)

    @property
    def registrations(self) -> tuple[SignerRegistration, ...]:
        """Return deterministic registration order for contract parametrization."""
        return self._registrations

    @property
    def adapter_ids(self) -> tuple[str, ...]:
        """Return the registered adapter IDs in deterministic order."""
        return tuple(registration.adapter_id for registration in self._registrations)

    @property
    def categories(self) -> tuple[BuiltinSignerCategory, ...]:
        """Return the registered closed categories in deterministic order."""
        return tuple(registration.category for registration in self._registrations)

    def registration(self, adapter_id: str) -> SignerRegistration:
        """Look up one first-party implementation or raise a classified error."""
        if type(adapter_id) is not str:
            message = "adapter_id must be a string"
            raise TypeError(message)
        registration = self._by_id.get(adapter_id)
        if registration is None:
            raise SignerError.unsupported()
        return registration

    def __repr__(self) -> str:
        return f"{type(self).__name__}(adapter_ids={self.adapter_ids!r})"


def _importable_module_stem(file_name: str) -> str | None:
    for suffix in _IMPORTABLE_SIGNATURE_FILE_SUFFIXES:
        if not file_name.endswith(suffix):
            continue
        stem = file_name[: -len(suffix)]
        return stem if stem.isidentifier() else None
    return None


def discover_builtin_signer_modules(
    package_directory: Path | None = None,
    *,
    package_module: str = _SIGNATURE_PACKAGE_MODULE,
) -> tuple[str, ...]:
    """Recursively inventory importable package artifacts without importing them."""
    directory = Path(__file__).resolve().parent if package_directory is None else package_directory
    if type(package_module) is not str:
        message = "package_module must be a string"
        raise TypeError(message)
    if any(not part.isidentifier() for part in package_module.split(".")):
        message = "package_module must be a dotted Python identifier"
        raise ValueError(message)
    module_names: list[str] = []
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(directory)
        if relative == Path("base.py"):
            continue
        module_stem = _importable_module_stem(path.name)
        if module_stem is None:
            continue
        parent_parts = () if relative.parent == Path() else relative.parent.parts
        if any(not part.isidentifier() for part in parent_parts):
            continue
        module_parts = parent_parts if module_stem == "__init__" else (*parent_parts, module_stem)
        module_names.append(".".join((package_module, *module_parts)))
    return tuple(sorted(module_names))


def discover_builtin_signer_implementations() -> tuple[type[Signer], ...]:
    """Discover every loaded nominal implementation across the signature package."""
    pending: list[type[Signer]] = list(Signer.__subclasses__())
    seen: set[type[Signer]] = set()
    implementations: list[type[Signer]] = []
    while pending:
        implementation = pending.pop()
        if implementation in seen:
            continue
        seen.add(implementation)
        pending.extend(implementation.__subclasses__())
        if implementation.__module__.startswith(_SIGNATURE_PACKAGE_PREFIX):
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
    registry: StaticSignerRegistry,
    *,
    implementation_types: tuple[type[Signer], ...] | None = None,
    present_modules: tuple[str, ...] | None = None,
) -> None:
    """Prove that package modules, loaded implementations, and registry agree."""
    if type(registry) is not StaticSignerRegistry:
        message = "registry must be a StaticSignerRegistry"
        raise TypeError(message)
    _validate_frozen_builtin_signer_contract()
    implementations = (
        discover_builtin_signer_implementations()
        if implementation_types is None
        else implementation_types
    )
    modules = discover_builtin_signer_modules() if present_modules is None else present_modules
    expected_categories = _expected_builtin_categories(modules)
    if set(registry.categories) != expected_categories:
        raise SignerError.configuration(
            "SIG_BUILTIN_REGISTRY_INCOMPLETE",
            "The signer registry does not cover every present built-in category exactly once.",
        )

    implementation_by_category = _index_builtin_implementations(
        implementations,
        present_modules=modules,
    )
    registered_implementations = {
        registration.category: registration.implementation
        for registration in registry.registrations
    }
    if registered_implementations != implementation_by_category:
        raise SignerError.configuration(
            "SIG_BUILTIN_REGISTRY_INCOMPLETE",
            "The signer registry and package implementations are not one-to-one.",
        )


def _validate_frozen_builtin_signer_contract() -> None:
    required_contract = dict(_REQUIRED_BUILTIN_SIGNER_CONTRACT)
    enum_categories = {category.value for category in BuiltinSignerCategory}
    if enum_categories != set(required_contract):
        raise SignerError.configuration(
            "SIG_BUILTIN_REGISTRY_INCOMPLETE",
            "The signer category enum differs from the frozen ADR-024 v0.1 contract.",
        )
    mapped_contract = {
        category.value: module_name for category, module_name in BUILTIN_SIGNER_MODULES.items()
    }
    if mapped_contract != required_contract:
        raise SignerError.configuration(
            "SIG_BUILTIN_REGISTRY_INCOMPLETE",
            "The signer module map differs from the frozen ADR-024 v0.1 contract.",
        )


def _expected_builtin_categories(
    modules: tuple[str, ...],
) -> set[BuiltinSignerCategory]:
    if type(modules) is not tuple:
        message = "present_modules must be provided as a tuple"
        raise TypeError(message)
    if len(modules) != len(set(modules)):
        raise SignerError.configuration(
            "SIG_BUILTIN_MODULE_DUPLICATE",
            "A built-in signer package module appears more than once.",
        )
    category_by_module = {
        module_name: category for category, module_name in BUILTIN_SIGNER_MODULES.items()
    }
    categories: set[BuiltinSignerCategory] = set()
    for module_name in modules:
        if type(module_name) is not str:
            message = "present module names must be strings"
            raise TypeError(message)
        category = category_by_module.get(module_name)
        if category is None:
            raise SignerError.configuration(
                "SIG_BUILTIN_MODULE_UNDECLARED",
                "A signature package module is not assigned to a closed built-in category.",
            )
        categories.add(category)
    return categories


def _index_builtin_implementations(
    implementations: tuple[type[Signer], ...],
    *,
    present_modules: tuple[str, ...],
) -> dict[BuiltinSignerCategory, type[Signer]]:
    if type(implementations) is not tuple:
        message = "implementation_types must be provided as a tuple"
        raise TypeError(message)
    implementation_by_category: dict[BuiltinSignerCategory, type[Signer]] = {}
    for implementation in implementations:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            implementation,
            type,
        ):
            message = "implementation_types entries must be classes"
            raise TypeError(message)
        if Signer not in implementation.__mro__:
            message = "built-in signer implementations must inherit the Signer protocol"
            raise TypeError(message)
        category = implementation.BUILTIN_CATEGORY
        if type(category) is not BuiltinSignerCategory:
            raise SignerError.configuration(
                "SIG_BUILTIN_CATEGORY_UNDECLARED",
                "A package signer implementation has no closed built-in category.",
            )
        if implementation.__module__ != BUILTIN_SIGNER_MODULES[category]:
            raise SignerError.configuration(
                "SIG_BUILTIN_MODULE_CONFLICT",
                "A built-in signer implementation is outside its declared category module.",
            )
        if implementation.__module__ not in present_modules:
            raise SignerError.configuration(
                "SIG_BUILTIN_REGISTRY_INCOMPLETE",
                "A loaded signer implementation has no present package module.",
            )
        if category in implementation_by_category:
            raise SignerError.configuration(
                "SIG_BUILTIN_CATEGORY_DUPLICATE",
                "A built-in signer category has more than one implementation.",
            )
        implementation_by_category[category] = implementation
    return implementation_by_category


def validate_header_ownership(
    owned_headers: Sequence[str],
    *,
    user_header_names: Sequence[str] = (),
) -> tuple[str, ...]:
    """Validate bounded, case-insensitive exclusive signer header ownership."""
    owned = _normalize_header_sequence(
        owned_headers,
        field_name="owned signer headers",
        maximum=MAX_SIGNER_HEADERS,
    )
    users = _normalize_header_sequence(
        user_header_names,
        field_name="user headers",
        maximum=MAX_USER_HEADERS,
    )
    if len(owned) != len(set(owned)):
        raise SignerError.configuration(
            "SIG_SIGNER_HEADER_INTERNAL_CONFLICT",
            "Signer profile declares the same owned header more than once.",
        )
    if set(owned) & set(users):
        raise SignerError.configuration(
            "SIG_SIGNER_HEADER_CONFLICT",
            "User-supplied value conflicts with a signer-owned signature header.",
            safe_details={"conflict_source": "planned-user-header"},
        )
    if set(owned) & _HARNESS_REQUEST_HEADERS:
        raise SignerError.configuration(
            "SIG_SIGNER_HEADER_RESERVED",
            "Signer-owned header conflicts with a harness-owned request header.",
        )
    return owned


def signing_evidence(
    *,
    adapter_id: str,
    adapter_version: str,
    template_version: str,
    signing_input: SigningInput,
    covered_bytes: bytes,
    key_fingerprint: Sha256Digest,
    key_id: str | None,
    output_encoding: SignatureEncoding,
) -> SigningEvidence:
    """Build the shared safe evidence projection for an exact signing input."""
    if type(signing_input) is not SigningInput:
        message = "signing_input must be a SigningInput"
        raise TypeError(message)
    if type(covered_bytes) is not bytes:
        message = "covered_bytes must be immutable bytes"
        raise TypeError(message)
    return SigningEvidence(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        template_version=template_version,
        logical_time_ns=signing_input.logical_time_ns,
        body_sha256=sha256_digest(signing_input.body),
        covered_bytes_sha256=sha256_digest(covered_bytes),
        key_fingerprint=key_fingerprint,
        key_id=key_id,
        output_encoding=output_encoding,
    )


def _normalize_header_sequence(
    values: Sequence[str],
    *,
    field_name: str,
    maximum: int,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        values,
        Sequence,
    ):
        raise SignerError.configuration(
            "SIG_SIGNER_HEADERS_INVALID",
            f"{field_name} must be a bounded sequence of header names.",
        )
    try:
        iterator = iter(values)
    except Exception:
        raise SignerError.configuration(
            "SIG_SIGNER_HEADERS_INVALID",
            f"{field_name} must be a bounded sequence of header names.",
        ) from None
    normalized: list[str] = []
    for index in range(maximum + 1):
        try:
            value = next(iterator)
        except StopIteration:
            return tuple(normalized)
        except Exception:
            raise SignerError.configuration(
                "SIG_SIGNER_HEADERS_INVALID",
                f"{field_name} contains an invalid HTTP header name.",
            ) from None
        if index == maximum:
            raise SignerError.configuration(
                "SIG_SIGNER_HEADERS_INVALID",
                f"{field_name} exceeds its bounded item limit.",
            )
        try:
            normalized.append(_validate_header_name(value))
        except (TypeError, ValueError):
            raise SignerError.configuration(
                "SIG_SIGNER_HEADERS_INVALID",
                f"{field_name} contains an invalid HTTP header name.",
            ) from None
    return tuple(normalized)


def _validate_result_headers(headers: tuple[SignatureHeader, ...]) -> None:
    if type(headers) is not tuple:
        message = "signing result headers must be provided as a tuple"
        raise TypeError(message)
    if not 1 <= len(headers) <= MAX_SIGNER_HEADERS:
        message = "signing result must contain between 1 and 16 headers"
        raise ValueError(message)
    names: list[str] = []
    for header in headers:
        if type(header) is not SignatureHeader:
            message = "signing result headers must be SignatureHeader values"
            raise TypeError(message)
        names.append(header.name)
    if len(names) != len(set(names)):
        message = "signing result header names must be unique case-insensitively"
        raise ValueError(message)


def _validate_identifier(value: str, *, field_name: str) -> str:
    if type(value) is not str:
        message = f"{field_name} must be a string"
        raise TypeError(message)
    if _IDENTIFIER.fullmatch(value) is None:
        message = f"{field_name} must be a bounded lowercase identifier"
        raise ValueError(message)
    return value


def _validate_header_name(value: str) -> str:
    if type(value) is not str:
        message = "header name must be a string"
        raise TypeError(message)
    if not 1 <= len(value) <= MAX_HEADER_NAME_LENGTH or _HEADER_NAME.fullmatch(value) is None:
        message = "header name must be a bounded HTTP token"
        raise ValueError(message)
    return value.casefold()


def _validate_header_value(value: str) -> None:
    if type(value) is not str:
        message = "header value must be a string"
        raise TypeError(message)
    if len(value) > MAX_HEADER_VALUE_LENGTH:
        message = "header value exceeds the bounded value limit"
        raise ValueError(message)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        message = "signature header value must contain ASCII characters"
        raise ValueError(message) from None
    if any(byte < 32 or byte == 127 for byte in encoded):
        message = "signature header value must not contain control characters"
        raise ValueError(message)


def _validate_key_id(value: str | None) -> None:
    if value is None:
        return
    if type(value) is not str:
        message = "key_id must be a string or None"
        raise TypeError(message)
    if len(value) > MAX_KEY_ID_LENGTH:
        message = "key_id exceeds the 128-character limit"
        raise ValueError(message)
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        message = "key_id must not contain control characters"
        raise ValueError(message)


def _validate_sha256_fingerprint(value: Sha256Digest) -> None:
    if type(value) is not str or _SHA256_DIGEST.fullmatch(value) is None:
        message = "key fingerprint must use sha256: plus lowercase hexadecimal"
        raise ValueError(message)


def _validate_logical_time(value: int) -> int:
    if type(value) is not int:
        message = "logical_time_ns must be an integer"
        raise TypeError(message)
    if not SIGNED_INT64_MIN <= value <= SIGNED_INT64_MAX:
        message = "logical_time_ns must fit a signed 64-bit integer"
        raise ValueError(message)
    return value


def _render_length_prefixed_template(
    template: CanonicalSigningTemplate,
    signing_input: SigningInput,
    *,
    timestamp_encoding: TimestampEncoding,
) -> bytes:
    version = template.version.encode("ascii")
    framed_components: list[tuple[bytes, bytes]] = []
    for component in template.components:
        if type(component) is bytes:
            tag = _FRAME_LITERAL_TAG
            value = component
        elif component is SigningInputToken.TIMESTAMP:
            tag = _FRAME_TIMESTAMP_TAG
            value = _encode_timestamp(
                signing_input.logical_time_ns,
                encoding=timestamp_encoding,
            )
        elif component is SigningInputToken.EVENT_ID:
            tag = _FRAME_EVENT_ID_TAG
            value = signing_input.event_id.encode("utf-8")
        else:
            tag = _FRAME_BODY_TAG
            value = signing_input.body
        framed_components.append((tag, value))

    framed_size = (
        len(LENGTH_PREFIXED_TEMPLATE_DOMAIN)
        + _FRAME_VERSION_LENGTH_BYTES
        + len(version)
        + 1
        + sum(len(tag) + _FRAME_VALUE_LENGTH_BYTES + len(value) for tag, value in framed_components)
    )
    if framed_size > MAX_SIGNING_INPUT_BYTES:
        message = "rendered signing input exceeds the bounded byte limit"
        raise ValueError(message)

    rendered = bytearray(LENGTH_PREFIXED_TEMPLATE_DOMAIN)
    rendered.extend(len(version).to_bytes(_FRAME_VERSION_LENGTH_BYTES, "big"))
    rendered.extend(version)
    rendered.extend(len(framed_components).to_bytes(1, "big"))
    for tag, value in framed_components:
        rendered.extend(tag)
        rendered.extend(len(value).to_bytes(_FRAME_VALUE_LENGTH_BYTES, "big"))
        rendered.extend(value)
    return bytes(rendered)


def _encode_timestamp(value: int, *, encoding: TimestampEncoding) -> bytes:
    if encoding is TimestampEncoding.ASCII_DECIMAL_NANOSECONDS:
        encoded = value
    else:
        encoded = value // NANOSECONDS_PER_SECOND
    return str(encoded).encode("ascii")


def _encode_bounded_text(
    value: str,
    *,
    field_name: str,
    maximum_bytes: int,
) -> bytes:
    if type(value) is not str:
        message = f"{field_name} must be a string"
        raise TypeError(message)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        message = f"{field_name} must be valid Unicode"
        raise ValueError(message) from None
    if len(encoded) > maximum_bytes:
        message = f"{field_name} exceeds its UTF-8 byte limit"
        raise ValueError(message)
    return encoded
