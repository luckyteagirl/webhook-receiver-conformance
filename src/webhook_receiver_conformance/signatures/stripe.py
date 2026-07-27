"""Stripe v1-compatible timestamped HMAC-SHA256 signing."""
# ruff: noqa: BLE001, C901, D105, D107, EM101, INP001, PLR0911, PLR0912, PLR2004

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import ClassVar, Final, NoReturn

from webhook_receiver_conformance.secrets import SecretHandle
from webhook_receiver_conformance.signatures.base import (
    BUILTIN_SIGNER_MODULES,
    MAX_HEADER_VALUE_LENGTH,
    MAX_KEY_ID_LENGTH,
    MAX_SIGNER_HEADERS,
    MAX_SIGNING_INPUT_BYTES,
    NANOSECONDS_PER_SECOND,
    BuiltinSignerCategory,
    SignatureEncoding,
    SignatureHeader,
    Signer,
    SignerError,
    SignerRegistration,
    SigningEvidence,
    SigningInput,
    SigningResult,
    StaticSignerRegistry,
    VerificationReason,
    VerificationResult,
    signing_evidence,
    validate_builtin_registry_completeness,
    validate_header_ownership,
)

STRIPE_V1_ADAPTER_ID: Final = BuiltinSignerCategory.STRIPE_V1.value
STRIPE_V1_ADAPTER_VERSION: Final = "v1"
STRIPE_V1_TEMPLATE_VERSION: Final = "stripe-v1-timestamp-dot-body-v1"
STRIPE_SIGNATURE_HEADER: Final = "stripe-signature"
MAX_STRIPE_SIGNING_SECRETS: Final = 8
MAX_STRIPE_HEADER_COMPONENTS: Final = 32
SHA256_DIGEST_BYTES: Final = 32
SHA256_HEX_CHARACTERS: Final = SHA256_DIGEST_BYTES * 2

_CANONICAL_INTEGER = re.compile(r"(?:0|-?[1-9][0-9]{0,18})")
_LOWER_HEX_SIGNATURE = re.compile(r"[0-9a-f]{64}")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")


@dataclass(frozen=True, slots=True)
class StripeV1Settings:
    """Closed settings for the versioned Stripe v1 profile."""

    header_name: str = STRIPE_SIGNATURE_HEADER
    key_id: str | None = None
    additional_key_ids: tuple[str | None, ...] = ()

    def __post_init__(self) -> None:
        normalized = validate_header_ownership((self.header_name,))
        object.__setattr__(self, "header_name", normalized[0])
        _validate_key_id(self.key_id)
        if type(self.additional_key_ids) is not tuple:
            message = "additional_key_ids must be provided as a tuple"
            raise TypeError(message)
        if len(self.additional_key_ids) >= MAX_STRIPE_SIGNING_SECRETS:
            raise SignerError.configuration(
                "SIG_STRIPE_KEY_COUNT_INVALID",
                "Stripe v1 supports at most eight deterministic signing keys.",
            )
        for key_id in self.additional_key_ids:
            _validate_key_id(key_id)


class StripeV1Signer(Signer):
    """Exact-byte Stripe v1 signer with deterministic key-rotation ordering."""

    __slots__ = ("_secrets", "_settings")

    BUILTIN_CATEGORY: ClassVar[BuiltinSignerCategory] = BuiltinSignerCategory.STRIPE_V1

    def __init__(
        self,
        secret: SecretHandle,
        settings: StripeV1Settings | None = None,
        *,
        additional_secrets: tuple[SecretHandle, ...] = (),
    ) -> None:
        if type(secret) is not SecretHandle:
            message = "Stripe v1 signer requires a SecretHandle"
            raise TypeError(message)
        if settings is not None and type(settings) is not StripeV1Settings:
            message = "settings must be StripeV1Settings or None"
            raise TypeError(message)
        if type(additional_secrets) is not tuple:
            message = "additional_secrets must be provided as a tuple"
            raise TypeError(message)
        if any(type(item) is not SecretHandle for item in additional_secrets):
            message = "additional_secrets must contain only SecretHandle values"
            raise TypeError(message)
        secrets = (secret, *additional_secrets)
        if len(secrets) > MAX_STRIPE_SIGNING_SECRETS:
            raise SignerError.configuration(
                "SIG_STRIPE_KEY_COUNT_INVALID",
                "Stripe v1 supports at most eight deterministic signing keys.",
            )
        resolved_settings = StripeV1Settings() if settings is None else settings
        if resolved_settings.additional_key_ids and len(
            resolved_settings.additional_key_ids
        ) != len(additional_secrets):
            raise SignerError.configuration(
                "SIG_STRIPE_KEY_ID_COUNT_INVALID",
                "Stripe v1 additional key IDs must align with additional signing keys.",
            )
        fingerprints = tuple(str(item.fingerprint) for item in secrets)
        if len(fingerprints) != len(set(fingerprints)):
            raise SignerError.configuration(
                "SIG_STRIPE_DUPLICATE_KEY",
                "Stripe v1 signing keys must have distinct fingerprints.",
            )
        self._secrets = secrets
        self._settings = resolved_settings

    @property
    def adapter_id(self) -> str:
        """Return the stable Stripe adapter identifier."""
        return STRIPE_V1_ADAPTER_ID

    @property
    def adapter_version(self) -> str:
        """Return the frozen Stripe v1 implementation version."""
        return STRIPE_V1_ADAPTER_VERSION

    @property
    def owned_headers(self) -> tuple[str, ...]:
        """Return the normalized Stripe signature header."""
        return (self._settings.header_name,)

    @property
    def key_fingerprint(self) -> str:
        """Return only the primary resolver-produced fingerprint."""
        return str(self._secrets[0].fingerprint)

    @property
    def key_fingerprints(self) -> tuple[str, ...]:
        """Return deterministic, secret-free fingerprints for rotation evidence."""
        return tuple(str(secret.fingerprint) for secret in self._secrets)

    def validate_user_headers(self, user_header_names: tuple[str, ...]) -> None:
        """Reject a caller-supplied Stripe signature header."""
        validate_header_ownership(
            self.owned_headers,
            user_header_names=user_header_names,
        )

    def canonical_message(self, signing_input: SigningInput) -> bytes:
        """Render ASCII Unix seconds, one dot, and exact body bytes."""
        if type(signing_input) is not SigningInput:
            message = "signing_input must be a SigningInput"
            raise TypeError(message)
        timestamp = signing_input.logical_time_ns // NANOSECONDS_PER_SECOND
        return _canonical_message(timestamp, signing_input.body)

    def sign(self, signing_input: SigningInput) -> SigningResult:
        """Generate one header with a timestamp and ordered v1 values."""
        canonical = self.canonical_message(signing_input)
        timestamp = signing_input.logical_time_ns // NANOSECONDS_PER_SECOND
        signatures = self._digests(canonical)
        value = ",".join((f"t={timestamp}", *(f"v1={signature.hex()}" for signature in signatures)))
        if len(value) > MAX_HEADER_VALUE_LENGTH:
            raise SignerError.signing()
        return SigningResult(
            headers=(SignatureHeader(name=self._settings.header_name, value=value),),
            evidence=self._evidence(signing_input, canonical),
        )

    def verify(
        self,
        signing_input: SigningInput,
        headers: tuple[SignatureHeader, ...],
    ) -> VerificationResult:
        """Strictly parse and constant-time verify all v1/key combinations."""
        if type(signing_input) is not SigningInput:
            message = "signing_input must be a SigningInput"
            raise TypeError(message)
        default_canonical = self.canonical_message(signing_input)
        default_evidence = self._evidence(signing_input, default_canonical)
        matching = _matching_headers(headers, name=self._settings.header_name)
        if not matching:
            return VerificationResult(
                valid=False,
                reason=VerificationReason.MISSING_HEADER,
                evidence=default_evidence,
            )
        if len(matching) != 1:
            return VerificationResult(
                valid=False,
                reason=VerificationReason.DUPLICATE_HEADER,
                evidence=default_evidence,
            )
        parsed = _parse_header(matching[0].value)
        if parsed is None:
            return VerificationResult(
                valid=False,
                reason=VerificationReason.MALFORMED_HEADER,
                evidence=default_evidence,
            )
        timestamp, supplied = parsed
        canonical = _canonical_message(timestamp, signing_input.body)
        evidence = self._evidence(signing_input, canonical)
        expected = self._digests(canonical)
        valid = False
        for expected_digest in expected:
            for supplied_digest in supplied:
                comparison = hmac.compare_digest(expected_digest, supplied_digest)
                valid = comparison or valid
        return VerificationResult(
            valid=valid,
            reason=(VerificationReason.VALID if valid else VerificationReason.SIGNATURE_MISMATCH),
            evidence=evidence,
        )

    def _digests(self, canonical: bytes) -> tuple[bytes, ...]:
        digests: list[bytes] = []
        for secret in self._secrets:
            failed = False

            def compute(key: memoryview[int]) -> bytes:
                nonlocal failed
                try:
                    return hmac.digest(key, canonical, "sha256")
                except Exception:
                    failed = True
                    return b""

            digest = secret.use_with(compute)
            if failed or type(digest) is not bytes or len(digest) != SHA256_DIGEST_BYTES:
                raise SignerError.signing() from None
            digests.append(digest)
        return tuple(digests)

    def _evidence(
        self,
        signing_input: SigningInput,
        canonical: bytes,
    ) -> SigningEvidence:
        return signing_evidence(
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            template_version=STRIPE_V1_TEMPLATE_VERSION,
            signing_input=signing_input,
            covered_bytes=canonical,
            key_fingerprint=self._secrets[0].fingerprint,
            key_id=self._settings.key_id,
            output_encoding=SignatureEncoding.HEX,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"adapter_version={self.adapter_version!r}, "
            f"header_name={self._settings.header_name!r}, "
            f"key_fingerprints={self.key_fingerprints!r}, "
            f"key_ids={(self._settings.key_id, *self._settings.additional_key_ids)!r})"
        )

    __str__ = __repr__

    def __copy__(self) -> NoReturn:
        raise _nonserializable_error()

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise _nonserializable_error()

    def __reduce__(self) -> NoReturn:
        raise _nonserializable_error()

    def __reduce_ex__(self, _protocol: object) -> NoReturn:
        raise _nonserializable_error()

    def __getstate__(self) -> NoReturn:
        raise _nonserializable_error()

    def __bytes__(self) -> NoReturn:
        raise _nonserializable_error()

    def model_dump(self, *_args: object, **_kwargs: object) -> NoReturn:
        """Reject model-style serialization of retained secret handles."""
        raise _nonserializable_error()

    def model_dump_json(self, *_args: object, **_kwargs: object) -> NoReturn:
        """Reject JSON serialization of retained secret handles."""
        raise _nonserializable_error()


STRIPE_V1_REGISTRATION: Final = SignerRegistration(
    category=BuiltinSignerCategory.STRIPE_V1,
    adapter_version=STRIPE_V1_ADAPTER_VERSION,
    implementation=StripeV1Signer,
)

BUILTIN_SIGNER_REGISTRY: Final = StaticSignerRegistry((STRIPE_V1_REGISTRATION,))
validate_builtin_registry_completeness(
    BUILTIN_SIGNER_REGISTRY,
    implementation_types=(StripeV1Signer,),
    present_modules=(BUILTIN_SIGNER_MODULES[BuiltinSignerCategory.STRIPE_V1],),
)


def _canonical_message(timestamp: int, body: bytes) -> bytes:
    if type(timestamp) is not int:
        message = "Stripe timestamp must be an integer"
        raise TypeError(message)
    if type(body) is not bytes:
        message = "Stripe body must be immutable bytes"
        raise TypeError(message)
    rendered = str(timestamp).encode("ascii") + b"." + body
    if len(rendered) > MAX_SIGNING_INPUT_BYTES:
        message = "Stripe signing input exceeds the bounded byte limit"
        raise ValueError(message)
    return rendered


def _parse_header(value: str) -> tuple[int, tuple[bytes, ...]] | None:
    if type(value) is not str or not value:
        return None
    components = value.split(",")
    if not 2 <= len(components) <= MAX_STRIPE_HEADER_COMPONENTS:
        return None
    timestamps: list[int] = []
    signatures: list[bytes] = []
    for component in components:
        if component.count("=") != 1:
            return None
        scheme, encoded = component.split("=", 1)
        if _SCHEME.fullmatch(scheme) is None or not encoded:
            return None
        if scheme == "t":
            if _CANONICAL_INTEGER.fullmatch(encoded) is None:
                return None
            try:
                timestamp = int(encoded)
            except ValueError:
                return None
            if str(timestamp) != encoded:
                return None
            timestamps.append(timestamp)
        elif scheme == "v1":
            if (
                len(signatures) >= MAX_STRIPE_SIGNING_SECRETS
                or _LOWER_HEX_SIGNATURE.fullmatch(encoded) is None
            ):
                return None
            signatures.append(bytes.fromhex(encoded))
        elif len(encoded) > SHA256_HEX_CHARACTERS or any(
            ord(character) < 33 or ord(character) == 127 for character in encoded
        ):
            return None
    if len(timestamps) != 1 or not signatures:
        return None
    return timestamps[0], tuple(signatures)


def _matching_headers(
    headers: tuple[SignatureHeader, ...],
    *,
    name: str,
) -> tuple[SignatureHeader, ...]:
    if type(headers) is not tuple:
        message = "verification headers must be provided as a tuple"
        raise TypeError(message)
    if len(headers) > MAX_SIGNER_HEADERS:
        message = "verification headers exceed the bounded signer-header limit"
        raise ValueError(message)
    matching: list[SignatureHeader] = []
    for header in headers:
        if type(header) is not SignatureHeader:
            message = "verification headers must be SignatureHeader values"
            raise TypeError(message)
        if header.name == name:
            matching.append(header)
    return tuple(matching)


def _validate_key_id(value: str | None) -> None:
    if value is None:
        return
    if type(value) is not str:
        message = "key_id must be a string or None"
        raise TypeError(message)
    if len(value) > MAX_KEY_ID_LENGTH:
        raise SignerError.configuration(
            "SIG_KEY_ID_INVALID",
            "Signer key ID exceeds the 128-character limit.",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SignerError.configuration(
            "SIG_KEY_ID_INVALID",
            "Signer key ID must not contain control characters.",
        )


def _nonserializable_error() -> TypeError:
    return TypeError("signers retaining secret handles cannot be copied or serialized")
