"""Versioned provider-independent generic HMAC-SHA256 signing."""
# ruff: noqa: BLE001, D105, D107, EM101, INP001, PLR0911, PLR2004

from __future__ import annotations

import base64
import binascii
import hmac
import re
from dataclasses import dataclass
from typing import ClassVar, Final, NoReturn

from webhook_receiver_conformance.secrets import SecretHandle
from webhook_receiver_conformance.signatures.base import (
    MAX_HEADER_VALUE_LENGTH,
    MAX_KEY_ID_LENGTH,
    MAX_SIGNER_HEADERS,
    BuiltinSignerCategory,
    CanonicalSigningTemplate,
    SignatureEncoding,
    SignatureHeader,
    Signer,
    SignerError,
    SignerRegistration,
    SigningEvidence,
    SigningInput,
    SigningInputToken,
    SigningResult,
    SigningTemplateRegistration,
    StaticSignerRegistry,
    StaticSigningTemplateRegistry,
    TemplateFraming,
    TimestampEncoding,
    VerificationReason,
    VerificationResult,
    signing_evidence,
    validate_builtin_registry_completeness,
    validate_header_ownership,
)

GENERIC_HMAC_SHA256_ADAPTER_ID: Final = BuiltinSignerCategory.GENERIC_HMAC_SHA256.value
GENERIC_HMAC_SHA256_ADAPTER_VERSION: Final = "v1"
GENERIC_HMAC_SHA256_TEMPLATE_VERSION: Final = "generic-hmac-sha256-body-v1"
GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_VERSION: Final = "generic-hmac-sha256-framed-ns-v1"
GENERIC_HMAC_SHA256_FRAMED_SECONDS_TEMPLATE_VERSION: Final = "generic-hmac-sha256-framed-seconds-v1"
DEFAULT_SIGNATURE_HEADER: Final = "x-webhook-signature"
MAX_SIGNATURE_PREFIX_LENGTH: Final = 128
SHA256_DIGEST_BYTES: Final = 32
SHA256_HEX_CHARACTERS: Final = SHA256_DIGEST_BYTES * 2
SHA256_BASE64_CHARACTERS: Final = 44

_LOWER_HEX_SIGNATURE = re.compile(r"[0-9a-f]{64}")

GENERIC_HMAC_SHA256_TEMPLATE_V1: Final = CanonicalSigningTemplate(
    version=GENERIC_HMAC_SHA256_TEMPLATE_VERSION,
    components=(SigningInputToken.BODY,),
    framing=TemplateFraming.EXACT_BODY_V1,
)
GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_V1: Final = CanonicalSigningTemplate(
    version=GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_VERSION,
    components=(
        SigningInputToken.TIMESTAMP,
        SigningInputToken.EVENT_ID,
        SigningInputToken.BODY,
    ),
)
GENERIC_HMAC_SHA256_FRAMED_SECONDS_TEMPLATE_V1: Final = CanonicalSigningTemplate(
    version=GENERIC_HMAC_SHA256_FRAMED_SECONDS_TEMPLATE_VERSION,
    components=(
        SigningInputToken.TIMESTAMP,
        SigningInputToken.EVENT_ID,
        SigningInputToken.BODY,
    ),
)
GENERIC_HMAC_SHA256_TEMPLATE_REGISTRY: Final = StaticSigningTemplateRegistry(
    (
        SigningTemplateRegistration(
            template=GENERIC_HMAC_SHA256_TEMPLATE_V1,
            timestamp_encoding=TimestampEncoding.ASCII_DECIMAL_NANOSECONDS,
        ),
        SigningTemplateRegistration(
            template=GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_V1,
            timestamp_encoding=TimestampEncoding.ASCII_DECIMAL_NANOSECONDS,
        ),
        SigningTemplateRegistration(
            template=GENERIC_HMAC_SHA256_FRAMED_SECONDS_TEMPLATE_V1,
            timestamp_encoding=TimestampEncoding.ASCII_DECIMAL_SECONDS_FLOOR,
        ),
    )
)


@dataclass(frozen=True, slots=True)
class GenericHmacSha256Settings:
    """Closed internal settings for the v1 generic HMAC profile.

    These settings are intentionally not a public serialized configuration
    model. The public project schema remains authoritative for what operators
    can configure in v0.1.
    """

    header_name: str = DEFAULT_SIGNATURE_HEADER
    prefix: str = ""
    template: CanonicalSigningTemplate = GENERIC_HMAC_SHA256_TEMPLATE_V1
    timestamp_encoding: TimestampEncoding = TimestampEncoding.ASCII_DECIMAL_NANOSECONDS
    output_encoding: SignatureEncoding = SignatureEncoding.HEX
    key_id: str | None = None

    def __post_init__(self) -> None:
        normalized = validate_header_ownership((self.header_name,))
        object.__setattr__(self, "header_name", normalized[0])
        _validate_prefix(self.prefix)
        if type(self.template) is not CanonicalSigningTemplate:
            message = "template must be a CanonicalSigningTemplate"
            raise TypeError(message)
        if type(self.timestamp_encoding) is not TimestampEncoding:
            message = "timestamp_encoding must be a TimestampEncoding member"
            raise TypeError(message)
        registered_template = GENERIC_HMAC_SHA256_TEMPLATE_REGISTRY.validate(
            self.template,
            self.timestamp_encoding,
        )
        object.__setattr__(self, "template", registered_template.template)
        object.__setattr__(
            self,
            "timestamp_encoding",
            registered_template.timestamp_encoding,
        )
        if type(self.output_encoding) is not SignatureEncoding:
            message = "output_encoding must be a SignatureEncoding member"
            raise TypeError(message)
        _validate_key_id(self.key_id)
        encoded_length = (
            SHA256_HEX_CHARACTERS
            if self.output_encoding is SignatureEncoding.HEX
            else SHA256_BASE64_CHARACTERS
        )
        if len(self.prefix) + encoded_length > MAX_HEADER_VALUE_LENGTH:
            raise SignerError.configuration(
                "SIG_SIGNATURE_HEADER_TOO_LARGE",
                "Configured signature prefix exceeds the header value limit.",
            )


class GenericHmacSha256Signer(Signer):
    """Exact-byte HMAC-SHA256 signer backed only by an opaque SecretHandle."""

    __slots__ = ("_secret", "_settings")

    BUILTIN_CATEGORY: ClassVar[BuiltinSignerCategory] = BuiltinSignerCategory.GENERIC_HMAC_SHA256

    def __init__(
        self,
        secret: SecretHandle,
        settings: GenericHmacSha256Settings | None = None,
    ) -> None:
        if type(secret) is not SecretHandle:
            message = "generic HMAC signer requires a SecretHandle"
            raise TypeError(message)
        if settings is not None and type(settings) is not GenericHmacSha256Settings:
            message = "settings must be GenericHmacSha256Settings or None"
            raise TypeError(message)
        self._secret = secret
        self._settings = GenericHmacSha256Settings() if settings is None else settings

    @property
    def adapter_id(self) -> str:
        """Return the stable generic adapter identifier."""
        return GENERIC_HMAC_SHA256_ADAPTER_ID

    @property
    def adapter_version(self) -> str:
        """Return the frozen v1 adapter implementation version."""
        return GENERIC_HMAC_SHA256_ADAPTER_VERSION

    @property
    def owned_headers(self) -> tuple[str, ...]:
        """Return the one normalized signature header owned by this signer."""
        return (self._settings.header_name,)

    @property
    def key_fingerprint(self) -> str:
        """Return only the resolver-produced, non-secret key fingerprint."""
        return str(self._secret.fingerprint)

    def validate_user_headers(self, user_header_names: tuple[str, ...]) -> None:
        """Reject case-insensitive user conflicts before request construction."""
        validate_header_ownership(
            self.owned_headers,
            user_header_names=user_header_names,
        )

    def canonical_message(self, signing_input: SigningInput) -> bytes:
        """Render the exact versioned message covered by this signer."""
        return self._settings.template.render(
            signing_input,
            timestamp_encoding=self._settings.timestamp_encoding,
        )

    def sign(self, signing_input: SigningInput) -> SigningResult:
        """Generate one deterministic signature header over exact input bytes."""
        canonical = self.canonical_message(signing_input)
        digest = self._digest(canonical)
        value = self._settings.prefix + _encode_digest(
            digest,
            encoding=self._settings.output_encoding,
        )
        return SigningResult(
            headers=(SignatureHeader(name=self._settings.header_name, value=value),),
            evidence=self._evidence(signing_input, canonical),
        )

    def verify(
        self,
        signing_input: SigningInput,
        headers: tuple[SignatureHeader, ...],
    ) -> VerificationResult:
        """Strictly decode and constant-time verify this signer's one header."""
        canonical = self.canonical_message(signing_input)
        evidence = self._evidence(signing_input, canonical)
        matching = _matching_headers(headers, name=self._settings.header_name)
        if not matching:
            return VerificationResult(
                valid=False,
                reason=VerificationReason.MISSING_HEADER,
                evidence=evidence,
            )
        if len(matching) != 1:
            return VerificationResult(
                valid=False,
                reason=VerificationReason.DUPLICATE_HEADER,
                evidence=evidence,
            )
        supplied = _decode_header_value(
            matching[0].value,
            prefix=self._settings.prefix,
            encoding=self._settings.output_encoding,
        )
        if supplied is None:
            return VerificationResult(
                valid=False,
                reason=VerificationReason.MALFORMED_HEADER,
                evidence=evidence,
            )
        expected = self._digest(canonical)
        valid = hmac.compare_digest(expected, supplied)
        return VerificationResult(
            valid=valid,
            reason=(VerificationReason.VALID if valid else VerificationReason.SIGNATURE_MISMATCH),
            evidence=evidence,
        )

    def _digest(self, canonical: bytes) -> bytes:
        failed = False

        def compute(key: memoryview[int]) -> bytes:
            nonlocal failed
            try:
                return hmac.digest(key, canonical, "sha256")
            except Exception:
                failed = True
                return b""

        digest = self._secret.use_with(compute)
        if failed or type(digest) is not bytes or len(digest) != SHA256_DIGEST_BYTES:
            raise SignerError.signing() from None
        return digest

    def _evidence(
        self,
        signing_input: SigningInput,
        canonical: bytes,
    ) -> SigningEvidence:
        return signing_evidence(
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            template_version=self._settings.template.version,
            signing_input=signing_input,
            covered_bytes=canonical,
            key_fingerprint=self._secret.fingerprint,
            key_id=self._settings.key_id,
            output_encoding=self._settings.output_encoding,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"adapter_version={self.adapter_version!r}, "
            f"header_name={self._settings.header_name!r}, "
            f"key_fingerprint={self.key_fingerprint!r}, "
            f"key_id={self._settings.key_id!r})"
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
        """Reject model-style serialization of a retained secret handle."""
        raise _nonserializable_error()

    def model_dump_json(self, *_args: object, **_kwargs: object) -> NoReturn:
        """Reject JSON serialization of a retained secret handle."""
        raise _nonserializable_error()


GENERIC_HMAC_SHA256_REGISTRATION: Final = SignerRegistration(
    category=BuiltinSignerCategory.GENERIC_HMAC_SHA256,
    adapter_version=GENERIC_HMAC_SHA256_ADAPTER_VERSION,
    implementation=GenericHmacSha256Signer,
)

BUILTIN_SIGNER_REGISTRY: Final = StaticSignerRegistry((GENERIC_HMAC_SHA256_REGISTRATION,))
validate_builtin_registry_completeness(BUILTIN_SIGNER_REGISTRY)


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


def _encode_digest(digest: bytes, *, encoding: SignatureEncoding) -> str:
    if encoding is SignatureEncoding.HEX:
        return digest.hex()
    return base64.b64encode(digest).decode("ascii")


def _decode_header_value(
    value: str,
    *,
    prefix: str,
    encoding: SignatureEncoding,
) -> bytes | None:
    if not value.startswith(prefix):
        return None
    encoded = value[len(prefix) :]
    if encoding is SignatureEncoding.HEX:
        if _LOWER_HEX_SIGNATURE.fullmatch(encoded) is None:
            return None
        return bytes.fromhex(encoded)
    if len(encoded) != SHA256_BASE64_CHARACTERS:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) != SHA256_DIGEST_BYTES or base64.b64encode(decoded).decode("ascii") != encoded:
        return None
    return decoded


def _validate_prefix(value: str) -> None:
    if type(value) is not str:
        message = "signature prefix must be a string"
        raise TypeError(message)
    if len(value) > MAX_SIGNATURE_PREFIX_LENGTH:
        raise SignerError.configuration(
            "SIG_SIGNATURE_PREFIX_INVALID",
            "Signature prefix exceeds the 128-character limit.",
        )
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise SignerError.configuration(
            "SIG_SIGNATURE_PREFIX_INVALID",
            "Signature prefix must contain visible ASCII characters.",
        ) from None
    if any(byte < 33 or byte == 127 for byte in encoded):
        raise SignerError.configuration(
            "SIG_SIGNATURE_PREFIX_INVALID",
            "Signature prefix must contain visible ASCII characters.",
        )


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
