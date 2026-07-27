"""Standard Webhooks HMAC-SHA256 signing and verification."""
# ruff: noqa: BLE001, D102, D105, D107, EM101, INP001, PLR2004, TRY003

from __future__ import annotations

import base64
import binascii
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

STANDARD_WEBHOOKS_ADAPTER_ID: Final = BuiltinSignerCategory.STANDARD_WEBHOOKS_HMAC.value
STANDARD_WEBHOOKS_HMAC_ADAPTER_ID: Final = STANDARD_WEBHOOKS_ADAPTER_ID
STANDARD_WEBHOOKS_ADAPTER_VERSION: Final = "v1"
STANDARD_WEBHOOKS_HMAC_ADAPTER_VERSION: Final = STANDARD_WEBHOOKS_ADAPTER_VERSION
STANDARD_WEBHOOKS_TEMPLATE_VERSION: Final = "standard-webhooks-id-timestamp-body-v1"
WEBHOOK_ID_HEADER: Final = "webhook-id"
WEBHOOK_TIMESTAMP_HEADER: Final = "webhook-timestamp"
WEBHOOK_SIGNATURE_HEADER: Final = "webhook-signature"
MAX_STANDARD_WEBHOOKS_SIGNING_SECRETS: Final = 8
MAX_SIGNATURE_COMPONENTS: Final = 16
SHA256_DIGEST_BYTES: Final = 32
SHA256_BASE64_CHARACTERS: Final = 44

_CANONICAL_INTEGER = re.compile(r"(?:0|-?[1-9][0-9]{0,18})")
_SIGNATURE_COMPONENT = re.compile(r"v1,([A-Za-z0-9+/]{43}=)")


@dataclass(frozen=True, slots=True)
class StandardWebhooksSettings:
    """Closed settings for the versioned Standard Webhooks profile."""

    header_name: str = WEBHOOK_SIGNATURE_HEADER
    key_id: str | None = None
    additional_key_ids: tuple[str | None, ...] = ()

    def __post_init__(self) -> None:
        normalized = validate_header_ownership(
            (WEBHOOK_ID_HEADER, WEBHOOK_TIMESTAMP_HEADER, self.header_name)
        )
        object.__setattr__(self, "header_name", normalized[2])
        _validate_key_id(self.key_id)
        if type(self.additional_key_ids) is not tuple:
            raise TypeError("additional_key_ids must be provided as a tuple")
        if len(self.additional_key_ids) >= MAX_STANDARD_WEBHOOKS_SIGNING_SECRETS:
            raise SignerError.configuration(
                "SIG_STANDARD_WEBHOOKS_KEY_COUNT_INVALID",
                "Standard Webhooks supports at most eight deterministic signing keys.",
            )
        for key_id in self.additional_key_ids:
            _validate_key_id(key_id)


class StandardWebhooksHmacSigner(Signer):
    """Exact-byte Standard Webhooks signer with deterministic key rotation."""

    __slots__ = ("_secrets", "_settings")

    BUILTIN_CATEGORY: ClassVar[BuiltinSignerCategory] = BuiltinSignerCategory.STANDARD_WEBHOOKS_HMAC

    def __init__(
        self,
        secret: SecretHandle,
        settings: StandardWebhooksSettings | None = None,
        *,
        additional_secrets: tuple[SecretHandle, ...] = (),
    ) -> None:
        if type(secret) is not SecretHandle:
            raise TypeError("Standard Webhooks signer requires a SecretHandle")
        if settings is not None and type(settings) is not StandardWebhooksSettings:
            raise TypeError("settings must be StandardWebhooksSettings or None")
        if type(additional_secrets) is not tuple:
            raise TypeError("additional_secrets must be provided as a tuple")
        if any(type(item) is not SecretHandle for item in additional_secrets):
            raise TypeError("additional_secrets must contain only SecretHandle values")
        secrets = (secret, *additional_secrets)
        if len(secrets) > MAX_STANDARD_WEBHOOKS_SIGNING_SECRETS:
            raise SignerError.configuration(
                "SIG_STANDARD_WEBHOOKS_KEY_COUNT_INVALID",
                "Standard Webhooks supports at most eight deterministic signing keys.",
            )
        resolved = StandardWebhooksSettings() if settings is None else settings
        if resolved.additional_key_ids and len(resolved.additional_key_ids) != len(
            additional_secrets
        ):
            raise SignerError.configuration(
                "SIG_STANDARD_WEBHOOKS_KEY_ID_COUNT_INVALID",
                "Additional key IDs must align with additional signing keys.",
            )
        fingerprints = tuple(str(item.fingerprint) for item in secrets)
        if len(fingerprints) != len(set(fingerprints)):
            raise SignerError.configuration(
                "SIG_STANDARD_WEBHOOKS_DUPLICATE_KEY",
                "Standard Webhooks signing keys must have distinct fingerprints.",
            )
        self._secrets = secrets
        self._settings = resolved

    @property
    def adapter_id(self) -> str:
        return STANDARD_WEBHOOKS_ADAPTER_ID

    @property
    def adapter_version(self) -> str:
        return STANDARD_WEBHOOKS_ADAPTER_VERSION

    @property
    def owned_headers(self) -> tuple[str, ...]:
        return (
            WEBHOOK_ID_HEADER,
            WEBHOOK_TIMESTAMP_HEADER,
            self._settings.header_name,
        )

    @property
    def key_fingerprint(self) -> str:
        return str(self._secrets[0].fingerprint)

    @property
    def key_fingerprints(self) -> tuple[str, ...]:
        return tuple(str(secret.fingerprint) for secret in self._secrets)

    def validate_user_headers(self, user_header_names: tuple[str, ...]) -> None:
        validate_header_ownership(self.owned_headers, user_header_names=user_header_names)

    def canonical_message(self, signing_input: SigningInput) -> bytes:
        if type(signing_input) is not SigningInput:
            raise TypeError("signing_input must be a SigningInput")
        timestamp = signing_input.logical_time_ns // NANOSECONDS_PER_SECOND
        return _canonical_message(signing_input.event_id, timestamp, signing_input.body)

    def sign(self, signing_input: SigningInput) -> SigningResult:
        canonical = self.canonical_message(signing_input)
        timestamp = signing_input.logical_time_ns // NANOSECONDS_PER_SECOND
        signatures = " ".join(
            f"v1,{base64.b64encode(digest).decode('ascii')}" for digest in self._digests(canonical)
        )
        if len(signatures) > MAX_HEADER_VALUE_LENGTH:
            raise SignerError.signing()
        return SigningResult(
            headers=(
                SignatureHeader(name=WEBHOOK_ID_HEADER, value=signing_input.event_id),
                SignatureHeader(name=WEBHOOK_TIMESTAMP_HEADER, value=str(timestamp)),
                SignatureHeader(name=self._settings.header_name, value=signatures),
            ),
            evidence=self._evidence(signing_input, canonical),
        )

    def verify(
        self,
        signing_input: SigningInput,
        headers: tuple[SignatureHeader, ...],
    ) -> VerificationResult:
        if type(signing_input) is not SigningInput:
            raise TypeError("signing_input must be a SigningInput")
        default_canonical = self.canonical_message(signing_input)
        default_evidence = self._evidence(signing_input, default_canonical)
        matched = {name: _matching_headers(headers, name=name) for name in self.owned_headers}
        if any(not values for values in matched.values()):
            return VerificationResult(
                valid=False,
                reason=VerificationReason.MISSING_HEADER,
                evidence=default_evidence,
            )
        if any(len(values) != 1 for values in matched.values()):
            return VerificationResult(
                valid=False,
                reason=VerificationReason.DUPLICATE_HEADER,
                evidence=default_evidence,
            )
        event_id = matched[WEBHOOK_ID_HEADER][0].value
        timestamp_text = matched[WEBHOOK_TIMESTAMP_HEADER][0].value
        supplied = _parse_signatures(matched[self._settings.header_name][0].value)
        timestamp = _parse_timestamp(timestamp_text)
        if timestamp is None or supplied is None:
            return VerificationResult(
                valid=False,
                reason=VerificationReason.MALFORMED_HEADER,
                evidence=default_evidence,
            )
        try:
            canonical = _canonical_message(event_id, timestamp, signing_input.body)
        except (TypeError, ValueError):
            return VerificationResult(
                valid=False,
                reason=VerificationReason.MALFORMED_HEADER,
                evidence=default_evidence,
            )
        evidence = self._evidence(signing_input, canonical)
        expected = self._digests(canonical)
        valid = False
        for expected_digest in expected:
            for supplied_digest in supplied:
                valid = hmac.compare_digest(expected_digest, supplied_digest) or valid
        return VerificationResult(
            valid=valid,
            reason=(VerificationReason.VALID if valid else VerificationReason.SIGNATURE_MISMATCH),
            evidence=evidence,
        )

    def _digests(self, canonical: bytes) -> tuple[bytes, ...]:
        digests: list[bytes] = []
        for secret in self._secrets:
            failed = False

            def compute(material: memoryview[int]) -> bytes:
                nonlocal failed
                try:
                    key = _decode_secret(bytes(material))
                    return hmac.digest(key, canonical, "sha256")
                except Exception:
                    failed = True
                    return b""

            digest = secret.use_with(compute)
            if failed or type(digest) is not bytes or len(digest) != SHA256_DIGEST_BYTES:
                raise SignerError.signing() from None
            digests.append(digest)
        return tuple(digests)

    def _evidence(self, signing_input: SigningInput, canonical: bytes) -> SigningEvidence:
        return signing_evidence(
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            template_version=STANDARD_WEBHOOKS_TEMPLATE_VERSION,
            signing_input=signing_input,
            covered_bytes=canonical,
            key_fingerprint=self._secrets[0].fingerprint,
            key_id=self._settings.key_id,
            output_encoding=SignatureEncoding.BASE64,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(adapter_version={self.adapter_version!r}, "
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
        raise _nonserializable_error()

    def model_dump_json(self, *_args: object, **_kwargs: object) -> NoReturn:
        raise _nonserializable_error()


StandardWebhooksSigner = StandardWebhooksHmacSigner

STANDARD_WEBHOOKS_REGISTRATION: Final = SignerRegistration(
    category=BuiltinSignerCategory.STANDARD_WEBHOOKS_HMAC,
    adapter_version=STANDARD_WEBHOOKS_ADAPTER_VERSION,
    implementation=StandardWebhooksHmacSigner,
)
BUILTIN_SIGNER_REGISTRY: Final = StaticSignerRegistry((STANDARD_WEBHOOKS_REGISTRATION,))
validate_builtin_registry_completeness(
    BUILTIN_SIGNER_REGISTRY,
    implementation_types=(StandardWebhooksHmacSigner,),
    present_modules=(BUILTIN_SIGNER_MODULES[BuiltinSignerCategory.STANDARD_WEBHOOKS_HMAC],),
)


def _decode_secret(material: bytes) -> bytes:
    encoded = material[6:] if material.startswith(b"whsec_") else material
    if not encoded:
        raise ValueError("invalid Standard Webhooks secret")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("invalid Standard Webhooks secret") from None
    if not decoded or base64.b64encode(decoded) != encoded:
        raise ValueError("invalid Standard Webhooks secret")
    return decoded


def _canonical_message(event_id: str, timestamp: int, body: bytes) -> bytes:
    if type(event_id) is not str or not event_id:
        raise ValueError("webhook ID must be a non-empty string")
    try:
        encoded_id = event_id.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("webhook ID must be valid Unicode") from None
    if any(byte < 32 or byte == 127 for byte in encoded_id):
        raise ValueError("webhook ID contains an invalid character")
    if type(timestamp) is not int:
        raise TypeError("webhook timestamp must be an integer")
    if type(body) is not bytes:
        raise TypeError("webhook body must be immutable bytes")
    rendered = encoded_id + b"." + str(timestamp).encode("ascii") + b"." + body
    if len(rendered) > MAX_SIGNING_INPUT_BYTES:
        raise ValueError("Standard Webhooks signing input exceeds the bounded byte limit")
    return rendered


def _parse_timestamp(value: str) -> int | None:
    if type(value) is not str or _CANONICAL_INTEGER.fullmatch(value) is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if str(parsed) == value else None


def _parse_signatures(value: str) -> tuple[bytes, ...] | None:
    if type(value) is not str or not value:
        return None
    components = value.split(" ")
    if not 1 <= len(components) <= MAX_SIGNATURE_COMPONENTS:
        return None
    decoded: list[bytes] = []
    for component in components:
        match = _SIGNATURE_COMPONENT.fullmatch(component)
        if match is None:
            return None
        try:
            digest = base64.b64decode(match.group(1), validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(digest) != SHA256_DIGEST_BYTES:
            return None
        decoded.append(digest)
    return tuple(decoded)


def _matching_headers(
    headers: tuple[SignatureHeader, ...],
    *,
    name: str,
) -> tuple[SignatureHeader, ...]:
    if type(headers) is not tuple:
        raise TypeError("verification headers must be provided as a tuple")
    if len(headers) > MAX_SIGNER_HEADERS:
        raise ValueError("verification headers exceed the bounded signer-header limit")
    matching: list[SignatureHeader] = []
    for header in headers:
        if type(header) is not SignatureHeader:
            raise TypeError("verification headers must be SignatureHeader values")
        if header.name == name:
            matching.append(header)
    return tuple(matching)


def _validate_key_id(value: str | None) -> None:
    if value is None:
        return
    if type(value) is not str:
        raise TypeError("key_id must be a string or None")
    if len(value) > MAX_KEY_ID_LENGTH or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise SignerError.configuration(
            "SIG_KEY_ID_INVALID",
            "Signer key ID is invalid.",
        )


def _nonserializable_error() -> TypeError:
    return TypeError("signers retaining secret handles cannot be copied or serialized")
