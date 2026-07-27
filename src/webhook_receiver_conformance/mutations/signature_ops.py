"""Versioned signature-state mutation operators."""
# ruff: noqa: INP001, SLF001

from __future__ import annotations

import base64
import hashlib
from typing import Final, cast

from webhook_receiver_conformance.config.models import EnvironmentSecretRef
from webhook_receiver_conformance.mutations.base import (
    MutationError,
    MutationInput,
    MutationOutput,
    MutationRegistration,
    MutationStage,
    SignatureHeaderAction,
    StaticMutationRegistry,
    thaw_parameter_object,
)
from webhook_receiver_conformance.secrets import SecretHandle, SecretResolver
from webhook_receiver_conformance.signatures.base import (
    SignatureHeader,
    Signer,
    SignerError,
)
from webhook_receiver_conformance.signatures.hmac_generic import GenericHmacSha256Signer
from webhook_receiver_conformance.signatures.standard_webhooks import (
    StandardWebhooksHmacSigner,
)
from webhook_receiver_conformance.signatures.stripe import StripeV1Signer

OPERATOR_VERSION: Final = 1
STALE_SIGNATURE_TIMESTAMP_V1: Final = "stale-signature-timestamp-v1"
WRONG_SIGNING_KEY_V1: Final = "wrong-signing-key-v1"
MISSING_SIGNATURE_V1: Final = "missing-signature-v1"
MALFORMED_SIGNATURE_V1: Final = "malformed-signature-v1"
MALFORMED_SIGNATURE_CASES: Final = (
    "invalid-encoding",
    "missing-component",
    "invalid-delimiter",
    "duplicate-component",
)
_WRONG_KEY_DOMAIN: Final = b"wrch-wrong-signing-key-v1\x00"
MAX_WRONG_KEY_CONTEXT_LENGTH: Final = 4096


def _parameters(
    mutation_input: MutationInput,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, object]:
    values = cast(
        "dict[str, object]",
        thaw_parameter_object(mutation_input.parameters),
    )
    if set(values) - required - optional or not required.issubset(values):
        raise _invalid(
            mutation_input,
            "MUT_SIGNATURE_PARAMETERS_INVALID",
            "The realized signature mutation parameters do not match the operator contract.",
        )
    return values


def _invalid(
    mutation_input: MutationInput,
    code: str,
    message: str,
) -> MutationError:
    realized = mutation_input.realized
    return MutationError.invalid_parameter(
        code,
        message,
        operator_id=realized.operator_id,
        operator_version=realized.operator_version,
    )


def _not_applicable(
    mutation_input: MutationInput,
    code: str,
    message: str,
) -> MutationError:
    realized = mutation_input.realized
    return MutationError.not_applicable(
        code,
        message,
        operator_id=realized.operator_id,
        operator_version=realized.operator_version,
    )


def _output(
    mutation_input: MutationInput,
    *,
    headers: tuple[SignatureHeader, ...] | None = None,
    signing_time_ns: int | None = None,
    signer: Signer | None = None,
) -> MutationOutput:
    state = mutation_input.state
    return MutationOutput(
        body=state.body,
        headers=state.headers if headers is None else headers,
        signing_time_ns=state.signing_time_ns if signing_time_ns is None else signing_time_ns,
        signer=state.signer if signer is None else signer,
    )


class StaleSignatureTimestampV1:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        values = _parameters(mutation_input, required=frozenset({"age_ns"}))
        age = values["age_ns"]
        if type(age) is not int or age <= 0:
            raise _invalid(
                mutation_input,
                "MUT_STALE_AGE_INVALID",
                "The stale-signature age must be a positive integer nanosecond value.",
            )
        signer = mutation_input.state.signer
        if signer is None:
            raise _not_applicable(
                mutation_input,
                "MUT_STALE_SIGNER_REQUIRED",
                "stale-signature-timestamp-v1 requires a selected signer.",
            )
        if signer.adapter_id == "generic-hmac-sha256":
            raise _not_applicable(
                mutation_input,
                "MUT_STALE_SIGNER_NOT_TIMESTAMPED",
                "stale-signature-timestamp-v1 requires a timestamped signer profile.",
            )
        stale = mutation_input.state.signing_time_ns - age
        if stale < 0:
            raise _invalid(
                mutation_input,
                "MUT_STALE_TIMESTAMP_NEGATIVE",
                "The stale-signature age precedes the timestamp domain.",
            )
        return _output(mutation_input, signing_time_ns=stale)


def _wrong_key_signer(delegate: Signer, context: bytes) -> Signer:
    if isinstance(delegate, GenericHmacSha256Signer):
        key_count = 1
    elif isinstance(delegate, (StripeV1Signer, StandardWebhooksHmacSigner)):
        key_count = len(delegate.key_fingerprints)
    else:
        raise TypeError

    handles: list[SecretHandle] = []
    try:
        for index in range(key_count):
            derived = hashlib.sha256(
                _WRONG_KEY_DOMAIN + index.to_bytes(4, "big") + context
            ).digest()
            encoded = (
                "whsec_" + base64.b64encode(derived).decode("ascii")
                if isinstance(delegate, StandardWebhooksHmacSigner)
                else derived.hex()
            )
            variable = f"WRCH_WRONG_TEST_KEY_{index}"
            reference = EnvironmentSecretRef(env=variable)
            handles.append(SecretResolver(environ={variable: encoded}).resolve(reference))

        primary, *additional = handles
        if isinstance(delegate, GenericHmacSha256Signer):
            replacement: Signer = GenericHmacSha256Signer(
                primary,
                delegate._settings,  # pyright: ignore[reportPrivateUsage]
            )
        elif isinstance(delegate, StripeV1Signer):
            replacement = StripeV1Signer(
                primary,
                delegate._settings,  # pyright: ignore[reportPrivateUsage]
                additional_secrets=tuple(additional),
            )
        else:
            replacement = StandardWebhooksHmacSigner(
                primary,
                delegate._settings,  # pyright: ignore[reportPrivateUsage]
                additional_secrets=tuple(additional),
            )

        _require_distinct_wrong_keys(delegate, replacement)
    except BaseException:
        for handle in handles:
            handle.close()
        raise
    else:
        return replacement


def _key_fingerprints(signer: Signer) -> tuple[str, ...]:
    if isinstance(signer, GenericHmacSha256Signer):
        return (signer.key_fingerprint,)
    if isinstance(signer, (StripeV1Signer, StandardWebhooksHmacSigner)):
        return signer.key_fingerprints
    raise TypeError


def _require_distinct_wrong_keys(original: Signer, replacement: Signer) -> None:
    original_fingerprints = _key_fingerprints(original)
    replacement_fingerprints = _key_fingerprints(replacement)
    if len(replacement_fingerprints) != len(set(replacement_fingerprints)) or set(
        original_fingerprints
    ) & set(replacement_fingerprints):
        raise ValueError


class WrongSigningKeyV1:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        values = _parameters(mutation_input, required=frozenset({"context"}))
        context = values["context"]
        if type(context) is not str or not 1 <= len(context) <= MAX_WRONG_KEY_CONTEXT_LENGTH:
            raise _invalid(
                mutation_input,
                "MUT_WRONG_KEY_CONTEXT_INVALID",
                "The wrong-key derivation context is invalid.",
            )
        try:
            context_bytes = context.encode("utf-8")
        except UnicodeEncodeError:
            raise _invalid(
                mutation_input,
                "MUT_WRONG_KEY_CONTEXT_INVALID",
                "The wrong-key derivation context is invalid.",
            ) from None
        if len(context_bytes) > MAX_WRONG_KEY_CONTEXT_LENGTH:
            raise _invalid(
                mutation_input,
                "MUT_WRONG_KEY_CONTEXT_INVALID",
                "The wrong-key derivation context is invalid.",
            )
        signer = mutation_input.state.signer
        if signer is None:
            raise _not_applicable(
                mutation_input,
                "MUT_WRONG_KEY_SIGNER_REQUIRED",
                "wrong-signing-key-v1 requires a selected signer.",
            )
        try:
            replacement = _wrong_key_signer(signer, context_bytes)
        except (SignerError, TypeError, ValueError):
            raise _not_applicable(
                mutation_input,
                "MUT_WRONG_KEY_SIGNER_UNSUPPORTED",
                "The selected signer cannot derive a deterministic wrong test key.",
            ) from None
        return _output(mutation_input, signer=replacement)


def _owned_header_names(mutation_input: MutationInput) -> frozenset[str]:
    signer = mutation_input.state.signer
    if signer is None:
        raise _not_applicable(
            mutation_input,
            "MUT_SIGNATURE_SIGNER_REQUIRED",
            "The signature-header mutation requires a selected signer.",
        )
    return frozenset(signer.owned_headers)


class MissingSignatureV1:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        _parameters(mutation_input, required=frozenset())
        owned = _owned_header_names(mutation_input)
        return _output(
            mutation_input,
            headers=tuple(
                header for header in mutation_input.state.headers if header.name not in owned
            ),
        )


class MalformedSignatureV1:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        values = _parameters(mutation_input, required=frozenset({"case"}))
        case = values["case"]
        if type(case) is not str or case not in MALFORMED_SIGNATURE_CASES:
            raise _invalid(
                mutation_input,
                "MUT_MALFORMED_SIGNATURE_CASE_INVALID",
                "The malformed-signature catalog case is unknown.",
            )
        owned = _owned_header_names(mutation_input)
        replacements = {
            name: SignatureHeader(name=name, value=_malformed_value(case)) for name in owned
        }
        result: list[SignatureHeader] = []
        replaced: set[str] = set()
        for header in mutation_input.state.headers:
            if header.name in replacements:
                result.append(replacements[header.name])
                replaced.add(header.name)
            else:
                result.append(header)
        result.extend(replacements[name] for name in sorted(owned - replaced))
        return _output(mutation_input, headers=tuple(result))


def _malformed_value(case: str) -> str:
    return {
        "invalid-encoding": "v1=!",
        "missing-component": "v1",
        "invalid-delimiter": "v1:00",
        "duplicate-component": "v1=00,v1=11",
    }[case]


SIGNATURE_MUTATION_REGISTRATIONS: Final = (
    MutationRegistration(
        operator_id=STALE_SIGNATURE_TIMESTAMP_V1,
        operator_version=OPERATOR_VERSION,
        stage=MutationStage.SIGNING,
        implementation=StaleSignatureTimestampV1(),
        may_change_signing_time=True,
    ),
    MutationRegistration(
        operator_id=WRONG_SIGNING_KEY_V1,
        operator_version=OPERATOR_VERSION,
        stage=MutationStage.SIGNING,
        implementation=WrongSigningKeyV1(),
        may_replace_signer=True,
    ),
    MutationRegistration(
        operator_id=MISSING_SIGNATURE_V1,
        operator_version=OPERATOR_VERSION,
        stage=MutationStage.HEADER_POST_SIGN,
        implementation=MissingSignatureV1(),
        signature_header_action=SignatureHeaderAction.REMOVE,
    ),
    MutationRegistration(
        operator_id=MALFORMED_SIGNATURE_V1,
        operator_version=OPERATOR_VERSION,
        stage=MutationStage.HEADER_POST_SIGN,
        implementation=MalformedSignatureV1(),
        signature_header_action=SignatureHeaderAction.REPLACE,
    ),
)
SIGNATURE_MUTATION_REGISTRY: Final = StaticMutationRegistry(SIGNATURE_MUTATION_REGISTRATIONS)

__all__ = [
    "MALFORMED_SIGNATURE_CASES",
    "MALFORMED_SIGNATURE_V1",
    "MISSING_SIGNATURE_V1",
    "SIGNATURE_MUTATION_REGISTRATIONS",
    "SIGNATURE_MUTATION_REGISTRY",
    "STALE_SIGNATURE_TIMESTAMP_V1",
    "WRONG_SIGNING_KEY_V1",
]
