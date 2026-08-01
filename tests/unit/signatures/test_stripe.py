"""Stripe v1 compatibility, rotation, security, and golden-vector tests."""
# ruff: noqa: INP001, PLW0108, TC003

from __future__ import annotations

import base64
import copy
import hmac as stdlib_hmac
import inspect
import io
import json
import pickle
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from webhook_receiver_conformance.config.models import (
    EnvironmentSecretRef,
    GeneratedSecretRef,
)
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.secrets import SecretHandle, SecretResolver
from webhook_receiver_conformance.signatures import stripe
from webhook_receiver_conformance.signatures.base import (
    BUILTIN_SIGNER_MODULES,
    BuiltinSignerCategory,
    SignatureEncoding,
    SignatureHeader,
    SignerError,
    SigningInput,
    VerificationReason,
    validate_builtin_registry_completeness,
)
from webhook_receiver_conformance.signatures.stripe import (
    BUILTIN_SIGNER_REGISTRY,
    MAX_STRIPE_SIGNING_SECRETS,
    SHA256_DIGEST_BYTES,
    STRIPE_SIGNATURE_HEADER,
    STRIPE_V1_ADAPTER_ID,
    STRIPE_V1_ADAPTER_VERSION,
    STRIPE_V1_REGISTRATION,
    STRIPE_V1_TEMPLATE_VERSION,
    StripeV1Settings,
    StripeV1Signer,
)

PRIMARY_KEY = "whsec_test_primary_32_byte_key_material"  # gitleaks:allow
ROTATION_KEY = "whsec_test_rotation_32_byte_key_material"  # gitleaks:allow
WRONG_KEY = "whsec_test_wrong_32_byte_key_material"  # gitleaks:allow
SECRET_CANARY = b"stripe-secret-canary-32-bytes!!!"
LOGICAL_TIME_NS = 1_700_000_000_123_456_789
BODY = b'{"id":"evt_1","ok":true}'
GOLDEN_PATH = Path(__file__).parents[2] / "golden" / "signatures" / "stripe.json"


def _handle(value: str, *, name: str = "STRIPE_KEY") -> SecretHandle:
    return SecretResolver(environ={name: value}).resolve(EnvironmentSecretRef(env=name))


def _input(
    body: bytes = BODY,
    *,
    event_id: str = "evt_stripe_contract",
    logical_time_ns: int = LOGICAL_TIME_NS,
) -> SigningInput:
    return SigningInput(
        body=body,
        event_id=event_id,
        logical_time_ns=logical_time_ns,
    )


def _signer(
    key: str = PRIMARY_KEY,
    *,
    rotation_key: str | None = None,
    settings: StripeV1Settings | None = None,
) -> StripeV1Signer:
    additional = (
        () if rotation_key is None else (_handle(rotation_key, name="STRIPE_ROTATION_KEY"),)
    )
    return StripeV1Signer(
        _handle(key),
        settings,
        additional_secrets=additional,
    )


def _golden() -> dict[str, object]:
    return cast("dict[str, object]", json.loads(GOLDEN_PATH.read_text(encoding="utf-8")))


def test_golden_vectors_lock_timestamp_dot_exact_body_and_header_order() -> None:
    golden = _golden()
    vectors = cast("list[dict[str, object]]", golden["vectors"])
    assert golden["profile"] == STRIPE_V1_ADAPTER_ID
    assert golden["adapter_version"] == STRIPE_V1_ADAPTER_VERSION
    assert golden["template_version"] == STRIPE_V1_TEMPLATE_VERSION
    assert golden["compatibility_review"] == {
        "status": "approved",
        "contract": "SIG-014",
        "marker": "stripe-v1-v1-reviewed-2026-07-27",
    }
    assert "secret" not in json.dumps(golden).casefold()

    single = _signer()
    rotation = _signer(rotation_key=ROTATION_KEY)
    assert golden["key_fingerprints"] == list(rotation.key_fingerprints)
    for vector in vectors:
        body = base64.b64decode(cast("str", vector["body_base64"]), validate=True)
        signing_input = _input(
            body,
            event_id=cast("str", vector["event_id"]),
            logical_time_ns=cast("int", vector["logical_time_ns"]),
        )
        canonical = single.canonical_message(signing_input)
        single_result = single.sign(signing_input)
        rotation_result = rotation.sign(signing_input)

        assert canonical == base64.b64decode(
            cast("str", vector["covered_bytes_base64"]),
            validate=True,
        )
        assert canonical == (str(vector["timestamp_seconds"]).encode("ascii") + b"." + body)
        assert sha256_digest(body) == vector["body_sha256"]
        assert sha256_digest(canonical) == vector["covered_bytes_sha256"]
        assert single_result.headers[0].value == vector["single_header"]
        assert rotation_result.headers[0].value == vector["rotation_header"]
        assert single.verify(signing_input, single_result.headers).valid
        assert rotation.verify(signing_input, rotation_result.headers).valid


def test_signing_evidence_is_exact_and_secret_free() -> None:
    signer = _signer(
        settings=StripeV1Settings(key_id="primary-key"),
    )
    signing_input = _input()
    result = signer.sign(signing_input)
    canonical = b"1700000000." + BODY

    assert result.evidence.model_dump() == {
        "adapter_id": STRIPE_V1_ADAPTER_ID,
        "adapter_version": STRIPE_V1_ADAPTER_VERSION,
        "template_version": STRIPE_V1_TEMPLATE_VERSION,
        "logical_time_ns": LOGICAL_TIME_NS,
        "body_sha256": sha256_digest(BODY),
        "covered_bytes_sha256": sha256_digest(canonical),
        "key_fingerprint": signer.key_fingerprint,
        "key_id": "primary-key",
        "output_encoding": SignatureEncoding.HEX.value,
    }
    signature = result.headers[0].value
    assert signature not in repr(result)
    assert PRIMARY_KEY not in repr(signer)
    assert PRIMARY_KEY not in json.dumps(result.evidence.model_dump(), sort_keys=True)


def test_rotation_header_has_two_independently_verifiable_v1_values() -> None:
    signer = _signer(rotation_key=ROTATION_KEY)
    signing_input = _input()
    header = signer.sign(signing_input).headers[0]
    timestamp, first, second = header.value.split(",")

    assert timestamp == "t=1700000000"
    assert first.startswith("v1=")
    assert second.startswith("v1=")
    assert first != second
    assert signer.verify(
        signing_input,
        (SignatureHeader(name=STRIPE_SIGNATURE_HEADER, value=f"{timestamp},{first}"),),
    ).valid
    assert signer.verify(
        signing_input,
        (SignatureHeader(name=STRIPE_SIGNATURE_HEADER, value=f"{timestamp},{second}"),),
    ).valid


def test_verification_uses_header_timestamp_and_leaves_recency_to_policy() -> None:
    stale_input = _input(logical_time_ns=1_600_000_000_000_000_000)
    stale_header = _signer().sign(stale_input).headers
    current_input = _input(logical_time_ns=1_700_000_000_000_000_000)

    assert _signer().verify(current_input, stale_header).valid


def test_verification_compares_all_key_signature_pairs_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[bytes | str, bytes | str]] = []
    original = stdlib_hmac.compare_digest

    def observed(first: bytes | str, second: bytes | str) -> bool:
        calls.append((first, second))
        if isinstance(first, str) and isinstance(second, str):
            return original(first, second)
        if isinstance(first, bytes) and isinstance(second, bytes):
            return original(first, second)
        message = "compare_digest inputs must have matching types"
        raise TypeError(message)

    monkeypatch.setattr(stripe.hmac, "compare_digest", observed)
    signer = _signer(rotation_key=ROTATION_KEY)
    signing_input = _input()
    header = signer.sign(signing_input).headers
    calls.clear()

    assert signer.verify(signing_input, header).valid
    digest_calls = [
        (first, second)
        for first, second in calls
        if isinstance(first, bytes)
        and isinstance(second, bytes)
        and len(first) == len(second) == SHA256_DIGEST_BYTES
    ]
    assert len(digest_calls) == 2 * 2
    assert "hmac.compare_digest" in inspect.getsource(StripeV1Signer.verify)


def test_wrong_key_and_altered_body_fail_without_exposing_values() -> None:
    producer = _signer()
    signing_input = _input()
    headers = producer.sign(signing_input).headers

    wrong = _signer(WRONG_KEY).verify(signing_input, headers)
    altered = producer.verify(_input(BODY + b" "), headers)

    assert not wrong.valid
    assert wrong.reason is VerificationReason.SIGNATURE_MISMATCH
    assert not altered.valid
    assert altered.reason is VerificationReason.SIGNATURE_MISMATCH
    assert wrong.evidence.key_fingerprint != producer.key_fingerprint


def test_missing_and_duplicate_signature_headers_are_distinct() -> None:
    signer = _signer()
    signing_input = _input()
    header = signer.sign(signing_input).headers[0]

    missing = signer.verify(signing_input, ())
    duplicate = signer.verify(signing_input, (header, header))

    assert missing.reason is VerificationReason.MISSING_HEADER
    assert duplicate.reason is VerificationReason.DUPLICATE_HEADER


@pytest.mark.parametrize(
    "value",
    [
        "",
        "t=1700000000",
        "v1=" + ("0" * 64),
        "t=01700000000,v1=" + ("0" * 64),
        "t=1700000000,t=1700000000,v1=" + ("0" * 64),
        "t=1700000000,v1=" + ("A" * 64),
        "t=1700000000, v1=" + ("0" * 64),
        "t=1700000000,v1=" + ("0" * 63),
        "t=1700000000,v1=" + ("0" * 65),
        "t=1700000000,v1=" + ("0" * 64) + ",broken",
        "t=1700000000,v1=" + ("0" * 64) + ",v0=bad value",
        "t=1700000000," + ",".join(f"v1={index:064x}" for index in range(9)),
    ],
)
def test_malformed_header_corpus_is_rejected_before_comparison(value: str) -> None:
    result = _signer().verify(
        _input(),
        (SignatureHeader(name=STRIPE_SIGNATURE_HEADER, value=value),),
    )

    assert not result.valid
    assert result.reason is VerificationReason.MALFORMED_HEADER


def test_unknown_well_formed_scheme_is_ignored_like_stripe_rotation_headers() -> None:
    signer = _signer()
    signing_input = _input()
    header = signer.sign(signing_input).headers[0]
    extended = SignatureHeader(
        name=STRIPE_SIGNATURE_HEADER,
        value=f"{header.value},v0={'0' * 64}",
    )

    assert signer.verify(signing_input, (extended,)).valid


def test_user_header_conflict_is_case_insensitive_and_classified() -> None:
    with pytest.raises(SignerError) as raised:
        _signer().validate_user_headers(("Stripe-Signature",))

    assert raised.value.diagnostic.code == "SIG_SIGNER_HEADER_CONFLICT"
    assert raised.value.diagnostic.category is ErrorCategory.CONFIGURATION_ERROR


def test_settings_and_rotation_key_shapes_are_strictly_bounded() -> None:
    with pytest.raises(TypeError, match="tuple"):
        StripeV1Settings(
            additional_key_ids=cast("tuple[str | None, ...]", ["rotation"]),
        )
    with pytest.raises(SignerError) as too_many_ids:
        StripeV1Settings(
            additional_key_ids=(None,) * MAX_STRIPE_SIGNING_SECRETS,
        )
    assert too_many_ids.value.diagnostic.code == "SIG_STRIPE_KEY_COUNT_INVALID"
    with pytest.raises(SignerError) as count_mismatch:
        StripeV1Signer(
            _handle(PRIMARY_KEY),
            StripeV1Settings(additional_key_ids=("rotation", "extra")),
            additional_secrets=(_handle(ROTATION_KEY, name="ROTATION_MISMATCH"),),
        )
    assert count_mismatch.value.diagnostic.code == "SIG_STRIPE_KEY_ID_COUNT_INVALID"
    with pytest.raises(TypeError, match="tuple"):
        StripeV1Signer(
            _handle(PRIMARY_KEY),
            additional_secrets=cast(
                "tuple[SecretHandle, ...]",
                [_handle(ROTATION_KEY, name="ROTATION")],
            ),
        )


def test_duplicate_and_excess_rotation_keys_are_rejected() -> None:
    duplicate = _handle(PRIMARY_KEY, name="DUPLICATE")
    with pytest.raises(SignerError) as repeated:
        StripeV1Signer(
            _handle(PRIMARY_KEY),
            StripeV1Settings(additional_key_ids=("duplicate",)),
            additional_secrets=(duplicate,),
        )
    assert repeated.value.diagnostic.code == "SIG_STRIPE_DUPLICATE_KEY"

    additional = tuple(
        _handle(f"key-{index}", name=f"KEY_{index}") for index in range(MAX_STRIPE_SIGNING_SECRETS)
    )
    with pytest.raises(SignerError) as too_many:
        StripeV1Signer(_handle(PRIMARY_KEY), additional_secrets=additional)
    assert too_many.value.diagnostic.code == "SIG_STRIPE_KEY_COUNT_INVALID"


def test_signer_constructor_accepts_only_opaque_secret_handles() -> None:
    for value in (PRIMARY_KEY, PRIMARY_KEY.encode(), bytearray(PRIMARY_KEY.encode())):
        with pytest.raises(TypeError, match="SecretHandle"):
            StripeV1Signer(value)  # pyright: ignore[reportArgumentType]


def test_signer_copy_pickle_bytes_and_model_dumps_are_canary_safe() -> None:
    signer = StripeV1Signer(
        SecretResolver(token_bytes=lambda _length: SECRET_CANARY).resolve(
            GeneratedSecretRef(generated="hmac-256")
        )
    )
    pickle_output = io.BytesIO()
    operations: tuple[Callable[[], object], ...] = (
        lambda: copy.copy(signer),
        lambda: copy.deepcopy(signer),
        lambda: bytes(signer),
        lambda: signer.model_dump(),
        lambda: signer.model_dump_json(),
        lambda: json.dumps(signer),
        lambda: pickle.Pickler(pickle_output).dump(signer),
    )

    for operation in operations:
        with pytest.raises(TypeError) as raised:
            operation()
        assert SECRET_CANARY not in (repr(raised.value) + str(raised.value)).encode()
    assert SECRET_CANARY not in pickle_output.getvalue()


def test_secret_callback_failure_drops_exception_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exception_canary = b"stripe-callback-exception-canary"

    def explode(
        _key: memoryview[int],
        _message: bytes,
        _digest: str,
    ) -> bytes:
        raise RuntimeError(SECRET_CANARY + exception_canary)

    monkeypatch.setattr(stripe.hmac, "digest", explode)
    signer = _signer()

    with pytest.raises(SignerError) as raised:
        signer.sign(_input())

    rendered = (
        repr(raised.value) + str(raised.value) + "".join(traceback.format_exception(raised.value))
    ).encode()
    assert raised.value.diagnostic.code == "SIG_SIGNING_FAILED"
    assert raised.value.__cause__ is None
    assert SECRET_CANARY not in rendered
    assert exception_canary not in rendered


def test_local_registration_and_protocol_contract_are_complete() -> None:
    signer = _signer()
    result = signer.sign(_input())

    validate_builtin_registry_completeness(
        BUILTIN_SIGNER_REGISTRY,
        implementation_types=(StripeV1Signer,),
        present_modules=(BUILTIN_SIGNER_MODULES[BuiltinSignerCategory.STRIPE_V1],),
    )
    assert BUILTIN_SIGNER_REGISTRY.registrations == (STRIPE_V1_REGISTRATION,)
    assert tuple(header.name for header in result.headers) == signer.owned_headers
    assert signer.verify(_input(), result.headers).valid


def test_canonical_message_preserves_subsecond_floor_and_binary_bytes() -> None:
    signer = _signer()
    first = _input(b"\x00\xffraw\r\n", logical_time_ns=1_999_999_999)
    second = _input(b"\x00\xffraw\r\n", logical_time_ns=2_000_000_000)

    assert signer.canonical_message(first) == b"1.\x00\xffraw\r\n"
    assert signer.canonical_message(second) == b"2.\x00\xffraw\r\n"
    assert signer.sign(first).headers != signer.sign(second).headers
