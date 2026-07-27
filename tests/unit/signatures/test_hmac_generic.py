"""Contract, vector, boundary, and secret-safety tests for generic HMAC."""
# ruff: noqa: D105, D107, FBT003, I001, INP001, PLR2004, PLW0108, S105, TC003, TC006

from __future__ import annotations

import base64
import copy
import gc
import hmac as stdlib_hmac
import inspect
import io
import json
import pickle
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path
from types import MappingProxyType
from typing import cast, overload

import pytest

import webhook_receiver_conformance.signatures.base as signer_base
import webhook_receiver_conformance.signatures.hmac_generic as generic_hmac
from webhook_receiver_conformance.config.models import (
    EnvironmentSecretRef,
    GeneratedSecretRef,
)
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.errors import ErrorCategory, ResultCategory
from webhook_receiver_conformance.secrets import (
    GENERATED_HMAC_KEY_BYTES,
    SecretHandle,
    SecretResolutionError,
    SecretResolver,
    secret_fingerprint,
)
from webhook_receiver_conformance.signatures.base import (
    BUILTIN_SIGNER_MODULES,
    LENGTH_PREFIXED_TEMPLATE_DOMAIN,
    MAX_USER_HEADERS,
    MAX_SIGNING_BODY_BYTES,
    BuiltinSignerCategory,
    CanonicalSigningTemplate,
    SignatureEncoding,
    SignatureHeader,
    Signer,
    SignerError,
    SigningInput,
    SigningInputToken,
    SignerRegistration,
    SigningTemplateRegistration,
    StaticSigningTemplateRegistry,
    StaticSignerRegistry,
    TemplateFraming,
    TimestampEncoding,
    VerificationReason,
    discover_builtin_signer_implementations,
    discover_builtin_signer_modules,
    validate_builtin_registry_completeness,
    validate_header_ownership,
)
from webhook_receiver_conformance.signatures.hmac_generic import (
    BUILTIN_SIGNER_REGISTRY,
    DEFAULT_SIGNATURE_HEADER,
    GENERIC_HMAC_SHA256_ADAPTER_ID,
    GENERIC_HMAC_SHA256_ADAPTER_VERSION,
    GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_V1,
    GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_VERSION,
    GENERIC_HMAC_SHA256_FRAMED_SECONDS_TEMPLATE_V1,
    GENERIC_HMAC_SHA256_FRAMED_SECONDS_TEMPLATE_VERSION,
    GENERIC_HMAC_SHA256_REGISTRATION,
    GENERIC_HMAC_SHA256_TEMPLATE_REGISTRY,
    GENERIC_HMAC_SHA256_TEMPLATE_VERSION,
    GenericHmacSha256Settings,
    GenericHmacSha256Signer,
)

RFC_4231_KEY = "Jefe"
RFC_4231_BODY = b"what do ya want for nothing?"
RFC_4231_SHA256_HEX = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
RFC_4231_SHA256_BASE64 = "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM="
SECRET_CANARY = b"signer-secret-canary-32-bytes!!!"
LOGICAL_TIME_NS = 1_700_000_000_123_456_789


@dataclass(frozen=True, slots=True)
class SignerContractCase:
    """One registry-linked constructor for the shared signer contract suite."""

    registration: SignerRegistration
    build: Callable[[], Signer]


class LyingInfiniteHeaderSequence(Sequence[str]):
    """Sequence that lies about length and never raises IndexError."""

    def __init__(self) -> None:
        self.item_requests = 0
        self.length_requests = 0

    def __len__(self) -> int:
        self.length_requests += 1
        return 0

    @overload
    def __getitem__(self, index: int) -> str: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[str]: ...

    def __getitem__(self, index: int | slice) -> str | Sequence[str]:
        if isinstance(index, slice):
            return ()
        self.item_requests += 1
        return f"x-infinite-{index}"


class LyingFiniteHeaderSequence(Sequence[str]):
    """Finite sequence whose declared length is intentionally enormous."""

    def __init__(self, values: tuple[str, ...]) -> None:
        self._values = values
        self.length_requests = 0

    def __len__(self) -> int:
        self.length_requests += 1
        return 1_000_000_000

    @overload
    def __getitem__(self, index: int) -> str: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[str]: ...

    def __getitem__(self, index: int | slice) -> str | Sequence[str]:
        return self._values[index]


CONTRACT_CASES = (
    SignerContractCase(
        registration=GENERIC_HMAC_SHA256_REGISTRATION,
        build=lambda: _signer(),
    ),
)


def _handle(key: str = RFC_4231_KEY) -> SecretHandle:
    return SecretResolver(environ={"SIGNING_KEY": key}).resolve(
        EnvironmentSecretRef(env="SIGNING_KEY")
    )


def _signer(
    key: str = RFC_4231_KEY,
    settings: GenericHmacSha256Settings | None = None,
) -> GenericHmacSha256Signer:
    return GenericHmacSha256Signer(_handle(key), settings)


def _input(
    body: bytes = RFC_4231_BODY,
    *,
    event_id: str = "evt_contract_1",
    logical_time_ns: int = LOGICAL_TIME_NS,
) -> SigningInput:
    return SigningInput(
        body=body,
        event_id=event_id,
        logical_time_ns=logical_time_ns,
    )


def _signature(signer: GenericHmacSha256Signer, signing_input: SigningInput) -> str:
    return signer.sign(signing_input).headers[0].value


def _expected_frame(
    version: str,
    components: tuple[tuple[int, bytes], ...],
) -> bytes:
    rendered = bytearray(LENGTH_PREFIXED_TEMPLATE_DOMAIN)
    encoded_version = version.encode("ascii")
    rendered.extend(len(encoded_version).to_bytes(2, "big"))
    rendered.extend(encoded_version)
    rendered.extend(len(components).to_bytes(1, "big"))
    for tag, value in components:
        rendered.extend(bytes((tag,)))
        rendered.extend(len(value).to_bytes(8, "big"))
        rendered.extend(value)
    return bytes(rendered)


def _assert_signer_contract(case: SignerContractCase) -> None:
    signer = case.build()
    signing_input = _input()

    assert isinstance(signer, Signer)
    assert type(signer) is case.registration.implementation
    assert signer.adapter_id == case.registration.adapter_id
    assert signer.adapter_version == case.registration.adapter_version
    assert signer.owned_headers
    assert signer.owned_headers == tuple(name.casefold() for name in signer.owned_headers)

    result = signer.sign(signing_input)
    assert tuple(header.name for header in result.headers) == signer.owned_headers
    assert result.evidence.adapter_id == signer.adapter_id
    assert result.evidence.adapter_version == signer.adapter_version
    verified = signer.verify(signing_input, result.headers)
    assert verified.valid
    assert verified.reason is VerificationReason.VALID
    assert verified.evidence == result.evidence


@pytest.mark.parametrize("case", CONTRACT_CASES, ids=lambda case: case.registration.adapter_id)
def test_every_registered_implementation_passes_shared_contract(
    case: SignerContractCase,
) -> None:
    _assert_signer_contract(case)


def test_registry_and_contract_case_completeness_are_locked_together() -> None:
    contract_types = {case.registration.implementation for case in CONTRACT_CASES}
    registered_types = {
        registration.implementation for registration in BUILTIN_SIGNER_REGISTRY.registrations
    }
    package_implementations = set(discover_builtin_signer_implementations())
    package_modules = discover_builtin_signer_modules()

    validate_builtin_registry_completeness(BUILTIN_SIGNER_REGISTRY)

    assert tuple(case.registration for case in CONTRACT_CASES) == (
        GENERIC_HMAC_SHA256_REGISTRATION,
    )
    assert package_modules == (generic_hmac.__name__,)
    assert contract_types == registered_types == package_implementations
    assert set(BUILTIN_SIGNER_MODULES) == set(BuiltinSignerCategory)
    assert {
        category.value: module_name for category, module_name in BUILTIN_SIGNER_MODULES.items()
    } == {
        "generic-hmac-sha256": "webhook_receiver_conformance.signatures.hmac_generic",
        "stripe-v1": "webhook_receiver_conformance.signatures.stripe",
        "standard-webhooks-hmac": ("webhook_receiver_conformance.signatures.standard_webhooks"),
    }
    assert BUILTIN_SIGNER_REGISTRY.adapter_ids == (GENERIC_HMAC_SHA256_ADAPTER_ID,)
    assert BUILTIN_SIGNER_REGISTRY.categories == (BuiltinSignerCategory.GENERIC_HMAC_SHA256,)
    assert (
        BUILTIN_SIGNER_REGISTRY.registration(GENERIC_HMAC_SHA256_ADAPTER_ID)
        is GENERIC_HMAC_SHA256_REGISTRATION
    )


def test_closed_category_inventory_rejects_cross_module_and_future_evasion() -> None:
    stripe_module = BUILTIN_SIGNER_MODULES[BuiltinSignerCategory.STRIPE_V1]

    class CrossModuleFakeSigner(GenericHmacSha256Signer):
        BUILTIN_CATEGORY = BuiltinSignerCategory.STRIPE_V1

    CrossModuleFakeSigner.__module__ = stripe_module
    try:
        with pytest.raises(SignerError) as missing_registration:
            validate_builtin_registry_completeness(
                BUILTIN_SIGNER_REGISTRY,
                implementation_types=(
                    GenericHmacSha256Signer,
                    CrossModuleFakeSigner,
                ),
                present_modules=(generic_hmac.__name__, stripe_module),
            )
        assert missing_registration.value.diagnostic.code == "SIG_BUILTIN_REGISTRY_INCOMPLETE"

        with pytest.raises(SignerError) as undeclared_module:
            validate_builtin_registry_completeness(
                BUILTIN_SIGNER_REGISTRY,
                present_modules=(
                    generic_hmac.__name__,
                    "webhook_receiver_conformance.signatures.future_signer",
                ),
            )
        assert undeclared_module.value.diagnostic.code == "SIG_BUILTIN_MODULE_UNDECLARED"
    finally:
        del CrossModuleFakeSigner
        gc.collect()


def test_module_inventory_recurses_without_importing_package_or_native_artifacts(
    tmp_path: Path,
) -> None:
    (tmp_path / "__init__.py").write_text(
        "raise RuntimeError('must not import')",
        encoding="utf-8",
    )
    (tmp_path / "base.py").write_text(
        "raise RuntimeError('must not import')",
        encoding="utf-8",
    )
    (tmp_path / "hmac_generic.py").write_text(
        "raise RuntimeError('must not import')",
        encoding="utf-8",
    )
    (tmp_path / "ignored.pyi").write_text("", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "__init__.py").write_text(
        "raise RuntimeError('must not import')",
        encoding="utf-8",
    )
    native_suffix = EXTENSION_SUFFIXES[0]
    (nested / f"native{native_suffix}").write_bytes(b"not-loadable")
    (tmp_path / f"base{native_suffix}").write_bytes(b"not-loadable")

    modules = discover_builtin_signer_modules(
        tmp_path,
        package_module="test_signatures",
    )

    assert modules == (
        "test_signatures",
        "test_signatures.base",
        "test_signatures.hmac_generic",
        "test_signatures.nested",
        "test_signatures.nested.native",
    )


def test_recursive_and_native_unregistered_signer_modules_fail_completeness(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "rogue"
    nested.mkdir()
    (nested / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / f"native{EXTENSION_SUFFIXES[0]}").write_bytes(b"not-loadable")
    modules = discover_builtin_signer_modules(
        tmp_path,
        package_module="webhook_receiver_conformance.signatures",
    )

    assert "webhook_receiver_conformance.signatures.native" in modules
    assert "webhook_receiver_conformance.signatures.rogue" in modules
    with pytest.raises(SignerError) as captured:
        validate_builtin_registry_completeness(
            BUILTIN_SIGNER_REGISTRY,
            implementation_types=(GenericHmacSha256Signer,),
            present_modules=(generic_hmac.__name__, *modules),
        )
    assert captured.value.diagnostic.code == "SIG_BUILTIN_MODULE_UNDECLARED"


def test_added_enum_and_mapping_category_cannot_expand_adr024_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExpandedBuiltinSignerCategory(StrEnum):
        GENERIC_HMAC_SHA256 = "generic-hmac-sha256"
        STRIPE_V1 = "stripe-v1"
        STANDARD_WEBHOOKS_HMAC = "standard-webhooks-hmac"
        FUTURE = "future"

    expanded_modules = MappingProxyType(
        {
            ExpandedBuiltinSignerCategory.GENERIC_HMAC_SHA256: BUILTIN_SIGNER_MODULES[
                BuiltinSignerCategory.GENERIC_HMAC_SHA256
            ],
            ExpandedBuiltinSignerCategory.STRIPE_V1: BUILTIN_SIGNER_MODULES[
                BuiltinSignerCategory.STRIPE_V1
            ],
            ExpandedBuiltinSignerCategory.STANDARD_WEBHOOKS_HMAC: BUILTIN_SIGNER_MODULES[
                BuiltinSignerCategory.STANDARD_WEBHOOKS_HMAC
            ],
            ExpandedBuiltinSignerCategory.FUTURE: (
                "webhook_receiver_conformance.signatures.future"
            ),
        }
    )
    monkeypatch.setattr(
        signer_base,
        "BuiltinSignerCategory",
        ExpandedBuiltinSignerCategory,
    )
    monkeypatch.setattr(signer_base, "BUILTIN_SIGNER_MODULES", expanded_modules)

    with pytest.raises(SignerError) as captured:
        validate_builtin_registry_completeness(
            BUILTIN_SIGNER_REGISTRY,
            implementation_types=(GenericHmacSha256Signer,),
            present_modules=(generic_hmac.__name__,),
        )
    assert captured.value.diagnostic.code == "SIG_BUILTIN_REGISTRY_INCOMPLETE"


def test_static_registry_rejects_duplicates_and_unknown_adapters_classifiably() -> None:
    with pytest.raises(SignerError) as duplicate:
        StaticSignerRegistry((GENERIC_HMAC_SHA256_REGISTRATION, GENERIC_HMAC_SHA256_REGISTRATION))
    assert duplicate.value.diagnostic.category is ErrorCategory.CONFIGURATION_ERROR
    assert duplicate.value.diagnostic.code == "SIG_DUPLICATE_ADAPTER"
    assert duplicate.value.diagnostic.result_category is ResultCategory.INVALID_INPUT

    with pytest.raises(SignerError) as unknown:
        BUILTIN_SIGNER_REGISTRY.registration("unregistered-adapter")
    assert unknown.value.diagnostic.category is ErrorCategory.UNSUPPORTED_ALGORITHM
    assert unknown.value.diagnostic.code == "SIG_UNSUPPORTED_ADAPTER"
    assert unknown.value.diagnostic.result_category is ResultCategory.UNSUPPORTED


def test_registration_enforces_closed_category_and_owning_module() -> None:
    class MisplacedSigner(GenericHmacSha256Signer):
        BUILTIN_CATEGORY = BuiltinSignerCategory.STRIPE_V1

    with pytest.raises(SignerError) as category_conflict:
        SignerRegistration(
            category=BuiltinSignerCategory.GENERIC_HMAC_SHA256,
            adapter_version="v1",
            implementation=MisplacedSigner,
        )
    assert category_conflict.value.diagnostic.code == "SIG_BUILTIN_CATEGORY_CONFLICT"

    with pytest.raises(SignerError) as module_conflict:
        SignerRegistration(
            category=BuiltinSignerCategory.STRIPE_V1,
            adapter_version="v1",
            implementation=MisplacedSigner,
        )
    assert module_conflict.value.diagnostic.code == "SIG_BUILTIN_MODULE_CONFLICT"


def test_registry_and_generic_signer_have_no_plugin_or_provider_import_path() -> None:
    source = inspect.getsource(signer_base) + inspect.getsource(generic_hmac)

    assert "entry_points" not in source
    assert "importlib.metadata" not in source
    assert "__import__(" not in source
    assert "import stripe" not in source.casefold()
    assert "import standard_webhooks" not in source.casefold()


def test_rfc_4231_sha256_vector_matches_exact_body_bytes() -> None:
    signer = _signer()
    signing_input = _input(RFC_4231_BODY, event_id="", logical_time_ns=0)

    result = signer.sign(signing_input)

    assert result.headers == (
        SignatureHeader(name=DEFAULT_SIGNATURE_HEADER, value=RFC_4231_SHA256_HEX),
    )
    assert result.evidence.adapter_id == GENERIC_HMAC_SHA256_ADAPTER_ID
    assert result.evidence.adapter_version == GENERIC_HMAC_SHA256_ADAPTER_VERSION
    assert result.evidence.template_version == GENERIC_HMAC_SHA256_TEMPLATE_VERSION
    assert result.evidence.body_sha256 == sha256_digest(RFC_4231_BODY)
    assert result.evidence.covered_bytes_sha256 == sha256_digest(RFC_4231_BODY)


def test_rfc_4231_base64_vector_prefix_and_configured_header_match() -> None:
    settings = GenericHmacSha256Settings(
        header_name="X-Receiver-Signature",
        prefix="hmac=",
        output_encoding=SignatureEncoding.BASE64,
        key_id="rotation-a",
    )
    signer = _signer(settings=settings)

    result = signer.sign(_input(RFC_4231_BODY))

    assert result.headers == (
        SignatureHeader(
            name="x-receiver-signature",
            value=f"hmac={RFC_4231_SHA256_BASE64}",
        ),
    )
    assert result.evidence.output_encoding is SignatureEncoding.BASE64
    assert result.evidence.key_id == "rotation-a"
    assert signer.verify(_input(RFC_4231_BODY), result.headers).valid


def test_default_profile_does_not_add_newline_or_decode_json() -> None:
    signer = _signer()
    binary_body = b'\xff\xfe{"valid": false}\x00'

    assert signer.canonical_message(_input(binary_body)) is binary_body
    assert _signature(signer, _input(RFC_4231_BODY)) == RFC_4231_SHA256_HEX
    assert _signature(signer, _input(RFC_4231_BODY + b"\n")) != RFC_4231_SHA256_HEX
    assert len(_signature(signer, _input(binary_body))) == 64


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (b'{"a":1}', b'{"a": 1}'),
        (b'{"a":1}', b'{\n  "a": 1\n}'),
        (b"payload", b"payload "),
        (b"payload\n", b"payload\r\n"),
    ],
)
def test_whitespace_only_changes_alter_the_exact_byte_signature(
    first: bytes,
    second: bytes,
) -> None:
    signer = _signer()

    assert _signature(signer, _input(first)) != _signature(signer, _input(second))


def test_registered_multi_token_template_uses_explicit_injective_framing() -> None:
    settings = GenericHmacSha256Settings(
        template=GENERIC_HMAC_SHA256_FRAMED_SECONDS_TEMPLATE_V1,
        timestamp_encoding=TimestampEncoding.ASCII_DECIMAL_SECONDS_FLOOR,
        prefix="sha256=",
    )
    signer = _signer(settings=settings)
    signing_input = _input(b'{"ok":true}', event_id="evt_42")
    expected_message = _expected_frame(
        GENERIC_HMAC_SHA256_FRAMED_SECONDS_TEMPLATE_VERSION,
        (
            (1, b"1700000000"),
            (2, b"evt_42"),
            (3, b'{"ok":true}'),
        ),
    )
    expected = stdlib_hmac.digest(
        RFC_4231_KEY.encode(),
        expected_message,
        "sha256",
    ).hex()

    assert signer.canonical_message(signing_input) == expected_message
    assert _signature(signer, signing_input) == f"sha256={expected}"
    assert signer.sign(signing_input).evidence.covered_bytes_sha256 == sha256_digest(
        expected_message
    )


def test_nanosecond_timestamp_encoding_is_exact_ascii_decimal() -> None:
    signer = _signer(
        settings=GenericHmacSha256Settings(
            template=GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_V1,
            timestamp_encoding=TimestampEncoding.ASCII_DECIMAL_NANOSECONDS,
        )
    )
    expected = _expected_frame(
        GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_VERSION,
        (
            (1, b"-123"),
            (2, b"evt_contract_1"),
            (3, RFC_4231_BODY),
        ),
    )

    assert signer.canonical_message(_input(logical_time_ns=-123)) == expected


def test_scaled_replay_reuses_manifest_logical_time_and_signature_bytes() -> None:
    settings = GenericHmacSha256Settings(
        template=GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_V1,
        timestamp_encoding=TimestampEncoding.ASCII_DECIMAL_NANOSECONDS,
    )
    source = _signer(settings=settings)
    scaled_replay = _signer(settings=settings)
    manifest_input = _input(b"replayed exact bytes", logical_time_ns=45_000_000_007)

    source_result = source.sign(manifest_input)
    replay_result = scaled_replay.sign(manifest_input)

    assert replay_result.headers == source_result.headers
    assert replay_result.evidence.logical_time_ns == source_result.evidence.logical_time_ns
    assert replay_result.evidence.covered_bytes_sha256 == (
        source_result.evidence.covered_bytes_sha256
    )
    assert (
        _signature(
            scaled_replay,
            _input(b"replayed exact bytes", logical_time_ns=45_000_000_008),
        )
        != source_result.headers[0].value
    )


def test_length_framing_prevents_hostile_event_id_body_boundary_collision() -> None:
    signer = _signer(
        settings=GenericHmacSha256Settings(
            template=GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_V1,
        )
    )
    first = _input(b"c", event_id="ab")
    second = _input(b"bc", event_id="a")

    assert first.event_id.encode() + first.body == second.event_id.encode() + second.body
    assert signer.canonical_message(first) != signer.canonical_message(second)
    assert _signature(signer, first) != _signature(signer, second)


def test_length_framing_domain_version_tags_and_uint64_lengths_prevent_collisions() -> None:
    timestamp_encoding = TimestampEncoding.ASCII_DECIMAL_NANOSECONDS
    first_input = _input(b"bc", event_id="a", logical_time_ns=1)
    second_input = _input(b"c", event_id="ab", logical_time_ns=1)
    split_literal_a = CanonicalSigningTemplate(
        version="collision-v1",
        components=(b"a", SigningInputToken.BODY),
    )
    split_literal_ab = CanonicalSigningTemplate(
        version="collision-v1",
        components=(b"ab", SigningInputToken.BODY),
    )
    event_tagged = CanonicalSigningTemplate(
        version="collision-v1",
        components=(SigningInputToken.EVENT_ID, SigningInputToken.BODY),
    )
    changed_version = CanonicalSigningTemplate(
        version="collision-v2",
        components=(SigningInputToken.EVENT_ID, SigningInputToken.BODY),
    )

    frames = (
        split_literal_a.render(first_input, timestamp_encoding=timestamp_encoding),
        split_literal_ab.render(second_input, timestamp_encoding=timestamp_encoding),
        event_tagged.render(first_input, timestamp_encoding=timestamp_encoding),
        event_tagged.render(second_input, timestamp_encoding=timestamp_encoding),
        changed_version.render(first_input, timestamp_encoding=timestamp_encoding),
    )

    assert b"a" + first_input.body == b"ab" + second_input.body == b"abc"
    assert first_input.event_id.encode() + first_input.body == b"abc"
    assert second_input.event_id.encode() + second_input.body == b"abc"
    assert all(frame.startswith(LENGTH_PREFIXED_TEMPLATE_DOMAIN) for frame in frames)
    assert len(set(frames)) == len(frames)
    assert b"\x00" + (1).to_bytes(8, "big") + b"a" in frames[0]
    assert b"\x02" + (1).to_bytes(8, "big") + b"a" in frames[2]
    assert b"\x03" + (2).to_bytes(8, "big") + b"bc" in frames[2]


def test_template_versions_have_one_registered_framing_and_timestamp_meaning() -> None:
    registration = GENERIC_HMAC_SHA256_TEMPLATE_REGISTRY.registrations[0]
    with pytest.raises(SignerError) as duplicate:
        StaticSigningTemplateRegistry((registration, registration))
    assert duplicate.value.diagnostic.code == "SIG_TEMPLATE_VERSION_DUPLICATE"

    changed_semantics = CanonicalSigningTemplate(
        version=GENERIC_HMAC_SHA256_TEMPLATE_VERSION,
        components=(SigningInputToken.EVENT_ID, SigningInputToken.BODY),
    )
    with pytest.raises(SignerError) as conflict:
        GenericHmacSha256Settings(template=changed_semantics)
    assert conflict.value.diagnostic.code == "SIG_TEMPLATE_VERSION_CONFLICT"

    with pytest.raises(SignerError) as timestamp_conflict:
        GenericHmacSha256Settings(
            template=GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_V1,
            timestamp_encoding=TimestampEncoding.ASCII_DECIMAL_SECONDS_FLOOR,
        )
    assert timestamp_conflict.value.diagnostic.code == "SIG_TEMPLATE_VERSION_CONFLICT"

    unregistered = CanonicalSigningTemplate(
        version="generic-hmac-unregistered-v1",
        components=(SigningInputToken.BODY,),
    )
    with pytest.raises(SignerError) as unknown:
        GenericHmacSha256Settings(template=unregistered)
    assert unknown.value.diagnostic.code == "SIG_TEMPLATE_VERSION_UNREGISTERED"


def test_template_registry_snapshots_semantics_and_returns_detached_copies() -> None:
    version = "alias-resistant-v1"
    original_components = (
        SigningInputToken.TIMESTAMP,
        SigningInputToken.EVENT_ID,
        SigningInputToken.BODY,
    )
    template = CanonicalSigningTemplate(
        version=version,
        components=original_components,
        framing=TemplateFraming.LENGTH_PREFIXED_V1,
    )
    registration = SigningTemplateRegistration(
        template=template,
        timestamp_encoding=TimestampEncoding.ASCII_DECIMAL_NANOSECONDS,
    )
    registry = StaticSigningTemplateRegistry((registration,))

    object.__setattr__(template, "version", "mutated-v1")
    object.__setattr__(template, "components", (SigningInputToken.BODY,))
    object.__setattr__(template, "framing", TemplateFraming.EXACT_BODY_V1)
    object.__setattr__(
        registration,
        "timestamp_encoding",
        TimestampEncoding.ASCII_DECIMAL_SECONDS_FLOOR,
    )

    detached = registry.registrations[0]
    assert detached is not registration
    assert detached.template is not template
    assert detached.version == version
    assert detached.template.components == original_components
    assert detached.template.framing is TemplateFraming.LENGTH_PREFIXED_V1
    assert detached.timestamp_encoding is TimestampEncoding.ASCII_DECIMAL_NANOSECONDS
    registry.validate(
        CanonicalSigningTemplate(
            version=version,
            components=original_components,
            framing=TemplateFraming.LENGTH_PREFIXED_V1,
        ),
        TimestampEncoding.ASCII_DECIMAL_NANOSECONDS,
    )

    object.__setattr__(detached.template, "version", "detached-mutated-v1")
    object.__setattr__(detached.template, "components", (SigningInputToken.BODY,))
    object.__setattr__(detached.template, "framing", TemplateFraming.EXACT_BODY_V1)
    object.__setattr__(
        detached,
        "timestamp_encoding",
        TimestampEncoding.ASCII_DECIMAL_SECONDS_FLOOR,
    )
    fresh = registry.registrations[0]
    assert fresh.version == version
    assert fresh.template.components == original_components
    assert fresh.template.framing is TemplateFraming.LENGTH_PREFIXED_V1
    assert fresh.timestamp_encoding is TimestampEncoding.ASCII_DECIMAL_NANOSECONDS


def test_generic_settings_detach_the_registered_template_from_caller_aliases() -> None:
    caller_template = CanonicalSigningTemplate(
        version=GENERIC_HMAC_SHA256_FRAMED_NS_TEMPLATE_VERSION,
        components=(
            SigningInputToken.TIMESTAMP,
            SigningInputToken.EVENT_ID,
            SigningInputToken.BODY,
        ),
        framing=TemplateFraming.LENGTH_PREFIXED_V1,
    )
    settings = GenericHmacSha256Settings(template=caller_template)
    expected = _signer(settings=settings).canonical_message(_input())

    object.__setattr__(caller_template, "components", (SigningInputToken.BODY,))
    object.__setattr__(caller_template, "framing", TemplateFraming.EXACT_BODY_V1)

    assert settings.template is not caller_template
    assert settings.template.components == (
        SigningInputToken.TIMESTAMP,
        SigningInputToken.EVENT_ID,
        SigningInputToken.BODY,
    )
    assert settings.template.framing is TemplateFraming.LENGTH_PREFIXED_V1
    assert _signer(settings=settings).canonical_message(_input()) == expected


def test_user_header_conflicts_are_case_insensitive_and_classified() -> None:
    signer = _signer()

    with pytest.raises(SignerError) as raised:
        signer.validate_user_headers(("X-WebHook-Signature",))

    diagnostic = raised.value.diagnostic
    assert diagnostic.category is ErrorCategory.CONFIGURATION_ERROR
    assert diagnostic.code == "SIG_SIGNER_HEADER_CONFLICT"
    assert diagnostic.safe_details == {"conflict_source": "planned-user-header"}
    assert diagnostic.result_category is ResultCategory.INVALID_INPUT


def test_header_ownership_rejects_internal_duplicates_reserved_and_invalid_names() -> None:
    with pytest.raises(SignerError) as duplicate:
        validate_header_ownership(("X-Signature", "x-signature"))
    assert duplicate.value.diagnostic.code == "SIG_SIGNER_HEADER_INTERNAL_CONFLICT"

    with pytest.raises(SignerError) as reserved:
        GenericHmacSha256Settings(header_name="Content-Type")
    assert reserved.value.diagnostic.code == "SIG_SIGNER_HEADER_RESERVED"

    with pytest.raises(SignerError) as invalid:
        GenericHmacSha256Settings(header_name="bad header")
    assert invalid.value.diagnostic.code == "SIG_SIGNER_HEADERS_INVALID"

    with pytest.raises(SignerError) as too_many:
        validate_header_ownership(
            ("x-signature",),
            user_header_names=tuple(f"x-user-{index}" for index in range(129)),
        )
    assert too_many.value.diagnostic.code == "SIG_SIGNER_HEADERS_INVALID"


def test_header_normalization_caps_a_lying_infinite_sequence_by_realized_items() -> None:
    infinite = LyingInfiniteHeaderSequence()

    with pytest.raises(SignerError) as captured:
        validate_header_ownership(
            ("x-signature",),
            user_header_names=infinite,
        )

    assert captured.value.diagnostic.code == "SIG_SIGNER_HEADERS_INVALID"
    assert "bounded item limit" in captured.value.diagnostic.message
    assert infinite.item_requests == MAX_USER_HEADERS + 1
    assert infinite.length_requests == 0


def test_header_normalization_uses_realized_items_not_a_lying_large_length() -> None:
    finite = LyingFiniteHeaderSequence(("x-user-one", "x-user-two"))

    normalized = validate_header_ownership(
        ("x-signature",),
        user_header_names=finite,
    )

    assert normalized == ("x-signature",)
    assert finite.length_requests == 0


def test_correct_signature_verifies_with_constant_time_compare(
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

    monkeypatch.setattr(generic_hmac.hmac, "compare_digest", observed)
    signer = _signer()
    signing_input = _input()
    result = signer.sign(signing_input)

    verification = signer.verify(signing_input, result.headers)

    assert verification.valid
    assert any(
        isinstance(first, bytes) and isinstance(second, bytes) and len(first) == len(second) == 32
        for first, second in calls
    )
    assert "hmac.compare_digest" in inspect.getsource(GenericHmacSha256Signer.verify)


def test_wrong_key_and_altered_body_fail_without_ambiguity() -> None:
    producer = _signer("correct-signing-key")
    wrong_key = _signer("wrong-signing-key")
    signing_input = _input(b"covered bytes")
    headers = producer.sign(signing_input).headers

    wrong_key_result = wrong_key.verify(signing_input, headers)
    altered_result = producer.verify(_input(b"covered bytes "), headers)

    assert not wrong_key_result.valid
    assert wrong_key_result.reason is VerificationReason.SIGNATURE_MISMATCH
    assert not altered_result.valid
    assert altered_result.reason is VerificationReason.SIGNATURE_MISMATCH
    assert (
        wrong_key_result.evidence.key_fingerprint
        != producer.sign(signing_input).evidence.key_fingerprint
    )


def test_missing_and_duplicate_signature_headers_are_distinct() -> None:
    signer = _signer()
    signing_input = _input()
    header = signer.sign(signing_input).headers[0]

    missing = signer.verify(signing_input, ())
    duplicate = signer.verify(signing_input, (header, header))

    assert not missing.valid
    assert missing.reason is VerificationReason.MISSING_HEADER
    assert not duplicate.valid
    assert duplicate.reason is VerificationReason.DUPLICATE_HEADER


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "0" * 63,
        "0" * 65,
        "g" * 64,
        RFC_4231_SHA256_HEX.upper(),
        f" {RFC_4231_SHA256_HEX}",
        f"{RFC_4231_SHA256_HEX} ",
        f"sha256={RFC_4231_SHA256_HEX}",
    ],
)
def test_hex_verification_rejects_noncanonical_encoding(malformed: str) -> None:
    signer = _signer()

    result = signer.verify(
        _input(),
        (SignatureHeader(name=DEFAULT_SIGNATURE_HEADER, value=malformed),),
    )

    assert not result.valid
    assert result.reason is VerificationReason.MALFORMED_HEADER


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        RFC_4231_SHA256_BASE64.removesuffix("="),
        f"{RFC_4231_SHA256_BASE64}=",
        f"!{RFC_4231_SHA256_BASE64[1:]}",
        RFC_4231_SHA256_BASE64.replace("=", "A"),
        f"{RFC_4231_SHA256_BASE64[:-2]}N=",
        f" {RFC_4231_SHA256_BASE64}",
        f"{RFC_4231_SHA256_BASE64} ",
    ],
)
def test_base64_verification_rejects_noncanonical_encoding(malformed: str) -> None:
    signer = _signer(settings=GenericHmacSha256Settings(output_encoding=SignatureEncoding.BASE64))

    result = signer.verify(
        _input(),
        (SignatureHeader(name=DEFAULT_SIGNATURE_HEADER, value=malformed),),
    )

    assert not result.valid
    assert result.reason is VerificationReason.MALFORMED_HEADER


def test_prefix_is_required_exactly_during_verification() -> None:
    signer = _signer(settings=GenericHmacSha256Settings(prefix="sha256="))
    signing_input = _input()
    valid = signer.sign(signing_input).headers[0]
    without_prefix = SignatureHeader(
        name=valid.name,
        value=valid.value.removeprefix("sha256="),
    )

    assert signer.verify(signing_input, (valid,)).valid
    assert signer.verify(signing_input, (without_prefix,)).reason is (
        VerificationReason.MALFORMED_HEADER
    )


def test_signer_constructor_accepts_only_an_opaque_secret_handle() -> None:
    for value in (
        RFC_4231_KEY.encode(),
        bytearray(RFC_4231_KEY.encode()),
        memoryview(RFC_4231_KEY.encode()),
        RFC_4231_KEY,
    ):
        with pytest.raises(TypeError, match="SecretHandle"):
            GenericHmacSha256Signer(value)  # pyright: ignore[reportArgumentType]


def test_closed_secret_handle_propagates_classified_key_unavailable() -> None:
    handle = _handle()
    signer = GenericHmacSha256Signer(handle)
    handle.close()

    with pytest.raises(SecretResolutionError) as raised:
        signer.sign(_input())

    assert raised.value.diagnostic.category is ErrorCategory.KEY_UNAVAILABLE
    assert raised.value.diagnostic.code == "SECRET_KEY_UNAVAILABLE"
    assert raised.value.diagnostic.result_category is ResultCategory.ENVIRONMENT_ERROR


def test_generated_key_request_and_retained_state_are_resolver_owned_and_safe() -> None:
    calls: list[int] = []
    generated_key = SECRET_CANARY
    assert len(generated_key) == GENERATED_HMAC_KEY_BYTES

    def token_bytes(length: int) -> bytes:
        calls.append(length)
        return generated_key

    reference = GeneratedSecretRef(generated="hmac-256")
    handle = SecretResolver(environ={}, token_bytes=token_bytes).resolve(reference)
    signer = GenericHmacSha256Signer(handle)
    result = signer.sign(_input(b"generated-key signing"))
    encoded_key = base64.b64encode(generated_key)
    safe_surfaces = (
        repr(signer).encode()
        + str(signer).encode()
        + repr(result).encode()
        + repr(result.headers[0]).encode()
        + json.dumps(result.evidence.model_dump(), sort_keys=True).encode()
        + json.dumps(handle.model_dump(mode="json"), sort_keys=True).encode()
    )

    assert calls == [32]
    assert handle.model_dump() == {
        "reference": {"generated": "hmac-256"},
        "fingerprint": secret_fingerprint(generated_key),
    }
    assert set(handle.model_dump()) == {"reference", "fingerprint"}
    assert result.evidence.key_fingerprint == secret_fingerprint(generated_key)
    assert generated_key not in safe_surfaces
    assert encoded_key not in safe_surfaces
    assert not hasattr(signer, "__dict__")
    assert not hasattr(signer, "_key")


def test_signer_copy_pickle_bytes_and_model_dumps_are_canary_safe() -> None:
    signer = GenericHmacSha256Signer(
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
    assert base64.b64encode(SECRET_CANARY) not in pickle_output.getvalue()


def test_secret_callback_exception_drops_key_and_exception_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exception_canary = b"callback-exception-canary"

    def explode(
        _key: memoryview[int],
        _message: bytes,
        _digest: str,
    ) -> bytes:
        raise RuntimeError(SECRET_CANARY + exception_canary)

    monkeypatch.setattr(generic_hmac.hmac, "digest", explode)
    signer = GenericHmacSha256Signer(
        SecretResolver(token_bytes=lambda _length: SECRET_CANARY).resolve(
            GeneratedSecretRef(generated="hmac-256")
        )
    )

    with pytest.raises(SignerError) as raised:
        signer.sign(_input())

    rendered = (
        repr(raised.value) + str(raised.value) + "".join(traceback.format_exception(raised.value))
    ).encode()
    assert raised.value.diagnostic.category is ErrorCategory.SIGNING_ERROR
    assert raised.value.diagnostic.code == "SIG_SIGNING_FAILED"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert SECRET_CANARY not in rendered
    assert exception_canary not in rendered


def test_secret_callback_baseexception_is_normalized_after_wiping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CancellationCanary(BaseException):
        pass

    def cancel(
        _key: memoryview[int],
        _message: bytes,
        _digest: str,
    ) -> bytes:
        raise CancellationCanary(SECRET_CANARY)

    monkeypatch.setattr(generic_hmac.hmac, "digest", cancel)
    signer = GenericHmacSha256Signer(
        SecretResolver(token_bytes=lambda _length: SECRET_CANARY).resolve(
            GeneratedSecretRef(generated="hmac-256")
        )
    )

    with pytest.raises(SecretResolutionError) as raised:
        signer.sign(_input())

    assert raised.value.diagnostic.code == "SECRET_CALLBACK_FAILED"
    assert (
        SECRET_CANARY
        not in (
            repr(raised.value)
            + str(raised.value)
            + "".join(traceback.format_exception(raised.value))
        ).encode()
    )


def test_public_evidence_and_result_repr_hide_authentication_values() -> None:
    signer = _signer(settings=GenericHmacSha256Settings(key_id="public-key-a"))
    result = signer.sign(_input())
    signature = result.headers[0].value
    evidence_wire = result.evidence.model_dump()

    assert evidence_wire == {
        "adapter_id": GENERIC_HMAC_SHA256_ADAPTER_ID,
        "adapter_version": GENERIC_HMAC_SHA256_ADAPTER_VERSION,
        "template_version": GENERIC_HMAC_SHA256_TEMPLATE_VERSION,
        "logical_time_ns": LOGICAL_TIME_NS,
        "body_sha256": sha256_digest(RFC_4231_BODY),
        "covered_bytes_sha256": sha256_digest(RFC_4231_BODY),
        "key_fingerprint": signer.key_fingerprint,
        "key_id": "public-key-a",
        "output_encoding": "hex",
    }
    assert signature not in repr(result)
    assert signature not in repr(result.headers[0])
    assert RFC_4231_KEY not in repr(result)
    assert RFC_4231_KEY not in json.dumps(evidence_wire, sort_keys=True)


@pytest.mark.parametrize(
    "body",
    [
        bytearray(b"mutable"),
        memoryview(b"view"),
        "text",
    ],
)
def test_signing_input_rejects_nonimmutable_body_types(body: object) -> None:
    with pytest.raises(TypeError, match="immutable bytes"):
        SigningInput(
            body=body,  # pyright: ignore[reportArgumentType]
            event_id="evt",
            logical_time_ns=0,
        )


def test_signing_input_bounds_body_event_id_and_signed_timestamp() -> None:
    with pytest.raises(ValueError, match="hard limit"):
        _input(b"x" * (MAX_SIGNING_BODY_BYTES + 1))
    with pytest.raises(ValueError, match="UTF-8 byte limit"):
        _input(b"", event_id="é" * 2049)
    with pytest.raises(ValueError, match="valid Unicode"):
        _input(b"", event_id="\ud800")
    with pytest.raises(TypeError, match="integer"):
        _input(logical_time_ns=cast(int, True))
    with pytest.raises(ValueError, match="signed 64-bit"):
        _input(logical_time_ns=1 << 63)
    with pytest.raises(ValueError, match="signed 64-bit"):
        _input(logical_time_ns=-(1 << 63) - 1)

    assert _input(logical_time_ns=-(1 << 63)).logical_time_ns == -(1 << 63)
    assert _input(logical_time_ns=(1 << 63) - 1).logical_time_ns == (1 << 63) - 1


def test_template_rejects_ambiguous_or_unbounded_shapes() -> None:
    with pytest.raises(TypeError, match="tuple"):
        CanonicalSigningTemplate(
            version="bad-v1",
            components=cast(
                tuple[SigningInputToken | bytes, ...],
                [SigningInputToken.BODY],
            ),
        )
    with pytest.raises(ValueError, match="authoritative"):
        CanonicalSigningTemplate(version="bad-v1", components=(b"constant",))
    with pytest.raises(ValueError, match="more than once"):
        CanonicalSigningTemplate(
            version="bad-v1",
            components=(SigningInputToken.BODY, SigningInputToken.BODY),
        )
    with pytest.raises(ValueError, match="1024-byte"):
        CanonicalSigningTemplate(
            version="bad-v1",
            components=(b"x" * 1025, SigningInputToken.BODY),
        )
    with pytest.raises(ValueError, match="body-only"):
        CanonicalSigningTemplate(
            version="bad-v1",
            components=(SigningInputToken.EVENT_ID, SigningInputToken.BODY),
            framing=TemplateFraming.EXACT_BODY_V1,
        )


@pytest.mark.parametrize(
    "prefix",
    [
        "x" * 129,
        "contains space",
        "contains\ttab",
        "snowman-\N{SNOWMAN}",
    ],
)
def test_prefix_is_bounded_visible_ascii(prefix: str) -> None:
    with pytest.raises(SignerError) as raised:
        GenericHmacSha256Settings(prefix=prefix)

    assert raised.value.diagnostic.code == "SIG_SIGNATURE_PREFIX_INVALID"
    assert prefix not in repr(raised.value)


def test_key_id_and_closed_setting_enums_are_bounded() -> None:
    with pytest.raises(SignerError) as too_long:
        GenericHmacSha256Settings(key_id="k" * 129)
    assert too_long.value.diagnostic.code == "SIG_KEY_ID_INVALID"

    with pytest.raises(SignerError) as control:
        GenericHmacSha256Settings(key_id="key\nid")
    assert control.value.diagnostic.code == "SIG_KEY_ID_INVALID"

    with pytest.raises(TypeError, match="SignatureEncoding"):
        GenericHmacSha256Settings(
            output_encoding=cast(SignatureEncoding, "hex"),
        )
    with pytest.raises(TypeError, match="TimestampEncoding"):
        GenericHmacSha256Settings(
            timestamp_encoding=cast(TimestampEncoding, "ascii"),
        )


def test_verification_headers_are_bounded_and_typed() -> None:
    signer = _signer()
    too_many = tuple(
        SignatureHeader(name=f"x-unrelated-{index}", value="value") for index in range(17)
    )

    with pytest.raises(ValueError, match="bounded"):
        signer.verify(_input(), too_many)
    with pytest.raises(TypeError, match="tuple"):
        signer.verify(
            _input(),
            cast(tuple[SignatureHeader, ...], [too_many[0]]),
        )


def test_signature_header_validates_name_value_and_hides_value_in_repr() -> None:
    empty = SignatureHeader(name="X-Signature", value="")
    secret_value = "auth-value-that-should-not-render"
    populated = SignatureHeader(name="X-Signature", value=secret_value)

    assert empty.name == "x-signature"
    assert empty.value == ""
    assert secret_value not in repr(populated)
    with pytest.raises(ValueError, match="HTTP token"):
        SignatureHeader(name="bad header", value="value")
    with pytest.raises(ValueError, match="control"):
        SignatureHeader(name="x-signature", value="bad\nvalue")
