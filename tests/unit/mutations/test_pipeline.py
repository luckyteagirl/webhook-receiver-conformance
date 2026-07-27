"""Contract, ordering, atomicity, hostile-input, and privacy tests for mutations."""
# ruff: noqa: D101, D102, D105, D107, INP001, PLR0913, S105

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import ClassVar, cast, overload

import pytest

from webhook_receiver_conformance.config.models import EnvironmentSecretRef
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.mutations.base import (
    MAX_MUTATIONS_PER_PIPELINE,
    REDACTED_PARAMETER_VALUE,
    MutationError,
    MutationInput,
    MutationOperator,
    MutationOutput,
    MutationRegistration,
    MutationStage,
    RealizedMutation,
    SignatureHeaderAction,
    StaticMutationRegistry,
)
from webhook_receiver_conformance.mutations.pipeline import (
    MutationPipeline,
    MutationPipelineLimits,
    MutationPipelineResult,
)
from webhook_receiver_conformance.secrets import SecretHandle, SecretResolver
from webhook_receiver_conformance.signatures.base import (
    BuiltinSignerCategory,
    SignatureHeader,
    Signer,
    SigningInput,
    SigningResult,
    VerificationResult,
)
from webhook_receiver_conformance.signatures.hmac_generic import (
    GenericHmacSha256Signer,
)

EVENT_ID = "evt_pipeline_contract"
LOGICAL_TIME_NS = 1_700_000_000_123_456_789
SECRET_CANARY = "mutation-secret-canary-never-render"


def _handle(value: str) -> SecretHandle:
    return SecretResolver(environ={"MUTATION_TEST_KEY": value}).resolve(
        EnvironmentSecretRef(env="MUTATION_TEST_KEY")
    )


def _signer(value: str = "valid-signing-key") -> GenericHmacSha256Signer:
    return GenericHmacSha256Signer(_handle(value))


def _realized(
    operator_id: str,
    stage: MutationStage,
    *,
    version: int = 1,
    parameters: dict[str, object] | None = None,
    parameters_safe: dict[str, object] | None = None,
) -> RealizedMutation:
    return RealizedMutation(
        operator_id=operator_id,
        operator_version=version,
        stage=stage,
        parameters={} if parameters is None else parameters,
        parameters_safe=parameters_safe,
    )


def _registration(
    operator_id: str,
    stage: MutationStage,
    implementation: MutationOperator,
    **effects: object,
) -> MutationRegistration:
    return MutationRegistration(
        operator_id=operator_id,
        operator_version=1,
        stage=stage,
        implementation=implementation,
        **effects,  # pyright: ignore[reportArgumentType]
    )


def _run(
    registry: StaticMutationRegistry,
    mutations: Sequence[RealizedMutation],
    *,
    body: bytes = b'{"amount":1}',
    signer: Signer | None = None,
    headers: Sequence[SignatureHeader] = (),
    limits: MutationPipelineLimits | None = None,
) -> MutationPipelineResult:
    return MutationPipeline(registry, limits).execute(
        body=body,
        headers=headers,
        event_id=EVENT_ID,
        logical_time_ns=LOGICAL_TIME_NS,
        media_type="application/json",
        signer=signer,
        mutations=mutations,
    )


@dataclass(slots=True)
class BodyFake:
    calls: list[str]
    name: str
    transform: Callable[[bytes], bytes]
    expected_parameter: tuple[str, object] | None = None

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        self.calls.append(self.name)
        if self.expected_parameter is not None:
            key, value = self.expected_parameter
            assert mutation_input.parameters[key] == value
        state = mutation_input.state
        return MutationOutput(
            body=self.transform(state.body),
            headers=state.headers,
            signing_time_ns=state.signing_time_ns,
            signer=state.signer,
        )


@dataclass(slots=True)
class HeaderFake:
    calls: list[str]
    name: str
    header_name: str
    header_value: str

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        self.calls.append(self.name)
        state = mutation_input.state
        retained = tuple(
            header for header in state.headers if header.name != self.header_name.casefold()
        )
        return MutationOutput(
            body=state.body,
            headers=(
                *retained,
                SignatureHeader(name=self.header_name, value=self.header_value),
            ),
            signing_time_ns=state.signing_time_ns,
            signer=state.signer,
        )


@dataclass(slots=True)
class RemoveSignerHeadersFake:
    calls: list[str]
    name: str

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        self.calls.append(self.name)
        state = mutation_input.state
        assert state.signer is not None
        owned = set(state.signer.owned_headers)
        return MutationOutput(
            body=state.body,
            headers=tuple(header for header in state.headers if header.name not in owned),
            signing_time_ns=state.signing_time_ns,
            signer=state.signer,
        )


@dataclass(slots=True)
class SigningTimeFake:
    calls: list[str]
    name: str
    offset_ns: int

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        self.calls.append(self.name)
        state = mutation_input.state
        return MutationOutput(
            body=state.body,
            headers=state.headers,
            signing_time_ns=state.signing_time_ns + self.offset_ns,
            signer=state.signer,
        )


@dataclass(slots=True)
class ReplaceSignerFake:
    replacement: Signer

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        state = mutation_input.state
        return MutationOutput(
            body=state.body,
            headers=state.headers,
            signing_time_ns=state.signing_time_ns,
            signer=self.replacement,
        )


class RecordingSigner(Signer):
    BUILTIN_CATEGORY: ClassVar[BuiltinSignerCategory] = BuiltinSignerCategory.GENERIC_HMAC_SHA256

    def __init__(self, delegate: Signer, calls: list[str]) -> None:
        self._delegate = delegate
        self._calls = calls

    @property
    def adapter_id(self) -> str:
        return self._delegate.adapter_id

    @property
    def adapter_version(self) -> str:
        return self._delegate.adapter_version

    @property
    def owned_headers(self) -> tuple[str, ...]:
        return self._delegate.owned_headers

    def sign(self, signing_input: SigningInput) -> SigningResult:
        self._calls.append("signer")
        return self._delegate.sign(signing_input)

    def verify(
        self,
        signing_input: SigningInput,
        headers: tuple[SignatureHeader, ...],
    ) -> VerificationResult:
        return self._delegate.verify(signing_input, headers)


def test_golden_pipeline_has_fixed_stage_order_and_every_intermediate_digest() -> None:
    calls: list[str] = []
    structural = BodyFake(
        calls,
        "structural",
        lambda body: body[:-1] + b',"currency":"USD"}',
    )
    raw_pre = BodyFake(calls, "raw-pre", lambda body: body + b"\n")
    header_pre = HeaderFake(calls, "header-pre", "Content-Type", "application/problem+json")
    signing = SigningTimeFake(calls, "signing", -5_000_000_000)
    raw_post = BodyFake(calls, "raw-post", lambda body: body + b"!")
    header_post = HeaderFake(calls, "header-post", "X-Mutated", "yes")
    registrations = (
        _registration(
            "json-field",
            MutationStage.STRUCTURAL,
            structural,
            changes_body=True,
            requires_valid_json=True,
        ),
        _registration(
            "raw-suffix",
            MutationStage.RAW_PRE_SIGN,
            raw_pre,
            changes_body=True,
        ),
        _registration(
            "content-type",
            MutationStage.HEADER_PRE_SIGN,
            header_pre,
            written_headers=("Content-Type",),
        ),
        _registration(
            "stale-time",
            MutationStage.SIGNING,
            signing,
            may_change_signing_time=True,
        ),
        _registration(
            "post-body",
            MutationStage.RAW_POST_SIGN,
            raw_post,
            changes_body=True,
        ),
        _registration(
            "post-header",
            MutationStage.HEADER_POST_SIGN,
            header_post,
            written_headers=("X-Mutated",),
        ),
    )
    mutations = tuple(
        _realized(registration.operator_id, registration.stage) for registration in registrations
    )
    initial = b'{"amount":1}'
    body_structural = b'{"amount":1,"currency":"USD"}'
    body_raw_pre = body_structural + b"\n"
    body_raw_post = body_raw_pre + b"!"

    result = _run(
        StaticMutationRegistry(registrations),
        mutations,
        body=initial,
        signer=RecordingSigner(_signer(), calls),
        headers=(SignatureHeader(name="content-type", value="application/json"),),
    )

    assert calls == [
        "structural",
        "raw-pre",
        "header-pre",
        "signing",
        "signer",
        "raw-post",
        "header-post",
    ]
    assert tuple(item.stage for item in result.mutation_evidence) == tuple(
        registration.stage for registration in registrations
    )
    assert [
        (item.input_body_sha256, item.output_body_sha256) for item in result.mutation_evidence
    ] == [
        (sha256_digest(initial), sha256_digest(body_structural)),
        (sha256_digest(body_structural), sha256_digest(body_raw_pre)),
        (sha256_digest(body_raw_pre), sha256_digest(body_raw_pre)),
        (sha256_digest(body_raw_pre), sha256_digest(body_raw_pre)),
        (sha256_digest(body_raw_pre), sha256_digest(body_raw_post)),
        (sha256_digest(body_raw_post), sha256_digest(body_raw_post)),
    ]
    assert result.signed_body_sha256 == sha256_digest(body_raw_pre)
    assert result.delivered_body_sha256 == sha256_digest(body_raw_post)
    assert result.body == body_raw_post


def test_wrong_key_replacement_records_distinct_fingerprint_and_fails_valid_verifier() -> None:
    valid_signer = _signer("valid-signing-key")
    wrong_signer = _signer("deterministic-wrong-key")
    registration = _registration(
        "wrong-key",
        MutationStage.SIGNING,
        ReplaceSignerFake(wrong_signer),
        may_replace_signer=True,
    )
    body = b'{"event":"paid"}'

    valid_result = _run(StaticMutationRegistry(()), (), body=body, signer=valid_signer)
    wrong_result = _run(
        StaticMutationRegistry((registration,)),
        (_realized("wrong-key", MutationStage.SIGNING),),
        body=body,
        signer=valid_signer,
    )

    assert valid_result.signing_evidence is not None
    assert wrong_result.signing_evidence is not None
    assert (
        wrong_result.signing_evidence.key_fingerprint
        != valid_result.signing_evidence.key_fingerprint
    )
    verification = valid_signer.verify(
        SigningInput(
            body=body,
            event_id=EVENT_ID,
            logical_time_ns=LOGICAL_TIME_NS,
        ),
        wrong_result.headers,
    )
    assert not verification.valid


def test_post_sign_body_change_keeps_signature_header_byte_for_byte() -> None:
    signer = _signer()
    registration = _registration(
        "alter-after-signing",
        MutationStage.RAW_POST_SIGN,
        BodyFake([], "post", lambda body: bytes((body[0] ^ 1,)) + body[1:]),
        changes_body=True,
    )
    body = b'{"event":"paid"}'
    baseline = _run(StaticMutationRegistry(()), (), body=body, signer=signer)
    altered = _run(
        StaticMutationRegistry((registration,)),
        (_realized("alter-after-signing", MutationStage.RAW_POST_SIGN),),
        body=body,
        signer=signer,
    )

    assert altered.headers == baseline.headers
    assert altered.signed_body_sha256 == baseline.delivered_body_sha256
    assert altered.delivered_body_sha256 != altered.signed_body_sha256
    verification = signer.verify(
        SigningInput(
            body=altered.body,
            event_id=EVENT_ID,
            logical_time_ns=LOGICAL_TIME_NS,
        ),
        altered.headers,
    )
    assert not verification.valid


def test_registry_requires_exact_identity_version_and_registered_stage() -> None:
    registration = _registration(
        "raw-one",
        MutationStage.RAW_PRE_SIGN,
        BodyFake([], "raw", lambda body: body),
        changes_body=True,
    )
    registry = StaticMutationRegistry((registration,))

    with pytest.raises(MutationError) as unknown:
        _run(
            registry,
            (_realized("unknown", MutationStage.RAW_PRE_SIGN),),
        )
    assert unknown.value.diagnostic.code == "MUT_OPERATOR_UNREGISTERED"

    with pytest.raises(MutationError) as version:
        _run(
            registry,
            (_realized("raw-one", MutationStage.RAW_PRE_SIGN, version=2),),
        )
    assert version.value.diagnostic.code == "MUT_OPERATOR_VERSION_UNREGISTERED"

    with pytest.raises(MutationError) as stage:
        _run(
            registry,
            (_realized("raw-one", MutationStage.RAW_POST_SIGN),),
        )
    assert stage.value.diagnostic.code == "MUT_OPERATOR_STAGE_CONFLICT"


def test_out_of_order_plan_fails_atomically_before_operator_or_signer() -> None:
    calls: list[str] = []
    raw_post = _registration(
        "post",
        MutationStage.RAW_POST_SIGN,
        BodyFake(calls, "post", lambda body: body),
        changes_body=True,
    )
    raw_pre = _registration(
        "pre",
        MutationStage.RAW_PRE_SIGN,
        BodyFake(calls, "pre", lambda body: body),
        changes_body=True,
    )
    signer = RecordingSigner(_signer(), calls)

    with pytest.raises(MutationError) as caught:
        _run(
            StaticMutationRegistry((raw_post, raw_pre)),
            (
                _realized("post", MutationStage.RAW_POST_SIGN),
                _realized("pre", MutationStage.RAW_PRE_SIGN),
            ),
            signer=signer,
        )

    assert caught.value.diagnostic.code == "MUT_PIPELINE_STAGE_ORDER"
    assert caught.value.diagnostic.safe_details["operator_id"] == "pre"
    assert calls == []


def test_structural_after_json_invalidation_has_operator_specific_diagnostic() -> None:
    calls: list[str] = []
    invalid = _registration(
        "invalid-json",
        MutationStage.RAW_PRE_SIGN,
        BodyFake(calls, "invalid", lambda body: body[:-1]),
        changes_body=True,
        invalidates_json=True,
    )
    structural = _registration(
        "json-replace",
        MutationStage.STRUCTURAL,
        BodyFake(calls, "structural", lambda body: body),
        changes_body=True,
        requires_valid_json=True,
    )

    with pytest.raises(MutationError) as caught:
        _run(
            StaticMutationRegistry((invalid, structural)),
            (
                _realized("invalid-json", MutationStage.RAW_PRE_SIGN),
                _realized("json-replace", MutationStage.STRUCTURAL),
            ),
        )

    assert caught.value.diagnostic.code == "MUT_STRUCTURAL_AFTER_INVALID_JSON"
    assert caught.value.diagnostic.safe_details == {
        "prior_operator_id": "invalid-json",
        "prior_operator_version": 1,
        "operator_id": "json-replace",
        "operator_version": 1,
    }
    assert calls == []


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_structural_preflight_rejects_non_rfc_json_constants(constant: bytes) -> None:
    calls: list[str] = []
    registration = _registration(
        "json-replace",
        MutationStage.STRUCTURAL,
        BodyFake(calls, "structural", lambda body: body),
        changes_body=True,
        requires_valid_json=True,
    )

    with pytest.raises(MutationError) as caught:
        _run(
            StaticMutationRegistry((registration,)),
            (_realized("json-replace", MutationStage.STRUCTURAL),),
            body=b'{"value":' + constant + b"}",
        )

    assert caught.value.diagnostic.code == "MUT_STRUCTURAL_INPUT_INVALID_JSON"
    assert constant.decode("ascii") not in str(caught.value)
    assert constant.decode("ascii") not in repr(caught.value)
    assert calls == []


def test_conflicting_signature_removals_fail_before_signing() -> None:
    calls: list[str] = []
    first = _registration(
        "missing-signature",
        MutationStage.HEADER_POST_SIGN,
        RemoveSignerHeadersFake(calls, "first"),
        signature_header_action=SignatureHeaderAction.REMOVE,
    )
    second = _registration(
        "also-missing-signature",
        MutationStage.HEADER_POST_SIGN,
        RemoveSignerHeadersFake(calls, "second"),
        signature_header_action=SignatureHeaderAction.REMOVE,
    )
    signer = RecordingSigner(_signer(), calls)

    with pytest.raises(MutationError) as caught:
        _run(
            StaticMutationRegistry((first, second)),
            (
                _realized("missing-signature", MutationStage.HEADER_POST_SIGN),
                _realized("also-missing-signature", MutationStage.HEADER_POST_SIGN),
            ),
            signer=signer,
        )

    assert caught.value.diagnostic.code == "MUT_SIGNATURE_HEADER_ACTION_CONFLICT"
    assert caught.value.diagnostic.safe_details["prior_operator_id"] == "missing-signature"
    assert calls == []


def test_header_claims_and_signer_ownership_are_normalized_and_exclusive() -> None:
    first = _registration(
        "header-one",
        MutationStage.HEADER_PRE_SIGN,
        HeaderFake([], "one", "X-Collision", "one"),
        written_headers=("X-Collision",),
    )
    second = _registration(
        "header-two",
        MutationStage.HEADER_PRE_SIGN,
        HeaderFake([], "two", "x-collision", "two"),
        written_headers=("x-collision",),
    )
    with pytest.raises(MutationError) as duplicate:
        _run(
            StaticMutationRegistry((first, second)),
            (
                _realized("header-one", MutationStage.HEADER_PRE_SIGN),
                _realized("header-two", MutationStage.HEADER_PRE_SIGN),
            ),
        )
    assert duplicate.value.diagnostic.code == "MUT_HEADER_TARGET_CONFLICT"

    signer_owned = _registration(
        "steal-signature",
        MutationStage.HEADER_PRE_SIGN,
        HeaderFake([], "steal", "X-Webhook-Signature", "value"),
        written_headers=("x-webhook-signature",),
    )
    with pytest.raises(MutationError) as ownership:
        _run(
            StaticMutationRegistry((signer_owned,)),
            (_realized("steal-signature", MutationStage.HEADER_PRE_SIGN),),
            signer=_signer(),
        )
    assert ownership.value.diagnostic.code == "MUT_SIGNER_HEADER_OWNERSHIP_CONFLICT"

    with pytest.raises(MutationError) as input_collision:
        _run(
            StaticMutationRegistry(()),
            (),
            signer=_signer(),
            headers=(SignatureHeader("X-WEBHOOK-SIGNATURE", "user-value"),),
        )
    assert input_collision.value.diagnostic.code == "MUT_SIGNER_HEADER_COLLISION"


class LyingMutationSequence(Sequence[RealizedMutation]):
    def __init__(self, value: RealizedMutation) -> None:
        self.value = value
        self.requests = 0

    def __len__(self) -> int:
        return 0

    @overload
    def __getitem__(self, index: int) -> RealizedMutation: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[RealizedMutation]: ...

    def __getitem__(
        self,
        index: int | slice,
    ) -> RealizedMutation | Sequence[RealizedMutation]:
        if isinstance(index, slice):
            return ()
        self.requests += 1
        return self.value


def test_lying_unbounded_sequence_is_capped_without_calling_operator() -> None:
    calls: list[str] = []
    registration = _registration(
        "raw",
        MutationStage.RAW_PRE_SIGN,
        BodyFake(calls, "raw", lambda body: body),
        changes_body=True,
    )
    lying = LyingMutationSequence(_realized("raw", MutationStage.RAW_PRE_SIGN))

    with pytest.raises(MutationError) as caught:
        _run(StaticMutationRegistry((registration,)), lying)

    assert caught.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert caught.value.diagnostic.code == "MUT_SEQUENCE_LIMIT"
    assert lying.requests == MAX_MUTATIONS_PER_PIPELINE + 1
    assert calls == []


def test_parameters_are_detached_and_evidence_is_redacted_by_default() -> None:
    nested = [SECRET_CANARY]
    parameters: dict[str, object] = {"replacement": SECRET_CANARY, "nested": nested}
    realized = _realized(
        "replace-sensitive",
        MutationStage.RAW_PRE_SIGN,
        parameters=parameters,
    )
    nested[0] = "alias-mutated"
    parameters["replacement"] = "alias-mutated"
    calls: list[str] = []
    registration = _registration(
        "replace-sensitive",
        MutationStage.RAW_PRE_SIGN,
        BodyFake(
            calls,
            "replace",
            lambda body: body,
            expected_parameter=("replacement", SECRET_CANARY),
        ),
        changes_body=True,
    )

    result = _run(StaticMutationRegistry((registration,)), (realized,))
    rendered = json.dumps(result.log_safe_dict(), sort_keys=True)
    reprs = " ".join(
        (
            repr(realized),
            repr(realized.parameters),
            repr(result.mutation_evidence[0]),
            repr(result),
        )
    )

    assert calls == ["replace"]
    assert SECRET_CANARY not in rendered
    assert SECRET_CANARY not in reprs
    assert "alias-mutated" not in rendered
    assert REDACTED_PARAMETER_VALUE in rendered


class InputAliasMutator:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        original = mutation_input.state
        object.__setattr__(original, "body", b"tampered")
        return MutationOutput.unchanged(original)


def test_input_alias_tampering_is_detected_and_no_result_is_exposed() -> None:
    registration = _registration(
        "alias-mutator",
        MutationStage.RAW_PRE_SIGN,
        InputAliasMutator(),
        changes_body=True,
    )
    with pytest.raises(MutationError) as caught:
        _run(
            StaticMutationRegistry((registration,)),
            (_realized("alias-mutator", MutationStage.RAW_PRE_SIGN),),
        )
    assert caught.value.diagnostic.code == "MUT_OPERATOR_MUTATED_INPUT"


def test_registry_snapshots_registration_metadata_against_alias_changes() -> None:
    registration = _registration(
        "stable",
        MutationStage.RAW_PRE_SIGN,
        BodyFake([], "stable", lambda body: body),
        changes_body=True,
    )
    registry = StaticMutationRegistry((registration,))
    object.__setattr__(registration, "operator_id", "changed-by-alias")

    assert registry.operator_versions == (("stable", 1),)
    result = _run(
        registry,
        (_realized("stable", MutationStage.RAW_PRE_SIGN),),
    )
    assert result.mutation_evidence[0].operator_id == "stable"


def test_resource_limits_fail_atomically_before_operator_and_signer_calls() -> None:
    calls: list[str] = []
    registration = _registration(
        "raw",
        MutationStage.RAW_PRE_SIGN,
        BodyFake(calls, "raw", lambda body: body),
        changes_body=True,
    )
    signer = RecordingSigner(_signer(), calls)

    with pytest.raises(MutationError) as caught:
        _run(
            StaticMutationRegistry((registration,)),
            (_realized("raw", MutationStage.RAW_PRE_SIGN),),
            body=b"1234",
            signer=signer,
            limits=MutationPipelineLimits(max_body_bytes=3),
        )

    assert caught.value.diagnostic.code == "MUT_BODY_LIMIT"
    assert calls == []


def test_undeclared_operator_effect_fails_without_signing_partial_state() -> None:
    calls: list[str] = []
    registration = _registration(
        "lying-header",
        MutationStage.RAW_PRE_SIGN,
        HeaderFake(calls, "lying", "X-Undeclared", "value"),
        changes_body=True,
    )
    signer = RecordingSigner(_signer(), calls)

    with pytest.raises(MutationError) as caught:
        _run(
            StaticMutationRegistry((registration,)),
            (_realized("lying-header", MutationStage.RAW_PRE_SIGN),),
            signer=signer,
        )

    assert caught.value.diagnostic.code == "MUT_OPERATOR_UNDECLARED_EFFECT"
    assert caught.value.diagnostic.safe_details["effect"] == "headers"
    assert calls == ["lying"]


@pytest.mark.parametrize(
    ("operator_id", "operator_version"),
    [
        ("", 1),
        ("UPPERCASE", 1),
        ("valid", 0),
        ("valid", True),
    ],
)
def test_realized_identity_is_closed_and_version_is_an_exact_integer(
    operator_id: str,
    operator_version: int,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        RealizedMutation(
            operator_id=operator_id,
            operator_version=operator_version,
            stage=MutationStage.RAW_PRE_SIGN,
            parameters={},
        )


def test_secret_handles_cannot_enter_serializable_mutation_parameters() -> None:
    with pytest.raises(TypeError, match="only JSON values"):
        _realized(
            "secret-parameter",
            MutationStage.RAW_PRE_SIGN,
            parameters={"key": cast("object", _handle("secret-key"))},
        )
