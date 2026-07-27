"""Atomic fixed-order execution for registered mutation operators and signers."""
# ruff: noqa: BLE001, C901, D105, D107, EM101, INP001, PLR0912, PLR0913, PLR2004, TC001, TRY003, TRY301

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, NoReturn, cast

from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.mutations.base import (
    MAX_MUTATION_HEADERS,
    MAX_MUTATIONS_PER_PIPELINE,
    PIPELINE_STAGE_RANK,
    MutationError,
    MutationEvidence,
    MutationInput,
    MutationOutput,
    MutationRegistration,
    MutationStage,
    MutationState,
    RealizedMutation,
    SignatureHeaderAction,
    StaticMutationRegistry,
    thaw_parameter_object,
)
from webhook_receiver_conformance.signatures.base import (
    MAX_SIGNING_BODY_BYTES,
    SignatureHeader,
    Signer,
    SignerError,
    SigningEvidence,
    SigningInput,
    SigningResult,
    validate_header_ownership,
)
from webhook_receiver_conformance.types import JsonObject

MAX_TOTAL_HEADER_BYTES: Final = 262_144
_SIGNER_IDENTIFIER = re.compile(r"[a-z][a-z0-9._-]{0,127}")


@dataclass(frozen=True, slots=True)
class MutationPipelineLimits:
    """Hard-bounded execution limits no caller may raise beyond package caps."""

    max_body_bytes: int = MAX_SIGNING_BODY_BYTES
    max_headers: int = MAX_MUTATION_HEADERS
    max_total_header_bytes: int = MAX_TOTAL_HEADER_BYTES
    max_mutations: int = MAX_MUTATIONS_PER_PIPELINE

    def __post_init__(self) -> None:
        _validate_limit(
            self.max_body_bytes,
            field_name="max_body_bytes",
            hard_maximum=MAX_SIGNING_BODY_BYTES,
        )
        _validate_limit(
            self.max_headers,
            field_name="max_headers",
            hard_maximum=MAX_MUTATION_HEADERS,
        )
        _validate_limit(
            self.max_total_header_bytes,
            field_name="max_total_header_bytes",
            hard_maximum=MAX_TOTAL_HEADER_BYTES,
        )
        _validate_limit(
            self.max_mutations,
            field_name="max_mutations",
            hard_maximum=MAX_MUTATIONS_PER_PIPELINE,
            allow_zero=True,
        )


@dataclass(frozen=True, slots=True, repr=False)
class MutationPipelineResult:
    """Complete atomic request result plus secret-free intermediate evidence."""

    body: bytes
    headers: tuple[SignatureHeader, ...]
    mutation_evidence: tuple[MutationEvidence, ...]
    signing_evidence: SigningEvidence | None
    signed_body_sha256: str | None
    delivered_body_sha256: str

    def __post_init__(self) -> None:
        if type(self.body) is not bytes:
            message = "pipeline result body must be immutable bytes"
            raise TypeError(message)
        if type(self.headers) is not tuple:
            message = "pipeline result headers must be a tuple"
            raise TypeError(message)
        if any(type(header) is not SignatureHeader for header in self.headers):
            message = "pipeline result headers must contain SignatureHeader values"
            raise TypeError(message)
        if type(self.mutation_evidence) is not tuple:
            message = "pipeline mutation evidence must be a tuple"
            raise TypeError(message)
        if any(type(item) is not MutationEvidence for item in self.mutation_evidence):
            message = "pipeline evidence must contain MutationEvidence values"
            raise TypeError(message)
        if self.signing_evidence is not None and type(self.signing_evidence) is not SigningEvidence:
            message = "pipeline signing evidence must be SigningEvidence or None"
            raise TypeError(message)
        if (self.signing_evidence is None) is not (self.signed_body_sha256 is None):
            message = "signed body digest and signing evidence must be present together"
            raise ValueError(message)
        if self.signed_body_sha256 is not None:
            _require_digest(self.signed_body_sha256)
        _require_digest(self.delivered_body_sha256)
        if self.delivered_body_sha256 != sha256_digest(self.body):
            message = "delivered body digest does not match exact result bytes"
            raise ValueError(message)

    def log_safe_dict(self) -> JsonObject:
        """Return sanitized evidence without body bytes or header values."""
        signing: JsonObject | None = (
            None
            if self.signing_evidence is None
            else cast("JsonObject", self.signing_evidence.model_dump())
        )
        return {
            "body_length": len(self.body),
            "header_names": [header.name for header in self.headers],
            "mutations": [item.log_safe_dict() for item in self.mutation_evidence],
            "signing": signing,
            "signed_body_sha256": self.signed_body_sha256,
            "delivered_body_sha256": self.delivered_body_sha256,
        }

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"body_length={len(self.body)}, "
            f"header_names={tuple(header.name for header in self.headers)!r}, "
            f"mutation_count={len(self.mutation_evidence)}, "
            f"has_signing_evidence={self.signing_evidence is not None}, "
            f"signed_body_sha256={self.signed_body_sha256!r}, "
            f"delivered_body_sha256={self.delivered_body_sha256!r})"
        )


@dataclass(frozen=True, slots=True)
class _SignerSnapshot:
    signer: Signer
    adapter_id: str
    adapter_version: str
    owned_headers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _PreparedMutation:
    realized: RealizedMutation
    registration: MutationRegistration


@dataclass(frozen=True, slots=True)
class _PreparedPipeline:
    mutations: tuple[_PreparedMutation, ...]
    body: bytes
    headers: tuple[SignatureHeader, ...]
    signer: Signer | None
    signer_snapshot: _SignerSnapshot | None


class MutationPipeline:
    """Preflight the complete plan, then expose either one result or one error."""

    __slots__ = ("_limits", "_registry")

    def __init__(
        self,
        registry: StaticMutationRegistry,
        limits: MutationPipelineLimits | None = None,
    ) -> None:
        if type(registry) is not StaticMutationRegistry:
            message = "mutation pipeline requires a StaticMutationRegistry"
            raise TypeError(message)
        if limits is not None and type(limits) is not MutationPipelineLimits:
            message = "limits must be MutationPipelineLimits or None"
            raise TypeError(message)
        self._registry = registry
        self._limits = MutationPipelineLimits() if limits is None else limits

    def execute(
        self,
        *,
        body: bytes,
        headers: Sequence[SignatureHeader],
        event_id: str,
        logical_time_ns: int,
        media_type: str,
        signer: Signer | None,
        mutations: Sequence[RealizedMutation],
    ) -> MutationPipelineResult:
        """Execute the fixed pipeline without exposing an intermediate state."""
        prepared = self._preflight(
            body=body,
            headers=headers,
            event_id=event_id,
            logical_time_ns=logical_time_ns,
            media_type=media_type,
            signer=signer,
            mutations=mutations,
        )
        state = MutationState(
            body=prepared.body,
            headers=prepared.headers,
            signing_time_ns=logical_time_ns,
            signer=prepared.signer,
        )
        evidence: list[MutationEvidence] = []
        signing_evidence: SigningEvidence | None = None
        signed_body_sha256: str | None = None
        signer_invoked = False

        for prepared_mutation in prepared.mutations:
            if (
                not signer_invoked
                and PIPELINE_STAGE_RANK[prepared_mutation.realized.stage]
                > PIPELINE_STAGE_RANK[MutationStage.SIGNING]
            ):
                state, signing_evidence, signed_body_sha256 = self._sign(
                    state,
                    event_id=event_id,
                    expected_snapshot=prepared.signer_snapshot,
                )
                signer_invoked = True
            state, item_evidence = self._apply_one(
                state,
                prepared_mutation,
                event_id=event_id,
                media_type=media_type,
                expected_signer_snapshot=prepared.signer_snapshot,
            )
            evidence.append(item_evidence)

        if not signer_invoked:
            state, signing_evidence, signed_body_sha256 = self._sign(
                state,
                event_id=event_id,
                expected_snapshot=prepared.signer_snapshot,
            )

        self._validate_state_resources(state)
        return MutationPipelineResult(
            body=state.body,
            headers=tuple(state.headers),
            mutation_evidence=tuple(evidence),
            signing_evidence=signing_evidence,
            signed_body_sha256=signed_body_sha256,
            delivered_body_sha256=sha256_digest(state.body),
        )

    run = execute

    def _preflight(
        self,
        *,
        body: bytes,
        headers: Sequence[SignatureHeader],
        event_id: str,
        logical_time_ns: int,
        media_type: str,
        signer: Signer | None,
        mutations: Sequence[RealizedMutation],
    ) -> _PreparedPipeline:
        if type(body) is not bytes:
            raise MutationError.invalid_parameter(
                "MUT_BODY_TYPE",
                "The mutation pipeline body must be immutable bytes.",
            )
        if len(body) > self._limits.max_body_bytes:
            raise MutationError.resource_limit(
                "MUT_BODY_LIMIT",
                "The mutation pipeline input exceeds its configured body limit.",
            )
        materialized_headers = _bounded_headers(headers, maximum=self._limits.max_headers)
        materialized_mutations = _bounded_mutations(
            mutations,
            maximum=self._limits.max_mutations,
        )
        try:
            seed_state = MutationState(
                body=body,
                headers=materialized_headers,
                signing_time_ns=logical_time_ns,
                signer=signer,
            )
            MutationInput(
                realized=RealizedMutation(
                    operator_id="pipeline-preflight",
                    operator_version=1,
                    stage=MutationStage.RAW_PRE_SIGN,
                    parameters={},
                    parameters_safe={},
                ),
                state=seed_state,
                event_id=event_id,
                media_type=media_type,
            )
        except (TypeError, ValueError):
            raise MutationError.invalid_parameter(
                "MUT_PIPELINE_INPUT_INVALID",
                "The mutation pipeline input is invalid.",
            ) from None
        self._validate_header_resources(materialized_headers)
        signer_snapshot = None if signer is None else _snapshot_signer(signer)
        if signer_snapshot is not None:
            _reject_signer_input_collision(
                signer_snapshot,
                headers=materialized_headers,
            )

        prepared: list[_PreparedMutation] = []
        furthest: _PreparedMutation | None = None
        invalid_json_by: _PreparedMutation | None = None
        header_claims: dict[str, _PreparedMutation] = {}
        signature_action: _PreparedMutation | None = None
        structural_present = False

        for source_realized in materialized_mutations:
            try:
                realized = _detach_realized(source_realized)
            except Exception:
                raise MutationError.invalid_parameter(
                    "MUT_REALIZED_OPERATOR_INVALID",
                    "A realized mutation was modified or violates its immutable contract.",
                ) from None
            registration = self._registry.registration(realized)
            current = _PreparedMutation(
                realized=realized,
                registration=registration,
            )
            if realized.stage is MutationStage.STRUCTURAL and invalid_json_by is not None:
                raise MutationError.conflict(
                    "MUT_STRUCTURAL_AFTER_INVALID_JSON",
                    "A structural JSON mutation cannot follow a JSON-invalidating operator.",
                    operator_id=realized.operator_id,
                    operator_version=realized.operator_version,
                    safe_details={
                        "prior_operator_id": invalid_json_by.realized.operator_id,
                        "prior_operator_version": (invalid_json_by.realized.operator_version),
                    },
                )
            if (
                furthest is not None
                and PIPELINE_STAGE_RANK[realized.stage]
                < PIPELINE_STAGE_RANK[furthest.realized.stage]
            ):
                raise MutationError.conflict(
                    "MUT_PIPELINE_STAGE_ORDER",
                    "A mutation appears after an operator from a later pipeline stage.",
                    operator_id=realized.operator_id,
                    operator_version=realized.operator_version,
                    safe_details={
                        "operator_stage": realized.stage.value,
                        "prior_operator_id": furthest.realized.operator_id,
                        "prior_stage": furthest.realized.stage.value,
                    },
                )
            if (
                furthest is None
                or PIPELINE_STAGE_RANK[realized.stage]
                > PIPELINE_STAGE_RANK[furthest.realized.stage]
            ):
                furthest = current
            if registration.invalidates_json:
                invalid_json_by = current
            if registration.requires_valid_json:
                structural_present = True
                if not _is_json_media_type(media_type):
                    raise MutationError.not_applicable(
                        "MUT_STRUCTURAL_REQUIRES_JSON",
                        "A structural mutation requires a JSON media type.",
                        operator_id=realized.operator_id,
                        operator_version=realized.operator_version,
                    )
            if (
                registration.may_change_signing_time
                or registration.may_replace_signer
                or registration.signature_header_action is not SignatureHeaderAction.NONE
            ) and signer_snapshot is None:
                raise MutationError.not_applicable(
                    "MUT_OPERATOR_REQUIRES_SIGNER",
                    "The mutation operator requires a selected signer.",
                    operator_id=realized.operator_id,
                    operator_version=realized.operator_version,
                )
            self._preflight_header_effects(
                current,
                signer_snapshot=signer_snapshot,
                header_claims=header_claims,
            )
            if registration.signature_header_action is not SignatureHeaderAction.NONE:
                if signature_action is not None:
                    raise MutationError.conflict(
                        "MUT_SIGNATURE_HEADER_ACTION_CONFLICT",
                        "Signature-header mutations conflict within one delivery.",
                        operator_id=realized.operator_id,
                        operator_version=realized.operator_version,
                        safe_details={
                            "prior_operator_id": (signature_action.realized.operator_id),
                            "prior_operator_version": (signature_action.realized.operator_version),
                        },
                    )
                signature_action = current
            prepared.append(current)

        if structural_present:
            _require_valid_json(
                body,
                code="MUT_STRUCTURAL_INPUT_INVALID_JSON",
                message="A structural mutation requires valid UTF-8 JSON input.",
            )
        return _PreparedPipeline(
            mutations=tuple(prepared),
            body=body,
            headers=materialized_headers,
            signer=signer,
            signer_snapshot=signer_snapshot,
        )

    def _preflight_header_effects(
        self,
        current: _PreparedMutation,
        *,
        signer_snapshot: _SignerSnapshot | None,
        header_claims: dict[str, _PreparedMutation],
    ) -> None:
        registration = current.registration
        static_targets = (
            *registration.written_headers,
            *registration.removed_headers,
        )
        signer_headers: frozenset[str] = (
            frozenset[str]()
            if signer_snapshot is None
            else frozenset(signer_snapshot.owned_headers)
        )
        if (
            registration.signature_header_action is SignatureHeaderAction.NONE
            and signer_headers.intersection(static_targets)
        ):
            raise MutationError.conflict(
                "MUT_SIGNER_HEADER_OWNERSHIP_CONFLICT",
                "A mutation targets a header exclusively owned by the signer.",
                operator_id=current.realized.operator_id,
                operator_version=current.realized.operator_version,
            )
        if (
            registration.signature_header_action is SignatureHeaderAction.REMOVE
            and signer_headers.intersection(registration.written_headers)
        ):
            raise MutationError.conflict(
                "MUT_SIGNATURE_HEADER_ACTION_CONFLICT",
                "A signature-removal operator also declares a signer-header write.",
                operator_id=current.realized.operator_id,
                operator_version=current.realized.operator_version,
            )
        for header_name in static_targets:
            prior = header_claims.get(header_name)
            if prior is not None:
                raise MutationError.conflict(
                    "MUT_HEADER_TARGET_CONFLICT",
                    "Two mutation operators claim the same normalized header.",
                    operator_id=current.realized.operator_id,
                    operator_version=current.realized.operator_version,
                    safe_details={
                        "header_name": header_name,
                        "prior_operator_id": prior.realized.operator_id,
                        "prior_operator_version": prior.realized.operator_version,
                    },
                )
            header_claims[header_name] = current

    def _apply_one(
        self,
        state: MutationState,
        prepared: _PreparedMutation,
        *,
        event_id: str,
        media_type: str,
        expected_signer_snapshot: _SignerSnapshot | None,
    ) -> tuple[MutationState, MutationEvidence]:
        registration = prepared.registration
        realized = prepared.realized
        if registration.requires_valid_json:
            _require_valid_json(
                state.body,
                code="MUT_STRUCTURAL_INPUT_INVALID_JSON",
                message="A structural mutation received invalid UTF-8 JSON.",
                operator_id=realized.operator_id,
                operator_version=realized.operator_version,
            )
        mutation_input = MutationInput(
            realized=realized,
            state=state,
            event_id=event_id,
            media_type=media_type,
        )
        input_snapshot = _state_snapshot(state)
        realized_snapshot = _realized_snapshot(realized)
        input_digest = sha256_digest(state.body)
        try:
            output = registration.implementation.apply(mutation_input)
        except MutationError:
            raise
        except Exception:
            raise MutationError.not_applicable(
                "MUT_OPERATOR_FAILED",
                "The mutation operator could not apply its realized parameters.",
                operator_id=realized.operator_id,
                operator_version=realized.operator_version,
            ) from None
        if (
            _state_snapshot(mutation_input.state) != input_snapshot
            or _realized_snapshot(mutation_input.realized) != realized_snapshot
        ):
            raise MutationError.conflict(
                "MUT_OPERATOR_MUTATED_INPUT",
                "A mutation operator modified its immutable input alias.",
                operator_id=realized.operator_id,
                operator_version=realized.operator_version,
            )
        if type(output) is not MutationOutput:
            raise MutationError.conflict(
                "MUT_OPERATOR_OUTPUT_INVALID",
                "A mutation operator returned an invalid output contract.",
                operator_id=realized.operator_id,
                operator_version=realized.operator_version,
            )
        candidate = MutationState(
            body=output.body,
            headers=tuple(output.headers),
            signing_time_ns=output.signing_time_ns,
            signer=output.signer,
        )
        self._validate_state_resources(candidate)
        self._validate_declared_effects(
            before=state,
            after=candidate,
            prepared=prepared,
            expected_signer_snapshot=expected_signer_snapshot,
        )
        if realized.stage is MutationStage.STRUCTURAL:
            _require_valid_json(
                candidate.body,
                code="MUT_STRUCTURAL_OUTPUT_INVALID_JSON",
                message="A structural mutation produced invalid UTF-8 JSON.",
                operator_id=realized.operator_id,
                operator_version=realized.operator_version,
            )
        output_digest = sha256_digest(candidate.body)
        return candidate, MutationEvidence(
            operator_id=realized.operator_id,
            operator_version=realized.operator_version,
            stage=realized.stage,
            parameters_safe=realized.parameters_safe,
            input_body_sha256=input_digest,
            output_body_sha256=output_digest,
        )

    def _validate_declared_effects(
        self,
        *,
        before: MutationState,
        after: MutationState,
        prepared: _PreparedMutation,
        expected_signer_snapshot: _SignerSnapshot | None,
    ) -> None:
        registration = prepared.registration
        realized = prepared.realized
        if before.body != after.body and not registration.changes_body:
            _raise_undeclared_effect(realized, "body")
        if (
            before.signing_time_ns != after.signing_time_ns
            and not registration.may_change_signing_time
        ):
            _raise_undeclared_effect(realized, "signing_time")
        if before.signer is not after.signer:
            if not registration.may_replace_signer:
                _raise_undeclared_effect(realized, "signer")
            replacement_signer = after.signer
            expected = expected_signer_snapshot
            if replacement_signer is None or expected is None:
                _raise_undeclared_effect(realized, "signer")
            replacement = _snapshot_signer(replacement_signer)
            if (
                replacement.adapter_id != expected.adapter_id
                or replacement.adapter_version != expected.adapter_version
                or replacement.owned_headers != expected.owned_headers
            ):
                raise MutationError.conflict(
                    "MUT_REPLACEMENT_SIGNER_CONTRACT",
                    "A replacement signer changed adapter identity or header ownership.",
                    operator_id=realized.operator_id,
                    operator_version=realized.operator_version,
                )
        self._validate_header_effects(
            before=before.headers,
            after=after.headers,
            prepared=prepared,
            signer_snapshot=expected_signer_snapshot,
        )

    def _validate_header_effects(
        self,
        *,
        before: tuple[SignatureHeader, ...],
        after: tuple[SignatureHeader, ...],
        prepared: _PreparedMutation,
        signer_snapshot: _SignerSnapshot | None,
    ) -> None:
        registration = prepared.registration
        realized = prepared.realized
        before_by_name = {header.name: header.value for header in before}
        after_by_name = {header.name: header.value for header in after}
        removed = set(before_by_name) - set(after_by_name)
        written = {
            name for name, value in after_by_name.items() if before_by_name.get(name) != value
        }
        allowed_removed = set(registration.removed_headers)
        allowed_written = set(registration.written_headers)
        signer_headers: set[str] = (
            set() if signer_snapshot is None else set(signer_snapshot.owned_headers)
        )
        if registration.signature_header_action is SignatureHeaderAction.REMOVE:
            allowed_removed.update(signer_headers)
        elif registration.signature_header_action is SignatureHeaderAction.REPLACE:
            allowed_removed.update(signer_headers)
            allowed_written.update(signer_headers)
        if not removed.issubset(allowed_removed) or not written.issubset(allowed_written):
            _raise_undeclared_effect(realized, "headers")
        targeted = allowed_removed | allowed_written
        before_untargeted = tuple(
            (header.name, header.value) for header in before if header.name not in targeted
        )
        after_untargeted = tuple(
            (header.name, header.value) for header in after if header.name not in targeted
        )
        if before_untargeted != after_untargeted:
            _raise_undeclared_effect(realized, "header_order")

    def _sign(
        self,
        state: MutationState,
        *,
        event_id: str,
        expected_snapshot: _SignerSnapshot | None,
    ) -> tuple[MutationState, SigningEvidence | None, str | None]:
        if state.signer is None:
            if expected_snapshot is not None:
                raise MutationError.conflict(
                    "MUT_SIGNER_REMOVED",
                    "A mutation removed the selected signer before signing.",
                )
            return state, None, None
        actual_snapshot = _snapshot_signer(state.signer)
        if expected_snapshot is None or (
            actual_snapshot.adapter_id != expected_snapshot.adapter_id
            or actual_snapshot.adapter_version != expected_snapshot.adapter_version
            or actual_snapshot.owned_headers != expected_snapshot.owned_headers
        ):
            raise MutationError.conflict(
                "MUT_SIGNER_CONTRACT_CHANGED",
                "The selected signer changed identity or header ownership.",
            )
        _reject_signer_input_collision(actual_snapshot, headers=state.headers)
        signing_input = SigningInput(
            body=state.body,
            event_id=event_id,
            logical_time_ns=state.signing_time_ns,
        )
        input_snapshot = (
            signing_input.body,
            signing_input.event_id,
            signing_input.logical_time_ns,
        )
        try:
            result = state.signer.sign(signing_input)
        except SignerError:
            raise
        except Exception:
            raise MutationError.not_applicable(
                "MUT_SIGNER_FAILED",
                "The selected signer could not sign the realized request.",
            ) from None
        if (
            signing_input.body,
            signing_input.event_id,
            signing_input.logical_time_ns,
        ) != input_snapshot:
            raise MutationError.conflict(
                "MUT_SIGNER_MUTATED_INPUT",
                "The signer modified its immutable signing input.",
            )
        if type(result) is not SigningResult:
            raise MutationError.conflict(
                "MUT_SIGNER_OUTPUT_INVALID",
                "The signer returned an invalid signing result.",
            )
        expected_digest = sha256_digest(state.body)
        evidence = result.evidence
        if (
            evidence.adapter_id != actual_snapshot.adapter_id
            or evidence.adapter_version != actual_snapshot.adapter_version
            or evidence.logical_time_ns != state.signing_time_ns
            or evidence.body_sha256 != expected_digest
            or tuple(header.name for header in result.headers) != actual_snapshot.owned_headers
        ):
            raise MutationError.conflict(
                "MUT_SIGNER_EVIDENCE_CONFLICT",
                "Signer output does not match the realized exact-byte input.",
            )
        candidate = MutationState(
            body=state.body,
            headers=(*state.headers, *result.headers),
            signing_time_ns=state.signing_time_ns,
            signer=state.signer,
        )
        self._validate_state_resources(candidate)
        return candidate, evidence, expected_digest

    def _validate_state_resources(self, state: MutationState) -> None:
        if len(state.body) > self._limits.max_body_bytes:
            raise MutationError.resource_limit(
                "MUT_BODY_LIMIT",
                "A mutation output exceeds the configured body limit.",
            )
        if len(state.headers) > self._limits.max_headers:
            raise MutationError.resource_limit(
                "MUT_HEADER_COUNT_LIMIT",
                "A mutation output exceeds the configured header-count limit.",
            )
        self._validate_header_resources(state.headers)

    def _validate_header_resources(
        self,
        headers: tuple[SignatureHeader, ...],
    ) -> None:
        total = sum(
            len(header.name.encode("ascii")) + len(header.value.encode("ascii"))
            for header in headers
        )
        if total > self._limits.max_total_header_bytes:
            raise MutationError.resource_limit(
                "MUT_HEADER_BYTES_LIMIT",
                "Mutation headers exceed the configured aggregate byte limit.",
            )


def _bounded_headers(
    values: object,
    *,
    maximum: int,
) -> tuple[SignatureHeader, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise MutationError.invalid_parameter(
            "MUT_HEADERS_INVALID",
            "Pipeline headers must be a bounded sequence.",
        )
    sequence = cast("Sequence[SignatureHeader]", values)
    materialized = _bounded_exact_sequence(
        sequence,
        maximum=maximum,
        expected_type=SignatureHeader,
        invalid_code="MUT_HEADERS_INVALID",
        invalid_message="Pipeline headers contain an invalid value.",
        limit_code="MUT_HEADER_COUNT_LIMIT",
        limit_message="Pipeline headers exceed the configured count limit.",
    )
    try:
        return tuple(
            SignatureHeader(name=header.name, value=header.value) for header in materialized
        )
    except (TypeError, ValueError):
        raise MutationError.invalid_parameter(
            "MUT_HEADERS_INVALID",
            "Pipeline headers contain an invalid value.",
        ) from None


def _bounded_mutations(
    values: object,
    *,
    maximum: int,
) -> tuple[RealizedMutation, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise MutationError.invalid_parameter(
            "MUT_SEQUENCE_INVALID",
            "Mutations must be a bounded sequence of realized operators.",
        )
    sequence = cast("Sequence[RealizedMutation]", values)
    return _bounded_exact_sequence(
        sequence,
        maximum=maximum,
        expected_type=RealizedMutation,
        invalid_code="MUT_SEQUENCE_INVALID",
        invalid_message="Mutations contain an invalid realized operator.",
        limit_code="MUT_SEQUENCE_LIMIT",
        limit_message="Mutations exceed the configured operator-count limit.",
    )


def _bounded_exact_sequence[T](
    values: Sequence[T],
    *,
    maximum: int,
    expected_type: type[T],
    invalid_code: str,
    invalid_message: str,
    limit_code: str,
    limit_message: str,
) -> tuple[T, ...]:
    try:
        iterator = iter(values)
    except Exception:
        raise MutationError.invalid_parameter(invalid_code, invalid_message) from None
    materialized: list[T] = []
    for index in range(maximum + 1):
        try:
            value = next(iterator)
        except StopIteration:
            return tuple(materialized)
        except Exception:
            raise MutationError.invalid_parameter(invalid_code, invalid_message) from None
        if index == maximum:
            raise MutationError.resource_limit(limit_code, limit_message)
        if type(value) is not expected_type:
            raise MutationError.invalid_parameter(invalid_code, invalid_message)
        materialized.append(value)
    raise AssertionError("bounded sequence loop did not terminate")


def _snapshot_signer(signer: Signer) -> _SignerSnapshot:
    try:
        adapter_id = signer.adapter_id
        adapter_version = signer.adapter_version
        raw_owned_headers = signer.owned_headers
        if (
            type(adapter_id) is not str
            or _SIGNER_IDENTIFIER.fullmatch(adapter_id) is None
            or type(adapter_version) is not str
            or _SIGNER_IDENTIFIER.fullmatch(adapter_version) is None
        ):
            raise ValueError
        owned_headers = validate_header_ownership(raw_owned_headers)
    except Exception:
        raise MutationError.not_applicable(
            "MUT_SIGNER_CONTRACT_INVALID",
            "The selected signer has an invalid identity or header-ownership contract.",
        ) from None
    return _SignerSnapshot(
        signer=signer,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        owned_headers=owned_headers,
    )


def _reject_signer_input_collision(
    snapshot: _SignerSnapshot,
    *,
    headers: tuple[SignatureHeader, ...],
) -> None:
    try:
        validate_header_ownership(
            snapshot.owned_headers,
            user_header_names=tuple(header.name for header in headers),
        )
    except SignerError:
        raise MutationError.conflict(
            "MUT_SIGNER_HEADER_COLLISION",
            "A planned request header conflicts with signer-owned header space.",
        ) from None


def _state_snapshot(
    state: MutationState,
) -> tuple[bytes, tuple[tuple[str, str], ...], int, int | None]:
    return (
        state.body,
        tuple((header.name, header.value) for header in state.headers),
        state.signing_time_ns,
        None if state.signer is None else id(state.signer),
    )


def _realized_snapshot(
    realized: RealizedMutation,
) -> tuple[str, int, MutationStage, JsonObject, JsonObject]:
    return (
        realized.operator_id,
        realized.operator_version,
        realized.stage,
        thaw_parameter_object(realized.parameters),
        thaw_parameter_object(realized.parameters_safe),
    )


def _detach_realized(realized: RealizedMutation) -> RealizedMutation:
    return RealizedMutation(
        operator_id=realized.operator_id,
        operator_version=realized.operator_version,
        stage=realized.stage,
        parameters=cast("dict[str, object]", thaw_parameter_object(realized.parameters)),
        parameters_safe=cast(
            "dict[str, object]",
            thaw_parameter_object(realized.parameters_safe),
        ),
    )


def _raise_undeclared_effect(realized: RealizedMutation, effect: str) -> NoReturn:
    raise MutationError.conflict(
        "MUT_OPERATOR_UNDECLARED_EFFECT",
        "A mutation operator produced an effect outside its registered contract.",
        operator_id=realized.operator_id,
        operator_version=realized.operator_version,
        safe_details={"effect": effect},
    )


def _require_valid_json(
    body: bytes,
    *,
    code: str,
    message: str,
    operator_id: str | None = None,
    operator_version: int | None = None,
) -> None:
    try:
        decoded = body.decode("utf-8")
        json.loads(decoded, parse_constant=_reject_non_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise MutationError.not_applicable(
            code,
            message,
            operator_id=operator_id,
            operator_version=operator_version,
        ) from None


def _reject_non_json_constant(_token: str) -> NoReturn:
    message = "non-finite constants are not valid JSON"
    raise ValueError(message)


def _is_json_media_type(media_type: str) -> bool:
    base = media_type.partition(";")[0].strip().casefold()
    return base == "application/json" or base.endswith("+json")


def _validate_limit(
    value: int,
    *,
    field_name: str,
    hard_maximum: int,
    allow_zero: bool = False,
) -> None:
    if type(value) is not int:
        message = f"{field_name} must be an integer"
        raise TypeError(message)
    minimum = 0 if allow_zero else 1
    if not minimum <= value <= hard_maximum:
        message = f"{field_name} exceeds its hard bounded range"
        raise ValueError(message)


def _require_digest(value: str) -> None:
    if not (
        type(value) is str
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    ):
        message = "pipeline digest must be a prefixed lowercase SHA-256 value"
        raise ValueError(message)
