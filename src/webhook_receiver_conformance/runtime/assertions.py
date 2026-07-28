"""Assertion dispatch, capability preflight, lifecycle, and durable verdicts."""
# ruff: noqa: BLE001, D105, D107, EM101, INP001, PLR0913, SIM114, TRY003, TRY301

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Union, cast, get_args, get_origin

from webhook_receiver_conformance.assertions.composite import (
    CompositeAssertionCode,
    NoPartialSideEffectEvaluation,
    evaluate_composite_assertion,
)
from webhook_receiver_conformance.assertions.state import (
    StateAssertionCode,
    StateAssertionEvaluation,
    StateAssertionFact,
    evaluate_state_assertion,
)
from webhook_receiver_conformance.assertions.temporal import (
    EventualStateEvaluation,
    OrderedTransitionEvaluation,
    TemporalAssertionCode,
    evaluate_temporal_assertion,
)
from webhook_receiver_conformance.assertions.transport import (
    TransportAssertionCode,
    TransportAssertionEvaluation,
    TransportAssertionInput,
    evaluate_transport_assertion,
)
from webhook_receiver_conformance.config.models import (
    AcknowledgementDeadlineAssertion,
    AssertionConfig,
    CallbackCountAssertion,
    EventualStateAssertion,
    HttpStatusAssertion,
    JournalCountAssertion,
    NoPartialSideEffectAssertion,
    OnUnsupported,
    OrderedTransitionAssertion,
    ProcessingCountAssertion,
    ResourceAbsentAssertion,
    ResourceExistsAssertion,
    ResourceFieldAssertion,
    TypedValue,
)
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    EvidenceValueType,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    new_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.domain.models import AssertionEvaluation, AttemptEvidence
from webhook_receiver_conformance.journal.repositories import (
    AssertionEvaluationCommand,
    AssertionEvidenceKind,
    AssertionEvidenceReference,
    AssertionRepository,
    CommittedAssertionEvaluation,
)
from webhook_receiver_conformance.journal.transitions import (
    CausalReference,
    CommittedTransition,
    EntityType,
    TransitionCommand,
)
from webhook_receiver_conformance.observers.polling import ObservationPollResult
from webhook_receiver_conformance.observers.protocol import (
    ObserverCapabilities,
    ObserverEvidence,
    ObserverResponse,
)

from .verdicts import (
    AssertionErrorOrigin,
    TerminalVerdict,
    classify_assertion_verdict,
)

if TYPE_CHECKING:
    from webhook_receiver_conformance.scheduler.clocks import RuntimeClock
    from webhook_receiver_conformance.types import JsonValue

type AssertionEvidencePayload = (
    AttemptEvidence
    | TransportAssertionInput
    | tuple[ObserverEvidence, ...]
    | ObservationPollResult
    | ObserverResponse
)
type AssertionEvaluatorResult = (
    TransportAssertionEvaluation
    | StateAssertionEvaluation
    | OrderedTransitionEvaluation
    | EventualStateEvaluation
    | NoPartialSideEffectEvaluation
)
type EvidenceSupplier = Callable[[], Awaitable["AssertionEvidenceBundle"]]
type FreshIdFactory = Callable[[FreshIdKind], str]
type AssertionConfigType = type[
    HttpStatusAssertion
    | AcknowledgementDeadlineAssertion
    | ProcessingCountAssertion
    | CallbackCountAssertion
    | JournalCountAssertion
    | ResourceExistsAssertion
    | ResourceAbsentAssertion
    | ResourceFieldAssertion
    | EventualStateAssertion
    | OrderedTransitionAssertion
    | NoPartialSideEffectAssertion
]
type TransportAssertionConfig = HttpStatusAssertion | AcknowledgementDeadlineAssertion
type StateAssertionConfig = (
    ProcessingCountAssertion
    | CallbackCountAssertion
    | JournalCountAssertion
    | ResourceExistsAssertion
    | ResourceAbsentAssertion
    | ResourceFieldAssertion
)
type TemporalAssertionConfig = OrderedTransitionAssertion | EventualStateAssertion
type ObserverAssertionConfig = (
    StateAssertionConfig | TemporalAssertionConfig | NoPartialSideEffectAssertion
)

TRIGGER_ASSERTION_STARTED = "assertion_started"
TRIGGER_ASSERTION_EVALUATION = "assertion_evaluation"
TRIGGER_ASSERTION_CANCELLED = "assertion_cancelled"
REDACTED_ASSERTION_VALUE = "[REDACTED]"


class AssertionEvaluatorFamily(StrEnum):
    """Closed built-in evaluator families."""

    TRANSPORT = "transport"
    STATE = "state"
    TEMPORAL = "temporal"
    COMPOSITE = "composite"


@dataclass(frozen=True, slots=True)
class AssertionRegistration:
    """One configuration type registered with its shared contract suite."""

    type_name: str
    config_type: AssertionConfigType
    family: AssertionEvaluatorFamily
    contract_test_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.type_name) is not str or not self.type_name:
            raise ValueError("type_name must be a nonempty string")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.config_type,
            type,
        ):
            raise TypeError("config_type must be a class")
        if type(self.family) is not AssertionEvaluatorFamily:
            raise TypeError("family must be an AssertionEvaluatorFamily")
        if (
            type(self.contract_test_ids) is not tuple
            or not self.contract_test_ids
            or any(type(item) is not str or not item for item in self.contract_test_ids)
        ):
            raise ValueError("contract_test_ids must contain nonempty test IDs")


_ASSERTION_REGISTRATIONS = (
    AssertionRegistration(
        "http-status",
        HttpStatusAssertion,
        AssertionEvaluatorFamily.TRANSPORT,
        ("VT-ASSERT-001", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "acknowledgement-deadline",
        AcknowledgementDeadlineAssertion,
        AssertionEvaluatorFamily.TRANSPORT,
        ("VT-ASSERT-003", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "processing-count",
        ProcessingCountAssertion,
        AssertionEvaluatorFamily.STATE,
        ("VT-ASSERT-004", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "callback-count",
        CallbackCountAssertion,
        AssertionEvaluatorFamily.STATE,
        ("VT-ASSERT-005", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "journal-count",
        JournalCountAssertion,
        AssertionEvaluatorFamily.STATE,
        ("VT-ASSERT-006", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "resource-exists",
        ResourceExistsAssertion,
        AssertionEvaluatorFamily.STATE,
        ("VT-ASSERT-007", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "resource-absent",
        ResourceAbsentAssertion,
        AssertionEvaluatorFamily.STATE,
        ("VT-ASSERT-008", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "resource-field",
        ResourceFieldAssertion,
        AssertionEvaluatorFamily.STATE,
        ("VT-ASSERT-009", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "ordered-transition",
        OrderedTransitionAssertion,
        AssertionEvaluatorFamily.TEMPORAL,
        ("VT-ASSERT-010", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "eventual-state",
        EventualStateAssertion,
        AssertionEvaluatorFamily.TEMPORAL,
        ("VT-ASSERT-012", "VT-ASSERT-013", "VT-TEST-002"),
    ),
    AssertionRegistration(
        "no-partial-side-effect",
        NoPartialSideEffectAssertion,
        AssertionEvaluatorFamily.COMPOSITE,
        ("VT-ASSERT-011", "VT-ASSERT-013", "VT-TEST-002"),
    ),
)
BUILTIN_ASSERTION_REGISTRY: Mapping[AssertionConfigType, AssertionRegistration] = MappingProxyType(
    {registration.config_type: registration for registration in _ASSERTION_REGISTRATIONS}
)


@dataclass(frozen=True, slots=True)
class AssertionRuntimeContext:
    """Stable planned assertion identity plus the active owner epoch."""

    run_id: str
    scenario_id: str
    assertion_id: str
    owner_epoch: int

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_planned_id(
            self.assertion_id,
            expected_kind=PlannedIdKind.ASSERTION,
        )
        if type(self.owner_epoch) is not int or self.owner_epoch < 0:
            raise ValueError("owner_epoch must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class AssertionEvidenceBundle:
    """One evaluator input and its separately typed durable evidence links."""

    payload: AssertionEvidencePayload
    references: tuple[AssertionEvidenceReference, ...]

    def __post_init__(self) -> None:
        if (
            type(self.references) is not tuple
            or not self.references
            or any(type(item) is not AssertionEvidenceReference for item in self.references)
        ):
            raise TypeError("references must be a nonempty tuple of typed evidence links")


@dataclass(frozen=True, slots=True)
class CapabilityGap:
    """Stable pre-poll description of required observer facts that are absent."""

    missing_keys: tuple[str, ...] = ()
    missing_types: tuple[EvidenceValueType, ...] = ()
    automatic_polling_unavailable: bool = False

    @property
    def supported(self) -> bool:
        """Return whether all required observer capabilities are present."""
        return not (self.missing_keys or self.missing_types or self.automatic_polling_unavailable)


@dataclass(frozen=True, slots=True)
class NormalizedAssertionEvaluation:
    """Persistence-safe evaluator facts and their terminal classification."""

    result: AssertionResult
    state: AssertionState
    verdict: TerminalVerdict
    code: str
    expected: JsonValue = None
    actual: JsonValue = None
    comparison: str | None = None
    message: str | None = None
    error_origin: AssertionErrorOrigin | None = None

    def __post_init__(self) -> None:
        if type(self.result) is not AssertionResult:
            raise TypeError("result must be an AssertionResult")
        if type(self.state) is not AssertionState:
            raise TypeError("state must be an AssertionState")
        if type(self.verdict) is not TerminalVerdict:
            raise TypeError("verdict must be a TerminalVerdict")
        if type(self.code) is not str or not self.code:
            raise ValueError("code must be a nonempty string")
        classified = classify_assertion_verdict(
            self.result,
            self.state,
            error_origin=self.error_origin,
        )
        if classified != self.verdict:
            raise ValueError("normalized verdict differs from its lifecycle facts")


@dataclass(frozen=True, slots=True)
class AssertionLifecycleResult:
    """One committed public record and its exact terminal verdict."""

    committed: CommittedAssertionEvaluation
    normalized: NormalizedAssertionEvaluation


class AssertionLifecycle:
    """Run preflight, pure evaluation, and journal persistence in lifecycle order."""

    __slots__ = ("_clock", "_fresh_id", "_repository")

    def __init__(
        self,
        *,
        repository: AssertionRepository,
        clock: RuntimeClock,
        fresh_id: FreshIdFactory = new_fresh_id,
    ) -> None:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            repository,
            AssertionRepository,
        ):
            raise TypeError("repository must be an AssertionRepository")
        if not callable(fresh_id):
            raise TypeError("fresh_id must be callable")
        self._repository = repository
        self._clock = clock
        self._fresh_id = fresh_id

    async def evaluate(
        self,
        context: AssertionRuntimeContext,
        assertion: AssertionConfig,
        bundle: AssertionEvidenceBundle,
    ) -> AssertionLifecycleResult:
        """Evaluate already-collected evidence and persist one terminal result."""
        _validate_runtime_inputs(context, assertion)
        _validate_bundle_for_assertion(assertion, bundle)
        await self._start(context)
        normalized = _evaluate_and_normalize(assertion, bundle.payload)
        return await self._persist(
            context,
            assertion,
            normalized,
            bundle.references,
        )

    async def evaluate_observer(
        self,
        context: AssertionRuntimeContext,
        assertion: AssertionConfig,
        capabilities: ObserverCapabilities,
        evidence_supplier: EvidenceSupplier,
        *,
        capability_reference: AssertionEvidenceReference | None = None,
    ) -> AssertionLifecycleResult:
        """Reject capability gaps before invoking an observer polling supplier."""
        _validate_runtime_inputs(context, assertion)
        if not _is_observer_assertion(assertion):
            raise TypeError("evaluate_observer requires an observer assertion")
        if type(capabilities) is not ObserverCapabilities:
            raise TypeError("capabilities must be ObserverCapabilities")
        if not callable(evidence_supplier):
            raise TypeError("evidence_supplier must be callable")
        start = await self._start(context)
        gap = observer_capability_gap(assertion, capabilities)
        if not gap.supported:
            if type(capability_reference) is not AssertionEvidenceReference:
                raise ValueError(
                    "unsupported capability evaluation requires durable preflight evidence"
                )
            normalized = _unsupported_evaluation(assertion, capabilities, gap)
            references = (capability_reference,)
            return await self._persist(
                context,
                assertion,
                normalized,
                references,
            )
        del start
        bundle = await evidence_supplier()
        if type(bundle) is not AssertionEvidenceBundle:
            raise TypeError("evidence_supplier must return an AssertionEvidenceBundle")
        _validate_bundle_for_assertion(assertion, bundle)
        normalized = _evaluate_and_normalize(assertion, bundle.payload)
        return await self._persist(
            context,
            assertion,
            normalized,
            bundle.references,
        )

    async def cancel(
        self,
        context: AssertionRuntimeContext,
        *,
        expected_state: AssertionState,
    ) -> TerminalVerdict:
        """Persist an explicit assertion cancellation without fabricating evaluation."""
        if type(context) is not AssertionRuntimeContext:
            raise TypeError("context must be an AssertionRuntimeContext")
        if expected_state not in {
            AssertionState.PENDING,
            AssertionState.RUNNING,
        }:
            raise ValueError("assertion cancellation requires pending or running")
        timestamp = self._clock.transition_timestamp()
        await self._repository.transition(
            TransitionCommand(
                run_id=context.run_id,
                transition_id=f"assertion.cancel.{context.assertion_id}",
                entity_type=EntityType.ASSERTION,
                entity_id=context.assertion_id,
                expected_state=expected_state,
                new_state=AssertionState.CANCELLED,
                trigger_category=TRIGGER_ASSERTION_CANCELLED,
                timestamp=timestamp,
                owner_epoch=context.owner_epoch,
                idempotency_key=f"assertion.cancel.{context.assertion_id}",
            )
        )
        return classify_assertion_verdict(
            AssertionResult.ERROR,
            AssertionState.CANCELLED,
        )

    async def _start(
        self,
        context: AssertionRuntimeContext,
    ) -> CommittedTransition:
        timestamp = self._clock.transition_timestamp()
        return await self._repository.transition(
            TransitionCommand(
                run_id=context.run_id,
                transition_id=f"assertion.run.{context.assertion_id}",
                entity_type=EntityType.ASSERTION,
                entity_id=context.assertion_id,
                expected_state=AssertionState.PENDING,
                new_state=AssertionState.RUNNING,
                trigger_category=TRIGGER_ASSERTION_STARTED,
                timestamp=timestamp,
                owner_epoch=context.owner_epoch,
                idempotency_key=f"assertion.run.{context.assertion_id}",
            )
        )

    async def _persist(
        self,
        context: AssertionRuntimeContext,
        assertion: AssertionConfig,
        normalized: NormalizedAssertionEvaluation,
        references: tuple[AssertionEvidenceReference, ...],
    ) -> AssertionLifecycleResult:
        timestamp = self._clock.transition_timestamp()
        evaluation_id = self._fresh_id(FreshIdKind.EVALUATION)
        record_id = self._fresh_id(FreshIdKind.RECORD)
        evaluation = AssertionEvaluation(
            record_id=record_id,
            run_id=context.run_id,
            scenario_id=context.scenario_id,
            assertion_id=context.assertion_id,
            evaluation_sequence=1,
            recorded_at=timestamp.wall_time,
            type=assertion.type,
            result=normalized.result,
            expected=normalized.expected,
            actual=normalized.actual,
            comparison=normalized.comparison,
            evidence_refs=tuple(item.evidence_id for item in references),
            message=normalized.message,
        )
        terminal = TransitionCommand(
            run_id=context.run_id,
            transition_id=(f"assertion.evaluation.{evaluation.record_id}.{normalized.state.value}"),
            entity_type=EntityType.ASSERTION,
            entity_id=context.assertion_id,
            expected_state=AssertionState.RUNNING,
            new_state=normalized.state,
            trigger_category=TRIGGER_ASSERTION_EVALUATION,
            timestamp=timestamp,
            owner_epoch=context.owner_epoch,
            idempotency_key=(
                f"assertion.evaluation.{evaluation.record_id}.{normalized.state.value}"
            ),
            causal_reference=CausalReference(context.run_id, evaluation.record_id),
        )
        committed = await self._repository.append_evaluation(
            AssertionEvaluationCommand(
                evaluation_id=evaluation_id,
                evaluation=evaluation,
                evidence=references,
                terminal_transition=terminal,
            )
        )
        return AssertionLifecycleResult(committed, normalized)


def validate_builtin_assertion_registry(
    registrations: tuple[AssertionRegistration, ...] = _ASSERTION_REGISTRATIONS,
    *,
    declared_types: tuple[AssertionConfigType, ...] | None = None,
) -> None:
    """Fail closed when config implementations and contract registrations diverge."""
    if type(registrations) is not tuple or any(
        type(item) is not AssertionRegistration for item in registrations
    ):
        raise TypeError("registrations must be a tuple of AssertionRegistration")
    configured = _declared_assertion_types() if declared_types is None else declared_types
    if type(configured) is not tuple or any(
        not isinstance(item, type)  # pyright: ignore[reportUnnecessaryIsInstance]
        for item in configured
    ):
        raise TypeError("declared_types must be a tuple of assertion classes")
    registered_types = tuple(item.config_type for item in registrations)
    registered_names = tuple(item.type_name for item in registrations)
    if len(set(registered_types)) != len(registered_types):
        raise ValueError("a built-in assertion implementation is registered more than once")
    if len(set(registered_names)) != len(registered_names):
        raise ValueError("a built-in assertion type name is registered more than once")
    if set(registered_types) != set(configured):
        raise ValueError("built-in assertion implementations and contract registrations differ")
    for registration in registrations:
        model_fields = registration.config_type.model_fields
        type_field = model_fields.get("type")
        if type_field is None or get_args(type_field.annotation) != (registration.type_name,):
            raise ValueError("assertion registration type name differs from its config model")
        if "VT-TEST-002" not in registration.contract_test_ids:
            raise ValueError("every assertion registration requires the shared contract suite")


def observer_capability_gap(
    assertion: AssertionConfig,
    capabilities: ObserverCapabilities,
) -> CapabilityGap:
    """Return missing observer facts without invoking or polling the observer."""
    if not _is_observer_assertion(assertion):
        raise TypeError("capability negotiation requires an observer assertion")
    if type(capabilities) is not ObserverCapabilities:
        raise TypeError("capabilities must be ObserverCapabilities")
    requirements = _capability_requirements(assertion)
    missing_keys = tuple(key for key in requirements if key not in capabilities.evidence_keys)
    required_types = tuple(
        dict.fromkeys(
            value_type for value_types in requirements.values() for value_type in value_types
        )
    )
    missing_types = tuple(
        value_type for value_type in required_types if value_type not in capabilities.evidence_types
    )
    polling = _requires_automatic_polling(assertion)
    return CapabilityGap(
        missing_keys=missing_keys,
        missing_types=missing_types,
        automatic_polling_unavailable=(
            polling
            and not (capabilities.automatic_reinvocation_safe and capabilities.supports_pending)
        ),
    )


def _declared_assertion_types() -> tuple[AssertionConfigType, ...]:
    annotated = getattr(AssertionConfig, "__value__", AssertionConfig)
    if get_origin(annotated) is not Annotated:
        raise RuntimeError("AssertionConfig must remain an annotated union")
    annotated_args = get_args(annotated)
    union = annotated_args[0]
    if get_origin(union) not in {Union, type(int | str)}:
        raise RuntimeError("AssertionConfig must contain a closed union")
    members = get_args(union)
    if not members or any(not isinstance(member, type) for member in members):
        raise RuntimeError("AssertionConfig contains a non-class implementation")
    return cast("tuple[AssertionConfigType, ...]", members)


def _validate_runtime_inputs(
    context: AssertionRuntimeContext,
    assertion: AssertionConfig,
) -> None:
    if type(context) is not AssertionRuntimeContext:
        raise TypeError("context must be an AssertionRuntimeContext")
    if type(assertion) not in BUILTIN_ASSERTION_REGISTRY:
        raise TypeError("assertion is not a registered built-in implementation")


def _validate_bundle_for_assertion(
    assertion: AssertionConfig,
    bundle: AssertionEvidenceBundle,
) -> None:
    if type(bundle) is not AssertionEvidenceBundle:
        raise TypeError("bundle must be an AssertionEvidenceBundle")
    kinds = {item.kind for item in bundle.references}
    if _is_transport_assertion(assertion):
        if AssertionEvidenceKind.ATTEMPT not in kinds:
            raise ValueError("transport assertions require typed attempt evidence")
        if AssertionEvidenceKind.OBSERVATION in kinds:
            raise ValueError("transport assertions cannot consume observation evidence")
        return
    if AssertionEvidenceKind.OBSERVATION not in kinds:
        raise ValueError("observer assertions require typed observation evidence")
    if AssertionEvidenceKind.ATTEMPT in kinds:
        raise ValueError("observer assertions cannot consume attempt evidence")


def _evaluate_and_normalize(
    assertion: AssertionConfig,
    payload: AssertionEvidencePayload,
) -> NormalizedAssertionEvaluation:
    try:
        registration = BUILTIN_ASSERTION_REGISTRY[type(assertion)]
        if registration.family is AssertionEvaluatorFamily.TRANSPORT:
            if type(payload) not in {AttemptEvidence, TransportAssertionInput}:
                raise TypeError("transport assertion evidence has the wrong type")
            evaluation = evaluate_transport_assertion(
                cast("TransportAssertionConfig", assertion),
                cast("AttemptEvidence | TransportAssertionInput", payload),
            )
        elif registration.family is AssertionEvaluatorFamily.STATE:
            if type(payload) is not tuple:
                raise TypeError("state assertion evidence has the wrong type")
            evaluation = evaluate_state_assertion(
                cast("StateAssertionConfig", assertion),
                payload,
            )
        elif registration.family is AssertionEvaluatorFamily.TEMPORAL:
            evaluation = evaluate_temporal_assertion(
                cast("TemporalAssertionConfig", assertion),
                cast("tuple[ObserverEvidence, ...] | ObservationPollResult", payload),
            )
        else:
            if type(payload) is not ObserverResponse:
                raise TypeError("composite assertion evidence has the wrong type")
            evaluation = evaluate_composite_assertion(
                cast("NoPartialSideEffectAssertion", assertion),
                payload,
            )
        return _normalize_evaluator_result(evaluation)
    except Exception:
        return _normalized(
            AssertionResult.ERROR,
            AssertionState.ERROR,
            "evaluator_exception",
            error_origin=AssertionErrorOrigin.HARNESS,
            message="The built-in assertion evaluator failed safely.",
        )


def _normalize_evaluator_result(
    evaluation: AssertionEvaluatorResult,
) -> NormalizedAssertionEvaluation:
    result = evaluation.result
    code = evaluation.code.value
    state = _terminal_state(result, code)
    origin = _error_origin(evaluation) if state is AssertionState.ERROR else None
    expected: JsonValue = None
    actual: JsonValue = None

    if type(evaluation) is TransportAssertionEvaluation:
        if evaluation.deadline_ns is not None:
            expected = {"maximum_response_headers_elapsed_ns": evaluation.deadline_ns}
            actual = {
                "response_headers_elapsed_ns": evaluation.response_headers_elapsed_ns,
                "status": evaluation.actual_status,
            }
        else:
            expected = {
                "statuses": list(evaluation.expected_statuses),
                "classes": [item.value for item in evaluation.expected_classes],
            }
            actual = evaluation.actual_status
    elif type(evaluation) is StateAssertionEvaluation:
        expected = _fact_projection(evaluation.expected)
        actual = _fact_projection(evaluation.actual)
    elif type(evaluation) is OrderedTransitionEvaluation:
        expected = _fact_projection(evaluation.expected)
        actual = _fact_projection(evaluation.actual)
    elif type(evaluation) is EventualStateEvaluation:
        expected = _fact_projection(evaluation.expected)
        actual = _fact_projection(evaluation.actual)
    elif type(evaluation) is NoPartialSideEffectEvaluation:
        expected = {item.predicate_name: True for item in evaluation.predicates}
        actual = {item.predicate_name: item.truth_value for item in evaluation.predicates}
    return _normalized(
        result,
        state,
        code,
        expected=expected,
        actual=actual,
        error_origin=origin,
        comparison=code,
        message=f"Assertion evaluation completed with code {code}.",
    )


def _terminal_state(result: AssertionResult, code: str) -> AssertionState:
    if result is AssertionResult.PASS:
        return AssertionState.PASSED
    if result is AssertionResult.FAIL:
        return AssertionState.FAILED
    if result is AssertionResult.SKIPPED or code == "observer_unsupported":
        return AssertionState.UNSUPPORTED
    return AssertionState.ERROR


def _error_origin(
    evaluation: AssertionEvaluatorResult,
) -> AssertionErrorOrigin:
    if type(evaluation) is TransportAssertionEvaluation:
        return (
            AssertionErrorOrigin.HARNESS
            if evaluation.code is TransportAssertionCode.HEADER_TIMING_MISSING
            else AssertionErrorOrigin.ENVIRONMENT
        )
    if type(evaluation) is StateAssertionEvaluation:
        return (
            AssertionErrorOrigin.HARNESS
            if evaluation.code is StateAssertionCode.COMPARATOR_UNSUPPORTED
            else AssertionErrorOrigin.ENVIRONMENT
        )
    if type(evaluation) in {OrderedTransitionEvaluation, EventualStateEvaluation}:
        temporal = cast("OrderedTransitionEvaluation | EventualStateEvaluation", evaluation)
        return (
            AssertionErrorOrigin.HARNESS
            if temporal.code is TemporalAssertionCode.POLL_RESULT_INCONSISTENT
            else AssertionErrorOrigin.ENVIRONMENT
        )
    composite = cast("NoPartialSideEffectEvaluation", evaluation)
    if composite.code is CompositeAssertionCode.SNAPSHOT_SCOPE_MISMATCH:
        return AssertionErrorOrigin.INVALID_INPUT
    return AssertionErrorOrigin.ENVIRONMENT


def _normalized(
    result: AssertionResult,
    state: AssertionState,
    code: str,
    *,
    expected: JsonValue = None,
    actual: JsonValue = None,
    error_origin: AssertionErrorOrigin | None = None,
    comparison: str | None = None,
    message: str | None = None,
) -> NormalizedAssertionEvaluation:
    return NormalizedAssertionEvaluation(
        result=result,
        state=state,
        verdict=classify_assertion_verdict(
            result,
            state,
            error_origin=error_origin,
        ),
        code=code,
        expected=expected,
        actual=actual,
        comparison=comparison,
        message=message,
        error_origin=error_origin,
    )


def _unsupported_evaluation(
    assertion: AssertionConfig,
    capabilities: ObserverCapabilities,
    gap: CapabilityGap,
) -> NormalizedAssertionEvaluation:
    policy = cast("ObserverAssertionConfig", assertion).on_unsupported
    result = AssertionResult.SKIPPED if policy is OnUnsupported.SKIP else AssertionResult.ERROR
    expected: JsonValue = {
        "evidence_keys": list(_capability_requirements(assertion)),
        "evidence_types": [
            value_type.value
            for values in _capability_requirements(assertion).values()
            for value_type in values
        ],
        "automatic_polling": _requires_automatic_polling(assertion),
    }
    actual: JsonValue = {
        "evidence_keys": list(capabilities.evidence_keys),
        "evidence_types": [item.value for item in capabilities.evidence_types],
        "automatic_polling": (
            capabilities.automatic_reinvocation_safe and capabilities.supports_pending
        ),
        "missing_keys": list(gap.missing_keys),
        "missing_types": [item.value for item in gap.missing_types],
    }
    return _normalized(
        result,
        AssertionState.UNSUPPORTED,
        "observer_unsupported",
        expected=expected,
        actual=actual,
        comparison="observer capability preflight",
        message="The observer did not advertise every required assertion capability.",
    )


def _fact_projection(fact: StateAssertionFact | None) -> JsonValue:
    if fact is None:
        return None
    if fact.sensitive:
        value: object = REDACTED_ASSERTION_VALUE
    else:
        value = ObserverEvidence(
            key="assertion_value",
            value_type=fact.value_type,
            value=fact.value,
            sensitive=False,
        ).wire_dict()["value"]
    return {
        "value_type": fact.value_type.value,
        "value": cast("JsonValue", value),
    }


def _capability_requirements(
    assertion: AssertionConfig,
) -> Mapping[str, tuple[EvidenceValueType, ...]]:
    if type(assertion) in {
        ProcessingCountAssertion,
        CallbackCountAssertion,
        JournalCountAssertion,
    }:
        count_assertion = cast(
            "ProcessingCountAssertion | CallbackCountAssertion | JournalCountAssertion",
            assertion,
        )
        return MappingProxyType({count_assertion.query.key: (EvidenceValueType.INTEGER,)})
    if type(assertion) in {ResourceExistsAssertion, ResourceAbsentAssertion}:
        existence = cast("ResourceExistsAssertion | ResourceAbsentAssertion", assertion)
        return MappingProxyType({existence.query.key: (EvidenceValueType.BOOLEAN,)})
    if type(assertion) is ResourceFieldAssertion:
        return MappingProxyType({assertion.query.key: (EvidenceValueType.OBJECT,)})
    if type(assertion) is EventualStateAssertion:
        return MappingProxyType(
            {
                assertion.query.key: (
                    EvidenceValueType.OBJECT
                    if assertion.path is not None
                    else _typed_value_type(assertion.expected),
                )
            }
        )
    if type(assertion) is OrderedTransitionAssertion:
        return MappingProxyType({assertion.query.key: (EvidenceValueType.ARRAY,)})
    if type(assertion) is NoPartialSideEffectAssertion:
        requirements: dict[str, tuple[EvidenceValueType, ...]] = {}
        for predicate in assertion.predicates:
            requirements[predicate.query.key] = (
                EvidenceValueType.OBJECT
                if predicate.path is not None
                else _typed_value_type(predicate.expected),
            )
        return MappingProxyType(requirements)
    raise TypeError("transport assertions do not require observer capabilities")


def _typed_value_type(value: TypedValue) -> EvidenceValueType:
    wire = value.to_wire()
    raw = wire.get("value_type")
    if type(raw) is not str:
        raise TypeError("typed assertion value lacks a value_type")
    return EvidenceValueType(raw)


def _requires_automatic_polling(assertion: AssertionConfig) -> bool:
    if type(assertion) is EventualStateAssertion:
        return True
    if not _is_observer_assertion(assertion):
        return False
    observer_assertion = cast("ObserverAssertionConfig", assertion)
    return observer_assertion.within is not None


def _is_transport_assertion(assertion: AssertionConfig) -> bool:
    return type(assertion) in {
        HttpStatusAssertion,
        AcknowledgementDeadlineAssertion,
    }


def _is_observer_assertion(assertion: AssertionConfig) -> bool:
    return type(assertion) in {
        ProcessingCountAssertion,
        CallbackCountAssertion,
        JournalCountAssertion,
        ResourceExistsAssertion,
        ResourceAbsentAssertion,
        ResourceFieldAssertion,
        EventualStateAssertion,
        OrderedTransitionAssertion,
        NoPartialSideEffectAssertion,
    }


validate_builtin_assertion_registry()


__all__ = [
    "BUILTIN_ASSERTION_REGISTRY",
    "REDACTED_ASSERTION_VALUE",
    "TRIGGER_ASSERTION_CANCELLED",
    "TRIGGER_ASSERTION_EVALUATION",
    "TRIGGER_ASSERTION_STARTED",
    "AssertionEvaluatorFamily",
    "AssertionEvidenceBundle",
    "AssertionLifecycle",
    "AssertionLifecycleResult",
    "AssertionRegistration",
    "AssertionRuntimeContext",
    "CapabilityGap",
    "NormalizedAssertionEvaluation",
    "observer_capability_gap",
    "validate_builtin_assertion_registry",
]
