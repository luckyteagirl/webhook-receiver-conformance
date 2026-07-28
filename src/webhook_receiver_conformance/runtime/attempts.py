"""Journal-first orchestration for exactly one physical HTTP attempt."""
# ruff: noqa: C901, D105, D107, EM101, INP001, PLR0911, PLR0913, PLR2004, TRY003

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from anyio.lowlevel import checkpoint

from webhook_receiver_conformance.domain.enums import (
    AttemptClassification,
    AttemptEvidenceState,
    AttemptState,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    new_fresh_id,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.domain.models import (
    RequestMetadata,
    ResponseMetadata,
    TransportError,
)
from webhook_receiver_conformance.http.evidence import (
    AttemptErrorCode,
    AttemptOutcome,
    AttemptProgressCheckpoint,
    AttemptResult,
    HeaderOwner,
)
from webhook_receiver_conformance.http.executor import (
    HttpAttemptCommand,
    HttpAttemptExecutor,
    HttpHeader,
)
from webhook_receiver_conformance.journal.repositories import TransitionRepository
from webhook_receiver_conformance.journal.transitions import (
    MAX_OWNER_EPOCH,
    MAX_SAFE_INTEGER,
    AttemptPhaseEvidence,
    AttemptPhaseEvidenceCommand,
    AttemptResponseStagingCommand,
    AttemptScheduleClaim,
    AttemptTerminalOutcome,
    AttemptTransportEvidenceCommand,
    EntityType,
    RetrySchedule,
    TransitionCommand,
)
from webhook_receiver_conformance.manifest.compiler import RealizedDeliveryExecution
from webhook_receiver_conformance.mutations.base import StaticMutationRegistry
from webhook_receiver_conformance.mutations.pipeline import (
    MutationPipeline,
    MutationPipelineResult,
)
from webhook_receiver_conformance.mutations.raw_ops import RAW_MUTATION_REGISTRATIONS
from webhook_receiver_conformance.mutations.signature_ops import (
    SIGNATURE_MUTATION_REGISTRATIONS,
)
from webhook_receiver_conformance.scheduler.clocks import RuntimeClock, TransitionTimestamp
from webhook_receiver_conformance.scheduler.retries import (
    ClassifiedPredecessor,
    RetryDecision,
    RetryPredicate,
)
from webhook_receiver_conformance.signatures.base import SignatureHeader, Signer

_TIMEOUT_CODES: Final = frozenset(
    {
        AttemptErrorCode.CONNECT_TIMEOUT,
        AttemptErrorCode.READ_TIMEOUT,
        AttemptErrorCode.WRITE_TIMEOUT,
        AttemptErrorCode.POOL_TIMEOUT,
        AttemptErrorCode.TOTAL_TIMEOUT,
    }
)
_RUNTIME_MUTATION_REGISTRY: Final = StaticMutationRegistry(
    (*RAW_MUTATION_REGISTRATIONS, *SIGNATURE_MUTATION_REGISTRATIONS)
)
type RetryDecider = Callable[[ClassifiedPredecessor], RetryDecision]
type RetryableStatus = Callable[[int], bool]
type RecordIdFactory = Callable[[], str]


@dataclass(frozen=True, slots=True)
class AttemptRuntimeContext:
    """Stable run and ordering coordinates needed by journal commands."""

    run_id: str
    scenario_id: str
    event_id: str
    delivery_id: str
    attempt_id: str
    owner_epoch: int
    logical_time_ns: int
    scenario_ordinal: int
    step_ordinal: int
    delivery_ordinal: int
    attempt_ordinal: int

    def __post_init__(self) -> None:
        """Reject malformed identity and ordering coordinates at the boundary."""
        validate_run_id(self.run_id)
        validate_planned_id(self.scenario_id, expected_kind=PlannedIdKind.SCENARIO)
        validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)
        validate_planned_id(self.delivery_id, expected_kind=PlannedIdKind.DELIVERY)
        validate_fresh_id(self.attempt_id, expected_kind=FreshIdKind.ATTEMPT)
        _bounded_nonnegative(self.owner_epoch, "owner epoch", maximum=MAX_OWNER_EPOCH)
        _bounded_signed(self.logical_time_ns, "logical time")
        _bounded_nonnegative(self.scenario_ordinal, "scenario ordinal")
        _bounded_nonnegative(self.step_ordinal, "step ordinal")
        _bounded_nonnegative(self.delivery_ordinal, "delivery ordinal")
        _bounded_nonnegative(self.attempt_ordinal, "attempt ordinal")


@dataclass(frozen=True, slots=True)
class AttemptLifecycleResult:
    """Terminal durable reduction for one executor invocation."""

    transport: AttemptResult
    terminal_state: AttemptState
    classification: AttemptClassification
    retry_decision: RetryDecision | None


@dataclass(frozen=True, slots=True, repr=False)
class PreparedAttemptRequest:
    """Exact transport command plus secret-free signing and mutation evidence."""

    command: HttpAttemptCommand
    pipeline: MutationPipelineResult

    def __post_init__(self) -> None:
        if type(self.command) is not HttpAttemptCommand:
            raise TypeError("prepared request command must be a HttpAttemptCommand")
        if type(self.pipeline) is not MutationPipelineResult:
            raise TypeError("prepared request pipeline must be a MutationPipelineResult")
        if self.command.body != self.pipeline.body:
            raise ValueError("prepared transport body differs from pipeline output")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"body_bytes={len(self.command.body)!r}, "
            f"header_names={tuple(item.name for item in self.command.headers)!r}, "
            f"pipeline={self.pipeline!r})"
        )


@dataclass(frozen=True, slots=True)
class RealizedAttemptLifecycleResult:
    """Durable lifecycle result bound to the exact prepared request."""

    lifecycle: AttemptLifecycleResult
    prepared: PreparedAttemptRequest

    def __post_init__(self) -> None:
        if type(self.lifecycle) is not AttemptLifecycleResult:
            raise TypeError("lifecycle must be an AttemptLifecycleResult")
        if type(self.prepared) is not PreparedAttemptRequest:
            raise TypeError("prepared must be a PreparedAttemptRequest")


class AttemptLifecycle:
    """Coordinate the real HTTP executor exclusively through typed journal seams."""

    __slots__ = ("_clock", "_executor", "_record_id_factory", "_repository")

    def __init__(
        self,
        *,
        repository: TransitionRepository,
        executor: HttpAttemptExecutor,
        clock: RuntimeClock,
        record_id_factory: RecordIdFactory | None = None,
    ) -> None:
        if type(repository) is not TransitionRepository:
            raise TypeError("repository must be a TransitionRepository")
        if type(executor) is not HttpAttemptExecutor:
            raise TypeError("executor must be a HttpAttemptExecutor")
        if type(clock) is not RuntimeClock:
            raise TypeError("clock must be a RuntimeClock")
        if record_id_factory is not None and not callable(record_id_factory):
            raise TypeError("record_id_factory must be callable")
        self._repository = repository
        self._executor = executor
        self._clock = clock
        self._record_id_factory = _new_record_id if record_id_factory is None else record_id_factory

    async def claim(self, claim: AttemptScheduleClaim) -> None:
        """Atomically consume a persisted schedule and claim its fresh attempt."""
        await self._repository.claim_attempt_schedule(claim)

    async def execute(
        self,
        context: AttemptRuntimeContext,
        command: HttpAttemptCommand,
        *,
        retry_decider: RetryDecider | None = None,
        retryable_status: RetryableStatus | None = None,
    ) -> AttemptLifecycleResult:
        """Run one claimed attempt through durable phases and terminal reduction."""
        inventory = await self._repository.projection_inventory(context.run_id)
        projection = next(
            (
                item
                for item in inventory
                if item.entity_type is EntityType.ATTEMPT and item.entity_id == context.attempt_id
            ),
            None,
        )
        if projection is None or projection.state is not AttemptState.CLAIMED:
            raise RuntimeError("attempt execution requires a uniquely claimed attempt")
        body_digest = _digest(command.body)
        headers_digest = _headers_digest(command)
        current = AttemptState.CLAIMED
        await self._apply_phase(
            context,
            current,
            AttemptState.PRE_SEND_COMMITTED,
            AttemptPhaseEvidence.CONTROLLED_PRE_TRANSPORT,
            body_digest=body_digest,
            headers_digest=headers_digest,
        )
        current = AttemptState.PRE_SEND_COMMITTED

        async def progress(checkpoint: AttemptProgressCheckpoint) -> None:
            nonlocal current
            source, target, phase = {
                AttemptProgressCheckpoint.CONNECTION_ATTEMPT_STARTED: (
                    AttemptState.PRE_SEND_COMMITTED,
                    AttemptState.CONNECTING,
                    AttemptPhaseEvidence.CONNECTION_ATTEMPT_STARTED,
                ),
                AttemptProgressCheckpoint.REQUEST_SEND_STARTED: (
                    AttemptState.CONNECTING,
                    AttemptState.SENDING,
                    AttemptPhaseEvidence.REQUEST_SEND_STARTED,
                ),
                AttemptProgressCheckpoint.AWAITING_RESPONSE: (
                    AttemptState.SENDING,
                    AttemptState.AWAITING_RESPONSE,
                    AttemptPhaseEvidence.AWAITING_RESPONSE,
                ),
            }[checkpoint]
            if current is not source:
                raise RuntimeError("executor checkpoint order differs from durable state")
            await self._apply_phase(context, source, target, phase)
            current = target

        result = await self._executor.execute(command, progress_sink=progress)
        current = await self._durable_live_state(context)
        terminal_state, classification, terminal_phase = _terminal_reduction(
            result,
            current,
        )
        predecessor = ClassifiedPredecessor(
            attempt_id=context.attempt_id,
            attempt_ordinal=context.attempt_ordinal,
            classification=classification,
            predicate=_retry_predicate(
                result,
                classification,
                retryable_status=retryable_status,
            ),
            logical_time_ns=context.logical_time_ns,
            status_code=(
                result.response.status
                if (
                    classification is AttemptClassification.RECEIVER_REJECTED
                    and result.response is not None
                    and retryable_status is not None
                    and retryable_status(result.response.status)
                )
                else None
            ),
        )
        decision = retry_decider(predecessor) if retry_decider is not None else None
        retry_schedule = _retry_schedule(context, decision)
        terminal_outcome = AttemptTerminalOutcome(classification, retry_schedule)
        transport_evidence = _transport_evidence(
            context,
            command,
            result,
            record_id=self._record_id_factory(),
            terminal_state=terminal_state,
            classification=classification,
        )
        if (
            result.outcome is AttemptOutcome.RESPONSE
            and result.response is not None
            and result.response.body_complete
        ):
            await self._apply_phase(
                context,
                current,
                AttemptState.RESPONSE_OBSERVED,
                AttemptPhaseEvidence.RESPONSE_OBSERVED,
                response_staging=AttemptResponseStagingCommand(
                    terminal_state=terminal_state,
                    terminal_outcome=terminal_outcome,
                    transport_evidence=transport_evidence,
                ),
            )
            current = AttemptState.RESPONSE_OBSERVED
        await self._repository.apply_attempt(
            _transition(
                context,
                current,
                terminal_state,
                trigger="attempt_outcome",
                timestamp=self._clock.transition_timestamp(),
                outcome=terminal_outcome,
            ),
            AttemptPhaseEvidenceCommand(terminal_phase),
            transport_evidence=transport_evidence,
        )
        return AttemptLifecycleResult(
            transport=result,
            terminal_state=terminal_state,
            classification=classification,
            retry_decision=decision,
        )

    async def execute_realized(
        self,
        context: AttemptRuntimeContext,
        command: HttpAttemptCommand,
        recipe: RealizedDeliveryExecution,
        *,
        signer: Signer | None,
        retry_decider: RetryDecider | None = None,
        retryable_status: RetryableStatus | None = None,
    ) -> RealizedAttemptLifecycleResult:
        """Prepare exact signed bytes, then run the normal journal-first lifecycle."""
        if (
            context.scenario_id != recipe.scenario_id
            or context.delivery_id != recipe.delivery_id
            or context.event_id != recipe.event_id
            or context.logical_time_ns != recipe.logical_time_ns
        ):
            raise ValueError("attempt context does not match its realized execution recipe")
        prepared = prepare_realized_attempt(command, recipe, signer=signer)
        lifecycle = await self.execute(
            context,
            prepared.command,
            retry_decider=retry_decider,
            retryable_status=retryable_status,
        )
        return RealizedAttemptLifecycleResult(
            lifecycle=lifecycle,
            prepared=prepared,
        )

    async def _durable_live_state(self, context: AttemptRuntimeContext) -> AttemptState:
        """Reload the authoritative phase after executor cancellation checkpoints."""
        inventory = await self._repository.projection_inventory(context.run_id)
        matches = tuple(
            item
            for item in inventory
            if item.entity_type is EntityType.ATTEMPT and item.entity_id == context.attempt_id
        )
        if len(matches) != 1 or type(matches[0].state) is not AttemptState:
            raise RuntimeError("attempt projection lookup is not unique and typed")
        state = matches[0].state
        if state not in {
            AttemptState.PRE_SEND_COMMITTED,
            AttemptState.CONNECTING,
            AttemptState.SENDING,
            AttemptState.AWAITING_RESPONSE,
        }:
            raise RuntimeError("executor returned after attempt left a live phase")
        return state

    async def _apply_phase(
        self,
        context: AttemptRuntimeContext,
        source: AttemptState,
        target: AttemptState,
        phase: AttemptPhaseEvidence,
        *,
        body_digest: str | None = None,
        headers_digest: str | None = None,
        response_staging: AttemptResponseStagingCommand | None = None,
    ) -> None:
        await self._repository.apply_attempt(
            _transition(
                context,
                source,
                target,
                trigger="attempt_phase",
                timestamp=self._clock.transition_timestamp(),
            ),
            AttemptPhaseEvidenceCommand(
                phase,
                request_blob_hash=body_digest,
                request_headers_hash=headers_digest,
            ),
            response_staging=response_staging,
        )
        # The journal writer returns only after the phase transaction has a
        # definitive outcome. Observe any pending attempt/outer deadline here,
        # before the executor can advance to the next physical I/O phase.
        await checkpoint()


def prepare_realized_attempt(
    command: HttpAttemptCommand,
    recipe: RealizedDeliveryExecution,
    *,
    signer: Signer | None,
) -> PreparedAttemptRequest:
    """Apply the manifest-realized live stages and produce the exact wire command."""
    if type(command) is not HttpAttemptCommand:
        raise TypeError("command must be a HttpAttemptCommand")
    if type(recipe) is not RealizedDeliveryExecution:
        raise TypeError("recipe must be a RealizedDeliveryExecution")
    if _digest(command.body) != recipe.request_blob:
        raise ValueError("attempt body does not match the realized request blob")
    if recipe.signer_name is None:
        if signer is not None:
            raise ValueError("unsigned realized delivery cannot receive a signer")
    elif signer is None:
        raise ValueError("realized delivery requires its selected signer")
    if any(header.owner is HeaderOwner.SIGNER for header in command.headers):
        raise ValueError("base attempt command cannot contain precomputed signer headers")

    input_headers = tuple(
        SignatureHeader(name=header.name, value=header.value) for header in command.headers
    )
    pipeline = MutationPipeline(_RUNTIME_MUTATION_REGISTRY).execute(
        body=command.body,
        headers=input_headers,
        event_id=recipe.event_id,
        logical_time_ns=recipe.logical_time_ns,
        media_type=recipe.media_type,
        signer=signer,
        mutations=recipe.runtime_mutations,
    )
    signer_headers: frozenset[str] = (
        frozenset() if signer is None else frozenset(signer.owned_headers)
    )
    exact_command = HttpAttemptCommand(
        policy=command.policy,
        body=pipeline.body,
        headers=tuple(
            HttpHeader(
                name=header.name,
                value=header.value,
                owner=(HeaderOwner.SIGNER if header.name in signer_headers else HeaderOwner.USER),
            )
            for header in pipeline.headers
        ),
    )
    return PreparedAttemptRequest(command=exact_command, pipeline=pipeline)


def _terminal_reduction(
    result: AttemptResult,
    current: AttemptState,
) -> tuple[AttemptState, AttemptClassification, AttemptPhaseEvidence]:
    if result.outcome is AttemptOutcome.NOT_SENT:
        if current in {AttemptState.SENDING, AttemptState.AWAITING_RESPONSE}:
            phase = (
                AttemptPhaseEvidence.REQUEST_SEND_STARTED
                if current is AttemptState.SENDING
                else AttemptPhaseEvidence.AWAITING_RESPONSE
            )
            return AttemptState.UNKNOWN_OUTCOME, AttemptClassification.AMBIGUOUS, phase
        if current is AttemptState.PRE_SEND_COMMITTED:
            return (
                AttemptState.NOT_SENT,
                AttemptClassification.ENVIRONMENT_FAILURE,
                AttemptPhaseEvidence.CONTROLLED_PRE_TRANSPORT,
            )
        if current is AttemptState.CONNECTING:
            return (
                AttemptState.NOT_SENT,
                AttemptClassification.ENVIRONMENT_FAILURE,
                AttemptPhaseEvidence.NO_CONNECTION_ESTABLISHED,
            )
        raise RuntimeError("not_sent transport evidence followed a durable send phase")
    if result.outcome is AttemptOutcome.UNKNOWN_OUTCOME:
        phase = {
            AttemptState.CONNECTING: AttemptPhaseEvidence.CONNECTION_ATTEMPT_STARTED,
            AttemptState.SENDING: AttemptPhaseEvidence.REQUEST_SEND_STARTED,
            AttemptState.AWAITING_RESPONSE: AttemptPhaseEvidence.AWAITING_RESPONSE,
        }.get(current)
        if phase is None:
            raise RuntimeError("unknown outcome lacks a durable possible-send phase")
        return AttemptState.UNKNOWN_OUTCOME, AttemptClassification.AMBIGUOUS, phase
    if result.response is None:
        raise RuntimeError("response outcome lacks response evidence")
    if not result.response.body_complete:
        phase = {
            AttemptState.SENDING: AttemptPhaseEvidence.REQUEST_SEND_STARTED,
            AttemptState.AWAITING_RESPONSE: AttemptPhaseEvidence.AWAITING_RESPONSE,
        }.get(current)
        if phase is None:
            raise RuntimeError("incomplete response lacks a durable possible-send phase")
        return AttemptState.UNKNOWN_OUTCOME, AttemptClassification.AMBIGUOUS, phase
    if result.error is not None:
        return (
            AttemptState.TRANSPORT_FAILED,
            AttemptClassification.ENVIRONMENT_FAILURE,
            AttemptPhaseEvidence.RESPONSE_OBSERVED,
        )
    if 200 <= result.response.status <= 299:
        return (
            AttemptState.SUCCEEDED,
            AttemptClassification.RECEIVER_ACCEPTED,
            AttemptPhaseEvidence.RESPONSE_OBSERVED,
        )
    return (
        AttemptState.REJECTED,
        AttemptClassification.RECEIVER_REJECTED,
        AttemptPhaseEvidence.RESPONSE_OBSERVED,
    )


def _retry_predicate(
    result: AttemptResult,
    classification: AttemptClassification,
    *,
    retryable_status: RetryableStatus | None,
) -> RetryPredicate | None:
    if (
        classification is AttemptClassification.RECEIVER_REJECTED
        and result.response is not None
        and retryable_status is not None
        and retryable_status(result.response.status)
    ):
        return RetryPredicate.RETRYABLE_STATUS
    error = result.error
    if classification is not AttemptClassification.ENVIRONMENT_FAILURE or error is None:
        return None
    if error.code in _TIMEOUT_CODES:
        return RetryPredicate.TIMED_OUT
    if error.retryable:
        return RetryPredicate.CONNECTION_FAILED
    return None


def _retry_schedule(
    context: AttemptRuntimeContext,
    decision: RetryDecision | None,
) -> RetrySchedule | None:
    if decision is None or not decision.should_schedule:
        return None
    if (
        decision.schedule_entry_id is None
        or decision.attempt_plan_id is None
        or decision.logical_due_ns is None
        or decision.next_attempt_ordinal is None
        or decision.schedule_idempotency_key is None
    ):
        raise RuntimeError("scheduled retry decision is incomplete")
    return RetrySchedule(
        schedule_entry_id=decision.schedule_entry_id,
        scenario_id=context.scenario_id,
        entity_type="attempt",
        entity_id=decision.attempt_plan_id,
        logical_time_ns=decision.logical_due_ns,
        scenario_ordinal=context.scenario_ordinal,
        step_ordinal=context.step_ordinal,
        delivery_ordinal=context.delivery_ordinal,
        attempt_ordinal=decision.next_attempt_ordinal,
        deterministic_tie_key=f"retry.{decision.attempt_plan_id}",
        idempotency_key=decision.schedule_idempotency_key,
        predecessor_attempt_id=context.attempt_id,
        condition_json=decision.condition_json,
    )


def _transition(
    context: AttemptRuntimeContext,
    source: AttemptState,
    target: AttemptState,
    *,
    trigger: str,
    timestamp: TransitionTimestamp,
    outcome: AttemptTerminalOutcome | None = None,
) -> TransitionCommand[AttemptState]:
    edge = f"{source.value}.{target.value}"
    return TransitionCommand(
        run_id=context.run_id,
        transition_id=f"attempt.{context.attempt_id}.{target.value}",
        entity_type=EntityType.ATTEMPT,
        entity_id=context.attempt_id,
        expected_state=source,
        new_state=target,
        trigger_category=trigger,
        timestamp=timestamp,
        owner_epoch=context.owner_epoch,
        idempotency_key=f"attempt.{context.attempt_id}.{edge}",
        logical_time_ns=context.logical_time_ns,
        attempt_outcome=outcome,
    )


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _headers_digest(command: HttpAttemptCommand) -> str:
    digest = hashlib.sha256()
    for header in command.headers:
        for component in (header.name.encode(), header.value.encode(), header.owner.value.encode()):
            digest.update(len(component).to_bytes(4, "big"))
            digest.update(component)
    return f"sha256:{digest.hexdigest()}"


def _transport_evidence(
    context: AttemptRuntimeContext,
    command: HttpAttemptCommand,
    result: AttemptResult,
    *,
    record_id: str,
    terminal_state: AttemptState,
    classification: AttemptClassification,
) -> AttemptTransportEvidenceCommand:
    error = _transport_error(result, classification)
    response = (
        ResponseMetadata(
            status=result.response.status,
            body_sha256=result.response.body_sha256,
            captured_bytes=len(result.response.captured_body),
            truncated=result.response.truncated or not result.response.body_complete,
        )
        if result.response is not None
        else None
    )
    return AttemptTransportEvidenceCommand(
        record_id=record_id,
        run_id=context.run_id,
        scenario_id=context.scenario_id,
        event_id=context.event_id,
        delivery_id=context.delivery_id,
        attempt_id=context.attempt_id,
        state=_evidence_state(terminal_state, result),
        classification=classification,
        request=RequestMetadata(
            url_redacted=_redacted_url(command),
            body_sha256=result.request.body_sha256,
            byte_length=result.request.body_bytes,
            header_names=tuple(sorted({header.name.lower() for header in result.request.headers})),
        ),
        response=response,
        error=error,
        response_headers_elapsed_ns=result.timings.response_headers_elapsed_ns,
    )


def _evidence_state(
    terminal_state: AttemptState,
    result: AttemptResult,
) -> AttemptEvidenceState:
    if terminal_state is AttemptState.SUCCEEDED:
        return AttemptEvidenceState.ACKNOWLEDGED
    if terminal_state is AttemptState.REJECTED:
        return AttemptEvidenceState.REJECTED
    if terminal_state is AttemptState.UNKNOWN_OUTCOME:
        return AttemptEvidenceState.UNKNOWN_OUTCOME
    if terminal_state is AttemptState.CANCELLED:
        return AttemptEvidenceState.CANCELLED
    error = result.error
    if terminal_state is AttemptState.NOT_SENT:
        return (
            AttemptEvidenceState.PROTOCOL_FAILED
            if error is not None and error.code is AttemptErrorCode.PROTOCOL_ERROR
            else AttemptEvidenceState.CONNECTION_FAILED
        )
    if error is not None and error.code in _TIMEOUT_CODES:
        return AttemptEvidenceState.TIMED_OUT
    if error is not None and error.code is AttemptErrorCode.PROTOCOL_ERROR:
        return AttemptEvidenceState.PROTOCOL_FAILED
    return AttemptEvidenceState.CONNECTION_FAILED


def _transport_error(
    result: AttemptResult,
    classification: AttemptClassification,
) -> TransportError | None:
    if classification in {
        AttemptClassification.RECEIVER_ACCEPTED,
        AttemptClassification.RECEIVER_REJECTED,
        AttemptClassification.CANCELLED,
    }:
        return None
    if result.error is None:
        return TransportError(
            category="ambiguous_transport",
            message_redacted="transport completion is ambiguous",
            phase=None,
        )
    return TransportError(
        category=result.error.code.value,
        message_redacted=result.error.message_redacted,
        phase=result.error.phase.value,
    )


def _redacted_url(command: HttpAttemptCommand) -> str:
    destination = command.policy.destination
    return f"{destination.scheme}://{destination.authority}/[REDACTED]"


def _new_record_id() -> str:
    return new_fresh_id(FreshIdKind.RECORD)


def _bounded_nonnegative(value: object, name: str, *, maximum: int = MAX_SAFE_INTEGER) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        message = f"{name} must be a nonnegative safe integer"
        raise ValueError(message)


def _bounded_signed(value: object, name: str) -> None:
    if type(value) is not int or not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        message = f"{name} must be a signed safe integer"
        raise ValueError(message)
