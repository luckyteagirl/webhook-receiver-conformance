"""Bounded monotonic observer polling with append-first sample accounting."""
# ruff: noqa: BLE001, C901, D105, D107, EM101, EM102, INP001, PLR0911, PLR0912, PLR0913, PLR0915, PLR2004, TRY003, TRY301

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol, cast, runtime_checkable

import anyio
from anyio.lowlevel import checkpoint

from webhook_receiver_conformance.domain.enums import ObservationState, ObservationStatus
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    new_fresh_id,
    validate_planned_id,
)
from webhook_receiver_conformance.errors import Diagnostic, ErrorCategory
from webhook_receiver_conformance.observers.protocol import (
    CapabilityNegotiation,
    ObservationRecord,
    ObservationRecordError,
    Observer,
    ObserverCapabilities,
    ObserverOperation,
    ObserverRequest,
    ObserverResponse,
    ObserverResponseStatus,
    automatic_polling_allowed,
    automatic_retry_allowed,
    negotiate_capabilities,
    retry_observe_request,
)
from webhook_receiver_conformance.scheduler.clocks import (
    MonotonicDeadline,
    RuntimeClock,
    TransitionTimestamp,
)

MINIMUM_POLL_INTERVAL_NS: Final = 10_000_000
_NANOSECONDS_PER_SECOND: Final = 1_000_000_000
_MAX_SAFE_INTEGER: Final = (1 << 53) - 1

type PollPredicate = Callable[[ObserverResponse], bool]
type FreshIdFactory = Callable[[FreshIdKind], str]


class ObservationPollOutcome(StrEnum):
    """Terminal meaning of one bounded polling series."""

    MATCHED = "matched"
    MISMATCH = "mismatch"
    PENDING = "pending"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class ObservationPollPlan:
    """One logical observation series and its physical polling bounds."""

    observation_id: str
    observer_id: str
    request: ObserverRequest
    capabilities: ObserverCapabilities
    within_ns: int
    poll_interval_ns: int
    invocation_timeout_ns: int
    requires_stable_snapshot: bool = False

    def __post_init__(self) -> None:
        validate_planned_id(
            self.observation_id,
            expected_kind=PlannedIdKind.OBSERVATION,
        )
        if (
            type(self.observer_id) is not str
            or not 1 <= len(self.observer_id) <= 256
            or any(character in "\r\n\x00" for character in self.observer_id)
        ):
            raise ValueError("observer_id must be bounded and line-safe")
        if type(self.request) is not ObserverRequest:
            raise TypeError("request must be an ObserverRequest")
        if (
            self.request.operation is not ObserverOperation.OBSERVE
            or self.request.sample_id is None
            or self.request.scenario_id is None
            or self.request.checkpoint is None
        ):
            raise ValueError("polling requires a scenario-scoped observe request with a checkpoint")
        if type(self.capabilities) is not ObserverCapabilities:
            raise TypeError("capabilities must be ObserverCapabilities")
        _positive_safe_integer(self.within_ns, field_name="polling deadline")
        _positive_safe_integer(
            self.invocation_timeout_ns,
            field_name="observer invocation timeout",
        )
        interval = _positive_safe_integer(
            self.poll_interval_ns,
            field_name="polling interval",
        )
        if interval < MINIMUM_POLL_INTERVAL_NS:
            raise ValueError("polling interval must be at least 10 milliseconds")
        if interval > self.within_ns:
            raise ValueError("polling interval cannot exceed its deadline")
        if type(self.requires_stable_snapshot) is not bool:
            raise TypeError("requires_stable_snapshot must be a bool")

    @property
    def negotiation(self) -> CapabilityNegotiation:
        """Return the immutable pre-poll capability comparison."""
        return negotiate_capabilities(
            self.capabilities,
            self.request.queries,
            requires_stable_snapshot=self.requires_stable_snapshot,
        )


@dataclass(frozen=True, slots=True)
class ObservationSampleCommit:
    """One sanitized sample plus an optional terminal series transition."""

    record: ObservationRecord
    timestamp: TransitionTimestamp
    terminal_state: ObservationState | None

    def __post_init__(self) -> None:
        if type(self.record) is not ObservationRecord:
            raise TypeError("record must be an ObservationRecord")
        if type(self.timestamp) is not TransitionTimestamp:
            raise TypeError("timestamp must be a TransitionTimestamp")
        if self.terminal_state is not None and self.terminal_state not in {
            ObservationState.OK,
            ObservationState.PENDING,
            ObservationState.UNSUPPORTED,
            ObservationState.ERROR,
            ObservationState.TIMED_OUT,
            ObservationState.CANCELLED,
        }:
            raise ValueError("sample terminal state is not an observation terminal")


@runtime_checkable
class ObservationJournal(Protocol):
    """Atomic persistence boundary consumed by the poller."""

    async def begin_series(
        self,
        plan: ObservationPollPlan,
        timestamp: TransitionTimestamp,
    ) -> None:
        """Create and move one series from scheduled to running.

        Implementations must not return until the commit has a definitive outcome.
        Once accepted, commit ownership remains structured and cannot be detached
        from the calling task.
        """
        ...

    async def append_sample(
        self,
        plan: ObservationPollPlan,
        sample: ObservationSampleCommit,
    ) -> None:
        """Append one sample and atomically apply its terminal edge when present.

        Implementations obey the same definitive-outcome and no-background-work
        constraint as ``begin_series``.
        """
        ...


@dataclass(frozen=True, slots=True)
class ObservationPollResult:
    """Complete in-memory result with secret-safe persisted sample identities."""

    outcome: ObservationPollOutcome
    final_state: ObservationState
    sample_ids: tuple[str, ...]
    predicate_matched: bool
    valid_evidence_seen: bool
    deadline_elapsed: bool
    last_response: ObserverResponse | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.outcome) is not ObservationPollOutcome:
            raise TypeError("outcome must be an ObservationPollOutcome")
        if type(self.final_state) is not ObservationState:
            raise TypeError("final_state must be an ObservationState")
        if type(self.sample_ids) is not tuple or not self.sample_ids:
            raise ValueError("a polling result requires at least one sample ID")
        if any(type(sample_id) is not str for sample_id in self.sample_ids):
            raise TypeError("sample_ids must contain strings")
        for value, field_name in (
            (self.predicate_matched, "predicate_matched"),
            (self.valid_evidence_seen, "valid_evidence_seen"),
            (self.deadline_elapsed, "deadline_elapsed"),
        ):
            if type(value) is not bool:
                raise TypeError(f"{field_name} must be a bool")
        if self.last_response is not None and type(self.last_response) is not ObserverResponse:
            raise TypeError("last_response must be an ObserverResponse or None")


class ObservationPoller:
    """Invoke one observer series without hidden backoff or background work."""

    __slots__ = (
        "_clock",
        "_fresh_id",
        "_journal",
        "_observer",
    )

    def __init__(
        self,
        *,
        observer: Observer,
        journal: ObservationJournal,
        clock: RuntimeClock,
        fresh_id: FreshIdFactory = new_fresh_id,
    ) -> None:
        if not isinstance(observer, Observer):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("observer must implement the Observer protocol")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            journal,
            ObservationJournal,
        ):
            raise TypeError("journal must implement the ObservationJournal protocol")
        if type(clock) is not RuntimeClock:
            raise TypeError("clock must be a RuntimeClock")
        if not callable(fresh_id):
            raise TypeError("fresh_id must be callable")
        self._observer = observer
        self._journal = journal
        self._clock = clock
        self._fresh_id = fresh_id

    async def poll(
        self,
        plan: ObservationPollPlan,
        predicate: PollPredicate,
    ) -> ObservationPollResult:
        """Poll until the typed predicate passes or a physical deadline ends."""
        if type(plan) is not ObservationPollPlan:
            raise TypeError("plan must be an ObservationPollPlan")
        if not callable(predicate):
            raise TypeError("predicate must be callable")

        request = plan.request
        sample_sequence = 1
        await self._journal.begin_series(
            plan,
            self._clock.transition_timestamp(),
        )
        try:
            await checkpoint()
        except anyio.get_cancelled_exc_class():
            await self._cancel(plan, request, sample_sequence=sample_sequence)
            raise

        sample_ids: list[str] = []
        deadline = self._clock.deadline_after(plan.within_ns)
        last_response: ObserverResponse | None = None
        valid_evidence_seen = False

        if not plan.negotiation.supported:
            record = self._response_record(
                plan,
                request,
                sample_sequence=sample_sequence,
                response=None,
                status=ObservationStatus.UNSUPPORTED,
            )
            await self._append(
                plan,
                record,
                terminal_state=ObservationState.UNSUPPORTED,
            )
            return _result(
                outcome=ObservationPollOutcome.UNSUPPORTED,
                final_state=ObservationState.UNSUPPORTED,
                sample_ids=(record.sample_id,),
            )

        while True:
            if deadline.expired(self._clock):
                record = self._timeout_record(
                    plan,
                    request,
                    sample_sequence=sample_sequence,
                    category="observer_deadline",
                )
                await self._append(
                    plan,
                    record,
                    terminal_state=ObservationState.TIMED_OUT,
                )
                sample_ids.append(record.sample_id)
                return _result(
                    outcome=ObservationPollOutcome.TIMED_OUT,
                    final_state=ObservationState.TIMED_OUT,
                    sample_ids=tuple(sample_ids),
                    valid_evidence_seen=valid_evidence_seen,
                    deadline_elapsed=True,
                    last_response=last_response,
                )

            try:
                response = await self._invoke_with_deadline(plan, request, deadline)
            except anyio.get_cancelled_exc_class():
                await self._cancel(plan, request, sample_sequence=sample_sequence)
                raise
            except TimeoutError:
                record = self._timeout_record(
                    plan,
                    request,
                    sample_sequence=sample_sequence,
                    category="observer_timeout",
                )
                await self._append(
                    plan,
                    record,
                    terminal_state=ObservationState.TIMED_OUT,
                )
                sample_ids.append(record.sample_id)
                return _result(
                    outcome=ObservationPollOutcome.TIMED_OUT,
                    final_state=ObservationState.TIMED_OUT,
                    sample_ids=tuple(sample_ids),
                    valid_evidence_seen=valid_evidence_seen,
                    deadline_elapsed=deadline.expired(self._clock),
                    last_response=last_response,
                )
            except Exception as error:
                diagnostic = _safe_diagnostic(error)
                can_retry = (
                    diagnostic is not None
                    and diagnostic.retryable
                    and plan.capabilities.automatic_reinvocation_safe
                    and not deadline.expired(self._clock)
                )
                record = self._error_record(
                    plan,
                    request,
                    sample_sequence=sample_sequence,
                    category=(
                        diagnostic.category.value
                        if diagnostic is not None
                        else ErrorCategory.OBSERVER_PROTOCOL_ERROR.value
                    ),
                    message="Observer invocation failed with a classified error.",
                )
                await self._append(
                    plan,
                    record,
                    terminal_state=None if can_retry else ObservationState.ERROR,
                )
                sample_ids.append(record.sample_id)
                if not can_retry:
                    return _result(
                        outcome=ObservationPollOutcome.ERROR,
                        final_state=ObservationState.ERROR,
                        sample_ids=tuple(sample_ids),
                        valid_evidence_seen=valid_evidence_seen,
                        last_response=last_response,
                    )
                request, sample_sequence = await self._next_request(
                    plan,
                    request,
                    sample_sequence,
                    deadline,
                )
                continue

            if response.capabilities != plan.capabilities:
                record = self._error_record(
                    plan,
                    request,
                    sample_sequence=sample_sequence,
                    category="observer_protocol_error",
                    message="Observer capabilities changed during one polling series.",
                )
                await self._append(
                    plan,
                    record,
                    terminal_state=ObservationState.ERROR,
                )
                sample_ids.append(record.sample_id)
                return _result(
                    outcome=ObservationPollOutcome.ERROR,
                    final_state=ObservationState.ERROR,
                    sample_ids=tuple(sample_ids),
                    valid_evidence_seen=valid_evidence_seen,
                    last_response=last_response,
                )

            last_response = response
            if response.status is ObserverResponseStatus.OK:
                valid_evidence_seen = True
                try:
                    matched = predicate(response)
                    if type(matched) is not bool:
                        raise TypeError("poll predicate must return a bool")
                except Exception:
                    record = self._error_record(
                        plan,
                        request,
                        sample_sequence=sample_sequence,
                        category="predicate_error",
                        message="The typed polling predicate could not evaluate valid evidence.",
                    )
                    await self._append(
                        plan,
                        record,
                        terminal_state=ObservationState.ERROR,
                    )
                    sample_ids.append(record.sample_id)
                    return _result(
                        outcome=ObservationPollOutcome.ERROR,
                        final_state=ObservationState.ERROR,
                        sample_ids=tuple(sample_ids),
                        valid_evidence_seen=True,
                        last_response=response,
                    )
                if matched:
                    record = self._response_record(
                        plan,
                        request,
                        sample_sequence=sample_sequence,
                        response=response,
                    )
                    await self._append(
                        plan,
                        record,
                        terminal_state=ObservationState.OK,
                    )
                    sample_ids.append(record.sample_id)
                    return _result(
                        outcome=ObservationPollOutcome.MATCHED,
                        final_state=ObservationState.OK,
                        sample_ids=tuple(sample_ids),
                        predicate_matched=True,
                        valid_evidence_seen=True,
                        last_response=response,
                    )
                can_poll = plan.capabilities.automatic_reinvocation_safe
                if not can_poll:
                    record = self._response_record(
                        plan,
                        request,
                        sample_sequence=sample_sequence,
                        response=response,
                    )
                    await self._append(
                        plan,
                        record,
                        terminal_state=ObservationState.OK,
                    )
                    sample_ids.append(record.sample_id)
                    return _result(
                        outcome=ObservationPollOutcome.MISMATCH,
                        final_state=ObservationState.OK,
                        sample_ids=tuple(sample_ids),
                        valid_evidence_seen=True,
                        last_response=response,
                    )
                record = self._response_record(
                    plan,
                    request,
                    sample_sequence=sample_sequence,
                    response=response,
                )
                await self._append(plan, record, terminal_state=None)
                sample_ids.append(record.sample_id)
            elif response.status is ObserverResponseStatus.PENDING:
                can_poll = automatic_polling_allowed(plan.capabilities, plan.negotiation)
                record = self._response_record(
                    plan,
                    request,
                    sample_sequence=sample_sequence,
                    response=response,
                )
                await self._append(
                    plan,
                    record,
                    terminal_state=None if can_poll else ObservationState.PENDING,
                )
                sample_ids.append(record.sample_id)
                if not can_poll:
                    return _result(
                        outcome=ObservationPollOutcome.PENDING,
                        final_state=ObservationState.PENDING,
                        sample_ids=tuple(sample_ids),
                        valid_evidence_seen=valid_evidence_seen,
                        last_response=response,
                    )
            elif response.status is ObserverResponseStatus.UNSUPPORTED:
                record = self._response_record(
                    plan,
                    request,
                    sample_sequence=sample_sequence,
                    response=response,
                )
                await self._append(
                    plan,
                    record,
                    terminal_state=ObservationState.UNSUPPORTED,
                )
                sample_ids.append(record.sample_id)
                return _result(
                    outcome=ObservationPollOutcome.UNSUPPORTED,
                    final_state=ObservationState.UNSUPPORTED,
                    sample_ids=tuple(sample_ids),
                    valid_evidence_seen=valid_evidence_seen,
                    last_response=response,
                )
            else:
                can_retry = automatic_retry_allowed(plan.capabilities, response)
                record = self._response_record(
                    plan,
                    request,
                    sample_sequence=sample_sequence,
                    response=response,
                )
                await self._append(
                    plan,
                    record,
                    terminal_state=None if can_retry else ObservationState.ERROR,
                )
                sample_ids.append(record.sample_id)
                if not can_retry:
                    return _result(
                        outcome=ObservationPollOutcome.ERROR,
                        final_state=ObservationState.ERROR,
                        sample_ids=tuple(sample_ids),
                        valid_evidence_seen=valid_evidence_seen,
                        last_response=response,
                    )

            request, sample_sequence = await self._next_request(
                plan,
                request,
                sample_sequence,
                deadline,
            )

    async def _invoke_with_deadline(
        self,
        plan: ObservationPollPlan,
        request: ObserverRequest,
        deadline: MonotonicDeadline,
    ) -> ObserverResponse:
        remaining_ns = deadline.remaining_ns(self._clock)
        if remaining_ns == 0:
            raise TimeoutError
        timeout_ns = min(plan.invocation_timeout_ns, remaining_ns)
        with anyio.fail_after(timeout_ns / _NANOSECONDS_PER_SECOND):
            return await self._observer.invoke(request)

    async def _next_request(
        self,
        plan: ObservationPollPlan,
        request: ObserverRequest,
        sample_sequence: int,
        deadline: MonotonicDeadline,
    ) -> tuple[ObserverRequest, int]:
        next_request = retry_observe_request(
            request,
            self._fresh_id(FreshIdKind.SAMPLE),
        )
        next_sequence = sample_sequence + 1
        remaining_ns = deadline.remaining_ns(self._clock)
        try:
            await checkpoint()
            if remaining_ns:
                await self._clock.sleep_physical(min(plan.poll_interval_ns, remaining_ns))
        except anyio.get_cancelled_exc_class():
            await self._cancel(
                plan,
                next_request,
                sample_sequence=next_sequence,
            )
            raise
        return (next_request, next_sequence)

    async def _append(
        self,
        plan: ObservationPollPlan,
        record: ObservationRecord,
        *,
        terminal_state: ObservationState | None,
    ) -> None:
        await self._journal.append_sample(
            plan,
            ObservationSampleCommit(
                record=record,
                timestamp=self._clock.transition_timestamp(),
                terminal_state=terminal_state,
            ),
        )
        if terminal_state is not None:
            await checkpoint()

    async def _cancel(
        self,
        plan: ObservationPollPlan,
        request: ObserverRequest,
        *,
        sample_sequence: int,
    ) -> None:
        record = self._error_record(
            plan,
            request,
            sample_sequence=sample_sequence,
            category="cancelled",
            message="Observer invocation was cancelled.",
        )
        await self._append(
            plan,
            record,
            terminal_state=ObservationState.CANCELLED,
        )

    def _response_record(
        self,
        plan: ObservationPollPlan,
        request: ObserverRequest,
        *,
        sample_sequence: int,
        response: ObserverResponse | None,
        status: ObservationStatus | None = None,
    ) -> ObservationRecord:
        selected_status = status if status is not None else _record_status(response)
        error = None
        if selected_status is ObservationStatus.ERROR:
            category = "observer_error"
            if response is not None and response.error is not None:
                category = response.error.category
            error = ObservationRecordError(
                category=category,
                message_redacted="Observer returned a classified error.",
            )
        return ObservationRecord(
            schema_version="1.0",
            record_id=self._fresh_id(FreshIdKind.RECORD),
            run_id=cast("str", request.run_id),
            scenario_id=cast("str", request.scenario_id),
            observation_id=plan.observation_id,
            sample_id=cast("str", request.sample_id),
            observer_id=plan.observer_id,
            sample_sequence=sample_sequence,
            recorded_at=_format_recorded_at(self._clock),
            status=selected_status,
            event_id=request.event_id,
            snapshot_id=(response.snapshot_id if response is not None else None),
            evidence=(
                tuple(item for item in response.evidence if not item.sensitive)
                if response is not None
                else ()
            ),
            error=error,
        )

    def _error_record(
        self,
        plan: ObservationPollPlan,
        request: ObserverRequest,
        *,
        sample_sequence: int,
        category: str,
        message: str,
    ) -> ObservationRecord:
        return ObservationRecord(
            schema_version="1.0",
            record_id=self._fresh_id(FreshIdKind.RECORD),
            run_id=cast("str", request.run_id),
            scenario_id=cast("str", request.scenario_id),
            observation_id=plan.observation_id,
            sample_id=cast("str", request.sample_id),
            observer_id=plan.observer_id,
            sample_sequence=sample_sequence,
            recorded_at=_format_recorded_at(self._clock),
            status=ObservationStatus.ERROR,
            event_id=request.event_id,
            error=ObservationRecordError(
                category=category,
                message_redacted=message,
            ),
        )

    def _timeout_record(
        self,
        plan: ObservationPollPlan,
        request: ObserverRequest,
        *,
        sample_sequence: int,
        category: str,
    ) -> ObservationRecord:
        return ObservationRecord(
            schema_version="1.0",
            record_id=self._fresh_id(FreshIdKind.RECORD),
            run_id=cast("str", request.run_id),
            scenario_id=cast("str", request.scenario_id),
            observation_id=plan.observation_id,
            sample_id=cast("str", request.sample_id),
            observer_id=plan.observer_id,
            sample_sequence=sample_sequence,
            recorded_at=_format_recorded_at(self._clock),
            status=ObservationStatus.TIMEOUT,
            event_id=request.event_id,
            error=ObservationRecordError(
                category=category,
                message_redacted="The physical observer deadline elapsed.",
            ),
        )


def _record_status(response: ObserverResponse | None) -> ObservationStatus:
    if response is None:
        raise TypeError("response is required when status is not explicit")
    return {
        ObserverResponseStatus.OK: ObservationStatus.OK,
        ObserverResponseStatus.PENDING: ObservationStatus.PENDING,
        ObserverResponseStatus.UNSUPPORTED: ObservationStatus.UNSUPPORTED,
        ObserverResponseStatus.ERROR: ObservationStatus.ERROR,
    }[response.status]


def _safe_diagnostic(error: Exception) -> Diagnostic | None:
    diagnostic = getattr(error, "diagnostic", None)
    return diagnostic if type(diagnostic) is Diagnostic else None


def _format_recorded_at(clock: RuntimeClock) -> str:
    return clock.wall_now().isoformat(timespec="microseconds").replace("+00:00", "Z")


def _positive_safe_integer(value: object, *, field_name: str) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SAFE_INTEGER:
        raise ValueError(f"{field_name} must be a positive I-JSON integer")
    return value


def _result(
    *,
    outcome: ObservationPollOutcome,
    final_state: ObservationState,
    sample_ids: tuple[str, ...],
    predicate_matched: bool = False,
    valid_evidence_seen: bool = False,
    deadline_elapsed: bool = False,
    last_response: ObserverResponse | None = None,
) -> ObservationPollResult:
    return ObservationPollResult(
        outcome=outcome,
        final_state=final_state,
        sample_ids=sample_ids,
        predicate_matched=predicate_matched,
        valid_evidence_seen=valid_evidence_seen,
        deadline_elapsed=deadline_elapsed,
        last_response=last_response,
    )


__all__ = [
    "MINIMUM_POLL_INTERVAL_NS",
    "ObservationJournal",
    "ObservationPollOutcome",
    "ObservationPollPlan",
    "ObservationPollResult",
    "ObservationPoller",
    "ObservationSampleCommit",
    "PollPredicate",
]
