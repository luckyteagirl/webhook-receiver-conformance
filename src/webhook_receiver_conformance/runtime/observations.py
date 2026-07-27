"""Runtime wiring for atomic observation polling and SQLite journaling."""
# ruff: noqa: D107, EM101, INP001, TRY003

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, cast

from webhook_receiver_conformance.domain.enums import ObservationState
from webhook_receiver_conformance.domain.identifiers import FreshIdKind, new_fresh_id
from webhook_receiver_conformance.journal.repositories import (
    ObservationRepository,
    ObservationSampleCommand,
    ObservationSeriesCommand,
)
from webhook_receiver_conformance.journal.transitions import (
    CausalReference,
    EntityType,
    TransitionCommand,
)
from webhook_receiver_conformance.observers.polling import (
    ObservationJournal,
    ObservationPoller,
    ObservationPollPlan,
    ObservationPollResult,
    ObservationSampleCommit,
    PollPredicate,
)

if TYPE_CHECKING:
    from webhook_receiver_conformance.observers.protocol import (
        ObservationRecord,
        Observer,
    )
    from webhook_receiver_conformance.scheduler.clocks import (
        RuntimeClock,
        TransitionTimestamp,
    )

TRIGGER_OBSERVATION_PLANNED = "observation_planned"
TRIGGER_OBSERVATION_STARTED = "observation_started"
TRIGGER_OBSERVATION_OK = "observation_ok"
TRIGGER_OBSERVATION_PENDING = "observation_pending"
TRIGGER_OBSERVATION_UNSUPPORTED = "observation_unsupported"
TRIGGER_OBSERVATION_ERROR = "observation_error"
TRIGGER_OBSERVATION_TIMED_OUT = "observation_timed_out"
TRIGGER_OBSERVATION_CANCELLED = "observation_cancelled"

type FreshIdFactory = Callable[[FreshIdKind], str]


class SqliteObservationJournal(ObservationJournal):
    """Translate poller commits into the journal's atomic observation repository."""

    __slots__ = ("_owner_epoch", "_repository")

    def __init__(
        self,
        repository: ObservationRepository,
        *,
        owner_epoch: int,
    ) -> None:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            repository,
            ObservationRepository,
        ):
            raise TypeError("repository must be an ObservationRepository")
        if type(owner_epoch) is not int or owner_epoch < 0:
            raise ValueError("owner_epoch must be a nonnegative integer")
        self._repository = repository
        self._owner_epoch = owner_epoch

    async def begin_series(
        self,
        plan: ObservationPollPlan,
        timestamp: TransitionTimestamp,
    ) -> None:
        """Create the planned series and enter running atomically."""
        request = plan.request
        run_id = cast("str", request.run_id)
        scenario_id = cast("str", request.scenario_id)
        checkpoint = cast("str", request.checkpoint)
        initial = TransitionCommand(
            run_id=run_id,
            transition_id=f"observation.begin.{plan.observation_id}",
            entity_type=EntityType.OBSERVATION,
            entity_id=plan.observation_id,
            expected_state=None,
            new_state=ObservationState.SCHEDULED,
            trigger_category=TRIGGER_OBSERVATION_PLANNED,
            timestamp=timestamp,
            owner_epoch=self._owner_epoch,
            idempotency_key=f"observation.begin.{plan.observation_id}",
        )
        running = TransitionCommand(
            run_id=run_id,
            transition_id=f"observation.run.{plan.observation_id}",
            entity_type=EntityType.OBSERVATION,
            entity_id=plan.observation_id,
            expected_state=ObservationState.SCHEDULED,
            new_state=ObservationState.RUNNING,
            trigger_category=TRIGGER_OBSERVATION_STARTED,
            timestamp=timestamp,
            owner_epoch=self._owner_epoch,
            idempotency_key=f"observation.run.{plan.observation_id}",
            causal_reference=CausalReference(run_id, plan.observation_id),
        )
        await self._repository.begin_series(
            ObservationSeriesCommand(
                run_id=run_id,
                scenario_id=scenario_id,
                observation_id=plan.observation_id,
                observer_id=plan.observer_id,
                checkpoint=checkpoint,
                event_id=request.event_id,
                initial_transition=initial,
                running_transition=running,
            )
        )

    async def append_sample(
        self,
        plan: ObservationPollPlan,
        sample: ObservationSampleCommit,
    ) -> None:
        """Append one sample and its final series transition when present."""
        del plan
        record = sample.record
        transition = (
            None
            if sample.terminal_state is None
            else self._terminal_transition(
                record,
                sample.terminal_state,
                sample.timestamp,
            )
        )
        await self._repository.append_sample(
            ObservationSampleCommand(
                record=record,
                owner_epoch=self._owner_epoch,
                terminal_transition=transition,
            )
        )

    def _terminal_transition(
        self,
        record: ObservationRecord,
        state: ObservationState,
        timestamp: TransitionTimestamp,
    ) -> TransitionCommand[ObservationState]:
        triggers = {
            ObservationState.OK: TRIGGER_OBSERVATION_OK,
            ObservationState.PENDING: TRIGGER_OBSERVATION_PENDING,
            ObservationState.UNSUPPORTED: TRIGGER_OBSERVATION_UNSUPPORTED,
            ObservationState.ERROR: TRIGGER_OBSERVATION_ERROR,
            ObservationState.TIMED_OUT: TRIGGER_OBSERVATION_TIMED_OUT,
            ObservationState.CANCELLED: TRIGGER_OBSERVATION_CANCELLED,
        }
        try:
            trigger = triggers[state]
        except KeyError as error:
            raise ValueError("terminal observation state is invalid") from error
        return TransitionCommand(
            run_id=record.run_id,
            transition_id=f"observation.sample.{record.record_id}.{state.value}",
            entity_type=EntityType.OBSERVATION,
            entity_id=record.observation_id,
            expected_state=ObservationState.RUNNING,
            new_state=state,
            trigger_category=trigger,
            timestamp=timestamp,
            owner_epoch=self._owner_epoch,
            idempotency_key=f"observation.sample.{record.record_id}.{state.value}",
            causal_reference=CausalReference(record.run_id, record.record_id),
        )


class ObservationRuntime:
    """High-level observation lifecycle with no unmanaged background tasks."""

    __slots__ = ("_poller", "_repository")

    def __init__(
        self,
        *,
        observer: Observer,
        repository: ObservationRepository,
        clock: RuntimeClock,
        owner_epoch: int,
        fresh_id: FreshIdFactory = new_fresh_id,
    ) -> None:
        self._repository = repository
        self._poller = ObservationPoller(
            observer=observer,
            journal=SqliteObservationJournal(
                repository,
                owner_epoch=owner_epoch,
            ),
            clock=clock,
            fresh_id=fresh_id,
        )

    async def poll(
        self,
        plan: ObservationPollPlan,
        predicate: PollPredicate,
    ) -> ObservationPollResult:
        """Execute one bounded series and return every durable sample identity."""
        return await self._poller.poll(plan, predicate)

    async def samples(
        self,
        plan: ObservationPollPlan,
    ) -> tuple[ObservationRecord, ...]:
        """Load every durable sample for reporting or later assertion evaluation."""
        return await self._repository.samples(
            cast("str", plan.request.run_id),
            plan.observation_id,
        )


__all__ = [
    "TRIGGER_OBSERVATION_CANCELLED",
    "TRIGGER_OBSERVATION_ERROR",
    "TRIGGER_OBSERVATION_OK",
    "TRIGGER_OBSERVATION_PENDING",
    "TRIGGER_OBSERVATION_PLANNED",
    "TRIGGER_OBSERVATION_STARTED",
    "TRIGGER_OBSERVATION_TIMED_OUT",
    "TRIGGER_OBSERVATION_UNSUPPORTED",
    "ObservationRuntime",
    "SqliteObservationJournal",
]
