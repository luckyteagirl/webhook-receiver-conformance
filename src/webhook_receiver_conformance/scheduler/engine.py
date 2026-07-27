"""Journal-first leasing engine over the deterministic schedule projection."""
# ruff: noqa: D107, EM101, INP001, TRY003

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from webhook_receiver_conformance.scheduler.clocks import (
    RuntimeClock,
    TransitionTimestamp,
    validate_logical_nanoseconds,
)
from webhook_receiver_conformance.scheduler.queue import (
    PersistentPriorityQueue,
    ScheduleItem,
)


class ScheduleJournal(Protocol):
    """Persistence boundary whose methods each commit one atomic transaction."""

    async def persist(self, item: ScheduleItem) -> bool:
        """Persist a new item; return false for an exact idempotent replay."""
        ...

    async def consume(
        self,
        item: ScheduleItem,
        *,
        owner_epoch: int,
        timestamp: TransitionTimestamp,
    ) -> bool:
        """Atomically consume and claim work; false means already consumed."""
        ...


@dataclass(frozen=True, slots=True)
class WorkLease:
    """Executable work exposed only after atomic journal consumption."""

    item: ScheduleItem
    owner_epoch: int
    leased_at: TransitionTimestamp


class PersistentScheduler:
    """Bounded scheduler coordinating queue projection and journal commits."""

    __slots__ = ("_clock", "_journal", "_owner_epoch", "_queue")

    def __init__(
        self,
        queue: PersistentPriorityQueue,
        *,
        journal: ScheduleJournal,
        clock: RuntimeClock,
        owner_epoch: int,
    ) -> None:
        if type(queue) is not PersistentPriorityQueue:
            raise TypeError("queue must be a PersistentPriorityQueue")
        if type(clock) is not RuntimeClock:
            raise TypeError("clock must be a RuntimeClock")
        if type(owner_epoch) is not int or not 0 <= owner_epoch <= (2**63) - 1:
            raise ValueError("owner_epoch must be a nonnegative signed-int64 integer")
        if not hasattr(journal, "persist") or not hasattr(journal, "consume"):
            raise TypeError("journal must implement the schedule persistence boundary")
        self._queue = queue
        self._journal = journal
        self._clock = clock
        self._owner_epoch = owner_epoch

    async def schedule(self, item: ScheduleItem) -> bool:
        """Persist before making one item visible in the runnable projection."""
        if type(item) is not ScheduleItem:
            raise TypeError("item must be a ScheduleItem")
        should_add = self._queue.validate_add(item)
        committed = await self._journal.persist(item)
        added = self._queue.add(item)
        if added != should_add or committed != added:
            # Exact replay may encounter a reconstructed queue that already contains
            # the row. Every other disagreement means the supplied boundary is broken.
            if not committed and not added:
                return False
            raise RuntimeError("journal and scheduler pending projections disagree")
        return added

    async def lease_due(
        self,
        logical_now_ns: int,
        *,
        limit: int = 1,
    ) -> tuple[WorkLease, ...]:
        """Lease due work in stable order, never exposing an uncommitted claim."""
        logical_now = validate_logical_nanoseconds(logical_now_ns)
        if type(limit) is not int or limit != 1:
            raise ValueError("lease_due commits exactly one physical work lease")
        due = self._queue.due(logical_now, limit=limit)
        leases: list[WorkLease] = []
        for item in due:
            timestamp = self._clock.transition_timestamp()
            consumed = await self._journal.consume(
                item,
                owner_epoch=self._owner_epoch,
                timestamp=timestamp,
            )
            self._queue.mark_consumed(item.schedule_entry_id)
            if consumed:
                leases.append(
                    WorkLease(
                        item=item,
                        owner_epoch=self._owner_epoch,
                        leased_at=timestamp,
                    )
                )
        return tuple(leases)

    def pending(self) -> tuple[ScheduleItem, ...]:
        """Return the canonical pending projection."""
        return self._queue.snapshot()
