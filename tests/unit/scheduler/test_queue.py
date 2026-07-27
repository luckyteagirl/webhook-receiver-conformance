"""Deterministic persistent scheduler tests for TASK-0302."""
# ruff: noqa: D101, D102, EM101, INP001, TRY003

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import anyio
import pytest
from hypothesis import given, note, settings
from hypothesis import strategies as st

from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
    TransitionTimestamp,
)
from webhook_receiver_conformance.scheduler.engine import (
    PersistentScheduler,
    ScheduleJournal,
    WorkLease,
)
from webhook_receiver_conformance.scheduler.queue import (
    PersistentPriorityQueue,
    ScheduleItem,
    ScheduleQueueError,
    canonical_schedule_bytes,
)

settings.register_profile("scheduler_ci", max_examples=100, derandomize=True, deadline=None)


def _item(
    index: int, *, due: int = 0, ordinals: tuple[int, int, int, int] | None = None
) -> ScheduleItem:
    scenario, step, delivery, attempt = ordinals or (index, 0, 0, 0)
    return ScheduleItem(
        schedule_entry_id=f"schedule.{index}",
        entity_id=f"attempt.{index}",
        logical_due_ns=due,
        scenario_ordinal=scenario,
        step_ordinal=step,
        delivery_ordinal=delivery,
        attempt_ordinal=attempt,
        deterministic_tie_key=f"tie.{index}",
    )


def _clock() -> RuntimeClock:
    return RuntimeClock(
        ClockPolicy(ClockMode.REAL),
        wall_now=lambda: datetime(2026, 1, 1, tzinfo=UTC),
        monotonic_now=lambda: 10,
    )


@dataclass
class MemoryJournal(ScheduleJournal):
    entries: dict[str, ScheduleItem] = field(default_factory=dict[str, ScheduleItem])
    consumed: set[str] = field(default_factory=set[str])
    consume_order: list[str] = field(default_factory=list[str])
    fail_persist: bool = False
    fail_consume: bool = False

    async def persist(self, item: ScheduleItem) -> bool:
        if self.fail_persist:
            raise RuntimeError("injected persistence failure")
        existing = self.entries.get(item.schedule_entry_id)
        if existing is not None:
            if existing != item:
                raise RuntimeError("identity conflict")
            return False
        self.entries[item.schedule_entry_id] = item
        return True

    async def consume(
        self,
        item: ScheduleItem,
        *,
        owner_epoch: int,
        timestamp: TransitionTimestamp,
    ) -> bool:
        del owner_epoch, timestamp
        if self.fail_consume:
            raise RuntimeError("injected consumption failure")
        if item.schedule_entry_id in self.consumed:
            return False
        self.consumed.add(item.schedule_entry_id)
        self.consume_order.append(item.schedule_entry_id)
        return True


def test_equal_due_time_golden_uses_normative_ordinal_order() -> None:
    entries = (
        _item(4, ordinals=(1, 1, 0, 0)),
        _item(3, ordinals=(1, 0, 1, 0)),
        _item(2, ordinals=(1, 0, 0, 1)),
        _item(1, ordinals=(0, 9, 9, 9)),
        _item(0, ordinals=(1, 0, 0, 0)),
    )

    queue = PersistentPriorityQueue.reconstruct(tuple(reversed(entries)))

    assert tuple(item.schedule_entry_id for item in queue.snapshot()) == (
        "schedule.1",
        "schedule.0",
        "schedule.2",
        "schedule.3",
        "schedule.4",
    )
    golden = (
        b'[{"attempt_ordinal":9,"delivery_ordinal":9,'
        b'"deterministic_tie_key":"tie.1","entity_id":"attempt.1",'
        b'"logical_due_ns":0,"scenario_ordinal":0,'
        b'"schedule_entry_id":"schedule.1","step_ordinal":9},'
        b'{"attempt_ordinal":0,"delivery_ordinal":0,'
        b'"deterministic_tie_key":"tie.0","entity_id":"attempt.0",'
        b'"logical_due_ns":0,"scenario_ordinal":1,'
        b'"schedule_entry_id":"schedule.0","step_ordinal":0},'
        b'{"attempt_ordinal":1,"delivery_ordinal":0,'
        b'"deterministic_tie_key":"tie.2","entity_id":"attempt.2",'
        b'"logical_due_ns":0,"scenario_ordinal":1,'
        b'"schedule_entry_id":"schedule.2","step_ordinal":0},'
        b'{"attempt_ordinal":0,"delivery_ordinal":1,'
        b'"deterministic_tie_key":"tie.3","entity_id":"attempt.3",'
        b'"logical_due_ns":0,"scenario_ordinal":1,'
        b'"schedule_entry_id":"schedule.3","step_ordinal":0},'
        b'{"attempt_ordinal":0,"delivery_ordinal":0,'
        b'"deterministic_tie_key":"tie.4","entity_id":"attempt.4",'
        b'"logical_due_ns":0,"scenario_ordinal":1,'
        b'"schedule_entry_id":"schedule.4","step_ordinal":1}]'
    )
    assert canonical_schedule_bytes(entries) == golden
    assert canonical_schedule_bytes(tuple(reversed(entries))) == golden


@pytest.mark.anyio
async def test_persist_precedes_visibility_and_failure_leaves_no_pending_item() -> None:
    journal = MemoryJournal(fail_persist=True)
    scheduler = PersistentScheduler(
        PersistentPriorityQueue(),
        journal=journal,
        clock=_clock(),
        owner_epoch=1,
    )

    with pytest.raises(RuntimeError, match="injected persistence"):
        await scheduler.schedule(_item(0))

    assert scheduler.pending() == ()


@pytest.mark.anyio
async def test_resume_leases_each_due_entry_exactly_once() -> None:
    entries = tuple(_item(index, due=index) for index in range(4))
    journal = MemoryJournal(entries={item.schedule_entry_id: item for item in entries})
    first = PersistentScheduler(
        PersistentPriorityQueue.reconstruct(entries),
        journal=journal,
        clock=_clock(),
        owner_epoch=4,
    )

    first_leases_list: list[WorkLease] = []
    for _index in range(3):
        first_leases_list.extend(await first.lease_due(2))
    first_leases = tuple(first_leases_list)
    resumed = PersistentScheduler(
        PersistentPriorityQueue.reconstruct(
            entries,
            consumed_entry_ids=frozenset(journal.consumed),
        ),
        journal=journal,
        clock=_clock(),
        owner_epoch=5,
    )
    second_leases_list: list[WorkLease] = []
    for _index in range(4):
        second_leases_list.extend(await resumed.lease_due(10))
    second_leases = tuple(second_leases_list)
    third_leases = await resumed.lease_due(10)

    leased = first_leases + second_leases
    assert tuple(lease.item.schedule_entry_id for lease in leased) == tuple(
        item.schedule_entry_id for item in entries
    )
    assert third_leases == ()
    assert len(set(journal.consume_order)) == len(entries)


@pytest.mark.anyio
async def test_failed_atomic_consume_does_not_expose_lease_or_remove_item() -> None:
    item = _item(0)
    journal = MemoryJournal(entries={item.schedule_entry_id: item}, fail_consume=True)
    scheduler = PersistentScheduler(
        PersistentPriorityQueue.reconstruct((item,)),
        journal=journal,
        clock=_clock(),
        owner_epoch=1,
    )

    with pytest.raises(RuntimeError, match="injected consumption"):
        await scheduler.lease_due(0)

    assert scheduler.pending() == (item,)


@pytest.mark.anyio
async def test_cancelled_journal_claim_leaves_item_pending() -> None:
    item = _item(0)
    entered = anyio.Event()

    class BlockingJournal(MemoryJournal):
        async def consume(
            self,
            item: ScheduleItem,
            *,
            owner_epoch: int,
            timestamp: TransitionTimestamp,
        ) -> bool:
            del item, owner_epoch, timestamp
            entered.set()
            await anyio.sleep_forever()
            raise AssertionError

    scheduler = PersistentScheduler(
        PersistentPriorityQueue.reconstruct((item,)),
        journal=BlockingJournal(entries={item.schedule_entry_id: item}),
        clock=_clock(),
        owner_epoch=1,
    )

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(scheduler.lease_due, 0)
        await entered.wait()
        tasks.cancel_scope.cancel()

    assert scheduler.pending() == (item,)


def test_resource_bound_duplicate_replay_and_conflict() -> None:
    queue = PersistentPriorityQueue(maximum_items=1)
    item = _item(0)
    assert queue.add(item)
    assert not queue.add(item)
    with pytest.raises(ScheduleQueueError):
        queue.add(_item(0, due=1))
    with pytest.raises(ScheduleQueueError):
        queue.add(_item(1))


@given(
    st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=20),
            st.integers(min_value=-5, max_value=5),
        ),
        max_size=100,
    )
)
@settings(max_examples=100, derandomize=True, deadline=None)
def test_property_queue_matches_sorted_unique_reference_model(
    actions: list[tuple[int, int]],
) -> None:
    note(f"replayable_actions={actions!r}")
    queue = PersistentPriorityQueue(maximum_items=21)
    model: dict[int, ScheduleItem] = {}
    for identity, due in actions:
        item = _item(identity, due=due)
        existing = model.get(identity)
        if existing is not None and existing != item:
            with pytest.raises(ScheduleQueueError):
                queue.add(item)
        else:
            added = queue.add(item)
            assert added is (existing is None)
            model[identity] = item
        assert queue.snapshot() == tuple(sorted(model.values(), key=lambda entry: entry.order_key))


@given(
    st.lists(
        st.tuples(
            st.sampled_from(("add", "consume")),
            st.integers(min_value=0, max_value=15),
        ),
        max_size=100,
    )
)
@settings(max_examples=100, derandomize=True, deadline=None)
def test_stateful_action_lists_replay_against_reference_model(
    actions: list[tuple[str, int]],
) -> None:
    note(f"replayable_actions={actions!r}")
    queue = PersistentPriorityQueue(maximum_items=16)
    model: dict[int, ScheduleItem] = {}
    for action, identity in actions:
        if action == "add":
            item = _item(identity)
            queue.add(item)
            model[identity] = item
        else:
            removed = queue.mark_consumed(f"schedule.{identity}")
            expected = model.pop(identity, None)
            assert removed == expected
        assert queue.snapshot() == tuple(sorted(model.values(), key=lambda entry: entry.order_key))
