"""Deterministic bounded priority queue for persisted schedule entries."""
# ruff: noqa: D105, D107, EM101, INP001, TRY003

from __future__ import annotations

import heapq
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from webhook_receiver_conformance.scheduler.clocks import validate_logical_nanoseconds

MAX_SCHEDULE_ITEMS: Final = 100_000
MAX_ORDINAL: Final = 9_007_199_254_740_991
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]+")


class ScheduleQueueErrorCode(StrEnum):
    """Stable queue failure classifications."""

    CAPACITY_EXCEEDED = "capacity-exceeded"
    DUPLICATE_CONFLICT = "duplicate-conflict"
    INVALID_ITEM = "invalid-item"


class ScheduleQueueError(RuntimeError):
    """Bounded scheduler input/resource failure."""

    code: ScheduleQueueErrorCode

    def __init__(self, code: ScheduleQueueErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ScheduleItem:
    """One immutable persisted work identity and normative stable order key."""

    schedule_entry_id: str
    entity_id: str
    logical_due_ns: int
    scenario_ordinal: int
    step_ordinal: int
    delivery_ordinal: int
    attempt_ordinal: int
    deterministic_tie_key: str

    def __post_init__(self) -> None:
        _token(self.schedule_entry_id, "schedule entry ID", 96)
        _token(self.entity_id, "scheduled entity ID", 96)
        validate_logical_nanoseconds(self.logical_due_ns)
        for value, name in (
            (self.scenario_ordinal, "scenario ordinal"),
            (self.step_ordinal, "step ordinal"),
            (self.delivery_ordinal, "delivery ordinal"),
            (self.attempt_ordinal, "attempt ordinal"),
        ):
            if type(value) is not int or not 0 <= value <= MAX_ORDINAL:
                raise ScheduleQueueError(
                    ScheduleQueueErrorCode.INVALID_ITEM,
                    f"{name} must be a nonnegative safe integer",
                )
        _token(self.deterministic_tie_key, "deterministic tie key", 256)

    @property
    def order_key(self) -> tuple[int, int, int, int, int, str, str]:
        """Return the complete cross-platform comparison key."""
        return (
            self.logical_due_ns,
            self.scenario_ordinal,
            self.step_ordinal,
            self.delivery_ordinal,
            self.attempt_ordinal,
            self.deterministic_tie_key,
            self.schedule_entry_id,
        )


class PersistentPriorityQueue:
    """In-memory projection reconstructed only from persistent schedule state."""

    __slots__ = ("_entries", "_heap", "_maximum_items")

    def __init__(self, *, maximum_items: int = MAX_SCHEDULE_ITEMS) -> None:
        if type(maximum_items) is not int or not 1 <= maximum_items <= MAX_SCHEDULE_ITEMS:
            raise ValueError("maximum_items must be between 1 and 100000")
        self._maximum_items = maximum_items
        self._entries: dict[str, ScheduleItem] = {}
        self._heap: list[tuple[tuple[int, int, int, int, int, str, str], str]] = []

    @classmethod
    def reconstruct(
        cls,
        entries: tuple[ScheduleItem, ...],
        *,
        consumed_entry_ids: frozenset[str] = frozenset(),
        maximum_items: int = MAX_SCHEDULE_ITEMS,
    ) -> PersistentPriorityQueue:
        """Rebuild the same pending set while excluding durably consumed rows."""
        if type(entries) is not tuple or type(consumed_entry_ids) is not frozenset:
            raise TypeError("persistent schedule snapshots must be tuple/frozenset values")
        queue = cls(maximum_items=maximum_items)
        for entry in entries:
            if type(entry) is not ScheduleItem:
                raise TypeError("schedule snapshots must contain ScheduleItem values")
            if entry.schedule_entry_id not in consumed_entry_ids:
                queue.add(entry)
        return queue

    def add(self, item: ScheduleItem) -> bool:
        """Add one item idempotently; conflicting identity reuse fails closed."""
        should_add = self.validate_add(item)
        if not should_add:
            return False
        self._entries[item.schedule_entry_id] = item
        heapq.heappush(self._heap, (item.order_key, item.schedule_entry_id))
        return True

    def validate_add(self, item: ScheduleItem) -> bool:
        """Validate an insertion without changing the pending projection."""
        if type(item) is not ScheduleItem:
            raise TypeError("item must be a ScheduleItem")
        existing = self._entries.get(item.schedule_entry_id)
        if existing is not None:
            if existing != item:
                raise ScheduleQueueError(
                    ScheduleQueueErrorCode.DUPLICATE_CONFLICT,
                    "schedule entry identity was reused with different semantics",
                )
            return False
        if len(self._entries) >= self._maximum_items:
            raise ScheduleQueueError(
                ScheduleQueueErrorCode.CAPACITY_EXCEEDED,
                "persistent schedule exceeded its configured item bound",
            )
        return True

    def peek(self) -> ScheduleItem | None:
        """Return the next pending item without changing its persistent meaning."""
        self._discard_stale()
        if not self._heap:
            return None
        return self._entries[self._heap[0][1]]

    def due(self, logical_now_ns: int, *, limit: int) -> tuple[ScheduleItem, ...]:
        """Return an ordered bounded snapshot without leasing or removing items."""
        now = validate_logical_nanoseconds(logical_now_ns)
        if type(limit) is not int or not 1 <= limit <= self._maximum_items:
            raise ValueError("due limit must be within the configured item bound")
        return tuple(
            item
            for item in sorted(self._entries.values(), key=lambda candidate: candidate.order_key)
            if item.logical_due_ns <= now
        )[:limit]

    def mark_consumed(self, schedule_entry_id: str) -> ScheduleItem | None:
        """Remove an item only after its journal consumption commit."""
        _token(schedule_entry_id, "schedule entry ID", 96)
        return self._entries.pop(schedule_entry_id, None)

    def snapshot(self) -> tuple[ScheduleItem, ...]:
        """Return a canonical platform-independent pending projection."""
        return tuple(sorted(self._entries.values(), key=lambda item: item.order_key))

    def __len__(self) -> int:
        return len(self._entries)

    def _discard_stale(self) -> None:
        while self._heap and self._heap[0][1] not in self._entries:
            heapq.heappop(self._heap)


def _token(value: object, name: str, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _TOKEN.fullmatch(value) is None:
        raise ScheduleQueueError(
            ScheduleQueueErrorCode.INVALID_ITEM,
            f"{name} must be a bounded ASCII token",
        )
    return value


def canonical_schedule_bytes(entries: tuple[ScheduleItem, ...]) -> bytes:
    """Serialize a canonical golden projection without platform-dependent text."""
    if type(entries) is not tuple or any(type(item) is not ScheduleItem for item in entries):
        raise TypeError("canonical schedule input must be a tuple of ScheduleItem values")
    ordered = sorted(entries, key=lambda item: item.order_key)
    payload = [
        {
            "attempt_ordinal": item.attempt_ordinal,
            "delivery_ordinal": item.delivery_ordinal,
            "deterministic_tie_key": item.deterministic_tie_key,
            "entity_id": item.entity_id,
            "logical_due_ns": item.logical_due_ns,
            "scenario_ordinal": item.scenario_ordinal,
            "schedule_entry_id": item.schedule_entry_id,
            "step_ordinal": item.step_ordinal,
        }
        for item in ordered
    ]
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
