"""Bounded structured-concurrency release for delivery concurrency groups."""
# ruff: noqa: C901, D105, EM101, EM102, INP001, TC003, TRY003

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Final, Protocol, cast

import anyio

DEFAULT_DELIVERY_CONCURRENCY: Final = 10
HARD_DELIVERY_CONCURRENCY: Final = 50
MAX_GROUP_ITEMS: Final = 100_000
MAX_ORDINAL: Final = 9_007_199_254_740_991
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]+")


class BarrierInputError(ValueError):
    """Fail-closed invalid group, identity, or concurrency input."""


@dataclass(frozen=True, slots=True, repr=False)
class ConcurrencyWork[T]:
    """One uniquely identified callback input in deterministic result order."""

    work_id: str
    concurrency_group: str
    ordinal: int
    payload: T = field(repr=False)

    def __post_init__(self) -> None:
        _token(self.work_id, field_name="work_id", maximum=96)
        _token(
            self.concurrency_group,
            field_name="concurrency_group",
            maximum=128,
        )
        if type(self.ordinal) is not int or not 0 <= self.ordinal <= MAX_ORDINAL:
            raise BarrierInputError("ordinal must be a nonnegative safe integer")


@dataclass(frozen=True, slots=True)
class ActualStartEvidence:
    """Actual worker callback start observation; no simultaneity is implied."""

    work_id: str
    concurrency_group: str
    actual_monotonic_start_ns: int

    def __post_init__(self) -> None:
        _token(self.work_id, field_name="work_id", maximum=96)
        _token(
            self.concurrency_group,
            field_name="concurrency_group",
            maximum=128,
        )
        _monotonic(self.actual_monotonic_start_ns)


@dataclass(frozen=True, slots=True)
class BarrierRelease:
    """One cohort release observation from a single shared barrier."""

    concurrency_group: str
    released_monotonic_ns: int
    eligible_work_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _token(
            self.concurrency_group,
            field_name="concurrency_group",
            maximum=128,
        )
        _monotonic(self.released_monotonic_ns)
        if (
            type(self.eligible_work_ids) is not tuple
            or not self.eligible_work_ids
            or any(type(item) is not str for item in self.eligible_work_ids)
        ):
            raise BarrierInputError("eligible_work_ids must be a nonempty tuple")
        for work_id in self.eligible_work_ids:
            _token(work_id, field_name="eligible work ID", maximum=96)
        if len(self.eligible_work_ids) != len(set(self.eligible_work_ids)):
            raise BarrierInputError("eligible_work_ids must be unique")


@dataclass(frozen=True, slots=True)
class CompletedWork[T]:
    """One callback result associated with its exact input and start evidence."""

    work: ConcurrencyWork[object]
    result: T
    start: ActualStartEvidence


@dataclass(frozen=True, slots=True)
class BarrierRun[T]:
    """Deterministically associated outputs plus actual release evidence."""

    completed: tuple[CompletedWork[T], ...]
    releases: tuple[BarrierRelease, ...]
    configured_concurrency: int
    peak_created_tasks: int

    def __post_init__(self) -> None:
        validate_concurrency(self.configured_concurrency)
        if type(self.peak_created_tasks) is not int or not (
            0 <= self.peak_created_tasks <= self.configured_concurrency
        ):
            raise ValueError("peak_created_tasks exceeds configured concurrency")


class WorkCallback[T, R](Protocol):
    """One asynchronous delivery/attempt execution boundary."""

    def __call__(self, work: ConcurrencyWork[T], /) -> Awaitable[R]: ...


def validate_concurrency(value: int | None = None) -> int:
    """Realize the default and reject values above the v0.1 hard cap."""
    realized = DEFAULT_DELIVERY_CONCURRENCY if value is None else value
    if type(realized) is not int:
        raise BarrierInputError("delivery concurrency must be an integer")
    if not 1 <= realized <= HARD_DELIVERY_CONCURRENCY:
        raise BarrierInputError("delivery concurrency must be between 1 and 50")
    return realized


async def run_concurrency_groups[T, R](
    work: tuple[ConcurrencyWork[T], ...],
    callback: WorkCallback[T, R],
    *,
    max_concurrency: int | None = None,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
    task_created: Callable[[str], None] | None = None,
) -> BarrierRun[R]:
    """Release each group cohort through one barrier using a bounded worker pool.

    At most ``max_concurrency`` worker tasks are created for a cohort. Work beyond
    that bound is pulled by those workers instead of being represented by dormant
    tasks waiting on a semaphore.
    """
    concurrency = validate_concurrency(max_concurrency)
    cohorts = _validate_and_group(work)
    if not callable(callback):
        raise BarrierInputError("callback must be callable")
    if not callable(monotonic_ns):
        raise BarrierInputError("monotonic_ns must be callable")
    if task_created is not None and not callable(task_created):
        raise BarrierInputError("task_created must be callable or None")

    completed: list[CompletedWork[R] | None] = [None] * len(work)
    releases: list[BarrierRelease] = []
    created = min(concurrency, len(work))
    barriers = {group: anyio.Event() for group, _cohort in cohorts}
    pending = tuple(entry for _group, cohort in cohorts for entry in cohort)
    index_lock = anyio.Lock()
    next_index = 0

    async def worker() -> None:
        nonlocal next_index
        while True:
            async with index_lock:
                if next_index >= len(pending):
                    return
                original_index, item = pending[next_index]
                next_index += 1
            await barriers[item.concurrency_group].wait()
            started_ns = _monotonic(monotonic_ns())
            start = ActualStartEvidence(
                work_id=item.work_id,
                concurrency_group=item.concurrency_group,
                actual_monotonic_start_ns=started_ns,
            )
            result = await callback(item)
            completed[original_index] = CompletedWork(
                work=cast("ConcurrencyWork[object]", item),
                result=result,
                start=start,
            )

    async with anyio.create_task_group() as task_group:
        for worker_index in range(created):
            task_id = f"concurrency-worker:{worker_index}"
            if task_created is not None:
                task_created(task_id)
            task_group.start_soon(worker, name=task_id)
        for group, cohort in cohorts:
            released = _monotonic(monotonic_ns())
            releases.append(
                BarrierRelease(
                    concurrency_group=group,
                    released_monotonic_ns=released,
                    eligible_work_ids=tuple(item.work_id for _index, item in cohort),
                )
            )
            barriers[group].set()

    if any(item is None for item in completed):
        raise RuntimeError("structured concurrency completed without every result")
    return BarrierRun(
        completed=cast("tuple[CompletedWork[R], ...]", tuple(completed)),
        releases=tuple(releases),
        configured_concurrency=concurrency,
        peak_created_tasks=created,
    )


def _validate_and_group[T](
    work: tuple[ConcurrencyWork[T], ...],
) -> tuple[tuple[str, tuple[tuple[int, ConcurrencyWork[T]], ...]], ...]:
    if type(work) is not tuple:
        raise BarrierInputError("work must be provided as a tuple")
    if len(work) > MAX_GROUP_ITEMS:
        raise BarrierInputError("work exceeds the scheduler item limit")
    identities: set[str] = set()
    groups: dict[str, list[tuple[int, ConcurrencyWork[T]]]] = {}
    group_order: list[str] = []
    for index, item in enumerate(work):
        if type(item) is not ConcurrencyWork:
            raise BarrierInputError("work must contain exact ConcurrencyWork values")
        if item.work_id in identities:
            raise BarrierInputError("duplicate or conflicting work identity")
        identities.add(item.work_id)
        if item.concurrency_group not in groups:
            groups[item.concurrency_group] = []
            group_order.append(item.concurrency_group)
        groups[item.concurrency_group].append((index, item))
    return tuple(
        (
            group,
            tuple(sorted(groups[group], key=lambda entry: (entry[1].ordinal, entry[0]))),
        )
        for group in group_order
    )


def _token(value: object, *, field_name: str, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _TOKEN.fullmatch(value) is None:
        raise BarrierInputError(f"{field_name} must be a bounded ASCII token")
    return value


def _monotonic(value: object) -> int:
    if type(value) is not int or value < 0:
        raise BarrierInputError("monotonic evidence must be a nonnegative integer")
    return value


__all__ = [
    "DEFAULT_DELIVERY_CONCURRENCY",
    "HARD_DELIVERY_CONCURRENCY",
    "ActualStartEvidence",
    "BarrierInputError",
    "BarrierRelease",
    "BarrierRun",
    "CompletedWork",
    "ConcurrencyWork",
    "run_concurrency_groups",
    "validate_concurrency",
]
