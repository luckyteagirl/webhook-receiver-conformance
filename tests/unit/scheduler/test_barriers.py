"""Hostile and contract tests for bounded concurrency-group barriers."""
# ruff: noqa: ASYNC115, E731, EM101, INP001, PLR2004, RUF043, TC003

from __future__ import annotations

from collections.abc import Callable

import anyio
import pytest

from webhook_receiver_conformance.scheduler.barriers import (
    DEFAULT_DELIVERY_CONCURRENCY,
    HARD_DELIVERY_CONCURRENCY,
    BarrierInputError,
    BarrierRelease,
    ConcurrencyWork,
    run_concurrency_groups,
    validate_concurrency,
)


def _items(
    count: int,
    *,
    group: str = "cohort-a",
    duplicate_delivery: bool = False,
) -> tuple[ConcurrencyWork[str], ...]:
    return tuple(
        ConcurrencyWork(
            work_id=f"attempt-{index}",
            concurrency_group=group,
            ordinal=index,
            payload=("delivery-shared" if duplicate_delivery else f"delivery-{index}"),
        )
        for index in range(count)
    )


def test_vt_perf_004_default_concurrency_is_ten() -> None:
    assert validate_concurrency() == DEFAULT_DELIVERY_CONCURRENCY == 10
    assert HARD_DELIVERY_CONCURRENCY == 50


@pytest.mark.parametrize("value", [1, 10, 50])
def test_vt_perf_005_valid_concurrency_boundaries(value: int) -> None:
    assert validate_concurrency(value) == value


@pytest.mark.parametrize("value", [0, 51, -1, True, 1.5, "10"])
def test_vt_fr_009_invalid_concurrency_fails_closed(value: object) -> None:
    with pytest.raises(BarrierInputError, match="concurrency"):
        validate_concurrency(value)  # pyright: ignore[reportArgumentType]


@pytest.mark.anyio
async def test_50_accepts_and_51_rejects_before_any_task_creation() -> None:
    created: list[str] = []

    async def callback(item: ConcurrencyWork[str]) -> str:
        return item.payload

    accepted = await run_concurrency_groups(
        _items(50),
        callback,
        max_concurrency=50,
        task_created=created.append,
    )
    assert accepted.peak_created_tasks == 50
    assert len(created) == 50

    created.clear()
    with pytest.raises(BarrierInputError, match="concurrency"):
        await run_concurrency_groups(
            _items(51),
            callback,
            max_concurrency=51,
            task_created=created.append,
        )
    assert created == []


@pytest.mark.anyio
async def test_vt_sec_026_large_duplicate_retry_workload_bounds_task_creation() -> None:
    cap = 7
    active = 0
    peak_active = 0
    created: list[str] = []
    lock = anyio.Lock()

    async def callback(item: ConcurrencyWork[str]) -> str:
        nonlocal active, peak_active
        async with lock:
            active += 1
            peak_active = max(peak_active, active)
        await anyio.sleep(0)
        async with lock:
            active -= 1
        return item.payload

    result = await run_concurrency_groups(
        _items(250, duplicate_delivery=True),
        callback,
        max_concurrency=cap,
        task_created=created.append,
    )
    assert len(created) == cap
    assert result.peak_created_tasks == cap
    assert peak_active <= cap
    assert len(result.completed) == 250
    assert tuple(item.work.work_id for item in result.completed) == tuple(
        f"attempt-{index}" for index in range(250)
    )


@pytest.mark.anyio
async def test_many_groups_reuse_one_globally_bounded_worker_pool() -> None:
    cap = 5
    created: list[str] = []
    work = tuple(
        ConcurrencyWork(
            work_id=f"grouped-{index}",
            concurrency_group=f"group-{index // 3}",
            ordinal=index,
            payload=index,
        )
        for index in range(120)
    )

    async def callback(item: ConcurrencyWork[int]) -> int:
        await anyio.sleep(0)
        return item.payload

    result = await run_concurrency_groups(
        work,
        callback,
        max_concurrency=cap,
        task_created=created.append,
    )
    assert len(created) == cap
    assert result.peak_created_tasks == cap
    assert len(result.releases) == 40


@pytest.mark.anyio
async def test_vt_sched_015_one_barrier_releases_each_initial_cohort() -> None:
    ticks = iter(range(100, 1000))
    monotonic: Callable[[], int] = lambda: next(ticks)
    work = (
        *_items(3, group="first"),
        *tuple(
            ConcurrencyWork(
                work_id=f"second-{index}",
                concurrency_group="second",
                ordinal=index,
                payload=f"value-{index}",
            )
            for index in range(2)
        ),
    )

    async def callback(item: ConcurrencyWork[str]) -> str:
        await anyio.sleep(0)
        return item.payload

    result = await run_concurrency_groups(
        work,
        callback,
        max_concurrency=3,
        monotonic_ns=monotonic,
    )
    assert tuple(release.concurrency_group for release in result.releases) == (
        "first",
        "second",
    )
    assert result.releases[0].eligible_work_ids == (
        "attempt-0",
        "attempt-1",
        "attempt-2",
    )
    releases = {item.concurrency_group: item.released_monotonic_ns for item in result.releases}
    assert all(
        item.start.actual_monotonic_start_ns >= releases[item.start.concurrency_group]
        for item in result.completed
    )
    assert all(
        "actual_monotonic_start_ns" in item.start.__dataclass_fields__ for item in result.completed
    )


@pytest.mark.anyio
async def test_results_remain_associated_and_ordered_despite_completion_order() -> None:
    async def callback(item: ConcurrencyWork[int]) -> str:
        await anyio.sleep((5 - item.payload) / 1000)
        return f"result-{item.payload}"

    work = tuple(
        ConcurrencyWork(
            work_id=f"work-{index}",
            concurrency_group="reordered",
            ordinal=index,
            payload=index,
        )
        for index in range(6)
    )
    result = await run_concurrency_groups(work, callback, max_concurrency=6)
    assert tuple(item.result for item in result.completed) == tuple(
        f"result-{index}" for index in range(6)
    )
    assert tuple(item.work.payload for item in result.completed) == tuple(range(6))


@pytest.mark.anyio
async def test_duplicate_and_conflicting_identities_fail_before_task_creation() -> None:
    first = ConcurrencyWork("same", "group", 0, "first")
    exact = ConcurrencyWork("same", "group", 0, "first")
    conflict = ConcurrencyWork("same", "other", 1, "second")
    callback_calls = 0
    created: list[str] = []

    async def callback(_item: ConcurrencyWork[str]) -> str:
        nonlocal callback_calls
        callback_calls += 1
        return "unexpected"

    for invalid in ((first, exact), (first, conflict)):
        with pytest.raises(BarrierInputError, match="duplicate|conflicting"):
            await run_concurrency_groups(
                invalid,
                callback,
                task_created=created.append,
            )
    assert callback_calls == 0
    assert created == []


@pytest.mark.anyio
async def test_cancellation_cleans_up_every_created_worker() -> None:
    entered = 0
    exited = 0

    async def callback(_item: ConcurrencyWork[str]) -> str:
        nonlocal entered, exited
        entered += 1
        try:
            await anyio.sleep_forever()
        finally:
            exited += 1
        return "unreachable"

    with anyio.move_on_after(0.02) as scope:
        await run_concurrency_groups(
            _items(100),
            callback,
            max_concurrency=5,
        )
    assert scope.cancel_called
    assert entered == 5
    assert exited == entered


@pytest.mark.anyio
async def test_worker_exception_cancels_siblings_and_releases_resources() -> None:
    entered = 0
    exited = 0

    async def callback(item: ConcurrencyWork[str]) -> str:
        nonlocal entered, exited
        entered += 1
        try:
            if item.work_id == "attempt-0":
                raise RuntimeError("worker-failure")
            await anyio.sleep_forever()
        finally:
            exited += 1
        return "unreachable"

    with pytest.raises(ExceptionGroup) as captured:
        await run_concurrency_groups(
            _items(20),
            callback,
            max_concurrency=4,
        )
    assert any(
        isinstance(error, RuntimeError) and str(error) == "worker-failure"
        for error in captured.value.exceptions
    )
    assert 1 <= entered <= 4
    assert exited == entered


def test_invalid_work_shapes_fail_closed() -> None:
    with pytest.raises(BarrierInputError):
        ConcurrencyWork("", "group", 0, None)
    with pytest.raises(BarrierInputError):
        ConcurrencyWork("work", "", 0, None)
    with pytest.raises(BarrierInputError):
        ConcurrencyWork("work", "group", -1, None)
    with pytest.raises(BarrierInputError):
        BarrierRelease("group", 0, ("bad work id",))
    with pytest.raises(BarrierInputError):
        BarrierRelease("group", 0, ("work", "work"))
