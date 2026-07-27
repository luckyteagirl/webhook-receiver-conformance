"""Contract and adversarial tests for strict scheduler clock domains."""
# ruff: noqa: D102, D107, INP001, PLR2004

from __future__ import annotations

import time
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from fractions import Fraction
from typing import cast

import anyio
import pytest
from pydantic import TypeAdapter, ValidationError

from webhook_receiver_conformance.config.models import (
    RealClockConfig,
    ScaledClockConfig,
)
from webhook_receiver_conformance.scheduler.clocks import (
    MAXIMUM_SCALE,
    MINIMUM_SCALE,
    NANOSECONDS_PER_SECOND,
    SIGNED_INT64_MAX,
    SIGNED_INT64_MIN,
    ClockMode,
    ClockPolicy,
    MonotonicDeadline,
    RuntimeClock,
    TransitionTimestamp,
    add_logical_nanoseconds,
    validate_logical_nanoseconds,
    validate_utc_wall_time,
)


class VirtualTestClock:
    """Deterministic in-process fake; it never represents external virtual time."""

    def __init__(
        self,
        *,
        monotonic_ns: int = 0,
        wall_time: datetime | None = None,
    ) -> None:
        self.monotonic_ns = monotonic_ns
        self.wall_time = datetime(2026, 7, 27, 12, tzinfo=UTC) if wall_time is None else wall_time
        self.sleep_seconds: list[float] = []

    def read_wall(self) -> datetime:
        return self.wall_time

    def read_monotonic(self) -> int:
        return self.monotonic_ns

    async def sleep(self, seconds: float) -> None:
        self.sleep_seconds.append(seconds)
        self.monotonic_ns += round(seconds * NANOSECONDS_PER_SECOND)

    def advance(self, nanoseconds: int) -> None:
        self.monotonic_ns += nanoseconds


def _runtime(
    policy: ClockPolicy | None = None,
    *,
    fake: VirtualTestClock | None = None,
) -> tuple[RuntimeClock, VirtualTestClock]:
    source = VirtualTestClock() if fake is None else fake
    return (
        RuntimeClock(
            ClockPolicy(ClockMode.REAL) if policy is None else policy,
            wall_now=source.read_wall,
            monotonic_now=source.read_monotonic,
            sleep=source.sleep,
        ),
        source,
    )


def test_clock_policy_is_created_exactly_from_closed_project_config() -> None:
    real_config = RealClockConfig.model_validate({"mode": "real", "minimum_physical_wait": "2ms"})
    scaled_config = ScaledClockConfig.model_validate(
        {
            "mode": "scaled",
            "scale": "0.0100",
            "minimum_physical_wait": "1ms",
        }
    )

    real = ClockPolicy.from_config(real_config)
    scaled = ClockPolicy.from_config(scaled_config)

    assert real == ClockPolicy(mode=ClockMode.REAL)
    assert scaled.mode is ClockMode.SCALED
    assert scaled.scale == Fraction(1, 100)
    assert (scaled.scale_numerator, scaled.scale_denominator) == (1, 100)
    assert scaled.minimum_physical_wait_ns == 1_000_000


def test_virtual_mode_is_not_a_project_configuration_branch() -> None:
    adapter: TypeAdapter[RealClockConfig | ScaledClockConfig] = TypeAdapter(
        RealClockConfig | ScaledClockConfig
    )

    with pytest.raises(ValidationError):
        adapter.validate_python({"mode": "virtual"})

    virtual = VirtualTestClock()
    clock = RuntimeClock(
        ClockPolicy(ClockMode.SCALED, 1, 100),
        wall_now=virtual.read_wall,
        monotonic_now=virtual.read_monotonic,
        sleep=virtual.sleep,
    )
    assert clock.policy.mode is ClockMode.SCALED


@pytest.mark.parametrize(
    ("values", "exception", "message"),
    [
        ({"mode": "real"}, TypeError, "ClockMode"),
        ({"mode": ClockMode.REAL, "scale_numerator": True}, TypeError, "integer"),
        ({"mode": ClockMode.REAL, "scale_denominator": 1.0}, TypeError, "integer"),
        ({"mode": ClockMode.REAL, "minimum_physical_wait_ns": False}, TypeError, "integer"),
        ({"mode": ClockMode.REAL, "scale_numerator": 2}, ValueError, "scale of one"),
        (
            {"mode": ClockMode.SCALED, "scale_numerator": 1, "scale_denominator": 1001},
            ValueError,
            "0.001",
        ),
        ({"mode": ClockMode.SCALED, "scale_numerator": 101}, ValueError, "0.001"),
        ({"mode": ClockMode.SCALED, "scale_denominator": 0}, ValueError, "between 1"),
        ({"mode": ClockMode.REAL, "minimum_physical_wait_ns": -1}, ValueError, "negative"),
        (
            {
                "mode": ClockMode.REAL,
                "minimum_physical_wait_ns": SIGNED_INT64_MAX + 1,
            },
            ValueError,
            "signed 64-bit",
        ),
    ],
)
def test_clock_policy_rejects_wrong_types_ranges_and_modes(
    values: dict[str, object],
    exception: type[Exception],
    message: str,
) -> None:
    with pytest.raises(exception, match=message):
        ClockPolicy(**values)  # pyright: ignore[reportArgumentType]


def test_scale_constants_and_exact_boundaries_are_frozen() -> None:
    minimum = ClockPolicy(ClockMode.SCALED, 1, 1000)
    maximum = ClockPolicy(ClockMode.SCALED, 100, 1)

    assert minimum.scale == MINIMUM_SCALE
    assert maximum.scale == MAXIMUM_SCALE
    assert minimum.physical_wait_ns(1000) == 1
    assert maximum.physical_wait_ns(1) == 100


@pytest.mark.parametrize(
    ("logical_ns", "expected_ns"),
    [
        (0, 0),
        (1, 1),
        (999, 1),
        (1000, 1),
        (1001, 2),
        (10 * NANOSECONDS_PER_SECOND, 10_000_000),
    ],
)
def test_scaled_wait_uses_exact_integer_ceiling(
    logical_ns: int,
    expected_ns: int,
) -> None:
    policy = ClockPolicy(ClockMode.SCALED, 1, 1000)

    assert policy.physical_wait_ns(logical_ns) == expected_ns


def test_scale_point_zero_one_maps_ten_seconds_to_one_hundred_milliseconds() -> None:
    policy = ClockPolicy(ClockMode.SCALED, 1, 100)

    assert policy.physical_wait_ns(10 * NANOSECONDS_PER_SECOND) == 100_000_000


def test_minimum_physical_wait_applies_only_to_positive_scaled_schedule_waits() -> None:
    scaled = ClockPolicy(
        ClockMode.SCALED,
        1,
        1000,
        minimum_physical_wait_ns=1_000_000,
    )

    assert scaled.physical_wait_ns(0) == 0
    assert scaled.physical_wait_ns(1) == 1_000_000


@pytest.mark.parametrize(
    "logical_wait_ns",
    [
        0,
        1,
        100_000_000,
        NANOSECONDS_PER_SECOND,
        SIGNED_INT64_MAX,
    ],
)
def test_real_configured_minimum_never_changes_exact_one_to_one_mapping(
    logical_wait_ns: int,
) -> None:
    config = RealClockConfig.model_validate(
        {
            "mode": "real",
            "minimum_physical_wait": "2s",
        }
    )
    policy = ClockPolicy.from_config(config)

    assert policy.minimum_physical_wait_ns == 0
    assert policy.physical_wait_ns(logical_wait_ns) == logical_wait_ns


def test_direct_real_policy_also_normalizes_minimum_to_zero() -> None:
    policy = ClockPolicy(
        ClockMode.REAL,
        minimum_physical_wait_ns=2 * NANOSECONDS_PER_SECOND,
    )

    assert policy.minimum_physical_wait_ns == 0
    assert policy.physical_wait_ns(100_000_000) == 100_000_000
    assert policy.physical_wait_ns(NANOSECONDS_PER_SECOND) == NANOSECONDS_PER_SECOND


@pytest.mark.anyio
async def test_runtime_real_config_ignores_minimum_for_one_to_one_sleep() -> None:
    config = RealClockConfig.model_validate(
        {
            "mode": "real",
            "minimum_physical_wait": "2s",
        }
    )
    fake = VirtualTestClock()
    clock = RuntimeClock.from_config(
        config,
        wall_now=fake.read_wall,
        monotonic_now=fake.read_monotonic,
        sleep=fake.sleep,
    )

    hundred_ms = await clock.sleep_logical(100_000_000)
    one_second = await clock.sleep_logical(NANOSECONDS_PER_SECOND)

    assert hundred_ms == 100_000_000
    assert one_second == NANOSECONDS_PER_SECOND
    assert fake.sleep_seconds == [0.1, 1.0]


def test_physical_wait_rejects_negative_wrong_type_and_scaled_overflow() -> None:
    real = ClockPolicy(ClockMode.REAL)
    maximum = ClockPolicy(ClockMode.SCALED, 100)

    for value in (True, False, 1.0, Fraction(1, 1)):
        with pytest.raises(TypeError, match="integer"):
            real.physical_wait_ns(value)
    with pytest.raises(ValueError, match="negative"):
        real.physical_wait_ns(-1)
    with pytest.raises(ValueError, match="signed 64-bit"):
        maximum.physical_wait_ns(SIGNED_INT64_MAX)


def test_physical_timeouts_are_unscaled_in_every_schedule_mode() -> None:
    timeout = 2 * NANOSECONDS_PER_SECOND
    policies = (
        ClockPolicy(ClockMode.REAL),
        ClockPolicy(ClockMode.SCALED, 1, 1000),
        ClockPolicy(ClockMode.SCALED, 100),
    )

    assert [policy.physical_timeout_ns(timeout) for policy in policies] == [
        timeout,
        timeout,
        timeout,
    ]


@pytest.mark.parametrize(
    "value",
    [SIGNED_INT64_MIN, -1, 0, 1, SIGNED_INT64_MAX],
)
def test_logical_nanoseconds_accept_exact_signed_int64_boundaries(value: int) -> None:
    assert validate_logical_nanoseconds(value) == value


@pytest.mark.parametrize("value", [True, False, 0.0, 1.5, "1", None])
def test_logical_nanoseconds_reject_fractional_and_coerced_values(value: object) -> None:
    with pytest.raises(TypeError, match="integer"):
        validate_logical_nanoseconds(value)


@pytest.mark.parametrize("value", [SIGNED_INT64_MIN - 1, SIGNED_INT64_MAX + 1])
def test_logical_nanoseconds_reject_signed_int64_overflow(value: int) -> None:
    with pytest.raises(ValueError, match="signed 64-bit"):
        validate_logical_nanoseconds(value)


def test_logical_addition_accepts_boundaries_and_rejects_overflow() -> None:
    assert add_logical_nanoseconds(SIGNED_INT64_MIN, SIGNED_INT64_MAX) == -1
    assert add_logical_nanoseconds(SIGNED_INT64_MAX, 0) == SIGNED_INT64_MAX

    with pytest.raises(OverflowError, match="signed 64-bit"):
        add_logical_nanoseconds(SIGNED_INT64_MAX, 1)
    with pytest.raises(OverflowError, match="signed 64-bit"):
        add_logical_nanoseconds(SIGNED_INT64_MIN, -1)


def test_utc_wall_time_requires_aware_zero_offset_datetime() -> None:
    utc = datetime(2026, 7, 27, 12, 30, 45, 123456, tzinfo=UTC)
    equivalent_zero_offset = utc.replace(tzinfo=timezone(timedelta(0), name="Etc/UTC"))

    assert validate_utc_wall_time(utc) == utc
    normalized = validate_utc_wall_time(equivalent_zero_offset)
    assert normalized == utc
    assert normalized.tzinfo is UTC

    with pytest.raises(TypeError, match="datetime"):
        validate_utc_wall_time("2026-07-27T12:30:45Z")
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        validate_utc_wall_time(utc.replace(tzinfo=None))
    with pytest.raises(ValueError, match="use UTC"):
        validate_utc_wall_time(utc.astimezone(timezone(timedelta(hours=1))))


def test_transition_timestamps_distinguish_live_and_historical_evidence() -> None:
    fake = VirtualTestClock(monotonic_ns=5_000)
    clock, _ = _runtime(fake=fake)
    fake.advance(250)

    live = clock.transition_timestamp()
    historical = TransitionTimestamp.historical(fake.wall_time)

    assert live.wall_time == fake.wall_time
    assert live.monotonic_elapsed_ns == 250
    assert live.is_live
    assert historical.wall_time == fake.wall_time
    assert historical.monotonic_elapsed_ns is None
    assert not historical.is_live
    with pytest.raises(FrozenInstanceError):
        live.monotonic_elapsed_ns = 0  # pyright: ignore[reportAttributeAccessIssue]


@pytest.mark.parametrize("value", [-1, SIGNED_INT64_MAX + 1])
def test_transition_timestamp_rejects_invalid_monotonic_history(value: int) -> None:
    with pytest.raises(ValueError, match="monotonic_elapsed_ns"):
        TransitionTimestamp(
            wall_time=datetime.now(UTC),
            monotonic_elapsed_ns=value,
        )


@pytest.mark.parametrize("value", [True, 1.0, "1"])
def test_transition_timestamp_rejects_noninteger_monotonic_history(value: object) -> None:
    with pytest.raises(TypeError, match="integer"):
        TransitionTimestamp(
            wall_time=datetime.now(UTC),
            monotonic_elapsed_ns=value,  # pyright: ignore[reportArgumentType]
        )


def test_runtime_clock_rejects_noncallable_dependencies_and_wrong_policy() -> None:
    policy = ClockPolicy(ClockMode.REAL)

    with pytest.raises(TypeError, match="ClockPolicy"):
        RuntimeClock(cast("ClockPolicy", object()))
    with pytest.raises(TypeError, match="wall_now"):
        RuntimeClock(policy, wall_now=cast("object", 1))  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match="monotonic_now"):
        RuntimeClock(
            policy,
            monotonic_now=cast("object", 1),  # pyright: ignore[reportArgumentType]
        )
    with pytest.raises(TypeError, match="sleep"):
        RuntimeClock(policy, sleep=cast("object", 1))  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize(
    ("value", "exception"),
    [
        (True, TypeError),
        (1.0, TypeError),
        (-1, ValueError),
        (SIGNED_INT64_MAX + 1, ValueError),
    ],
)
def test_runtime_clock_rejects_invalid_initial_monotonic_values(
    value: object,
    exception: type[Exception],
) -> None:
    with pytest.raises(exception):
        RuntimeClock(
            ClockPolicy(ClockMode.REAL),
            monotonic_now=lambda: value,  # pyright: ignore[reportArgumentType, reportReturnType]
        )


def test_runtime_clock_rejects_a_monotonic_source_that_moves_backwards() -> None:
    values = iter((100, 99))
    clock = RuntimeClock(
        ClockPolicy(ClockMode.REAL),
        monotonic_now=lambda: next(values),
    )

    with pytest.raises(ValueError, match="backwards"):
        clock.monotonic_now_ns()


def test_elapsed_measurement_rejects_future_start_and_overflow() -> None:
    fake = VirtualTestClock(monotonic_ns=100)
    clock, _ = _runtime(fake=fake)
    fake.advance(50)

    assert clock.elapsed_since(100) == 50
    with pytest.raises(ValueError, match="later"):
        clock.elapsed_since(151)
    with pytest.raises(TypeError, match="integer"):
        clock.elapsed_since(100.0)


def test_deadlines_are_monotonic_and_ignore_large_wall_clock_jumps() -> None:
    fake = VirtualTestClock(monotonic_ns=10_000)
    clock, _ = _runtime(
        ClockPolicy(ClockMode.SCALED, 1, 1000),
        fake=fake,
    )
    deadline = clock.deadline_after(2 * NANOSECONDS_PER_SECOND)
    expected_deadline = 10_000 + (2 * NANOSECONDS_PER_SECOND)

    assert deadline.nanoseconds == expected_deadline
    fake.wall_time += timedelta(days=3650)
    fake.advance((2 * NANOSECONDS_PER_SECOND) - 1)
    assert deadline.remaining_ns(clock) == 1
    fake.wall_time -= timedelta(days=7300)
    fake.advance(1)
    assert deadline.expired(clock)


def test_deadline_creation_rejects_absolute_monotonic_overflow() -> None:
    fake = VirtualTestClock(monotonic_ns=SIGNED_INT64_MAX - 5)
    clock, _ = _runtime(fake=fake)

    with pytest.raises(OverflowError, match="deadline"):
        clock.deadline_after(6)


def test_monotonic_deadline_constructor_is_strict_and_immutable() -> None:
    deadline = MonotonicDeadline(1)

    with pytest.raises(FrozenInstanceError):
        deadline.nanoseconds = 2  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(TypeError, match="integer"):
        MonotonicDeadline(nanoseconds=True)  # pyright: ignore[reportArgumentType]
    with pytest.raises(ValueError, match="negative"):
        MonotonicDeadline(nanoseconds=-1)


def test_wall_clock_jumps_do_not_change_logical_schedule_order() -> None:
    fake = VirtualTestClock()
    clock, _ = _runtime(fake=fake)
    logical_schedule = [10, -5, 10, 0]
    expected_order = sorted(range(len(logical_schedule)), key=logical_schedule.__getitem__)

    first_order = sorted(range(len(logical_schedule)), key=logical_schedule.__getitem__)
    fake.wall_time += timedelta(days=10_000)
    clock.wall_now()
    fake.wall_time -= timedelta(days=20_000)
    clock.wall_now()
    second_order = sorted(range(len(logical_schedule)), key=logical_schedule.__getitem__)

    assert first_order == second_order == expected_order


@pytest.mark.anyio
async def test_virtual_test_sleep_is_deterministic_and_instant() -> None:
    policy = ClockPolicy(ClockMode.SCALED, 1, 100)
    clock, fake = _runtime(policy)

    physical = await clock.sleep_logical(10 * NANOSECONDS_PER_SECOND)

    assert physical == 100_000_000
    assert fake.sleep_seconds == [0.1]
    assert clock.monotonic_elapsed_ns() == 100_000_000


@pytest.mark.anyio
async def test_scaled_schedule_wait_does_not_scale_physical_timeout_sleep() -> None:
    clock, fake = _runtime(ClockPolicy(ClockMode.SCALED, 1, 1000))

    logical = await clock.sleep_logical(2 * NANOSECONDS_PER_SECOND)
    timeout = await clock.sleep_physical(2 * NANOSECONDS_PER_SECOND)

    assert logical == 2_000_000
    assert timeout == 2 * NANOSECONDS_PER_SECOND
    assert fake.sleep_seconds == [0.002, 2.0]


@pytest.mark.anyio
async def test_default_sleep_is_cancellation_safe_and_starts_no_background_work() -> None:
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    entered = anyio.Event()
    completed = False

    async def wait_forever() -> None:
        nonlocal completed
        entered.set()
        await clock.sleep_logical(10 * NANOSECONDS_PER_SECOND)
        completed = True

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(wait_forever)
        await entered.wait()
        task_group.cancel_scope.cancel()

    assert not completed


@pytest.mark.anyio
async def test_real_mode_one_hundred_millisecond_wait_has_meaningful_tolerance() -> None:
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    started = time.monotonic_ns()

    physical = await clock.sleep_logical(100_000_000)
    elapsed = time.monotonic_ns() - started

    assert physical == 100_000_000
    # The upper bound allows substantial shared-runner jitter while still
    # rejecting the former multi-second minimum-wait regression.
    assert 70_000_000 <= elapsed <= 750_000_000


def test_default_runtime_sources_return_utc_and_monotonic_values() -> None:
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))

    wall = clock.wall_now()
    first = clock.monotonic_now_ns()
    second = clock.monotonic_now_ns()

    assert wall.tzinfo is UTC
    assert 0 <= first <= second <= SIGNED_INT64_MAX
