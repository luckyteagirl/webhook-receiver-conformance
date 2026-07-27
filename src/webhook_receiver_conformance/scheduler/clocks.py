"""Strict wall, monotonic, and logical clock-domain primitives."""
# ruff: noqa: D105, D107, INP001

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from fractions import Fraction
from typing import Final

import anyio

from webhook_receiver_conformance.config.models import (
    RealClockConfig,
    ScaledClockConfig,
)

NANOSECONDS_PER_SECOND: Final = 1_000_000_000
SIGNED_INT64_MIN: Final = -(1 << 63)
SIGNED_INT64_MAX: Final = (1 << 63) - 1
MINIMUM_SCALE: Final = Fraction(1, 1000)
MAXIMUM_SCALE: Final = Fraction(100)
_MAX_SCALE_COMPONENT: Final = 10**32

type WallNow = Callable[[], datetime]
type MonotonicNow = Callable[[], int]
type Sleep = Callable[[float], Awaitable[None]]


class ClockMode(StrEnum):
    """The two clock modes supported for external receiver execution."""

    REAL = "real"
    SCALED = "scaled"


@dataclass(frozen=True, slots=True)
class ClockPolicy:
    """Immutable conversion from logical waits to physical monotonic waits."""

    mode: ClockMode
    scale_numerator: int = 1
    scale_denominator: int = 1
    minimum_physical_wait_ns: int = 0

    def __post_init__(self) -> None:
        if type(self.mode) is not ClockMode:
            message = "mode must be a ClockMode member"
            raise TypeError(message)
        numerator = _positive_integer(
            self.scale_numerator,
            field_name="scale_numerator",
            maximum=_MAX_SCALE_COMPONENT,
        )
        denominator = _positive_integer(
            self.scale_denominator,
            field_name="scale_denominator",
            maximum=_MAX_SCALE_COMPONENT,
        )
        minimum_wait = _nonnegative_int64(
            self.minimum_physical_wait_ns,
            field_name="minimum_physical_wait_ns",
        )
        scale = Fraction(numerator, denominator)
        if self.mode is ClockMode.REAL and scale != 1:
            message = "real clock mode requires an exact scale of one"
            raise ValueError(message)
        if self.mode is ClockMode.SCALED and not MINIMUM_SCALE <= scale <= MAXIMUM_SCALE:
            message = "scaled clock mode requires a scale between 0.001 and 100"
            raise ValueError(message)
        if self.mode is ClockMode.REAL:
            minimum_wait = 0
        object.__setattr__(self, "scale_numerator", scale.numerator)
        object.__setattr__(self, "scale_denominator", scale.denominator)
        object.__setattr__(self, "minimum_physical_wait_ns", minimum_wait)

    @classmethod
    def from_config(cls, config: RealClockConfig | ScaledClockConfig) -> ClockPolicy:
        """Create a clock policy from the closed project configuration union."""
        if type(config) is RealClockConfig:
            return cls(
                mode=ClockMode.REAL,
                minimum_physical_wait_ns=_configured_minimum_wait(config),
            )
        if type(config) is ScaledClockConfig:
            scale = config.scale.fraction
            return cls(
                mode=ClockMode.SCALED,
                scale_numerator=scale.numerator,
                scale_denominator=scale.denominator,
                minimum_physical_wait_ns=_configured_minimum_wait(config),
            )
        message = "clock config must select real or scaled mode"
        raise TypeError(message)

    @property
    def scale(self) -> Fraction:
        """Return the exact logical-to-physical schedule scale."""
        return Fraction(self.scale_numerator, self.scale_denominator)

    def physical_wait_ns(self, logical_wait_ns: object) -> int:
        """Map a nonnegative logical wait to an exact physical wait."""
        logical = validate_logical_nanoseconds(logical_wait_ns)
        if logical < 0:
            message = "logical wait cannot be negative"
            raise ValueError(message)
        if logical == 0:
            return 0
        scaled = _ceil_fraction(logical, self.scale_numerator, self.scale_denominator)
        physical = (
            max(scaled, self.minimum_physical_wait_ns) if self.mode is ClockMode.SCALED else scaled
        )
        return _nonnegative_int64(physical, field_name="physical wait")

    def physical_timeout_ns(self, timeout_ns: object) -> int:
        """Return an unscaled physical timeout for HTTP and observer use."""
        return _nonnegative_int64(timeout_ns, field_name="physical timeout")


@dataclass(frozen=True, slots=True)
class MonotonicDeadline:
    """One absolute process-local monotonic deadline."""

    nanoseconds: int

    def __post_init__(self) -> None:
        _nonnegative_int64(self.nanoseconds, field_name="monotonic deadline")

    def remaining_ns(self, clock: RuntimeClock) -> int:
        """Return the nonnegative physical time remaining."""
        return max(0, self.nanoseconds - clock.monotonic_now_ns())

    def expired(self, clock: RuntimeClock) -> bool:
        """Return whether the process-local monotonic deadline elapsed."""
        return clock.monotonic_now_ns() >= self.nanoseconds


@dataclass(frozen=True, slots=True)
class TransitionTimestamp:
    """Wall audit time plus optional live execution-relative monotonic time."""

    wall_time: datetime
    monotonic_elapsed_ns: int | None

    def __post_init__(self) -> None:
        wall_time = validate_utc_wall_time(self.wall_time)
        if self.monotonic_elapsed_ns is not None:
            _nonnegative_int64(
                self.monotonic_elapsed_ns,
                field_name="monotonic_elapsed_ns",
            )
        object.__setattr__(self, "wall_time", wall_time)

    @classmethod
    def historical(cls, wall_time: datetime) -> TransitionTimestamp:
        """Represent imported history with explicitly unavailable monotonic time."""
        return cls(wall_time=wall_time, monotonic_elapsed_ns=None)

    @property
    def is_live(self) -> bool:
        """Return whether live execution-relative monotonic evidence is present."""
        return self.monotonic_elapsed_ns is not None


class RuntimeClock:
    """Injected runtime clock that keeps wall and monotonic domains separate."""

    __slots__ = (
        "_last_monotonic_ns",
        "_monotonic_now",
        "_origin_monotonic_ns",
        "_policy",
        "_sleep",
        "_wall_now",
    )

    def __init__(
        self,
        policy: ClockPolicy,
        *,
        wall_now: WallNow | None = None,
        monotonic_now: MonotonicNow | None = None,
        sleep: Sleep | None = None,
    ) -> None:
        if type(policy) is not ClockPolicy:
            message = "policy must be a ClockPolicy"
            raise TypeError(message)
        self._policy = policy
        self._wall_now = (
            _system_wall_now
            if wall_now is None
            else _require_callable(
                wall_now,
                field_name="wall_now",
            )
        )
        self._monotonic_now = (
            time.monotonic_ns
            if monotonic_now is None
            else _require_callable(monotonic_now, field_name="monotonic_now")
        )
        self._sleep = (
            _anyio_sleep
            if sleep is None
            else _require_callable(
                sleep,
                field_name="sleep",
            )
        )
        origin = _nonnegative_int64(
            self._monotonic_now(),
            field_name="monotonic clock value",
        )
        self._origin_monotonic_ns = origin
        self._last_monotonic_ns = origin

    @classmethod
    def from_config(
        cls,
        config: RealClockConfig | ScaledClockConfig,
        *,
        wall_now: WallNow | None = None,
        monotonic_now: MonotonicNow | None = None,
        sleep: Sleep | None = None,
    ) -> RuntimeClock:
        """Create a runtime clock from a validated external-run clock config."""
        return cls(
            ClockPolicy.from_config(config),
            wall_now=wall_now,
            monotonic_now=monotonic_now,
            sleep=sleep,
        )

    @property
    def policy(self) -> ClockPolicy:
        """Return the immutable schedule conversion policy."""
        return self._policy

    def wall_now(self) -> datetime:
        """Read a timezone-aware UTC timestamp for audit evidence only."""
        return validate_utc_wall_time(self._wall_now())

    def monotonic_now_ns(self) -> int:
        """Read and validate the process-local monotonic clock."""
        current = _nonnegative_int64(
            self._monotonic_now(),
            field_name="monotonic clock value",
        )
        if current < self._last_monotonic_ns:
            message = "monotonic clock moved backwards"
            raise ValueError(message)
        self._last_monotonic_ns = current
        return current

    def monotonic_elapsed_ns(self) -> int:
        """Return signed-int64 nanoseconds elapsed since this clock was created."""
        elapsed = self.monotonic_now_ns() - self._origin_monotonic_ns
        return _nonnegative_int64(elapsed, field_name="monotonic elapsed time")

    def transition_timestamp(self) -> TransitionTimestamp:
        """Capture the two timestamp fields required for a live transition."""
        return TransitionTimestamp(
            wall_time=self.wall_now(),
            monotonic_elapsed_ns=self.monotonic_elapsed_ns(),
        )

    def deadline_after(self, timeout_ns: object) -> MonotonicDeadline:
        """Create an absolute deadline from an unscaled physical timeout."""
        timeout = self._policy.physical_timeout_ns(timeout_ns)
        now = self.monotonic_now_ns()
        if timeout > SIGNED_INT64_MAX - now:
            message = "monotonic deadline exceeds signed 64-bit nanoseconds"
            raise OverflowError(message)
        return MonotonicDeadline(now + timeout)

    def elapsed_since(self, started_ns: object) -> int:
        """Measure a nonnegative monotonic duration from a prior reading."""
        started = _nonnegative_int64(started_ns, field_name="monotonic start")
        current = self.monotonic_now_ns()
        if started > current:
            message = "monotonic start is later than the current clock value"
            raise ValueError(message)
        return current - started

    async def sleep_logical(self, logical_wait_ns: object) -> int:
        """Sleep for one real/scaled schedule wait and return its physical value."""
        physical = self._policy.physical_wait_ns(logical_wait_ns)
        await self._sleep(_seconds(physical))
        return physical

    async def sleep_physical(self, timeout_ns: object) -> int:
        """Sleep for an unscaled physical duration and return its nanoseconds."""
        physical = self._policy.physical_timeout_ns(timeout_ns)
        await self._sleep(_seconds(physical))
        return physical


def validate_logical_nanoseconds(value: object) -> int:
    """Validate one signed-int64 logical time or duration value."""
    return _signed_int64(value, field_name="logical nanoseconds")


def add_logical_nanoseconds(left: object, right: object) -> int:
    """Add two logical values and reject signed-int64 overflow."""
    first = validate_logical_nanoseconds(left)
    second = validate_logical_nanoseconds(right)
    total = first + second
    if not SIGNED_INT64_MIN <= total <= SIGNED_INT64_MAX:
        message = "logical nanosecond addition exceeds signed 64-bit range"
        raise OverflowError(message)
    return total


def validate_utc_wall_time(value: object) -> datetime:
    """Validate and normalize one timezone-aware UTC wall timestamp."""
    if type(value) is not datetime:
        message = "wall time must be a datetime"
        raise TypeError(message)
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None:
        message = "wall time must be timezone-aware UTC"
        raise ValueError(message)
    if offset.total_seconds() != 0:
        message = "wall time must use UTC"
        raise ValueError(message)
    return value.astimezone(UTC)


def _configured_minimum_wait(config: RealClockConfig | ScaledClockConfig) -> int:
    minimum = config.minimum_physical_wait
    return 0 if minimum is None else minimum.nanoseconds


def _ceil_fraction(value: int, numerator: int, denominator: int) -> int:
    product = value * numerator
    return (product + denominator - 1) // denominator


def _seconds(nanoseconds: int) -> float:
    return nanoseconds / NANOSECONDS_PER_SECOND


async def _anyio_sleep(seconds: float) -> None:
    await anyio.sleep(seconds)


def _system_wall_now() -> datetime:
    return datetime.now(UTC)


def _require_callable[T](value: T, *, field_name: str) -> T:
    if not callable(value):
        message = f"{field_name} must be callable"
        raise TypeError(message)
    return value


def _signed_int64(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        message = f"{field_name} must be an integer"
        raise TypeError(message)
    if not SIGNED_INT64_MIN <= value <= SIGNED_INT64_MAX:
        message = f"{field_name} must fit signed 64-bit nanoseconds"
        raise ValueError(message)
    return value


def _nonnegative_int64(value: object, *, field_name: str) -> int:
    integer = _signed_int64(value, field_name=field_name)
    if integer < 0:
        message = f"{field_name} cannot be negative"
        raise ValueError(message)
    return integer


def _positive_integer(value: object, *, field_name: str, maximum: int) -> int:
    if type(value) is not int:
        message = f"{field_name} must be an integer"
        raise TypeError(message)
    if not 1 <= value <= maximum:
        message = f"{field_name} must be between 1 and {maximum}"
        raise ValueError(message)
    return value
