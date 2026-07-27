"""Structured interruption handling with bounded cooperative cleanup."""
# ruff: noqa: C901, D105, EM101, INP001, TRY003

from __future__ import annotations

import signal
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

import anyio

from webhook_receiver_conformance.errors import ExitCode, ResultCategory

if TYPE_CHECKING:
    from anyio.abc import TaskGroup

DEFAULT_CLEANUP_TIMEOUT_SECONDS: Final = 5.0
type AsyncOperation[T] = Callable[[], Awaitable[T]]
type InterruptWaiter = Callable[[], Awaitable[object]]
type CleanupCallback = Callable[[], Awaitable[None]]


class InterruptKind(StrEnum):
    """Closed interruption vocabulary consumed by the future run coordinator."""

    SIGINT = "sigint"
    REQUESTED = "requested"


@dataclass(frozen=True, slots=True)
class CancellationResult[T]:
    """One classified operation result with no fabricated interrupted value."""

    value: T | None
    interrupted: bool
    category: ResultCategory
    exit_code: ExitCode
    interrupt_kind: InterruptKind | None
    signal_number: int | None
    cleanup_completed: bool

    def __post_init__(self) -> None:
        if type(self.interrupted) is not bool:
            raise TypeError("interrupted must be a bool")
        if type(self.category) is not ResultCategory:
            raise TypeError("category must be a ResultCategory")
        if type(self.exit_code) is not ExitCode:
            raise TypeError("exit_code must be an ExitCode")
        if self.interrupt_kind is not None and type(self.interrupt_kind) is not InterruptKind:
            raise TypeError("interrupt_kind must be an InterruptKind or None")
        if self.signal_number is not None and type(self.signal_number) is not int:
            raise TypeError("signal_number must be an int or None")
        if type(self.cleanup_completed) is not bool:
            raise TypeError("cleanup_completed must be a bool")
        if self.interrupted:
            if (
                self.value is not None
                or self.category is not ResultCategory.CANCELLED
                or self.exit_code is not ExitCode.CANCELLED
                or self.interrupt_kind is None
            ):
                raise ValueError("interrupted results must be value-free cancellation results")
        elif (
            self.category is not ResultCategory.PASS
            or self.exit_code is not ExitCode.PASS
            or self.interrupt_kind is not None
            or self.signal_number is not None
        ):
            raise ValueError("completed results must use the pass result shape")


async def wait_for_sigint() -> int:
    """Wait for one process SIGINT without installing a persistent handler."""
    with anyio.open_signal_receiver(signal.SIGINT) as signals:
        async for received in signals:
            return int(received)
    raise RuntimeError("SIGINT receiver ended without a signal")


async def run_interruptibly[T](
    operation: AsyncOperation[T],
    interrupt_waiter: InterruptWaiter,
    *,
    interrupt_kind: InterruptKind = InterruptKind.REQUESTED,
    cleanup_callbacks: tuple[CleanupCallback, ...] = (),
    cleanup_timeout_seconds: float = DEFAULT_CLEANUP_TIMEOUT_SECONDS,
) -> CancellationResult[T]:
    """Race one operation against interruption and await structured cleanup."""
    if not callable(operation):
        raise TypeError("operation must be callable")
    if not callable(interrupt_waiter):
        raise TypeError("interrupt_waiter must be callable")
    if type(interrupt_kind) is not InterruptKind:
        raise TypeError("interrupt_kind must be an InterruptKind")
    if type(cleanup_callbacks) is not tuple or any(
        not callable(callback) for callback in cleanup_callbacks
    ):
        raise TypeError("cleanup_callbacks must be a tuple of callables")
    if (
        type(cleanup_timeout_seconds) is not float
        or not 0 < cleanup_timeout_seconds <= DEFAULT_CLEANUP_TIMEOUT_SECONDS
    ):
        raise ValueError("cleanup timeout must be a positive float no greater than 5.0")

    operation_done = anyio.Event()
    operation_value: list[T] = []
    interrupted = False
    signal_number: int | None = None

    async def execute_operation() -> None:
        try:
            operation_value.append(await operation())
        finally:
            operation_done.set()

    async def observe_interrupt(task_group: TaskGroup) -> None:
        nonlocal interrupted, signal_number
        received = await interrupt_waiter()
        if operation_done.is_set():
            return
        interrupted = True
        signal_number = int(received) if type(received) is int else None
        task_group.cancel_scope.cancel()

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(execute_operation)
        task_group.start_soon(observe_interrupt, task_group)
        await operation_done.wait()
        task_group.cancel_scope.cancel()

    cleanup_completed = await _run_cleanup(
        cleanup_callbacks,
        timeout_seconds=cleanup_timeout_seconds,
    )
    if interrupted:
        return CancellationResult(
            value=None,
            interrupted=True,
            category=ResultCategory.CANCELLED,
            exit_code=ExitCode.CANCELLED,
            interrupt_kind=interrupt_kind,
            signal_number=signal_number,
            cleanup_completed=cleanup_completed,
        )
    if len(operation_value) != 1:
        raise RuntimeError("completed operation did not produce exactly one value")
    return CancellationResult(
        value=operation_value[0],
        interrupted=False,
        category=ResultCategory.PASS,
        exit_code=ExitCode.PASS,
        interrupt_kind=None,
        signal_number=None,
        cleanup_completed=cleanup_completed,
    )


async def _run_cleanup(
    callbacks: tuple[CleanupCallback, ...],
    *,
    timeout_seconds: float,
) -> bool:
    if not callbacks:
        return True
    with anyio.move_on_after(timeout_seconds, shield=True) as scope:
        for callback in callbacks:
            await callback()
    return not scope.cancel_called
