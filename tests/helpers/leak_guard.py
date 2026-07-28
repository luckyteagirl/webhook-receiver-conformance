"""Session-level process and listening-socket leak detection for pytest."""
# ruff: noqa: EM101, INP001, TRY003

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Final

import psutil

_CREATE_TIME_RESOLUTION: Final = 1_000_000
_DEFAULT_SETTLE_SECONDS: Final = 0.75
_POLL_SECONDS: Final = 0.05
_TERMINATE_SECONDS: Final = 0.5


class LeakInspectionError(RuntimeError):
    """The pytest process could not be inspected reliably."""


@dataclass(frozen=True, order=True, slots=True)
class ProcessIdentity:
    """PID plus creation time, which remains safe when an OS reuses a PID."""

    pid: int
    created_at_microseconds: int


@dataclass(frozen=True, order=True, slots=True)
class ProcessRecord:
    """Privacy-safe evidence for one child process."""

    identity: ProcessIdentity
    name: str


@dataclass(frozen=True, order=True, slots=True)
class ListenerRecord:
    """One TCP listening address owned by pytest or one of its children."""

    owner: ProcessIdentity
    family: int
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    """A point-in-time inventory limited to the pytest process tree."""

    root: ProcessIdentity
    children: frozenset[ProcessRecord]
    listeners: frozenset[ListenerRecord]


@dataclass(frozen=True, slots=True)
class LeakReport:
    """Resources created after the baseline that remain after test teardown."""

    processes: tuple[ProcessRecord, ...]
    listeners: tuple[ListenerRecord, ...]

    @property
    def found(self) -> bool:
        """Return whether any test-owned resource leaked."""
        return bool(self.processes or self.listeners)

    def lines(self) -> tuple[str, ...]:
        """Render bounded evidence without command lines or test data."""
        process_lines = tuple(
            f"child process pid={record.identity.pid} name={record.name!r}"
            for record in self.processes
        )
        listener_lines = tuple(
            "listening socket "
            f"pid={record.owner.pid} address={_render_address(record.host, record.port)}"
            for record in self.listeners
        )
        return (*process_lines, *listener_lines)


class ProcessTreeInspector:
    """Inspect only pytest and its descendants, never unrelated host processes."""

    __slots__ = ("_root",)

    def __init__(self, root_pid: int | None = None) -> None:
        """Select the process-tree root, defaulting to pytest itself."""
        self._root = psutil.Process(root_pid)

    def capture(self) -> ResourceSnapshot:
        """Capture live descendants and their TCP listeners."""
        root_record = self._record(self._root, required=True)
        if root_record is None:  # pragma: no cover - required=True raises
            raise LeakInspectionError("pytest process disappeared during leak inspection")

        try:
            child_processes = self._root.children(recursive=True)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess) as error:
            raise LeakInspectionError("pytest child processes could not be inspected") from error

        child_records: set[ProcessRecord] = set()
        inspected_processes: list[tuple[psutil.Process, ProcessRecord]] = [
            (self._root, root_record)
        ]
        for process in child_processes:
            record = self._record(process, required=False)
            if record is None:
                continue
            child_records.add(record)
            inspected_processes.append((process, record))

        listeners: set[ListenerRecord] = set()
        for process, record in inspected_processes:
            listeners.update(
                self._listeners(
                    process,
                    owner=record.identity,
                    required=record.identity == root_record.identity,
                )
            )
        return ResourceSnapshot(
            root=root_record.identity,
            children=frozenset(child_records),
            listeners=frozenset(listeners),
        )

    def terminate(self, records: tuple[ProcessRecord, ...]) -> None:
        """Best-effort cleanup after evidence for leaked children is retained."""
        processes: list[psutil.Process] = []
        for record in records:
            try:
                process = psutil.Process(record.identity.pid)
                current = self._record(process, required=False)
                if current is None or current.identity != record.identity:
                    continue
                process.terminate()
                processes.append(process)
            except (
                LeakInspectionError,
                psutil.AccessDenied,
                psutil.NoSuchProcess,
                psutil.ZombieProcess,
            ):
                continue

        _, alive = psutil.wait_procs(processes, timeout=_TERMINATE_SECONDS)
        for process in alive:
            try:
                process.kill()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        if alive:
            psutil.wait_procs(alive, timeout=_TERMINATE_SECONDS)

    @staticmethod
    def _record(process: psutil.Process, *, required: bool) -> ProcessRecord | None:
        try:
            created_at = round(process.create_time() * _CREATE_TIME_RESOLUTION)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            if required:
                raise LeakInspectionError(
                    "pytest process disappeared during leak inspection"
                ) from None
            return None
        except psutil.AccessDenied:
            raise LeakInspectionError("process identity could not be inspected") from None
        try:
            name = process.name()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            name = "<unavailable>"
        except psutil.NoSuchProcess:
            if required:
                raise LeakInspectionError(
                    "pytest process disappeared during leak inspection"
                ) from None
            return None
        return ProcessRecord(
            identity=ProcessIdentity(
                pid=process.pid,
                created_at_microseconds=created_at,
            ),
            name=name,
        )

    @staticmethod
    def _listeners(
        process: psutil.Process,
        *,
        owner: ProcessIdentity,
        required: bool,
    ) -> set[ListenerRecord]:
        try:
            connections = process.net_connections(kind="inet")
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return set()
        except psutil.AccessDenied:
            if required:
                raise LeakInspectionError(
                    "pytest listening sockets could not be inspected"
                ) from None
            return set()

        listeners: set[ListenerRecord] = set()
        for connection in connections:
            if connection.type != socket.SOCK_STREAM or connection.status != psutil.CONN_LISTEN:
                continue
            listeners.add(
                ListenerRecord(
                    owner=owner,
                    family=int(connection.family),
                    host=connection.laddr.ip,
                    port=connection.laddr.port,
                )
            )
        return listeners


class SessionLeakGuard:
    """Compare the final pytest process tree with its explicit baseline allowlist."""

    __slots__ = ("_baseline", "_inspector")

    def __init__(
        self,
        inspector: ProcessTreeInspector,
        baseline: ResourceSnapshot,
    ) -> None:
        """Bind one inspector to its exact before-suite snapshot."""
        self._inspector = inspector
        self._baseline = baseline

    @classmethod
    def start(cls, inspector: ProcessTreeInspector | None = None) -> SessionLeakGuard:
        """Capture the session baseline before tests can create resources."""
        selected = ProcessTreeInspector() if inspector is None else inspector
        return cls(selected, selected.capture())

    def finish(self, *, settle_seconds: float = _DEFAULT_SETTLE_SECONDS) -> LeakReport:
        """Return persistent leaks after a short bounded teardown grace period."""
        if settle_seconds < 0:
            raise ValueError("settle_seconds must be nonnegative")
        deadline = time.monotonic() + settle_seconds
        while True:
            report = compare_snapshots(self._baseline, self._inspector.capture())
            if not report.found or time.monotonic() >= deadline:
                return report
            time.sleep(min(_POLL_SECONDS, max(0.0, deadline - time.monotonic())))

    def cleanup(self, report: LeakReport) -> None:
        """Stop only exact leaked child identities after reporting them."""
        self._inspector.terminate(report.processes)


def compare_snapshots(baseline: ResourceSnapshot, final: ResourceSnapshot) -> LeakReport:
    """Return final resources not covered by the exact session baseline."""
    if baseline.root != final.root:
        raise LeakInspectionError("pytest process identity changed during the test session")

    allowed_processes = {record.identity for record in baseline.children}
    leaked_processes = tuple(
        sorted(
            (record for record in final.children if record.identity not in allowed_processes),
            key=lambda record: record.identity,
        )
    )
    leaked_process_identities = {record.identity for record in leaked_processes}
    baseline_listeners = baseline.listeners
    leaked_listeners = tuple(
        sorted(
            (
                listener
                for listener in final.listeners
                if (listener.owner == final.root and listener not in baseline_listeners)
                or listener.owner in leaked_process_identities
            ),
            key=lambda listener: (
                listener.owner,
                listener.family,
                listener.host,
                listener.port,
            ),
        )
    )
    return LeakReport(
        processes=leaked_processes,
        listeners=leaked_listeners,
    )


def _render_address(host: str, port: int) -> str:
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{rendered_host}:{port}"
