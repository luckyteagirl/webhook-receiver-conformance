"""Ownership, takeover, and hostile-path tests for TASK-0204."""
# ruff: noqa: D101, D102, D107, INP001, PLR0913, S603

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.journal.run_lock import (
    FilesystemKind,
    ProcessProbe,
    ProcessState,
    RunLockActiveError,
    RunLockEpochError,
    RunLockError,
    RunLockMetadata,
    RunLockMetadataError,
    RunLockOwnerUnverifiableError,
    RunLockTakeoverRequiredError,
    TakeoverReason,
    UnsupportedRunFilesystemError,
    acquire_run_lock,
    read_run_lock,
)

RUN_ID = "12345678-1234-4234-8234-123456789abc"
OTHER_RUN_ID = "abcdefab-cdef-4abc-8def-abcdefabcdef"
WALL_TIME = datetime(2026, 7, 27, 12, 34, 56, 123456, tzinfo=UTC)
WALL_TIMESTAMP = "2026-07-27T12:34:56.123456Z"
INITIAL_OWNER_EPOCH = 7


@dataclass(frozen=True, slots=True)
class StaticFilesystemProbe:
    kind: FilesystemKind

    def classify(self, path: Path) -> FilesystemKind:
        assert path.is_absolute()
        return self.kind


class StaticProcessInspector:
    def __init__(
        self,
        *,
        current_fingerprint: str = "current-start",
        probes: dict[int, ProcessProbe] | None = None,
    ) -> None:
        self.current_fingerprint = current_fingerprint
        self.probes = {} if probes is None else probes
        self.inspected: list[int] = []

    def current_process_fingerprint(self) -> str:
        return self.current_fingerprint

    def inspect(self, pid: int) -> ProcessProbe:
        self.inspected.append(pid)
        return self.probes.get(pid, ProcessProbe(ProcessState.ABSENT, None))


def _clock() -> datetime:
    return WALL_TIME


def _canonical_lock_bytes(metadata: RunLockMetadata) -> bytes:
    return (
        json.dumps(
            asdict(metadata),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _write_stale_lock(
    directory: Path,
    *,
    run_id: str = RUN_ID,
    pid: int = 424_242,
    fingerprint: str = "previous-start",
    hostname: str | None = None,
    owner_epoch: int = 4,
) -> RunLockMetadata:
    metadata = RunLockMetadata(
        run_id=run_id,
        pid=pid,
        process_start_fingerprint=fingerprint,
        hostname=socket.gethostname().rstrip(".").casefold() if hostname is None else hostname,
        owner_epoch=owner_epoch,
        wall_timestamp=WALL_TIMESTAMP,
    )
    (directory / "run.lock").write_bytes(_canonical_lock_bytes(metadata))
    return metadata


def test_acquire_persists_canonical_metadata_and_release_removes_lock(
    tmp_path: Path,
) -> None:
    inspector = StaticProcessInspector()

    lock = acquire_run_lock(
        tmp_path,
        run_id=RUN_ID,
        owner_epoch=INITIAL_OWNER_EPOCH,
        process_inspector=inspector,
        clock=_clock,
    )

    assert read_run_lock(tmp_path) == lock.metadata
    assert lock.metadata.wall_timestamp == WALL_TIMESTAMP
    assert lock.metadata.owner_epoch == INITIAL_OWNER_EPOCH
    assert lock.metadata.process_start_fingerprint == "current-start"
    assert lock.takeover_event is None
    assert not lock.closed

    lock.release()
    lock.release()
    assert lock.closed
    assert not (tmp_path / "run.lock").exists()


def test_context_manager_releases_lock(tmp_path: Path) -> None:
    with acquire_run_lock(
        tmp_path,
        run_id=RUN_ID,
        owner_epoch=0,
        process_inspector=StaticProcessInspector(),
    ) as lock:
        assert not lock.closed
        assert (tmp_path / "run.lock").is_file()

    assert lock.closed
    assert not (tmp_path / "run.lock").exists()


def test_live_guard_authorizes_only_its_exact_run_epoch(tmp_path: Path) -> None:
    lock = acquire_run_lock(
        tmp_path,
        run_id=RUN_ID,
        owner_epoch=INITIAL_OWNER_EPOCH,
        process_inspector=StaticProcessInspector(),
    )
    try:
        lock.require_owner(
            tmp_path.resolve(),
            run_id=RUN_ID,
            owner_epoch=INITIAL_OWNER_EPOCH,
        )
        with pytest.raises(RunLockEpochError):
            lock.require_owner(
                tmp_path.resolve(),
                run_id=OTHER_RUN_ID,
                owner_epoch=INITIAL_OWNER_EPOCH,
            )
        with pytest.raises(RunLockEpochError):
            lock.require_owner(
                tmp_path.resolve(),
                run_id=RUN_ID,
                owner_epoch=INITIAL_OWNER_EPOCH + 1,
            )
    finally:
        lock.release()

    with pytest.raises(RunLockError, match="released"):
        lock.require_owner(
            tmp_path.resolve(),
            run_id=RUN_ID,
            owner_epoch=INITIAL_OWNER_EPOCH,
        )


def test_operating_system_lock_blocks_even_explicit_takeover(tmp_path: Path) -> None:
    inspector = StaticProcessInspector()
    first = acquire_run_lock(
        tmp_path,
        run_id=RUN_ID,
        owner_epoch=0,
        process_inspector=inspector,
    )
    try:
        with pytest.raises(RunLockActiveError) as captured:
            acquire_run_lock(
                tmp_path,
                run_id=RUN_ID,
                owner_epoch=1,
                take_over=True,
                process_inspector=inspector,
            )
        assert captured.value.owner == first.metadata
        assert captured.value.category is ErrorCategory.JOURNAL_BUSY
    finally:
        first.release()


def test_detected_network_filesystem_fails_before_lock_creation(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedRunFilesystemError) as captured:
        acquire_run_lock(
            tmp_path,
            run_id=RUN_ID,
            owner_epoch=0,
            filesystem_probe=StaticFilesystemProbe(FilesystemKind.NETWORK),
            process_inspector=StaticProcessInspector(),
        )

    assert captured.value.category is ErrorCategory.UNSUPPORTED_CAPABILITY
    assert not (tmp_path / "run.lock").exists()
    assert not (tmp_path / "journal.sqlite3").exists()


def test_unknown_filesystem_is_allowed_when_platform_cannot_identify_it(
    tmp_path: Path,
) -> None:
    lock = acquire_run_lock(
        tmp_path,
        run_id=RUN_ID,
        owner_epoch=0,
        filesystem_probe=StaticFilesystemProbe(FilesystemKind.UNKNOWN),
        process_inspector=StaticProcessInspector(),
    )
    lock.release()


def test_dead_same_host_owner_requires_explicit_takeover(tmp_path: Path) -> None:
    previous = _write_stale_lock(tmp_path)
    inspector = StaticProcessInspector(
        probes={previous.pid: ProcessProbe(ProcessState.ABSENT, None)}
    )

    with pytest.raises(RunLockTakeoverRequiredError) as captured:
        acquire_run_lock(
            tmp_path,
            run_id=RUN_ID,
            owner_epoch=previous.owner_epoch + 1,
            process_inspector=inspector,
        )

    assert captured.value.owner == previous
    assert read_run_lock(tmp_path) == previous


def test_explicit_dead_owner_takeover_advances_epoch_and_returns_audit_event(
    tmp_path: Path,
) -> None:
    previous = _write_stale_lock(tmp_path)
    inspector = StaticProcessInspector(
        current_fingerprint="replacement-start",
        probes={previous.pid: ProcessProbe(ProcessState.ABSENT, None)},
    )

    lock = acquire_run_lock(
        tmp_path,
        run_id=RUN_ID,
        owner_epoch=previous.owner_epoch + 1,
        take_over=True,
        process_inspector=inspector,
        clock=_clock,
    )
    try:
        assert lock.takeover_event is not None
        assert lock.takeover_event.previous_owner == previous
        assert lock.takeover_event.new_owner == lock.metadata
        assert lock.takeover_event.reason is TakeoverReason.PROCESS_ABSENT
        assert read_run_lock(tmp_path) == lock.metadata
    finally:
        lock.release()


@pytest.mark.parametrize("owner_epoch", [4, 6, 99])
def test_takeover_requires_exactly_one_epoch_increment(
    tmp_path: Path,
    owner_epoch: int,
) -> None:
    previous = _write_stale_lock(tmp_path, owner_epoch=4)

    with pytest.raises(RunLockEpochError):
        acquire_run_lock(
            tmp_path,
            run_id=RUN_ID,
            owner_epoch=owner_epoch,
            take_over=True,
            process_inspector=StaticProcessInspector(),
        )

    assert read_run_lock(tmp_path) == previous


def test_pid_reuse_is_explicitly_audited_as_stale_identity(tmp_path: Path) -> None:
    previous = _write_stale_lock(tmp_path, fingerprint="old-process-start")
    inspector = StaticProcessInspector(
        probes={
            previous.pid: ProcessProbe(
                ProcessState.PRESENT,
                "reused-pid-process-start",
            )
        }
    )

    lock = acquire_run_lock(
        tmp_path,
        run_id=RUN_ID,
        owner_epoch=5,
        take_over=True,
        process_inspector=inspector,
    )
    try:
        assert lock.takeover_event is not None
        assert lock.takeover_event.reason is TakeoverReason.PID_REUSED
    finally:
        lock.release()


def test_matching_live_process_blocks_takeover_after_stale_handle(tmp_path: Path) -> None:
    previous = _write_stale_lock(tmp_path, fingerprint="still-running-start")
    inspector = StaticProcessInspector(
        probes={
            previous.pid: ProcessProbe(
                ProcessState.PRESENT,
                previous.process_start_fingerprint,
            )
        }
    )

    with pytest.raises(RunLockActiveError) as captured:
        acquire_run_lock(
            tmp_path,
            run_id=RUN_ID,
            owner_epoch=5,
            take_over=True,
            process_inspector=inspector,
        )

    assert captured.value.owner == previous


@pytest.mark.parametrize(
    ("hostname", "probe"),
    [
        ("another-host", ProcessProbe(ProcessState.ABSENT, None)),
        (
            socket.gethostname().rstrip(".").casefold(),
            ProcessProbe(ProcessState.UNVERIFIABLE, None),
        ),
    ],
)
def test_unverifiable_owner_is_never_taken_over(
    tmp_path: Path,
    hostname: str,
    probe: ProcessProbe,
) -> None:
    previous = _write_stale_lock(tmp_path, hostname=hostname)

    with pytest.raises(RunLockOwnerUnverifiableError) as captured:
        acquire_run_lock(
            tmp_path,
            run_id=RUN_ID,
            owner_epoch=5,
            take_over=True,
            process_inspector=StaticProcessInspector(probes={previous.pid: probe}),
        )

    assert captured.value.owner == previous


def test_lock_for_another_run_is_integrity_error(tmp_path: Path) -> None:
    previous = _write_stale_lock(tmp_path, run_id=OTHER_RUN_ID)

    with pytest.raises(RunLockMetadataError):
        acquire_run_lock(
            tmp_path,
            run_id=RUN_ID,
            owner_epoch=previous.owner_epoch + 1,
            take_over=True,
            process_inspector=StaticProcessInspector(),
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"{}\n",
        b'{"format_version":1,"format_version":1}\n',
        b"\xff",
        b"x" * 16_385,
    ],
)
def test_malformed_or_oversized_lock_metadata_fails_closed(
    tmp_path: Path,
    payload: bytes,
) -> None:
    (tmp_path / "run.lock").write_bytes(payload)

    with pytest.raises(RunLockMetadataError):
        acquire_run_lock(
            tmp_path,
            run_id=RUN_ID,
            owner_epoch=1,
            take_over=True,
            process_inspector=StaticProcessInspector(),
        )


def test_hard_linked_lock_metadata_fails_closed(tmp_path: Path) -> None:
    _write_stale_lock(tmp_path)
    alias = tmp_path / "run.lock.alias"
    try:
        os.link(tmp_path / "run.lock", alias)
    except OSError:
        pytest.skip("hard links are unavailable on this test filesystem")

    with pytest.raises(RunLockMetadataError):
        read_run_lock(tmp_path)


def test_nonregular_lock_path_fails_before_opening_it(tmp_path: Path) -> None:
    (tmp_path / "run.lock").mkdir()

    with pytest.raises(RunLockMetadataError, match="regular file"):
        acquire_run_lock(
            tmp_path,
            run_id=RUN_ID,
            owner_epoch=1,
            take_over=True,
            process_inspector=StaticProcessInspector(),
        )


def test_symlink_run_directory_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable for this test account")

    with pytest.raises(RunLockMetadataError):
        acquire_run_lock(
            alias,
            run_id=RUN_ID,
            owner_epoch=0,
            process_inspector=StaticProcessInspector(),
        )


def test_relative_run_directory_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="absolute"):
        acquire_run_lock(
            Path(),
            run_id=RUN_ID,
            owner_epoch=0,
            process_inspector=StaticProcessInspector(),
        )


def test_real_crashed_process_lock_can_be_taken_over(tmp_path: Path) -> None:
    script = """
import os
import sys
from pathlib import Path
from webhook_receiver_conformance.journal.run_lock import acquire_run_lock

acquire_run_lock(
    Path(sys.argv[1]),
    run_id=sys.argv[2],
    owner_epoch=0,
)
os._exit(0)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, os.fspath(tmp_path), RUN_ID],
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    previous = read_run_lock(tmp_path)

    lock = acquire_run_lock(
        tmp_path,
        run_id=RUN_ID,
        owner_epoch=1,
        take_over=True,
    )
    try:
        assert lock.takeover_event is not None
        assert lock.takeover_event.previous_owner == previous
        assert lock.takeover_event.reason is TakeoverReason.PROCESS_ABSENT
    finally:
        lock.release()
