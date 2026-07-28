"""Cross-platform, process-aware ownership lock for one local run directory."""
# ruff: noqa: INP001, PLC0415, TRY301

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, Self, cast

if TYPE_CHECKING:
    from types import TracebackType

from webhook_receiver_conformance.domain.identifiers import validate_run_id
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.types import DiagnosticCode

LOCK_FILENAME = "run.lock"
LOCK_FORMAT_VERSION = 1
MAX_LOCK_BYTES = 16_384
MAX_HOSTNAME_BYTES = 255
MAX_PROCESS_FINGERPRINT_BYTES = 512
MAX_OWNER_EPOCH = (2**63) - 1
MAX_PID = (2**32) - 1
_WINDOWS_DRIVE_REMOTE = 4
_WINDOWS_LOCK_RETRIES = 20
_WINDOWS_LOCK_RETRY_SECONDS = 0.001
_MOUNTINFO_LIMIT_BYTES = 1_048_576
_MOUNTINFO_MIN_FIELDS = 5
_PLATFORM_OUTPUT_LIMIT_BYTES = 256
_PROC_STAT_LIMIT_BYTES = 4096
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_NETWORK_FILESYSTEM_TYPES = frozenset(
    {
        "9p",
        "afs",
        "ceph",
        "cifs",
        "coda",
        "davfs",
        "davfs2",
        "fuse.ceph",
        "fuse.glusterfs",
        "fuse.rclone",
        "fuse.sshfs",
        "gfs",
        "gfs2",
        "glusterfs",
        "lustre",
        "ncp",
        "ncpfs",
        "nfs",
        "nfs4",
        "ocfs2",
        "smb",
        "smb2",
        "smb3",
        "smbfs",
        "sshfs",
    }
)
_LOCK_KEYS = frozenset(
    {
        "format_version",
        "hostname",
        "owner_epoch",
        "pid",
        "process_start_fingerprint",
        "run_id",
        "wall_timestamp",
    }
)

type UtcClock = Callable[[], datetime]


class RunLockError(RuntimeError):
    """A classified failure at the run-directory ownership boundary."""

    category: ErrorCategory = ErrorCategory.INTEGRITY_ERROR
    code: DiagnosticCode = DiagnosticCode("RUN_LOCK_ERROR")


class UnsupportedRunFilesystemError(RunLockError):
    """The configured run directory is on an identifiable network filesystem."""

    category = ErrorCategory.UNSUPPORTED_CAPABILITY
    code = DiagnosticCode("RUN_FILESYSTEM_UNSUPPORTED")


class RunLockActiveError(RunLockError):
    """A live or operating-system-locked owner still controls the run."""

    category = ErrorCategory.JOURNAL_BUSY
    code = DiagnosticCode("RUN_LOCK_ACTIVE")

    def __init__(self, message: str, *, owner: RunLockMetadata | None) -> None:
        """Retain safe owner metadata when it was readable."""
        super().__init__(message)
        self.owner = owner


class RunLockTakeoverRequiredError(RunLockError):
    """A stale lock was found but explicit takeover was not requested."""

    category = ErrorCategory.JOURNAL_BUSY
    code = DiagnosticCode("RUN_LOCK_TAKEOVER_REQUIRED")

    def __init__(self, message: str, *, owner: RunLockMetadata) -> None:
        """Retain the verified stale owner for a recovery preview."""
        super().__init__(message)
        self.owner = owner


class RunLockOwnerUnverifiableError(RunLockError):
    """The recorded process cannot be safely proven absent on this host."""

    category = ErrorCategory.UNSUPPORTED_CAPABILITY
    code = DiagnosticCode("RUN_LOCK_OWNER_UNVERIFIABLE")

    def __init__(self, message: str, *, owner: RunLockMetadata) -> None:
        """Retain the owner whose absence could not be proven."""
        super().__init__(message)
        self.owner = owner


class RunLockMetadataError(RunLockError):
    """Existing run-lock metadata is malformed, aliased, or inconsistent."""

    code = DiagnosticCode("RUN_LOCK_METADATA_INVALID")


class RunLockEpochError(RunLockError):
    """A takeover did not advance the authoritative owner epoch exactly once."""

    category = ErrorCategory.ILLEGAL_TRANSITION
    code = DiagnosticCode("RUN_LOCK_EPOCH_INVALID")


class FilesystemKind(StrEnum):
    """Conservative local-filesystem classification."""

    LOCAL = "local"
    NETWORK = "network"
    UNKNOWN = "unknown"


class ProcessState(StrEnum):
    """Whether one process identity can be verified on the current host."""

    PRESENT = "present"
    ABSENT = "absent"
    UNVERIFIABLE = "unverifiable"


class TakeoverReason(StrEnum):
    """Safe, bounded reasons for replacing stale ownership metadata."""

    PROCESS_ABSENT = "process_absent"
    PID_REUSED = "pid_reused"


@dataclass(frozen=True, slots=True)
class RunLockMetadata:
    """Strict persisted owner identity for one run directory."""

    run_id: str
    pid: int
    process_start_fingerprint: str
    hostname: str
    owner_epoch: int
    wall_timestamp: str
    format_version: int = LOCK_FORMAT_VERSION

    def __post_init__(self) -> None:
        """Validate the exact bounded persisted lock format."""
        validate_run_id(self.run_id)
        _validate_positive_integer(self.pid, name="pid", maximum=MAX_PID)
        _validate_bounded_text(
            self.process_start_fingerprint,
            name="process_start_fingerprint",
            maximum_bytes=MAX_PROCESS_FINGERPRINT_BYTES,
        )
        _validate_bounded_text(
            self.hostname,
            name="hostname",
            maximum_bytes=MAX_HOSTNAME_BYTES,
        )
        if self.hostname != _normalize_hostname(self.hostname):
            message = "run-lock hostname must use its canonical local form"
            raise RunLockMetadataError(message)
        _validate_nonnegative_integer(
            self.owner_epoch,
            name="owner_epoch",
            maximum=MAX_OWNER_EPOCH,
        )
        _validate_wall_timestamp(self.wall_timestamp)
        if self.format_version != LOCK_FORMAT_VERSION:
            message = "run-lock format version is unsupported"
            raise RunLockMetadataError(message)


@dataclass(frozen=True, slots=True)
class ProcessProbe:
    """Detached process-liveness evidence."""

    state: ProcessState
    start_fingerprint: str | None

    def __post_init__(self) -> None:
        """Require fingerprint evidence exactly for present processes."""
        if self.state is ProcessState.PRESENT:
            if self.start_fingerprint is None:
                message = "a present process requires a start fingerprint"
                raise ValueError(message)
            _validate_bounded_text(
                self.start_fingerprint,
                name="start_fingerprint",
                maximum_bytes=MAX_PROCESS_FINGERPRINT_BYTES,
            )
        elif self.start_fingerprint is not None:
            message = "only a present process may expose a start fingerprint"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class RunLockTakeoverEvent:
    """Immutable evidence returned for journal/audit persistence by the caller."""

    previous_owner: RunLockMetadata
    new_owner: RunLockMetadata
    reason: TakeoverReason


class FilesystemProbe(Protocol):
    """Platform seam for identifying unsupported network storage."""

    def classify(self, path: Path) -> FilesystemKind:
        """Classify an existing directory without mutating it."""
        ...


class ProcessInspector(Protocol):
    """Platform seam for PID liveness and start-identity verification."""

    def current_process_fingerprint(self) -> str:
        """Return the current process's stable start identity."""
        ...

    def inspect(self, pid: int) -> ProcessProbe:
        """Return bounded liveness evidence for a local PID."""
        ...


class DefaultFilesystemProbe:
    """Best-effort platform filesystem classifier with a conservative fallback."""

    def classify(self, path: Path) -> FilesystemKind:
        """Return network when the current platform can identify it."""
        if _looks_like_unc_path(path):
            return FilesystemKind.NETWORK
        if os.name == "nt":
            return _classify_windows_filesystem(path)
        if sys.platform.startswith("linux"):
            return _classify_linux_filesystem(path)
        if sys.platform == "darwin" or "bsd" in sys.platform:
            return _classify_bsd_filesystem(path)
        return FilesystemKind.UNKNOWN


class DefaultProcessInspector:
    """Local process inspector that detects PID reuse where the OS exposes it."""

    def current_process_fingerprint(self) -> str:
        """Return the current process's verified start fingerprint."""
        fingerprint = _process_start_fingerprint(os.getpid())
        if fingerprint is None:
            message = "the current process start identity is unavailable"
            raise RunLockOwnerUnverifiableError(
                message,
                owner=_placeholder_owner(),
            )
        return fingerprint

    def inspect(self, pid: int) -> ProcessProbe:
        """Verify liveness and start identity without signaling the process."""
        _validate_positive_integer(pid, name="pid", maximum=MAX_PID)
        if not _pid_exists(pid):
            return ProcessProbe(ProcessState.ABSENT, None)
        fingerprint = _process_start_fingerprint(pid)
        if fingerprint is None:
            return ProcessProbe(ProcessState.UNVERIFIABLE, None)
        return ProcessProbe(ProcessState.PRESENT, fingerprint)


class RunLock:
    """A retained operating-system lock and its immutable acquisition evidence."""

    __slots__ = (
        "_closed",
        "_descriptor",
        "_lock_path",
        "_path_identity",
        "_takeover_event",
        "metadata",
    )

    def __init__(
        self,
        *,
        descriptor: int,
        lock_path: Path,
        metadata: RunLockMetadata,
        takeover_event: RunLockTakeoverEvent | None,
    ) -> None:
        """Retain one already-locked descriptor until explicit release."""
        self._descriptor = descriptor
        self._lock_path = lock_path
        descriptor_stat = os.fstat(descriptor)
        self._path_identity = (descriptor_stat.st_dev, descriptor_stat.st_ino)
        self.metadata = metadata
        self._takeover_event = takeover_event
        self._closed = False

    @property
    def takeover_event(self) -> RunLockTakeoverEvent | None:
        """Return detached explicit-takeover evidence, when applicable."""
        return self._takeover_event

    @property
    def closed(self) -> bool:
        """Return whether this owner released its retained lock handle."""
        return self._closed

    def require_owner(
        self,
        run_directory: str | os.PathLike[str],
        *,
        run_id: str,
        owner_epoch: int,
    ) -> None:
        """Verify that this still-live guard owns the exact requested run epoch."""
        if self._closed:
            message = "a released run lock cannot authorize execution"
            raise RunLockError(message)
        directory = _validate_run_directory(run_directory)
        validated_run_id = validate_run_id(run_id)
        _validate_nonnegative_integer(
            owner_epoch,
            name="owner_epoch",
            maximum=MAX_OWNER_EPOCH,
        )
        if (
            self._lock_path != directory / LOCK_FILENAME
            or self.metadata.run_id != validated_run_id
            or self.metadata.owner_epoch != owner_epoch
        ):
            message = "run-lock ownership does not match the requested run epoch"
            raise RunLockEpochError(message)
        _verify_descriptor_path_identity(self._descriptor, self._lock_path)
        if _read_metadata(self._descriptor) != self.metadata:
            message = "run-lock metadata changed while ownership was retained"
            raise RunLockMetadataError(message)

    def release(self) -> None:
        """Release ownership and remove only the still-identical lock path."""
        if self._closed:
            return
        descriptor = self._descriptor
        lock_path = self._lock_path
        try:
            if os.name != "nt":
                _unlink_if_same_identity(lock_path, self._path_identity)
                _fsync_directory(lock_path.parent)
                _unlock_descriptor(descriptor)
                os.close(descriptor)
            else:
                _unlock_descriptor(descriptor)
                os.close(descriptor)
                _unlink_windows_released_lock(lock_path, self._path_identity)
        finally:
            self._closed = True
            self._descriptor = -1

    def __enter__(self) -> Self:
        """Return this retained ownership guard."""
        if self._closed:
            message = "a released run lock cannot be entered"
            raise RunLockError(message)
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        """Release the lock on context exit."""
        self.release()


def acquire_run_lock(  # noqa: PLR0913
    run_directory: str | os.PathLike[str],
    *,
    run_id: str,
    owner_epoch: int,
    take_over: bool = False,
    filesystem_probe: FilesystemProbe | None = None,
    process_inspector: ProcessInspector | None = None,
    clock: UtcClock | None = None,
    hostname: str | None = None,
) -> RunLock:
    """Acquire one atomic local owner lock or classify the existing owner."""
    if type(take_over) is not bool:
        message = "take_over must be a boolean"
        raise TypeError(message)
    validated_run_id = validate_run_id(run_id)
    _validate_nonnegative_integer(
        owner_epoch,
        name="owner_epoch",
        maximum=MAX_OWNER_EPOCH,
    )
    directory = _validate_run_directory(run_directory)
    storage_probe = DefaultFilesystemProbe() if filesystem_probe is None else filesystem_probe
    filesystem_kind = storage_probe.classify(directory)
    if type(filesystem_kind) is not FilesystemKind:
        message = "filesystem probe returned an invalid classification"
        raise TypeError(message)
    if filesystem_kind is FilesystemKind.NETWORK:
        message = "run directories on network filesystems are unsupported"
        raise UnsupportedRunFilesystemError(message)
    inspector = DefaultProcessInspector() if process_inspector is None else process_inspector
    current_hostname = _normalize_hostname(socket.gethostname() if hostname is None else hostname)
    metadata = RunLockMetadata(
        run_id=validated_run_id,
        pid=os.getpid(),
        process_start_fingerprint=inspector.current_process_fingerprint(),
        hostname=current_hostname,
        owner_epoch=owner_epoch,
        wall_timestamp=_wall_timestamp(clock),
    )
    lock_path = directory / LOCK_FILENAME
    try:
        descriptor = _create_locked_file(lock_path, metadata)
    except (FileExistsError, PermissionError):
        return _acquire_existing_lock(
            lock_path,
            requested=metadata,
            take_over=take_over,
            process_inspector=inspector,
        )
    return RunLock(
        descriptor=descriptor,
        lock_path=lock_path,
        metadata=metadata,
        takeover_event=None,
    )


def read_run_lock(run_directory: str | os.PathLike[str]) -> RunLockMetadata:
    """Read and validate bounded canonical metadata without taking ownership."""
    directory = _validate_run_directory(run_directory)
    lock_path = directory / LOCK_FILENAME
    descriptor = _open_existing_lock(lock_path)
    try:
        return _read_metadata(descriptor)
    finally:
        os.close(descriptor)


def _acquire_existing_lock(
    lock_path: Path,
    *,
    requested: RunLockMetadata,
    take_over: bool,
    process_inspector: ProcessInspector,
) -> RunLock:
    descriptor = _open_existing_lock(lock_path)
    locked = False
    try:
        locked = _try_lock_descriptor(descriptor)
        if not locked:
            owner = _read_active_owner_best_effort(descriptor)
            message = "the run directory has an active operating-system owner lock"
            raise RunLockActiveError(message, owner=owner)
        previous = _read_metadata(descriptor)
        if previous.run_id != requested.run_id:
            message = "run-lock metadata belongs to a different run"
            raise RunLockMetadataError(message)
        reason = _classify_stale_owner(
            previous,
            current_hostname=requested.hostname,
            process_inspector=process_inspector,
        )
        if reason is None:
            message = "the recorded run-lock owner process is still active"
            raise RunLockActiveError(message, owner=previous)
        if not take_over:
            message = "the stale run lock requires explicit takeover"
            raise RunLockTakeoverRequiredError(message, owner=previous)
        if requested.owner_epoch != previous.owner_epoch + 1:
            message = "explicit takeover must increment owner_epoch exactly once"
            raise RunLockEpochError(message)
        _rewrite_locked_file(descriptor, requested)
        _verify_descriptor_path_identity(descriptor, lock_path)
        event = RunLockTakeoverEvent(
            previous_owner=previous,
            new_owner=requested,
            reason=reason,
        )
        return RunLock(
            descriptor=descriptor,
            lock_path=lock_path,
            metadata=requested,
            takeover_event=event,
        )
    except BaseException:
        if locked:
            _unlock_descriptor(descriptor)
        os.close(descriptor)
        raise


def _classify_stale_owner(
    owner: RunLockMetadata,
    *,
    current_hostname: str,
    process_inspector: ProcessInspector,
) -> TakeoverReason | None:
    if owner.hostname != current_hostname:
        message = "a lock recorded by another host cannot be safely taken over"
        raise RunLockOwnerUnverifiableError(message, owner=owner)
    probe = process_inspector.inspect(owner.pid)
    if type(probe) is not ProcessProbe:
        message = "process inspector returned invalid liveness evidence"
        raise TypeError(message)
    if probe.state is ProcessState.ABSENT:
        return TakeoverReason.PROCESS_ABSENT
    if probe.state is ProcessState.UNVERIFIABLE:
        message = "the recorded local process cannot be proven absent"
        raise RunLockOwnerUnverifiableError(message, owner=owner)
    if probe.start_fingerprint != owner.process_start_fingerprint:
        return TakeoverReason.PID_REUSED
    return None


def _create_locked_file(lock_path: Path, metadata: RunLockMetadata) -> int:
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    locked = False
    try:
        _validate_lock_descriptor(descriptor)
        if not _try_lock_descriptor(descriptor):
            message = "new run-lock file could not be locked"
            raise RunLockActiveError(message, owner=None)
        locked = True
        _rewrite_locked_file(descriptor, metadata)
        _verify_descriptor_path_identity(descriptor, lock_path)
        _fsync_directory(lock_path.parent)
    except BaseException:
        if locked:
            _unlock_descriptor(descriptor)
        identity = _descriptor_identity(descriptor)
        os.close(descriptor)
        _unlink_if_same_identity(lock_path, identity)
        raise
    return descriptor


def _open_existing_lock(lock_path: Path) -> int:
    _preflight_lock_path(lock_path)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            message = "run-lock path must not be a symbolic link"
            raise RunLockMetadataError(message) from error
        raise
    try:
        _validate_lock_descriptor(descriptor)
        _verify_descriptor_path_identity(descriptor, lock_path)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _preflight_lock_path(lock_path: Path) -> None:
    try:
        path_stat = lock_path.stat(follow_symlinks=False)
    except OSError as error:
        message = "run-lock path could not be inspected safely"
        raise RunLockMetadataError(message) from error
    if not stat.S_ISREG(path_stat.st_mode):
        message = "run-lock path must be a regular file"
        raise RunLockMetadataError(message)
    if path_stat.st_nlink != 1:
        message = "run-lock file must not have filesystem aliases"
        raise RunLockMetadataError(message)
    if path_stat.st_size > MAX_LOCK_BYTES:
        message = "run-lock metadata exceeds its byte limit"
        raise RunLockMetadataError(message)


def _validate_lock_descriptor(descriptor: int) -> None:
    descriptor_stat = os.fstat(descriptor)
    if not stat.S_ISREG(descriptor_stat.st_mode):
        message = "run-lock path must be a regular file"
        raise RunLockMetadataError(message)
    if descriptor_stat.st_nlink != 1:
        message = "run-lock file must not have filesystem aliases"
        raise RunLockMetadataError(message)
    if descriptor_stat.st_size > MAX_LOCK_BYTES:
        message = "run-lock metadata exceeds its byte limit"
        raise RunLockMetadataError(message)


def _verify_descriptor_path_identity(descriptor: int, lock_path: Path) -> None:
    descriptor_identity = _descriptor_identity(descriptor)
    try:
        path_stat = lock_path.stat(follow_symlinks=False)
    except OSError as error:
        message = "run-lock path changed while it was being inspected"
        raise RunLockMetadataError(message) from error
    if not stat.S_ISREG(path_stat.st_mode) or descriptor_identity != (
        path_stat.st_dev,
        path_stat.st_ino,
    ):
        message = "run-lock path changed while it was being inspected"
        raise RunLockMetadataError(message)


def _descriptor_identity(descriptor: int) -> tuple[int, int]:
    descriptor_stat = os.fstat(descriptor)
    return descriptor_stat.st_dev, descriptor_stat.st_ino


def _read_metadata(descriptor: int) -> RunLockMetadata:
    _validate_lock_descriptor(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    try:
        raw = os.read(descriptor, MAX_LOCK_BYTES + 1)
    except PermissionError:
        if os.name != "nt":
            raise
        # The retained Windows lock covers byte zero. Canonical metadata always
        # starts with ``{``, so readers can inspect the remaining locked file.
        os.lseek(descriptor, 1, os.SEEK_SET)
        raw = b"{" + os.read(descriptor, MAX_LOCK_BYTES)
    if len(raw) > MAX_LOCK_BYTES:
        message = "run-lock metadata exceeds its byte limit"
        raise RunLockMetadataError(message)
    return _decode_metadata(raw)


def _read_active_owner_best_effort(descriptor: int) -> RunLockMetadata | None:
    for attempt in range(_WINDOWS_LOCK_RETRIES):
        try:
            return _read_metadata(descriptor)
        except RunLockMetadataError:
            if attempt + 1 == _WINDOWS_LOCK_RETRIES:
                return None
            time.sleep(_WINDOWS_LOCK_RETRY_SECONDS)
    return None


def _decode_metadata(raw: bytes) -> RunLockMetadata:
    if not raw or len(raw) > MAX_LOCK_BYTES:
        message = "run-lock metadata is empty or oversized"
        raise RunLockMetadataError(message)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        message = "run-lock metadata is not UTF-8"
        raise RunLockMetadataError(message) from error
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        message = "run-lock metadata is not canonical JSON"
        raise RunLockMetadataError(message) from error
    if type(value) is not dict:
        message = "run-lock metadata has an unexpected object shape"
        raise RunLockMetadataError(message)
    values = cast("dict[str, object]", value)
    if frozenset(values) != _LOCK_KEYS:
        message = "run-lock metadata has an unexpected object shape"
        raise RunLockMetadataError(message)
    try:
        metadata = RunLockMetadata(
            format_version=_exact_integer(values["format_version"], "format_version"),
            hostname=_exact_string(values["hostname"], "hostname"),
            owner_epoch=_exact_integer(values["owner_epoch"], "owner_epoch"),
            pid=_exact_integer(values["pid"], "pid"),
            process_start_fingerprint=_exact_string(
                values["process_start_fingerprint"],
                "process_start_fingerprint",
            ),
            run_id=_exact_string(values["run_id"], "run_id"),
            wall_timestamp=_exact_string(values["wall_timestamp"], "wall_timestamp"),
        )
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, RunLockMetadataError):
            raise
        message = "run-lock metadata contains invalid field values"
        raise RunLockMetadataError(message) from error
    if raw != _encode_metadata(metadata):
        message = "run-lock metadata must use canonical JSON encoding"
        raise RunLockMetadataError(message)
    return metadata


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = "run-lock metadata contains a duplicate key"
            raise RunLockMetadataError(message)
        result[key] = value
    return result


def _rewrite_locked_file(descriptor: int, metadata: RunLockMetadata) -> None:
    payload = _encode_metadata(metadata)
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    written = 0
    while written < len(payload):
        count = os.write(descriptor, payload[written:])
        if count <= 0:
            message = "run-lock metadata write made no progress"
            raise RunLockMetadataError(message)
        written += count
    os.ftruncate(descriptor, len(payload))
    os.fsync(descriptor)


def _encode_metadata(metadata: RunLockMetadata) -> bytes:
    value = {
        "format_version": metadata.format_version,
        "hostname": metadata.hostname,
        "owner_epoch": metadata.owner_epoch,
        "pid": metadata.pid,
        "process_start_fingerprint": metadata.process_start_fingerprint,
        "run_id": metadata.run_id,
        "wall_timestamp": metadata.wall_timestamp,
    }
    payload = (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )
    if len(payload) > MAX_LOCK_BYTES:
        message = "run-lock metadata exceeds its byte limit"
        raise RunLockMetadataError(message)
    return payload


def _try_lock_descriptor(descriptor: int) -> bool:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                return False
            raise
        return True
    import fcntl

    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EAGAIN}:
            return False
        raise
    return True


def _unlock_descriptor(descriptor: int) -> None:
    if descriptor < 0:
        return
    os.lseek(descriptor, 0, os.SEEK_SET)
    with suppress(OSError):
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)


def _unlink_windows_released_lock(
    lock_path: Path,
    expected_identity: tuple[int, int],
) -> None:
    for attempt in range(_WINDOWS_LOCK_RETRIES):
        try:
            _unlink_if_same_identity(lock_path, expected_identity)
        except PermissionError:
            if attempt + 1 == _WINDOWS_LOCK_RETRIES:
                raise
            time.sleep(_WINDOWS_LOCK_RETRY_SECONDS)
        else:
            return


def _unlink_if_same_identity(
    path: Path,
    expected_identity: tuple[int, int],
) -> None:
    try:
        path_stat = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if (
        stat.S_ISREG(path_stat.st_mode)
        and (path_stat.st_dev, path_stat.st_ino) == expected_identity
    ):
        path.unlink()


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_run_directory(path: str | os.PathLike[str]) -> Path:
    try:
        candidate = Path(os.fspath(path))
    except (TypeError, ValueError) as error:
        message = "run_directory must be a filesystem path"
        raise TypeError(message) from error
    if not candidate.is_absolute():
        message = "run_directory must be an absolute path"
        raise ValueError(message)
    if candidate.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(candidate)):
        message = "run_directory must not be a symbolic link or junction"
        raise RunLockMetadataError(message)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        message = "run_directory must already exist"
        raise RunLockMetadataError(message) from error
    if not resolved.is_dir():
        message = "run_directory must be an existing directory"
        raise RunLockMetadataError(message)
    return resolved


def _classify_windows_filesystem(path: Path) -> FilesystemKind:
    import ctypes

    anchor = path.anchor
    if not anchor:
        return FilesystemKind.UNKNOWN
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # pyright: ignore[reportAttributeAccessIssue]
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        drive_type = int(get_drive_type(anchor))
    except (AttributeError, OSError, TypeError, ValueError):
        return FilesystemKind.UNKNOWN
    if drive_type == _WINDOWS_DRIVE_REMOTE:
        return FilesystemKind.NETWORK
    if drive_type in {2, 3, 5, 6}:
        return FilesystemKind.LOCAL
    return FilesystemKind.UNKNOWN


def _classify_linux_filesystem(path: Path) -> FilesystemKind:
    mountinfo_path = Path("/proc/self/mountinfo")
    try:
        descriptor = os.open(
            mountinfo_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        return FilesystemKind.UNKNOWN
    try:
        raw = os.read(descriptor, _MOUNTINFO_LIMIT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > _MOUNTINFO_LIMIT_BYTES:
        return FilesystemKind.UNKNOWN
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return FilesystemKind.UNKNOWN
    resolved_text = os.fspath(path)
    best_mount = ""
    best_type: str | None = None
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < _MOUNTINFO_MIN_FIELDS or not right_fields:
            continue
        mount_point = _decode_mountinfo_path(left_fields[4])
        if _path_is_within_mount(resolved_text, mount_point) and len(mount_point) > len(best_mount):
            best_mount = mount_point
            best_type = right_fields[0].casefold()
    if best_type is None:
        return FilesystemKind.UNKNOWN
    if best_type in _NETWORK_FILESYSTEM_TYPES:
        return FilesystemKind.NETWORK
    return FilesystemKind.LOCAL


def _classify_bsd_filesystem(path: Path) -> FilesystemKind:
    try:
        completed = subprocess.run(  # noqa: S603
            ["/usr/bin/stat", "-f", "%T", os.fspath(path)],
            check=False,
            capture_output=True,
            timeout=1,
            env={"PATH": os.defpath},
        )
    except (OSError, subprocess.SubprocessError):
        return FilesystemKind.UNKNOWN
    if completed.returncode != 0 or len(completed.stdout) > _PLATFORM_OUTPUT_LIMIT_BYTES:
        return FilesystemKind.UNKNOWN
    try:
        filesystem_type = completed.stdout.decode("ascii").strip().casefold()
    except UnicodeDecodeError:
        return FilesystemKind.UNKNOWN
    if filesystem_type in _NETWORK_FILESYSTEM_TYPES:
        return FilesystemKind.NETWORK
    return FilesystemKind.LOCAL if filesystem_type else FilesystemKind.UNKNOWN


def _decode_mountinfo_path(value: str) -> str:
    return (
        value.replace(r"\040", " ")
        .replace(r"\011", "\t")
        .replace(r"\012", "\n")
        .replace(r"\134", "\\")
    )


def _path_is_within_mount(path: str, mount_point: str) -> bool:
    if mount_point == os.sep:
        return path.startswith(os.sep)
    normalized = mount_point.rstrip(os.sep)
    return path == normalized or path.startswith(f"{normalized}{os.sep}")


def _looks_like_unc_path(path: Path) -> bool:
    text = os.fspath(path)
    return text.startswith(("\\\\", "//"))


def _pid_exists(pid: int) -> bool:
    if os.name == "nt":
        windows_state = _windows_pid_exists(pid)
        return True if windows_state is None else windows_state
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        return error.errno != errno.ESRCH
    return True


def _windows_pid_exists(pid: int) -> bool | None:
    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    still_active = 259
    error_invalid_parameter = 87
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # pyright: ignore[reportAttributeAccessIssue]
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_exit_code.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        handle = open_process(
            process_query_limited_information,
            wintypes.BOOL(0),
            pid,
        )
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if not handle:
        return False if ctypes.get_last_error() == error_invalid_parameter else None
    exit_code = wintypes.DWORD()
    try:
        if not get_exit_code(handle, ctypes.byref(exit_code)):
            return None
        return exit_code.value == still_active
    finally:
        close_handle(handle)


def _process_start_fingerprint(pid: int) -> str | None:
    if os.name == "nt":
        return _windows_process_start_fingerprint(pid)
    if sys.platform.startswith("linux"):
        return _linux_process_start_fingerprint(pid)
    return _ps_process_start_fingerprint(pid)


def _linux_process_start_fingerprint(pid: int) -> str | None:
    path = Path(f"/proc/{pid}/stat")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        raw = os.read(descriptor, _PROC_STAT_LIMIT_BYTES + 1)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > _PROC_STAT_LIMIT_BYTES:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    close_parenthesis = text.rfind(")")
    if close_parenthesis < 0:
        return None
    fields = text[close_parenthesis + 1 :].split()
    start_time_index = 19
    if len(fields) <= start_time_index or not fields[start_time_index].isdigit():
        return None
    return f"linux-proc-start:{fields[start_time_index]}"


def _windows_process_start_fingerprint(pid: int) -> str | None:
    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # pyright: ignore[reportAttributeAccessIssue]
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        get_process_times = kernel32.GetProcessTimes
        get_process_times.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        get_process_times.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        handle = open_process(
            process_query_limited_information,
            wintypes.BOOL(0),
            pid,
        )
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if not handle:
        return None
    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    try:
        if not get_process_times(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return None
    finally:
        close_handle(handle)
    ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    return f"windows-filetime:{ticks:016x}"


def _ps_process_start_fingerprint(pid: int) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603
            ["/bin/ps", "-o", "lstart=", "-p", str(pid)],
            check=False,
            capture_output=True,
            timeout=1,
            env={"PATH": os.defpath, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > _PLATFORM_OUTPUT_LIMIT_BYTES
    ):
        return None
    return f"ps-start-sha256:{hashlib.sha256(completed.stdout.strip()).hexdigest()}"


def _wall_timestamp(clock: UtcClock | None) -> str:
    value = datetime.now(UTC) if clock is None else clock()
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        message = "run-lock clock must return a UTC-aware datetime"
        raise ValueError(message)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_wall_timestamp(value: str) -> None:
    _validate_bounded_text(value, name="wall_timestamp", maximum_bytes=64)
    if not value.endswith("Z"):
        message = "run-lock wall_timestamp must be canonical UTC"
        raise RunLockMetadataError(message)
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as error:
        message = "run-lock wall_timestamp must be canonical UTC"
        raise RunLockMetadataError(message) from error
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != UTC.utcoffset(parsed)
        or parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") != value
    ):
        message = "run-lock wall_timestamp must be canonical UTC"
        raise RunLockMetadataError(message)


def _normalize_hostname(value: str) -> str:
    _validate_bounded_text(value, name="hostname", maximum_bytes=MAX_HOSTNAME_BYTES)
    normalized = value.rstrip(".").casefold()
    if not normalized:
        message = "hostname must not be empty"
        raise RunLockMetadataError(message)
    return normalized


def _validate_bounded_text(value: object, *, name: str, maximum_bytes: int) -> None:
    if type(value) is not str or not value or _CONTROL_CHARACTERS.search(value) is not None:
        message = f"{name} must be nonempty control-free text"
        raise RunLockMetadataError(message)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        message = f"{name} must contain Unicode scalar values"
        raise RunLockMetadataError(message) from error
    if len(encoded) > maximum_bytes:
        message = f"{name} exceeds its byte limit"
        raise RunLockMetadataError(message)


def _validate_positive_integer(value: object, *, name: str, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        message = f"{name} must be an integer in the range 1..{maximum}"
        raise RunLockMetadataError(message)


def _validate_nonnegative_integer(value: object, *, name: str, maximum: int) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        message = f"{name} must be an integer in the range 0..{maximum}"
        raise RunLockMetadataError(message)


def _exact_integer(value: object, name: str) -> int:
    if type(value) is not int:
        message = f"run-lock {name} must be an integer"
        raise RunLockMetadataError(message)
    return value


def _exact_string(value: object, name: str) -> str:
    if type(value) is not str:
        message = f"run-lock {name} must be a string"
        raise RunLockMetadataError(message)
    return value


def _placeholder_owner() -> RunLockMetadata:
    """Construct unreachable diagnostic context for an unsupported local platform."""
    return RunLockMetadata(
        run_id="00000000-0000-4000-8000-000000000000",
        pid=max(os.getpid(), 1),
        process_start_fingerprint="unavailable",
        hostname=_normalize_hostname(socket.gethostname()),
        owner_epoch=0,
        wall_timestamp=datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
    )
