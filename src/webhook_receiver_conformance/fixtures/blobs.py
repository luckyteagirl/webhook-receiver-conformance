"""Atomic content-addressed storage for exact fixture bytes."""
# ruff: noqa: INP001, PLC0415, PLR0912, PLR0913, RUF012, TRY203, TRY300, TRY301

from __future__ import annotations

import ctypes
import os
import stat
import uuid
from contextlib import suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, NoReturn

from webhook_receiver_conformance.domain.hashing import (
    sha256_digest,
    validate_sha256_digest,
)
from webhook_receiver_conformance.errors import Diagnostic, ErrorCategory, ResultCategory
from webhook_receiver_conformance.fixtures.loader import (
    HARD_MAX_FIXTURE_BYTES,
    _same_windows_path,  # pyright: ignore[reportPrivateUsage]
    _windows_close_handle,  # pyright: ignore[reportPrivateUsage]
    _windows_file_attributes,  # pyright: ignore[reportPrivateUsage]
    _windows_file_type,  # pyright: ignore[reportPrivateUsage]
    _windows_final_path,  # pyright: ignore[reportPrivateUsage]
    _windows_open_path,  # pyright: ignore[reportPrivateUsage]
    _windows_path_is_within,  # pyright: ignore[reportPrivateUsage]
    _windows_volume_serial,  # pyright: ignore[reportPrivateUsage]
)
from webhook_receiver_conformance.types import DiagnosticCode

if TYPE_CHECKING:
    from pathlib import Path

_DIRECTORY_MODE: Final = 0o700
_FILE_MODE: Final = 0o600
_OPEN_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_READ_CHUNK_BYTES: Final = 65_536
_MAX_MEDIA_TYPE_LENGTH: Final = 255
_SAFE_DIRECTORY_DESCRIPTORS_SUPPORTED: Final = (
    os.open in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
    and os.link in os.supports_dir_fd
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
)
_WINDOWS_DELETE: Final = 0x00010000
_WINDOWS_FILE_ATTRIBUTE_DEVICE: Final = 0x00000040
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_NORMAL: Final = 0x00000080
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
_WINDOWS_FILE_CREATE: Final = 2
_WINDOWS_FILE_DIRECTORY_FILE: Final = 0x00000001
_WINDOWS_FILE_DISPOSITION_INFO: Final = 4
_WINDOWS_FILE_LIST_DIRECTORY: Final = 0x00000001
_WINDOWS_FILE_NON_DIRECTORY_FILE: Final = 0x00000040
_WINDOWS_FILE_OPEN: Final = 1
_WINDOWS_FILE_OPEN_IF: Final = 3
_WINDOWS_FILE_OPEN_REPARSE_POINT: Final = 0x00200000
_WINDOWS_FILE_RENAME_INFORMATION: Final = 10
_WINDOWS_FILE_READ_ATTRIBUTES: Final = 0x00000080
_WINDOWS_FILE_READ_DATA: Final = 0x00000001
_WINDOWS_FILE_SHARE_DELETE: Final = 0x00000004
_WINDOWS_FILE_SHARE_READ: Final = 0x00000001
_WINDOWS_FILE_SHARE_WRITE: Final = 0x00000002
_WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT: Final = 0x00000020
_WINDOWS_FILE_TYPE_DISK: Final = 0x0001
_WINDOWS_FILE_TRAVERSE: Final = 0x00000020
_WINDOWS_FILE_WRITE_DATA: Final = 0x00000002
_WINDOWS_OBJ_CASE_INSENSITIVE: Final = 0x00000040
_WINDOWS_STATUS_OBJECT_NAME_COLLISION: Final = 0xC0000035
_WINDOWS_STATUS_OBJECT_NAME_NOT_FOUND: Final = 0xC0000034
_WINDOWS_STATUS_OBJECT_PATH_NOT_FOUND: Final = 0xC000003A
_WINDOWS_SYNCHRONIZE: Final = 0x00100000


class _WindowsUnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", ctypes.c_void_p),
    ]


class _WindowsObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("root_directory", ctypes.c_void_p),
        ("object_name", ctypes.POINTER(_WindowsUnicodeString)),
        ("attributes", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


class _WindowsIoStatusValue(ctypes.Union):
    _fields_ = [
        ("status", ctypes.c_int32),
        ("pointer", ctypes.c_void_p),
    ]


class _WindowsIoStatusBlock(ctypes.Structure):
    _fields_ = [
        ("value", _WindowsIoStatusValue),
        ("information", ctypes.c_size_t),
    ]


class _WindowsFileDispositionInfo(ctypes.Structure):
    _fields_ = [("delete_file", ctypes.c_int)]


@dataclass(frozen=True, slots=True)
class BlobSnapshot:
    """Manifest-compatible metadata for one immutable blob."""

    sha256: str
    byte_length: int
    media_type: str
    path: Path = field(repr=False)

    def to_manifest_entry(self) -> dict[str, str | int]:
        """Return the serialized run-manifest blob projection."""
        return {
            "sha256": self.sha256,
            "byte_length": self.byte_length,
            "media_type": self.media_type,
        }


class BlobStoreError(Exception):
    """A blob-store failure carrying a bounded, privacy-safe diagnostic."""

    diagnostic: Diagnostic

    def __init__(self, diagnostic: Diagnostic) -> None:
        """Initialize without retaining sensitive bytes or output paths."""
        self.diagnostic = diagnostic
        super().__init__(diagnostic.code)


@dataclass(frozen=True, slots=True)
class _PinnedWindowsBlobTree:
    root: Path
    shard: Path
    volume_serial: int
    handles: tuple[int, ...] = field(repr=False)
    paths: tuple[Path, ...] = field(repr=False)

    def close(self) -> None:
        for handle in reversed(self.handles):
            _windows_close_handle(handle)


class BlobStore:
    """A run-local SHA-256 blob store."""

    _run_directory: Path

    def __init__(self, run_directory: Path) -> None:
        """Bind the store to a run directory without performing I/O."""
        self._run_directory = run_directory.absolute()

    @property
    def run_directory(self) -> Path:
        """Return the configured run directory."""
        return self._run_directory

    def path_for(self, digest: str) -> Path:
        """Return the canonical run-bundle path for a validated digest."""
        raw_digest = validate_sha256_digest(digest).removeprefix("sha256:")
        return self._run_directory / "blobs" / "sha256" / raw_digest[:2] / raw_digest

    def snapshot(self, body: bytes, *, media_type: str) -> BlobSnapshot:
        """Atomically install exact bytes, or verify a matching existing blob."""
        _validate_body(body)
        _validate_media_type(media_type)
        if len(body) > HARD_MAX_FIXTURE_BYTES:
            raise _blob_resource_limit_error()
        digest = sha256_digest(body)
        destination = self.path_for(digest)
        raw_digest = digest.removeprefix("sha256:")

        try:
            if _supports_safe_directory_descriptors():
                shard_descriptor = _open_blob_shard_at(
                    self._run_directory,
                    raw_digest[:2],
                    create=True,
                )
                try:
                    _snapshot_at(
                        shard_descriptor,
                        raw_digest,
                        body,
                        expected_digest=digest,
                    )
                finally:
                    os.close(shard_descriptor)
            elif os.name == "nt":
                tree = _open_blob_tree_windows(
                    self._run_directory,
                    raw_digest[:2],
                    create=True,
                )
                try:
                    _snapshot_windows(tree, raw_digest, body, expected_digest=digest)
                finally:
                    tree.close()
            else:
                raise OSError
        except BlobStoreError:
            raise
        except OSError:
            raise _write_error() from None

        return BlobSnapshot(
            sha256=digest,
            byte_length=len(body),
            media_type=media_type,
            path=destination,
        )

    def verify(self, snapshot: BlobSnapshot) -> Path:
        """Verify a stored blob against its digest and declared byte length."""
        if type(snapshot.byte_length) is not int or snapshot.byte_length < 0:
            raise _integrity_error()
        if snapshot.byte_length > HARD_MAX_FIXTURE_BYTES:
            raise _blob_resource_limit_error()
        try:
            digest = validate_sha256_digest(snapshot.sha256)
        except (TypeError, ValueError):
            raise _integrity_error() from None
        raw_digest = digest.removeprefix("sha256:")
        expected_path = self.path_for(digest)
        if snapshot.path != expected_path:
            raise _integrity_error()

        try:
            if _supports_safe_directory_descriptors():
                shard_descriptor = _open_blob_shard_at(
                    self._run_directory,
                    raw_digest[:2],
                    create=False,
                )
                try:
                    descriptor = _open_existing_at(shard_descriptor, raw_digest)
                    try:
                        _verify_descriptor(
                            descriptor,
                            expected_digest=digest,
                            expected_length=snapshot.byte_length,
                            expected_body=None,
                        )
                    finally:
                        os.close(descriptor)
                finally:
                    os.close(shard_descriptor)
            elif os.name == "nt":
                tree = _open_blob_tree_windows(
                    self._run_directory,
                    raw_digest[:2],
                    create=False,
                )
                try:
                    descriptor = _open_existing_windows(tree, raw_digest)
                    try:
                        _verify_descriptor(
                            descriptor,
                            expected_digest=digest,
                            expected_length=snapshot.byte_length,
                            expected_body=None,
                        )
                    finally:
                        os.close(descriptor)
                finally:
                    tree.close()
            else:
                raise OSError
        except BlobStoreError:
            raise
        except OSError:
            raise _integrity_error() from None
        return expected_path


def snapshot_blob(
    run_directory: Path,
    body: bytes,
    *,
    media_type: str,
) -> BlobSnapshot:
    """Snapshot exact bytes into a run bundle using the standard layout."""
    return BlobStore(run_directory).snapshot(body, media_type=media_type)


def verify_blob(run_directory: Path, snapshot: BlobSnapshot) -> Path:
    """Verify a content-addressed blob in a run bundle."""
    return BlobStore(run_directory).verify(snapshot)


def _snapshot_at(
    shard_descriptor: int,
    name: str,
    body: bytes,
    *,
    expected_digest: str,
) -> None:
    existing = _try_open_existing_at(shard_descriptor, name)
    if existing is not None:
        try:
            _verify_descriptor(
                existing,
                expected_digest=expected_digest,
                expected_length=len(body),
                expected_body=body,
            )
        finally:
            os.close(existing)
        return

    temporary_name = f".tmp-{uuid.uuid4().hex}"
    temporary_descriptor = os.open(
        temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _OPEN_CLOEXEC,
        _FILE_MODE,
        dir_fd=shard_descriptor,
    )
    try:
        _write_all(temporary_descriptor, body)
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        try:
            os.link(
                temporary_name,
                name,
                src_dir_fd=shard_descriptor,
                dst_dir_fd=shard_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            try:
                existing = _open_existing_at(shard_descriptor, name)
            except OSError:
                raise _integrity_error() from None
            try:
                _verify_descriptor(
                    existing,
                    expected_digest=expected_digest,
                    expected_length=len(body),
                    expected_body=body,
                )
            finally:
                os.close(existing)
    except BlobStoreError:
        raise
    except OSError:
        raise _write_error() from None
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary_name, dir_fd=shard_descriptor)


def _snapshot_windows(
    tree: _PinnedWindowsBlobTree,
    name: str,
    body: bytes,
    *,
    expected_digest: str,
) -> None:
    _require_windows_tree_stable(tree)
    existing = _try_open_existing_windows(tree, name)
    if existing is not None:
        try:
            _verify_descriptor(
                existing,
                expected_digest=expected_digest,
                expected_length=len(body),
                expected_body=body,
            )
        finally:
            os.close(existing)
        return

    temporary_name = f".tmp-{uuid.uuid4().hex}"
    temporary_handle = _windows_open_relative_handle(
        tree.handles[-1],
        temporary_name,
        desired_access=(
            _WINDOWS_FILE_WRITE_DATA
            | _WINDOWS_FILE_READ_ATTRIBUTES
            | _WINDOWS_DELETE
            | _WINDOWS_SYNCHRONIZE
        ),
        share_access=(
            _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE
        ),
        create_disposition=_WINDOWS_FILE_CREATE,
    )
    try:
        temporary_descriptor = _windows_descriptor_from_handle(
            temporary_handle,
            flags=os.O_WRONLY | getattr(os, "O_BINARY", 0),
        )
        temporary_handle = -1
    except BaseException:
        with suppress(OSError):
            _windows_mark_delete(temporary_handle)
        _windows_close_handle(temporary_handle)
        raise
    installed = False
    succeeded = False
    try:
        _write_all(temporary_descriptor, body)
        os.fsync(temporary_descriptor)
        _require_windows_tree_stable(tree)
        try:
            _windows_rename_handle(
                os_handle=_windows_os_handle(temporary_descriptor),
                root_handle=tree.handles[-1],
                name=name,
            )
            installed = True
            _require_windows_tree_stable(tree)
        except FileExistsError:
            existing = _open_existing_windows(tree, name)
            try:
                _verify_descriptor(
                    existing,
                    expected_digest=expected_digest,
                    expected_length=len(body),
                    expected_body=body,
                )
            finally:
                os.close(existing)
        succeeded = True
    except BlobStoreError:
        raise
    except OSError:
        raise _write_error() from None
    finally:
        if not installed or not succeeded:
            with suppress(OSError):
                _windows_mark_delete(_windows_os_handle(temporary_descriptor))
        os.close(temporary_descriptor)
        if temporary_handle != -1:
            _windows_close_handle(temporary_handle)


def _verify_descriptor(
    descriptor: int,
    *,
    expected_digest: str,
    expected_length: int,
    expected_body: bytes | None,
) -> None:
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_length:
            raise _integrity_error()
        body = _read_existing_bounded(descriptor, maximum=expected_length)
        if (
            len(body) != expected_length
            or sha256_digest(body) != expected_digest
            or (expected_body is not None and body != expected_body)
        ):
            raise _integrity_error()
    except BlobStoreError:
        raise
    except OSError:
        raise _integrity_error() from None


def _read_existing_bounded(descriptor: int, *, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        read_size = min(_READ_CHUNK_BYTES, maximum - total + 1)
        chunk = os.read(descriptor, read_size)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > maximum:
            raise _integrity_error()
        chunks.append(chunk)


def _write_all(descriptor: int, body: bytes) -> None:
    view = memoryview(body)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError
        written += count


def _supports_safe_directory_descriptors() -> bool:
    return _SAFE_DIRECTORY_DESCRIPTORS_SUPPORTED


def _open_blob_shard_at(
    run_directory: Path,
    shard_name: str,
    *,
    create: bool,
) -> int:
    open_path = _open_or_create_directory_path if create else _open_directory_path
    open_child = _open_or_create_directory_at if create else _open_directory_at
    run_descriptor = open_path(run_directory)
    try:
        blobs_descriptor = open_child(run_descriptor, "blobs")
    finally:
        os.close(run_descriptor)
    try:
        algorithm_descriptor = open_child(blobs_descriptor, "sha256")
    finally:
        os.close(blobs_descriptor)
    try:
        return open_child(algorithm_descriptor, shard_name)
    finally:
        os.close(algorithm_descriptor)


def _open_blob_tree_windows(
    run_directory: Path,
    shard_name: str,
    *,
    create: bool,
) -> _PinnedWindowsBlobTree:
    handles: list[int] = []
    paths: list[Path] = []
    try:
        if create:
            with suppress(FileExistsError):
                run_directory.mkdir(mode=_DIRECTORY_MODE)
        root_handle = _windows_open_path(run_directory, directory=True)
        handles.append(root_handle)
        root = _windows_final_path(root_handle)
        paths.append(root)
        volume_serial = _windows_volume_serial(root_handle)
        current = root
        for component in ("blobs", "sha256", shard_name):
            requested = current / component
            _require_windows_handles_stable(
                handles,
                paths,
                root=root,
                volume_serial=volume_serial,
            )
            handle = _windows_open_relative_handle(
                handles[-1],
                component,
                desired_access=(
                    _WINDOWS_FILE_LIST_DIRECTORY
                    | _WINDOWS_FILE_TRAVERSE
                    | _WINDOWS_FILE_READ_ATTRIBUTES
                    | _WINDOWS_SYNCHRONIZE
                ),
                share_access=(
                    _WINDOWS_FILE_SHARE_READ
                    | _WINDOWS_FILE_SHARE_WRITE
                    | _WINDOWS_FILE_SHARE_DELETE
                ),
                create_disposition=(_WINDOWS_FILE_OPEN_IF if create else _WINDOWS_FILE_OPEN),
                directory=True,
            )
            handles.append(handle)
            actual = _windows_final_path(handle)
            paths.append(actual)
            _require_windows_handles_stable(
                handles,
                paths,
                root=root,
                volume_serial=volume_serial,
            )
            if not _same_windows_path(actual, requested):
                raise OSError
            current = actual
        return _PinnedWindowsBlobTree(
            root=root,
            shard=current,
            volume_serial=volume_serial,
            handles=tuple(handles),
            paths=tuple(paths),
        )
    except BaseException:
        for handle in reversed(handles):
            _windows_close_handle(handle)
        raise


def _open_or_create_directory_path(path: Path) -> int:
    with suppress(FileExistsError):
        path.mkdir(mode=_DIRECTORY_MODE)
    flags = os.O_RDONLY | _OPEN_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        _require_directory_descriptor(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_or_create_directory_at(parent_descriptor: int, name: str) -> int:
    with suppress(FileExistsError):
        os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent_descriptor)
    flags = os.O_RDONLY | _OPEN_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        _require_directory_descriptor(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_directory_path(path: Path) -> int:
    flags = os.O_RDONLY | _OPEN_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        _require_directory_descriptor(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_directory_at(parent_descriptor: int, name: str) -> int:
    flags = os.O_RDONLY | _OPEN_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        _require_directory_descriptor(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _require_directory_descriptor(descriptor: int) -> None:
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        raise _write_error()


def _try_open_existing_at(parent_descriptor: int, name: str) -> int | None:
    try:
        return _open_existing_at(parent_descriptor, name)
    except FileNotFoundError:
        return None
    except OSError:
        raise _integrity_error() from None


def _open_existing_at(parent_descriptor: int, name: str) -> int:
    flags = os.O_RDONLY | _OPEN_CLOEXEC | os.O_NOFOLLOW
    return os.open(name, flags, dir_fd=parent_descriptor)


def _try_open_existing_windows(
    tree: _PinnedWindowsBlobTree,
    name: str,
) -> int | None:
    try:
        return _open_existing_windows(tree, name)
    except FileNotFoundError:
        return None
    except OSError:
        raise _integrity_error() from None


def _open_existing_windows(tree: _PinnedWindowsBlobTree, name: str) -> int:
    _require_windows_tree_stable(tree)
    handle = _windows_open_relative_handle(
        tree.handles[-1],
        name,
        desired_access=(
            _WINDOWS_FILE_READ_DATA | _WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE
        ),
        share_access=_WINDOWS_FILE_SHARE_READ,
        create_disposition=_WINDOWS_FILE_OPEN,
    )
    try:
        attributes = _windows_file_attributes(handle)
        if (
            attributes
            & (
                _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
                | _WINDOWS_FILE_ATTRIBUTE_DIRECTORY
                | _WINDOWS_FILE_ATTRIBUTE_DEVICE
            )
            or _windows_file_type(handle) != _WINDOWS_FILE_TYPE_DISK
            or _windows_volume_serial(handle) != tree.volume_serial
        ):
            raise _integrity_error()
        _require_windows_tree_stable(tree)
        descriptor = _windows_descriptor_from_handle(
            handle,
            flags=os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
        handle = -1
        return descriptor
    except BaseException:
        raise
    finally:
        if handle != -1:
            _windows_close_handle(handle)


def _require_windows_tree_stable(tree: _PinnedWindowsBlobTree) -> None:
    _require_windows_handles_stable(
        tree.handles,
        tree.paths,
        root=tree.root,
        volume_serial=tree.volume_serial,
    )


def _require_windows_handles_stable(
    handles: list[int] | tuple[int, ...],
    paths: list[Path] | tuple[Path, ...],
    *,
    root: Path,
    volume_serial: int,
) -> None:
    if len(handles) != len(paths):
        raise OSError
    for handle, expected in zip(handles, paths, strict=True):
        actual = _windows_final_path(handle)
        if (
            _windows_volume_serial(handle) != volume_serial
            or not _same_windows_path(actual, expected)
            or not _windows_path_is_within(actual, root)
        ):
            raise OSError


def _windows_open_relative_handle(
    root_handle: int,
    name: str,
    *,
    desired_access: int,
    share_access: int,
    create_disposition: int,
    directory: bool = False,
) -> int:
    _require_windows_leaf_name(name)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    nt_create_file = ntdll.NtCreateFile
    nt_create_file.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.POINTER(_WindowsObjectAttributes),
        ctypes.POINTER(_WindowsIoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    nt_create_file.restype = ctypes.c_int32

    name_buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    unicode_name = _WindowsUnicodeString(
        length=encoded_length,
        maximum_length=encoded_length,
        buffer=ctypes.cast(name_buffer, ctypes.c_void_p),
    )
    object_attributes = _WindowsObjectAttributes(
        length=ctypes.sizeof(_WindowsObjectAttributes),
        root_directory=ctypes.c_void_p(root_handle),
        object_name=ctypes.pointer(unicode_name),
        attributes=_WINDOWS_OBJ_CASE_INSENSITIVE,
        security_descriptor=None,
        security_quality_of_service=None,
    )
    io_status = _WindowsIoStatusBlock()
    handle = ctypes.c_void_p()
    status = int(
        nt_create_file(
            ctypes.byref(handle),
            desired_access,
            ctypes.byref(object_attributes),
            ctypes.byref(io_status),
            None,
            (_WINDOWS_FILE_ATTRIBUTE_DIRECTORY if directory else _WINDOWS_FILE_ATTRIBUTE_NORMAL),
            share_access,
            create_disposition,
            (
                (_WINDOWS_FILE_DIRECTORY_FILE if directory else _WINDOWS_FILE_NON_DIRECTORY_FILE)
                | _WINDOWS_FILE_OPEN_REPARSE_POINT
                | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
            ),
            None,
            0,
        )
    )
    if status < 0:
        if handle.value is not None:
            _windows_close_handle(int(handle.value))
        _raise_windows_ntstatus(status)
    if handle.value is None:
        raise OSError
    integer_handle = int(handle.value)
    try:
        attributes = _windows_file_attributes(integer_handle)
        if attributes & (_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT | _WINDOWS_FILE_ATTRIBUTE_DEVICE):
            raise OSError
        if directory != bool(attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY):
            raise OSError
        if not directory and _windows_file_type(integer_handle) != _WINDOWS_FILE_TYPE_DISK:
            raise OSError
    except BaseException:
        _windows_close_handle(integer_handle)
        raise
    return integer_handle


def _windows_descriptor_from_handle(handle: int, *, flags: int) -> int:
    import msvcrt

    return msvcrt.open_osfhandle(handle, flags)


def _windows_os_handle(descriptor: int) -> int:
    import msvcrt

    return int(msvcrt.get_osfhandle(descriptor))


def _windows_rename_handle(*, os_handle: int, root_handle: int, name: str) -> None:
    _require_windows_leaf_name(name)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    set_information = ntdll.NtSetInformationFile
    set_information.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsIoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    set_information.restype = ctypes.c_int32
    encoded_name = name.encode("utf-16-le")
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    root_offset = pointer_size
    length_offset = root_offset + pointer_size
    name_offset = length_offset + ctypes.sizeof(ctypes.c_uint32)
    information = ctypes.create_string_buffer(name_offset + len(encoded_name))
    ctypes.c_ubyte.from_buffer(information, 0).value = 0
    ctypes.c_void_p.from_buffer(information, root_offset).value = root_handle
    ctypes.c_uint32.from_buffer(information, length_offset).value = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(information) + name_offset,
        encoded_name,
        len(encoded_name),
    )
    io_status = _WindowsIoStatusBlock()
    status = int(
        set_information(
            ctypes.c_void_p(os_handle),
            ctypes.byref(io_status),
            information,
            len(information),
            _WINDOWS_FILE_RENAME_INFORMATION,
        )
    )
    if status < 0:
        _raise_windows_ntstatus(status)


def _windows_mark_delete(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    set_information.restype = ctypes.c_int
    information = _WindowsFileDispositionInfo(delete_file=1)
    if not set_information(
        ctypes.c_void_p(handle),
        _WINDOWS_FILE_DISPOSITION_INFO,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise OSError(ctypes.get_last_error(), "secure Windows cleanup failed")


def _raise_windows_ntstatus(status: int) -> NoReturn:
    normalized = status & 0xFFFFFFFF
    if normalized in {
        _WINDOWS_STATUS_OBJECT_NAME_NOT_FOUND,
        _WINDOWS_STATUS_OBJECT_PATH_NOT_FOUND,
    }:
        raise FileNotFoundError(2, "secure relative Windows file open failed")
    if normalized == _WINDOWS_STATUS_OBJECT_NAME_COLLISION:
        raise FileExistsError(80, "secure relative Windows file create collided")
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    translate = ntdll.RtlNtStatusToDosError
    translate.argtypes = [ctypes.c_int32]
    translate.restype = ctypes.c_uint32
    raise OSError(
        int(translate(ctypes.c_int32(status))),
        "secure relative Windows file open failed",
    )


def _require_windows_leaf_name(name: str) -> None:
    if not name or "\x00" in name or "/" in name or "\\" in name or ":" in name:
        raise OSError


def _validate_body(body: bytes) -> None:
    if not isinstance(body, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
        message = "blob body must be bytes"
        raise TypeError(message)


def _validate_media_type(media_type: str) -> None:
    if not isinstance(media_type, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        message = "media_type must be a string"
        raise TypeError(message)
    if not 1 <= len(media_type) <= _MAX_MEDIA_TYPE_LENGTH:
        message = "media_type must contain between 1 and 255 characters"
        raise ValueError(message)


def _integrity_error() -> BlobStoreError:
    return BlobStoreError(
        Diagnostic(
            category=ErrorCategory.ARTIFACT_INTEGRITY_ERROR,
            code=DiagnosticCode("BLOB_INTEGRITY_ERROR"),
            message="A content-addressed blob failed integrity verification.",
            retryable=False,
            safe_details={},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="blobs",
            corrective_action="Re-plan the run bundle from trusted project fixtures.",
        )
    )


def _write_error() -> BlobStoreError:
    return BlobStoreError(
        Diagnostic(
            category=ErrorCategory.PLANNING_ERROR,
            code=DiagnosticCode("BLOB_WRITE_FAILED"),
            message="A content-addressed blob could not be stored safely.",
            retryable=False,
            safe_details={},
            result_category=ResultCategory.ENVIRONMENT_ERROR,
            user_correctable=False,
        )
    )


def _blob_resource_limit_error() -> BlobStoreError:
    return BlobStoreError(
        Diagnostic(
            category=ErrorCategory.RESOURCE_LIMIT,
            code=DiagnosticCode("BLOB_RESOURCE_LIMIT"),
            message="Blob exceeds the hard fixture byte limit.",
            retryable=False,
            safe_details={
                "limit": "max_request_bytes_hard",
                "maximum": HARD_MAX_FIXTURE_BYTES,
            },
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="blobs",
            corrective_action="Reduce the blob to the supported hard request-body limit.",
        )
    )
