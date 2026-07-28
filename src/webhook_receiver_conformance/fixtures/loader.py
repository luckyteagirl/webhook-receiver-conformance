"""Byte-preserving, resource-bounded fixture loading."""
# ruff: noqa: ANN401, INP001, PLC0415, PTH100, TRY301

from __future__ import annotations

import ctypes
import os
import stat
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.errors import Diagnostic, ErrorCategory, ResultCategory
from webhook_receiver_conformance.types import DiagnosticCode, EntityId

if TYPE_CHECKING:
    from typing import Any

    from webhook_receiver_conformance.config.models import FixtureConfig

DEFAULT_MAX_FIXTURE_BYTES: Final = 1_048_576
HARD_MAX_FIXTURE_BYTES: Final = 16_777_216
_READ_CHUNK_BYTES: Final = 65_536
_PATH_FIELD = "fixtures[].path"
_OPEN_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_OPEN_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)
_SAFE_DIRECTORY_OPEN_SUPPORTED: Final = (
    os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
)
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_DEVICE: Final = 0x00000040
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
_WINDOWS_FILE_ATTRIBUTE_TAG_INFO: Final = 9
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
_WINDOWS_FILE_READ_ATTRIBUTES: Final = 0x00000080
_WINDOWS_FILE_SHARE_READ: Final = 0x00000001
_WINDOWS_FILE_SHARE_WRITE: Final = 0x00000002
_WINDOWS_FILE_TYPE_DISK: Final = 0x0001
_WINDOWS_GENERIC_READ: Final = 0x80000000
_WINDOWS_OPEN_EXISTING: Final = 3
_WINDOWS_INVALID_HANDLE: Final = ctypes.c_void_p(-1).value


class _WindowsFileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("reparse_tag", ctypes.c_uint32),
    ]


class _WindowsByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("creation_time_low", ctypes.c_uint32),
        ("creation_time_high", ctypes.c_uint32),
        ("last_access_time_low", ctypes.c_uint32),
        ("last_access_time_high", ctypes.c_uint32),
        ("last_write_time_low", ctypes.c_uint32),
        ("last_write_time_high", ctypes.c_uint32),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


@dataclass(frozen=True, slots=True)
class LoadedFixture:
    """An immutable exact-byte fixture plus manifest-compatible metadata."""

    fixture_id: str
    body: bytes = field(repr=False)
    blob_sha256: str
    byte_length: int
    media_type: str
    source_path: str = field(repr=False)

    @property
    def sha256(self) -> str:
        """Return the fixture body digest."""
        return self.blob_sha256

    def to_manifest_entry(self) -> dict[str, str | int]:
        """Return the fixture-manifest projection without embedding body bytes."""
        return {
            "fixture_id": self.fixture_id,
            "blob_sha256": self.blob_sha256,
            "byte_length": self.byte_length,
            "media_type": self.media_type,
            "source_path": self.source_path,
        }


class FixtureLoadError(Exception):
    """A fixture failure carrying a bounded, privacy-safe diagnostic."""

    diagnostic: Diagnostic

    def __init__(self, diagnostic: Diagnostic) -> None:
        """Initialize the exception without including sensitive paths or bytes."""
        self.diagnostic = diagnostic
        super().__init__(diagnostic.code)


class _NotRegularFixtureError(OSError):
    pass


def load_fixture(
    config: FixtureConfig,
    *,
    project_root: Path,
    max_bytes: int = DEFAULT_MAX_FIXTURE_BYTES,
) -> LoadedFixture:
    """Load one configured fixture as exact bytes from beneath ``project_root``."""
    normalized_path = _normalize_relative_path(config.path, fixture_id=config.id)
    body = _load_fixture_parts(
        project_root,
        normalized_path.parts,
        max_bytes=_validate_max_bytes(max_bytes),
        fixture_id=config.id,
    )
    return LoadedFixture(
        fixture_id=config.id,
        body=body,
        blob_sha256=sha256_digest(body),
        byte_length=len(body),
        media_type=config.media_type,
        source_path=normalized_path.as_posix(),
    )


def load_fixture_bytes(
    project_root: Path,
    relative_path: str,
    *,
    max_bytes: int = DEFAULT_MAX_FIXTURE_BYTES,
) -> bytes:
    """Load exact bytes for a contained relative path without decoding them."""
    normalized_path = _normalize_relative_path(relative_path, fixture_id=None)
    return _load_fixture_parts(
        project_root,
        normalized_path.parts,
        max_bytes=_validate_max_bytes(max_bytes),
        fixture_id=None,
    )


def _load_fixture_parts(
    project_root: Path,
    parts: tuple[str, ...],
    *,
    max_bytes: int,
    fixture_id: str | None,
) -> bytes:
    try:
        root = project_root.absolute() if os.name == "nt" else project_root.resolve(strict=True)
        if os.name != "nt":
            _require_directory(root)
        descriptor = _open_contained_file(root, parts)
    except _NotRegularFixtureError:
        raise _fixture_error(
            code="FIXTURE_NOT_REGULAR",
            message="Fixture path must identify a regular file.",
            fixture_id=fixture_id,
        ) from None
    except FixtureLoadError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise _fixture_error(
            code="FIXTURE_PATH_REJECTED",
            message="Fixture path is not a contained readable regular file.",
            fixture_id=fixture_id,
        ) from None

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _fixture_error(
                code="FIXTURE_NOT_REGULAR",
                message="Fixture path must identify a regular file.",
                fixture_id=fixture_id,
            )
        if metadata.st_size > max_bytes:
            raise _resource_limit_error(max_bytes=max_bytes, fixture_id=fixture_id)
        return _read_bounded(descriptor, max_bytes=max_bytes, fixture_id=fixture_id)
    except FixtureLoadError:
        raise
    except OSError:
        raise _fixture_error(
            code="FIXTURE_READ_FAILED",
            message="Fixture bytes could not be read.",
            fixture_id=fixture_id,
        ) from None
    finally:
        os.close(descriptor)


def _open_contained_file(root: Path, parts: tuple[str, ...]) -> int:
    if os.name == "nt":
        return _open_contained_file_windows(root, parts)
    if _SAFE_DIRECTORY_OPEN_SUPPORTED:
        return _open_contained_file_at(root, parts)
    raise OSError


def _open_contained_file_windows(root: Path, parts: tuple[str, ...]) -> int:
    import msvcrt

    root_handle: int | None = None
    file_handle: int | None = None
    try:
        root_handle = _windows_open_path(root, directory=True)
        actual_root = _windows_final_path(root_handle)
        root_volume = _windows_volume_serial(root_handle)

        candidate = actual_root.joinpath(*parts)
        file_handle = _windows_open_path(candidate, directory=False)
        actual_file = _windows_final_path(file_handle)
        if (
            _windows_volume_serial(file_handle) != root_volume
            or not _same_windows_path(actual_file, candidate)
            or not _windows_path_is_within(actual_file, actual_root)
        ):
            raise OSError

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        descriptor = msvcrt.open_osfhandle(file_handle, flags)
        file_handle = None
        return descriptor
    finally:
        if file_handle is not None:
            _windows_close_handle(file_handle)
        if root_handle is not None:
            _windows_close_handle(root_handle)


def _open_contained_file_at(root: Path, parts: tuple[str, ...]) -> int:
    directory_flags = os.O_RDONLY | _OPEN_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_descriptor = os.open(root, directory_flags)
    try:
        for component in parts[:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_flags = os.O_RDONLY | _OPEN_CLOEXEC | _OPEN_NONBLOCK | os.O_NOFOLLOW
        return os.open(parts[-1], file_flags, dir_fd=directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _read_bounded(
    descriptor: int,
    *,
    max_bytes: int,
    fixture_id: str | None,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        read_size = min(_READ_CHUNK_BYTES, max_bytes - total + 1)
        chunk = os.read(descriptor, read_size)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > max_bytes:
            raise _resource_limit_error(max_bytes=max_bytes, fixture_id=fixture_id)
        chunks.append(chunk)


def _normalize_relative_path(value: str, *, fixture_id: str | None) -> PurePosixPath:
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise _fixture_error(
            code="FIXTURE_PATH_REJECTED",
            message="Fixture path must be a contained relative path.",
            fixture_id=fixture_id,
        )
    native_path = Path(value)
    if (
        not value
        or "\x00" in value
        or native_path.is_absolute()
        or bool(native_path.drive)
        or not native_path.parts
        or any(part in {"", ".", ".."} for part in native_path.parts)
    ):
        raise _fixture_error(
            code="FIXTURE_PATH_REJECTED",
            message="Fixture path must be a contained relative path.",
            fixture_id=fixture_id,
        )
    return PurePosixPath(*native_path.parts)


def _validate_max_bytes(value: int) -> int:
    if type(value) is not int:
        message = "max_bytes must be an integer"
        raise TypeError(message)
    if not 1 <= value <= HARD_MAX_FIXTURE_BYTES:
        message = f"max_bytes must be between 1 and {HARD_MAX_FIXTURE_BYTES}"
        raise ValueError(message)
    return value


def _require_directory(path: Path) -> None:
    if not path.is_dir():
        raise OSError


def _windows_kernel32() -> Any:
    if os.name != "nt":
        raise OSError
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _windows_open_path(path: Path, *, directory: bool) -> int:
    kernel32 = _windows_kernel32()
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    desired_access = (
        _WINDOWS_FILE_READ_ATTRIBUTES
        if directory
        else _WINDOWS_GENERIC_READ | _WINDOWS_FILE_READ_ATTRIBUTES
    )
    share_mode = (
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE
        if directory
        else _WINDOWS_FILE_SHARE_READ
    )
    handle = create_file(
        str(path),
        desired_access,
        share_mode,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle in {None, _WINDOWS_INVALID_HANDLE}:
        raise _safe_windows_os_error()
    integer_handle = int(handle)
    try:
        attributes = _windows_file_attributes(integer_handle)
        if attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError
        if attributes & _WINDOWS_FILE_ATTRIBUTE_DEVICE:
            raise _NotRegularFixtureError
        if directory:
            if not attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
                raise _NotRegularFixtureError
        elif (
            attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY
            or _windows_file_type(integer_handle) != _WINDOWS_FILE_TYPE_DISK
        ):
            raise _NotRegularFixtureError
    except BaseException:
        _windows_close_handle(integer_handle)
        raise
    return integer_handle


def _windows_file_attributes(handle: int) -> int:
    kernel32 = _windows_kernel32()
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    get_information.restype = ctypes.c_int
    information = _WindowsFileAttributeTagInfo()
    succeeded = get_information(
        ctypes.c_void_p(handle),
        _WINDOWS_FILE_ATTRIBUTE_TAG_INFO,
        ctypes.byref(information),
        ctypes.sizeof(information),
    )
    if not succeeded:
        raise _safe_windows_os_error()
    return int(information.file_attributes)


def _windows_file_type(handle: int) -> int:
    kernel32 = _windows_kernel32()
    get_file_type = kernel32.GetFileType
    get_file_type.argtypes = [ctypes.c_void_p]
    get_file_type.restype = ctypes.c_uint32
    return int(get_file_type(ctypes.c_void_p(handle)))


def _windows_final_path(handle: int) -> Path:
    kernel32 = _windows_kernel32()
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    get_final_path.restype = ctypes.c_uint32
    required = int(get_final_path(ctypes.c_void_p(handle), None, 0, 0))
    if required == 0:
        raise _safe_windows_os_error()
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = int(
        get_final_path(
            ctypes.c_void_p(handle),
            buffer,
            len(buffer),
            0,
        )
    )
    if written == 0 or written >= len(buffer):
        raise _safe_windows_os_error()
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _windows_volume_serial(handle: int) -> int:
    kernel32 = _windows_kernel32()
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsByHandleFileInformation),
    ]
    get_information.restype = ctypes.c_int
    information = _WindowsByHandleFileInformation()
    if not get_information(ctypes.c_void_p(handle), ctypes.byref(information)):
        raise _safe_windows_os_error()
    return int(information.volume_serial_number)


def _windows_close_handle(handle: int) -> None:
    kernel32 = _windows_kernel32()
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    with suppress(Exception):
        close_handle(ctypes.c_void_p(handle))


def _safe_windows_os_error() -> OSError:
    return OSError(ctypes.get_last_error(), "secure Windows file operation failed")


def _same_windows_path(first: Path, second: Path) -> bool:
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


def _windows_path_is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate_text = os.path.normcase(os.path.abspath(candidate))
        root_text = os.path.normcase(os.path.abspath(root))
        return os.path.commonpath((candidate_text, root_text)) == root_text
    except (OSError, ValueError):
        return False


def _resource_limit_error(
    *,
    max_bytes: int,
    fixture_id: str | None,
) -> FixtureLoadError:
    return FixtureLoadError(
        Diagnostic(
            category=ErrorCategory.RESOURCE_LIMIT,
            code=DiagnosticCode("FIXTURE_RESOURCE_LIMIT"),
            message="Fixture exceeds the configured request-body byte limit.",
            retryable=False,
            safe_details={"limit": "max_request_bytes", "maximum": max_bytes},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path=_PATH_FIELD,
            entity_id=EntityId(fixture_id) if fixture_id is not None else None,
            corrective_action=(
                "Reduce the fixture size or raise max_request_bytes within its hard cap."
            ),
        )
    )


def _fixture_error(
    *,
    code: str,
    message: str,
    fixture_id: str | None,
) -> FixtureLoadError:
    return FixtureLoadError(
        Diagnostic(
            category=ErrorCategory.FIXTURE_ERROR,
            code=DiagnosticCode(code),
            message=message,
            retryable=False,
            safe_details={},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path=_PATH_FIELD,
            entity_id=EntityId(fixture_id) if fixture_id is not None else None,
            corrective_action="Use a regular fixture file contained beneath the project root.",
        )
    )
