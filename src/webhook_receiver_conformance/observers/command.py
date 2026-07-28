"""Bounded shell-free command observer adapter."""
# ruff: noqa: D107, EM101, FBT003, INP001, PLC0415, PLR0912, PLR0915, PLR2004, TRY003
# pyright: reportAttributeAccessIssue=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import os
import signal
import stat
import sys
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import anyio
from anyio import EndOfStream

from webhook_receiver_conformance.config.models import CommandObserverConfig
from webhook_receiver_conformance.errors import (
    Diagnostic,
    ErrorCategory,
    ResultCategory,
)
from webhook_receiver_conformance.observers.protocol import (
    MAX_OBSERVER_MESSAGE_BYTES,
    OBSERVER_PROTOCOL_VERSION,
    BuiltinObserverKind,
    Observer,
    ObserverProtocolError,
    ObserverRequest,
    ObserverResponse,
    canonical_observer_wire_bytes,
    parse_observer_response,
    validate_response_for_request,
)
from webhook_receiver_conformance.types import DiagnosticCode

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping, Sequence

    from anyio.abc import ByteReceiveStream, Process

MAX_STDOUT_BYTES: Final = 1_048_576
MAX_STDERR_BYTES: Final = 65_536
MAX_EXECUTABLE_PATH_BYTES: Final = 4096
_NANOSECONDS_PER_SECOND = 1_000_000_000
_CORRELATION_REQUEST_ID = "WEBHOOK_CONFORMANCE_REQUEST_ID"
_CORRELATION_SAMPLE_ID = "WEBHOOK_CONFORMANCE_SAMPLE_ID"
_CORRELATION_PROTOCOL_VERSION = "WEBHOOK_CONFORMANCE_PROTOCOL_VERSION"
_WINDOWS_REPARSE_ATTRIBUTE = 0x400


def _pin_current_interpreter() -> tuple[Path, Path, int, int] | None:
    """Pin the exact active interpreter launcher to its canonical file identity."""
    base_executable = getattr(sys, "_base_executable", None)
    if type(base_executable) is not str or not base_executable:
        return None
    launcher = Path(sys.executable).absolute()
    try:
        target = launcher.resolve(strict=True)
        base_target = Path(base_executable).resolve(strict=True)
        metadata = target.lstat()
    except (OSError, RuntimeError):
        return None
    if (
        target != base_target
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_ATTRIBUTE)
    ):
        return None
    return launcher, target, metadata.st_dev, metadata.st_ino


_CURRENT_INTERPRETER: Final = _pin_current_interpreter()


class CommandObserverError(RuntimeError):
    """A classified failure that never retains command output or environment values."""

    diagnostic: Diagnostic

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.code)


@dataclass(frozen=True, slots=True)
class _PreparedCommand:
    argv: tuple[str, ...]
    project_root: Path
    working_directory: Path
    environment_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _LaunchBinding:
    argv: tuple[str, ...]
    cwd: Path
    pass_fds: tuple[int, ...] = ()
    creationflags: int = 0
    windows_job: int | None = None


class CommandObserver(Observer):
    """Invoke one configured executable through exact argv and bounded pipes."""

    BUILTIN_KIND = BuiltinObserverKind.COMMAND
    __slots__ = ("_environ", "_prepared", "_timeout_ns")

    def __init__(
        self,
        config: CommandObserverConfig,
        *,
        project_root: Path,
        environ: Mapping[str, str] | None = None,
        executable_search_paths: Sequence[Path] = (),
        allowlisted_executable_names: frozenset[str] = frozenset(),
    ) -> None:
        if type(config) is not CommandObserverConfig:
            raise TypeError("config must be a CommandObserverConfig")
        source_environment = os.environ if environ is None else environ
        if not isinstance(project_root, Path):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("project_root must be a pathlib.Path")
        root = _safe_directory(project_root, root=project_root)
        working_directory = (
            root
            if config.working_directory is None
            else _safe_directory(root / config.working_directory, root=root)
        )
        executable = _resolve_executable(
            config.argv[0],
            project_root=root,
            search_paths=executable_search_paths,
            allowlisted_names=allowlisted_executable_names,
        )
        argv = (str(executable), *config.argv[1:])
        environment_names = tuple(config.environment_allowlist or ())
        self._prepared = _PreparedCommand(
            argv=argv,
            project_root=root,
            working_directory=working_directory,
            environment_names=environment_names,
        )
        self._environ = {
            name: source_environment[name]
            for name in environment_names
            if name in source_environment
        }
        self._timeout_ns = config.timeout.nanoseconds

    async def invoke(self, request: ObserverRequest) -> ObserverResponse:  # noqa: C901
        """Execute one request and return its correlated schema-valid response."""
        if type(request) is not ObserverRequest:
            raise TypeError("request must be an ObserverRequest")
        payload = canonical_observer_wire_bytes(request) + b"\n"
        if len(payload) > MAX_OBSERVER_MESSAGE_BYTES + 1:
            raise _resource_error("OBSERVER_INPUT_LIMIT")
        environment = dict(self._environ)
        environment[_CORRELATION_REQUEST_ID] = request.request_id
        environment[_CORRELATION_PROTOCOL_VERSION] = OBSERVER_PROTOCOL_VERSION
        if request.sample_id is not None:
            environment[_CORRELATION_SAMPLE_ID] = request.sample_id
        process: Process | None = None
        binding: _LaunchBinding | None = None
        try:
            with _bound_launch(self._prepared) as binding:
                try:
                    with anyio.fail_after(self._timeout_ns / _NANOSECONDS_PER_SECOND):
                        process = await anyio.open_process(
                            binding.argv,
                            stdin=-1,
                            stdout=-1,
                            stderr=-1,
                            cwd=binding.cwd,
                            env=environment,
                            start_new_session=os.name == "posix",
                            pass_fds=binding.pass_fds,
                            creationflags=binding.creationflags,
                        )
                        if binding.windows_job is not None:
                            _contain_and_resume_windows(process.pid, binding.windows_job)
                        _revalidate_prepared(self._prepared)
                        stdout, _stderr = await _communicate_bounded(process, payload)
                        return_code = await process.wait()
                except TimeoutError as error:
                    raise _timeout_error() from error
            if return_code != 0:
                raise _process_error("OBSERVER_PROCESS_EXIT")
            if not stdout:
                raise _process_error("OBSERVER_PROCESS_IO")
            try:
                response = parse_observer_response(stdout)
                return validate_response_for_request(request, response)
            except ObserverProtocolError as error:
                raise CommandObserverError(error.diagnostic) from None
        except CommandObserverError:
            raise
        except (FileNotFoundError, PermissionError, OSError) as error:
            raise _process_error("OBSERVER_PROCESS_START") from error
        finally:
            if binding is not None and binding.windows_job is not None:
                _terminate_windows_job(binding.windows_job)
                _close_windows_handle(binding.windows_job)
            if process is not None and process.returncode is None:
                with suppress(OSError):
                    _kill_process_tree(process)
                with anyio.move_on_after(1, shield=True):
                    await process.wait()


async def _communicate_bounded(
    process: Process,
    payload: bytes,
) -> tuple[bytes, bytes]:
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise _process_error("OBSERVER_PIPE_UNAVAILABLE")
    stdin = process.stdin
    stdout = process.stdout
    stderr = process.stderr
    stdout_result: list[bytes] = []
    stderr_result: list[bytes] = []

    async def write_stdin() -> None:
        await stdin.send(payload)
        await stdin.aclose()

    async def read_stdout() -> None:
        stdout_result.append(
            await _read_bounded(
                stdout,
                maximum=MAX_STDOUT_BYTES,
                code="OBSERVER_OUTPUT_LIMIT",
            )
        )

    async def read_stderr() -> None:
        stderr_result.append(
            await _read_bounded(
                stderr,
                maximum=MAX_STDERR_BYTES,
                code="OBSERVER_OUTPUT_LIMIT",
            )
        )

    try:
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(write_stdin)
            tasks.start_soon(read_stdout)
            tasks.start_soon(read_stderr)
    except BaseExceptionGroup as errors:
        command_error = _find_command_error(errors)
        if command_error is not None:
            raise command_error from None
        if _contains_cancellation(errors):
            raise
        if _contains_broken_pipe(errors):
            raise _process_error("OBSERVER_PROCESS_IO") from None
        raise
    return stdout_result[0], stderr_result[0]


async def _read_bounded(
    stream: ByteReceiveStream,
    *,
    maximum: int,
    code: str,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = await stream.receive(min(65_536, maximum + 1 - total))
        except EndOfStream:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise _resource_error(code)
    return b"".join(chunks)


def _resolve_executable(
    value: str,
    *,
    project_root: Path,
    search_paths: Sequence[Path],
    allowlisted_names: frozenset[str],
) -> Path:
    if type(value) is not str or not value or len(os.fsencode(value)) > MAX_EXECUTABLE_PATH_BYTES:
        raise _configuration_error("OBSERVER_EXECUTABLE_INVALID")
    candidate = Path(value)
    if candidate.is_absolute():
        return _safe_executable(candidate)
    if candidate.name != value:
        return _safe_executable(project_root / candidate)
    if value not in allowlisted_names:
        raise _configuration_error("OBSERVER_PATH_SEARCH_FORBIDDEN")
    for directory in search_paths:
        if not isinstance(directory, Path):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("executable search paths must contain pathlib.Path values")
        try:
            return _safe_executable(directory / value)
        except CommandObserverError:
            continue
    raise _configuration_error("OBSERVER_EXECUTABLE_NOT_FOUND")


def _safe_executable(path: Path) -> Path:
    absolute = path.absolute()
    try:
        metadata = absolute.lstat()
    except OSError as error:
        raise _configuration_error("OBSERVER_EXECUTABLE_NOT_FOUND") from error
    if os.name == "posix" and stat.S_ISLNK(metadata.st_mode):
        trusted_interpreter = _trusted_interpreter_target(absolute)
        if trusted_interpreter is not None:
            return trusted_interpreter
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_ATTRIBUTE)
    ):
        raise _configuration_error("OBSERVER_EXECUTABLE_INVALID")
    return absolute


def _trusted_interpreter_target(launcher: Path) -> Path | None:
    """Return the pinned target only for this process's unchanged venv launcher."""
    binding = _CURRENT_INTERPRETER
    if binding is None:
        return None
    expected_launcher, expected_target, expected_device, expected_inode = binding
    if launcher != expected_launcher:
        return None
    try:
        target = launcher.resolve(strict=True)
        metadata = target.lstat()
    except (OSError, RuntimeError):
        return None
    if (
        target != expected_target
        or metadata.st_dev != expected_device
        or metadata.st_ino != expected_inode
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_ATTRIBUTE)
    ):
        return None
    return target


def _safe_directory(path: Path, *, root: Path) -> Path:
    absolute_root = root.absolute()
    absolute = path.absolute()
    try:
        resolved_root = absolute_root.resolve(strict=True)
        resolved = absolute.resolve(strict=True)
        metadata = absolute.lstat()
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise _configuration_error("OBSERVER_WORKING_DIRECTORY_INVALID") from error
    if (
        resolved != absolute
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_ATTRIBUTE)
    ):
        raise _configuration_error("OBSERVER_WORKING_DIRECTORY_INVALID")
    return absolute


def _revalidate_prepared(prepared: _PreparedCommand) -> None:
    _safe_executable(Path(prepared.argv[0]))
    _safe_directory(prepared.project_root, root=prepared.project_root)
    _safe_directory(prepared.working_directory, root=prepared.project_root)


@contextmanager
def _bound_launch(prepared: _PreparedCommand) -> Generator[_LaunchBinding]:
    _revalidate_prepared(prepared)
    if os.name == "posix":
        fd_namespace = _select_fd_namespace()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
        executable_fd = os.open(prepared.argv[0], flags)
        directory_fd = os.open(prepared.working_directory, directory_flags)
        try:
            executable_stat = os.fstat(executable_fd)
            directory_stat = os.fstat(directory_fd)
            if not stat.S_ISREG(executable_stat.st_mode) or not stat.S_ISDIR(
                directory_stat.st_mode
            ):
                raise _configuration_error("OBSERVER_LAUNCH_IDENTITY_INVALID")
            yield _LaunchBinding(
                argv=(str(fd_namespace / str(executable_fd)), *prepared.argv[1:]),
                cwd=fd_namespace / str(directory_fd),
                pass_fds=(executable_fd, directory_fd),
            )
        finally:
            os.close(directory_fd)
            os.close(executable_fd)
        return
    if os.name != "nt":
        raise _configuration_error("OBSERVER_FD_LAUNCH_UNSUPPORTED")
    identity_handles: list[int] = []
    try:
        for directory in _windows_launch_directories(prepared):
            identity_handles.append(  # noqa: PERF401
                _open_windows_identity(directory, directory=True)
            )
        identity_handles.append(_open_windows_identity(Path(prepared.argv[0]), directory=False))
        job_handle = _create_windows_job()
        yield _LaunchBinding(
            argv=prepared.argv,
            cwd=prepared.working_directory,
            creationflags=0x00000004,  # CREATE_SUSPENDED
            windows_job=job_handle,
        )
    finally:
        for identity_handle in reversed(identity_handles):
            _close_windows_handle(identity_handle)


def _windows_launch_directories(prepared: _PreparedCommand) -> tuple[Path, ...]:
    directories: dict[Path, None] = {}
    for leaf in (
        prepared.project_root,
        prepared.working_directory,
        Path(prepared.argv[0]).parent,
    ):
        current = leaf
        while True:
            directories[current] = None
            if current.parent == current:
                break
            current = current.parent
    return tuple(directories)


def _select_fd_namespace() -> Path:
    for candidate in (Path("/proc/self/fd"), Path("/dev/fd")):
        if candidate.is_dir():
            return candidate
    raise _configuration_error("OBSERVER_FD_LAUNCH_UNSUPPORTED")


def _find_command_error(
    errors: BaseExceptionGroup[BaseException],
) -> CommandObserverError | None:
    for error in errors.exceptions:
        if isinstance(error, CommandObserverError):
            return error
        if isinstance(error, BaseExceptionGroup):
            nested = _find_command_error(cast("BaseExceptionGroup[BaseException]", error))
            if nested is not None:
                return nested
    return None


def _contains_broken_pipe(errors: BaseExceptionGroup[BaseException]) -> bool:
    for error in errors.exceptions:
        if isinstance(error, (anyio.BrokenResourceError, BrokenPipeError)):
            return True
        if isinstance(error, BaseExceptionGroup) and _contains_broken_pipe(
            cast("BaseExceptionGroup[BaseException]", error)
        ):
            return True
    return False


def _contains_cancellation(errors: BaseExceptionGroup[BaseException]) -> bool:
    cancelled_class = anyio.get_cancelled_exc_class()
    for error in errors.exceptions:
        if isinstance(error, cancelled_class):
            return True
        if isinstance(error, BaseExceptionGroup) and _contains_cancellation(
            cast("BaseExceptionGroup[BaseException]", error)
        ):
            return True
    return False


def _kill_process_tree(process: Process) -> None:
    """Terminate the isolated POSIX session or the direct Windows child."""
    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    else:
        process.kill()


def _windows_kernel32() -> object:
    import ctypes

    return ctypes.WinDLL("kernel32", use_last_error=True)


def _open_windows_identity(path: Path, *, directory: bool) -> int:
    import ctypes
    from ctypes import wintypes

    kernel32 = _windows_kernel32()
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    flags = 0x00200000 | 0x02000000  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
    handle = create_file(
        str(path),
        0x80000000 if not directory else 0,
        0x00000001,  # share read only; deny write/delete replacement through launch
        None,
        3,
        flags,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        raise _configuration_error("OBSERVER_LAUNCH_IDENTITY_INVALID")
    get_attributes = kernel32.GetFileAttributesW
    get_attributes.argtypes = (wintypes.LPCWSTR,)
    get_attributes.restype = wintypes.DWORD
    attributes = get_attributes(str(path))
    if attributes == 0xFFFFFFFF:
        _close_windows_handle(int(handle))
        raise _configuration_error("OBSERVER_LAUNCH_IDENTITY_INVALID")
    if attributes & _WINDOWS_REPARSE_ATTRIBUTE:
        _close_windows_handle(int(handle))
        raise _configuration_error("OBSERVER_LAUNCH_IDENTITY_INVALID")
    return int(handle)


def _create_windows_job() -> int:
    import ctypes
    from ctypes import wintypes

    kernel32 = _windows_kernel32()
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    create_job.restype = wintypes.HANDLE
    handle = create_job(None, None)
    if not handle:
        raise _process_error("OBSERVER_PROCESS_CONTAINMENT")
    set_information = kernel32.SetInformationJobObject
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    set_information.restype = wintypes.BOOL

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("read_operations", ctypes.c_uint64),
            ("write_operations", ctypes.c_uint64),
            ("other_operations", ctypes.c_uint64),
            ("read_bytes", ctypes.c_uint64),
            ("write_bytes", ctypes.c_uint64),
            ("other_bytes", ctypes.c_uint64),
        ]

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("per_process_user_time", ctypes.c_int64),
            ("per_job_user_time", ctypes.c_int64),
            ("limit_flags", wintypes.DWORD),
            ("minimum_working_set", ctypes.c_size_t),
            ("maximum_working_set", ctypes.c_size_t),
            ("active_process_limit", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority_class", wintypes.DWORD),
            ("scheduling_class", wintypes.DWORD),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("basic", BasicLimitInformation),
            ("io", IoCounters),
            ("process_memory_limit", ctypes.c_size_t),
            ("job_memory_limit", ctypes.c_size_t),
            ("peak_process_memory", ctypes.c_size_t),
            ("peak_job_memory", ctypes.c_size_t),
        ]

    information = ExtendedLimitInformation()
    information.basic.limit_flags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not set_information(
        handle,
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        _close_windows_handle(int(handle))
        raise _process_error("OBSERVER_PROCESS_CONTAINMENT")
    return int(handle)


def _contain_and_resume_windows(pid: int, job_handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = _windows_kernel32()
    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    assign_job = kernel32.AssignProcessToJobObject
    assign_job.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    assign_job.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    create_snapshot.restype = wintypes.HANDLE
    open_thread = kernel32.OpenThread
    open_thread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_thread.restype = wintypes.HANDLE
    resume_thread = kernel32.ResumeThread
    resume_thread.argtypes = (wintypes.HANDLE,)
    resume_thread.restype = wintypes.DWORD

    process_handle = open_process(0x0001 | 0x0100 | 0x0400, False, pid)
    if not process_handle:
        raise _process_error("OBSERVER_PROCESS_CONTAINMENT")
    try:
        if not assign_job(job_handle, process_handle):
            raise _process_error("OBSERVER_PROCESS_CONTAINMENT")
    finally:
        close_handle(process_handle)

    class ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    thread_first = kernel32.Thread32First
    thread_first.argtypes = (wintypes.HANDLE, ctypes.POINTER(ThreadEntry32))
    thread_first.restype = wintypes.BOOL
    thread_next = kernel32.Thread32Next
    thread_next.argtypes = (wintypes.HANDLE, ctypes.POINTER(ThreadEntry32))
    thread_next.restype = wintypes.BOOL
    snapshot = create_snapshot(0x00000004, 0)
    invalid = ctypes.c_void_p(-1).value
    if snapshot in (None, invalid):
        raise _process_error("OBSERVER_PROCESS_CONTAINMENT")
    resumed = False
    try:
        entry = ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        available = bool(thread_first(snapshot, ctypes.byref(entry)))
        while available:
            if entry.th32OwnerProcessID == pid:
                thread = open_thread(0x0002, False, entry.th32ThreadID)
                if thread:
                    try:
                        resumed = resume_thread(thread) != 0xFFFFFFFF or resumed
                    finally:
                        close_handle(thread)
            available = bool(thread_next(snapshot, ctypes.byref(entry)))
    finally:
        close_handle(snapshot)
    if not resumed:
        raise _process_error("OBSERVER_PROCESS_CONTAINMENT")


def _terminate_windows_job(job_handle: int) -> None:
    from ctypes import wintypes

    with suppress(Exception):
        terminate = _windows_kernel32().TerminateJobObject
        terminate.argtypes = (wintypes.HANDLE, wintypes.UINT)
        terminate.restype = wintypes.BOOL
        terminate(job_handle, 1)


def _close_windows_handle(handle: int) -> None:
    from ctypes import wintypes

    with suppress(Exception):
        close_handle = _windows_kernel32().CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        close_handle(handle)


def _configuration_error(code: str) -> CommandObserverError:
    return CommandObserverError(
        Diagnostic(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code=DiagnosticCode(code),
            message="The command observer process configuration is unsafe or invalid.",
            retryable=False,
            safe_details={},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="observers",
            corrective_action="Use an explicit safe executable and project-confined directory.",
        )
    )


def _resource_error(code: str) -> CommandObserverError:
    return CommandObserverError(
        Diagnostic(
            category=ErrorCategory.RESOURCE_LIMIT,
            code=DiagnosticCode(code),
            message="The command observer exceeded a bounded process I/O limit.",
            retryable=False,
            safe_details={},
            result_category=ResultCategory.ENVIRONMENT_ERROR,
        )
    )


def _timeout_error() -> CommandObserverError:
    return CommandObserverError(
        Diagnostic(
            category=ErrorCategory.OBSERVER_TIMEOUT,
            code=DiagnosticCode("OBSERVER_TIMEOUT"),
            message="The command observer exceeded its physical timeout.",
            retryable=True,
            safe_details={},
            result_category=ResultCategory.ENVIRONMENT_ERROR,
        )
    )


def _process_error(code: str) -> CommandObserverError:
    return CommandObserverError(
        Diagnostic(
            category=ErrorCategory.OBSERVER_PROCESS_ERROR,
            code=DiagnosticCode(code),
            message="The command observer process failed.",
            retryable=False,
            safe_details={},
            result_category=ResultCategory.ENVIRONMENT_ERROR,
        )
    )


__all__ = ["CommandObserver", "CommandObserverError"]
