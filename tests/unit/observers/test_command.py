"""Real-process security and protocol tests for TASK-0502."""
# ruff: noqa: INP001, SLF001

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path

import anyio
import pytest

from webhook_receiver_conformance.config.models import CommandObserverConfig
from webhook_receiver_conformance.domain.enums import EvidenceValueType
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.observers import command as command_module
from webhook_receiver_conformance.observers.command import (
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    CommandObserver,
    CommandObserverError,
)
from webhook_receiver_conformance.observers.protocol import (
    ObserverOperation,
    ObserverRequest,
    ObserverResponseStatus,
)

REQUEST_ID = "request_01J00000000000000000000000"
CANARY = "ambient-parent-secret-canary"
_RESPONSE = """{
    "protocol_version": "1.0",
    "request_id": request["request_id"],
    "status": "ok",
    "capabilities": {
        "evidence_types": ["integer"],
        "evidence_keys": ["processing_count"],
        "read_only": True,
        "idempotent": True,
        "max_queries": 64,
        "supports_pending": True,
        "stable_snapshot_ids": True
    },
    "snapshot_id": snapshot,
    "evidence": [],
    "error": None
}"""
_NOMINAL_CODE = (
    "import json,os,sys;"
    "raw=sys.stdin.buffer.read();"
    "assert raw.endswith(b'\\n') and raw.count(b'\\n')==1;"
    "request=json.loads(raw);"
    "assert os.environ['WEBHOOK_CONFORMANCE_REQUEST_ID']==request['request_id'];"
    "assert os.environ['WEBHOOK_CONFORMANCE_PROTOCOL_VERSION']=='1.0';"
    f"assert {CANARY!r} not in os.environ;"
    "snapshot=(sys.argv[1] if len(sys.argv)>1 else 'snapshot-safe');"
    f"print(json.dumps({_RESPONSE}))"
)


def _request() -> ObserverRequest:
    return ObserverRequest.model_validate(
        {
            "protocol_version": "1.0",
            "request_id": REQUEST_ID,
            "operation": ObserverOperation.CAPABILITIES.value,
        }
    )


def _config(
    code: str,
    *,
    arguments: tuple[str, ...] = (),
    timeout: str = "2s",
    working_directory: str | None = None,
    environment_allowlist: tuple[str, ...] = (),
) -> CommandObserverConfig:
    data: dict[str, object] = {
        "type": "command",
        "argv": [sys.executable, "-c", code, *arguments],
        "timeout": timeout,
        "environment_allowlist": list(environment_allowlist),
    }
    if working_directory is not None:
        data["working_directory"] = working_directory
    return CommandObserverConfig.model_validate(data)


def _process_resource_count() -> int | None:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetProcessHandleCount.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        count = wintypes.DWORD()
        assert kernel32.GetProcessHandleCount(kernel32.GetCurrentProcess(), ctypes.byref(count))
        return count.value
    for namespace in (Path("/proc/self/fd"), Path("/dev/fd")):
        if namespace.is_dir():
            return len(tuple(namespace.iterdir()))
    return None


@pytest.mark.anyio
async def test_real_child_receives_one_newline_json_and_returns_typed_response(
    tmp_path: Path,
) -> None:
    observer = CommandObserver(
        _config(_NOMINAL_CODE),
        project_root=tmp_path,
        environ={CANARY: CANARY},
    )

    response = await observer.invoke(_request())

    assert response.status is ObserverResponseStatus.OK
    assert response.request_id == REQUEST_ID
    assert response.capabilities.evidence_types == (EvidenceValueType.INTEGER,)


@pytest.mark.anyio
async def test_metacharacter_argument_is_literal_and_never_invokes_a_shell(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    hostile = f"literal;&|>$({marker})"
    observer = CommandObserver(
        _config(_NOMINAL_CODE, arguments=(hostile,)),
        project_root=tmp_path,
    )

    response = await observer.invoke(_request())

    assert response.snapshot_id == hostile
    assert not marker.exists()


@pytest.mark.anyio
async def test_environment_is_allowlist_plus_correlation_only(tmp_path: Path) -> None:
    code = _NOMINAL_CODE.replace(
        "assert 'ambient-parent-secret-canary' not in os.environ;",
        "assert os.environ['SAFE_VALUE']=='allowed';"
        "assert 'ambient-parent-secret-canary' not in os.environ;",
    )
    observer = CommandObserver(
        _config(code, environment_allowlist=("SAFE_VALUE",)),
        project_root=tmp_path,
        environ={"SAFE_VALUE": "allowed", CANARY: CANARY, "PATH": "forbidden"},
    )

    assert (await observer.invoke(_request())).status is ObserverResponseStatus.OK


@pytest.mark.anyio
@pytest.mark.parametrize(
    "code",
    [
        "print('leading prose')",
        "print('{}');print('{}')",
        "import sys;sys.stdout.buffer.write(b'\\xff')",
    ],
)
async def test_non_single_json_or_invalid_utf8_is_protocol_error(
    tmp_path: Path,
    code: str,
) -> None:
    observer = CommandObserver(_config(code), project_root=tmp_path)

    with pytest.raises(CommandObserverError) as captured:
        await observer.invoke(_request())

    assert captured.value.diagnostic.category is ErrorCategory.OBSERVER_PROTOCOL_ERROR


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            f"import sys;sys.stdout.buffer.write(b'x'*{MAX_STDOUT_BYTES + 1})",
            "OBSERVER_OUTPUT_LIMIT",
        ),
        (
            f"import sys;sys.stderr.buffer.write(b'x'*{MAX_STDERR_BYTES + 1})",
            "OBSERVER_OUTPUT_LIMIT",
        ),
    ],
)
async def test_output_flood_is_bounded_and_classified(
    tmp_path: Path,
    code: str,
    expected: str,
) -> None:
    observer = CommandObserver(_config(code), project_root=tmp_path)

    with pytest.raises(CommandObserverError) as captured:
        await observer.invoke(_request())

    assert str(captured.value.diagnostic.code) == expected
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT


@pytest.mark.anyio
async def test_hanging_child_is_killed_and_classified_timeout(tmp_path: Path) -> None:
    observer = CommandObserver(
        _config("import time;time.sleep(60)", timeout="10ms"),
        project_root=tmp_path,
    )

    with pytest.raises(CommandObserverError) as captured:
        await observer.invoke(_request())

    assert str(captured.value.diagnostic.code) == "OBSERVER_TIMEOUT"
    assert captured.value.diagnostic.category is ErrorCategory.OBSERVER_TIMEOUT


@pytest.mark.anyio
async def test_child_closing_stdin_is_classified_process_failure(tmp_path: Path) -> None:
    observer = CommandObserver(
        _config("import os,time;os.close(0);time.sleep(.1)"),
        project_root=tmp_path,
    )

    with pytest.raises(CommandObserverError) as captured:
        await observer.invoke(_request())

    assert captured.value.diagnostic.category is ErrorCategory.OBSERVER_PROCESS_ERROR


@pytest.mark.anyio
async def test_timeout_kills_descendant_session_before_canary_write(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-canary"
    descendant = (
        f"import time,pathlib;time.sleep(.2);pathlib.Path({str(marker)!r}).write_text('bad')"
    )
    code = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-c',{descendant!r}]);"
        "time.sleep(60)"
    )
    observer = CommandObserver(_config(code, timeout="20ms"), project_root=tmp_path)

    with pytest.raises(CommandObserverError):
        await observer.invoke(_request())
    await anyio.sleep(0.4)

    assert not marker.exists()


def test_working_directory_escape_and_symlink_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(CommandObserverError) as traversal:
        CommandObserver(
            _config(_NOMINAL_CODE, working_directory="../outside"),
            project_root=tmp_path,
        )
    assert str(traversal.value.diagnostic.code) == "OBSERVER_WORKING_DIRECTORY_INVALID"

    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(CommandObserverError):
        CommandObserver(
            _config(_NOMINAL_CODE, working_directory="link"),
            project_root=tmp_path,
        )


@pytest.mark.anyio
async def test_launch_time_directory_swap_cannot_overwrite_external_canary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path.parent / f"{tmp_path.name}-race-outside"
    outside.mkdir()
    canary = outside / "canary"
    canary.write_text("safe", encoding="utf-8")
    probe = (
        "import json,pathlib,sys;"
        "pathlib.Path('canary').write_text('overwritten');"
        "request=json.loads(sys.stdin.buffer.read());"
        f"print(json.dumps({_RESPONSE}))"
    )
    observer = CommandObserver(
        _config(probe, working_directory="work"),
        project_root=tmp_path,
    )
    original = command_module._revalidate_prepared  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def swap_after_validation(prepared: object) -> None:
        nonlocal calls
        original(prepared)  # type: ignore[arg-type]
        calls += 1
        if calls == 1:
            work.rename(tmp_path / "parked")
            try:
                work.symlink_to(outside, target_is_directory=True)
            except OSError:
                pytest.skip("symlink creation unavailable")

    monkeypatch.setattr(command_module, "_revalidate_prepared", swap_after_validation)
    with pytest.raises(CommandObserverError):
        await observer.invoke(_request())

    assert canary.read_text(encoding="utf-8") == "safe"


@pytest.mark.anyio
@pytest.mark.skipif(os.name != "nt", reason="Windows native handle accounting")
async def test_windows_launch_handles_do_not_leak(tmp_path: Path) -> None:
    before = _process_resource_count()
    assert before is not None
    observer = CommandObserver(_config(_NOMINAL_CODE), project_root=tmp_path)
    for _ in range(5):
        await observer.invoke(_request())
    after = _process_resource_count()

    assert after is not None
    assert after <= before + 2


@pytest.mark.anyio
async def test_outer_cancellation_propagates_and_kills_descendant(tmp_path: Path) -> None:
    before = _process_resource_count()
    marker = tmp_path / "cancel-descendant-canary"
    descendant = (
        f"import time,pathlib;time.sleep(.3);pathlib.Path({str(marker)!r}).write_text('bad')"
    )
    code = (
        "import os,subprocess,sys,time;"
        "os.close(0);"
        f"subprocess.Popen([sys.executable,'-c',{descendant!r}]);"
        "time.sleep(60)"
    )
    observer = CommandObserver(_config(code, timeout="10s"), project_root=tmp_path)
    cancellation_seen = anyio.Event()

    async def invoke_until_cancelled() -> None:
        try:
            await observer.invoke(_request())
        except anyio.get_cancelled_exc_class():
            cancellation_seen.set()
            raise

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(invoke_until_cancelled)
        await anyio.sleep(0.1)
        tasks.cancel_scope.cancel()

    assert cancellation_seen.is_set()
    await anyio.sleep(0.5)
    assert not marker.exists()
    after = _process_resource_count()
    if before is not None and after is not None:
        assert after <= before + 2


def test_path_search_is_disabled_without_explicit_name_policy(tmp_path: Path) -> None:
    config = CommandObserverConfig.model_validate(
        {
            "type": "command",
            "argv": ["python", "-c", _NOMINAL_CODE],
            "timeout": "1s",
        }
    )
    with pytest.raises(CommandObserverError) as captured:
        CommandObserver(config, project_root=tmp_path)
    assert str(captured.value.diagnostic.code) == "OBSERVER_PATH_SEARCH_FORBIDDEN"


def test_fd_namespace_supports_dev_fallback_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    available: set[str] = {"/proc/self/fd", "/dev/fd"}

    def is_available(path: Path) -> bool:
        return str(path).replace("\\", "/") in available

    monkeypatch.setattr(Path, "is_dir", is_available)
    assert command_module._select_fd_namespace() == Path("/proc/self/fd")  # pyright: ignore[reportPrivateUsage]

    available.remove("/proc/self/fd")
    assert command_module._select_fd_namespace() == Path("/dev/fd")  # pyright: ignore[reportPrivateUsage]

    available.clear()
    with pytest.raises(CommandObserverError) as captured:
        command_module._select_fd_namespace()  # pyright: ignore[reportPrivateUsage]
    assert str(captured.value.diagnostic.code) == "OBSERVER_FD_LAUNCH_UNSUPPORTED"


@pytest.mark.anyio
async def test_nonzero_stderr_is_never_retained_in_error(tmp_path: Path) -> None:
    code = f"import sys;sys.stderr.write({CANARY!r});sys.exit(7)"
    observer = CommandObserver(_config(code), project_root=tmp_path)

    with pytest.raises(CommandObserverError) as captured:
        await observer.invoke(_request())

    assert CANARY not in str(captured.value)
    assert CANARY not in repr(captured.value)
    assert captured.value.diagnostic.safe_details == {}


def test_source_has_no_shell_or_command_string_execution_path() -> None:
    source = Path("src/webhook_receiver_conformance/observers/command.py").read_text(
        encoding="utf-8"
    )
    assert "shell=True" not in source
    assert "create_subprocess_shell" not in source
    assert "subprocess.run" not in source
    assert "subprocess.Popen" not in source
