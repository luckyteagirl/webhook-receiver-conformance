"""Self-tests for session resource-leak detection."""
# ruff: noqa: INP001, S603

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

from tests.helpers.leak_guard import (
    ListenerRecord,
    ProcessIdentity,
    ProcessRecord,
    ProcessTreeInspector,
    ResourceSnapshot,
    compare_snapshots,
)

_ROOT = ProcessIdentity(pid=100, created_at_microseconds=1_000)
_BASELINE_CHILD = ProcessRecord(
    identity=ProcessIdentity(pid=101, created_at_microseconds=1_001),
    name="baseline-helper",
)
_NEW_CHILD = ProcessRecord(
    identity=ProcessIdentity(pid=102, created_at_microseconds=1_002),
    name="test-helper",
)


def _snapshot(
    *,
    children: frozenset[ProcessRecord] = frozenset(),
    listeners: frozenset[ListenerRecord] = frozenset(),
) -> ResourceSnapshot:
    return ResourceSnapshot(
        root=_ROOT,
        children=children,
        listeners=listeners,
    )


def _run_nested_pytest(tmp_path: Path, source: str) -> subprocess.CompletedProcess[str]:
    test_path = tmp_path / "test_intentional_leak.py"
    test_path.write_text(source, encoding="utf-8")
    root = Path(__file__).resolve().parents[2]
    return subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "tests.conftest",
            str(test_path),
        ),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_identical_baseline_is_leak_free() -> None:
    baseline = _snapshot(
        children=frozenset({_BASELINE_CHILD}),
        listeners=frozenset(
            {
                ListenerRecord(
                    owner=_ROOT,
                    family=int(socket.AF_INET),
                    host="127.0.0.1",
                    port=8000,
                )
            }
        ),
    )

    report = compare_snapshots(baseline, baseline)

    assert not report.found
    assert report.lines() == ()


def test_baseline_child_is_an_exact_process_allowlist() -> None:
    baseline = _snapshot(children=frozenset({_BASELINE_CHILD}))
    listener = ListenerRecord(
        owner=_BASELINE_CHILD.identity,
        family=int(socket.AF_INET),
        host="127.0.0.1",
        port=8001,
    )
    final = _snapshot(
        children=frozenset({_BASELINE_CHILD}),
        listeners=frozenset({listener}),
    )

    report = compare_snapshots(baseline, final)

    assert not report.found


def test_new_child_and_its_listener_are_reported() -> None:
    listener = ListenerRecord(
        owner=_NEW_CHILD.identity,
        family=int(socket.AF_INET6),
        host="::1",
        port=8002,
    )
    final = _snapshot(
        children=frozenset({_NEW_CHILD}),
        listeners=frozenset({listener}),
    )

    report = compare_snapshots(_snapshot(), final)

    assert report.processes == (_NEW_CHILD,)
    assert report.listeners == (listener,)
    assert report.lines() == (
        "child process pid=102 name='test-helper'",
        "listening socket pid=102 address=[::1]:8002",
    )


def test_new_listener_on_pytest_process_is_reported() -> None:
    listener = ListenerRecord(
        owner=_ROOT,
        family=int(socket.AF_INET),
        host="127.0.0.1",
        port=8003,
    )

    report = compare_snapshots(
        _snapshot(),
        _snapshot(listeners=frozenset({listener})),
    )

    assert report.processes == ()
    assert report.listeners == (listener,)


def test_real_inspector_detects_and_releases_current_process_listener() -> None:
    inspector = ProcessTreeInspector()
    baseline = inspector.capture()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        report = compare_snapshots(baseline, inspector.capture())
        bound_port = listener.getsockname()[1]

        assert any(item.port == bound_port for item in report.listeners)

    assert not compare_snapshots(baseline, inspector.capture()).found


def test_real_inspector_detects_and_releases_child_process() -> None:
    inspector = ProcessTreeInspector()
    baseline = inspector.capture()
    process = subprocess.Popen(
        (sys.executable, "-c", "import time; time.sleep(30)"),
    )
    try:
        report = compare_snapshots(baseline, inspector.capture())

        assert any(item.identity.pid == process.pid for item in report.processes)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    assert not compare_snapshots(baseline, inspector.capture()).found


def test_pytest_session_fails_for_leaked_listener(tmp_path: Path) -> None:
    result = _run_nested_pytest(
        tmp_path,
        (
            "import socket\n"
            "\n"
            "LISTENER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "LISTENER.bind(('127.0.0.1', 0))\n"
            "LISTENER.listen()\n"
            "\n"
            "def test_listener_remains_open():\n"
            "    assert LISTENER.fileno() >= 0\n"
        ),
    )

    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "TEST RESOURCE LEAKS" in result.stderr
    assert "listening socket" in result.stderr


def test_pytest_session_fails_and_cleans_up_leaked_child(tmp_path: Path) -> None:
    result = _run_nested_pytest(
        tmp_path,
        (
            "import subprocess\n"
            "import sys\n"
            "\n"
            "PROCESS = subprocess.Popen(\n"
            "    (sys.executable, '-c', 'import time; time.sleep(30)'),\n"
            ")\n"
            "\n"
            "def test_child_remains_running():\n"
            "    assert PROCESS.poll() is None\n"
        ),
    )

    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "TEST RESOURCE LEAKS" in result.stderr
    assert "child process" in result.stderr
