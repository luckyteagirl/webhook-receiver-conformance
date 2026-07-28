import sys
import tomllib
from importlib.metadata import distribution
from pathlib import Path
from typing import cast

import pytest
from tests.helpers.leak_guard import (
    LeakInspectionError,
    SessionLeakGuard,
)

INVALID_PEP_621 = "pyproject.toml must contain a PEP 621 [project] table"
INVALID_PYTHON_RANGE = "requires-python must support CPython 3.12 through 3.14"
PLUGIN_GROUP_DECLARED = "v0.1 must not declare plugin entry-point groups"
SETUP_PY_PRESENT = "setup.py must not be a package metadata source"
UNSUPPORTED_IMPLEMENTATION = "package metadata claims an unsupported Python implementation"
INSTALLED_PLUGIN_ENTRY_POINT = "installed package must not expose plugin entry points"
OWNED_CONSOLE_SCRIPT = (
    "console_scripts",
    "webhook-conformance",
    "webhook_receiver_conformance.cli:run_cli",
)
_LEAK_GUARD_KEY = pytest.StashKey[SessionLeakGuard]()


def _project_metadata() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    document = cast(
        "dict[str, object]",
        tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8")),
    )
    project = document.get("project")
    if not isinstance(project, dict):
        raise pytest.UsageError(INVALID_PEP_621)
    return cast("dict[str, object]", project)


def pytest_configure() -> None:
    root = Path(__file__).resolve().parents[1]
    project = _project_metadata()

    if project.get("requires-python") != ">=3.12,<3.15":
        raise pytest.UsageError(INVALID_PYTHON_RANGE)
    if "entry-points" in project:
        raise pytest.UsageError(PLUGIN_GROUP_DECLARED)
    if (root / "setup.py").exists():
        raise pytest.UsageError(SETUP_PY_PRESENT)

    metadata_text = repr(project).casefold()
    unsupported_claims = ("pypy", "free-threaded", "free threaded")
    if any(claim in metadata_text for claim in unsupported_claims):
        raise pytest.UsageError(UNSUPPORTED_IMPLEMENTATION)

    package = distribution("webhook-receiver-conformance")
    unexpected_entry_points = [
        entry_point
        for entry_point in package.entry_points
        if (entry_point.group, entry_point.name, entry_point.value) != OWNED_CONSOLE_SCRIPT
    ]
    if unexpected_entry_points:
        raise pytest.UsageError(INSTALLED_PLUGIN_ENTRY_POINT)


@pytest.hookimpl(trylast=True)
def pytest_sessionstart(session: pytest.Session) -> None:
    try:
        session.config.stash[_LEAK_GUARD_KEY] = SessionLeakGuard.start()
    except LeakInspectionError as error:
        message = f"test leak guard unavailable: {error}"
        raise pytest.UsageError(message) from error


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus: int | pytest.ExitCode) -> None:
    requested_paths = tuple(Path(str(argument)).name for argument in session.config.args)
    is_foundation_check = requested_paths == ("conftest.py",)
    if is_foundation_check and exitstatus == pytest.ExitCode.NO_TESTS_COLLECTED:
        session.exitstatus = pytest.ExitCode.OK

    guard = session.config.stash.get(_LEAK_GUARD_KEY, None)
    if guard is None:
        return
    try:
        report = guard.finish()
        diagnostics = report.lines()
    except LeakInspectionError as error:
        report = None
        diagnostics = (f"leak inspection failed: {error}",)
    if not diagnostics:
        return

    sys.stderr.write("\nTEST RESOURCE LEAKS\n")
    for diagnostic in diagnostics:
        sys.stderr.write(f"- {diagnostic}\n")
    if report is not None:
        guard.cleanup(report)
    if session.exitstatus in {
        pytest.ExitCode.OK,
        pytest.ExitCode.NO_TESTS_COLLECTED,
    }:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def isolated_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    return home
