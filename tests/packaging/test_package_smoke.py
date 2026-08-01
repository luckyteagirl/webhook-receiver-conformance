"""Cross-platform build artifact and workflow smoke contracts."""
# ruff: noqa: INP001, S603, S607

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
import yaml

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from http.server import ThreadingHTTPServer
    from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]


def _smoke_module() -> ModuleType:
    path = ROOT / "scripts" / "package_smoke.py"
    specification = importlib.util.spec_from_file_location("package_smoke_contract", path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_workflow_covers_every_supported_platform_and_python() -> None:
    workflow = cast(
        "dict[str, object]",
        yaml.safe_load(
            ROOT.joinpath(".github/workflows/package-test.yml").read_text(encoding="utf-8")
        ),
    )
    jobs = cast("Mapping[str, object]", workflow["jobs"])
    job = cast("Mapping[str, object]", jobs["package-smoke"])
    strategy = cast("Mapping[str, object]", job["strategy"])
    matrix = cast("Mapping[str, list[str]]", strategy["matrix"])
    assert matrix["os"] == ["ubuntu-24.04", "macos-14", "windows-2025"]
    assert matrix["python"] == ["3.12", "3.13", "3.14"]
    assert "continue-on-error" not in job
    text = ROOT.joinpath(".github/workflows/package-test.yml").read_text(encoding="utf-8")
    assert "pipx==1.7.1" in text
    assert "--exercise-runners" in text
    assert (
        "--expected-digest sha256:66c361e5c82d111575e14811d86e3ed7f03eb3a13018aa4d5d5c30ac26681e35"
    ) in text
    assert "@11bd71901bbe5b1630ceea73d27597364c9af683" in text
    assert "@42375524e23c412d93fb67b49958b491fce71c38" in text


def test_normalized_digest_ignores_only_declared_platform_fields() -> None:
    module = _smoke_module()
    digest = cast("Callable[[Mapping[str, object]], str]", module.normalized_manifest_digest)
    first = {
        "created_at": "one",
        "environment": {"os": "windows"},
        "manifest_id": "one",
        "path": r"fixtures\event.json",
        "tool": {"python": "3.12.1", "version": "0.1.0"},
        "value": 7,
    }
    second = {
        **first,
        "created_at": "two",
        "environment": {"os": "linux"},
        "manifest_id": "two",
        "path": "fixtures/event.json",
        "tool": {"python": "3.14.0", "version": "0.1.0"},
    }
    changed = {**second, "value": 8}
    assert digest(first) == digest(second)
    assert digest(first) != digest(changed)


def test_smoke_server_rejects_reused_listener_address() -> None:
    module = _smoke_module()
    server_type = cast("type[ThreadingHTTPServer]", module._SmokeServer)  # noqa: SLF001
    assert server_type.allow_reuse_address is False


@pytest.fixture(scope="module")
def distributions() -> tuple[Path, Path]:
    subprocess.run(
        ["uv", "build", "--no-sources"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return (
        ROOT / "dist" / "webhook_receiver_conformance-0.1.0-py3-none-any.whl",
        ROOT / "dist" / "webhook_receiver_conformance-0.1.0.tar.gz",
    )


def test_wheel_and_sdist_include_cli_and_runtime_assets(
    distributions: tuple[Path, Path],
) -> None:
    wheel, source = distributions
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = set(archive.namelist())
    with tarfile.open(source, "r:gz") as archive:
        source_names = set(archive.getnames())
    assert any(name.endswith(".dist-info/entry_points.txt") for name in wheel_names)
    assert any(name.endswith(".dist-info/licenses/LICENSE") for name in wheel_names)
    assert any(name.endswith("/cli/main.py") for name in wheel_names)
    assert any(name.endswith("/reporting/templates/report.html") for name in wheel_names)
    assert any(name.endswith("/cli/main.py") for name in source_names)
    assert any(name.endswith("/LICENSE") for name in source_names)
    assert not any("/validation/" in name for name in source_names)
    assert not any("/machine/" in name for name in source_names)
    assert not any("/specification/" in name for name in source_names)
    assert not any("/tasks/" in name for name in source_names)


def test_built_wheel_installs_and_runs_minimal_local_example(
    distributions: tuple[Path, Path],
) -> None:
    wheel, _source = distributions
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "package_smoke.py"),
            "--artifact",
            str(wheel),
            "--python",
            f"{sys.version_info.major}.{sys.version_info.minor}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=300,
    )
    assert '"status":"pass"' in completed.stdout
