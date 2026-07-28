"""Executable crash-matrix coverage and safe-controller contracts."""
# ruff: noqa: EM101, INP001, PLR2004, PT011, S603, TRY003

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]


def _harness() -> ModuleType:
    path = ROOT / "scripts" / "crash_harness.py"
    specification = importlib.util.spec_from_file_location("crash_harness_contract", path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def test_generated_matrix_has_complete_p0_boundary_coverage() -> None:
    module = _harness()
    report = cast("Callable[..., dict[str, object]]", module.build_report)()
    coverage = cast("dict[str, object]", report["coverage"])
    matrix = cast("list[dict[str, object]]", report["matrix"])
    assert coverage == {
        "p0_total": 16,
        "p0_covered": 16,
        "p0_percent": 100,
        "uncovered": [],
    }
    assert all(row["priority"] == "P0" for row in matrix)
    assert all(row["evidence"] for row in matrix)
    assert len({str(row["boundary_id"]) for row in matrix}) == len(matrix)


def test_every_migration_statement_and_ledger_phase_is_covered() -> None:
    report = cast("Callable[..., dict[str, object]]", _harness().build_report)()
    migrations = cast("list[dict[str, object]]", report["migration_failpoints"])
    assert migrations
    point_counts = [cast("int", row["points"]) for row in migrations]
    assert all(points >= 8 for points in point_counts)
    assert sum(point_counts) >= 20


def test_report_install_is_atomic_when_replace_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _harness()
    target = tmp_path / "crash-matrix.json"
    old = b'{"old":"valid"}\n'
    target.write_bytes(old)

    def interrupt(*_arguments: object) -> None:
        raise OSError("simulated power loss")

    monkeypatch.setattr(module.os, "replace", interrupt)
    write_report = cast(
        "Callable[[Path, dict[str, object]], None]",
        module.write_report,
    )
    with pytest.raises(OSError):
        write_report(target, {"new": "complete"})
    assert target.read_bytes() == old
    assert list(tmp_path.glob("*.tmp")) == []


def test_controller_executes_real_evidence_and_exposes_only_hashes() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "crash_harness.py"),
            "--verify",
            "--execute",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=900,
    )
    report = cast("dict[str, object]", json.loads(completed.stdout))
    execution = cast("dict[str, object]", report["execution"])
    assert execution["exit_code"] == 0
    assert cast("int", execution["node_count"]) >= 10
    assert str(execution["stdout_sha256"]).startswith("sha256:")
    assert str(execution["stderr_sha256"]).startswith("sha256:")
    assert "Traceback" not in completed.stdout
    assert "secret" not in completed.stdout.casefold()
