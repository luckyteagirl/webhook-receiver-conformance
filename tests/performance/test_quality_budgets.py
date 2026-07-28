"""Executable P0 performance-budget evidence contract."""
# ruff: noqa: INP001, PLR2004, S603

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, cast

import pytest


@pytest.fixture(scope="session")
def scorecard(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    output = tmp_path_factory.mktemp("performance") / "scorecard.json"
    completed = subprocess.run(
        (sys.executable, "scripts/benchmark.py", "--output", str(output)),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=180,
        text=True,
    )
    assert completed.returncode == 0, (
        f"benchmark failed\nstdout:\n{completed.stdout[-4000:]}\n"
        f"stderr:\n{completed.stderr[-4000:]}"
    )
    return cast("dict[str, Any]", json.loads(output.read_bytes()))


def _evidence(scorecard: dict[str, Any], requirement_id: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for raw in cast("list[object]", scorecard["evidence"]):
        if isinstance(raw, dict):
            item = cast("dict[str, Any]", raw)
            if item.get("requirement_id") == requirement_id:
                matches.append(item)
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize(
    ("requirement_id", "test_id"),
    [
        ("PERF-001", "VT-PERF-001"),
        ("PERF-002", "VT-PERF-002"),
        ("PERF-003", "VT-PERF-003"),
        ("PERF-006", "VT-PERF-006"),
        ("PERF-007", "VT-PERF-007"),
        ("PERF-008", "VT-PERF-008"),
    ],
)
def test_each_p0_budget_has_passing_measured_evidence(
    scorecard: dict[str, Any],
    requirement_id: str,
    test_id: str,
) -> None:
    evidence = _evidence(scorecard, requirement_id)
    assert evidence["test_id"] == test_id
    assert evidence["samples"] >= 1
    assert evidence["observed"] <= evidence["budget"]
    assert evidence["passed"] is True


def test_vt_perf_001_uses_thirty_measured_public_cli_invocations(
    scorecard: dict[str, Any],
) -> None:
    evidence = _evidence(scorecard, "PERF-001")
    assert evidence["samples"] == 30
    assert evidence["metric"] == "warm_startup_p95"


def test_vt_perf_002_locked_planning_corpus_is_offline(
    scorecard: dict[str, Any],
) -> None:
    evidence = _evidence(scorecard, "PERF-002")
    assert "100 events" in evidence["corpus"]
    assert "1,000 attempt" in evidence["corpus"]
    assert evidence["details"]["network_access"] is False
    assert scorecard["network_access"] is False


def test_vt_perf_003_uses_peak_rss_on_the_maximum_planning_corpus(
    scorecard: dict[str, Any],
) -> None:
    evidence = _evidence(scorecard, "PERF-003")
    assert evidence["unit"] == "MiB"
    assert "1,000-event/5,000-attempt" in evidence["corpus"]


def test_vt_perf_006_reports_bounded_per_attempt_growth(
    scorecard: dict[str, Any],
) -> None:
    evidence = _evidence(scorecard, "PERF-006")
    assert evidence["unit"] == "bytes/attempt"
    assert evidence["samples"] == 256
    assert "raw bodies excluded" in evidence["corpus"]


def test_vt_perf_007_regenerates_every_static_report_format(
    scorecard: dict[str, Any],
) -> None:
    evidence = _evidence(scorecard, "PERF-007")
    assert evidence["samples"] == 5
    assert "seven static report artifacts" in evidence["corpus"]


def test_vt_perf_008_closes_in_flight_response_resources(
    scorecard: dict[str, Any],
) -> None:
    evidence = _evidence(scorecard, "PERF-008")
    assert evidence["details"]["response_streams_closed"] is True


def test_vt_test_017_maps_every_p0_budget_to_reproducible_evidence(
    scorecard: dict[str, Any],
) -> None:
    assert scorecard["status"] == "pass"
    assert scorecard["load_test_claim"] is False
    assert scorecard["test_017"] == {
        "requirement_id": "TEST-017",
        "test_id": "VT-TEST-017",
        "p0_budget_count": 6,
        "all_have_reproducible_evidence": True,
    }
    assert len(scorecard["secondary_quality_attribute_diagnostics"]["measurements"]) == 7
