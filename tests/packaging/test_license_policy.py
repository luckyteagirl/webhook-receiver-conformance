"""Offline dependency-license release policy tests."""
# ruff: noqa: INP001, S603

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Mapping

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "validation" / "dependency-license-policy.json"
SCRIPT = ROOT / "scripts" / "release_check.py"
EXPECTED_LOCKED_PACKAGE_COUNT = 38
MALFORMED_INPUT = 2
POLICY_VIOLATION = 3


def test_repository_license_inventory_is_complete_offline_and_deterministic(
    tmp_path: Path,
) -> None:
    output = tmp_path / "license-inventory.json"
    first = _invoke(POLICY, output=output)
    second = _invoke(POLICY)

    assert first.returncode == 0, first.stdout
    assert second.returncode == 0, second.stdout
    assert first.stdout == second.stdout
    document = _document(first.stdout)
    assert document == json.loads(output.read_text(encoding="utf-8"))
    assert document["status"] == "pass"
    assert document["unknown_license_action"] == "deny"
    assert document["package_count"] == EXPECTED_LOCKED_PACKAGE_COUNT
    assert document["scope_counts"] == {
        "build": 0,
        "dev": 14,
        "reference": 10,
        "runtime": 25,
    }
    assert document["unlocked_build_requirement_count"] == 1
    packages = cast("list[Mapping[str, object]]", document["packages"])
    assert len(packages) == document["package_count"]
    assert {package["status"] for package in packages} == {"allowed"}


def test_release_gate_executes_the_offline_license_policy() -> None:
    workflow = ROOT.joinpath(".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "python scripts/release_check.py licenses" in workflow
    assert "--policy validation/dependency-license-policy.json" in workflow
    assert "--output .release/dependency-license-inventory.json" in workflow


def test_license_inventory_rejects_unreviewed_locked_package(tmp_path: Path) -> None:
    policy = _policy_document()
    packages = cast("list[object]", policy["packages"])
    removed = cast("dict[str, object]", packages.pop())
    result = _invoke(_write_policy(tmp_path, policy))

    assert result.returncode == POLICY_VIOLATION
    document = _document(result.stdout)
    assert document["classification"] == "policy_violation"
    assert f"missing {removed['name']}=={removed['version']}" in cast("str", document["message"])


def test_license_inventory_rejects_denylisted_expression(tmp_path: Path) -> None:
    policy = _policy_document()
    allowed = cast("list[str]", policy["allowed_license_expressions"])
    allowed.remove("MIT")
    denied = cast("list[str]", policy["denied_license_expressions"])
    denied.append("MIT")
    denied.sort()
    result = _invoke(_write_policy(tmp_path, policy))

    assert result.returncode == POLICY_VIOLATION
    document = _document(result.stdout)
    assert document["classification"] == "policy_violation"
    assert "denied dependency licenses" in cast("str", document["message"])


def test_license_inventory_fails_closed_for_unknown_expression(tmp_path: Path) -> None:
    policy = _policy_document()
    cast("list[str]", policy["allowed_license_expressions"]).remove("MIT")
    result = _invoke(_write_policy(tmp_path, policy))

    assert result.returncode == POLICY_VIOLATION
    document = _document(result.stdout)
    assert document["classification"] == "policy_violation"
    assert "unknown dependency licenses are denied" in cast("str", document["message"])


def test_license_inventory_rejects_unknown_policy_fields(tmp_path: Path) -> None:
    policy = _policy_document()
    policy["unexpected"] = True
    result = _invoke(_write_policy(tmp_path, policy))

    assert result.returncode == MALFORMED_INPUT
    document = _document(result.stdout)
    assert document["classification"] == "malformed_input"
    assert "fields must be exactly" in cast("str", document["message"])


def _invoke(
    policy: Path,
    *,
    output: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    arguments = [
        sys.executable,
        str(SCRIPT),
        "licenses",
        "--lockfile",
        str(ROOT / "uv.lock"),
        "--project",
        str(ROOT / "pyproject.toml"),
        "--policy",
        str(policy),
    ]
    if output is not None:
        arguments.extend(["--output", str(output)])
    return subprocess.run(
        arguments,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def _policy_document() -> dict[str, object]:
    return cast("dict[str, object]", json.loads(POLICY.read_text(encoding="utf-8")))


def _write_policy(tmp_path: Path, document: Mapping[str, object]) -> Path:
    path = tmp_path / "license-policy.json"
    path.write_text(
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _document(value: str) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(value))
