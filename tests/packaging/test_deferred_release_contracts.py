"""Release-readiness regressions for explicitly deferred v0.1 capabilities."""
# ruff: noqa: INP001

from __future__ import annotations

import ast
import json
import tomllib
from importlib.metadata import distribution
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
import yaml

if TYPE_CHECKING:
    from collections.abc import Mapping

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_CATEGORIES = (
    "assertion",
    "lifecycle",
    "mutation",
    "observer",
    "reporter",
    "signer",
)
OWNED_CONSOLE_SCRIPT = (
    "console_scripts",
    "webhook-conformance",
    "webhook_receiver_conformance.cli:run_cli",
)
FORBIDDEN_EXTERNAL_DEPENDENCY_PREFIXES = (
    "asyncpg",
    "confluent-kafka",
    "kafka-python",
    "kombu",
    "mysqlclient",
    "opentelemetry",
    "oracledb",
    "pika",
    "prometheus-client",
    "psycopg",
    "pymongo",
    "pymysql",
    "pyodbc",
    "redis",
    "sqlalchemy",
)
EXPECTED_DEFERRED_OBSERVER_ADRS = 2


def _pyproject() -> Mapping[str, object]:
    document = cast(
        "dict[str, object]",
        tomllib.loads(ROOT.joinpath("pyproject.toml").read_text(encoding="utf-8")),
    )
    return cast("Mapping[str, object]", document["project"])


def _lock_package_names() -> frozenset[str]:
    document = cast(
        "dict[str, object]",
        tomllib.loads(ROOT.joinpath("uv.lock").read_text(encoding="utf-8")),
    )
    packages = cast("list[dict[str, object]]", document["package"])
    return frozenset(cast("str", package["name"]).casefold() for package in packages)


def _production_sources() -> tuple[Path, ...]:
    package = ROOT / "src" / "webhook_receiver_conformance"
    return tuple(sorted(package.rglob("*.py")))


def _imported_modules(path: Path) -> frozenset[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return frozenset(imported)


def _is_forbidden_dependency(name: str) -> bool:
    normalized = name.casefold().replace("_", "-")
    return any(
        normalized == prefix or normalized.startswith(f"{prefix}-")
        for prefix in FORBIDDEN_EXTERNAL_DEPENDENCY_PREFIXES
    )


def test_plugin_metadata_has_required_experimental_stability_enum() -> None:
    schema = cast(
        "dict[str, object]",
        json.loads(
            ROOT.joinpath("schemas/plugin-metadata.schema.json").read_text(encoding="utf-8")
        ),
    )
    properties = cast("Mapping[str, object]", schema["properties"])
    stability = cast("Mapping[str, object]", properties["stability"])
    category = cast("Mapping[str, object]", properties["category"])
    required = cast("list[str]", schema["required"])

    assert stability == {"enum": ["experimental"]}
    assert "stability" in required
    assert set(cast("list[str]", category["enum"])) == set(PLUGIN_CATEGORIES)


@pytest.mark.parametrize("category", PLUGIN_CATEGORIES)
def test_every_plugin_category_has_no_entry_point_or_runtime_discovery(
    category: str,
) -> None:
    project = _pyproject()
    assert "entry-points" not in project

    package_entry_points = {
        (entry_point.group, entry_point.name, entry_point.value)
        for entry_point in distribution("webhook-receiver-conformance").entry_points
    }
    assert package_entry_points == {OWNED_CONSOLE_SCRIPT}
    assert not any(category in group.casefold() for group, _name, _value in package_entry_points)

    for path in _production_sources():
        source = path.read_text(encoding="utf-8")
        assert "importlib.metadata" not in source
        assert "entry_points(" not in source
        assert "import_module(" not in source
        assert "iter_modules(" not in source


def test_core_and_lock_have_no_external_database_telemetry_or_queue_drivers() -> None:
    project = _pyproject()
    dependencies = cast("list[str]", project["dependencies"])
    direct_names = {
        dependency.split("[", 1)[0].split(";", 1)[0].split(">", 1)[0].split("=", 1)[0].strip()
        for dependency in dependencies
    }
    locked_names = _lock_package_names()

    assert "sqlite3" not in direct_names
    assert not {name for name in direct_names if _is_forbidden_dependency(name)}
    assert not {name for name in locked_names if _is_forbidden_dependency(name)}

    imported = {module for path in _production_sources() for module in _imported_modules(path)}
    assert "sqlite3" in imported
    assert not {module for module in imported if _is_forbidden_dependency(module.split(".", 1)[0])}


def test_default_dependency_and_lock_graph_exclude_http2() -> None:
    dependencies = cast("list[str]", _pyproject()["dependencies"])
    locked_names = _lock_package_names()

    assert not any(dependency.casefold().startswith("h2") for dependency in dependencies)
    assert {"h2", "hpack", "hyperframe"}.isdisjoint(locked_names)
    assert 'protocol_version = "HTTP/1.1"' in ROOT.joinpath(
        "tests/e2e/test_vertical_slice.py"
    ).read_text(encoding="utf-8")


def test_deferred_roadmap_names_enabling_adrs_prerequisites_and_future_tests() -> None:
    roadmap = ROOT.joinpath("specification/27-roadmap-and-milestones.md").read_text(
        encoding="utf-8"
    )

    assert "superseding ADR to ADR-024 is the enabling ADR" in roadmap
    assert "official and golden" in roadmap
    assert "malformed and wrong-key" in roadmap
    assert roadmap.count("superseding ADR to ADR-010") == EXPECTED_DEFERRED_OBSERVER_ADRS
    assert "optional driver boundary isolated" in roadmap
    assert "optional client-library boundary isolated" in roadmap
    assert roadmap.count("from core dependencies") >= EXPECTED_DEFERRED_OBSERVER_ADRS
    assert "timeout and cancellation" in roadmap
    assert "do not authorize placeholder adapters" in roadmap
    assert "runtime discovery in v0.1" in roadmap


def test_release_publish_job_has_every_required_dag_prerequisite() -> None:
    workflow = cast(
        "dict[str, object]",
        yaml.safe_load(ROOT.joinpath(".github/workflows/release.yml").read_text(encoding="utf-8")),
    )
    jobs = cast("Mapping[str, Mapping[str, object]]", workflow["jobs"])
    needs = {name: set(cast("list[str]", job.get("needs", []))) for name, job in jobs.items()}

    assert needs["package-smoke"] == {"release-policy", "lint", "typing", "tests", "schema"}
    assert needs["security-scan"] == {"release-policy", "package-smoke", "image"}
    assert needs["sbom"] == {"release-policy", "package-smoke", "image"}
    assert needs["provenance"] == {
        "release-policy",
        "package-smoke",
        "image",
        "security-scan",
        "sbom",
    }
    assert needs["publish"] == {
        "release-policy",
        "lint",
        "typing",
        "tests",
        "schema",
        "package-smoke",
        "image",
        "security-scan",
        "sbom",
        "provenance",
    }


def test_stable_release_mutation_gate_is_explicit_and_v0_1_is_deferred() -> None:
    checklist = " ".join(
        ROOT.joinpath("checklists/release-readiness.md").read_text(encoding="utf-8").split()
    )

    assert "stable 1.0 release" in checklist
    assert "90% killed-or-timeout mutants" in checklist
    assert "journal/state transition" in checklist
    assert "destination-policy and public-preflight" in checklist
    assert "signature" in checklist
    assert "report-redaction" in checklist
    assert "equivalent" in checklist
    assert "additional-test-required" in checklist
    assert "accepted-low-impact" in checklist
    assert "Unreviewed survivors fail the gate." in checklist
    assert "Version 0.1.0 may record this stable-1.0 gate as deferred" in checklist
    assert "may not mark it as executed" in checklist
