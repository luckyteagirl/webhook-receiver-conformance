"""Semantic and subprocess closure tests for TASK-0003."""
# ruff: noqa: INP001, S603
# pyright: reportMissingImports=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers"))
from schema_validation import (
    COMPATIBILITY_BEHAVIOR_MATRIX,
    PERSISTED_ARTIFACT_SCHEMAS,
    VOLATILE_FIELD_CONTRACT,
    CompatibilityDecision,
    SchemaChangeKind,
    compatibility_decision,
    load_json,
    parse_compatibility_matrix,
    validate_persisted_schema_versions,
    validate_volatility_contract,
)

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_TIMEOUT_SECONDS = 30
PACK_DIRECTORIES = ("diagrams", "examples", "machine", "schemas", "specification")


def _load_schemas() -> dict[str, dict[str, Any]]:
    return {
        path.name: cast("dict[str, Any]", load_json(path))
        for path in sorted((ROOT / "schemas").glob("*.schema.json"))
    }


def test_compatibility_document_and_executable_matrix_are_identical() -> None:
    source = (ROOT / "specification" / "16-interfaces-and-contracts.md").read_text(encoding="utf-8")
    assert parse_compatibility_matrix(source) == COMPATIBILITY_BEHAVIOR_MATRIX
    assert (
        compatibility_decision(
            reader_major=1,
            artifact_major=1,
            change_kind=SchemaChangeKind.ADDITIVE_OPTIONAL,
        )
        is CompatibilityDecision.ACCEPT
    )
    assert (
        compatibility_decision(
            reader_major=1,
            artifact_major=2,
            change_kind=SchemaChangeKind.EXACT,
        )
        is CompatibilityDecision.REJECT
    )
    assert (
        compatibility_decision(
            reader_major=1,
            artifact_major=1,
            change_kind=SchemaChangeKind.BREAKING,
        )
        is CompatibilityDecision.REJECT
    )


@pytest.mark.parametrize("schema_name", sorted(VOLATILE_FIELD_CONTRACT))
def test_report_schema_volatility_annotations_are_exact_and_resolvable(
    schema_name: str,
) -> None:
    schema = cast(
        "dict[str, Any]",
        load_json(ROOT / "schemas" / schema_name),
    )
    assert validate_volatility_contract(schema_name, schema) == []

    missing = deepcopy(schema)
    if VOLATILE_FIELD_CONTRACT[schema_name]:
        missing["x-reproducibility"]["volatile_fields"].pop()
        expected_diagnostic = "missing volatile field"
    else:
        missing["x-reproducibility"]["volatile_fields"].append(
            {
                "json_pointer": "/fixtures",
                "category": "environment-observation",
            }
        )
        expected_diagnostic = "unexpected volatile field"
    errors = validate_volatility_contract(schema_name, missing)
    assert any(expected_diagnostic in error for error in errors)


def test_volatility_validator_rejects_wrong_categories_and_unresolved_paths() -> None:
    schema_name = "delivery-record.schema.json"
    schema = cast(
        "dict[str, Any]",
        load_json(ROOT / "schemas" / schema_name),
    )
    malformed = deepcopy(schema)
    fields = malformed["x-reproducibility"]["volatile_fields"]
    fields[0]["category"] = "wall-timestamp"
    fields.append(
        {
            "json_pointer": "/not_a_real_field",
            "category": "environment-observation",
        }
    )
    errors = validate_volatility_contract(schema_name, malformed)
    assert any("unexpected volatile field" in error for error in errors)
    assert any("path does not resolve" in error for error in errors)


def test_persisted_schema_registry_semantically_requires_schema_version() -> None:
    schemas = _load_schemas()
    assert validate_persisted_schema_versions(schemas) == []
    for schema_name in sorted(PERSISTED_ARTIFACT_SCHEMAS):
        mutated = deepcopy(schemas)
        mutated[schema_name]["required"].remove("schema_version")
        assert validate_persisted_schema_versions(mutated) == [
            f"{schema_name}: schema_version must be an explicit required field"
        ]


def test_validator_subprocess_fails_without_leaking_invalid_input(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir()
    for directory in PACK_DIRECTORIES:
        shutil.copytree(ROOT / directory, pack_root / directory)

    canary = "SECRET-CANARY-validator-stderr"
    summary_path = pack_root / "examples" / "result-summary.example.json"
    summary = cast("dict[str, Any]", load_json(summary_path))
    summary["schema_version"] = canary
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_artifacts.py"),
            "--root",
            str(pack_root),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=VALIDATOR_TIMEOUT_SECONDS,
    )
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr
    assert canary not in completed.stderr
    assert "Traceback" not in completed.stderr
