"""Focused regression tests for the artifact validator's local rules."""
# ruff: noqa: INP001
# pyright: reportMissingImports=false, reportUnknownVariableType=false

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers"))
import schema_validation as schema_validation_module
from schema_validation import (
    compare_state_transitions,
    load_json,
    parse_state_transitions,
    validate_instance,
)

ROOT = Path(__file__).resolve().parents[2]


def test_persisted_record_requires_schema_version() -> None:
    schema = load_json(ROOT / "schemas" / "delivery-record.schema.json")
    record = {
        "record_id": "record_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "run_id": "run_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "scenario_id": "scenario_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "event_id": "event_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "delivery_id": "delivery_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "attempt_id": "attempt_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "sequence": 1,
        "recorded_at": "2026-07-26T00:00:00Z",
        "state": "scheduled",
        "classification": "planned",
    }
    assert any("schema_version" in message for message in validate_instance(record, schema))


def test_task_index_empty_execution_evidence_is_rejected() -> None:
    schema = load_json(ROOT / "schemas" / "task-index.schema.json")
    task = {
        "task_id": "TASK-0003",
        "title": "test",
        "phase": "phase-00",
        "priority": "P0",
        "objective": "test",
        "requirement_ids": ["TEST-008"],
        "test_ids": ["VT-TEST-008"],
        "dependency_task_ids": [],
        "exclusive_file_ownership": ["tests/schema/**"],
        "allowed_files": ["tests/schema/**"],
        "forbidden_files": [],
        "acceptance_criteria": ["test"],
        "commands_to_run": [],
        "completion_evidence": [],
        "estimated_agent_complexity": "small",
    }
    errors = validate_instance({"schema_version": "1.0", "tasks": [task]}, schema)
    assert any("commands_to_run" in message for message in errors)
    assert any("completion_evidence" in message for message in errors)


def test_state_transition_comparison_detects_each_direction() -> None:
    documented = parse_state_transitions(
        """
        stateDiagram-v2
          planned --> running
          running --> passed
        """
    )
    errors = compare_state_transitions(
        machine_name="scenario",
        documented=documented,
        executable=frozenset({("planned", "running"), ("running", "failed")}),
    )
    assert errors == [
        "scenario: executable transition missing from diagram: running -> failed",
        "scenario: documented transition missing from executable table: running -> passed",
    ]


@settings(max_examples=50, deadline=500)
@given(st.text(max_size=256))
def test_schema_diagnostics_are_bounded_and_do_not_leak_values(generated_text: str) -> None:
    canary = f"SECRET-CANARY[{generated_text}]"
    schema = {
        "type": "object",
        "required": ["schema_version"],
        "properties": {"schema_version": {"const": "1.0"}},
        "additionalProperties": False,
    }
    errors = validate_instance({"schema_version": canary}, schema)
    assert errors == ["schema_version: violates JSON Schema 'const' constraint"]
    assert canary not in errors[0]


def test_artifact_size_limit_is_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(schema_validation_module, "MAX_ARTIFACT_BYTES", 8)
    path = tmp_path / "oversized.json"
    path.write_text('{"x":"too-large"}', encoding="utf-8")
    with pytest.raises(ValueError, match="artifact exceeds 8 byte limit"):
        load_json(path)
