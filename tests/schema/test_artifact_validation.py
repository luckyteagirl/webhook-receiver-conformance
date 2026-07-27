"""Focused regression tests for the artifact validator's local rules."""
# ruff: noqa: INP001
# pyright: reportMissingImports=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

if TYPE_CHECKING:
    from referencing import Registry

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers"))
import schema_validation as schema_validation_module
from schema_validation import (
    EXECUTABLE_TRANSITIONS,
    PERSISTED_ARTIFACT_SCHEMAS,
    build_schema_registry,
    compare_state_transitions,
    compare_transition_triplet,
    is_transition_allowed,
    load_json,
    load_jsonl,
    load_yaml,
    parse_state_transition_tables,
    parse_state_transitions,
    validate_instance,
)

from webhook_receiver_conformance.domain.enums import (
    AssertionState,
    AttemptState,
    DeliveryState,
    EvidenceValueType,
    ObservationState,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.domain.models import AggregateRunOutcome
from webhook_receiver_conformance.errors import ResultCategory

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
MANIFEST_ID = "bdd7360b498b0ce79aa162379249e88a1b8ab01f8875538b05122197046ae4e8"
DEFAULT_CONCURRENCY = 10
MAX_CONCURRENCY = 50
PERSISTED_EXAMPLE_CASES = (
    ("assertion-record.schema.json", "assertions.example.jsonl", True),
    ("delivery-record.schema.json", "deliveries.example.jsonl", True),
    ("fixture-manifest.schema.json", "fixture-manifest.example.json", False),
    ("observation-record.schema.json", "observations.example.jsonl", True),
    ("plugin-metadata.schema.json", "plugin-metadata.example.json", False),
    ("result-summary.schema.json", "result-summary.example.json", False),
    ("run-manifest.schema.json", "run-manifest.example.json", False),
)


def _schema_registry() -> Registry[Any]:
    schemas = [load_json(path) for path in sorted((ROOT / "schemas").glob("*.schema.json"))]
    return build_schema_registry(schemas)


def _minimal_task() -> dict[str, Any]:
    return {
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
        "commands_to_run": ["uv run pytest"],
        "completion_evidence": ["passing tests"],
        "estimated_agent_complexity": "small",
    }


@pytest.mark.parametrize(
    ("schema_name", "example_name", "is_jsonl"),
    PERSISTED_EXAMPLE_CASES,
)
def test_every_persisted_artifact_rejects_missing_schema_version(
    schema_name: str,
    example_name: str,
    *,
    is_jsonl: bool,
) -> None:
    assert {case[0] for case in PERSISTED_EXAMPLE_CASES} == PERSISTED_ARTIFACT_SCHEMAS
    schema = load_json(ROOT / "schemas" / schema_name)
    example_path = ROOT / "examples" / example_name
    instance = load_jsonl(example_path)[0] if is_jsonl else load_json(example_path)
    without_version = deepcopy(instance)
    del without_version["schema_version"]
    errors = validate_instance(without_version, schema, registry=_schema_registry())
    assert any("schema_version" in message for message in errors)


def test_task_index_empty_execution_evidence_is_rejected() -> None:
    schema = load_json(ROOT / "schemas" / "task-index.schema.json")
    task = _minimal_task()
    task["commands_to_run"] = []
    task["completion_evidence"] = []
    errors = validate_instance({"schema_version": "1.0", "tasks": [task]}, schema)
    assert any("commands_to_run" in message for message in errors)
    assert any("completion_evidence" in message for message in errors)


@pytest.mark.parametrize("blank", ["", " ", "\t\r\n"])
@pytest.mark.parametrize("field", ["commands_to_run", "completion_evidence"])
def test_task_index_blank_execution_evidence_is_rejected(field: str, blank: str) -> None:
    schema = load_json(ROOT / "schemas" / "task-index.schema.json")
    task = _minimal_task()
    task[field] = [blank]
    errors = validate_instance({"schema_version": "1.0", "tasks": [task]}, schema)
    assert errors


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


def test_project_config_contract_uses_numeric_v1_and_10_of_50_concurrency() -> None:
    schema = load_json(ROOT / "schemas" / "project-config.schema.json")
    version = schema["properties"]["schema_version"]
    concurrency = schema["properties"]["limits"]["properties"]["max_concurrency"]
    assert version == {"type": "integer", "const": 1}
    assert concurrency["default"] == DEFAULT_CONCURRENCY
    assert concurrency["maximum"] == MAX_CONCURRENCY

    complete = load_yaml(ROOT / "examples" / "project-config.complete.yaml")
    assert validate_instance(complete, schema) == []
    wrong_version = deepcopy(complete)
    wrong_version["schema_version"] = "1.0"
    assert validate_instance(wrong_version, schema)
    excessive = deepcopy(complete)
    excessive["limits"]["max_concurrency"] = 51
    assert validate_instance(excessive, schema)


def test_run_and_manifest_identifiers_use_dedicated_encodings() -> None:
    registry = _schema_registry()
    manifest_schema = load_json(ROOT / "schemas" / "run-manifest.schema.json")
    summary_schema = load_json(ROOT / "schemas" / "result-summary.schema.json")
    manifest = load_json(ROOT / "examples" / "run-manifest.example.json")
    summary = load_json(ROOT / "examples" / "result-summary.example.json")

    assert "run_id" not in manifest
    assert manifest["manifest_id"] == MANIFEST_ID
    assert validate_instance(manifest, manifest_schema, registry=registry) == []
    assert validate_instance(summary, summary_schema, registry=registry) == []
    assert manifest["generator"]["normalized_seed_hash_hex"] == (
        "66018d2afc139a44ea478dd11df81d5ffdd30c12475ba53916e5fa2f76a8c893"
    )

    missing_normalized_seed = deepcopy(manifest)
    del missing_normalized_seed["generator"]["normalized_seed_hash_hex"]
    assert validate_instance(
        missing_normalized_seed,
        manifest_schema,
        registry=registry,
    )

    canonical_projection = deepcopy(manifest)
    del canonical_projection["manifest_id"]
    canonical_bytes = json.dumps(
        canonical_projection,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert hashlib.sha256(canonical_bytes).hexdigest() == MANIFEST_ID

    execution_bound_manifest = deepcopy(manifest)
    execution_bound_manifest["run_id"] = RUN_ID
    assert validate_instance(
        execution_bound_manifest,
        manifest_schema,
        registry=registry,
    )
    old_run = deepcopy(summary)
    old_run["run_id"] = "run_01J00000000000000000000000"
    assert validate_instance(old_run, summary_schema, registry=registry)
    prefixed_manifest = deepcopy(manifest)
    prefixed_manifest["manifest_id"] = f"sha256:{MANIFEST_ID}"
    assert validate_instance(prefixed_manifest, manifest_schema, registry=registry)


def test_manifest_numeric_profile_is_integer_only_and_i_json_safe() -> None:
    registry = _schema_registry()
    schema = load_json(ROOT / "schemas" / "run-manifest.schema.json")
    manifest = load_json(ROOT / "examples" / "run-manifest.example.json")
    safe_limit = (1 << 53) - 1

    safe = deepcopy(manifest)
    delivery = safe["scenarios"][0]["deliveries"][0]
    delivery["logical_time_ns"] = -safe_limit
    delivery["attempt_plan"][0]["not_before_logical_ns"] = safe_limit
    safe["scenarios"][0]["assertions"] = [
        {
            "assertion_id": "assertion_01J00000000000000000000000",
            "type": "numeric-profile",
            "parameters": {"nested": [None, True, -safe_limit, safe_limit]},
        }
    ]
    assert validate_instance(safe, schema, registry=registry) == []

    overflowing = deepcopy(manifest)
    overflowing["scenarios"][0]["deliveries"][0]["logical_time_ns"] = 1 << 53
    assert validate_instance(overflowing, schema, registry=registry)

    fractional = deepcopy(manifest)
    fractional["scenarios"][0]["assertions"][0]["parameters"]["expected"] = 1.5
    assert validate_instance(fractional, schema, registry=registry)


def test_result_summary_verdicts_match_fr006_and_aggregate_model() -> None:
    schema = load_json(ROOT / "schemas" / "result-summary.schema.json")
    schema_values = set(schema["properties"]["verdict"]["enum"])
    assert schema_values == {category.value for category in ResultCategory}
    assert AggregateRunOutcome.model_fields["verdict"].annotation is ResultCategory
    assert "environment_failure" not in schema_values
    assert "harness_failure" not in schema_values


def test_observer_contract_requires_sample_identity_and_exact_evidence_types() -> None:
    registry = _schema_registry()
    request_schema = load_json(ROOT / "schemas" / "observer-request.schema.json")
    response_schema = load_json(ROOT / "schemas" / "observer-response.schema.json")
    evidence_schema = load_json(ROOT / "schemas" / "observer-evidence.schema.json")
    request = load_json(ROOT / "examples" / "observer-request.example.json")
    response = load_json(ROOT / "examples" / "observer-response.example.json")

    assert validate_instance(request, request_schema, registry=registry) == []
    assert validate_instance(response, response_schema, registry=registry) == []
    missing_sample = deepcopy(request)
    del missing_sample["sample_id"]
    assert validate_instance(missing_sample, request_schema, registry=registry)

    capability_types = set(response["capabilities"]["evidence_types"])
    assert capability_types == {value.value for value in EvidenceValueType}
    assert response["capabilities"]["read_only"] is True
    assert response["capabilities"]["idempotent"] is True

    empty_snapshot = deepcopy(response)
    empty_snapshot["snapshot_id"] = ""
    assert validate_instance(empty_snapshot, response_schema, registry=registry)
    assert (
        validate_instance(
            {"key": "amount", "value_type": "decimal-string", "value": "12.50"},
            evidence_schema,
            registry=registry,
        )
        == []
    )
    assert validate_instance(
        {"key": "amount", "value_type": "number", "value": 12.5},
        evidence_schema,
        registry=registry,
    )
    assert (
        validate_instance(
            {
                "key": "body",
                "value_type": "bytes-digest",
                "value": {"sha256": f"sha256:{MANIFEST_ID}", "byte_length": 4},
            },
            evidence_schema,
            registry=registry,
        )
        == []
    )


@pytest.mark.parametrize(
    ("diagram_name", "state_enum"),
    [
        ("run", RunState),
        ("scenario", ScenarioState),
        ("delivery", DeliveryState),
        ("attempt", AttemptState),
        ("observation", ObservationState),
        ("assertion", AssertionState),
    ],
)
def test_state_diagram_vocabularies_match_state_001_through_006(
    diagram_name: str,
    state_enum: type[
        RunState | ScenarioState | DeliveryState | AttemptState | ObservationState | AssertionState
    ],
) -> None:
    transitions = parse_state_transitions(
        (ROOT / "diagrams" / f"state-{diagram_name}.mmd").read_text(encoding="utf-8")
    )
    documented = {state for transition in transitions for state in transition}
    assert documented == {state.value for state in state_enum}


def test_transition_registry_diagrams_and_normative_tables_have_triple_parity() -> None:
    tables = parse_state_transition_tables(
        (ROOT / "specification" / "09-state-machines.md").read_text(encoding="utf-8")
    )
    expected_machines = {
        "run",
        "scenario",
        "delivery",
        "attempt",
        "observation",
        "assertion",
    }
    assert set(tables) == expected_machines
    assert set(EXECUTABLE_TRANSITIONS) == expected_machines
    for name, table in tables.items():
        diagram = parse_state_transitions(
            (ROOT / "diagrams" / f"state-{name}.mmd").read_text(encoding="utf-8")
        )
        assert (
            compare_transition_triplet(
                machine_name=name,
                registry=EXECUTABLE_TRANSITIONS[name],
                diagram=diagram,
                table=table,
            )
            == []
        )
        source, target = min(table)
        assert is_transition_allowed(name, source, target)


def test_transition_triplet_detects_drift_in_each_source() -> None:
    baseline = frozenset({("planned", "running"), ("running", "completed")})
    variants = (
        (frozenset({("planned", "running")}), baseline, baseline, "registry"),
        (baseline, frozenset({("planned", "running")}), baseline, "diagram"),
        (baseline, baseline, frozenset({("planned", "running")}), "table"),
    )
    for registry, diagram, table, changed_source in variants:
        errors = compare_transition_triplet(
            machine_name="run",
            registry=registry,
            diagram=diagram,
            table=table,
        )
        assert errors
        assert any(changed_source in error for error in errors)


def test_superseded_decisions_and_corrected_task_packets_are_machine_visible() -> None:
    decisions = {
        decision["id"]: decision
        for decision in load_yaml(ROOT / "machine" / "decisions.yaml")["decisions"]
    }
    assert decisions["ADR-007"]["status"] == "superseded"
    assert decisions["ADR-007"]["related_or_superseded_adrs"] == ["ADR-004"]
    assert decisions["ADR-006"]["status"] == "superseded"
    assert decisions["ADR-006"]["related_or_superseded_adrs"] == ["ADR-023"]

    tasks = {
        task["task_id"]: task for task in load_yaml(ROOT / "machine" / "task-index.yaml")["tasks"]
    }
    assert tasks["TASK-0003"]["commands_to_run"][0] == (
        "uv run pytest -q tests/schema tests/helpers/schema_validation.py"
    )
    assert tasks["TASK-0103"]["commands_to_run"][0] == (
        "uv run pytest -q tests/unit/determinism/test_generator.py"
    )
    assert "SCHED-019" not in tasks["TASK-0301"]["requirement_ids"]
    assert "VT-SCHED-019" not in tasks["TASK-0301"]["test_ids"]
    assert "ADR-006" not in tasks["TASK-0301"]["adr_ids"]
    assert "schemas/observer-evidence.schema.json" in tasks["TASK-0501"]["exclusive_file_ownership"]
