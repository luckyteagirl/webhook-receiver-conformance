"""Deterministic validation of the repository's authoritative artifact pack."""
# ruff: noqa: INP001

from __future__ import annotations

import argparse
import csv
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from jsonschema import Draft202012Validator

if TYPE_CHECKING:
    from referencing import Registry

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.helpers.schema_validation import (  # noqa: E402
    MAX_ARTIFACT_BYTES,
    build_schema_registry,
    compare_state_transitions,
    load_json,
    load_jsonl,
    load_yaml,
    parse_state_transition_tables,
    parse_state_transitions,
    validate_instance,
)

MAPPINGS: dict[str, str] = {
    "observer-request.example.json": "observer-request.schema.json",
    "observer-response.example.json": "observer-response.schema.json",
    "plugin-metadata.example.json": "plugin-metadata.schema.json",
    "project-config.complete.yaml": "project-config.schema.json",
    "project-config.minimal.yaml": "project-config.schema.json",
    "result-summary.example.json": "result-summary.schema.json",
    "run-manifest.example.json": "run-manifest.schema.json",
    "fixture-manifest.example.json": "fixture-manifest.schema.json",
}
JSONL_MAPPINGS = {
    "deliveries.example.jsonl": "delivery-record.schema.json",
    "observations.example.jsonl": "observation-record.schema.json",
    "assertions.example.jsonl": "assertion-record.schema.json",
}


def validate_pack(root: Path = ROOT) -> list[str]:
    """Validate all currently materialized artifacts; never mutate inputs."""
    errors: list[str] = []
    schemas: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "schemas").glob("*.schema.json")):
        try:
            schema = load_json(path)
            Draft202012Validator.check_schema(schema)
            schemas[path.name] = schema
        except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
            errors.append(f"{path.relative_to(root)}: invalid JSON Schema: {exc}")
    registry = build_schema_registry(schemas.values())

    for filename, schema_name in sorted(MAPPINGS.items()):
        path = root / "examples" / filename
        try:
            instance = load_yaml(path) if path.suffix in {".yaml", ".yml"} else load_json(path)
            errors.extend(
                f"{path.relative_to(root)}: {message}"
                for message in validate_instance(
                    instance,
                    schemas[schema_name],
                    registry=registry,
                )
            )
        except (OSError, UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")
    for filename, schema_name in sorted(JSONL_MAPPINGS.items()):
        path = root / "examples" / filename
        try:
            for number, instance in enumerate(load_jsonl(path), 1):
                errors.extend(
                    f"{path.relative_to(root)}:{number}: {message}"
                    for message in validate_instance(
                        instance,
                        schemas[schema_name],
                        registry=registry,
                    )
                )
        except (OSError, UnicodeDecodeError, ValueError, KeyError) as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")

    xml_path = root / "examples" / "junit.example.xml"
    try:
        if xml_path.stat().st_size > MAX_ARTIFACT_BYTES:
            message = "artifact exceeds size limit"
            errors.append(f"{xml_path.relative_to(root)}: invalid XML: {message}")
        else:
            ET.parse(xml_path)  # noqa: S314
    except (OSError, ET.ParseError) as exc:
        errors.append(f"{xml_path.relative_to(root)}: invalid XML: {exc}")
    errors.extend(_validate_task_index_schema(root, schemas, registry))
    errors.extend(_cross_references(root))
    errors.extend(_traceability_parity(root))
    errors.extend(_state_diagram_syntax(root))
    errors.extend(_state_table_diagram_parity(root))
    errors.extend(_documentation_checks(root))
    return sorted(set(errors))


def _validate_task_index_schema(
    root: Path,
    schemas: dict[str, dict[str, Any]],
    registry: Registry[Any],
) -> list[str]:
    path = root / "machine" / "task-index.yaml"
    try:
        instance = load_yaml(path)
        schema = schemas["task-index.schema.json"]
        return [
            f"{path.relative_to(root)}: {message}"
            for message in validate_instance(instance, schema, registry=registry)
        ]
    except (OSError, UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
        return [f"{path.relative_to(root)}: {exc}"]


def _cross_references(root: Path) -> list[str]:
    errors: list[str] = []
    requirements = load_yaml(root / "machine" / "requirements.yaml")
    decisions = load_yaml(root / "machine" / "decisions.yaml")
    tasks = load_yaml(root / "machine" / "task-index.yaml")
    requirement_ids = {item.get("id") for item in requirements.get("requirements", [])}
    adr_ids = {item.get("id") for item in decisions.get("decisions", [])}
    task_ids = {item.get("task_id") for item in tasks.get("tasks", [])}
    test_ids = set(
        re.findall(
            r"VT-[A-Z]+-\d{3}", (root / "machine" / "traceability.csv").read_text(encoding="utf-8")
        )
    )
    for task in tasks.get("tasks", []):
        label = task.get("task_id", "<unknown task>")
        for field, known in (
            ("requirement_ids", requirement_ids),
            ("adr_ids", adr_ids),
            ("dependency_task_ids", task_ids),
            ("blocks_task_ids", task_ids),
            ("test_ids", test_ids),
        ):
            for value in task.get(field, []):
                if value not in known:
                    errors.extend(
                        [f"machine/task-index.yaml:{label}.{field}: unknown reference {value}"]
                    )
        for field in ("commands_to_run", "completion_evidence"):
            if not task.get(field):
                errors.extend([f"machine/task-index.yaml:{label}.{field}: must not be empty"])
    return errors


def _traceability_parity(root: Path) -> list[str]:
    """Require the JSON and CSV traceability projections to contain identical rows."""
    json_path = root / "machine" / "traceability.json"
    csv_path = root / "machine" / "traceability.csv"
    try:
        document_value = cast("object", load_json(json_path))
        if not isinstance(document_value, dict):
            return [f"{json_path.relative_to(root)}: document must be an object"]
        document = cast("dict[str, object]", document_value)
        links_value = document.get("links")
        if not isinstance(links_value, list):
            return [f"{json_path.relative_to(root)}: links must be an array"]
        links = cast("list[object]", links_value)
        json_rows = {
            _traceability_row(cast("dict[str, object]", link))
            for link in links
            if isinstance(link, dict)
        }
        with csv_path.open(encoding="utf-8", newline="") as stream:
            csv_rows = {
                tuple(row.get(field, "") for field in _TRACEABILITY_FIELDS)
                for row in csv.DictReader(stream)
            }
    except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
        return [f"machine/traceability: {exc}"]
    diagnostics: list[str] = []
    if len(json_rows) != len(links):
        diagnostics.append("machine/traceability.json: every link must be an object")
    if json_rows != csv_rows:
        diagnostics.append("machine/traceability: JSON and CSV rows differ")
    return diagnostics


_TRACEABILITY_FIELDS = (
    "stakeholder_ids",
    "goal_ids",
    "use_case_ids",
    "requirement_id",
    "architecture_element_ids",
    "interface_schema_or_state_ids",
    "adr_ids",
    "task_id",
    "test_id",
    "evidence_artifact",
)
_TRACEABILITY_LIST_FIELDS = frozenset(
    {
        "stakeholder_ids",
        "goal_ids",
        "use_case_ids",
        "architecture_element_ids",
        "interface_schema_or_state_ids",
        "adr_ids",
    }
)


def _traceability_row(link: dict[str, object]) -> tuple[str, ...]:
    values: list[str] = []
    for field in _TRACEABILITY_FIELDS:
        value = link.get(field, "")
        if field in _TRACEABILITY_LIST_FIELDS:
            values.append(
                ";".join(str(item) for item in cast("list[object]", value))
                if isinstance(value, list)
                else ""
            )
        else:
            values.append(str(value))
    return tuple(values)


def _state_diagram_syntax(root: Path) -> list[str]:
    """Ensure every normative state diagram contains named, parseable transitions."""
    diagnostics: list[str] = []
    for path in sorted((root / "diagrams").glob("state-*.mmd")):
        try:
            transitions = parse_state_transitions(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            diagnostics.append(f"{path.relative_to(root)}: {exc}")
            continue
        if not transitions:
            diagnostics.append(f"{path.relative_to(root)}: no named state transitions")
    return diagnostics


def _state_table_diagram_parity(root: Path) -> list[str]:
    """Require specification/09 legal-exit tables and Mermaid edges to match."""
    specification_path = root / "specification" / "09-state-machines.md"
    try:
        tables = parse_state_transition_tables(specification_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        return [f"{specification_path.relative_to(root)}: {exc}"]
    diagnostics: list[str] = []
    expected_names = {"run", "scenario", "delivery", "attempt", "observation", "assertion"}
    diagnostics.extend(
        [
            f"{specification_path.relative_to(root)}: missing {missing_name} transition table"
            for missing_name in sorted(expected_names - tables.keys())
        ]
    )
    for name in sorted(expected_names & tables.keys()):
        diagram_path = root / "diagrams" / f"state-{name}.mmd"
        try:
            diagram = parse_state_transitions(diagram_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            diagnostics.append(f"{diagram_path.relative_to(root)}: {exc}")
            continue
        diagnostics.extend(
            compare_state_transitions(
                machine_name=name,
                documented=diagram,
                executable=tables[name],
            )
        )
    return diagnostics


def _documentation_checks(root: Path) -> list[str]:
    determinism = (
        (root / "specification" / "12-scheduler-and-determinism.md")
        .read_text(encoding="utf-8")
        .lower()
    )
    requirements = (
        (root / "specification" / "05-product-requirements.md").read_text(encoding="utf-8").lower()
    )
    report = (
        (root / "specification" / "20-observability-and-reporting.md")
        .read_text(encoding="utf-8")
        .lower()
    )
    checks = (
        ("run_id", determinism + requirements + report),
        ("wall", determinism),
        ("duration", determinism),
        ("environment", determinism),
        ("same-major", requirements),
        ("unknown major", requirements),
        ("volatile", requirements + report),
    )
    return [
        f"documentation: missing compatibility/volatility annotation '{term}'"
        for term, text in checks
        if term not in text
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    diagnostics = validate_pack()
    for diagnostic in diagnostics:
        sys.stderr.write(f"{diagnostic}\n")
    return 1 if diagnostics else 0


if __name__ == "__main__":
    raise SystemExit(main())
