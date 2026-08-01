"""Deterministic validation of the repository's authoritative artifact pack."""
# ruff: noqa: INP001

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from jsonschema import Draft202012Validator, SchemaError

if TYPE_CHECKING:
    from referencing import Registry

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.check_ste_docs import validate_documents  # noqa: E402
from tests.helpers.schema_validation import (  # noqa: E402
    COMPATIBILITY_BEHAVIOR_MATRIX,
    EXECUTABLE_TRANSITIONS,
    ArtifactValidationError,
    build_schema_registry,
    compare_transition_triplet,
    load_json,
    load_jsonl,
    load_xml,
    load_yaml,
    parse_compatibility_matrix,
    parse_state_transition_tables,
    parse_state_transitions,
    validate_instance,
    validate_persisted_schema_versions,
    validate_volatility_contract,
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
_VOLATILITY_SECTION = re.compile(
    r"^## Reproducibility comparison volatility\s*$"
    r"(?P<body>.*?)(?=^## |\Z)",
    re.MULTILINE | re.DOTALL,
)
_VOLATILITY_DOCUMENT_ROWS = frozenset(
    {
        ("environment-observation", "environment observations", "exclude"),
        ("execution-identity", "run_id", "exclude"),
        ("measured-duration", "measured durations", "exclude"),
        ("wall-timestamp", "wall timestamps", "exclude"),
    }
)
_CONTRACT_TABLE_COLUMNS = 3


def validate_pack(root: Path = ROOT) -> list[str]:  # noqa: C901, PLR0912
    """Validate all currently materialized artifacts; never mutate inputs."""
    errors: list[str] = []
    schemas: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "schemas").glob("*.schema.json")):
        try:
            schema_value = cast("object", load_json(path))
            if not isinstance(schema_value, dict):
                errors.append(f"{path.relative_to(root)}: schema document must be an object")
                continue
            schema = cast("dict[str, Any]", schema_value)
            Draft202012Validator.check_schema(schema)
            schemas[path.name] = schema
        except ArtifactValidationError as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")
        except (SchemaError, TypeError, ValueError):
            errors.append(f"{path.relative_to(root)}: invalid JSON Schema")
    registry = build_schema_registry(schemas.values())
    errors.extend(validate_persisted_schema_versions(schemas))
    for schema_name, schema in sorted(schemas.items()):
        errors.extend(validate_volatility_contract(schema_name, schema))

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
        except ArtifactValidationError as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")
        except (TypeError, KeyError):
            errors.append(f"{path.relative_to(root)}: artifact validation failed")
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
        except ArtifactValidationError as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")
        except (TypeError, KeyError):
            errors.append(f"{path.relative_to(root)}: artifact validation failed")

    xml_path = root / "examples" / "junit.example.xml"
    try:
        load_xml(xml_path)
    except ArtifactValidationError as exc:
        errors.append(f"{xml_path.relative_to(root)}: {exc}")
    errors.extend(_validate_task_index_schema(root, schemas, registry))
    errors.extend(_cross_references(root))
    errors.extend(_traceability_parity(root))
    errors.extend(_state_diagram_syntax(root))
    errors.extend(_state_table_diagram_parity(root))
    errors.extend(_compatibility_matrix_contract(root))
    errors.extend(_volatility_document_contract(root))
    errors.extend(validate_documents(root))
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
    except ArtifactValidationError as exc:
        return [f"{path.relative_to(root)}: {exc}"]
    except (TypeError, KeyError):
        return [f"{path.relative_to(root)}: task-index validation failed"]


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
            entries_value = cast("object", task.get(field))
            if not isinstance(entries_value, list) or not entries_value:
                errors.extend([f"machine/task-index.yaml:{label}.{field}: must not be empty"])
                continue
            entries = cast("list[object]", entries_value)
            for index, entry in enumerate(entries):
                if not isinstance(entry, str) or not entry.strip():
                    errors.append(
                        f"machine/task-index.yaml:{label}.{field}[{index}]: must not be blank"
                    )
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
    """Require registry, specification/09 tables, and Mermaid edges to match."""
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
    diagnostics.extend(
        [
            f"transition registry: missing machine {missing_name}"
            for missing_name in sorted(expected_names - set(EXECUTABLE_TRANSITIONS))
        ]
    )
    diagnostics.extend(
        [
            f"transition registry: unexpected machine {extra_name}"
            for extra_name in sorted(set(EXECUTABLE_TRANSITIONS) - expected_names)
        ]
    )
    for name in sorted(expected_names & tables.keys() & EXECUTABLE_TRANSITIONS.keys()):
        diagram_path = root / "diagrams" / f"state-{name}.mmd"
        try:
            diagram = parse_state_transitions(diagram_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            diagnostics.append(f"{diagram_path.relative_to(root)}: {exc}")
            continue
        diagnostics.extend(
            compare_transition_triplet(
                machine_name=name,
                registry=EXECUTABLE_TRANSITIONS[name],
                diagram=diagram,
                table=tables[name],
            )
        )
    return diagnostics


def _compatibility_matrix_contract(root: Path) -> list[str]:
    """Require interface documentation to match executable reader behavior exactly."""
    path = root / "specification" / "16-interfaces-and-contracts.md"
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [f"{path.relative_to(root)}: compatibility contract could not be read"]
    actual = parse_compatibility_matrix(source)
    diagnostics = [
        f"{path.relative_to(root)}: missing compatibility row {relation}/{change}/{behavior}"
        for relation, change, behavior in sorted(COMPATIBILITY_BEHAVIOR_MATRIX - actual)
    ]
    diagnostics.extend(
        f"{path.relative_to(root)}: unexpected compatibility row {relation}/{change}/{behavior}"
        for relation, change, behavior in sorted(actual - COMPATIBILITY_BEHAVIOR_MATRIX)
    )
    return diagnostics


def _volatility_document_contract(root: Path) -> list[str]:
    """Require an explicit category-level volatility declaration."""
    path = root / "specification" / "12-scheduler-and-determinism.md"
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [f"{path.relative_to(root)}: volatility contract could not be read"]
    match = _VOLATILITY_SECTION.search(source)
    if match is None:
        return [f"{path.relative_to(root)}: missing volatility declaration"]
    actual: set[tuple[str, str, str]] = set()
    for line in match.group("body").splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = tuple(
            cell.strip().strip("`").lower() for cell in line.strip().strip("|").split("|")
        )
        if len(cells) >= _CONTRACT_TABLE_COLUMNS and cells[0] in {
            "environment-observation",
            "execution-identity",
            "measured-duration",
            "wall-timestamp",
        }:
            actual.add(cast("tuple[str, str, str]", cells[:_CONTRACT_TABLE_COLUMNS]))
    diagnostics = [
        f"{path.relative_to(root)}: missing volatility row {category}/{fields}/{behavior}"
        for category, fields, behavior in sorted(_VOLATILITY_DOCUMENT_ROWS - actual)
    ]
    diagnostics.extend(
        f"{path.relative_to(root)}: unexpected volatility row {category}/{fields}/{behavior}"
        for category, fields, behavior in sorted(actual - _VOLATILITY_DOCUMENT_ROWS)
    )
    return diagnostics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help=argparse.SUPPRESS,
    )
    arguments = parser.parse_args(argv)
    try:
        diagnostics = validate_pack(arguments.root.resolve())
    except Exception:  # noqa: BLE001
        diagnostics = ["artifact validation failed safely"]
    for diagnostic in diagnostics:
        sys.stderr.write(f"{diagnostic}\n")
    return 1 if diagnostics else 0


if __name__ == "__main__":
    raise SystemExit(main())
