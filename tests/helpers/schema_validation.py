"""Small, import-safe helpers shared by schema tests and artifact validation."""
# ruff: noqa: INP001, TC003

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

import yaml
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
type Transition = tuple[str, str]

_STATE_TRANSITION = re.compile(
    r"^\s*(?P<source>[a-z][a-z0-9_]*)\s*-->\s*"
    r"(?P<target>[a-z][a-z0-9_]*)(?:\s*:.*)?$",
    re.MULTILINE,
)
_STATE_SECTION = re.compile(
    r"^## (?P<title>Run|Scenario|Planned delivery|Physical attempt|Observation|Assertion) "
    r"states(?: and transaction boundaries)?$",
    re.MULTILINE,
)
_STATE_TABLE_NAMES = {
    "Run": "run",
    "Scenario": "scenario",
    "Planned delivery": "delivery",
    "Physical attempt": "attempt",
    "Observation": "observation",
    "Assertion": "assertion",
}
_BACKTICK_VALUE = re.compile(r"`([a-z][a-z0-9_]*)`")
_MIN_TRANSITION_TABLE_COLUMNS = 2


def load_json(path: Path) -> Any:  # noqa: ANN401
    """Load a bounded JSON document without executing anything."""
    return json.loads(_read_text(path))


def load_yaml(path: Path) -> Any:  # noqa: ANN401
    """Load a bounded YAML document using PyYAML's safe loader."""
    return yaml.safe_load(_read_text(path))


def load_jsonl(path: Path) -> list[Any]:
    """Load bounded JSON Lines, rejecting blank or malformed records."""
    records: list[Any] = []
    for line_number, line in enumerate(_read_text(path).splitlines(), 1):
        if not line.strip():
            message = f"{path}:{line_number}: blank JSONL record"
            raise ValueError(message)
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            message = f"{path}:{line_number}: invalid JSON: {exc.msg}"
            raise ValueError(message) from exc
    return records


def build_schema_registry(schemas: Iterable[dict[str, Any]]) -> Registry[Any]:
    """Build an in-memory registry for repository-owned cross-schema references."""
    registry: Registry[Any] = Registry()
    for schema in schemas:
        identifier = schema.get("$id")
        if isinstance(identifier, str):
            registry = registry.with_resource(identifier, Resource.from_contents(schema))
    return registry


def validate_instance(
    instance: Any,  # noqa: ANN401
    schema: dict[str, Any],
    *,
    registry: Registry[Any] | None = None,
) -> list[str]:
    """Return deterministic diagnostics without echoing instance values."""
    kwargs: dict[str, Any] = {"format_checker": FormatChecker()}
    if registry is not None:
        kwargs["registry"] = registry
    validator: Any = Draft202012Validator(schema, **kwargs)
    return [
        _safe_error_message(error)
        for error in sorted(validator.iter_errors(instance), key=_error_key)
    ]


def validate_json(
    path: Path,
    schema: dict[str, Any],
    *,
    registry: Registry[Any] | None = None,
) -> list[str]:
    """Validate one JSON artifact and include its path in diagnostics."""
    try:
        errors = validate_instance(load_json(path), schema, registry=registry)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"{path}: {exc}"]
    return [f"{path}: {error}" for error in errors]


def parse_state_transitions(source: str) -> frozenset[Transition]:
    """Extract named Mermaid state transitions, excluding pseudo-state edges."""
    return frozenset(
        (match.group("source"), match.group("target"))
        for match in _STATE_TRANSITION.finditer(source)
    )


def parse_state_transition_tables(source: str) -> dict[str, frozenset[Transition]]:
    """Extract state edges from the legal-exits columns in specification/09."""
    matches = list(_STATE_SECTION.finditer(source))
    tables: dict[str, frozenset[Transition]] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        section = source[match.end() : end]
        transitions: set[Transition] = set()
        for line in section.splitlines():
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < _MIN_TRANSITION_TABLE_COLUMNS:
                continue
            source_match = _BACKTICK_VALUE.fullmatch(cells[0])
            if source_match is None:
                continue
            source_state = source_match.group(1)
            transitions.update(
                (source_state, target_state) for target_state in _BACKTICK_VALUE.findall(cells[1])
            )
        tables[_STATE_TABLE_NAMES[match.group("title")]] = frozenset(transitions)
    return tables


def compare_state_transitions(
    *,
    machine_name: str,
    documented: frozenset[Transition],
    executable: frozenset[Transition],
) -> list[str]:
    """Describe deterministic parity failures between documented and executable edges."""
    diagnostics = [
        f"{machine_name}: executable transition missing from diagram: {source} -> {target}"
        for source, target in sorted(executable - documented)
    ]
    diagnostics.extend(
        f"{machine_name}: documented transition missing from executable table: {source} -> {target}"
        for source, target in sorted(documented - executable)
    )
    return diagnostics


def _read_text(path: Path) -> str:
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        message = f"artifact exceeds {MAX_ARTIFACT_BYTES} byte limit"
        raise ValueError(message)
    return path.read_text(encoding="utf-8")


def _error_key(error: ValidationError) -> tuple[str, str]:
    return ("/".join(str(part) for part in error.absolute_path), error.message)


def _safe_error_message(error: ValidationError) -> str:
    path = "/".join(str(part) for part in error.absolute_path) or "<root>"
    keyword = str(error.validator)
    instance = cast("object", error.instance)
    required = cast("object", error.validator_value)
    if keyword == "required" and isinstance(instance, dict):
        instance_fields = cast("dict[object, object]", instance)
        if isinstance(required, list):
            required_fields = cast("list[object]", required)
            missing = sorted(
                field
                for field in required_fields
                if isinstance(field, str) and field not in instance_fields
            )
            if missing:
                return f"{path}: missing required field(s): {', '.join(missing)}"
    return f"{path}: violates JSON Schema '{keyword}' constraint"
