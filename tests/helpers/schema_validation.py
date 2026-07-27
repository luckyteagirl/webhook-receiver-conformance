"""Small, import-safe helpers shared by schema tests and artifact validation."""
# ruff: noqa: INP001, TC003

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

import yaml
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
type Transition = tuple[str, str]

_STATE_TRANSITION = re.compile(
    r"^\s*(?P<source>[a-z][a-z0-9_]*)\s*-->\s*"
    r"(?P<target>[a-z][a-z0-9_]*)(?:\s*:.*)?$",
    re.MULTILINE,
)


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


def validate_instance(instance: Any, schema: dict[str, Any]) -> list[str]:  # noqa: ANN401
    """Return deterministic diagnostics without echoing instance values."""
    validator: Any = Draft202012Validator(schema, format_checker=FormatChecker())
    return [
        _safe_error_message(error)
        for error in sorted(validator.iter_errors(instance), key=_error_key)
    ]


def validate_json(path: Path, schema: dict[str, Any]) -> list[str]:
    """Validate one JSON artifact and include its path in diagnostics."""
    try:
        errors = validate_instance(load_json(path), schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"{path}: {exc}"]
    return [f"{path}: {error}" for error in errors]


def parse_state_transitions(source: str) -> frozenset[Transition]:
    """Extract named Mermaid state transitions, excluding pseudo-state edges."""
    return frozenset(
        (match.group("source"), match.group("target"))
        for match in _STATE_TRANSITION.finditer(source)
    )


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
