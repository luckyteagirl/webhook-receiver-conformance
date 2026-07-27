"""Small, import-safe helpers shared by schema tests and artifact validation."""
# ruff: noqa: C901, EM101, EM102, INP001, TC003, TRY003, TRY301

from __future__ import annotations

import json
import math
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from enum import StrEnum
from html.parser import HTMLParser
from pathlib import Path
from time import monotonic
from types import MappingProxyType
from typing import Any, Final, cast

import yaml
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_DOCUMENT_DEPTH = 64
MAX_DOCUMENT_NODES = 100_000
MAX_JSONL_RECORDS = 100_000
MAX_PARSE_SECONDS = 2.0
type Transition = tuple[str, str]
type VolatileField = tuple[str, str]
type CompatibilityRow = tuple[str, str, str]


class ArtifactValidationError(ValueError):
    """Safe deterministic failure raised for bounded artifact input."""


class CompatibilityDecision(StrEnum):
    """Reader action selected by the schema compatibility policy."""

    ACCEPT = "accept"
    REJECT = "reject"


class SchemaChangeKind(StrEnum):
    """Change shapes understood by the same-major compatibility policy."""

    EXACT = "exact"
    ADDITIVE_OPTIONAL = "additive-optional"
    BREAKING = "breaking"


PERSISTED_ARTIFACT_SCHEMAS: Final = frozenset(
    {
        "assertion-record.schema.json",
        "delivery-record.schema.json",
        "fixture-manifest.schema.json",
        "observation-record.schema.json",
        "plugin-metadata.schema.json",
        "result-summary.schema.json",
        "run-manifest.schema.json",
    }
)

VOLATILE_FIELD_CONTRACT: Final = MappingProxyType(
    {
        "assertion-record.schema.json": frozenset(
            {
                ("/actual", "environment-observation"),
                ("/recorded_at", "wall-timestamp"),
                ("/run_id", "execution-identity"),
            }
        ),
        "delivery-record.schema.json": frozenset(
            {
                ("/error", "environment-observation"),
                ("/monotonic_elapsed_ns", "measured-duration"),
                ("/recorded_at", "wall-timestamp"),
                ("/response", "environment-observation"),
                ("/run_id", "execution-identity"),
            }
        ),
        "fixture-manifest.schema.json": frozenset(),
        "observation-record.schema.json": frozenset(
            {
                ("/error", "environment-observation"),
                ("/evidence", "environment-observation"),
                ("/recorded_at", "wall-timestamp"),
                ("/run_id", "execution-identity"),
                ("/snapshot_id", "environment-observation"),
            }
        ),
        "plugin-metadata.schema.json": frozenset(),
        "result-summary.schema.json": frozenset(
            {
                ("/generated_at", "wall-timestamp"),
                ("/run_id", "execution-identity"),
            }
        ),
        "run-manifest.schema.json": frozenset(
            {
                ("/created_at", "wall-timestamp"),
                ("/environment", "environment-observation"),
            }
        ),
    }
)

COMPATIBILITY_BEHAVIOR_MATRIX: Final = frozenset(
    {
        ("same-major", SchemaChangeKind.EXACT.value, CompatibilityDecision.ACCEPT.value),
        (
            "same-major",
            SchemaChangeKind.ADDITIVE_OPTIONAL.value,
            CompatibilityDecision.ACCEPT.value,
        ),
        ("same-major", SchemaChangeKind.BREAKING.value, CompatibilityDecision.REJECT.value),
        ("unknown-major", "any", CompatibilityDecision.REJECT.value),
    }
)

EXECUTABLE_TRANSITIONS: Final = MappingProxyType(
    {
        "run": frozenset(
            {
                ("paused", "cancelled"),
                ("paused", "failed"),
                ("paused", "running"),
                ("planned", "cancelled"),
                ("planned", "failed"),
                ("planned", "running"),
                ("running", "cancelled"),
                ("running", "completed"),
                ("running", "failed"),
                ("running", "paused"),
            }
        ),
        "scenario": frozenset(
            {
                ("eligible", "cancelled"),
                ("eligible", "error"),
                ("eligible", "running"),
                ("eligible", "skipped"),
                ("pending", "cancelled"),
                ("pending", "eligible"),
                ("pending", "error"),
                ("pending", "skipped"),
                ("running", "ambiguous"),
                ("running", "cancelled"),
                ("running", "error"),
                ("running", "failed"),
                ("running", "passed"),
                ("running", "skipped"),
            }
        ),
        "delivery": frozenset(
            {
                ("active", "ambiguous"),
                ("active", "cancelled"),
                ("active", "eligible"),
                ("active", "exhausted"),
                ("active", "satisfied"),
                ("eligible", "active"),
                ("eligible", "cancelled"),
                ("eligible", "skipped"),
                ("pending", "cancelled"),
                ("pending", "eligible"),
                ("pending", "skipped"),
            }
        ),
        "attempt": frozenset(
            {
                ("awaiting_response", "response_observed"),
                ("awaiting_response", "transport_failed"),
                ("awaiting_response", "unknown_outcome"),
                ("claimed", "cancelled"),
                ("claimed", "not_sent"),
                ("claimed", "pre_send_committed"),
                ("connecting", "cancelled"),
                ("connecting", "not_sent"),
                ("connecting", "sending"),
                ("connecting", "transport_failed"),
                ("connecting", "unknown_outcome"),
                ("pre_send_committed", "cancelled"),
                ("pre_send_committed", "connecting"),
                ("pre_send_committed", "not_sent"),
                ("response_observed", "rejected"),
                ("response_observed", "succeeded"),
                ("response_observed", "transport_failed"),
                ("scheduled", "cancelled"),
                ("scheduled", "claimed"),
                ("sending", "awaiting_response"),
                ("sending", "transport_failed"),
                ("sending", "unknown_outcome"),
            }
        ),
        "observation": frozenset(
            {
                ("running", "cancelled"),
                ("running", "error"),
                ("running", "ok"),
                ("running", "pending"),
                ("running", "timed_out"),
                ("running", "unsupported"),
                ("scheduled", "cancelled"),
                ("scheduled", "running"),
            }
        ),
        "assertion": frozenset(
            {
                ("pending", "cancelled"),
                ("pending", "running"),
                ("running", "cancelled"),
                ("running", "error"),
                ("running", "failed"),
                ("running", "passed"),
                ("running", "unsupported"),
            }
        ),
    }
)

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
_COMPATIBILITY_COLUMNS = 3
_COMPATIBILITY_SECTION = re.compile(
    r"^## Artifact schema compatibility behavior\s*$"
    r"(?P<body>.*?)(?=^## |\Z)",
    re.MULTILINE | re.DOTALL,
)
_HTML_VOID_ELEMENTS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)


class _BoundedHTMLParser(HTMLParser):
    """Count HTML structure without retaining untrusted document content."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.nodes = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del attrs
        self._count_node()
        if tag.lower() not in _HTML_VOID_ELEMENTS:
            self.depth += 1
            if self.depth > MAX_DOCUMENT_DEPTH:
                raise ArtifactValidationError(
                    f"document exceeds {MAX_DOCUMENT_DEPTH} nesting depth limit"
                )

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del tag, attrs
        self._count_node()

    def handle_endtag(self, tag: str) -> None:
        del tag
        if self.depth:
            self.depth -= 1

    def handle_data(self, data: str) -> None:
        if data:
            self._count_node()

    def _count_node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_DOCUMENT_NODES:
            raise ArtifactValidationError(f"document exceeds {MAX_DOCUMENT_NODES} node limit")


def parse_json_bytes(data: bytes) -> Any:  # noqa: ANN401
    """Parse one bounded JSON value with safe deterministic failures."""
    text = _decode_bounded(data)
    started = monotonic()
    try:
        value = json.loads(text, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
        raise ArtifactValidationError("invalid JSON document") from exc
    _enforce_parse_time(started)
    _enforce_structure_limits(value)
    _enforce_parse_time(started)
    return value


def parse_yaml_bytes(data: bytes) -> Any:  # noqa: ANN401
    """Parse one bounded JSON-compatible YAML value without object construction."""
    text = _decode_bounded(data)
    started = monotonic()
    try:
        value = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, TypeError, ValueError) as exc:
        raise ArtifactValidationError("invalid YAML document") from exc
    _enforce_parse_time(started)
    _enforce_structure_limits(value)
    _enforce_parse_time(started)
    return value


def parse_jsonl_bytes(data: bytes) -> list[Any]:
    """Parse bounded JSON Lines, rejecting blanks and excessive records."""
    text = _decode_bounded(data)
    started = monotonic()
    records: list[Any] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if line_number > MAX_JSONL_RECORDS:
            raise ArtifactValidationError(
                f"JSON Lines input exceeds {MAX_JSONL_RECORDS} record limit"
            )
        if not line.strip():
            raise ArtifactValidationError(f"blank JSONL record at line {line_number}")
        try:
            record = json.loads(line, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
            raise ArtifactValidationError(f"invalid JSONL record at line {line_number}") from exc
        _enforce_structure_limits(record)
        records.append(record)
        _enforce_parse_time(started)
    return records


def parse_xml_bytes(data: bytes) -> ET.Element:
    """Parse bounded XML while prohibiting declarations that can load entities."""
    text = _decode_bounded(data)
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, flags=re.IGNORECASE):
        raise ArtifactValidationError("XML document type and entity declarations are prohibited")
    started = monotonic()
    try:
        root = ET.fromstring(text)  # noqa: S314
    except (ET.ParseError, RecursionError, ValueError) as exc:
        raise ArtifactValidationError("invalid XML document") from exc
    _enforce_xml_limits(root)
    _enforce_parse_time(started)
    return root


def parse_html_bytes(data: bytes) -> None:
    """Parse bounded HTML structure without rendering or retaining content."""
    text = _decode_bounded(data)
    started = monotonic()
    parser = _BoundedHTMLParser()
    try:
        parser.feed(text)
        parser.close()
    except (ArtifactValidationError, RecursionError, ValueError) as exc:
        if isinstance(exc, ArtifactValidationError):
            raise
        raise ArtifactValidationError("invalid HTML document") from exc
    _enforce_parse_time(started)


def validate_observer_protocol(
    data: bytes,
    schema: dict[str, Any],
    *,
    registry: Registry[Any] | None = None,
) -> list[str]:
    """Parse and validate one bounded observer message without leaking its body."""
    try:
        instance = parse_json_bytes(data)
    except ArtifactValidationError as exc:
        return [f"<root>: {exc}"]
    return validate_instance(instance, schema, registry=registry)


def load_json(path: Path) -> Any:  # noqa: ANN401
    """Load a bounded JSON document without executing anything."""
    return parse_json_bytes(_read_bytes(path))


def load_yaml(path: Path) -> Any:  # noqa: ANN401
    """Load a bounded JSON-compatible YAML document."""
    return parse_yaml_bytes(_read_bytes(path))


def load_jsonl(path: Path) -> list[Any]:
    """Load bounded JSON Lines with deterministic diagnostics."""
    return parse_jsonl_bytes(_read_bytes(path))


def load_xml(path: Path) -> ET.Element:
    """Load one bounded XML document."""
    return parse_xml_bytes(_read_bytes(path))


def build_schema_registry(schemas: Iterable[dict[str, Any]]) -> Registry[Any]:
    """Build an in-memory registry for repository-owned cross-schema references."""
    registry: Registry[Any] = Registry()
    for schema in schemas:
        identifier = schema.get("$id")
        if isinstance(identifier, str):
            registry = registry.with_resource(identifier, Resource.from_contents(schema))
    return registry


def compatibility_decision(
    *,
    reader_major: int,
    artifact_major: int,
    change_kind: SchemaChangeKind,
) -> CompatibilityDecision:
    """Apply the executable artifact-reader compatibility matrix."""
    if reader_major < 1 or artifact_major < 1:
        raise ValueError("schema majors must be positive integers")
    if artifact_major != reader_major:
        return CompatibilityDecision.REJECT
    if change_kind in {SchemaChangeKind.EXACT, SchemaChangeKind.ADDITIVE_OPTIONAL}:
        return CompatibilityDecision.ACCEPT
    return CompatibilityDecision.REJECT


def parse_compatibility_matrix(source: str) -> frozenset[CompatibilityRow]:
    """Extract the concrete schema compatibility table from the interface contract."""
    match = _COMPATIBILITY_SECTION.search(source)
    if match is None:
        return frozenset()
    rows: set[CompatibilityRow] = set()
    for line in match.group("body").splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = tuple(cell.strip().strip("`") for cell in line.strip().strip("|").split("|"))
        if len(cells) < _COMPATIBILITY_COLUMNS or cells[0] not in {"same-major", "unknown-major"}:
            continue
        rows.add(cast("CompatibilityRow", cells[:_COMPATIBILITY_COLUMNS]))
    return frozenset(rows)


def parse_volatile_fields(schema: dict[str, Any]) -> frozenset[VolatileField]:
    """Read and structurally validate the semantic volatility annotation."""
    annotation_value = cast("object", schema.get("x-reproducibility"))
    if not isinstance(annotation_value, dict):
        raise ArtifactValidationError("missing x-reproducibility annotation")
    annotation = cast("dict[str, object]", annotation_value)
    fields_value = annotation.get("volatile_fields")
    if not isinstance(fields_value, list):
        raise ArtifactValidationError("volatile_fields annotation must be an array")
    fields = cast("list[object]", fields_value)
    parsed: set[VolatileField] = set()
    for entry_value in fields:
        if not isinstance(entry_value, dict):
            raise ArtifactValidationError("volatile field annotation must be an object")
        entry = cast("dict[object, object]", entry_value)
        pointer = entry.get("json_pointer")
        category = entry.get("category")
        if (
            not isinstance(pointer, str)
            or not pointer.startswith("/")
            or not isinstance(category, str)
            or not category
            or set(entry) != {"category", "json_pointer"}
        ):
            raise ArtifactValidationError("invalid volatile field annotation")
        field = (pointer, category)
        if field in parsed:
            raise ArtifactValidationError("duplicate volatile field annotation")
        parsed.add(field)
    return frozenset(parsed)


def validate_volatility_contract(
    schema_name: str,
    schema: dict[str, Any],
) -> list[str]:
    """Require an exact, resolvable volatility declaration for one report schema."""
    expected = VOLATILE_FIELD_CONTRACT.get(schema_name)
    if expected is None:
        return []
    try:
        actual = parse_volatile_fields(schema)
    except ArtifactValidationError as exc:
        return [f"{schema_name}: {exc}"]
    diagnostics = [
        f"{schema_name}: missing volatile field {pointer} ({category})"
        for pointer, category in sorted(expected - actual)
    ]
    diagnostics.extend(
        f"{schema_name}: unexpected volatile field {pointer} ({category})"
        for pointer, category in sorted(actual - expected)
    )
    for pointer, _category in sorted(actual):
        if not _schema_pointer_exists(schema, pointer):
            diagnostics.append(f"{schema_name}: volatile field path does not resolve: {pointer}")
    return diagnostics


def validate_persisted_schema_versions(
    schemas: dict[str, dict[str, Any]],
) -> list[str]:
    """Require every persisted JSON/JSONL contract to require schema_version."""
    diagnostics: list[str] = []
    for schema_name in sorted(PERSISTED_ARTIFACT_SCHEMAS):
        schema = schemas.get(schema_name)
        if schema is None:
            diagnostics.append(f"{schema_name}: persisted artifact schema is missing")
            continue
        properties = schema.get("properties")
        required = schema.get("required")
        if (
            not isinstance(properties, dict)
            or "schema_version" not in properties
            or not isinstance(required, list)
            or "schema_version" not in required
        ):
            diagnostics.append(f"{schema_name}: schema_version must be an explicit required field")
    return diagnostics


def is_transition_allowed(machine_name: str, source: str, target: str) -> bool:
    """Query the temporary executable transition registry."""
    transitions = EXECUTABLE_TRANSITIONS.get(machine_name)
    return transitions is not None and (source, target) in transitions


def compare_transition_triplet(
    *,
    machine_name: str,
    registry: frozenset[Transition],
    diagram: frozenset[Transition],
    table: frozenset[Transition],
) -> list[str]:
    """Compare registry, Mermaid, and normative table edges pairwise."""
    diagnostics = _compare_named_transition_sources(
        machine_name=machine_name,
        left_name="registry",
        left=registry,
        right_name="diagram",
        right=diagram,
    )
    diagnostics.extend(
        _compare_named_transition_sources(
            machine_name=machine_name,
            left_name="registry",
            left=registry,
            right_name="table",
            right=table,
        )
    )
    diagnostics.extend(
        _compare_named_transition_sources(
            machine_name=machine_name,
            left_name="diagram",
            left=diagram,
            right_name="table",
            right=table,
        )
    )
    return sorted(diagnostics)


def validate_instance(
    instance: Any,  # noqa: ANN401
    schema: dict[str, Any],
    *,
    registry: Registry[Any] | None = None,
) -> list[str]:
    """Return deterministic diagnostics without echoing instance values."""
    started = monotonic()
    try:
        _enforce_structure_limits(instance)
    except ArtifactValidationError as exc:
        return [f"<root>: {exc}"]
    kwargs: dict[str, Any] = {
        "format_checker": FormatChecker(),
        "registry": registry if registry is not None else Registry[Any](),
    }
    validator: Any = Draft202012Validator(schema, **kwargs)
    try:
        errors = sorted(validator.iter_errors(instance), key=_error_key)
    except (RecursionError, TypeError, Unresolvable, ValueError):
        return ["<root>: schema validation could not safely process the document"]
    try:
        _enforce_parse_time(started)
    except ArtifactValidationError as exc:
        return [f"<root>: {exc}"]
    return [_safe_error_message(error) for error in errors]


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


def _compare_named_transition_sources(
    *,
    machine_name: str,
    left_name: str,
    left: frozenset[Transition],
    right_name: str,
    right: frozenset[Transition],
) -> list[str]:
    diagnostics = [
        f"{machine_name}: {left_name} transition missing from {right_name}: {source} -> {target}"
        for source, target in sorted(left - right)
    ]
    diagnostics.extend(
        f"{machine_name}: {right_name} transition missing from {left_name}: {source} -> {target}"
        for source, target in sorted(right - left)
    )
    return diagnostics


def _read_bytes(path: Path) -> bytes:
    try:
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ArtifactValidationError(f"artifact exceeds {MAX_ARTIFACT_BYTES} byte limit")
        data = path.read_bytes()
    except ArtifactValidationError:
        raise
    except OSError as exc:
        raise ArtifactValidationError("artifact could not be read") from exc
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ArtifactValidationError(f"artifact exceeds {MAX_ARTIFACT_BYTES} byte limit")
    return data


def _decode_bounded(data: bytes) -> str:
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ArtifactValidationError(f"artifact exceeds {MAX_ARTIFACT_BYTES} byte limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactValidationError("artifact is not valid UTF-8") from exc


def _reject_json_constant(value: str) -> None:
    del value
    raise ArtifactValidationError("non-finite JSON numbers are prohibited")


def _enforce_parse_time(started: float) -> None:
    if monotonic() - started > MAX_PARSE_SECONDS:
        raise ArtifactValidationError(
            f"artifact parsing exceeds {MAX_PARSE_SECONDS:g} second time limit"
        )


def _enforce_structure_limits(value: object) -> None:
    stack: list[tuple[object, int, bool]] = [(value, 1, False)]
    active_containers: set[int] = set()
    node_count = 0
    while stack:
        current, depth, exiting = stack.pop()
        if exiting:
            active_containers.remove(id(current))
            continue
        node_count += 1
        if node_count > MAX_DOCUMENT_NODES:
            raise ArtifactValidationError(f"document exceeds {MAX_DOCUMENT_NODES} node limit")
        if depth > MAX_DOCUMENT_DEPTH:
            raise ArtifactValidationError(
                f"document exceeds {MAX_DOCUMENT_DEPTH} nesting depth limit"
            )
        if isinstance(current, dict):
            mapping = cast("dict[object, object]", current)
            identity = id(mapping)
            if identity in active_containers:
                raise ArtifactValidationError("document cycles are not supported")
            active_containers.add(identity)
            stack.append((mapping, depth, True))
            for key, item in mapping.items():
                if not isinstance(key, str):
                    raise ArtifactValidationError("document object keys must be strings")
                stack.append((item, depth + 1, False))
        elif isinstance(current, list):
            items = cast("list[object]", current)
            identity = id(items)
            if identity in active_containers:
                raise ArtifactValidationError("document cycles are not supported")
            active_containers.add(identity)
            stack.append((items, depth, True))
            stack.extend((item, depth + 1, False) for item in items)
        elif isinstance(current, float) and not math.isfinite(current):
            raise ArtifactValidationError("non-finite numbers are prohibited")
        elif current is not None and not isinstance(current, (bool, int, float, str)):
            raise ArtifactValidationError("document contains a non-JSON-compatible value")


def _enforce_xml_limits(root: ET.Element) -> None:
    stack: list[tuple[ET.Element, int]] = [(root, 1)]
    node_count = 0
    while stack:
        element, depth = stack.pop()
        node_count += 1
        if node_count > MAX_DOCUMENT_NODES:
            raise ArtifactValidationError(f"document exceeds {MAX_DOCUMENT_NODES} node limit")
        if depth > MAX_DOCUMENT_DEPTH:
            raise ArtifactValidationError(
                f"document exceeds {MAX_DOCUMENT_DEPTH} nesting depth limit"
            )
        stack.extend((child, depth + 1) for child in element)


def _schema_pointer_exists(schema: dict[str, Any], pointer: str) -> bool:
    current: object = schema
    for raw_part in pointer.lstrip("/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict):
            return False
        current_mapping = cast("dict[object, object]", current)
        properties_value = current_mapping.get("properties")
        if not isinstance(properties_value, dict):
            return False
        properties = cast("dict[object, object]", properties_value)
        if part not in properties:
            return False
        current = properties[part]
    return True


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
