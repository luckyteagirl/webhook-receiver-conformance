"""Offline exact-ID causal inspection with privacy-safe human and JSON views."""
# ruff: noqa: B008, D105, EM101, EM102, FBT001, FBT003, INP001, PLR0911, PLR2004, TRY003

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final, Protocol, cast

import typer

from webhook_receiver_conformance.errors import (
    ErrorCategory,
    ResultCategory,
)
from webhook_receiver_conformance.reporting.json_reports import (
    FailureCausalTrace,
    JsonReportArtifacts,
)
from webhook_receiver_conformance.types import DiagnosticCode

if TYPE_CHECKING:
    from collections.abc import Mapping

MAX_INSPECTION_ARTIFACT_BYTES: Final = 67_108_864
MAX_INSPECTION_RECORDS: Final = 100_000
MAX_INSPECTION_CHAINS: Final = 10_000
MAX_INSPECTION_TEXT: Final = 4_096
MAX_RAW_ARTIFACT_PATHS: Final = 1_000
INSPECT_COMMAND_HELP: Final = (
    "Query a local run and print an exact causal evidence chain without network access."
)
RAW_ARTIFACT_WARNING: Final = (
    "WARNING: raw artifact paths may contain sensitive webhook payloads or receiver data."
)
_SAFE_DIAGNOSTIC_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class InspectionError(RuntimeError):
    """One classified, secret-safe inspection failure."""

    category: ErrorCategory = ErrorCategory.ARTIFACT_INTEGRITY_ERROR
    result_category: ResultCategory = ResultCategory.HARNESS_ERROR
    code: DiagnosticCode = DiagnosticCode("INSPECTION_ERROR")


class InspectionNotFoundError(InspectionError):
    """No exact causal chain contains the requested identifier."""

    category = ErrorCategory.CONFIGURATION_ERROR
    result_category = ResultCategory.INVALID_INPUT
    code = DiagnosticCode("INSPECTION_IDENTIFIER_NOT_FOUND")


class InspectionIdentifierKind(StrEnum):
    """Supported exact causal filters."""

    SCENARIO = "scenario"
    EVENT = "event"
    DELIVERY = "delivery"
    ATTEMPT = "attempt"
    OBSERVATION = "observation"
    ASSERTION = "assertion"
    DIAGNOSTIC = "diagnostic"


@dataclass(frozen=True, slots=True)
class InspectionQuery:
    """One explicit identifier-kind filter."""

    kind: InspectionIdentifierKind
    identifier: str

    def __post_init__(self) -> None:
        if type(self.kind) is not InspectionIdentifierKind:
            raise TypeError("kind must be an InspectionIdentifierKind")
        if (
            type(self.identifier) is not str
            or not self.identifier
            or len(self.identifier) > 256
            or _CONTROL_CHARACTERS.search(self.identifier) is not None
        ):
            raise ValueError("inspection identifier must be bounded safe text")


@dataclass(frozen=True, slots=True)
class InspectionDiagnosticLink:
    """One explicit diagnostic-to-failed-assertion edge."""

    diagnostic_id: str
    assertion_record_id: str

    def __post_init__(self) -> None:
        if (
            type(self.diagnostic_id) is not str
            or _SAFE_DIAGNOSTIC_ID.fullmatch(self.diagnostic_id) is None
        ):
            raise ValueError("diagnostic_id must be one bounded identifier")
        if (
            type(self.assertion_record_id) is not str
            or not self.assertion_record_id.startswith("record_")
            or len(self.assertion_record_id) > 256
        ):
            raise ValueError("assertion_record_id must be one record identifier")


@dataclass(frozen=True, slots=True)
class InspectionCausalChain:
    """One exact failed-assertion chain plus sanitized record projections."""

    trace: FailureCausalTrace
    diagnostic_ids: tuple[str, ...]
    delivery_record: Mapping[str, object]
    observation_record: Mapping[str, object]
    assertion_record: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.trace) is not FailureCausalTrace:
            raise TypeError("trace must be a FailureCausalTrace")
        if (
            type(self.diagnostic_ids) is not tuple
            or any(type(value) is not str for value in self.diagnostic_ids)
            or len(set(self.diagnostic_ids)) != len(self.diagnostic_ids)
        ):
            raise TypeError("diagnostic_ids must be a unique string tuple")


@dataclass(frozen=True, slots=True)
class InspectionResult:
    """Stable manifest-ordered chains returned for one explicit query."""

    query: InspectionQuery
    chains: tuple[InspectionCausalChain, ...]
    raw_artifact_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.query) is not InspectionQuery:
            raise TypeError("query must be an InspectionQuery")
        if (
            type(self.chains) is not tuple
            or not self.chains
            or len(self.chains) > MAX_INSPECTION_CHAINS
            or any(type(value) is not InspectionCausalChain for value in self.chains)
        ):
            raise TypeError("chains must contain bounded causal results")
        _validate_raw_artifact_paths(self.raw_artifact_paths)


@dataclass(frozen=True, slots=True)
class InspectionIndex:
    """Read-only exact-ID index derived from sanitized local report projections."""

    chains: tuple[InspectionCausalChain, ...]
    raw_artifact_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.chains) is not tuple
            or len(self.chains) > MAX_INSPECTION_CHAINS
            or any(type(value) is not InspectionCausalChain for value in self.chains)
        ):
            raise TypeError("chains must contain InspectionCausalChain values")
        identities = tuple(item.trace.assertion_record_id for item in self.chains)
        if len(set(identities)) != len(identities):
            raise ValueError("inspection chains must have unique assertion records")
        _validate_raw_artifact_paths(self.raw_artifact_paths)

    def query(
        self,
        query: InspectionQuery,
        *,
        include_raw_artifacts: bool = False,
    ) -> InspectionResult:
        """Return every exact linked chain without prefix or heuristic matching."""
        if type(query) is not InspectionQuery:
            raise TypeError("query must be an InspectionQuery")
        if type(include_raw_artifacts) is not bool:
            raise TypeError("include_raw_artifacts must be a bool")
        matches = tuple(chain for chain in self.chains if _matches(chain, query))
        if not matches:
            raise InspectionNotFoundError("no causal chain contains the requested exact identifier")
        return InspectionResult(
            query=query,
            chains=matches,
            raw_artifact_paths=(self.raw_artifact_paths if include_raw_artifacts else ()),
        )


class InspectionIndexLoader(Protocol):
    """Local-only adapter used by the mountable CLI command."""

    def __call__(self, run_directory: Path) -> InspectionIndex:
        """Load one sanitized inspection index from a local run."""
        ...


def build_inspection_index(
    artifacts: JsonReportArtifacts,
    *,
    diagnostic_links: tuple[InspectionDiagnosticLink, ...] = (),
    raw_artifact_paths: tuple[str, ...] = (),
) -> InspectionIndex:
    """Build a fail-closed exact index from sanitized JSON reports."""
    if type(artifacts) is not JsonReportArtifacts:
        raise TypeError("artifacts must be JsonReportArtifacts")
    if type(diagnostic_links) is not tuple or any(
        type(value) is not InspectionDiagnosticLink for value in diagnostic_links
    ):
        raise TypeError("diagnostic_links must contain InspectionDiagnosticLink values")
    _validate_raw_artifact_paths(raw_artifact_paths)
    manifest = _json_document(artifacts.manifest_json)
    deliveries = _json_lines(artifacts.deliveries_jsonl)
    observations = _json_lines(artifacts.observations_jsonl)
    assertions = _json_lines(artifacts.assertions_jsonl)
    if max(len(deliveries), len(observations), len(assertions)) > MAX_INSPECTION_RECORDS:
        raise InspectionError("inspection record count exceeds the local limit")
    manifest_edges = _manifest_edges(manifest)
    delivery_by_record = _unique_record_map(deliveries, name="delivery")
    observation_by_record = _unique_record_map(observations, name="observation")
    assertion_by_record = _unique_record_map(assertions, name="assertion")
    diagnostic_by_assertion: dict[str, list[str]] = {}
    for link in diagnostic_links:
        diagnostic_by_assertion.setdefault(link.assertion_record_id, []).append(link.diagnostic_id)
    chains: list[InspectionCausalChain] = []
    for trace in artifacts.causal_index.traces:
        delivery = _require_record(
            delivery_by_record,
            trace.attempt_record_id,
            name="delivery attempt",
        )
        observation = _require_record(
            observation_by_record,
            trace.observation_record_id,
            name="observation",
        )
        assertion = _require_record(
            assertion_by_record,
            trace.assertion_record_id,
            name="assertion",
        )
        _validate_trace_resolution(
            trace,
            manifest_edges=manifest_edges,
            delivery=delivery,
            observation=observation,
            assertion=assertion,
        )
        chains.append(
            InspectionCausalChain(
                trace=trace,
                diagnostic_ids=tuple(
                    sorted(
                        diagnostic_by_assertion.get(
                            trace.assertion_record_id,
                            [],
                        )
                    )
                ),
                delivery_record=delivery,
                observation_record=observation,
                assertion_record=assertion,
            )
        )
    linked_assertions = {trace.trace.assertion_record_id for trace in chains}
    if any(link.assertion_record_id not in linked_assertions for link in diagnostic_links):
        raise InspectionError("diagnostic link does not resolve to a causal trace")
    return InspectionIndex(
        chains=tuple(chains),
        raw_artifact_paths=raw_artifact_paths,
    )


def render_inspection_json(
    result: InspectionResult,
    *,
    include_raw_artifacts: bool = False,
) -> bytes:
    """Render one deterministic machine-readable causal result."""
    if type(result) is not InspectionResult:
        raise TypeError("result must be an InspectionResult")
    if type(include_raw_artifacts) is not bool:
        raise TypeError("include_raw_artifacts must be a bool")
    document: dict[str, object] = {
        "query": {
            "kind": result.query.kind.value,
            "identifier": result.query.identifier,
        },
        "chains": [_chain_document(chain) for chain in result.chains],
    }
    if include_raw_artifacts:
        document["raw_artifacts"] = {
            "potentially_sensitive": True,
            "paths": list(result.raw_artifact_paths),
        }
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()


def render_inspection_human(
    result: InspectionResult,
    *,
    include_raw_artifacts: bool = False,
    stdout_is_tty: bool = False,
) -> str:
    """Render a control-safe causal view without terminal styling."""
    if type(result) is not InspectionResult:
        raise TypeError("result must be an InspectionResult")
    if type(include_raw_artifacts) is not bool or type(stdout_is_tty) is not bool:
        raise TypeError("inspection render controls must be bool values")
    lines = [
        "Causal evidence view",
        f"query: {result.query.kind.value}={_terminal_text(result.query.identifier)}",
    ]
    for ordinal, chain in enumerate(result.chains, start=1):
        trace = chain.trace
        delivery = chain.delivery_record
        response = _object_or_empty(delivery.get("response"))
        observation = chain.observation_record
        assertion = chain.assertion_record
        lines.extend(
            (
                "",
                f"chain {ordinal}: {trace.classification.value}",
                f"  scenario: {trace.scenario_id}",
                f"  event: {trace.event_id}",
                f"  delivery: {trace.delivery_id}",
                (f"  attempt: {trace.attempt_id} (record {trace.attempt_record_id})"),
                (
                    "  attempt response: "
                    f"status={_terminal_scalar(response.get('status'))} "
                    f"digest={_terminal_scalar(response.get('body_sha256'))} "
                    f"bytes={_terminal_scalar(response.get('captured_bytes'))}"
                ),
                (f"  observation: {trace.observation_id} (record {trace.observation_record_id})"),
                (
                    "  observation status: "
                    f"{_terminal_scalar(observation.get('status'))}; "
                    "evidence="
                    f"{_terminal_json(observation.get('evidence', []))}"
                ),
                (f"  assertion: {trace.assertion_id} (record {trace.assertion_record_id})"),
                (
                    "  assertion result: "
                    f"{_terminal_scalar(assertion.get('result'))}; "
                    f"expected={_terminal_json(assertion.get('expected'))}; "
                    f"actual={_terminal_json(assertion.get('actual'))}"
                ),
                ("  immediate evidence: " + ", ".join(trace.immediate_evidence_refs)),
                (
                    "  mutations: "
                    + (
                        ", ".join(_terminal_text(value) for value in trace.mutation_refs)
                        if trace.mutation_refs
                        else "(none)"
                    )
                ),
                (
                    "  diagnostics: "
                    + (", ".join(chain.diagnostic_ids) if chain.diagnostic_ids else "(none)")
                ),
            )
        )
    if include_raw_artifacts:
        lines.extend(("", "Potentially sensitive raw artifact paths:"))
        if stdout_is_tty:
            lines.append(RAW_ARTIFACT_WARNING)
        lines.extend(f"  {_terminal_text(value)}" for value in result.raw_artifact_paths)
    return "\n".join(lines) + "\n"


def register_inspect_command(
    app: typer.Typer,
    loader: InspectionIndexLoader,
) -> None:
    """Mount the inspect command without owning the top-level CLI application."""
    if type(app) is not typer.Typer:
        raise TypeError("app must be a Typer application")
    if not callable(loader):
        raise TypeError("loader must be callable")

    def command(
        run_directory: Path = typer.Argument(
            ...,
            exists=True,
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
            help="Local run directory to inspect.",
        ),
        identifier: str = typer.Option(
            ...,
            "--identifier",
            help="Exact identifier to trace.",
        ),
        kind: InspectionIdentifierKind = typer.Option(
            ...,
            "--kind",
            case_sensitive=False,
            help=(
                "Identifier kind: scenario, event, delivery, attempt, "
                "observation, assertion, or diagnostic."
            ),
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Write deterministic JSON instead of the human view.",
        ),
        raw_artifacts: bool = typer.Option(
            False,
            "--raw-artifacts",
            help="Include potentially sensitive run-bundle blob paths.",
        ),
    ) -> None:
        index = loader(run_directory)
        result = index.query(
            InspectionQuery(kind=kind, identifier=identifier),
            include_raw_artifacts=raw_artifacts,
        )
        if json_output:
            typer.echo(
                render_inspection_json(
                    result,
                    include_raw_artifacts=raw_artifacts,
                ).decode(),
                nl=False,
            )
            return
        typer.echo(
            render_inspection_human(
                result,
                include_raw_artifacts=raw_artifacts,
                stdout_is_tty=bool(typer.get_text_stream("stdout").isatty()),
            ),
            nl=False,
        )

    app.command("inspect", help=INSPECT_COMMAND_HELP)(command)


def _matches(chain: InspectionCausalChain, query: InspectionQuery) -> bool:
    trace = chain.trace
    match query.kind:
        case InspectionIdentifierKind.SCENARIO:
            return query.identifier == trace.scenario_id
        case InspectionIdentifierKind.EVENT:
            return query.identifier == trace.event_id
        case InspectionIdentifierKind.DELIVERY:
            return query.identifier == trace.delivery_id
        case InspectionIdentifierKind.ATTEMPT:
            return query.identifier in {
                trace.attempt_id,
                trace.attempt_record_id,
            }
        case InspectionIdentifierKind.OBSERVATION:
            return query.identifier in {
                trace.observation_id,
                trace.observation_record_id,
            }
        case InspectionIdentifierKind.ASSERTION:
            return query.identifier in {
                trace.assertion_id,
                trace.assertion_record_id,
            }
        case InspectionIdentifierKind.DIAGNOSTIC:
            return query.identifier in chain.diagnostic_ids


def _chain_document(chain: InspectionCausalChain) -> dict[str, object]:
    trace = chain.trace
    return {
        "classification": trace.classification.value,
        "scenario_id": trace.scenario_id,
        "event_id": trace.event_id,
        "delivery_id": trace.delivery_id,
        "attempt_id": trace.attempt_id,
        "attempt_record_id": trace.attempt_record_id,
        "observation_id": trace.observation_id,
        "observation_record_id": trace.observation_record_id,
        "assertion_id": trace.assertion_id,
        "assertion_record_id": trace.assertion_record_id,
        "immediate_evidence_refs": list(trace.immediate_evidence_refs),
        "mutation_refs": list(trace.mutation_refs),
        "diagnostic_ids": list(chain.diagnostic_ids),
        "delivery_record": dict(chain.delivery_record),
        "observation_record": dict(chain.observation_record),
        "assertion_record": dict(chain.assertion_record),
    }


def _validate_trace_resolution(
    trace: FailureCausalTrace,
    *,
    manifest_edges: set[tuple[str, str, str]],
    delivery: Mapping[str, object],
    observation: Mapping[str, object],
    assertion: Mapping[str, object],
) -> None:
    if (trace.scenario_id, trace.event_id, trace.delivery_id) not in manifest_edges:
        raise InspectionError("causal trace does not resolve in the run manifest")
    expected_delivery = {
        "record_id": trace.attempt_record_id,
        "scenario_id": trace.scenario_id,
        "event_id": trace.event_id,
        "delivery_id": trace.delivery_id,
        "attempt_id": trace.attempt_id,
    }
    expected_observation = {
        "record_id": trace.observation_record_id,
        "scenario_id": trace.scenario_id,
        "observation_id": trace.observation_id,
    }
    expected_assertion = {
        "record_id": trace.assertion_record_id,
        "scenario_id": trace.scenario_id,
        "assertion_id": trace.assertion_id,
    }
    for record, expected in (
        (delivery, expected_delivery),
        (observation, expected_observation),
        (assertion, expected_assertion),
    ):
        if any(record.get(name) != value for name, value in expected.items()):
            raise InspectionError("causal trace and sanitized record identifiers differ")


def _manifest_edges(manifest: Mapping[str, object]) -> set[tuple[str, str, str]]:
    scenarios = _object_list(manifest.get("scenarios"), name="manifest scenarios")
    edges: set[tuple[str, str, str]] = set()
    for scenario in scenarios:
        scenario_id = _required_text(scenario, "scenario_id")
        events = _object_list(scenario.get("events", []), name="manifest events")
        event_ids = {_required_text(event, "event_id") for event in events}
        deliveries = _object_list(
            scenario.get("deliveries", []),
            name="manifest deliveries",
        )
        for delivery in deliveries:
            event_id = _required_text(delivery, "event_id")
            if event_id not in event_ids:
                raise InspectionError("manifest delivery refers to an unknown event")
            edges.add(
                (
                    scenario_id,
                    event_id,
                    _required_text(delivery, "delivery_id"),
                )
            )
    return edges


def _unique_record_map(
    records: list[dict[str, object]],
    *,
    name: str,
) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for record in records:
        record_id = _required_text(record, "record_id")
        if record_id in result:
            raise InspectionError(f"{name} record IDs must be unique")
        result[record_id] = record
    return result


def _require_record(
    values: Mapping[str, Mapping[str, object]],
    record_id: str,
    *,
    name: str,
) -> Mapping[str, object]:
    value = values.get(record_id)
    if value is None:
        raise InspectionError(f"causal {name} record is missing")
    return value


def _required_text(value: Mapping[str, object], name: str) -> str:
    result = value.get(name)
    if type(result) is not str or not result:
        raise InspectionError(f"{name} must be nonempty text")
    return result


def _json_document(value: bytes) -> dict[str, object]:
    if len(value) > MAX_INSPECTION_ARTIFACT_BYTES:
        raise InspectionError("inspection JSON exceeds the local byte limit")
    try:
        parsed: object = json.loads(
            value,
            parse_constant=_reject_non_json_number,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise InspectionError("inspection input contains invalid JSON") from error
    if not isinstance(parsed, dict):
        raise InspectionError("inspection document must be a JSON object")
    untyped = cast("dict[object, object]", parsed)
    if any(type(key) is not str for key in untyped):
        raise InspectionError("inspection JSON object keys must be text")
    return cast("dict[str, object]", parsed)


def _json_lines(value: bytes) -> list[dict[str, object]]:
    if len(value) > MAX_INSPECTION_ARTIFACT_BYTES:
        raise InspectionError("inspection JSON Lines exceed the local byte limit")
    records: list[dict[str, object]] = []
    try:
        for line in value.splitlines():
            parsed: object = json.loads(
                line,
                parse_constant=_reject_non_json_number,
            )
            if not isinstance(parsed, dict):
                raise InspectionError("inspection JSON Lines records must be objects")
            untyped = cast("dict[object, object]", parsed)
            if any(type(key) is not str for key in untyped):
                raise InspectionError("inspection record keys must be text")
            records.append(cast("dict[str, object]", parsed))
    except (UnicodeDecodeError, ValueError) as error:
        if isinstance(error, InspectionError):
            raise
        raise InspectionError("inspection input contains invalid JSON Lines") from error
    return records


def _object_list(value: object, *, name: str) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise InspectionError(f"{name} must be a list of objects")
    items = cast("list[object]", value)
    result: list[dict[str, object]] = []
    for item in items:
        if not isinstance(item, dict):
            raise InspectionError(f"{name} must be a list of objects")
        untyped = cast("dict[object, object]", item)
        if any(type(key) is not str for key in untyped):
            raise InspectionError(f"{name} object keys must be text")
        result.append(cast("dict[str, object]", item))
    return result


def _object_or_empty(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        return {}
    untyped = cast("dict[object, object]", value)
    if any(type(key) is not str for key in untyped):
        return {}
    return cast("dict[str, object]", value)


def _validate_raw_artifact_paths(values: tuple[str, ...]) -> None:
    if (
        type(values) is not tuple
        or len(values) > MAX_RAW_ARTIFACT_PATHS
        or any(type(value) is not str for value in values)
    ):
        raise TypeError("raw_artifact_paths must be a bounded string tuple")
    for value in values:
        if (
            not value
            or len(value) > 1_024
            or "\\" in value
            or _CONTROL_CHARACTERS.search(value) is not None
        ):
            raise ValueError("raw artifact path is malformed")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or str(path) != value
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("raw artifact path must stay relative")
    if len(set(values)) != len(values):
        raise ValueError("raw artifact paths must be unique")


def _terminal_text(value: str) -> str:
    return _CONTROL_CHARACTERS.sub("\N{REPLACEMENT CHARACTER}", value)[:MAX_INSPECTION_TEXT]


def _terminal_scalar(value: object) -> str:
    if value is None:
        return "-"
    if type(value) in {str, int, float, bool}:
        return _terminal_text(str(value))
    return "[complex]"


def _terminal_json(value: object) -> str:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return "[invalid]"
    return _terminal_text(rendered)


def _reject_non_json_number(value: str) -> object:
    raise ValueError(f"non-JSON numeric constant is forbidden: {value}")


__all__ = [
    "INSPECT_COMMAND_HELP",
    "RAW_ARTIFACT_WARNING",
    "InspectionCausalChain",
    "InspectionDiagnosticLink",
    "InspectionError",
    "InspectionIdentifierKind",
    "InspectionIndex",
    "InspectionIndexLoader",
    "InspectionNotFoundError",
    "InspectionQuery",
    "InspectionResult",
    "build_inspection_index",
    "register_inspect_command",
    "render_inspection_human",
    "render_inspection_json",
]
