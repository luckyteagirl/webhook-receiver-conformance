"""Selected-format offline report command contract and stable output views."""
# ruff: noqa: B008, D105, EM101, FBT001, FBT003, INP001, TC003, TRY003

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

import typer

from webhook_receiver_conformance.domain.identifiers import validate_run_id
from webhook_receiver_conformance.journal.artifacts import ArtifactRecord

REPORT_COMMAND_HELP: Final = "Regenerate selected report formats solely from a local run journal."
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ARTIFACT_PATHS_BY_FORMAT: Final = {
    "json": frozenset(
        {
            "run-manifest.json",
            "deliveries.jsonl",
            "observations.jsonl",
            "assertions.jsonl",
            "result-summary.json",
        }
    ),
    "junit": frozenset({"junit.xml"}),
    "html": frozenset({"results.html"}),
}


class ReportFormat(StrEnum):
    """Report formats selectable by the CLI."""

    JSON = "json"
    JUNIT = "junit"
    HTML = "html"


@dataclass(frozen=True, slots=True)
class ReportCommandRequest:
    """One local report-regeneration request."""

    run_directory: Path
    formats: tuple[ReportFormat, ...]

    def __post_init__(self) -> None:
        if (
            type(self.formats) is not tuple
            or not self.formats
            or any(type(value) is not ReportFormat for value in self.formats)
            or len(set(self.formats)) != len(self.formats)
        ):
            raise ValueError("formats must contain unique ReportFormat values")


@dataclass(frozen=True, slots=True)
class ReportCommandResult:
    """Selected registered artifacts produced by one offline regeneration."""

    run_id: str
    formats: tuple[ReportFormat, ...]
    normalized_digest: str
    records: tuple[ArtifactRecord, ...]

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        if (
            type(self.formats) is not tuple
            or not self.formats
            or any(type(value) is not ReportFormat for value in self.formats)
            or len(set(self.formats)) != len(self.formats)
        ):
            raise ValueError("formats must contain unique ReportFormat values")
        if (
            type(self.normalized_digest) is not str
            or _SHA256.fullmatch(self.normalized_digest) is None
        ):
            raise ValueError("normalized_digest must be a lowercase SHA-256 digest")
        if type(self.records) is not tuple or any(
            type(value) is not ArtifactRecord for value in self.records
        ):
            raise TypeError("records must contain ArtifactRecord values")
        expected = selected_artifact_paths(self.formats)
        actual = frozenset(value.relative_path for value in self.records)
        if actual != expected or len(actual) != len(self.records):
            raise ValueError("records differ from the selected report formats")


class ReportCommandExecutor(Protocol):
    """Local journal adapter mounted into the final top-level CLI."""

    def __call__(self, request: ReportCommandRequest) -> ReportCommandResult:
        """Regenerate selected reports without contacting a receiver."""
        ...


def selected_artifact_paths(
    formats: tuple[ReportFormat, ...],
) -> frozenset[str]:
    """Return the exact fixed artifact paths for a format selection."""
    if (
        type(formats) is not tuple
        or not formats
        or any(type(value) is not ReportFormat for value in formats)
    ):
        raise ValueError("formats must contain ReportFormat values")
    result: set[str] = set()
    for value in formats:
        result.update(_ARTIFACT_PATHS_BY_FORMAT[value.value])
    return frozenset(result)


def select_registered_artifacts(
    records: tuple[ArtifactRecord, ...],
    formats: tuple[ReportFormat, ...],
) -> tuple[ArtifactRecord, ...]:
    """Filter a complete writer result to the explicit command selection."""
    if type(records) is not tuple or any(type(value) is not ArtifactRecord for value in records):
        raise TypeError("records must contain ArtifactRecord values")
    selected = selected_artifact_paths(formats)
    result = tuple(
        sorted(
            (value for value in records if value.relative_path in selected),
            key=lambda value: value.relative_path,
        )
    )
    if frozenset(value.relative_path for value in result) != selected:
        raise ValueError("complete registry lacks one selected report artifact")
    return result


def render_report_json(result: ReportCommandResult) -> bytes:
    """Render deterministic machine-readable report-command output."""
    if type(result) is not ReportCommandResult:
        raise TypeError("result must be a ReportCommandResult")
    document = {
        "run_id": result.run_id,
        "formats": [value.value for value in result.formats],
        "normalized_digest": result.normalized_digest,
        "artifacts": [
            {
                "relative_path": value.relative_path,
                "media_type": value.media_type,
                "byte_length": value.byte_length,
                "sha256": value.sha256,
            }
            for value in result.records
        ],
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


def render_report_human(result: ReportCommandResult) -> str:
    """Render a control-safe report regeneration summary."""
    if type(result) is not ReportCommandResult:
        raise TypeError("result must be a ReportCommandResult")
    lines = [
        "Reports regenerated from local journal",
        f"run_id: {_terminal_text(result.run_id)}",
        "formats: " + ", ".join(value.value for value in result.formats),
        f"normalized_digest: {result.normalized_digest}",
        "artifacts:",
    ]
    lines.extend(
        (
            f"  {_terminal_text(value.relative_path)} "
            f"({value.media_type}, {value.byte_length} bytes, {value.sha256})"
        )
        for value in result.records
    )
    return "\n".join(lines) + "\n"


def register_report_command(
    app: typer.Typer,
    executor: ReportCommandExecutor,
) -> None:
    """Mount the report command without owning the top-level CLI application."""
    if type(app) is not typer.Typer:
        raise TypeError("app must be a Typer application")
    if not callable(executor):
        raise TypeError("executor must be callable")

    def command(
        run_directory: Path = typer.Argument(
            ...,
            exists=True,
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
            help="Local run directory containing the journal.",
        ),
        formats: list[ReportFormat] = typer.Option(
            None,
            "--format",
            case_sensitive=False,
            help="Format to regenerate; repeat for multiple formats. Defaults to all.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Write deterministic JSON instead of the human summary.",
        ),
    ) -> None:
        selected = (
            (ReportFormat.JSON, ReportFormat.JUNIT, ReportFormat.HTML)
            if not formats
            else tuple(dict.fromkeys(formats))
        )
        result = executor(
            ReportCommandRequest(
                run_directory=run_directory,
                formats=selected,
            )
        )
        if json_output:
            typer.echo(render_report_json(result).decode(), nl=False)
            return
        typer.echo(render_report_human(result), nl=False)

    app.command("report", help=REPORT_COMMAND_HELP)(command)


def _terminal_text(value: str) -> str:
    return _CONTROL_CHARACTERS.sub("\N{REPLACEMENT CHARACTER}", value)[:4_096]


__all__ = [
    "REPORT_COMMAND_HELP",
    "ReportCommandExecutor",
    "ReportCommandRequest",
    "ReportCommandResult",
    "ReportFormat",
    "register_report_command",
    "render_report_human",
    "render_report_json",
    "select_registered_artifacts",
    "selected_artifact_paths",
]
