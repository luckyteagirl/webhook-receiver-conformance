"""Mountable command contract for one durable local webhook execution."""
# ruff: noqa: B008, D105, EM101, FBT001, FBT003, TRY003

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

import typer

from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.runtime.runner import VerticalSliceRunResult

RUN_COMMAND_HELP: Final = (
    "Compile one local delivery, execute it through the durable journal, "
    "and write local JSON evidence."
)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class RunCommandRequest:
    """CLI inputs retained until configuration and secret resolution."""

    config_path: Path
    manifest_path: Path | None
    output_directory: Path | None
    runtime_public_authorization: str | None

    def __post_init__(self) -> None:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.config_path,
            Path,
        ):
            raise TypeError("config_path must be a Path")
        if self.manifest_path is not None and not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.manifest_path,
            Path,
        ):
            raise TypeError("manifest_path must be a Path or None")
        if self.output_directory is not None and not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.output_directory,
            Path,
        ):
            raise TypeError("output_directory must be a Path or None")
        if self.runtime_public_authorization is not None and (
            type(self.runtime_public_authorization) is not str
            or not self.runtime_public_authorization
        ):
            raise ValueError("runtime_public_authorization must be nonempty text or None")


class RunCommandExecutor(Protocol):
    """Application adapter that resolves inputs and invokes the async runner."""

    def __call__(self, request: RunCommandRequest) -> VerticalSliceRunResult:
        """Execute one local journal-backed run and return its terminal facts."""
        ...


def render_run_json(result: VerticalSliceRunResult) -> bytes:
    """Render deterministic machine-readable command output."""
    if type(result) is not VerticalSliceRunResult:
        raise TypeError("result must be a VerticalSliceRunResult")
    document = {
        "command": "run",
        "run_id": result.run_id,
        "manifest_id": result.manifest_id,
        "run_directory": str(result.run_directory),
        "database_path": str(result.database_path),
        "attempt_id": result.attempt_id,
        "attempt_state": result.attempt_state.value,
        "classification": result.classification.value,
        "verdict": result.result_category.value,
        "exit_code": int(result.exit_code),
        "summary_path": str(result.summary_path),
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


def render_run_human(result: VerticalSliceRunResult) -> str:
    """Render a bounded control-safe terminal summary."""
    if type(result) is not VerticalSliceRunResult:
        raise TypeError("result must be a VerticalSliceRunResult")
    return "\n".join(
        (
            f"Run {result.run_id}: {result.result_category.value}",
            f"Manifest: {result.manifest_id}",
            f"Attempt: {result.attempt_id} ({result.classification.value})",
            f"Run directory: {_terminal_text(str(result.run_directory))}",
            f"Summary: {_terminal_text(str(result.summary_path))}",
            "",
        )
    )


def register_run_command(
    app: typer.Typer,
    executor: RunCommandExecutor,
) -> None:
    """Mount the run command without owning the top-level application."""
    if type(app) is not typer.Typer:
        raise TypeError("app must be a Typer application")
    if not callable(executor):
        raise TypeError("executor must be callable")

    def command(
        config: Path = typer.Option(
            Path("webhook-conformance.yaml"),
            "--config",
            "-c",
            help="Project configuration file.",
        ),
        manifest: Path | None = typer.Option(
            None,
            "--manifest",
            help="Existing immutable bundle or run-manifest.json to verify and execute.",
        ),
        output: Path | None = typer.Option(
            None,
            "--output",
            help="Root directory for distinct local run directories.",
        ),
        authorize_public_target: str | None = typer.Option(
            None,
            "--authorize-public-target",
            help="Exact HOST:PORT runtime consent for a configured public target.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Write deterministic JSON instead of the human summary.",
        ),
    ) -> None:
        result = executor(
            RunCommandRequest(
                config_path=config.resolve(strict=False),
                manifest_path=(None if manifest is None else manifest.resolve(strict=False)),
                output_directory=(None if output is None else output.resolve(strict=False)),
                runtime_public_authorization=authorize_public_target,
            )
        )
        if json_output:
            typer.echo(render_run_json(result).decode(), nl=False)
        else:
            typer.echo(render_run_human(result), nl=False)
        if result.result_category is not ResultCategory.PASS:
            raise typer.Exit(int(result.exit_code))

    app.command("run", help=RUN_COMMAND_HELP)(command)


def _terminal_text(value: str) -> str:
    return _CONTROL_CHARACTERS.sub("\N{REPLACEMENT CHARACTER}", value)[:4_096]


__all__ = [
    "RUN_COMMAND_HELP",
    "RunCommandExecutor",
    "RunCommandRequest",
    "register_run_command",
    "render_run_human",
    "render_run_json",
]
