"""Cross-platform GitHub Action adapter with sanitized artifact staging."""
# ruff: noqa: C901, EM101, EM102, INP001, PLR2004, S603, S607, SIM105, T201, TRY003, TRY004, TRY300

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_COMMANDS: Final = frozenset(
    {"validate", "plan", "run", "resume", "replay", "inspect", "report", "version"}
)
_EXIT_CATEGORIES: Final = {
    0: "pass",
    1: "receiver_failure",
    2: "invalid_input",
    3: "environment_error",
    4: "ambiguous",
    5: "harness_error",
    6: "unsupported",
    130: "cancelled",
}
_SAFE_ARTIFACT_NAMES: Final = frozenset(
    {
        "assertions.jsonl",
        "deliveries.jsonl",
        "effective-configuration.json",
        "junit.xml",
        "observations.jsonl",
        "plan-preview.json",
        "report.html",
        "result-summary.json",
        "results.html",
        "run-manifest.json",
        "run-state.json",
        "summary.json",
    }
)
_SENSITIVE_CLASSES: Final = (
    "blob payloads (blobs/)",
    "raw request and response bodies",
    "observer stdout and stderr",
    "unredacted debug logs",
)


def main(environ: Mapping[str, str] | None = None) -> int:
    """Execute one action request and preserve the CLI terminal classification."""
    source = os.environ if environ is None else environ
    try:
        command = _input(source, "COMMAND", default="run")
        if command not in _COMMANDS:
            return _setup_failure(source, f"unsupported action command: {command}")
        if _input(source, "NONINTERACTIVE", default="true").casefold() != "true":
            return _setup_failure(source, "the action requires noninteractive=true")
        expected_version = _input(source, "VERSION", default="0.1.0")
        artifact_directory = _workspace_path(
            source,
            _input(source, "ARTIFACT_DIRECTORY", default=".webhook-conformance/action"),
        )
        arguments = _arguments(source, command, artifact_directory)
        completed = _run_cli(source, arguments)
        document = _json_document(completed.stdout)
        _relay(completed)
        actual_version = _document_string(document, "package")
        if command == "version" and actual_version not in {None, expected_version}:
            return _setup_failure(
                source,
                f"installed version {actual_version} does not match {expected_version}",
            )
        report_directory = _stage_sanitized_artifacts(
            artifact_directory,
            document,
            include_raw=_boolean_input(source, "INCLUDE_RAW_ARTIFACTS"),
        )
        category = _document_string(document, "verdict") or _EXIT_CATEGORIES.get(
            completed.returncode, "harness_error"
        )
        outputs = {
            "run-id": _document_string(document, "run_id") or "",
            "manifest-id": _document_string(document, "manifest_id") or "",
            "result-category": category,
            "exit-code": str(completed.returncode),
            "report-directory": str(report_directory),
        }
        _write_outputs(source, outputs)
        _write_summary(
            source,
            command=command,
            category=category,
            report_directory=report_directory,
            raw_enabled=_boolean_input(source, "INCLUDE_RAW_ARTIFACTS"),
        )
        return completed.returncode
    except (OSError, TypeError, ValueError) as error:
        return _setup_failure(source, str(error))


def _arguments(
    source: Mapping[str, str],
    command: str,
    artifact_directory: Path,
) -> list[str]:
    arguments = ["--json", command]
    config = _workspace_path(source, _input(source, "CONFIG", default="webhook-conformance.yaml"))
    if command in {"validate", "plan", "run"}:
        arguments.extend(["--config", str(config)])
    if command == "plan":
        arguments.extend(["--out", str(artifact_directory / "plan")])
    elif command == "run":
        arguments.extend(["--output", _project_relative(source, artifact_directory)])
        authorization = _input(source, "AUTHORIZE_PUBLIC_TARGET", default="")
        if authorization:
            arguments.extend(["--authorize-public-target", authorization])
    elif command == "replay":
        manifest = _input(source, "MANIFEST", default="")
        if not manifest:
            raise ValueError("manifest is required for replay")
        arguments.extend(
            [
                str(_workspace_path(source, manifest)),
                "--output",
                str(artifact_directory / "replay"),
            ]
        )
    elif command in {"resume", "inspect", "report"}:
        run_directory = _input(source, "RUN_DIRECTORY", default="")
        if not run_directory:
            raise ValueError(f"run-directory is required for {command}")
        arguments.append(str(_workspace_path(source, run_directory)))
        if command == "resume":
            arguments.extend(["--on-ambiguous", "fail"])
        if command == "inspect" and _boolean_input(source, "INCLUDE_RAW_ARTIFACTS"):
            arguments.append("--raw-artifacts")
        if command == "report":
            for report_format in _formats(source):
                arguments.extend(["--format", report_format])
    return arguments


def _run_cli(
    source: Mapping[str, str],
    arguments: Sequence[str],
) -> subprocess.CompletedProcess[str]:
    action_path = Path(source.get("GITHUB_ACTION_PATH", Path.cwd())).resolve()
    return subprocess.run(
        [
            "uv",
            "run",
            "--project",
            str(action_path),
            "--locked",
            "webhook-conformance",
            *arguments,
        ],
        cwd=_workspace(source),
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=3600,
        env={**os.environ, "NO_COLOR": "1", "WEBHOOK_CONFORMANCE_CI": "1"},
    )


def _stage_sanitized_artifacts(
    artifact_directory: Path,
    document: Mapping[str, object],
    *,
    include_raw: bool,
) -> Path:
    source_text = _document_string(document, "run_directory") or _document_string(
        document,
        "destination",
    )
    source = Path(source_text).resolve() if source_text else artifact_directory.resolve()
    destination = artifact_directory.resolve() / "sanitized"
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    if not source.is_dir():
        return destination
    for candidate in sorted(source.rglob("*")):
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            continue
        if not include_raw and candidate.name not in _SAFE_ARTIFACT_NAMES:
            continue
        relative = candidate.relative_to(source)
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(candidate, target, follow_symlinks=False)
    return destination


def _write_outputs(source: Mapping[str, str], outputs: Mapping[str, str]) -> None:
    output_path = source.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with Path(output_path).open("a", encoding="utf-8", newline="\n") as stream:
        for name, value in outputs.items():
            if "\n" in value or "\r" in value:
                raise ValueError(f"unsafe multiline action output: {name}")
            stream.write(f"{name}={value}\n")


def _write_summary(
    source: Mapping[str, str],
    *,
    command: str,
    category: str,
    report_directory: Path,
    raw_enabled: bool,
) -> None:
    summary_path = source.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    sensitive = "\n".join(f"- {item}" for item in _SENSITIVE_CLASSES)
    raw_policy = (
        "**Sensitive raw-artifact exposure was explicitly enabled. Review before upload.**"
        if raw_enabled
        else "Sensitive artifact classes were excluded from the staged report directory."
    )
    text = (
        "## Webhook Receiver Conformance\n\n"
        f"- Command: `{command}`\n"
        f"- Result: `{category}`\n"
        f"- Sanitized reports: `{report_directory}`\n\n"
        f"{raw_policy}\n\n"
        "Sensitive artifact classes:\n\n"
        f"{sensitive}\n"
    )
    with Path(summary_path).open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def _setup_failure(source: Mapping[str, str], message: str) -> int:
    safe = "".join(
        character for character in message if ord(character) >= 32 and ord(character) != 127
    )
    print(f"::error title=Webhook conformance action setup::{safe}", file=sys.stderr)
    outputs = {
        "run-id": "",
        "manifest-id": "",
        "result-category": "harness_error",
        "exit-code": "5",
        "report-directory": "",
    }
    try:
        _write_outputs(source, outputs)
    except (OSError, ValueError):
        pass
    return 5


def _relay(completed: subprocess.CompletedProcess[str]) -> None:
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)


def _json_document(value: str) -> dict[str, object]:
    if not value.strip():
        return {}
    document = json.loads(value)
    if not isinstance(document, dict):
        raise ValueError("CLI JSON output must be an object")
    return cast("dict[str, object]", document)


def _document_string(document: Mapping[str, object], name: str) -> str | None:
    value = document.get(name)
    return value if isinstance(value, str) else None


def _formats(source: Mapping[str, str]) -> tuple[str, ...]:
    values = tuple(
        value.strip()
        for value in _input(source, "FORMATS", default="json,junit,html").split(",")
        if value.strip()
    )
    supported = frozenset({"html", "json", "junit"})
    if not values or any(value not in supported for value in values):
        raise ValueError("formats must contain only json, junit, or html")
    return values


def _boolean_input(source: Mapping[str, str], name: str) -> bool:
    value = _input(source, name, default="false").casefold()
    if value not in {"true", "false"}:
        raise ValueError(f"{name.casefold().replace('_', '-')} must be true or false")
    return value == "true"


def _input(source: Mapping[str, str], name: str, *, default: str) -> str:
    value = source.get(f"INPUT_{name}", default).strip()
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError(f"invalid action input: {name.casefold().replace('_', '-')}")
    return value


def _workspace(source: Mapping[str, str]) -> Path:
    return Path(source.get("GITHUB_WORKSPACE", Path.cwd())).resolve()


def _workspace_path(source: Mapping[str, str], value: str) -> Path:
    workspace = _workspace(source)
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(workspace):
        raise ValueError("action path escapes GITHUB_WORKSPACE")
    return resolved


def _project_relative(source: Mapping[str, str], path: Path) -> str:
    return path.resolve().relative_to(_workspace(source)).as_posix()


if __name__ == "__main__":
    raise SystemExit(main())
