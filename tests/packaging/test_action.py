"""Contract tests for the least-privilege composite GitHub Action."""
# ruff: noqa: INP001

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, cast

import yaml

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from types import ModuleType

    import pytest

ROOT = Path(__file__).resolve().parents[2]
ACTION = cast(
    "dict[str, object]",
    yaml.safe_load(ROOT.joinpath("action.yml").read_text(encoding="utf-8")),
)


def _adapter() -> ModuleType:
    path = ROOT / ".github" / "actions" / "run_action.py"
    specification = importlib.util.spec_from_file_location("run_action_contract", path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_action_declares_locked_inputs_and_stable_outputs() -> None:
    inputs = cast("Mapping[str, object]", ACTION["inputs"])
    outputs = cast("Mapping[str, object]", ACTION["outputs"])
    assert set(inputs) == {
        "artifact-directory",
        "authorize-public-target",
        "command",
        "config",
        "formats",
        "include-raw-artifacts",
        "manifest",
        "noninteractive",
        "retention-days",
        "run-directory",
        "version",
    }
    assert set(outputs) == {
        "exit-code",
        "manifest-id",
        "report-directory",
        "result-category",
        "run-id",
    }
    assert cast("Mapping[str, object]", inputs["include-raw-artifacts"])["default"] == "false"
    assert cast("Mapping[str, object]", inputs["noninteractive"])["default"] == "true"


def test_action_is_composite_locked_and_does_not_upload() -> None:
    serialized = json.dumps(ACTION, sort_keys=True)
    runs = cast("Mapping[str, object]", ACTION["runs"])
    assert runs["using"] == "composite"
    assert "uv run" in serialized
    assert "--locked" in serialized
    assert "upload-artifact" not in serialized
    assert "contents: write" not in serialized


def test_adapter_preserves_cli_exit_and_stages_only_redacted_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _adapter()
    workspace = tmp_path / "workspace"
    run = workspace / "artifacts" / "run-one"
    run.joinpath("blobs", "sha256").mkdir(parents=True)
    run.joinpath("summary.json").write_text("{}\n", encoding="utf-8")
    run.joinpath("report.html").write_text("<html></html>\n", encoding="utf-8")
    run.joinpath("blobs", "sha256", "secret").write_text("secret", encoding="utf-8")
    output = tmp_path / "outputs"
    summary = tmp_path / "summary"
    completed = subprocess.CompletedProcess(
        args=["webhook-conformance"],
        returncode=1,
        stdout=json.dumps(
            {
                "run_id": "run-one",
                "manifest_id": "manifest-one",
                "run_directory": str(run),
                "verdict": "receiver_failure",
            }
        )
        + "\n",
        stderr="",
    )

    def fake_run_cli(
        _source: Mapping[str, str],
        _arguments: Sequence[str],
    ) -> subprocess.CompletedProcess[str]:
        return completed

    monkeypatch.setattr(module, "_run_cli", fake_run_cli)
    environ = {
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_ACTION_PATH": str(ROOT),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary),
        "INPUT_COMMAND": "run",
        "INPUT_CONFIG": "webhook-conformance.yaml",
        "INPUT_ARTIFACT_DIRECTORY": "artifacts",
        "INPUT_NONINTERACTIVE": "true",
        "INPUT_INCLUDE_RAW_ARTIFACTS": "false",
    }
    main = cast("Callable[[Mapping[str, str]], int]", module.main)
    assert main(environ) == 1
    staged = workspace / "artifacts" / "sanitized"
    assert staged.joinpath("summary.json").is_file()
    assert staged.joinpath("report.html").is_file()
    assert not staged.joinpath("blobs").exists()
    assert "exit-code=1" in output.read_text(encoding="utf-8")
    summary_text = summary.read_text(encoding="utf-8")
    assert "blobs/" in summary_text
    assert "observer stdout and stderr" in summary_text
