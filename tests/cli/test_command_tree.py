"""Public command-tree, output-channel, and safety contracts."""
# ruff: noqa: EM101, INP001, S105, TRY003

from __future__ import annotations

import json
import re
import socket
import subprocess
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from webhook_receiver_conformance.cli import main as cli_main
from webhook_receiver_conformance.cli.exit_codes import (
    CommandSurface,
    process_exit_code,
)
from webhook_receiver_conformance.cli.main import app
from webhook_receiver_conformance.errors import ExitCode, ResultCategory

if TYPE_CHECKING:
    from pathlib import Path

COMMANDS = (
    "init",
    "validate",
    "plan",
    "run",
    "resume",
    "replay",
    "inspect",
    "report",
    "version",
)
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def project(runner: CliRunner, tmp_path: Path) -> Path:
    root = tmp_path / "project"
    result = runner.invoke(app, ["init", str(root)])
    assert result.exit_code == 0, result.output
    return root


@pytest.mark.parametrize("command", COMMANDS)
def test_every_public_command_has_stable_help(runner: CliRunner, command: str) -> None:
    result = runner.invoke(app, [command, "--help"], env={"NO_COLOR": "1"})
    assert result.exit_code == 0
    assert "Usage:" in result.stdout
    assert ANSI.search(result.stdout) is None


def test_version_json_is_one_document(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--json", "version"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["package"] == "0.1.0"
    assert document["configuration_schema"] == "1.0"
    assert result.stdout.count("\n") == 1
    assert result.stderr == ""


def test_validate_is_offline_and_does_not_launch_observer(
    runner: CliRunner,
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("offline validation attempted an external effect")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = runner.invoke(
        app,
        ["validate", "--config", str(project / "webhook-conformance.yaml")],
    )
    assert result.exit_code == 0
    assert "Configuration valid" in result.stdout
    assert result.stderr == ""


def test_unsupported_schema_is_exit_six_with_supported_range(
    runner: CliRunner,
    project: Path,
) -> None:
    config = project / "webhook-conformance.yaml"
    config.write_text(config.read_text().replace("schema_version: 1", "schema_version: 2"))
    result = runner.invoke(app, ["validate", "--config", str(config)])
    assert result.exit_code == ExitCode.UNSUPPORTED
    assert result.stdout == ""
    assert "schema" in result.stderr.casefold()
    assert "1" in result.stderr


def test_failed_validation_keeps_default_stdout_empty(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("schema_version: 1\nunknown: true\n")
    result = runner.invoke(app, ["validate", "--config", str(invalid)])
    assert result.exit_code == ExitCode.INVALID_INPUT
    assert result.stdout == ""
    assert "CFG_" in result.stderr


def test_plan_is_secret_free_and_prints_destination(
    runner: CliRunner,
    project: Path,
) -> None:
    secret = "plan-secret-canary"
    destination = project / "bundle"
    result = runner.invoke(
        app,
        [
            "--json",
            "plan",
            "--config",
            str(project / "webhook-conformance.yaml"),
            "--out",
            str(destination),
        ],
        env={"WEBHOOK_TEST_SECRET": secret},
    )
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["destination"] == str(destination.resolve())
    assert destination.joinpath("run-manifest.json").is_file()
    assert secret not in result.stdout
    assert secret not in destination.joinpath("effective-configuration.json").read_text()


def test_undeclared_target_override_is_rejected_by_parser(
    runner: CliRunner,
    project: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(project / "webhook-conformance.yaml"),
            "--receiver-url",
            "http://127.0.0.1:9999",
        ],
    )
    assert result.exit_code == ExitCode.INVALID_INPUT
    assert "No such option" in result.stderr


def test_public_target_requires_matching_cli_consent_before_network(
    runner: CliRunner,
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = project / "webhook-conformance.yaml"
    text = config.read_text()
    text = text.replace(
        "url: http://127.0.0.1:8000/webhooks",
        "url: https://example.com/webhooks",
    ).replace("target_profile: loopback", "target_profile: public-authorized")
    config.write_text(text)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("public target reached network before consent")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    result = runner.invoke(
        app,
        ["run", "--config", str(config)],
        env={"WEBHOOK_TEST_SECRET": "test-secret"},
    )
    assert result.exit_code == ExitCode.INVALID_INPUT
    assert "CLI_PUBLIC_AUTHORIZATION_REQUIRED" in result.stderr


def test_internal_error_has_incident_and_debug_controls_traceback(
    runner: CliRunner,
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("private-internal-detail")

    monkeypatch.setattr(cli_main, "_resolve_secrets", explode)
    arguments = [
        "plan",
        "--config",
        str(project / "webhook-conformance.yaml"),
        "--out",
        str(project / "bundle"),
    ]
    default = runner.invoke(app, arguments)
    debug = runner.invoke(app, ["--debug", *arguments])
    assert default.exit_code == ExitCode.HARNESS_FAILURE
    assert "incident_" in default.stderr
    assert "Traceback" not in default.stderr
    assert "private-internal-detail" not in default.stderr
    assert debug.exit_code == ExitCode.HARNESS_FAILURE
    assert "Traceback" in debug.stderr


def test_resume_ambiguity_without_policy_is_offline_exit_four(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    run.joinpath("run-state.json").write_text(
        json.dumps(
            {
                "run_id": "00000000-0000-4000-8000-000000000001",
                "verdict": "ambiguous",
                "destination": "http://127.0.0.1:8000/webhooks",
            }
        )
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("resume contacted receiver without ambiguity policy")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = runner.invoke(app, ["resume", str(run)])
    assert result.exit_code == ExitCode.AMBIGUOUS
    assert "no receiver contact" in result.stderr.casefold()


def test_inspect_raw_artifacts_requires_explicit_flag_and_warns(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    run = tmp_path / "run"
    run.joinpath("blobs", "sha256").mkdir(parents=True)
    run.joinpath("blobs", "sha256", "payload").write_bytes(b"sensitive")
    run.joinpath("run-state.json").write_text(json.dumps({"run_id": "run", "verdict": "pass"}))
    run.joinpath("deliveries.jsonl").write_text(
        json.dumps(
            {
                "scenario_id": "scenario_1",
                "event_id": "event_1",
                "delivery_id": "delivery_1",
            }
        )
        + "\n"
    )
    normal = runner.invoke(app, ["--json", "inspect", str(run)])
    raw = runner.invoke(app, ["--json", "inspect", str(run), "--raw-artifacts"])
    assert "raw_artifacts" not in json.loads(normal.stdout)
    assert json.loads(raw.stdout)["raw_artifacts"]["potentially_sensitive"] is True
    assert "WARNING" in raw.stderr


def test_no_color_and_hostile_text_never_emit_terminal_controls(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    hostile = tmp_path / "bad-\x1b]0;owned\x07.yaml"
    result = runner.invoke(
        app,
        ["validate", "--config", str(hostile)],
        env={"NO_COLOR": "1"},
    )
    assert result.exit_code == ExitCode.INVALID_INPUT
    assert ANSI.search(result.stdout + result.stderr) is None
    assert "\x07" not in result.stdout + result.stderr


def test_terminal_result_mapping_is_identical_across_execution_surfaces() -> None:
    for category in ResultCategory:
        codes = {process_exit_code(category, surface=surface) for surface in CommandSurface}
        assert len(codes) == 1
