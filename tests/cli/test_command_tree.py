"""Public command-tree, output-channel, and safety contracts."""
# ruff: noqa: EM101, INP001, S105, TRY003

from __future__ import annotations

import json
import re
import socket
import subprocess
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from typer.testing import CliRunner

from webhook_receiver_conformance.cli import main as cli_main
from webhook_receiver_conformance.cli.exit_codes import (
    CommandSurface,
    process_exit_code,
)
from webhook_receiver_conformance.cli.inspect import InspectionIndex
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


def test_run_manifest_executes_verified_bundle_with_fresh_config(
    runner: CliRunner,
    project: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_directory = tmp_path / "bundle"
    bundle_directory.mkdir()
    run_directory = tmp_path / "runs" / "loaded"
    run_directory.mkdir(parents=True)
    bundle = SimpleNamespace(directory=bundle_directory)
    terminal = SimpleNamespace(
        run_id="00000000-0000-4000-8000-000000000001",
        manifest_id="a" * 64,
        run_directory=run_directory,
        result_category=ResultCategory.PASS,
        exit_code=ExitCode.PASS,
    )
    report = SimpleNamespace(normalized_digest=f"sha256:{'b' * 64}")
    captured: dict[str, object] = {}
    preparation = SimpleNamespace(close=lambda: None)

    def load_bundle(path: Path) -> object:
        captured["bundle_path"] = path
        return bundle

    class LoadedRunner:
        def prepare_loaded(self, request: object, selected_bundle: object) -> object:
            captured["validated_request"] = request
            captured["validated_bundle"] = selected_bundle
            return preparation

        async def run_prepared_loaded(self, selected_preparation: object) -> object:
            assert selected_preparation is preparation
            captured["request"] = captured["validated_request"]
            captured["bundle"] = captured["validated_bundle"]
            return terminal

    def full_runner(*_args: object, **_kwargs: object) -> object:
        return LoadedRunner()

    async def regenerate(selected_run: Path) -> object:
        assert selected_run == run_directory
        return report

    monkeypatch.setattr(cli_main, "load_replay_bundle", load_bundle)
    monkeypatch.setattr(cli_main, "_full_run_runner", full_runner)
    monkeypatch.setattr(cli_main, "_regenerate_run_reports", regenerate)

    result = runner.invoke(
        app,
        [
            "--json",
            "run",
            "--config",
            str(project / "webhook-conformance.yaml"),
            "--manifest",
            str(bundle_directory),
        ],
        env={"WEBHOOK_TEST_SECRET": "fresh-run-manifest-secret"},
    )

    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["command"] == "run"
    assert document["manifest_id"] == terminal.manifest_id
    assert captured["bundle_path"] == bundle_directory.resolve()
    assert captured["bundle"] is bundle
    assert captured["validated_bundle"] is bundle
    assert captured["validated_request"] is captured["request"]
    assert captured["request"] is not None
    state = json.loads(run_directory.joinpath("run-state.json").read_text(encoding="utf-8"))
    assert state["replayed_from"] == str(bundle_directory)


@pytest.mark.parametrize("command", ["run", "replay"])
def test_loaded_public_execution_validates_locally_before_nonce_contact(  # noqa: C901
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    bundle_directory = tmp_path / "bundle"
    bundle_directory.mkdir()
    bundle = SimpleNamespace(directory=bundle_directory)
    config = SimpleNamespace(
        receiver=SimpleNamespace(
            target_profile=cli_main.TargetProfile.PUBLIC_AUTHORIZED,
            url="https://receiver.example/hook",
        ),
        project=SimpleNamespace(artifact_directory="artifacts"),
    )
    loaded = SimpleNamespace(config=config, project_root=tmp_path)
    trace: list[str] = []

    class OrderedRunner:
        def prepare_loaded(self, request: object, selected_bundle: object) -> object:
            del request
            assert selected_bundle is bundle
            trace.append("local_validation")
            raise ValueError("fresh replay configuration differs from the verified bundle")

        async def run_prepared_loaded(self, preparation: object) -> object:
            del preparation
            trace.append("fixture_send")
            raise AssertionError("invalid loaded execution reached a fixture send")

    def public_preflight(*_args: object, **_kwargs: object) -> None:
        trace.append("public_nonce_challenge")
        raise AssertionError("invalid loaded execution reached public preflight")

    class FakeSecrets:
        def __init__(self) -> None:
            self.handles: dict[str, object] = {}
            self.fingerprints: dict[str, str] = {}

        def close(self) -> None:
            return

    def load_bundle(_path: Path) -> object:
        return bundle

    def load_config(*_args: object, **_kwargs: object) -> object:
        return loaded

    def require_loaded(candidate: object) -> object:
        return candidate

    def resolve_secrets(*_args: object, **_kwargs: object) -> FakeSecrets:
        return FakeSecrets()

    def build_signers(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {}

    def full_runner(*_args: object, **_kwargs: object) -> object:
        return OrderedRunner()

    def build_request(**kwargs: object) -> object:
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(cli_main, "load_replay_bundle", load_bundle)
    monkeypatch.setattr(cli_main, "_load_config", load_config)
    monkeypatch.setattr(cli_main, "_require_loaded", require_loaded)
    monkeypatch.setattr(cli_main, "_resolve_secrets", resolve_secrets)
    monkeypatch.setattr(cli_main, "_build_signers", build_signers)
    monkeypatch.setattr(cli_main, "_full_run_runner", full_runner)
    monkeypatch.setattr(cli_main, "FullRunRequest", build_request)
    monkeypatch.setattr(cli_main, "_perform_public_preflight", public_preflight)

    arguments = (
        [
            command,
            "--manifest",
            str(bundle_directory),
            "--config",
            "ignored.yaml",
            "--authorize-public-target",
            "receiver.example:443",
        ]
        if command == "run"
        else [
            command,
            str(bundle_directory),
            "--config",
            "ignored.yaml",
            "--authorize-public-target",
            "receiver.example:443",
        ]
    )
    result = runner.invoke(app, arguments)

    assert result.exit_code == ExitCode.INVALID_INPUT
    assert "fresh replay configuration differs" in result.stderr
    assert trace == ["local_validation"]


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

    bundle = SimpleNamespace(
        manifest=SimpleNamespace(
            target_policy=SimpleNamespace(
                authorized_host="127.0.0.1",
                authorized_port=8000,
            )
        )
    )
    resume_result = SimpleNamespace(
        status=SimpleNamespace(value="ambiguous_read_only"),
        run_id="00000000-0000-4000-8000-000000000001",
        owner_epoch=0,
        result_category=ResultCategory.AMBIGUOUS,
        exit_code=ExitCode.AMBIGUOUS,
        read_only=True,
        ambiguous_attempt_ids=("attempt_00000000000000000000000001",),
        redeliveries_invoked=0,
        observations_invoked=0,
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("resume contacted receiver without ambiguity policy")

    def fake_resume(request: object, **callbacks: object) -> object:
        assert request.invocation.on_ambiguous is None  # type: ignore[attr-defined]
        assert request.manifest is bundle.manifest  # type: ignore[attr-defined]
        assert request.defer_redeliveries is True  # type: ignore[attr-defined]
        assert set(callbacks) == {"prepare", "continuation"}
        return SimpleNamespace(recovery=resume_result, continuation=None)

    def fake_bundle(_path: Path) -> object:
        return bundle

    def fake_request(**values: object) -> object:
        return SimpleNamespace(**values)

    monkeypatch.setattr(cli_main, "load_replay_bundle", fake_bundle)
    monkeypatch.setattr(cli_main, "ResumeRequest", fake_request)
    monkeypatch.setattr(cli_main, "resume_and_continue_sync", fake_resume)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = runner.invoke(app, ["resume", str(run)])
    assert result.exit_code == ExitCode.AMBIGUOUS
    assert "no receiver contact" in result.stderr.casefold()


def test_resume_continue_executes_same_run_and_emits_terminal_result(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    config = tmp_path / "project.yaml"
    config.write_text("not read by this command test\n", encoding="utf-8")
    manifest = SimpleNamespace(
        target_policy=SimpleNamespace(
            authorized_host="127.0.0.1",
            authorized_port=8000,
        )
    )
    recovery = SimpleNamespace(
        status=cli_main.ResumeStatus.CONTINUE,
        run_id="00000000-0000-4000-8000-000000000001",
        owner_epoch=1,
        result_category=None,
        exit_code=None,
        read_only=False,
        ambiguous_attempt_ids=("attempt_00000000000000000000000001",),
        redeliveries_invoked=0,
        observations_invoked=0,
        policy_plan=SimpleNamespace(redeliveries=(object(),)),
    )
    terminal = SimpleNamespace(
        run_id=recovery.run_id,
        manifest_id="a" * 64,
        run_directory=run,
        result_category=ResultCategory.PASS,
        exit_code=ExitCode.PASS,
    )
    report = SimpleNamespace(normalized_digest=f"sha256:{'b' * 64}")
    loaded = SimpleNamespace(
        config=SimpleNamespace(receiver=SimpleNamespace(url="http://127.0.0.1:8000/hook"))
    )

    def fake_request(**values: object) -> object:
        return SimpleNamespace(**values)

    def fake_bundle(_path: Path) -> object:
        return SimpleNamespace(manifest=manifest)

    def fake_resume(_request: object, **callbacks: object) -> object:
        assert set(callbacks) == {"prepare", "continuation"}
        return SimpleNamespace(recovery=recovery, continuation=object())

    def fake_completed(_workflow: object) -> object:
        return SimpleNamespace(
            result=terminal,
            report=report,
            loaded=loaded,
        )

    monkeypatch.setattr(cli_main, "load_replay_bundle", fake_bundle)
    monkeypatch.setattr(cli_main, "ResumeRequest", fake_request)
    monkeypatch.setattr(cli_main, "resume_and_continue_sync", fake_resume)
    monkeypatch.setattr(cli_main, "_completed_resume", fake_completed)

    result = runner.invoke(
        app,
        ["--json", "resume", str(run), "--config", str(config), "--on-ambiguous", "redeliver"],
    )

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["run_id"] == recovery.run_id
    assert document["status"] == "continue"
    assert document["verdict"] == "pass"
    assert document["redeliveries_scheduled"] == 1


def test_resume_preserves_classified_public_preflight_exit(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    manifest = SimpleNamespace(
        target_policy=SimpleNamespace(
            authorized_host="receiver.example",
            authorized_port=443,
        )
    )

    def fake_bundle(_path: Path) -> object:
        return SimpleNamespace(manifest=manifest)

    def fake_request(**values: object) -> object:
        return SimpleNamespace(**values)

    def fail_during_continuation(_request: object, **_callbacks: object) -> object:
        cli_main._fail(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            ResultCategory.ENVIRONMENT_ERROR,
            "CLI_PUBLIC_PREFLIGHT_CONNECTION_FAILED",
            "Public target challenge connection failed.",
        )

    monkeypatch.setattr(cli_main, "load_replay_bundle", fake_bundle)
    monkeypatch.setattr(cli_main, "ResumeRequest", fake_request)
    monkeypatch.setattr(
        cli_main,
        "resume_and_continue_sync",
        fail_during_continuation,
    )

    result = runner.invoke(
        app,
        [
            "resume",
            str(run),
            "--on-ambiguous",
            "redeliver",
            "--authorize-public-target",
            "receiver.example:443",
        ],
    )

    assert result.exit_code == ExitCode.ENVIRONMENT_FAILURE
    assert "CLI_PUBLIC_PREFLIGHT_CONNECTION_FAILED" in result.stderr
    assert "HARNESS_INTERNAL_ERROR" not in result.stderr


@pytest.mark.anyio
@pytest.mark.parametrize("case", ["valid", "invalid"])
async def test_public_resume_validates_before_challenge_and_challenges_before_send(  # noqa: C901
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    trace: list[str] = []
    run = tmp_path / "run"
    run.mkdir()
    run_id = "00000000-0000-4000-8000-000000000001"
    terminal = SimpleNamespace(
        run_id=run_id,
        manifest_id="a" * 64,
        run_directory=run,
        result_category=ResultCategory.PASS,
        exit_code=ExitCode.PASS,
    )

    class Validation:
        async def aclose(self) -> None:
            return None

    class OrderedRunner:
        async def validate_resume(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            trace.append("local_validation")
            if case == "invalid":
                raise RuntimeError("semantically invalid resume journal")
            return Validation()

        async def challenge_public_resume(
            self,
            *args: object,
            **kwargs: object,
        ) -> None:
            del args, kwargs
            trace.append("public_nonce_challenge")

        async def resume_validated(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            trace.append("fixture_send")
            return terminal

    class Ownership:
        def require_owner(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    async def report(_run_directory: Path) -> object:
        return SimpleNamespace(normalized_digest=f"sha256:{'b' * 64}")

    def discard_atomic(*_args: object, **_kwargs: object) -> None:
        return None

    def presentation(_context: object) -> object:
        return SimpleNamespace(json_output=True)

    monkeypatch.setattr(cli_main, "_PreparedResumeExecution", SimpleNamespace)
    monkeypatch.setattr(cli_main, "_regenerate_run_reports", report)
    monkeypatch.setattr(cli_main, "_atomic_json", discard_atomic)
    monkeypatch.setattr(cli_main, "_presentation", presentation)
    prepared = SimpleNamespace(
        loaded=SimpleNamespace(
            config=SimpleNamespace(
                receiver=SimpleNamespace(
                    target_profile=cli_main.TargetProfile.PUBLIC_AUTHORIZED,
                    url="https://receiver.example/webhook",
                )
            )
        ),
        secrets=object(),
        runner=OrderedRunner(),
        request=object(),
        preparation=object(),
    )
    coordinator_type = cast(
        "Any",
        cli_main._ResumeCommandCoordinator,  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    )
    coordinator = coordinator_type(
        context=SimpleNamespace(),
        run_directory=run,
        config_path=tmp_path / "project.yaml",
        project_root=None,
        on_ambiguous=None,
        authorize_public_target="receiver.example:443",
    )
    recovery = SimpleNamespace(
        run_id=run_id,
        owner_epoch=1,
        preflight=SimpleNamespace(owner_epoch=0),
    )

    if case == "invalid":
        with pytest.raises(RuntimeError, match="semantically invalid resume journal"):
            await coordinator.continue_run(recovery, Ownership(), prepared)
        assert trace == ["local_validation"]
    else:
        completed = await coordinator.continue_run(recovery, Ownership(), prepared)
        assert completed.result is terminal
        assert trace == [
            "local_validation",
            "public_nonce_challenge",
            "fixture_send",
        ]


def test_inspect_raw_artifacts_requires_explicit_flag_and_warns(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.joinpath("blobs", "sha256").mkdir(parents=True)
    run.joinpath("blobs", "sha256", "payload").write_bytes(b"sensitive")

    async def load_index(_run_directory: Path) -> InspectionIndex:
        return InspectionIndex(
            chains=(),
            raw_artifact_paths=("blobs/sha256/payload",),
        )

    monkeypatch.setattr(cli_main, "load_inspection_index", load_index)
    normal = runner.invoke(app, ["--json", "inspect", str(run)])
    raw = runner.invoke(app, ["--json", "inspect", str(run), "--raw-artifacts"])
    assert normal.exit_code == 0
    assert raw.exit_code == 0
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
