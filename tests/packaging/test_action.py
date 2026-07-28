"""Contract tests for the least-privilege composite GitHub Action."""
# ruff: noqa: INP001, S603, S607

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
_EVENT_BODY = b'{"id":"evt_action","type":"payment.succeeded","data":{"order_id":"action"}}\n'


class _RecordingServer(ThreadingHTTPServer):
    requests: list[bytes]


class _AcceptedWebhookHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        server = cast("_RecordingServer", self.server)
        server.requests.append(self.rfile.read(length))
        self.send_response(204)
        self.send_header("content-length", "0")
        self.send_header("connection", "close")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args


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


def test_action_adapter_executes_locked_cli_and_emits_every_declared_output(
    tmp_path: Path,
) -> None:
    server = _RecordingServer(("127.0.0.1", 0), _AcceptedWebhookHandler)
    server.requests = []
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        name="action-contract-receiver",
    )
    thread.start()
    try:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        workspace.joinpath("event.json").write_bytes(_EVENT_BODY)
        port = cast("tuple[str, int]", server.server_address)[1]
        workspace.joinpath("webhook-conformance.yaml").write_text(
            _configuration(port),
            encoding="utf-8",
        )
        output = tmp_path / "github-output"
        summary = tmp_path / "github-summary"
        environment = os.environ.copy()
        environment.update(
            {
                "GITHUB_ACTION_PATH": str(ROOT),
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary),
                "GITHUB_WORKSPACE": str(workspace),
                "INPUT_ARTIFACT_DIRECTORY": "action-artifacts",
                "INPUT_COMMAND": "run",
                "INPUT_CONFIG": "webhook-conformance.yaml",
                "INPUT_FORMATS": "json,junit,html",
                "INPUT_INCLUDE_RAW_ARTIFACTS": "false",
                "INPUT_NONINTERACTIVE": "true",
                "INPUT_VERSION": "0.1.0",
                "WEBHOOK_TEST_SECRET": "action-contract-local-secret",
            }
        )

        completed = subprocess.run(
            [
                "uv",
                "run",
                "--project",
                str(ROOT),
                "--locked",
                "python",
                str(ROOT / ".github" / "actions" / "run_action.py"),
            ],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        assert completed.returncode == 0, completed.stderr
        cli_document = cast("dict[str, object]", json.loads(completed.stdout))
        emitted = _action_outputs(output)
        declared = cast("Mapping[str, object]", ACTION["outputs"])
        assert set(emitted) == set(declared)
        assert emitted == {
            "exit-code": "0",
            "manifest-id": cli_document["manifest_id"],
            "report-directory": str(workspace / "action-artifacts" / "sanitized"),
            "result-category": "pass",
            "run-id": cli_document["run_id"],
        }
        report_directory = Path(emitted["report-directory"])
        assert {
            "assertions.jsonl",
            "deliveries.jsonl",
            "junit.xml",
            "observations.jsonl",
            "result-summary.json",
            "results.html",
            "run-manifest.json",
            "run-state.json",
        }.issubset({path.name for path in report_directory.iterdir()})
        assert not report_directory.joinpath("blobs").exists()
        assert server.requests == [_EVENT_BODY]
        assert "Sensitive artifact classes were excluded" in summary.read_text(encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


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


def _action_outputs(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if line
    )


def _configuration(port: int) -> str:
    return f"""\
schema_version: 1
project:
  name: action-contract
  artifact_directory: action-artifacts
  seed: action-contract-seed
receiver:
  url: http://127.0.0.1:{port}/webhooks
  target_profile: loopback
  allowed_hosts: [127.0.0.1]
  allowed_ports: [{port}]
  timeouts:
    connect: 2s
    write: 2s
    read: 2s
    pool: 2s
    total: 8s
fixtures:
- id: event
  path: event.json
  media_type: application/json
signers:
  local_hmac:
    profile: generic-hmac-sha256
    secret: {{env: WEBHOOK_TEST_SECRET}}
    header_name: X-Webhook-Signature
observers: {{}}
lifecycles: {{}}
clock:
  mode: scaled
  scale: "0.01"
  minimum_physical_wait: 1ms
limits:
  max_events: 10
  max_attempts: 20
  max_concurrency: 2
  max_request_bytes: 1048576
  max_response_capture_bytes: 65536
scenarios:
- id: one_delivery
  events:
  - id: event
    fixture: event
  steps:
  - deliver:
      event: event
      count: 1
      signer: local_hmac
      retry: {{max_attempts: 1, backoff: [], retry_on: []}}
  assertions:
  - id: accepted
    type: http-status
    attempt: {{event: event, mode: all-terminal}}
    expected: {{codes: [204]}}
reports:
  formats: [json, jsonl, junit, html]
  redaction:
    headers: [authorization, x-webhook-signature]
    json_pointers: []
    retain_raw_payloads: false
"""
