"""Real installed-CLI execution against a local HTTP receiver."""
# ruff: noqa: INP001, S105, S603

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Sequence

_EVENT_BODY = (
    b'{"id":"evt_cli_e2e","type":"payment.succeeded",'
    b'"data":{"order_id":"order_cli_e2e"}}\n'
)
_EXPECTED_REQUEST_COUNT = 2


class _RecordingServer(ThreadingHTTPServer):
    requests: list[tuple[str, bytes]]


class _AcceptedWebhookHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        server = cast("_RecordingServer", self.server)
        server.requests.append((self.path, body))
        self.send_response(204)
        self.send_header("content-length", "0")
        self.send_header("connection", "close")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args


def test_installed_cli_runs_replays_and_inspects_a_local_bundle(tmp_path: Path) -> None:
    server = _RecordingServer(("127.0.0.1", 0), _AcceptedWebhookHandler)
    server.requests = []
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        name="webhook-conformance-e2e-receiver",
    )
    thread.start()
    try:
        port = server.server_address[1]
        project = tmp_path / "project"
        project.mkdir()
        fixture = project / "event.json"
        fixture.write_bytes(_EVENT_BODY)
        config = project / "webhook-conformance.yaml"
        config.write_text(_configuration(port), encoding="utf-8")
        environment = os.environ.copy()
        environment["WEBHOOK_TEST_SECRET"] = "installed-cli-local-secret"
        executable = _console_script()

        run = _invoke(
            (
                str(executable),
                "--json",
                "run",
                "--config",
                str(config),
                "--output",
                "artifacts",
            ),
            cwd=project,
            environment=environment,
        )
        assert run.returncode == 0, run.stderr
        run_document = _single_json_document(run.stdout)
        assert run_document["command"] == "run"
        assert run_document["verdict"] == "pass"
        first_run = Path(cast("str", run_document["run_directory"]))
        assert first_run.is_dir()
        assert _expected_artifacts().issubset(
            {path.name for path in first_run.iterdir() if path.is_file()}
        )
        assert server.requests == [
            (
                "/webhooks",
                _EVENT_BODY,
            )
        ]

        inspection = _invoke(
            (
                str(executable),
                "--json",
                "inspect",
                str(first_run),
            ),
            cwd=project,
            environment=environment,
        )
        assert inspection.returncode == 0, inspection.stderr
        inspection_document = _single_json_document(inspection.stdout)
        assert inspection_document["verified"] is True
        assert inspection_document["failed_assertion_chains"] == 0

        fixture.unlink()
        replay = _invoke(
            (
                str(executable),
                "--json",
                "replay",
                str(first_run / "run-manifest.json"),
                "--config",
                str(config),
                "--output",
                "artifacts",
            ),
            cwd=project,
            environment=environment,
        )
        assert replay.returncode == 0, replay.stderr
        replay_document = _single_json_document(replay.stdout)
        assert replay_document["command"] == "replay"
        assert replay_document["verdict"] == "pass"
        second_run = Path(cast("str", replay_document["run_directory"]))
        assert second_run != first_run
        assert second_run.is_dir()
        assert len(server.requests) == _EXPECTED_REQUEST_COUNT
        assert server.requests[1] == server.requests[0]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def _invoke(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _console_script() -> Path:
    name = "webhook-conformance.exe" if os.name == "nt" else "webhook-conformance"
    executable = Path(sys.executable).with_name(name)
    assert executable.is_file(), f"installed console script is missing: {executable}"
    return executable


def _single_json_document(value: str) -> dict[str, object]:
    document: object = json.loads(value)
    assert isinstance(document, dict)
    return cast("dict[str, object]", document)


def _expected_artifacts() -> set[str]:
    return {
        "journal.sqlite3",
        "run-manifest.json",
        "deliveries.jsonl",
        "observations.jsonl",
        "assertions.jsonl",
        "result-summary.json",
        "junit.xml",
        "results.html",
        "run-state.json",
    }


def _configuration(port: int) -> str:
    return f"""\
schema_version: 1
project:
  name: installed-cli-e2e
  artifact_directory: artifacts
  seed: installed-cli-e2e-seed
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
    json_pointers: [/data/customer_email]
    retain_raw_payloads: false
"""
