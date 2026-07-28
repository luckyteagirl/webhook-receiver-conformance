"""End-to-end evidence for the first durable local execution slice."""
# ruff: noqa: INP001, PLR2004

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, cast

import pytest
import typer
from tests.helpers.schema_validation import load_json, validate_instance
from typer.testing import CliRunner

from webhook_receiver_conformance.cli.run import (
    RUN_COMMAND_HELP,
    RunCommandRequest,
    register_run_command,
)
from webhook_receiver_conformance.config.models import ProjectConfig
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.domain.models import AggregateRunOutcome
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.http.executor import (
    HttpAttemptExecutor,
    HttpLimits,
    HttpTimeouts,
)
from webhook_receiver_conformance.journal.bootstrap import (
    JournalLifecycleRepository,
)
from webhook_receiver_conformance.journal.run_lock import LOCK_FILENAME
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.transport import (
    AnyIOConnector,
    AnyIOResolver,
    ConnectedByteStream,
    ConnectionPlan,
)
from webhook_receiver_conformance.runtime.runner import (
    VerticalSliceRunner,
    VerticalSliceRunRequest,
    VerticalSliceRunResult,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from webhook_receiver_conformance.scheduler.clocks import RuntimeClock

_FINGERPRINT = "sha256:" + ("a5" * 32)


@dataclass(frozen=True, slots=True)
class _ReceivedRequest:
    path: str
    body: bytes
    content_type: str | None


class _RecordingServer(ThreadingHTTPServer):
    requests: list[_ReceivedRequest]

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _ReceiverHandler)
        self.requests = []


class _ReceiverHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        content_length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(content_length)
        server = cast("_RecordingServer", self.server)
        server.requests.append(
            _ReceivedRequest(
                path=self.path,
                body=body,
                content_type=self.headers.get("content-type"),
            )
        )
        self.send_response(204)
        self.send_header("content-length", "0")
        self.send_header("connection", "close")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args


class _LoopbackOnlyConnector:
    def __init__(self, destinations: list[tuple[str, int]]) -> None:
        self._delegate = AnyIOConnector()
        self._destinations = destinations

    async def connect(self, plan: ConnectionPlan) -> ConnectedByteStream:
        if not ip_address(plan.pinned_address).is_loopback:
            message = "the vertical slice attempted a non-loopback connection"
            raise AssertionError(message)
        self._destinations.append((plan.pinned_address, plan.port))
        return await self._delegate.connect(plan)


@contextmanager
def _receiver() -> Generator[_RecordingServer]:
    server = _RecordingServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _project_config(project_root: Path, port: int) -> ProjectConfig:
    fixture_directory = project_root / "fixtures"
    fixture_directory.mkdir()
    (fixture_directory / "payload.json").write_bytes(
        b'{"id":"evt_vertical_slice","type":"test.accepted","value":1}\n'
    )
    return ProjectConfig.model_validate(
        {
            "schema_version": 1,
            "project": {
                "name": "vertical-slice",
                "artifact_directory": "runs",
                "seed": "vertical-slice-deterministic-seed",
            },
            "receiver": {
                "url": f"http://127.0.0.1:{port}/webhook",
                "target_profile": "loopback",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_ports": [port],
                "timeouts": {
                    "connect": "2s",
                    "write": "2s",
                    "read": "2s",
                    "pool": "2s",
                    "total": "5s",
                },
            },
            "fixtures": [
                {
                    "id": "payload",
                    "path": "fixtures/payload.json",
                    "media_type": "application/json",
                }
            ],
            "signers": {
                "unused": {
                    "profile": "generic-hmac-sha256",
                    "secret": {"generated": "hmac-256"},
                }
            },
            "observers": {},
            "lifecycles": {},
            "clock": {"mode": "real"},
            "limits": {
                "max_events": 1,
                "max_attempts": 1,
                "max_concurrency": 1,
                "max_request_bytes": 65_536,
                "max_response_capture_bytes": 8_192,
            },
            "scenarios": [
                {
                    "id": "accept-one",
                    "events": [{"id": "event", "fixture": "payload"}],
                    "steps": [
                        {
                            "deliver": {
                                "event": "event",
                                "count": 1,
                                "retry": {
                                    "max_attempts": 1,
                                    "backoff": [],
                                    "retry_on": [],
                                },
                            }
                        }
                    ],
                    "assertions": [
                        {
                            "id": "accepted",
                            "type": "http-status",
                            "attempt": {
                                "event": "event",
                                "mode": "all-terminal",
                            },
                            "expected": {"codes": [204]},
                        }
                    ],
                }
            ],
            "reports": {
                "formats": ["json"],
                "redaction": {
                    "headers": [],
                    "json_pointers": [],
                    "retain_raw_payloads": False,
                },
            },
        }
    )


def _executor_factory(
    destinations: list[tuple[str, int]],
) -> Callable[[ProjectConfig, RuntimeClock], HttpAttemptExecutor]:
    def build(config: ProjectConfig, clock: RuntimeClock) -> HttpAttemptExecutor:
        return HttpAttemptExecutor(
            dialer=PinnedDestinationDialer(
                resolver=AnyIOResolver(),
                connector=_LoopbackOnlyConnector(destinations),
            ),
            timeouts=HttpTimeouts(
                connect_ns=config.receiver.timeouts.connect.nanoseconds,
                write_ns=config.receiver.timeouts.write.nanoseconds,
                read_ns=config.receiver.timeouts.read.nanoseconds,
                pool_ns=config.receiver.timeouts.pool.nanoseconds,
                total_ns=config.receiver.timeouts.total.nanoseconds,
            ),
            limits=HttpLimits(
                max_request_bytes=config.limits.max_request_bytes,
                response_capture_bytes=config.limits.max_response_capture_bytes,
            ),
            max_concurrency=config.limits.max_concurrency,
            clock=clock,
        )

    return build


@pytest.mark.anyio
async def test_vertical_slice_is_local_durable_isolated_and_non_destructive(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    artifact_root = project_root / "runs"
    artifact_root.mkdir()
    sentinel = artifact_root / "retain-me.txt"
    sentinel.write_text("operator-owned", encoding="utf-8")
    destinations: list[tuple[str, int]] = []

    with _receiver() as receiver:
        port = receiver.server_address[1]
        assert type(port) is int
        config = _project_config(project_root, port)
        runner = VerticalSliceRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory(destinations),
        )
        request = VerticalSliceRunRequest(
            config=config,
            project_root=project_root,
            artifact_directory=artifact_root,
            secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
            signers={},
        )
        first = await runner.run(request)
        second = await runner.run(request)

    assert first.run_id != second.run_id
    assert first.run_directory != second.run_directory
    assert first.database_path != second.database_path
    assert first.run_directory.name == first.run_id
    assert second.run_directory.name == second.run_id
    assert first.run_directory.parent == artifact_root.resolve()
    assert second.run_directory.parent == artifact_root.resolve()
    assert first.database_path.is_file()
    assert second.database_path.is_file()
    assert first.run_directory.is_dir()
    assert sentinel.read_text(encoding="utf-8") == "operator-owned"
    assert not (first.run_directory / LOCK_FILENAME).exists()
    assert not (second.run_directory / LOCK_FILENAME).exists()
    assert destinations == [("127.0.0.1", port), ("127.0.0.1", port)]
    assert len(receiver.requests) == 2
    assert all(item.path == "/webhook" for item in receiver.requests)
    assert all(item.content_type == "application/json" for item in receiver.requests)
    assert receiver.requests[0].body == receiver.requests[1].body
    delivery_document = cast(
        "dict[str, object]",
        json.loads((first.run_directory / "deliveries.jsonl").read_text()),
    )
    request_metadata = cast("dict[str, object]", delivery_document["request"])
    assert sha256_digest(receiver.requests[0].body) == request_metadata["body_sha256"]

    for result in (first, second):
        _assert_run_artifacts(result)
        _assert_journal(result)


def _assert_run_artifacts(result: VerticalSliceRunResult) -> None:
    assert result.result_category is ResultCategory.PASS
    expected = {
        "assertions.jsonl",
        "deliveries.jsonl",
        "effective-configuration.json",
        "journal.sqlite3",
        "observations.jsonl",
        "plan-preview.json",
        "result-summary.json",
        "run-manifest.json",
    }
    assert expected.issubset(
        {path.name for path in result.run_directory.iterdir() if path.is_file()}
    )
    summary_document = load_json(result.summary_path)
    assert (
        validate_instance(
            summary_document,
            load_json(Path("schemas/result-summary.schema.json")),
        )
        == []
    )
    summary = AggregateRunOutcome.model_validate_json(result.summary_path.read_bytes())
    assert summary.run_id == result.run_id
    assert summary.manifest_id == result.manifest_id
    assert summary.verdict is ResultCategory.PASS
    assert summary.counts.scenarios == 1
    assert summary.counts.attempts == 1
    assert summary.counts.observations == 0
    assert summary.counts.assertions == 1
    deliveries = (result.run_directory / "deliveries.jsonl").read_text().splitlines()
    assertions = (result.run_directory / "assertions.jsonl").read_text().splitlines()
    assert len(deliveries) == 1
    assert len(assertions) == 1
    assert (result.run_directory / "observations.jsonl").read_bytes() == b""
    assert (
        validate_instance(
            json.loads(deliveries[0]),
            load_json(Path("schemas/delivery-record.schema.json")),
        )
        == []
    )
    assert (
        validate_instance(
            json.loads(assertions[0]),
            load_json(Path("schemas/assertion-record.schema.json")),
        )
        == []
    )


def _assert_journal(result: VerticalSliceRunResult) -> None:
    connection = sqlite3.connect(
        f"file:{result.database_path.as_posix()}?mode=ro",
        uri=True,
    )
    try:
        run_row = connection.execute(
            "SELECT state, terminal_category FROM runs WHERE run_id = ?",
            (result.run_id,),
        ).fetchone()
        assert run_row == ("completed", "pass")
        assert connection.execute("SELECT state FROM scenarios").fetchone() == ("passed",)
        assert connection.execute("SELECT state FROM deliveries").fetchone() == ("satisfied",)
        assert connection.execute("SELECT state FROM assertions").fetchone() == ("passed",)
        assert connection.execute("SELECT state, outcome_category FROM attempts").fetchone() == (
            "succeeded",
            "receiver_accepted",
        )
        attempt_states = [
            row[0]
            for row in connection.execute(
                """
                SELECT to_state
                FROM transitions
                WHERE entity_type = 'attempt'
                ORDER BY sequence
                """
            )
        ]
        assert attempt_states == [
            "claimed",
            "pre_send_committed",
            "connecting",
            "sending",
            "awaiting_response",
            "response_observed",
            "succeeded",
        ]
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()


def test_run_help_describes_the_durable_local_job() -> None:
    app = typer.Typer(add_completion=False)

    def should_not_execute(request: RunCommandRequest) -> NoReturn:
        del request
        message = "help must not execute a run"
        raise AssertionError(message)

    register_run_command(app, should_not_execute)
    result = CliRunner().invoke(app, ["run", "--help"])

    assert result.exit_code == 0
    assert RUN_COMMAND_HELP in " ".join(result.stdout.split())
    assert "--config" in result.stdout
    assert "--manifest" in result.stdout
    assert "unsupported" not in result.stdout.casefold()
    assert "--output" in result.stdout
    assert "--authorize-public-target" in result.stdout
