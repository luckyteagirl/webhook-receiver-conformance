"""MUT-022 independent replay proof for a scenario-reduced local bundle."""
# ruff: noqa: INP001, TC003

from __future__ import annotations

import shutil
import threading
from collections.abc import Generator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from webhook_receiver_conformance.config.models import ProjectConfig
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.http.executor import (
    HttpAttemptExecutor,
    HttpLimits,
    HttpTimeouts,
)
from webhook_receiver_conformance.journal.bootstrap import JournalLifecycleRepository
from webhook_receiver_conformance.manifest.compiler import compile_run_bundle
from webhook_receiver_conformance.manifest.loader import load_replay_bundle
from webhook_receiver_conformance.manifest.reduction import (
    export_reduced_replay_bundle,
)
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.transport import AnyIOConnector, AnyIOResolver
from webhook_receiver_conformance.runtime.runner import FullRunRequest, FullRunRunner

if TYPE_CHECKING:
    from webhook_receiver_conformance.scheduler.clocks import RuntimeClock

_FINGERPRINT = "sha256:" + ("a5" * 32)
_FIRST_BODY = b'{"id":"evt_first","type":"test.first","value":1}\n'
_SECOND_BODY = b'{"id":"evt_second","type":"test.second","value":2}\n'


class _Receiver(ThreadingHTTPServer):
    bodies: list[bytes]
    _lock: threading.Lock

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.bodies = []
        self._lock = threading.Lock()

    def record(self, body: bytes) -> None:
        with self._lock:
            self.bodies.append(body)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        cast("_Receiver", self.server).record(self.rfile.read(length))
        self.send_response(204)
        self.send_header("content-length", "0")
        self.send_header("connection", "close")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args


@contextmanager
def _receiver() -> Generator[_Receiver]:
    server = _Receiver()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _config(project: Path, port: int) -> ProjectConfig:
    fixtures = project / "fixtures"
    fixtures.mkdir()
    (fixtures / "first.json").write_bytes(_FIRST_BODY)
    (fixtures / "second.json").write_bytes(_SECOND_BODY)
    return ProjectConfig.model_validate(
        {
            "schema_version": 1,
            "project": {
                "name": "mut-022-replay",
                "artifact_directory": "runs",
                "seed": "mut-022-replay-seed",
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
                    "id": "first",
                    "path": "fixtures/first.json",
                    "media_type": "application/json",
                },
                {
                    "id": "second",
                    "path": "fixtures/second.json",
                    "media_type": "application/json",
                },
            ],
            "signers": {
                "unused": {
                    "profile": "generic-hmac-sha256",
                    "secret": {"generated": "hmac-256"},
                }
            },
            "observers": {},
            "clock": {"mode": "real"},
            "limits": {
                "max_events": 8,
                "max_attempts": 8,
                "max_concurrency": 2,
                "max_request_bytes": 65_536,
                "max_response_capture_bytes": 8_192,
            },
            "scenarios": [
                _scenario("first-case", "first"),
                _scenario("second-case", "second"),
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


def _scenario(name: str, fixture: str) -> dict[str, object]:
    return {
        "id": name,
        "events": [{"id": "event", "fixture": fixture}],
        "steps": [{"deliver": {"event": "event"}}],
        "assertions": [
            {
                "id": "status",
                "type": "http-status",
                "attempt": {"event": "event", "mode": "all-terminal"},
                "expected": {"codes": [204]},
            }
        ],
    }


def _executor_factory(
    config: ProjectConfig,
    clock: RuntimeClock,
) -> HttpAttemptExecutor:
    return HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=AnyIOResolver(),
            connector=AnyIOConnector(),
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


@pytest.mark.anyio
async def test_vt_mut_022_replays_after_hypothesis_database_and_sources_are_deleted(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    hypothesis_database = project / ".hypothesis" / "examples"
    hypothesis_database.mkdir(parents=True)
    (hypothesis_database / "counterexample").write_bytes(b"property-test-state")
    source_directory = tmp_path / "source-bundle"
    reduced_directory = tmp_path / "reduced-bundle"
    replay_artifacts = tmp_path / "replays"
    replay_artifacts.mkdir()

    with _receiver() as receiver:
        port = cast("tuple[str, int]", receiver.server_address)[1]
        config = _config(project, port)
        compile_run_bundle(
            config,
            project_root=project,
            bundle_directory=source_directory,
            secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
        )
        source = load_replay_bundle(source_directory)
        retained = source.manifest.scenarios[1]
        export_reduced_replay_bundle(
            source,
            scenario_ids=(retained.scenario_id,),
            destination=reduced_directory,
        )
        reduced_config = config.model_copy(update={"scenarios": (config.scenarios[1],)})

        shutil.rmtree(project / "fixtures")
        shutil.rmtree(project / ".hypothesis")
        loaded_reduction = load_replay_bundle(reduced_directory)
        result = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
        ).run_loaded(
            FullRunRequest(
                config=reduced_config,
                project_root=project,
                artifact_directory=replay_artifacts,
                secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
                signers={},
            ),
            loaded_reduction,
        )

    assert not (project / "fixtures").exists()
    assert not (project / ".hypothesis").exists()
    assert result.result_category is ResultCategory.PASS
    assert receiver.bodies == [_SECOND_BODY]
