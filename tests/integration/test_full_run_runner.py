"""Integration coverage for the durable full transport runner."""
# ruff: noqa: INP001, PLR0913, PLR2004

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, cast

import pytest

from webhook_receiver_conformance.config.models import ClockConfig, ProjectConfig
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AttemptClassification,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.http.executor import (
    HttpAttemptExecutor,
    HttpLimits,
    HttpTimeouts,
)
from webhook_receiver_conformance.journal.bootstrap import JournalLifecycleRepository
from webhook_receiver_conformance.manifest.compiler import compile_run_bundle
from webhook_receiver_conformance.manifest.loader import load_replay_bundle
from webhook_receiver_conformance.manifest.models import RunManifest
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.transport import (
    AnyIOConnector,
    AnyIOResolver,
)
from webhook_receiver_conformance.runtime.observer_assertions import (
    CommandLaunchPolicy,
    ProjectObserverAssertionExecutorFactory,
)
from webhook_receiver_conformance.runtime.runner import (
    FullRunRequest,
    FullRunRunner,
)
from webhook_receiver_conformance.scheduler.clocks import RuntimeClock

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

_FINGERPRINT = "sha256:" + ("a5" * 32)
_FALSE_COUNT_OBSERVER = """\
import json
import sys

request = json.loads(sys.stdin.buffer.readline())
capabilities = {
    "evidence_types": ["integer"],
    "evidence_keys": ["processing_count"],
    "read_only": True,
    "idempotent": True,
    "max_queries": 64,
    "supports_pending": True,
    "stable_snapshot_ids": True,
}
response = {
    "protocol_version": "1.0",
    "request_id": request["request_id"],
    "status": "ok",
    "capabilities": capabilities,
    "snapshot_id": "receiver-state-1",
    "evidence": [],
    "error": None,
}
if request["operation"] == "observe":
    response["evidence"] = [{
        "key": "processing_count",
        "value_type": "integer",
        "value": 0,
        "sensitive": False,
    }]
sys.stdout.write(json.dumps(response, separators=(",", ":")))
"""


class _SequenceServer(ThreadingHTTPServer):
    statuses: list[int]
    bodies: list[bytes]
    _lock: threading.Lock

    def __init__(self, statuses: list[int]) -> None:
        super().__init__(("127.0.0.1", 0), _SequenceHandler)
        self.statuses = statuses
        self.bodies = []
        self._lock = threading.Lock()

    def response(self, body: bytes) -> int:
        with self._lock:
            self.bodies.append(body)
            index = len(self.bodies) - 1
            return self.statuses[min(index, len(self.statuses) - 1)]


class _SequenceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        status = cast("_SequenceServer", self.server).response(body)
        self.send_response(status)
        self.send_header("content-length", "0")
        self.send_header("connection", "close")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args


@contextmanager
def _receiver(statuses: list[int]) -> Generator[_SequenceServer]:
    server = _SequenceServer(statuses)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _config(
    project_root: Path,
    port: int,
    *,
    steps: list[object],
    assertions: list[object],
    max_attempts: int = 16,
    max_concurrency: int = 4,
) -> ProjectConfig:
    fixture_directory = project_root / "fixtures"
    fixture_directory.mkdir(exist_ok=True)
    (fixture_directory / "payload.json").write_bytes(
        b'{"id":"evt_full_runner","type":"test.accepted","value":1}\n'
    )
    return ProjectConfig.model_validate(
        {
            "schema_version": 1,
            "project": {
                "name": "full-runner",
                "artifact_directory": "runs",
                "seed": "full-runner-deterministic-seed",
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
                "max_events": 8,
                "max_attempts": max_attempts,
                "max_concurrency": max_concurrency,
                "max_request_bytes": 65_536,
                "max_response_capture_bytes": 8_192,
            },
            "scenarios": [
                {
                    "id": "full",
                    "events": [{"id": "event", "fixture": "payload"}],
                    "steps": steps,
                    "assertions": assertions,
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


def _status_assertion(
    *,
    expected: list[int],
    mode: str = "all-terminal",
) -> dict[str, object]:
    return {
        "id": "status",
        "type": "http-status",
        "attempt": {"event": "event", "mode": mode},
        "expected": {"codes": expected},
    }


def _request(
    config: ProjectConfig,
    project_root: Path,
    artifact_root: Path,
) -> FullRunRequest:
    return FullRunRequest(
        config=config,
        project_root=project_root,
        artifact_directory=artifact_root,
        secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
        signers={},
    )


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


def _clock_factory(waits: list[float]) -> Callable[[ClockConfig], RuntimeClock]:
    async def record(seconds: float) -> None:
        waits.append(seconds)

    def build(config: ClockConfig) -> RuntimeClock:
        return RuntimeClock.from_config(config, sleep=record)

    return build


@pytest.mark.anyio
async def test_executes_all_deliveries_waits_and_releases_concurrency(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    waits: list[float] = []
    with _receiver([204, 204, 204]) as receiver:
        port = receiver.server_address[1]
        config = _config(
            project,
            port,
            steps=[
                {
                    "deliver": {
                        "event": "event",
                        "count": 2,
                        "concurrency_group": "cohort",
                    }
                },
                {"wait": "7ms"},
                {"deliver": {"event": "event", "count": 1}},
            ],
            assertions=[_status_assertion(expected=[204])],
        )
        result = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
            clock_factory=_clock_factory(waits),
        ).run(_request(config, project, artifacts))

    assert result.result_category is ResultCategory.PASS
    assert [item.delivery_ordinal for item in result.attempts] == [0, 1, 2]
    assert len(receiver.bodies) == 3
    assert any(wait == pytest.approx(0.007) for wait in waits)
    cohort = next(item for item in result.barrier_releases if item.concurrency_group == "cohort")
    assert len(cohort.eligible_work_ids) == 2


@pytest.mark.anyio
async def test_same_time_dependency_reversal_preserves_manifest_stable_order(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    with _receiver([204, 204]) as receiver:
        port = receiver.server_address[1]
        base = _config(
            project,
            port,
            steps=[{"deliver": {"event": "event"}}],
            assertions=[_status_assertion(expected=[204])],
        )
        wire = cast(
            "dict[str, object]",
            base.model_dump(mode="json", exclude_none=True),
        )
        scenarios = cast("list[object]", wire["scenarios"])
        scenario = cast("dict[str, object]", scenarios[0])
        scenario["events"] = [
            {"id": "parent", "fixture": "payload"},
            {
                "id": "child",
                "fixture": "payload",
                "depends_on": ["parent"],
            },
        ]
        scenario["steps"] = [
            {"deliver": {"event": "child"}},
            {"deliver": {"event": "parent"}},
        ]
        scenario["assertions"] = [
            {
                "id": "status",
                "type": "http-status",
                "attempt": {"event": "child", "mode": "all-terminal"},
                "expected": {"codes": [204]},
            }
        ]
        config = ProjectConfig.model_validate(wire)
        result = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
        ).run(_request(config, project, artifacts))

    manifest = RunManifest.from_bytes((result.run_directory / "run-manifest.json").read_bytes())
    planned = manifest.scenarios[0]
    assert result.result_category is ResultCategory.PASS
    assert [item.evidence.event_id for item in result.attempts] == [
        planned.events[1].event_id,
        planned.events[0].event_id,
    ]


@pytest.mark.anyio
async def test_conditional_retry_uses_persisted_schedule_and_last_terminal_assertion(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    waits: list[float] = []
    with _receiver([503, 204]) as receiver:
        port = receiver.server_address[1]
        config = _config(
            project,
            port,
            steps=[
                {
                    "deliver": {
                        "event": "event",
                        "retry": {
                            "max_attempts": 2,
                            "backoff": ["3ms"],
                            "retry_on": ["retryable_status"],
                            "retryable_statuses": ["5xx"],
                        },
                    }
                }
            ],
            assertions=[_status_assertion(expected=[204], mode="last-terminal")],
        )
        result = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
            clock_factory=_clock_factory(waits),
        ).run(_request(config, project, artifacts))

    assert result.result_category is ResultCategory.PASS
    assert [item.attempt_ordinal for item in result.attempts] == [1, 2]
    assert [item.classification for item in result.attempts] == [
        AttemptClassification.RECEIVER_REJECTED,
        AttemptClassification.RECEIVER_ACCEPTED,
    ]
    assert any(wait == pytest.approx(0.003) for wait in waits)
    assert len(receiver.bodies) == 2


@pytest.mark.anyio
async def test_false_transport_assertion_fails_the_run(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    with _receiver([204, 204]) as receiver:
        port = receiver.server_address[1]
        config = _config(
            project,
            port,
            steps=[{"deliver": {"event": "event", "count": 2}}],
            assertions=[_status_assertion(expected=[200])],
        )
        result = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
        ).run(_request(config, project, artifacts))

    assert result.result_category is ResultCategory.RECEIVER_FAILURE
    assert result.assertions[0].result is AssertionResult.FAIL


@pytest.mark.anyio
async def test_absent_observer_capability_is_never_a_pass(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    with _receiver([204]) as receiver:
        port = receiver.server_address[1]
        config = _config(
            project,
            port,
            steps=[{"deliver": {"event": "event"}}],
            assertions=[
                {
                    "id": "processed",
                    "type": "processing-count",
                    "query": {
                        "observer": "missing",
                        "key": "processing_count",
                        "parameters": {},
                    },
                    "comparator": "eq",
                    "expected": 1,
                }
            ],
        )
        result = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
        ).run(_request(config, project, artifacts))

    assert result.result_category is ResultCategory.UNSUPPORTED
    assert result.assertions[0].result is not AssertionResult.PASS


@pytest.mark.anyio
async def test_false_configured_observer_assertion_is_journaled_exported_and_fails_run(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    (project / "observer.py").write_text(_FALSE_COUNT_OBSERVER, encoding="utf-8")
    with _receiver([204]) as receiver:
        port = receiver.server_address[1]
        base = _config(
            project,
            port,
            steps=[{"deliver": {"event": "event"}}],
            assertions=[
                {
                    "id": "processed_once",
                    "type": "processing-count",
                    "query": {
                        "observer": "receiver_state",
                        "key": "processing_count",
                        "parameters": {},
                    },
                    "comparator": "eq",
                    "expected": 1,
                }
            ],
        )
        wire = cast(
            "dict[str, object]",
            base.model_dump(mode="json", exclude_none=True),
        )
        wire["observers"] = {
            "receiver_state": {
                "type": "command",
                "argv": ["python", "observer.py"],
                "timeout": "2s",
                "working_directory": ".",
            }
        }
        config = ProjectConfig.model_validate(wire)
        observer_factory = ProjectObserverAssertionExecutorFactory(
            config=config,
            project_root=project,
            observer_secrets={},
            command_policy=CommandLaunchPolicy.for_current_interpreter(
                "python",
                environment={},
            ),
        )
        runner = FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
            observer_assertion_executor_factory=observer_factory,
        )
        result = await runner.run(_request(config, project, artifacts))
        repeated = await runner.run(_request(config, project, artifacts))

    assert result.result_category is ResultCategory.RECEIVER_FAILURE
    assert result.assertions[0].result is AssertionResult.FAIL
    assert len(result.observations) == 1
    assert result.observations[0].record.status.value == "ok"
    assert result.observations[0].record.evidence[0].typed_value == 0
    assert (
        repeated.observations[0].record.observation_id
        == result.observations[0].record.observation_id
    )

    with sqlite3.connect(result.database_path) as connection:
        samples = connection.execute(
            """
            SELECT status, sample_sequence
            FROM observation_samples
            """
        ).fetchall()
        evaluations = connection.execute(
            """
            SELECT result
            FROM assertion_evaluations
            """
        ).fetchall()
        links = connection.execute(
            """
            SELECT evidence_kind
            FROM evidence_links
            """
        ).fetchall()
    assert samples == [("ok", 1)]
    assert evaluations == [("fail",)]
    assert links == [("observation",)]

    exported = tuple(
        json.loads(line)
        for line in (result.run_directory / "observations.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert len(exported) == 1
    assert exported[0]["status"] == "ok"
    assert exported[0]["evidence"][0]["value"] == 0


@pytest.mark.anyio
async def test_loaded_bundle_execution_does_not_read_source_fixtures(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    bundle_directory = tmp_path / "bundle"
    replay_artifacts = tmp_path / "replays"
    replay_artifacts.mkdir()
    with _receiver([204]) as receiver:
        port = receiver.server_address[1]
        config = _config(
            project,
            port,
            steps=[{"deliver": {"event": "event"}}],
            assertions=[_status_assertion(expected=[204])],
        )
        compile_run_bundle(
            config,
            project_root=project,
            bundle_directory=bundle_directory,
            secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
        )
        loaded = load_replay_bundle(bundle_directory)
        (project / "fixtures" / "payload.json").unlink()
        result = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
        ).run_loaded(_request(config, project, replay_artifacts), loaded)

    assert result.result_category is ResultCategory.PASS
    assert len(receiver.bodies) == 1


@pytest.mark.anyio
async def test_loaded_bundle_rejects_redirected_target_and_secret_fingerprint(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    bundle_directory = tmp_path / "bundle"
    replay_artifacts = tmp_path / "replays"
    replay_artifacts.mkdir()
    with _receiver([204]) as receiver:
        port = receiver.server_address[1]
        config = _config(
            project,
            port,
            steps=[{"deliver": {"event": "event"}}],
            assertions=[_status_assertion(expected=[204])],
        )
        compile_run_bundle(
            config,
            project_root=project,
            bundle_directory=bundle_directory,
            secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
        )
        loaded = load_replay_bundle(bundle_directory)
        changed_wire = cast(
            "dict[str, object]",
            config.model_dump(mode="json", exclude_none=True),
        )
        changed_receiver = cast("dict[str, object]", changed_wire["receiver"])
        changed_receiver["url"] = f"http://127.0.0.1:{port + 1}/other-path"
        changed_receiver["allowed_ports"] = [port + 1]
        changed = ProjectConfig.model_validate(changed_wire)
        runner = FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
        )
        with pytest.raises(ValueError, match="digest-bound"):
            await runner.run_loaded(
                _request(changed, project, replay_artifacts),
                loaded,
            )
        wrong_fingerprint = FullRunRequest(
            config=config,
            project_root=project,
            artifact_directory=replay_artifacts,
            secret_fingerprints={"generated:hmac-256": "sha256:" + ("b6" * 32)},
            signers={},
        )
        with pytest.raises(ValueError, match="digest-bound"):
            await runner.run_loaded(wrong_fingerprint, loaded)

    assert receiver.bodies == []
    assert tuple(replay_artifacts.iterdir()) == ()
