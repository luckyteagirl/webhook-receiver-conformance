"""Integration coverage for the durable full transport runner."""
# ruff: noqa: EM101, INP001, PLR0913, PLR0917, PLR2004, TRY003

from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, BinaryIO, cast

import anyio
import pytest
from anyio.to_thread import run_sync as run_sync_in_worker_thread

import webhook_receiver_conformance.runtime.runner as runner_module
from webhook_receiver_conformance.config.models import ClockConfig, ProjectConfig
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AttemptClassification,
    AttemptState,
    DeliveryState,
    ScenarioState,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.fixtures.blobs import BlobSnapshot
from webhook_receiver_conformance.http.executor import (
    HttpAttemptExecutor,
    HttpLimits,
    HttpTimeouts,
)
from webhook_receiver_conformance.journal.bootstrap import JournalLifecycleRepository
from webhook_receiver_conformance.journal.repositories import (
    AttemptMutationPhase,
    ObservationRepository,
    TransitionMutationPhase,
    TransitionRepository,
)
from webhook_receiver_conformance.journal.run_lock import acquire_run_lock
from webhook_receiver_conformance.journal.service import (
    JournalService,
    JournalServiceState,
)
from webhook_receiver_conformance.journal.transitions import (
    EntityType,
    TransitionCommand,
)
from webhook_receiver_conformance.manifest.compiler import compile_run_bundle
from webhook_receiver_conformance.manifest.loader import BundleLoadError, load_replay_bundle
from webhook_receiver_conformance.manifest.models import RunManifest
from webhook_receiver_conformance.network.dialer import (
    PeerAddressEvidence,
    PinnedDestinationDialer,
)
from webhook_receiver_conformance.network.policy import parse_destination_policy
from webhook_receiver_conformance.network.preflight import (
    PreflightErrorCode,
    PreflightPhase,
    PublicTargetPreflightError,
    PublicTargetPreflightEvidence,
)
from webhook_receiver_conformance.network.transport import (
    AnyIOConnector,
    AnyIOResolver,
    ConnectionPlan,
    PeerAddress,
    SocketFamily,
)
from webhook_receiver_conformance.recovery.policy import (
    AmbiguityPolicy,
    ResumeInvocationPolicy,
)
from webhook_receiver_conformance.runtime.assertions import AssertionLifecycle
from webhook_receiver_conformance.runtime.observer_assertions import (
    CommandLaunchPolicy,
    ProjectObserverAssertionExecutorFactory,
)
from webhook_receiver_conformance.runtime.resume import (
    ResumeRequest,
    ResumeService,
    ResumeStatus,
)
from webhook_receiver_conformance.runtime.runner import (
    FullRunPublicPreflight,
    FullRunRequest,
    FullRunResult,
    FullRunResumePreparation,
    FullRunRunner,
    ObserverAssertionExecution,
)
from webhook_receiver_conformance.scheduler.clocks import RuntimeClock

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path
    from typing import Any

    from webhook_receiver_conformance.config.models import AssertionConfig
    from webhook_receiver_conformance.journal.repositories import PersistedAttemptEvidence
    from webhook_receiver_conformance.journal.resume import ResumeJournalPreflight
    from webhook_receiver_conformance.journal.run_lock import RunLock
    from webhook_receiver_conformance.runtime.assertions import AssertionRuntimeContext
    from webhook_receiver_conformance.runtime.resume import ResumeResult

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
_SIDE_EFFECTING_COUNT_OBSERVER = """\
import json
import pathlib
import sys

request = json.loads(sys.stdin.buffer.readline())
capabilities = {
    "evidence_types": ["integer"],
    "evidence_keys": ["processing_count"],
    "read_only": False,
    "idempotent": False,
    "max_queries": 64,
    "supports_pending": False,
    "stable_snapshot_ids": False,
}
count_path = pathlib.Path("observe-count.txt")
count = int(count_path.read_text(encoding="ascii")) if count_path.exists() else 0
response = {
    "protocol_version": "1.0",
    "request_id": request["request_id"],
    "status": "ok",
    "capabilities": capabilities,
    "snapshot_id": "receiver-state-" + str(count),
    "evidence": [],
    "error": None,
}
if request["operation"] == "observe":
    count += 1
    count_path.write_text(str(count), encoding="ascii")
    response["snapshot_id"] = "receiver-state-" + str(count)
    response["evidence"] = [{
        "key": "processing_count",
        "value_type": "integer",
        "value": count,
        "sensitive": False,
    }]
sys.stdout.write(json.dumps(response, separators=(",", ":")))
"""


class _SequenceServer(ThreadingHTTPServer):
    statuses: list[int]
    bodies: list[bytes]
    _lock: threading.Lock
    request_received: threading.Event
    response_release: threading.Event | None

    def __init__(self, statuses: list[int]) -> None:
        super().__init__(("127.0.0.1", 0), _SequenceHandler)
        self.statuses = statuses
        self.bodies = []
        self._lock = threading.Lock()
        self.request_received = threading.Event()
        self.response_release = None

    def response(self, body: bytes) -> int:
        with self._lock:
            self.bodies.append(body)
            index = len(self.bodies) - 1
            status = self.statuses[min(index, len(self.statuses) - 1)]
        self.request_received.set()
        if self.response_release is not None and not self.response_release.wait(timeout=5):
            raise TimeoutError("test receiver response was not released")
        return status


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


def _unexpected_executor_factory(
    config: ProjectConfig,
    clock: RuntimeClock,
) -> HttpAttemptExecutor:
    del config, clock
    message = "read-only resume preparation must not construct an HTTP executor"
    raise AssertionError(message)


def _clock_factory(waits: list[float]) -> Callable[[ClockConfig], RuntimeClock]:
    async def record(seconds: float) -> None:
        waits.append(seconds)

    def build(config: ClockConfig) -> RuntimeClock:
        return RuntimeClock.from_config(config, sleep=record)

    return build


class _InjectedRunInterruptionError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("deterministic interrupted run")


class _PossibleSendCrashError(BaseException):
    def __init__(self) -> None:
        super().__init__("simulated process crash after send intent")


class _CrashOnAttemptPhaseOccurrence:
    __slots__ = ("_occurrence", "_seen")

    def __init__(self, occurrence: int) -> None:
        self._occurrence = occurrence
        self._seen = 0

    def __call__(
        self,
        phase: TransitionMutationPhase | AttemptMutationPhase,
    ) -> None:
        if phase is not AttemptMutationPhase.AFTER_PHASE_EVIDENCE:
            return
        self._seen += 1
        if self._seen == self._occurrence:
            raise _InjectedRunInterruptionError


class _CrashAfterSendStartedStream:
    __slots__ = ("_peer_address",)

    def __init__(self, plan: ConnectionPlan) -> None:
        self._peer_address = PeerAddress(
            address=plan.pinned_address,
            port=plan.port,
            family=plan.family,
        )

    @property
    def peer_address(self) -> PeerAddress:
        return self._peer_address

    async def send(self, item: bytes) -> None:
        del item
        raise _PossibleSendCrashError

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        del max_bytes
        raise AssertionError

    async def send_eof(self) -> None:
        raise AssertionError

    async def aclose(self) -> None:
        return


class _CrashAfterSendStartedConnector:
    async def connect(self, plan: ConnectionPlan) -> _CrashAfterSendStartedStream:
        if plan.family is not SocketFamily.IPV4:
            raise AssertionError
        return _CrashAfterSendStartedStream(plan)


class _IncompleteResponseStream:
    __slots__ = ("_peer_address", "_response")

    def __init__(self, plan: ConnectionPlan) -> None:
        self._peer_address = PeerAddress(
            address=plan.pinned_address,
            port=plan.port,
            family=plan.family,
        )
        self._response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nxy"

    @property
    def peer_address(self) -> PeerAddress:
        return self._peer_address

    async def send(self, item: bytes) -> None:
        del item

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        del max_bytes
        if not self._response:
            raise anyio.EndOfStream
        response, self._response = self._response, b""
        return response

    async def send_eof(self) -> None:
        return

    async def aclose(self) -> None:
        return


class _IncompleteResponseConnector:
    async def connect(self, plan: ConnectionPlan) -> _IncompleteResponseStream:
        if plan.family is not SocketFamily.IPV4:
            raise AssertionError
        return _IncompleteResponseStream(plan)


class _FaultingSpool:
    __slots__ = ("_fault", "_seek_faulted", "_stream")

    def __init__(self, stream: BinaryIO, fault: str) -> None:
        self._stream = stream
        self._fault = fault
        self._seek_faulted = False

    @property
    def closed(self) -> bool:
        return self._stream.closed

    def tell(self) -> int:
        return self._stream.tell()

    def write(self, body: bytes) -> int:
        if self._fault == "write":
            raise OSError("injected spool write fault")
        return self._stream.write(body)

    def flush(self) -> None:
        if self._fault == "flush":
            raise OSError("injected spool flush fault")
        self._stream.flush()

    def seek(self, offset: int, whence: int = 0) -> int:
        if self._fault == "seek" and not self._seek_faulted:
            self._seek_faulted = True
            raise OSError("injected spool seek fault")
        return self._stream.seek(offset, whence)

    def read(self, size: int = -1) -> bytes:
        if self._fault in {"read", "read-close"}:
            raise OSError("injected spool read fault")
        if self._fault == "unreadable":
            raise PermissionError("injected unreadable spool")
        body = self._stream.read(size)
        if self._fault == "short" and body:
            return body[:-1]
        if self._fault == "corrupt" and body:
            return bytes([body[0] ^ 0xFF]) + body[1:]
        return body

    def close(self) -> None:
        self._stream.close()
        if self._fault in {"close", "read-close"}:
            raise OSError("injected spool close fault")


class _InterruptingObserverAssertionExecutor:
    async def evaluate(
        self,
        lifecycle: AssertionLifecycle,
        context: AssertionRuntimeContext,
        assertion: AssertionConfig,
        attempts: tuple[PersistedAttemptEvidence, ...],
    ) -> ObserverAssertionExecution:
        del lifecycle, context, assertion, attempts
        raise _InjectedRunInterruptionError


def _interrupt_on_positive_wait(config: ClockConfig) -> RuntimeClock:
    async def interrupt(seconds: float) -> None:
        if seconds > 0:
            raise _InjectedRunInterruptionError

    return RuntimeClock.from_config(config, sleep=interrupt)


def _possible_send_crash_executor_factory(
    config: ProjectConfig,
    clock: RuntimeClock,
) -> HttpAttemptExecutor:
    return HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=AnyIOResolver(),
            connector=_CrashAfterSendStartedConnector(),
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


def _incomplete_response_executor_factory(
    config: ProjectConfig,
    clock: RuntimeClock,
) -> HttpAttemptExecutor:
    return HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=AnyIOResolver(),
            connector=_IncompleteResponseConnector(),
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
async def test_legacy_resume_rejects_public_target_before_any_fixture_work(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    base = _config(
        project,
        443,
        steps=[{"deliver": {"event": "event"}}],
        assertions=[_status_assertion(expected=[204])],
    )
    wire = cast(
        "dict[str, object]",
        base.model_dump(mode="json", exclude_none=True),
    )
    receiver = cast("dict[str, object]", wire["receiver"])
    receiver.update(
        {
            "url": "https://receiver.example/webhook",
            "target_profile": "public-authorized",
            "allowed_hosts": ["receiver.example"],
            "allowed_ports": [443],
        }
    )
    config = ProjectConfig.model_validate(wire)
    request = FullRunRequest(
        config=config,
        project_root=project,
        artifact_directory=artifacts,
        secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
        signers={},
        runtime_public_authorization="receiver.example:443",
    )
    fixture_work: list[str] = []

    def executor_factory(
        executor_config: ProjectConfig,
        clock: RuntimeClock,
    ) -> HttpAttemptExecutor:
        del executor_config, clock
        fixture_work.append("executor")
        message = "legacy public resume must fail before fixture work"
        raise AssertionError(message)

    runner = FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=executor_factory,
    )
    with pytest.raises(
        ValueError,
        match="explicit validate/challenge/resume capability workflow",
    ):
        await runner.resume(
            request,
            cast("ResumeResult", object()),
            ownership=cast("RunLock", object()),
        )

    assert fixture_work == []
    assert list(artifacts.iterdir()) == []


@pytest.mark.anyio
async def test_public_resume_challenge_rejects_caller_fabricated_evidence_callback() -> None:
    runner = FullRunRunner(journal=JournalLifecycleRepository())
    callback_calls: list[str] = []

    async def fabricated_evidence() -> object:
        callback_calls.append("fabricated")
        return object()

    with pytest.raises(TypeError, match="unexpected keyword argument 'challenge'"):
        await cast("Any", runner.challenge_public_resume)(
            object(),
            ownership=object(),
            challenge=fabricated_evidence,
        )

    assert callback_calls == []


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
async def test_resume_continues_same_run_once_and_regenerates_complete_reports(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    waits: list[float] = []
    with _receiver([204, 204]) as receiver:
        port = receiver.server_address[1]
        config = _config(
            project,
            port,
            steps=[
                {"deliver": {"event": "event"}},
                {"wait": "7ms"},
                {"deliver": {"event": "event"}},
            ],
            assertions=[_status_assertion(expected=[204])],
        )
        request = _request(config, project, artifacts)
        with pytest.raises(ExceptionGroup) as captured:
            await FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
                clock_factory=_interrupt_on_positive_wait,
            ).run(request)
        assert any(
            isinstance(item, _InjectedRunInterruptionError) for item in captured.value.exceptions
        )

        assert len(receiver.bodies) == 1
        run_directory = next(artifacts.iterdir())
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            run_id = cast(
                "str",
                connection.execute("SELECT run_id FROM runs").fetchone()[0],
            )
            prior_attempt = cast(
                "str",
                connection.execute("SELECT attempt_id FROM attempts").fetchone()[0],
            )
            assert connection.execute(
                "SELECT COUNT(*) FROM schedule_entries WHERE consumed_at IS NULL"
            ).fetchone() == (1,)

        recovery = await ResumeService().resume(ResumeRequest(run_directory))
        assert recovery.status is ResumeStatus.CONTINUE
        assert recovery.run_id == run_id
        assert recovery.owner_epoch == 1
        assert recovery.policy_plan is not None
        assert len(recovery.policy_plan.runnable_schedule) == 1

        with acquire_run_lock(
            run_directory,
            run_id=recovery.run_id,
            owner_epoch=recovery.owner_epoch,
        ) as ownership:
            result = await FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
                clock_factory=_clock_factory(waits),
            ).resume(request, recovery, ownership=ownership)

    assert result.run_id == run_id
    assert result.result_category is ResultCategory.PASS
    assert len(receiver.bodies) == 2
    assert len(result.attempts) == 2
    assert result.attempts[0].attempt_id == prior_attempt
    assert [item.delivery_ordinal for item in result.attempts] == [0, 1]
    assert len(result.assertions) == 1
    assert result.assertions[0].result is AssertionResult.PASS
    assert any(wait == pytest.approx(0.007) for wait in waits)

    with sqlite3.connect(result.database_path) as connection:
        assert connection.execute(
            "SELECT owner_epoch, state, terminal_category FROM runs"
        ).fetchone() == (1, "completed", "pass")
        assert connection.execute(
            "SELECT COUNT(*), COUNT(DISTINCT attempt_id) FROM attempts"
        ).fetchone() == (2, 2)
        assert connection.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT schedule_entry_id)
            FROM schedule_entries
            WHERE consumed_at IS NOT NULL
            """
        ).fetchone() == (2, 2)
        assert connection.execute("SELECT COUNT(*) FROM assertion_evaluations").fetchone() == (1,)

    report_paths = {
        "assertions.jsonl",
        "deliveries.jsonl",
        "junit.xml",
        "observations.jsonl",
        "result-summary.json",
        "results.html",
        "run-manifest.json",
    }
    assert report_paths <= {item.name for item in result.run_directory.iterdir()}
    assert (
        len((result.run_directory / "deliveries.jsonl").read_text(encoding="utf-8").splitlines())
        == 2
    )


@pytest.mark.anyio
async def test_resume_reconciles_terminal_attempt_before_continuation_without_resend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()

    async def crash_after_terminal_attempt(
        *args: object,
        **kwargs: object,
    ) -> None:
        del args, kwargs
        raise _InjectedRunInterruptionError

    original_terminalize = runner_module._terminalize_delivery  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    monkeypatch.setattr(
        runner_module,
        "_terminalize_delivery",
        crash_after_terminal_attempt,
    )
    with _receiver([204]) as receiver:
        port = receiver.server_address[1]
        config = _config(
            project,
            port,
            steps=[{"deliver": {"event": "event"}}],
            assertions=[_status_assertion(expected=[204])],
        )
        request = _request(config, project, artifacts)
        with pytest.raises(ExceptionGroup) as captured:
            await FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
            ).run(request)
        assert captured.value.subgroup(_InjectedRunInterruptionError) is not None
        assert len(receiver.bodies) == 1
        run_directory = next(artifacts.iterdir())
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            assert connection.execute("SELECT state FROM attempts").fetchone() == (
                AttemptState.SUCCEEDED.value,
            )
            assert connection.execute("SELECT state FROM deliveries").fetchone() == (
                DeliveryState.ACTIVE.value,
            )
            assert connection.execute(
                "SELECT count(*) FROM schedule_entries WHERE consumed_at IS NULL"
            ).fetchone() == (0,)

        monkeypatch.setattr(
            runner_module,
            "_terminalize_delivery",
            original_terminalize,
        )
        recovery = await ResumeService().resume(ResumeRequest(run_directory))

        assert recovery.status is ResumeStatus.CONTINUE
        assert len(recovery.automatic_transitions) == 1
        assert recovery.automatic_transitions[0].record.entity_type is EntityType.DELIVERY
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            assert connection.execute("SELECT state FROM deliveries").fetchone() == (
                DeliveryState.SATISFIED.value,
            )

        with acquire_run_lock(
            run_directory,
            run_id=recovery.run_id,
            owner_epoch=recovery.owner_epoch,
        ) as ownership:
            result = await FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
            ).resume(request, recovery, ownership=ownership)

    assert result.result_category is ResultCategory.PASS
    assert len(result.attempts) == 1
    assert len(receiver.bodies) == 1


def test_retained_request_body_spool_reads_adjacent_segments_exactly() -> None:
    first = b"a"
    second = b"b"
    first_digest = f"sha256:{hashlib.sha256(first).hexdigest()}"
    second_digest = f"sha256:{hashlib.sha256(second).hexdigest()}"
    spool = runner_module._RetainedRequestBodies(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        cast("BinaryIO", io.BytesIO(first + second)),
        {
            first_digest: runner_module._RetainedBodyLocation(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
                offset=0,
                byte_length=len(first),
            ),
            second_digest: runner_module._RetainedBodyLocation(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
                offset=len(first),
                byte_length=len(second),
            ),
        },
    )
    try:
        assert spool.read(first_digest) == first
        assert spool.read(second_digest) == second
    finally:
        spool.close()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status_code", "attempt_state", "delivery_state", "result_category"),
    [
        (
            204,
            AttemptState.SUCCEEDED,
            DeliveryState.SATISFIED,
            ResultCategory.PASS,
        ),
        (
            400,
            AttemptState.REJECTED,
            DeliveryState.EXHAUSTED,
            ResultCategory.RECEIVER_FAILURE,
        ),
    ],
)
async def test_resume_reduces_v4_staged_response_and_delivery_before_resend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    attempt_state: AttemptState,
    delivery_state: DeliveryState,
    result_category: ResultCategory,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    crash_hook = _CrashOnAttemptPhaseOccurrence(6)

    def crashing_repository(service: JournalService) -> TransitionRepository:
        return TransitionRepository(service, crash_hook=crash_hook)

    monkeypatch.setattr(
        runner_module,
        "TransitionRepository",
        crashing_repository,
    )
    with _receiver([status_code]) as receiver:
        port = receiver.server_address[1]
        config = _config(
            project,
            port,
            steps=[{"deliver": {"event": "event"}}],
            assertions=[_status_assertion(expected=[204])],
        )
        request = _request(config, project, artifacts)
        with pytest.raises(ExceptionGroup) as captured:
            await FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
            ).run(request)
        assert captured.value.subgroup(_InjectedRunInterruptionError) is not None
        assert len(receiver.bodies) == 1
        run_directory = next(artifacts.iterdir())
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            assert connection.execute(
                """
                SELECT attempts.state, attempt_response_staging.terminal_state
                FROM attempts
                JOIN attempt_response_staging
                  ON attempt_response_staging.attempt_id = attempts.attempt_id
                """
            ).fetchone() == (
                AttemptState.RESPONSE_OBSERVED.value,
                attempt_state.value,
            )
            assert connection.execute("SELECT state FROM deliveries").fetchone() == (
                DeliveryState.ACTIVE.value,
            )
            assert connection.execute(
                "SELECT count(*) FROM schedule_entries WHERE consumed_at IS NULL"
            ).fetchone() == (0,)

        monkeypatch.setattr(
            runner_module,
            "TransitionRepository",
            TransitionRepository,
        )
        recovery = await ResumeService().resume(ResumeRequest(run_directory))

        assert recovery.status is ResumeStatus.CONTINUE
        assert len(recovery.automatic_transitions) == 2
        assert {item.record.entity_type for item in recovery.automatic_transitions} == {
            EntityType.ATTEMPT,
            EntityType.DELIVERY,
        }
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            assert connection.execute("SELECT state FROM attempts").fetchone() == (
                attempt_state.value,
            )
            assert connection.execute(
                "SELECT count(*) FROM attempt_response_staging"
            ).fetchone() == (0,)
            assert connection.execute("SELECT state FROM deliveries").fetchone() == (
                delivery_state.value,
            )

        with acquire_run_lock(
            run_directory,
            run_id=recovery.run_id,
            owner_epoch=recovery.owner_epoch,
        ) as ownership:
            result = await FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
            ).resume(request, recovery, ownership=ownership)

    assert result.result_category is result_category
    assert len(result.attempts) == 1
    assert len(receiver.bodies) == 1


@pytest.mark.anyio
async def test_resume_preserves_terminal_assertion_and_evaluates_only_pending(
    tmp_path: Path,
) -> None:
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
                _status_assertion(expected=[204]),
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
                },
            ],
        )
        request = _request(config, project, artifacts)
        with pytest.raises(ExceptionGroup):
            await FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
                observer_assertion_executor=_InterruptingObserverAssertionExecutor(),
            ).run(request)

        run_directory = next(artifacts.iterdir())
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            original = connection.execute(
                """
                SELECT evaluation_id, record_id, assertion_id, result
                FROM assertion_evaluations
                """
            ).fetchone()
            assert original is not None
            assert original[3] == "pass"

        recovery = await ResumeService().resume(ResumeRequest(run_directory))
        assert recovery.status is ResumeStatus.CONTINUE
        with acquire_run_lock(
            run_directory,
            run_id=recovery.run_id,
            owner_epoch=recovery.owner_epoch,
        ) as ownership:
            result = await FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
            ).resume(request, recovery, ownership=ownership)

    assert len(receiver.bodies) == 1
    assert result.result_category is ResultCategory.UNSUPPORTED
    assert [item.result for item in result.assertions] == [
        AssertionResult.PASS,
        AssertionResult.ERROR,
    ]
    with sqlite3.connect(result.database_path) as connection:
        evaluations = connection.execute(
            """
            SELECT evaluation_id, record_id, assertion_id, result
            FROM assertion_evaluations
            ORDER BY assertion_id
            """
        ).fetchall()
    assert len(evaluations) == 2
    assert original in evaluations
    assert len({item[2] for item in evaluations}) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("interrupted_state", ["pending", "running"])
async def test_resume_reuses_durable_non_read_only_observation_without_reinvocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupted_state: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    (project / "observer.py").write_text(
        _SIDE_EFFECTING_COUNT_OBSERVER,
        encoding="utf-8",
    )
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
        request = _request(config, project, artifacts)
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

        async def interrupt(*_args: object, **_kwargs: object) -> None:
            raise _InjectedRunInterruptionError

        target = "evaluate_observer" if interrupted_state == "pending" else "_persist"
        with monkeypatch.context() as interruption:
            interruption.setattr(AssertionLifecycle, target, interrupt)
            with pytest.raises(BaseExceptionGroup):
                await runner.run(request)

        run_directory = next(artifacts.iterdir())
        assert (project / "observe-count.txt").read_text(encoding="ascii") == "1"
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            assert connection.execute("SELECT COUNT(*) FROM observation_samples").fetchone() == (1,)
            assert connection.execute("SELECT state FROM assertions").fetchone() == (
                interrupted_state,
            )

        recovery = await ResumeService().resume(ResumeRequest(run_directory))
        assert recovery.status is ResumeStatus.CONTINUE
        with acquire_run_lock(
            run_directory,
            run_id=recovery.run_id,
            owner_epoch=recovery.owner_epoch,
        ) as ownership:
            prepared = await runner.prepare_resume(
                request,
                run_directory,
                ownership=ownership,
            )
            assert prepared.manifest_id == load_replay_bundle(run_directory).manifest.manifest_id
            result = await runner.resume(
                request,
                recovery,
                ownership=ownership,
            )

    assert len(receiver.bodies) == 1
    assert (project / "observe-count.txt").read_text(encoding="ascii") == "1"
    assert result.result_category is ResultCategory.PASS
    assert result.assertions[0].result is AssertionResult.PASS
    with sqlite3.connect(result.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM observation_samples").fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*), min(result) FROM assertion_evaluations"
        ).fetchone() == (1, "pass")


@pytest.mark.anyio
async def test_resume_does_not_reinvoke_interrupted_observer_without_durable_sample(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    (project / "observer.py").write_text(
        _SIDE_EFFECTING_COUNT_OBSERVER,
        encoding="utf-8",
    )
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
        request = _request(config, project, artifacts)
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

        async def interrupt_append(*_args: object, **_kwargs: object) -> None:
            raise _InjectedRunInterruptionError

        with monkeypatch.context() as interruption:
            interruption.setattr(
                ObservationRepository,
                "append_sample",
                interrupt_append,
            )
            with pytest.raises(BaseExceptionGroup):
                await runner.run(request)

        run_directory = next(artifacts.iterdir())
        assert (project / "observe-count.txt").read_text(encoding="ascii") == "1"
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            assert connection.execute("SELECT COUNT(*) FROM observation_samples").fetchone() == (0,)
            assert connection.execute("SELECT state FROM observer_series").fetchone() == (
                "running",
            )

        recovery = await ResumeService().resume(ResumeRequest(run_directory))
        assert recovery.status is ResumeStatus.CONTINUE
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            before_run_state = connection.execute("SELECT state FROM runs").fetchone()
            assert connection.execute("SELECT state FROM observer_series").fetchone() == ("error",)
        with acquire_run_lock(
            run_directory,
            run_id=recovery.run_id,
            owner_epoch=recovery.owner_epoch,
        ) as ownership:
            public_contacts: list[str] = []

            async def validate_before_public_contact() -> None:
                validation = await runner.validate_resume(
                    request,
                    recovery,
                    ownership=ownership,
                )
                public_contacts.append("public_nonce_challenge")
                await validation.aclose()

            with pytest.raises(
                RuntimeError,
                match="interrupted observer invocation lacks a reusable durable sample",
            ):
                await validate_before_public_contact()
            assert public_contacts == []

    assert len(receiver.bodies) == 1
    assert (project / "observe-count.txt").read_text(encoding="ascii") == "1"
    with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
        assert connection.execute("SELECT state FROM runs").fetchone() == before_run_state


@pytest.mark.anyio
async def test_noncrash_unknown_pauses_resumable_projections_then_redelivers(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    with _receiver([204]) as receiver:
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
                            "backoff": ["1ms"],
                            "retry_on": ["timed_out"],
                        },
                    }
                }
            ],
            assertions=[_status_assertion(expected=[204], mode="last-terminal")],
        )
        request = _request(config, project, artifacts)
        paused = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_incomplete_response_executor_factory,
        ).run(request)

        assert paused.result_category is ResultCategory.AMBIGUOUS
        assert paused.scenarios[0].state is ScenarioState.RUNNING
        assert paused.assertions == ()
        assert receiver.bodies == []
        with sqlite3.connect(paused.database_path) as connection:
            assert connection.execute(
                "SELECT state, terminal_category, terminal_at FROM runs"
            ).fetchone() == ("paused", None, None)
            assert connection.execute("SELECT state FROM scenarios").fetchone() == ("running",)
            assert connection.execute("SELECT state FROM deliveries").fetchone() == ("active",)
            assert connection.execute("SELECT state FROM assertions").fetchone() == ("pending",)
            predecessor_attempt_id = cast(
                "str",
                connection.execute(
                    "SELECT attempt_id FROM attempts WHERE state = 'unknown_outcome'"
                ).fetchone()[0],
            )

        loaded = load_replay_bundle(paused.run_directory)
        runner = FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
        )

        async def prepare(
            preflight: ResumeJournalPreflight,
            ownership: RunLock,
        ) -> FullRunResumePreparation:
            return await runner.prepare_resume(
                request,
                preflight.run_directory,
                ownership=ownership,
            )

        async def continue_run(
            recovery: ResumeResult,
            ownership: RunLock,
            prepared: object,
        ) -> FullRunResult:
            assert type(prepared) is FullRunResumePreparation
            return await runner.resume(
                request,
                recovery,
                ownership=ownership,
            )

        workflow = await ResumeService().resume_and_continue(
            ResumeRequest(
                paused.run_directory,
                invocation=ResumeInvocationPolicy(
                    on_ambiguous=AmbiguityPolicy.REDELIVER,
                ),
                manifest=loaded.manifest,
                defer_redeliveries=True,
            ),
            prepare=prepare,
            continuation=continue_run,
        )
        recovery = workflow.recovery
        result = cast("FullRunResult", workflow.continuation)
        assert recovery.status is ResumeStatus.CONTINUE
        assert recovery.policy_plan is not None
        assert len(recovery.policy_plan.redeliveries) == 1
        successor = recovery.policy_plan.redeliveries[0]

    assert result.result_category is ResultCategory.PASS
    assert len(receiver.bodies) == 1
    assert [item.attempt_id for item in result.attempts] == [
        predecessor_attempt_id,
        successor.attempt_id,
    ]
    assert [item.terminal_state for item in result.attempts] == [
        AttemptState.UNKNOWN_OUTCOME,
        AttemptState.SUCCEEDED,
    ]
    assert result.assertions[0].result is AssertionResult.PASS
    with sqlite3.connect(result.database_path) as connection:
        assert connection.execute("SELECT state, terminal_category FROM runs").fetchone() == (
            "completed",
            "pass",
        )
        assert connection.execute("SELECT state FROM scenarios").fetchone() == ("passed",)
        assert connection.execute("SELECT state FROM deliveries").fetchone() == ("satisfied",)


@pytest.mark.anyio
async def test_prepare_resume_rejects_legacy_terminal_ambiguity_without_mutation_or_network(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    with _receiver([204]) as receiver:
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
                            "backoff": ["1ms"],
                            "retry_on": ["timed_out"],
                        },
                    }
                }
            ],
            assertions=[_status_assertion(expected=[204], mode="last-terminal")],
        )
        request = _request(config, project, artifacts)
        paused = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_incomplete_response_executor_factory,
        ).run(request)
        scenario_id = paused.attempts[0].evidence.scenario_id
        delivery_id = paused.attempts[0].evidence.delivery_id
        clock = RuntimeClock.from_config(config.clock)
        async with JournalService.open(paused.database_path) as service:
            transitions = TransitionRepository(service)
            await transitions.apply(
                TransitionCommand(
                    run_id=paused.run_id,
                    transition_id="legacy.prepare.delivery.ambiguous",
                    entity_type=EntityType.DELIVERY,
                    entity_id=delivery_id,
                    expected_state=DeliveryState.ACTIVE,
                    new_state=DeliveryState.AMBIGUOUS,
                    trigger_category="legacy_ambiguous_reduction",
                    timestamp=clock.transition_timestamp(),
                    owner_epoch=0,
                    idempotency_key="legacy.prepare.delivery.ambiguous",
                )
            )
            await transitions.apply(
                TransitionCommand(
                    run_id=paused.run_id,
                    transition_id="legacy.prepare.scenario.ambiguous",
                    entity_type=EntityType.SCENARIO,
                    entity_id=scenario_id,
                    expected_state=ScenarioState.RUNNING,
                    new_state=ScenarioState.AMBIGUOUS,
                    trigger_category="legacy_ambiguous_reduction",
                    timestamp=clock.transition_timestamp(),
                    owner_epoch=0,
                    idempotency_key="legacy.prepare.scenario.ambiguous",
                )
            )

        database_before = paused.database_path.read_bytes()
        with sqlite3.connect(
            f"{paused.database_path.as_uri()}?mode=ro",
            uri=True,
        ) as connection:
            successors_before = connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE predecessor_attempt_id IS NOT NULL"
            ).fetchone()
            schedules_before = connection.execute(
                "SELECT COUNT(*) FROM schedule_entries"
            ).fetchone()
        loaded = load_replay_bundle(paused.run_directory)
        runner = FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_unexpected_executor_factory,
        )

        async def prepare(
            preflight: ResumeJournalPreflight,
            ownership: RunLock,
        ) -> FullRunResumePreparation:
            return await runner.prepare_resume(
                request,
                preflight.run_directory,
                ownership=ownership,
            )

        async def forbidden_continuation(
            recovery: ResumeResult,
            ownership: RunLock,
            prepared: object,
        ) -> object:
            del recovery, ownership, prepared
            message = "legacy ambiguity rejection must precede continuation"
            raise AssertionError(message)

        with pytest.raises(
            RuntimeError,
            match="legacy terminal-ambiguous delivery or scenario projection",
        ):
            await ResumeService().resume_and_continue(
                ResumeRequest(
                    paused.run_directory,
                    invocation=ResumeInvocationPolicy(
                        on_ambiguous=AmbiguityPolicy.REDELIVER,
                    ),
                    manifest=loaded.manifest,
                    defer_redeliveries=True,
                ),
                prepare=prepare,
                continuation=forbidden_continuation,
            )
        assert paused.database_path.read_bytes() == database_before
        with sqlite3.connect(
            f"{paused.database_path.as_uri()}?mode=ro",
            uri=True,
        ) as connection:
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM attempts WHERE predecessor_attempt_id IS NOT NULL"
                ).fetchone()
                == successors_before
                == (0,)
            )
            assert (
                connection.execute("SELECT COUNT(*) FROM schedule_entries").fetchone()
                == schedules_before
                == (1,)
            )

    assert receiver.bodies == []


@pytest.mark.anyio
async def test_resume_validation_rejects_cross_runner_challenge_and_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    config = _config(
        project,
        8081,
        steps=[
            {
                "deliver": {
                    "event": "event",
                    "retry": {
                        "max_attempts": 2,
                        "backoff": ["1ms"],
                        "retry_on": ["timed_out"],
                    },
                }
            }
        ],
        assertions=[_status_assertion(expected=[204], mode="last-terminal")],
    )
    request = _request(config, project, artifacts)
    paused = await FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_incomplete_response_executor_factory,
    ).run(request)
    loaded = load_replay_bundle(paused.run_directory)
    recovery = await ResumeService().resume(
        ResumeRequest(
            paused.run_directory,
            invocation=ResumeInvocationPolicy(
                on_ambiguous=AmbiguityPolicy.REDELIVER,
            ),
            manifest=loaded.manifest,
            defer_redeliveries=True,
        )
    )
    origin = FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_executor_factory,
    )
    public_contacts: list[str] = []

    async def unexpected_preflight(*_args: object, **_kwargs: object) -> object:
        public_contacts.append("public")
        return object()

    monkeypatch.setattr(
        runner_module,
        "preflight_public_target",
        unexpected_preflight,
    )
    other = FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_executor_factory,
        observer_assertion_executor=_InterruptingObserverAssertionExecutor(),
        public_resume_preflight=FullRunPublicPreflight(
            PinnedDestinationDialer(
                resolver=AnyIOResolver(),
                connector=AnyIOConnector(),
            )
        ),
    )

    with acquire_run_lock(
        paused.run_directory,
        run_id=recovery.run_id,
        owner_epoch=recovery.owner_epoch,
    ) as ownership:
        challenge_validation = await origin.validate_resume(
            request,
            recovery,
            ownership=ownership,
        )
        with pytest.raises(ValueError, match="different runner instance"):
            await other.challenge_public_resume(
                challenge_validation,
                ownership=ownership,
            )
        assert not challenge_validation.retained_resources_released
        await challenge_validation.aclose()
        assert challenge_validation.retained_resources_released

        execution_validation = await origin.validate_resume(
            request,
            recovery,
            ownership=ownership,
        )
        with pytest.raises(ValueError, match="different runner instance"):
            await other.resume_validated(
                execution_validation,
                ownership=ownership,
            )
        assert not execution_validation.retained_resources_released
        await execution_validation.aclose()
        assert execution_validation.retained_resources_released

    assert public_contacts == []
    with sqlite3.connect(paused.database_path) as connection:
        assert connection.execute("SELECT state FROM runs").fetchone() == ("paused",)
        assert connection.execute(
            "SELECT COUNT(*) FROM schedule_entries WHERE consumed_at IS NULL"
        ).fetchone() == (1,)


@pytest.mark.anyio
async def test_duplicate_public_challenge_cannot_close_legitimate_claim(  # noqa: PLR0915
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    config = _config(
        project,
        8081,
        steps=[
            {
                "deliver": {
                    "event": "event",
                    "retry": {
                        "max_attempts": 2,
                        "backoff": ["1ms"],
                        "retry_on": ["timed_out"],
                    },
                }
            }
        ],
        assertions=[_status_assertion(expected=[204], mode="last-terminal")],
    )
    request = _request(config, project, artifacts)
    paused = await FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_incomplete_response_executor_factory,
    ).run(request)
    loaded = load_replay_bundle(paused.run_directory)
    recovery = await ResumeService().resume(
        ResumeRequest(
            paused.run_directory,
            invocation=ResumeInvocationPolicy(
                on_ambiguous=AmbiguityPolicy.REDELIVER,
            ),
            manifest=loaded.manifest,
            defer_redeliveries=True,
        )
    )

    wire = cast("dict[str, object]", config.model_dump(mode="json", exclude_none=True))
    receiver_wire = cast("dict[str, object]", wire["receiver"])
    receiver_wire.update(
        {
            "url": "https://receiver.example/webhook",
            "target_profile": "public-authorized",
            "allowed_hosts": ["receiver.example"],
            "allowed_ports": [443],
        }
    )
    public_config = ProjectConfig.model_validate(wire)
    public_request = replace(
        request,
        config=public_config,
        runtime_public_authorization="receiver.example:443",
    )
    public_policy = parse_destination_policy(
        public_config.receiver,
        runtime_public_authorization="receiver.example:443",
    )
    challenge_started = anyio.Event()
    release_challenge = anyio.Event()
    challenge_completions: list[str] = []

    async def controlled_preflight(*_args: object, **_kwargs: object) -> object:
        challenge_started.set()
        await release_challenge.wait()
        return PublicTargetPreflightEvidence(
            authority=public_policy.destination.authority,
            challenge_path=public_policy.public_challenge_path,
            challenge_sha256="sha256:" + ("d" * 64),
            request_bytes=1,
            response_bytes=1,
            status_code=204,
            peer=PeerAddressEvidence(
                authorized_address="93.184.216.34",
                authorized_family=SocketFamily.IPV4,
                peer_address="93.184.216.34",
                peer_family=SocketFamily.IPV4,
            ),
        )

    monkeypatch.setattr(
        runner_module,
        "preflight_public_target",
        controlled_preflight,
    )
    runner = FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_executor_factory,
        public_resume_preflight=FullRunPublicPreflight(
            PinnedDestinationDialer(
                resolver=AnyIOResolver(),
                connector=AnyIOConnector(),
            )
        ),
    )

    with acquire_run_lock(
        paused.run_directory,
        run_id=recovery.run_id,
        owner_epoch=recovery.owner_epoch,
    ) as ownership:
        validation = await runner.validate_resume(
            request,
            recovery,
            ownership=ownership,
        )
        validation.request = public_request
        validation.policy = public_policy

        async def legitimate_challenge() -> None:
            await runner.challenge_public_resume(
                validation,
                ownership=ownership,
            )
            challenge_completions.append("legitimate")

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(legitimate_challenge)
            await challenge_started.wait()
            with pytest.raises(ValueError, match="not in an issuable state"):
                await runner.challenge_public_resume(
                    validation,
                    ownership=ownership,
                )
            assert not validation.is_closed
            assert validation.executor is not None
            release_challenge.set()

        assert challenge_completions == ["legitimate"]
        assert not validation.is_closed
        await validation.aclose()

        async def failing_preflight(*_args: object, **_kwargs: object) -> object:
            raise PublicTargetPreflightError(
                PreflightErrorCode.CONNECTION_FAILED,
                PreflightPhase.CONNECTION,
                "injected public challenge failure",
                retryable=True,
                network_contacted=False,
            )

        monkeypatch.setattr(
            runner_module,
            "preflight_public_target",
            failing_preflight,
        )
        failing_validation = await runner.validate_resume(
            request,
            recovery,
            ownership=ownership,
        )
        failing_validation.request = public_request
        failing_validation.policy = public_policy
        with pytest.raises(
            PublicTargetPreflightError,
            match="injected public challenge failure",
        ):
            await runner.challenge_public_resume(
                failing_validation,
                ownership=ownership,
            )
        assert failing_validation.retained_resources_released

    with sqlite3.connect(paused.database_path) as connection:
        assert connection.execute("SELECT owner_epoch, state FROM runs").fetchone() == (
            recovery.owner_epoch,
            "paused",
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM schedule_entries WHERE consumed_at IS NULL"
        ).fetchone() == (1,)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "fault",
    [
        "create",
        "write",
        "flush",
        "corrupt",
        "short",
        "unreadable",
        "seek",
        "read",
        "read-close",
        "close",
    ],
)
async def test_resume_spool_faults_are_pregate_and_cleanup_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    config = _config(
        project,
        8082,
        steps=[
            {
                "deliver": {
                    "event": "event",
                    "retry": {
                        "max_attempts": 2,
                        "backoff": ["1ms"],
                        "retry_on": ["timed_out"],
                    },
                }
            }
        ],
        assertions=[_status_assertion(expected=[204], mode="last-terminal")],
    )
    request = _request(config, project, artifacts)
    paused = await FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_incomplete_response_executor_factory,
    ).run(request)
    loaded = load_replay_bundle(paused.run_directory)
    recovery = await ResumeService().resume(
        ResumeRequest(
            paused.run_directory,
            invocation=ResumeInvocationPolicy(
                on_ambiguous=AmbiguityPolicy.REDELIVER,
            ),
            manifest=loaded.manifest,
            defer_redeliveries=True,
        )
    )
    original_temporary_file = runner_module.tempfile.TemporaryFile
    created: list[_FaultingSpool] = []

    def faulting_temporary_file(*args: object, **kwargs: object) -> BinaryIO:
        if fault == "create":
            raise OSError("injected spool creation fault")
        stream = cast("BinaryIO", original_temporary_file(*args, **kwargs))
        wrapper = _FaultingSpool(stream, fault)
        created.append(wrapper)
        return cast("BinaryIO", wrapper)

    monkeypatch.setattr(
        runner_module.tempfile,
        "TemporaryFile",
        faulting_temporary_file,
    )
    runner = FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_executor_factory,
    )
    with acquire_run_lock(
        paused.run_directory,
        run_id=recovery.run_id,
        owner_epoch=recovery.owner_epoch,
    ) as ownership:
        if fault == "close":
            validation = await runner.validate_resume(
                request,
                recovery,
                ownership=ownership,
            )
            with pytest.raises(OSError, match="injected spool close fault"):
                await validation.aclose()
            assert validation.retained_resources_released
            assert validation.service.state is JournalServiceState.CLOSED
            assert (
                len(
                    runner._resume_authorizations  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
                )
                == 0
            )
        else:
            expected = BaseExceptionGroup if fault == "read-close" else ValueError
            with pytest.raises(expected):
                await runner.validate_resume(
                    request,
                    recovery,
                    ownership=ownership,
                )

    assert all(item.closed for item in created)
    with sqlite3.connect(paused.database_path) as connection:
        assert connection.execute("SELECT state FROM runs").fetchone() == ("paused",)
        assert connection.execute(
            "SELECT COUNT(*) FROM schedule_entries WHERE consumed_at IS NULL"
        ).fetchone() == (1,)
    async with JournalService.open(paused.database_path) as verification_service:
        inventory = await TransitionRepository(verification_service).projection_inventory(
            paused.run_id
        )
        assert inventory
    assert verification_service.state is JournalServiceState.CLOSED


@pytest.mark.anyio
async def test_validate_resume_freezes_request_bytes_before_public_contact(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    config = _config(
        project,
        8080,
        steps=[
            {
                "deliver": {
                    "event": "event",
                    "retry": {
                        "max_attempts": 2,
                        "backoff": ["1ms"],
                        "retry_on": ["timed_out"],
                    },
                }
            }
        ],
        assertions=[_status_assertion(expected=[204], mode="last-terminal")],
    )
    request = _request(config, project, artifacts)
    paused = await FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_incomplete_response_executor_factory,
    ).run(request)
    assert paused.result_category is ResultCategory.AMBIGUOUS

    loaded = load_replay_bundle(paused.run_directory)
    recovery = await ResumeService().resume(
        ResumeRequest(
            paused.run_directory,
            invocation=ResumeInvocationPolicy(
                on_ambiguous=AmbiguityPolicy.REDELIVER,
            ),
            manifest=loaded.manifest,
            defer_redeliveries=True,
        )
    )
    assert recovery.status is ResumeStatus.CONTINUE
    runner = FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_executor_factory,
    )
    public_contacts: list[str] = []
    with acquire_run_lock(
        paused.run_directory,
        run_id=recovery.run_id,
        owner_epoch=recovery.owner_epoch,
    ) as ownership:
        preparation = await runner.prepare_resume(
            request,
            paused.run_directory,
            ownership=ownership,
        )
        request_digest = loaded.manifest.scenarios[0].deliveries[0].attempt_plan[0].request_blob
        request_snapshot = next(item for item in loaded.blobs if item.sha256 == request_digest)
        request_snapshot.path.write_bytes(b"x" * request_snapshot.byte_length)

        async def validate_before_public_contact() -> None:
            validation = await runner.validate_resume(
                request,
                recovery,
                ownership=ownership,
                preparation=preparation,
            )
            public_contacts.append("public_nonce_challenge")
            await validation.aclose()

        with pytest.raises(
            ValueError,
            match="request blob changed before public authorization",
        ):
            await validate_before_public_contact()

    assert public_contacts == []
    with sqlite3.connect(paused.database_path) as connection:
        assert connection.execute("SELECT state FROM runs").fetchone() == ("paused",)


@pytest.mark.anyio
async def test_resume_rejects_semantically_invalid_delivery_before_public_contact(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    with _receiver([204]) as receiver:
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
                            "backoff": ["1ms"],
                            "retry_on": ["timed_out"],
                        },
                    }
                }
            ],
            assertions=[_status_assertion(expected=[204], mode="last-terminal")],
        )
        request = _request(config, project, artifacts)
        paused = await FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_incomplete_response_executor_factory,
        ).run(request)
        scenario_id = paused.attempts[0].evidence.scenario_id
        delivery_id = paused.attempts[0].evidence.delivery_id
        clock = RuntimeClock.from_config(config.clock)
        async with JournalService.open(paused.database_path) as service:
            transitions = TransitionRepository(service)
            await transitions.apply(
                TransitionCommand(
                    run_id=paused.run_id,
                    transition_id="legacy.delivery.ambiguous",
                    entity_type=EntityType.DELIVERY,
                    entity_id=delivery_id,
                    expected_state=DeliveryState.ACTIVE,
                    new_state=DeliveryState.AMBIGUOUS,
                    trigger_category="legacy_ambiguous_reduction",
                    timestamp=clock.transition_timestamp(),
                    owner_epoch=0,
                    idempotency_key="legacy.delivery.ambiguous",
                )
            )
            await transitions.apply(
                TransitionCommand(
                    run_id=paused.run_id,
                    transition_id="legacy.scenario.ambiguous",
                    entity_type=EntityType.SCENARIO,
                    entity_id=scenario_id,
                    expected_state=ScenarioState.RUNNING,
                    new_state=ScenarioState.AMBIGUOUS,
                    trigger_category="legacy_ambiguous_reduction",
                    timestamp=clock.transition_timestamp(),
                    owner_epoch=0,
                    idempotency_key="legacy.scenario.ambiguous",
                )
            )

        loaded = load_replay_bundle(paused.run_directory)
        recovery = await ResumeService().resume(
            ResumeRequest(
                paused.run_directory,
                invocation=ResumeInvocationPolicy(
                    on_ambiguous=AmbiguityPolicy.REDELIVER,
                ),
                manifest=loaded.manifest,
                defer_redeliveries=True,
            )
        )
        assert recovery.status is ResumeStatus.CONTINUE
        with acquire_run_lock(
            paused.run_directory,
            run_id=recovery.run_id,
            owner_epoch=recovery.owner_epoch,
        ) as ownership:
            runner = FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
            )
            public_contacts: list[str] = []

            async def validate_contact_and_send() -> FullRunResult:
                validation = await runner.validate_resume(
                    request,
                    recovery,
                    ownership=ownership,
                )
                public_contacts.append("public_nonce_challenge")
                return await runner.resume_validated(
                    validation,
                    ownership=ownership,
                )

            with pytest.raises(
                RuntimeError,
                match="pending resume schedule targets an immutable terminal delivery",
            ):
                await validate_contact_and_send()
            assert public_contacts == []

    assert receiver.bodies == []


@pytest.mark.anyio
async def test_resume_executes_manifest_authorized_redelivery_once(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifacts = project / "runs"
    artifacts.mkdir()
    with _receiver([204]) as receiver:
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
                            "backoff": ["1ms"],
                            "retry_on": ["timed_out"],
                        },
                    }
                }
            ],
            assertions=[_status_assertion(expected=[204], mode="last-terminal")],
        )
        request = _request(config, project, artifacts)
        with pytest.raises(BaseExceptionGroup):
            await FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_possible_send_crash_executor_factory,
            ).run(request)

        assert receiver.bodies == []
        run_directory = next(artifacts.iterdir())
        loaded = load_replay_bundle(run_directory)
        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            run_id = cast("str", connection.execute("SELECT run_id FROM runs").fetchone()[0])
            crashed_attempt_id, crashed_state = connection.execute(
                "SELECT attempt_id, state FROM attempts"
            ).fetchone()
            assert crashed_state == "sending"
            assert connection.execute(
                "SELECT COUNT(*) FROM schedule_entries WHERE consumed_at IS NOT NULL"
            ).fetchone() == (1,)

        recovery = await ResumeService().resume(
            ResumeRequest(
                run_directory,
                invocation=ResumeInvocationPolicy(
                    on_ambiguous=AmbiguityPolicy.REDELIVER,
                ),
                manifest=loaded.manifest,
                defer_redeliveries=True,
            )
        )
        assert recovery.status is ResumeStatus.CONTINUE
        assert recovery.redeliveries_invoked == 0
        assert recovery.policy_plan is not None
        assert len(recovery.policy_plan.redeliveries) == 1
        redelivery = recovery.policy_plan.redeliveries[0]
        assert redelivery.predecessor_attempt_id == crashed_attempt_id

        with sqlite3.connect(run_directory / "journal.sqlite3") as connection:
            assert connection.execute(
                """
                SELECT attempt_id, state, ordinal, predecessor_attempt_id
                FROM attempts
                ORDER BY ordinal
                """
            ).fetchall() == [
                (crashed_attempt_id, "unknown_outcome", 1, None),
                (redelivery.attempt_id, "scheduled", 2, crashed_attempt_id),
            ]
            assert connection.execute(
                "SELECT COUNT(*) FROM schedule_entries WHERE consumed_at IS NULL"
            ).fetchone() == (1,)

        with acquire_run_lock(
            run_directory,
            run_id=recovery.run_id,
            owner_epoch=recovery.owner_epoch,
        ) as ownership:
            runner = FullRunRunner(
                journal=JournalLifecycleRepository(),
                executor_factory=_executor_factory,
            )
            duplicate_task_manager = anyio.create_task_group()
            duplicate_tasks = await duplicate_task_manager.__aenter__()
            validation = await runner.validate_resume(
                request,
                recovery,
                ownership=ownership,
            )
            pending = await validation.schedules.pending(recovery.run_id)
            unrelated = BlobSnapshot(
                sha256="sha256:" + ("c" * 64),
                byte_length=1_073_741_825,
                media_type="application/octet-stream",
                path=project / "unrelated-blob-must-not-be-read",
            )
            extended = runner_module._ExecutionBundle(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
                manifest=validation.bundle.manifest,
                blobs=(*validation.bundle.blobs, unrelated),
                realized_execution=validation.bundle.realized_execution,
            )
            scoped_bodies = runner_module._materialize_request_bodies(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
                extended,
                pending,
            )
            assert validation.request_bodies is not None
            assert scoped_bodies.digests == validation.request_bodies.digests
            scoped_bodies.close()

            response_release = threading.Event()
            receiver.response_release = response_release
            duplicate_failures: list[str] = []

            async def duplicate_resume() -> None:
                fixture_contacted = await run_sync_in_worker_thread(
                    receiver.request_received.wait,
                    5,
                )
                if not fixture_contacted:
                    response_release.set()
                    raise AssertionError("legitimate resume did not contact the fixture receiver")
                try:
                    with pytest.raises(ValueError, match="already being consumed"):
                        await runner.resume_validated(
                            validation,
                            ownership=ownership,
                        )
                    duplicate_failures.append("rejected")
                    assert not validation.is_closed
                    assert validation.executor is not None
                finally:
                    response_release.set()

            duplicate_tasks.start_soon(duplicate_resume)
            result = await runner.resume_validated(
                validation,
                ownership=ownership,
            )
            await duplicate_task_manager.__aexit__(None, None, None)

            assert duplicate_failures == ["rejected"]
            assert validation.retained_resources_released
            assert validation.request_bodies is None
            assert validation.executor is None
            with pytest.raises(ValueError, match="different runner instance"):
                await runner.resume_validated(
                    validation,
                    ownership=ownership,
                )

    assert result.run_id == run_id
    assert result.result_category is ResultCategory.PASS
    assert len(receiver.bodies) == 1
    assert [item.attempt_id for item in result.attempts] == [
        crashed_attempt_id,
        redelivery.attempt_id,
    ]
    assert [item.terminal_state.value for item in result.attempts] == [
        "unknown_outcome",
        "succeeded",
    ]
    with sqlite3.connect(result.database_path) as connection:
        assert connection.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT attempt_id),
                   max(CASE WHEN ordinal = 2 THEN predecessor_attempt_id END)
            FROM attempts
            """
        ).fetchone() == (2, 2, crashed_attempt_id)
        assert connection.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT schedule_entry_id)
            FROM schedule_entries
            WHERE consumed_at IS NOT NULL
            """
        ).fetchone() == (2, 2)
        assert connection.execute(
            "SELECT owner_epoch, state, terminal_category FROM runs"
        ).fetchone() == (1, "completed", "pass")


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
async def test_prepared_loaded_execution_ignores_all_original_bundle_mutation(
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
        expected_body = (project / "fixtures" / "payload.json").read_bytes()
        compile_run_bundle(
            config,
            project_root=project,
            bundle_directory=bundle_directory,
            secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
        )
        loaded = load_replay_bundle(bundle_directory)
        runner = FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
        )
        preparation = runner.prepare_loaded(
            _request(config, project, replay_artifacts),
            loaded,
        )
        other_runner = FullRunRunner(
            journal=JournalLifecycleRepository(),
            executor_factory=_executor_factory,
        )
        with pytest.raises(ValueError, match="different runner instance"):
            await other_runner.run_prepared_loaded(preparation)
        assert not preparation.is_closed

        (bundle_directory / "run-manifest.json").write_bytes(b"{}")
        (bundle_directory / "effective-configuration.json").write_bytes(b"{}")
        for snapshot in loaded.blobs:
            snapshot.path.write_bytes(b"x" * snapshot.byte_length)
        fixture_source = project / "fixtures" / "payload.json"
        fixture_source.unlink()
        attacker_source = project / "fixtures" / "attacker.json"
        attacker_source.write_bytes(b'{"attacker":true}\n')
        if os.name != "nt":
            fixture_source.symlink_to(attacker_source)

        result = await runner.run_prepared_loaded(preparation)

        assert result.result_category is ResultCategory.PASS
        assert receiver.bodies == [expected_body]
        assert preparation.is_closed
        with pytest.raises(ValueError, match="already been consumed"):
            await runner.run_prepared_loaded(preparation)


@pytest.mark.anyio
async def test_prepared_loaded_cancellation_releases_retained_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    bundle_directory = tmp_path / "bundle"
    replay_artifacts = tmp_path / "replays"
    replay_artifacts.mkdir()
    config = _config(
        project,
        8080,
        steps=[{"deliver": {"event": "event"}}],
        assertions=[_status_assertion(expected=[204])],
    )
    compile_run_bundle(
        config,
        project_root=project,
        bundle_directory=bundle_directory,
        secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
    )
    runner = FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_executor_factory,
    )
    preparation = runner.prepare_loaded(
        _request(config, project, replay_artifacts),
        load_replay_bundle(bundle_directory),
    )
    started = anyio.Event()

    async def block_after_claim(*_args: object, **_kwargs: object) -> FullRunResult:
        started.set()
        await anyio.sleep_forever()
        raise AssertionError("unreachable")

    monkeypatch.setattr(FullRunRunner, "_run_prepared", block_after_claim)
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(runner.run_prepared_loaded, preparation)
        await started.wait()
        tasks.cancel_scope.cancel()

    assert preparation.is_closed
    assert preparation._request_bodies is None  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    assert (
        preparation._temporary_directory is None  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    )


@pytest.mark.anyio
async def test_invalid_loaded_source_is_rejected_before_contact_capability(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    bundle_directory = tmp_path / "bundle"
    replay_artifacts = tmp_path / "replays"
    replay_artifacts.mkdir()
    config = _config(
        project,
        8080,
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
    loaded.blobs[0].path.write_bytes(b"x" * loaded.blobs[0].byte_length)
    public_contacts: list[str] = []
    runner = FullRunRunner(
        journal=JournalLifecycleRepository(),
        executor_factory=_executor_factory,
    )

    with pytest.raises(BundleLoadError, match="BLOB_INTEGRITY_ERROR"):
        runner.prepare_loaded(_request(config, project, replay_artifacts), loaded)

    assert public_contacts == []
    assert tuple(replay_artifacts.iterdir()) == ()


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
