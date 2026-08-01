"""Real journal/executor integration for the physical attempt lifecycle."""
# ruff: noqa: ANN202, EM101, INP001, S608, TC003, TRY003

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import anyio
import pytest

from webhook_receiver_conformance.config.models import ReceiverConfig
from webhook_receiver_conformance.domain.enums import AttemptState
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    new_fresh_id,
    validate_fresh_id,
)
from webhook_receiver_conformance.http.evidence import HeaderOwner
from webhook_receiver_conformance.http.executor import (
    HttpAttemptCommand,
    HttpAttemptExecutor,
    HttpHeader,
    HttpProgressError,
    HttpTimeouts,
)
from webhook_receiver_conformance.journal.integrity import verify_resume_integrity
from webhook_receiver_conformance.journal.repositories import (
    AttemptMutationPhase,
    TransitionMutationPhase,
    TransitionRepository,
)
from webhook_receiver_conformance.journal.run_lock import RunLockMetadata
from webhook_receiver_conformance.journal.schema import RunDatabase, create_run_database
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
    StatementOperation,
)
from webhook_receiver_conformance.journal.transitions import (
    AttemptScheduleClaim,
    EntityType,
    StaleOwnerEpochError,
    TransitionCommand,
)
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.policy import parse_destination_policy
from webhook_receiver_conformance.network.transport import (
    ConnectedByteStream,
    ConnectionPlan,
    Connector,
    PeerAddress,
    Resolver,
)
from webhook_receiver_conformance.recovery.models import (
    AttemptRecoveryAction,
    RecoveryScanContext,
)
from webhook_receiver_conformance.recovery.scanner import RecoveryScanner
from webhook_receiver_conformance.runtime.attempts import (
    AttemptLifecycle,
    AttemptRuntimeContext,
)
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
)
from webhook_receiver_conformance.scheduler.retries import (
    ClassifiedPredecessor,
    RetryDecision,
    RetryDisposition,
    RetryPredicate,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

RUN_ID = "00000000-0000-4000-8000-000000000001"
SCENARIO_ID = "scenario_00000000000000000000000001"
EVENT_ID = "event_00000000000000000000000001"
DELIVERY_ID = "delivery_00000000000000000000000001"
ATTEMPT_PLAN_ID = "attempt_plan_00000000000000000000000001"
NEXT_ATTEMPT_PLAN_ID = "attempt_plan_00000000000000000000000002"
OWNER = 7
NOW = "2026-07-27T19:34:56.000000Z"
SECOND = 1_000_000_000
MIN_SAFE_INTEGER = -9_007_199_254_740_991


@dataclass(slots=True)
class _Resolver(Resolver):
    fail: bool = False

    async def resolve(self, host: str, port: int) -> Sequence[str]:
        del host, port
        if self.fail:
            raise OSError("private DNS detail")
        raise AssertionError("literal target must not resolve")


@dataclass(slots=True)
class _Stream(ConnectedByteStream):
    peer: PeerAddress
    response: bytes
    read_delay: float = 0
    write_delay: float = 0
    sent: list[bytes] = field(default_factory=list[bytes])
    closed: bool = False

    @property
    def peer_address(self) -> PeerAddress:
        return self.peer

    async def send(self, item: bytes) -> None:
        if self.write_delay:
            await anyio.sleep(self.write_delay)
        self.sent.append(item)

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        if self.read_delay:
            await anyio.sleep(self.read_delay)
        if not self.response:
            raise anyio.EndOfStream
        result, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return result

    async def send_eof(self) -> None:
        return None

    async def aclose(self) -> None:
        self.closed = True


@dataclass(slots=True)
class _Connector(Connector):
    response: bytes
    fail: bool = False
    connect_delay: float = 0
    read_delay: float = 0
    write_delay: float = 0
    streams: list[_Stream] = field(default_factory=list[_Stream])

    async def connect(self, plan: ConnectionPlan) -> _Stream:
        if self.connect_delay:
            await anyio.sleep(self.connect_delay)
        if self.fail:
            raise OSError("private refusal detail")
        stream = _Stream(
            PeerAddress(plan.pinned_address, plan.port, plan.family),
            self.response,
            read_delay=self.read_delay,
            write_delay=self.write_delay,
        )
        self.streams.append(stream)
        return stream


class _InjectedCrashError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _ResponseRecoveryCase:
    response: bytes
    target: AttemptState
    classification: str
    evidence_state: str
    retry_status: int | None = None


@dataclass(slots=True)
class _CrashOnOccurrence:
    target: TransitionMutationPhase | AttemptMutationPhase
    occurrence: int
    seen: int = 0

    def __call__(self, phase: TransitionMutationPhase | AttemptMutationPhase) -> None:
        if phase is not self.target:
            return
        self.seen += 1
        if self.seen == self.occurrence:
            raise _InjectedCrashError(phase.value)


@dataclass(slots=True)
class _DelayOnOccurrence:
    target: TransitionMutationPhase | AttemptMutationPhase
    occurrence: int
    delay: float
    seen: int = 0

    def __call__(self, phase: TransitionMutationPhase | AttemptMutationPhase) -> None:
        if phase is not self.target:
            return
        self.seen += 1
        if self.seen == self.occurrence:
            time.sleep(self.delay)


def _policy(url: str = "http://127.0.0.1:8443/hook"):
    return parse_destination_policy(
        ReceiverConfig.model_validate(
            {
                "url": url,
                "target_profile": "loopback",
                "allowed_hosts": [],
                "allowed_ports": [8443],
                "timeouts": {
                    "connect": "1s",
                    "write": "1s",
                    "read": "1s",
                    "pool": "1s",
                    "total": "5s",
                },
            }
        )
    )


async def _seed(service: JournalService) -> None:
    digest = f"sha256:{'b' * 64}"
    await service.execute(
        BatchOperation(
            (
                JournalStatement(
                    "INSERT INTO runs (run_id, manifest_id, state, owner_epoch, created_at) "
                    "VALUES (?, ?, 'running', ?, ?)",
                    (RUN_ID, "a" * 64, OWNER, NOW),
                ),
                JournalStatement(
                    "INSERT INTO scenarios (scenario_id, run_id, ordinal, name, state) "
                    "VALUES (?, ?, 0, 'scenario', 'running')",
                    (SCENARIO_ID, RUN_ID),
                ),
                JournalStatement(
                    "INSERT INTO events (event_id, run_id, scenario_id, ordinal, "
                    "event_type, fixture_blob_hash) VALUES (?, ?, ?, 0, 'x', ?)",
                    (EVENT_ID, RUN_ID, SCENARIO_ID, digest),
                ),
                JournalStatement(
                    "INSERT INTO deliveries (delivery_id, run_id, scenario_id, event_id, "
                    "ordinal, step_ordinal, logical_time_ns, state) "
                    "VALUES (?, ?, ?, ?, 0, 0, 0, 'active')",
                    (DELIVERY_ID, RUN_ID, SCENARIO_ID, EVENT_ID),
                ),
                JournalStatement(
                    "INSERT INTO schedule_entries (schedule_entry_id, run_id, scenario_id, "
                    "entity_type, entity_id, logical_time_ns, scenario_ordinal, step_ordinal, "
                    "delivery_ordinal, attempt_ordinal, deterministic_tie_key, idempotency_key) "
                    "VALUES ('initial.schedule', ?, ?, 'attempt', ?, 0, 0, 0, 0, 1, "
                    "'initial.attempt', 'initial.schedule.key')",
                    (RUN_ID, SCENARIO_ID, ATTEMPT_PLAN_ID),
                ),
            )
        )
    )


async def _rows(service: JournalService, sql: str) -> tuple[tuple[object, ...], ...]:
    result = await service.execute(StatementOperation(JournalStatement(sql)))
    return result.rows


def _executor(
    connector: _Connector,
    *,
    short: bool = False,
    resolver: _Resolver | None = None,
    connect_ns: int = SECOND,
    total_ns: int = 5 * SECOND,
) -> HttpAttemptExecutor:
    timeout = 10_000_000 if short else SECOND
    return HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=_Resolver() if resolver is None else resolver,
            connector=connector,
        ),
        timeouts=HttpTimeouts(
            connect_ns=connect_ns,
            write_ns=timeout,
            read_ns=timeout,
            pool_ns=SECOND,
            total_ns=total_ns,
        ),
    )


def _recovery_context(run: RunDatabase) -> RecoveryScanContext:
    return RecoveryScanContext(
        run_id=RUN_ID,
        owner_epoch=OWNER,
        integrity=verify_resume_integrity(run.database_path),
        owner=RunLockMetadata(
            run_id=RUN_ID,
            pid=42,
            process_start_fingerprint="attempt-lifecycle-test",
            hostname="test-host",
            owner_epoch=OWNER,
            wall_timestamp=NOW,
        ),
    )


def _claim(attempt_id: str, clock: RuntimeClock) -> AttemptScheduleClaim:
    transition = TransitionCommand(
        run_id=RUN_ID,
        transition_id=f"claim.{attempt_id}",
        entity_type=EntityType.ATTEMPT,
        entity_id=attempt_id,
        expected_state=AttemptState.SCHEDULED,
        new_state=AttemptState.CLAIMED,
        trigger_category="schedule_claim",
        timestamp=clock.transition_timestamp(),
        owner_epoch=OWNER,
        idempotency_key=f"claim.{attempt_id}.key",
        logical_time_ns=0,
    )
    return AttemptScheduleClaim(
        schedule_entry_id="initial.schedule",
        attempt_id=attempt_id,
        attempt_plan_id=ATTEMPT_PLAN_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        predecessor_attempt_id=None,
        condition_json=None,
        claim_transition=transition,
    )


def _context(
    attempt_id: str,
    *,
    owner_epoch: int = OWNER,
    logical_time_ns: int = 0,
) -> AttemptRuntimeContext:
    return AttemptRuntimeContext(
        RUN_ID,
        SCENARIO_ID,
        EVENT_ID,
        DELIVERY_ID,
        attempt_id,
        owner_epoch,
        logical_time_ns,
        0,
        0,
        0,
        1,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "not-a-run"),
        ("scenario_id", "scenario_bad"),
        ("event_id", "event_bad"),
        ("delivery_id", "delivery_bad"),
        ("attempt_id", ATTEMPT_PLAN_ID),
        ("owner_epoch", -1),
        ("owner_epoch", 2**63),
        ("logical_time_ns", -9_007_199_254_740_992),
        ("logical_time_ns", 9_007_199_254_740_992),
        ("scenario_ordinal", True),
        ("step_ordinal", -1),
        ("delivery_ordinal", 9_007_199_254_740_992),
        ("attempt_ordinal", -1),
    ],
)
def test_runtime_context_rejects_hostile_boundaries(field: str, value: object) -> None:
    values: dict[str, object] = {
        "run_id": RUN_ID,
        "scenario_id": SCENARIO_ID,
        "event_id": EVENT_ID,
        "delivery_id": DELIVERY_ID,
        "attempt_id": new_fresh_id(FreshIdKind.ATTEMPT),
        "owner_epoch": OWNER,
        "logical_time_ns": 0,
        "scenario_ordinal": 0,
        "step_ordinal": 0,
        "delivery_ordinal": 0,
        "attempt_ordinal": 1,
    }
    values[field] = value
    with pytest.raises((TypeError, ValueError)):
        AttemptRuntimeContext(**values)  # pyright: ignore[reportArgumentType]


def test_runtime_context_accepts_signed_safe_logical_time() -> None:
    assert (
        _context(
            new_fresh_id(FreshIdKind.ATTEMPT),
            logical_time_ns=MIN_SAFE_INTEGER,
        ).logical_time_ns
        == MIN_SAFE_INTEGER
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (b"HTTP/1.1 204 No Content\r\n\r\n", "succeeded"),
        (b"HTTP/1.1 422 Nope\r\nContent-Length: 0\r\n\r\n", "rejected"),
    ],
)
async def test_response_lifecycle_is_fully_journaled(
    tmp_path: Path,
    response: bytes,
    expected: str,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        lifecycle = AttemptLifecycle(
            repository=repository,
            executor=_executor(_Connector(response)),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        await lifecycle.claim(_claim(attempt_id, clock))
        result = await lifecycle.execute(
            _context(attempt_id),
            HttpAttemptCommand(policy=_policy(), body=b"secret-canary-body"),
        )
        assert result.terminal_state.value == expected
        assert await _rows(
            service,
            f"SELECT state, phase FROM attempts WHERE attempt_id = '{attempt_id}'",
        ) == ((expected, "response_observed"),)
        evidence_state = "acknowledged" if expected == "succeeded" else "rejected"
        status = 204 if expected == "succeeded" else 422
        records = await _rows(
            service,
            "SELECT record_id, state, response_status, error_category, "
            "request_url_redacted, request_header_names_json "
            "FROM attempt_records",
        )
        record_id = str(records[0][0])
        validate_fresh_id(record_id, expected_kind=FreshIdKind.RECORD)
        assert record_id != f"record_{attempt_id.removeprefix('attempt_')}"
        assert records == (
            (
                record_id,
                evidence_state,
                status,
                None,
                "http://127.0.0.1:8443/[REDACTED]",
                b'["accept-encoding","connection","content-length","host","user-agent"]',
            ),
        )
        assert b"secret-canary-body" not in run.database_path.read_bytes()
    async with JournalService.open(run.database_path) as reopened:
        reopened_repository = TransitionRepository(reopened)
        assert (
            await reopened_repository.attempt_record_id(
                RUN_ID,
                attempt_id,
            )
            == record_id
        )
        persisted = await reopened_repository.attempt_evidence(RUN_ID, attempt_id)
        assert persisted is not None
        assert (
            persisted.response_headers_elapsed_ns
            == result.transport.timings.response_headers_elapsed_ns
        )
        assert persisted.response_headers_elapsed_ns is not None
        assert await _rows(
            reopened,
            "SELECT state, response_status, error_category FROM attempt_records",
        ) == ((evidence_state, status, None),)


@pytest.mark.anyio
async def test_stale_owner_fails_before_network_io(tmp_path: Path) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    connector = _Connector(b"HTTP/1.1 204 No Content\r\n\r\n")
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(service),
            executor=_executor(connector),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        with pytest.raises(
            StaleOwnerEpochError,
            match=r"^transition owner epoch is stale$",
        ):
            await lifecycle.execute(
                _context(attempt_id, owner_epoch=OWNER + 1),
                HttpAttemptCommand(policy=_policy(), body=b"x"),
            )
        assert connector.streams == []


@pytest.mark.anyio
async def test_failure_before_connection_leaves_scanner_classifiable_pre_send(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    connector = _Connector(b"HTTP/1.1 204 No Content\r\n\r\n")
    crash = _CrashOnOccurrence(TransitionMutationPhase.AFTER_APPEND, 3)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(service, crash_hook=crash),
            executor=_executor(connector),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        with pytest.raises(HttpProgressError, match="progress sink failed"):
            await lifecycle.execute(
                _context(attempt_id),
                HttpAttemptCommand(policy=_policy(), body=b"x"),
            )
        assert connector.streams == []
        assert await _rows(service, "SELECT state, phase FROM attempts") == (
            ("pre_send_committed", "controlled_pre_transport"),
        )
        plan = await RecoveryScanner(service, _recovery_context(run)).scan()
        assert len(plan.attempts) == 1
        item = plan.attempts[0]
        assert item.prior_state is AttemptState.PRE_SEND_COMMITTED
        assert item.target_state is AttemptState.NOT_SENT


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("phase", "occurrence"),
    [
        (AttemptMutationPhase.AFTER_PHASE_EVIDENCE, 6),
        (AttemptMutationPhase.AFTER_ATTEMPT_RECORD, 1),
        (TransitionMutationPhase.AFTER_DERIVED_SCHEDULE, 7),
    ],
)
async def test_terminal_failpoints_expose_no_partial_attempt_record(
    tmp_path: Path,
    phase: TransitionMutationPhase | AttemptMutationPhase,
    occurrence: int,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(
                service,
                crash_hook=_CrashOnOccurrence(phase, occurrence),
            ),
            executor=_executor(_Connector(b"HTTP/1.1 204 No Content\r\n\r\n")),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        with pytest.raises(_InjectedCrashError, match=phase.value):
            await lifecycle.execute(
                _context(attempt_id),
                HttpAttemptCommand(
                    policy=_policy(),
                    body=b"secret-canary-response-staging",
                ),
            )
        assert await _rows(service, "SELECT state FROM attempts") == (("response_observed",),)
        assert await _rows(service, "SELECT COUNT(*) FROM attempt_records") == ((0,),)
        assert await _rows(
            service,
            "SELECT COUNT(*) FROM schedule_entries WHERE attempt_ordinal = 2",
        ) == ((0,),)
    async with JournalService.open(run.database_path) as reopened:
        assert await _rows(reopened, "SELECT COUNT(*) FROM attempt_records") == ((0,),)
        plan = await RecoveryScanner(reopened, _recovery_context(run)).scan()
        assert plan.attempts[0].prior_state is AttemptState.RESPONSE_OBSERVED
        assert plan.attempts[0].action is AttemptRecoveryAction.REDUCE_DURABLE_RESPONSE


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case",
    [
        _ResponseRecoveryCase(
            response=b"HTTP/1.1 204 No Content\r\n\r\n",
            target=AttemptState.SUCCEEDED,
            classification="receiver_accepted",
            evidence_state="acknowledged",
        ),
        _ResponseRecoveryCase(
            response=b"HTTP/1.1 503 Retry\r\nContent-Length: 0\r\n\r\n",
            target=AttemptState.REJECTED,
            classification="receiver_rejected",
            evidence_state="rejected",
            retry_status=503,
        ),
    ],
)
async def test_crash_after_durable_response_recovers_exact_result_without_resend(
    tmp_path: Path,
    case: _ResponseRecoveryCase,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    connector = _Connector(case.response)

    def decide(predecessor: ClassifiedPredecessor) -> RetryDecision:
        assert case.retry_status is not None
        assert predecessor.predicate is RetryPredicate.RETRYABLE_STATUS
        assert predecessor.status_code == case.retry_status
        condition = json.dumps(
            {
                "classification": "receiver_rejected",
                "disposition": "scheduled",
                "logical_due_ns": 10,
                "next_attempt_ordinal": 2,
                "predecessor_attempt_id": attempt_id,
                "predecessor_attempt_ordinal": 1,
                "predicate": "retryable_status",
                "status_code": case.retry_status,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return RetryDecision(
            RetryDisposition.SCHEDULED,
            attempt_id,
            1,
            2,
            NEXT_ATTEMPT_PLAN_ID,
            "retry.response.schedule",
            "retry.response.schedule.key",
            10,
            RetryPredicate.RETRYABLE_STATUS,
            condition,
            None,
        )

    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(
                service,
                crash_hook=_CrashOnOccurrence(
                    AttemptMutationPhase.AFTER_PHASE_EVIDENCE,
                    6,
                ),
            ),
            executor=_executor(connector),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        with pytest.raises(
            _InjectedCrashError,
            match=AttemptMutationPhase.AFTER_PHASE_EVIDENCE.value,
        ):
            await lifecycle.execute(
                _context(attempt_id),
                HttpAttemptCommand(policy=_policy(), body=b"x"),
                retry_decider=(decide if case.retry_status is not None else None),
                retryable_status=(
                    (lambda status: status == case.retry_status)
                    if case.retry_status is not None
                    else None
                ),
            )
        assert len(connector.streams) == 1
        assert b"secret-canary-response-staging" not in run.database_path.read_bytes()
        sent_before_recovery = tuple(connector.streams[0].sent)
        assert await _rows(
            service,
            """
            SELECT attempts.state, attempt_response_staging.terminal_state,
                   attempt_response_staging.classification
            FROM attempts
            JOIN attempt_response_staging
              ON attempt_response_staging.attempt_id = attempts.attempt_id
            """,
        ) == (("response_observed", case.target.value, case.classification),)

        scanner = RecoveryScanner(service, _recovery_context(run))
        plan = await scanner.scan()
        assert plan.attempts[0].target_state is case.target
        await scanner.apply(plan, timestamp=clock.transition_timestamp())

        assert len(connector.streams) == 1
        assert tuple(connector.streams[0].sent) == sent_before_recovery
        assert await _rows(
            service,
            "SELECT state, outcome_category FROM attempts",
        ) == ((case.target.value, case.classification),)
        assert await _rows(
            service,
            "SELECT state, classification FROM attempt_records",
        ) == ((case.evidence_state, case.classification),)
        assert await _rows(
            service,
            "SELECT count(*) FROM attempt_response_staging",
        ) == ((0,),)
        assert await _rows(
            service,
            """
            SELECT count(*) FROM schedule_entries
            WHERE attempt_ordinal = 2 AND consumed_at IS NULL
            """,
        ) == ((int(case.retry_status is not None),),)
        assert await _rows(service, "SELECT state FROM deliveries") == (
            ("active" if case.retry_status is not None else "satisfied",),
        )


@pytest.mark.anyio
async def test_cancellation_during_connect_is_recovered_conservatively(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    connector = _Connector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        connect_delay=0.1,
    )
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(service),
            executor=_executor(connector),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        with anyio.move_on_after(0.01) as scope:
            await lifecycle.execute(
                _context(attempt_id),
                HttpAttemptCommand(policy=_policy(), body=b"x"),
            )
        assert scope.cancel_called
        assert connector.streams == []
        persisted = await _rows(service, "SELECT state, phase FROM attempts")
        assert persisted in {
            (("claimed", None),),
            (("pre_send_committed", "controlled_pre_transport"),),
            (("connecting", "connection_attempt_started"),),
        }
        plan = await RecoveryScanner(service, _recovery_context(run)).scan()
        assert plan.attempts[0].prior_state.value == persisted[0][0]
        if persisted[0][0] == "connecting":
            assert plan.attempts[0].target_state is AttemptState.UNKNOWN_OUTCOME
        else:
            assert plan.attempts[0].target_state is not AttemptState.UNKNOWN_OUTCOME


@pytest.mark.anyio
async def test_total_timeout_after_committed_checkpoint_reloads_durable_sending(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    connector = _Connector(b"HTTP/1.1 204 No Content\r\n\r\n")
    delay = _DelayOnOccurrence(
        AttemptMutationPhase.AFTER_PHASE_EVIDENCE,
        occurrence=3,
        delay=2.5,
    )
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(service, crash_hook=delay),
            executor=_executor(connector, total_ns=2 * SECOND),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        result = await lifecycle.execute(
            _context(attempt_id),
            HttpAttemptCommand(policy=_policy(), body=b"x"),
        )
        assert result.transport.error is not None
        assert result.transport.error.code.value == "total_timeout"
        assert result.terminal_state is AttemptState.UNKNOWN_OUTCOME
        assert await _rows(service, "SELECT state, phase FROM attempts") == (
            ("unknown_outcome", "request_send_started"),
        )


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["connection", "dns"])
async def test_preconnection_failure_is_not_sent_and_retry_is_atomic(
    tmp_path: Path,
    failure: str,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)

    def decide(predecessor: ClassifiedPredecessor) -> RetryDecision:
        assert predecessor.predicate is RetryPredicate.CONNECTION_FAILED
        condition = json.dumps(
            {
                "classification": "environment_failure",
                "disposition": "scheduled",
                "logical_due_ns": 10,
                "next_attempt_ordinal": 2,
                "predecessor_attempt_id": attempt_id,
                "predecessor_attempt_ordinal": 1,
                "predicate": "connection_failed",
                "status_code": None,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return RetryDecision(
            RetryDisposition.SCHEDULED,
            attempt_id,
            1,
            2,
            NEXT_ATTEMPT_PLAN_ID,
            "retry.schedule",
            "retry.schedule.key",
            10,
            RetryPredicate.CONNECTION_FAILED,
            condition,
            None,
        )

    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        repository = TransitionRepository(service)
        lifecycle = AttemptLifecycle(
            repository=repository,
            executor=_executor(
                _Connector(b"", fail=failure == "connection"),
                resolver=_Resolver(fail=failure == "dns"),
            ),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        result = await lifecycle.execute(
            _context(attempt_id),
            HttpAttemptCommand(
                policy=_policy(
                    "http://localhost:8443/hook"
                    if failure == "dns"
                    else "http://127.0.0.1:8443/hook"
                ),
                body=b"x",
            ),
            retry_decider=decide,
        )
        assert result.terminal_state is AttemptState.NOT_SENT
        assert await _rows(
            service,
            "SELECT state, phase FROM attempts",
        ) == (("not_sent", "no_connection_established"),)
        error_phase = "resolution" if failure == "dns" else "connect"
        assert await _rows(
            service,
            "SELECT state, response_status, error_category, error_phase FROM attempt_records",
        ) == (("connection_failed", None, "connection_error", error_phase),)
        schedules = await _rows(
            service,
            "SELECT attempt_ordinal, consumed_at FROM schedule_entries ORDER BY attempt_ordinal",
        )
        assert schedules[0][0] == 1
        assert schedules[0][1] is not None
        assert schedules[1] == (2, None)
        with pytest.raises(
            RuntimeError,
            match=r"^attempt execution requires a uniquely claimed attempt$",
        ):
            await lifecycle.execute(
                _context(attempt_id),
                HttpAttemptCommand(policy=_policy(), body=b"x"),
                retry_decider=decide,
            )
        assert await _rows(
            service,
            "SELECT COUNT(*) FROM schedule_entries",
        ) == ((2,),)


@pytest.mark.anyio
async def test_connect_timeout_is_not_sent_with_compatible_connection_evidence(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    connector = _Connector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        connect_delay=0.1,
    )
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(service),
            executor=_executor(connector, connect_ns=10_000_000),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        result = await lifecycle.execute(
            _context(attempt_id),
            HttpAttemptCommand(policy=_policy(), body=b"x"),
        )
        assert result.terminal_state is AttemptState.NOT_SENT
        assert await _rows(
            service,
            "SELECT state, error_category, error_phase FROM attempt_records",
        ) == (("connection_failed", "connect_timeout", "connect"),)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("delay_field", "expected_phase"),
    [("write", "request_send_started"), ("read", "awaiting_response")],
)
async def test_post_connection_timeout_is_unknown(
    tmp_path: Path,
    delay_field: str,
    expected_phase: str,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    connector = _Connector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        write_delay=0.1 if delay_field == "write" else 0,
        read_delay=0.1 if delay_field == "read" else 0,
    )
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(service),
            executor=_executor(connector, short=True),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        result = await lifecycle.execute(
            _context(attempt_id),
            HttpAttemptCommand(policy=_policy(), body=b"x"),
        )
        assert result.terminal_state is AttemptState.UNKNOWN_OUTCOME
        assert await _rows(service, "SELECT state, phase FROM attempts") == (
            ("unknown_outcome", expected_phase),
        )
        expected_error = "write_timeout" if delay_field == "write" else "read_timeout"
        expected_error_phase = "write" if delay_field == "write" else "response_headers"
        assert await _rows(
            service,
            "SELECT state, error_category, error_phase FROM attempt_records",
        ) == (("unknown_outcome", expected_error, expected_error_phase),)


@pytest.mark.anyio
async def test_incomplete_response_body_is_unknown_not_response_observed(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nxy"
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(service),
            executor=_executor(_Connector(response)),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        result = await lifecycle.execute(
            _context(attempt_id),
            HttpAttemptCommand(policy=_policy(), body=b"x"),
        )
        assert result.transport.response is not None
        assert result.transport.response.body_complete is False
        assert result.terminal_state is AttemptState.UNKNOWN_OUTCOME
        assert await _rows(service, "SELECT state, phase FROM attempts") == (
            ("unknown_outcome", "awaiting_response"),
        )
        assert await _rows(
            service,
            "SELECT COUNT(*) FROM transitions WHERE to_state = 'response_observed'",
        ) == ((0,),)


@pytest.mark.anyio
async def test_header_digest_preserves_order_duplicates_and_owner_without_values(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    clock = RuntimeClock(ClockPolicy(ClockMode.REAL))
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    headers = (
        HttpHeader("X-First", "duplicate-secret", HeaderOwner.USER),
        HttpHeader("X-Second", "second-secret", HeaderOwner.SIGNER),
        HttpHeader("X-Third", "duplicate-secret", HeaderOwner.USER),
    )
    command = HttpAttemptCommand(policy=_policy(), body=b"x", headers=headers)
    expected = hashlib.sha256()
    for name, value, owner in (
        ("X-First", "duplicate-secret", "user"),
        ("X-Second", "second-secret", "signer"),
        ("X-Third", "duplicate-secret", "user"),
    ):
        for component in (name.encode(), value.encode(), owner.encode()):
            expected.update(len(component).to_bytes(4, "big"))
            expected.update(component)
    expected_digest = f"sha256:{expected.hexdigest()}"

    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        lifecycle = AttemptLifecycle(
            repository=TransitionRepository(service),
            executor=_executor(_Connector(b"HTTP/1.1 204 No Content\r\n\r\n")),
            clock=clock,
        )
        await lifecycle.claim(_claim(attempt_id, clock))
        await lifecycle.execute(
            _context(attempt_id),
            command,
        )
        assert await _rows(
            service,
            "SELECT request_headers_hash FROM attempts",
        ) == ((expected_digest,),)
        assert "duplicate-secret" not in repr(command)
        assert "second-secret" not in repr(command)
        database = run.database_path.read_bytes()
        assert b"duplicate-secret" not in database
        assert b"second-secret" not in database
