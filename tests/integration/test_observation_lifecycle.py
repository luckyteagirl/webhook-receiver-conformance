"""Observation polling, persistence, timeout, privacy, and replay integration."""
# ruff: noqa: INP001, PLR0913, PLR2004, S105

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

import anyio
import pytest
from anyio import lowlevel as anyio_lowlevel

from webhook_receiver_conformance.domain.enums import EvidenceValueType, ObservationState
from webhook_receiver_conformance.journal.repositories import (
    AttemptMutationPhase,
    ObservationMutationPhase,
    ObservationRepository,
    TransitionMutationPhase,
)
from webhook_receiver_conformance.journal.schema import RunDatabase, create_run_database
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
    StatementOperation,
)
from webhook_receiver_conformance.observers.polling import (
    MINIMUM_POLL_INTERVAL_NS,
    ObservationPollOutcome,
    ObservationPollPlan,
)
from webhook_receiver_conformance.observers.protocol import (
    BuiltinObserverKind,
    ObserverCapabilities,
    ObserverEvidence,
    ObserverOperation,
    ObserverQuery,
    ObserverRequest,
    ObserverResponse,
    ObserverResponseStatus,
    ObserverWireError,
)
from webhook_receiver_conformance.runtime.observations import (
    ObservationRuntime,
    SqliteObservationJournal,
)
from webhook_receiver_conformance.scheduler.clocks import ClockMode, ClockPolicy, RuntimeClock

if TYPE_CHECKING:
    from pathlib import Path

    from webhook_receiver_conformance.domain.identifiers import FreshIdKind

RUN_ID = "00000000-0000-4000-8000-000000000504"
MANIFEST_ID = "a" * 64
SCENARIO_ID = f"scenario_{1:026d}"
EVENT_ID = f"event_{1:026d}"
OBSERVATION_ID = f"observation_{1:026d}"
REQUEST_ID = f"request_{1:026d}"
FIXTURE_HASH = f"sha256:{'b' * 64}"
WALL_TEXT = "2026-07-27T20:00:00.000000Z"
SECRET_CANARY = "observer-secret-canary-must-not-persist"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _int_list() -> list[int]:
    return []


def _request_list() -> list[ObserverRequest]:
    return []


@dataclass
class _FakeTime:
    now_ns: int = 1_000_000_000
    sleeps_ns: list[int] = field(default_factory=_int_list)

    def monotonic_now(self) -> int:
        return self.now_ns

    async def sleep(self, seconds: float) -> None:
        duration = round(seconds * 1_000_000_000)
        self.sleeps_ns.append(duration)
        self.now_ns += duration
        await anyio_lowlevel.checkpoint()


@dataclass
class _FreshFactory:
    ordinal: int = 100

    def __call__(self, kind: FreshIdKind) -> str:
        self.ordinal += 1
        return f"{kind.value}_{self.ordinal:026d}"


class _InjectedCrashError(RuntimeError):
    pass


@dataclass(frozen=True)
class _CrashAt:
    target: TransitionMutationPhase | AttemptMutationPhase | ObservationMutationPhase

    def __call__(
        self,
        phase: TransitionMutationPhase | AttemptMutationPhase | ObservationMutationPhase,
    ) -> None:
        if phase is self.target:
            raise _InjectedCrashError(phase.value)


@dataclass
class _SequenceObserver:
    outcomes: tuple[ObserverResponse | Exception | None, ...]
    calls: list[ObserverRequest] = field(default_factory=_request_list)
    index: int = 0

    BUILTIN_KIND: ClassVar[BuiltinObserverKind] = BuiltinObserverKind.COMMAND

    async def invoke(self, request: ObserverRequest) -> ObserverResponse:
        self.calls.append(request)
        selected = self.outcomes[min(self.index, len(self.outcomes) - 1)]
        self.index += 1
        if selected is None:
            await anyio.sleep_forever()
            raise AssertionError
        if isinstance(selected, Exception):
            raise selected
        return selected


def _capabilities(
    *,
    read_only: bool = True,
    idempotent: bool = True,
    supports_pending: bool = True,
) -> ObserverCapabilities:
    return ObserverCapabilities(
        evidence_types=(EvidenceValueType.INTEGER, EvidenceValueType.STRING),
        evidence_keys=("processing_count", "secret_value"),
        read_only=read_only,
        idempotent=idempotent,
        max_queries=64,
        supports_pending=supports_pending,
        stable_snapshot_ids=True,
    )


def _response(
    status: ObserverResponseStatus,
    *,
    capabilities: ObserverCapabilities,
    value: int = 1,
    retryable: bool = False,
    error_message: str = "observer detail",
    sensitive_secret: bool = False,
) -> ObserverResponse:
    if status is ObserverResponseStatus.OK:
        evidence = [
            ObserverEvidence(
                key="processing_count",
                value_type=EvidenceValueType.INTEGER,
                value=value,
                sensitive=False,
            )
        ]
        if sensitive_secret:
            evidence.append(
                ObserverEvidence(
                    key="secret_value",
                    value_type=EvidenceValueType.STRING,
                    value=SECRET_CANARY,
                    sensitive=True,
                )
            )
        return ObserverResponse(
            protocol_version="1.0",
            request_id=REQUEST_ID,
            status=status,
            capabilities=capabilities,
            snapshot_id=f"snapshot-{value}",
            evidence=tuple(evidence),
            error=None,
        )
    error = (
        ObserverWireError(
            category="receiver_unavailable",
            message=error_message,
            retryable=retryable,
        )
        if status is ObserverResponseStatus.ERROR
        else None
    )
    return ObserverResponse(
        protocol_version="1.0",
        request_id=REQUEST_ID,
        status=status,
        capabilities=capabilities,
        snapshot_id=None,
        evidence=(),
        error=error,
    )


def _plan(
    capabilities: ObserverCapabilities,
    *,
    within_ns: int = 30_000_000,
    poll_interval_ns: int = MINIMUM_POLL_INTERVAL_NS,
    invocation_timeout_ns: int = 20_000_000,
    include_secret_query: bool = False,
) -> ObservationPollPlan:
    queries = [
        ObserverQuery(
            key="processing_count",
            type=EvidenceValueType.INTEGER,
            parameters={},
        )
    ]
    if include_secret_query:
        queries.append(
            ObserverQuery(
                key="secret_value",
                type=EvidenceValueType.STRING,
                parameters={},
            )
        )
    return ObservationPollPlan(
        observation_id=OBSERVATION_ID,
        observer_id="receiver-probe",
        request=ObserverRequest(
            protocol_version="1.0",
            request_id=REQUEST_ID,
            operation=ObserverOperation.OBSERVE,
            sample_id=f"sample_{1:026d}",
            run_id=RUN_ID,
            scenario_id=SCENARIO_ID,
            event_id=EVENT_ID,
            checkpoint="after-delivery",
            queries=tuple(queries),
        ),
        capabilities=capabilities,
        within_ns=within_ns,
        poll_interval_ns=poll_interval_ns,
        invocation_timeout_ns=invocation_timeout_ns,
        requires_stable_snapshot=True,
    )


def _clock(fake: _FakeTime) -> RuntimeClock:
    return RuntimeClock(
        ClockPolicy(mode=ClockMode.REAL),
        wall_now=lambda: datetime(2026, 7, 27, 20, 0, tzinfo=UTC),
        monotonic_now=fake.monotonic_now,
        sleep=fake.sleep,
    )


async def _database(root: Path) -> RunDatabase:
    run = create_run_database(root, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await service.execute(
            BatchOperation(
                (
                    JournalStatement(
                        """
                        INSERT INTO runs (
                            run_id, manifest_id, state, owner_epoch, created_at
                        ) VALUES (?, ?, 'running', 1, ?)
                        """,
                        (RUN_ID, MANIFEST_ID, WALL_TEXT),
                    ),
                    JournalStatement(
                        """
                        INSERT INTO scenarios (
                            scenario_id, run_id, ordinal, name, state
                        ) VALUES (?, ?, 0, 'observation', 'running')
                        """,
                        (SCENARIO_ID, RUN_ID),
                    ),
                    JournalStatement(
                        """
                        INSERT INTO events (
                            event_id, run_id, scenario_id, ordinal,
                            event_type, fixture_blob_hash
                        ) VALUES (?, ?, ?, 0, 'fixture.created', ?)
                        """,
                        (EVENT_ID, RUN_ID, SCENARIO_ID, FIXTURE_HASH),
                    ),
                )
            )
        )
    return run


async def _rows(
    service: JournalService,
    sql: str,
    parameters: tuple[object, ...] = (),
) -> tuple[tuple[object, ...], ...]:
    result = await service.execute(
        StatementOperation(
            JournalStatement(sql, parameters),  # type: ignore[arg-type]
        )
    )
    return result.rows


@pytest.mark.anyio
async def test_pending_then_ok_preserves_request_id_and_journals_fresh_samples(
    tmp_path: Path,
) -> None:
    run = await _database(tmp_path)
    capabilities = _capabilities()
    observer = _SequenceObserver(
        (
            _response(ObserverResponseStatus.PENDING, capabilities=capabilities),
            _response(ObserverResponseStatus.OK, capabilities=capabilities, value=2),
        )
    )
    fake = _FakeTime()
    plan = _plan(capabilities)

    async with JournalService.open(run.database_path) as service:
        repository = ObservationRepository(service)
        runtime = ObservationRuntime(
            observer=observer,
            repository=repository,
            clock=_clock(fake),
            owner_epoch=1,
            fresh_id=_FreshFactory(),
        )
        result = await runtime.poll(
            plan,
            lambda response: response.evidence[0].typed_value == 2,
        )
        records = await runtime.samples(plan)

        assert result.outcome is ObservationPollOutcome.MATCHED
        assert result.final_state is ObservationState.OK
        assert result.sample_ids == tuple(record.sample_id for record in records)
        assert tuple(request.request_id for request in observer.calls) == (
            REQUEST_ID,
            REQUEST_ID,
        )
        assert observer.calls[0].sample_id != observer.calls[1].sample_id
        assert tuple(record.status.value for record in records) == ("pending", "ok")
        assert fake.sleeps_ns == [MINIMUM_POLL_INTERVAL_NS]
        assert await _rows(
            service,
            "SELECT state FROM observer_series WHERE observation_id = ?",
            (OBSERVATION_ID,),
        ) == ((ObservationState.OK.value,),)


@pytest.mark.anyio
async def test_capability_mismatch_is_persisted_unsupported_before_invocation(
    tmp_path: Path,
) -> None:
    run = await _database(tmp_path)
    capabilities = ObserverCapabilities(
        evidence_types=(EvidenceValueType.STRING,),
        evidence_keys=("secret_value",),
        read_only=True,
        idempotent=True,
        max_queries=64,
        supports_pending=True,
        stable_snapshot_ids=True,
    )
    observer = _SequenceObserver(
        (_response(ObserverResponseStatus.PENDING, capabilities=capabilities),)
    )
    plan = _plan(capabilities)
    async with JournalService.open(run.database_path) as service:
        runtime = ObservationRuntime(
            observer=observer,
            repository=ObservationRepository(service),
            clock=_clock(_FakeTime()),
            owner_epoch=1,
            fresh_id=_FreshFactory(),
        )
        result = await runtime.poll(plan, lambda _response: False)
        records = await runtime.samples(plan)
    assert result.outcome is ObservationPollOutcome.UNSUPPORTED
    assert result.final_state is ObservationState.UNSUPPORTED
    assert not observer.calls
    assert tuple(record.status.value for record in records) == ("unsupported",)


@pytest.mark.anyio
async def test_pending_samples_become_timed_out_at_deadline_without_busy_loop(
    tmp_path: Path,
) -> None:
    run = await _database(tmp_path)
    capabilities = _capabilities()
    observer = _SequenceObserver(
        (_response(ObserverResponseStatus.PENDING, capabilities=capabilities),)
    )
    fake = _FakeTime()
    plan = _plan(
        capabilities,
        within_ns=20_000_000,
        poll_interval_ns=MINIMUM_POLL_INTERVAL_NS,
    )

    async with JournalService.open(run.database_path) as service:
        runtime = ObservationRuntime(
            observer=observer,
            repository=ObservationRepository(service),
            clock=_clock(fake),
            owner_epoch=1,
            fresh_id=_FreshFactory(),
        )
        result = await runtime.poll(plan, lambda _response: False)
        records = await runtime.samples(plan)

    assert result.outcome is ObservationPollOutcome.TIMED_OUT
    assert result.deadline_elapsed
    assert len(observer.calls) == 2
    assert tuple(record.status.value for record in records) == (
        "pending",
        "pending",
        "timeout",
    )
    assert fake.sleeps_ns == [MINIMUM_POLL_INTERVAL_NS, MINIMUM_POLL_INTERVAL_NS]


@pytest.mark.anyio
async def test_non_read_only_pending_and_non_idempotent_error_are_never_retried(
    tmp_path: Path,
) -> None:
    for suffix, capabilities, response, expected in (
        (
            "pending",
            _capabilities(read_only=False),
            ObserverResponseStatus.PENDING,
            ObservationPollOutcome.PENDING,
        ),
        (
            "error",
            _capabilities(idempotent=False),
            ObserverResponseStatus.ERROR,
            ObservationPollOutcome.ERROR,
        ),
    ):
        root = tmp_path / suffix
        run = await _database(root)
        observer = _SequenceObserver(
            (
                _response(
                    response,
                    capabilities=capabilities,
                    retryable=True,
                    error_message=SECRET_CANARY,
                ),
            )
        )
        async with JournalService.open(run.database_path) as service:
            runtime = ObservationRuntime(
                observer=observer,
                repository=ObservationRepository(service),
                clock=_clock(_FakeTime()),
                owner_epoch=1,
                fresh_id=_FreshFactory(),
            )
            result = await runtime.poll(_plan(capabilities), lambda _response: False)
        assert result.outcome is expected
        assert len(observer.calls) == 1
        assert SECRET_CANARY.encode() not in run.database_path.read_bytes()


@pytest.mark.anyio
async def test_hanging_observer_is_terminated_and_persisted_as_timeout(
    tmp_path: Path,
) -> None:
    run = await _database(tmp_path)
    capabilities = _capabilities()
    observer = _SequenceObserver((None,))
    plan = _plan(
        capabilities,
        within_ns=100_000_000,
        invocation_timeout_ns=10_000_000,
    )
    async with JournalService.open(run.database_path) as service:
        runtime = ObservationRuntime(
            observer=observer,
            repository=ObservationRepository(service),
            clock=_clock(_FakeTime()),
            owner_epoch=1,
            fresh_id=_FreshFactory(),
        )
        result = await runtime.poll(plan, lambda _response: False)
        records = await runtime.samples(plan)
    assert result.outcome is ObservationPollOutcome.TIMED_OUT
    assert len(observer.calls) == 1
    assert tuple(record.status.value for record in records) == ("timeout",)


@pytest.mark.anyio
async def test_outer_cancellation_is_persisted_and_no_observer_task_survives(
    tmp_path: Path,
) -> None:
    run = await _database(tmp_path)
    capabilities = _capabilities()
    observer = _SequenceObserver((None,))
    plan = _plan(
        capabilities,
        within_ns=2_000_000_000,
        invocation_timeout_ns=1_000_000_000,
    )
    cancelled = anyio.Event()
    async with JournalService.open(run.database_path) as service:
        runtime = ObservationRuntime(
            observer=observer,
            repository=ObservationRepository(service),
            clock=_clock(_FakeTime()),
            owner_epoch=1,
            fresh_id=_FreshFactory(),
        )

        async def invoke() -> None:
            try:
                await runtime.poll(plan, lambda _response: False)
            except anyio.get_cancelled_exc_class():
                cancelled.set()
                raise

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(invoke)
            await anyio.sleep(0.02)
            tasks.cancel_scope.cancel()

        assert cancelled.is_set()
        assert await _rows(
            service,
            "SELECT state FROM observer_series WHERE observation_id = ?",
            (OBSERVATION_ID,),
        ) == ((ObservationState.CANCELLED.value,),)
        assert tuple(record.status.value for record in await runtime.samples(plan)) == ("error",)


@pytest.mark.anyio
async def test_sensitive_evidence_is_available_in_memory_but_absent_from_sqlite(
    tmp_path: Path,
) -> None:
    run = await _database(tmp_path)
    capabilities = _capabilities()
    observer = _SequenceObserver(
        (
            _response(
                ObserverResponseStatus.OK,
                capabilities=capabilities,
                sensitive_secret=True,
            ),
        )
    )
    observed_secret = False

    def predicate(response: ObserverResponse) -> bool:
        nonlocal observed_secret
        observed_secret = response.evidence[1].typed_value == SECRET_CANARY
        return observed_secret

    async with JournalService.open(run.database_path) as service:
        plan = _plan(capabilities, include_secret_query=True)
        runtime = ObservationRuntime(
            observer=observer,
            repository=ObservationRepository(service),
            clock=_clock(_FakeTime()),
            owner_epoch=1,
            fresh_id=_FreshFactory(),
        )
        result = await runtime.poll(plan, predicate)
        records = await runtime.samples(plan)
        assert result.sample_ids == tuple(record.sample_id for record in records)
        assert tuple(item.key for item in records[0].evidence) == ("processing_count",)

    assert observed_secret
    assert SECRET_CANARY.encode() not in run.database_path.read_bytes()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "phase",
    [
        ObservationMutationPhase.AFTER_SAMPLE_INSERT,
        TransitionMutationPhase.AFTER_APPEND,
        TransitionMutationPhase.AFTER_PROJECTION,
        TransitionMutationPhase.AFTER_DERIVED_SCHEDULE,
    ],
)
async def test_terminal_sample_and_state_roll_back_at_every_atomic_boundary(
    tmp_path: Path,
    phase: TransitionMutationPhase | ObservationMutationPhase,
) -> None:
    run = await _database(tmp_path)
    capabilities = _capabilities()
    plan = _plan(capabilities)
    async with JournalService.open(run.database_path) as service:
        normal_repository = ObservationRepository(service)
        normal_clock = _clock(_FakeTime())
        await SqliteObservationJournal(
            normal_repository,
            owner_epoch=1,
        ).begin_series(plan, normal_clock.transition_timestamp())

        crashing = ObservationRuntime(
            observer=_SequenceObserver(
                (
                    _response(
                        ObserverResponseStatus.OK,
                        capabilities=capabilities,
                    ),
                )
            ),
            repository=ObservationRepository(
                service,
                crash_hook=_CrashAt(phase),
            ),
            clock=_clock(_FakeTime()),
            owner_epoch=1,
            fresh_id=_FreshFactory(),
        )
        with pytest.raises(_InjectedCrashError, match=phase.value):
            await crashing.poll(plan, lambda _response: True)

        assert await _rows(
            service,
            "SELECT state FROM observer_series WHERE observation_id = ?",
            (OBSERVATION_ID,),
        ) == ((ObservationState.RUNNING.value,),)
        assert await _rows(
            service,
            "SELECT count(*) FROM observation_samples WHERE observation_id = ?",
            (OBSERVATION_ID,),
        ) == ((0,),)

        recovered = ObservationRuntime(
            observer=_SequenceObserver(
                (
                    _response(
                        ObserverResponseStatus.OK,
                        capabilities=capabilities,
                    ),
                )
            ),
            repository=normal_repository,
            clock=_clock(_FakeTime()),
            owner_epoch=1,
            fresh_id=_FreshFactory(),
        )
        assert (await recovered.poll(plan, lambda _response: True)).outcome is (
            ObservationPollOutcome.MATCHED
        )
        assert len(await recovered.samples(plan)) == 1


@pytest.mark.anyio
async def test_series_creation_crash_exposes_no_partial_identity_or_transition(
    tmp_path: Path,
) -> None:
    run = await _database(tmp_path)
    capabilities = _capabilities()
    plan = _plan(capabilities)
    async with JournalService.open(run.database_path) as service:
        runtime = ObservationRuntime(
            observer=_SequenceObserver(
                (
                    _response(
                        ObserverResponseStatus.OK,
                        capabilities=capabilities,
                    ),
                )
            ),
            repository=ObservationRepository(
                service,
                crash_hook=_CrashAt(ObservationMutationPhase.AFTER_SERIES_INSERT),
            ),
            clock=_clock(_FakeTime()),
            owner_epoch=1,
            fresh_id=_FreshFactory(),
        )
        with pytest.raises(_InjectedCrashError, match="after_series_insert"):
            await runtime.poll(plan, lambda _response: True)
        assert await _rows(
            service,
            "SELECT count(*) FROM observer_series WHERE run_id = ?",
            (RUN_ID,),
        ) == ((0,),)
        assert await _rows(
            service,
            "SELECT count(*) FROM transitions WHERE run_id = ?",
            (RUN_ID,),
        ) == ((0,),)


@pytest.mark.parametrize("poll_interval_ns", [0, MINIMUM_POLL_INTERVAL_NS - 1, 30_000_001])
def test_invalid_poll_interval_fails_before_observer_or_journal(
    poll_interval_ns: int,
) -> None:
    with pytest.raises(ValueError, match="polling interval"):
        _plan(
            _capabilities(),
            within_ns=30_000_000,
            poll_interval_ns=poll_interval_ns,
        )
