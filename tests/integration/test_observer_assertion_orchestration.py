"""Focused integration coverage for observer/assertion scenario orchestration."""
# ruff: noqa: EM101, INP001, PLR2004, TRY003

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

import pytest

from webhook_receiver_conformance.config.models import (
    ProcessingCountAssertion,
    ResourceFieldAssertion,
)
from webhook_receiver_conformance.domain.enums import AssertionState, EvidenceValueType
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.journal.repositories import (
    AssertionRepository,
    ObservationRepository,
)
from webhook_receiver_conformance.journal.schema import create_run_database
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
    StatementOperation,
)
from webhook_receiver_conformance.observers.protocol import (
    BuiltinObserverKind,
    ObserverCapabilities,
    ObserverEvidence,
    ObserverOperation,
    ObserverRequest,
    ObserverResponse,
    ObserverResponseStatus,
)
from webhook_receiver_conformance.runtime.assertions import AssertionRuntimeContext
from webhook_receiver_conformance.runtime.observer_assertions import (
    ScenarioObserverAssertion,
    ScenarioObserverAssertionRuntime,
)
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
)

if TYPE_CHECKING:
    from pathlib import Path

    from webhook_receiver_conformance.domain.identifiers import FreshIdKind

RUN_ID = "00000000-0000-4000-8000-000000000903"
SCENARIO_ID = f"scenario_{1:026d}"
EVENT_ID = f"event_{1:026d}"
COUNT_ASSERTION_ID = f"assertion_{1:026d}"
FIELD_ASSERTION_ID = f"assertion_{2:026d}"
COUNT_OBSERVATION_ID = f"observation_{1:026d}"
FIELD_OBSERVATION_ID = f"observation_{2:026d}"
OWNER_EPOCH = 4
WALL_TIME = datetime(2026, 7, 27, 20, 0, tzinfo=UTC)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _FreshIds:
    ordinal: int = 100

    def __call__(self, kind: FreshIdKind) -> str:
        self.ordinal += 1
        return f"{kind.value}_{self.ordinal:026d}"


@dataclass
class _RequestIds:
    ordinal: int = 0

    def __call__(self) -> str:
        self.ordinal += 1
        return f"request_{self.ordinal:026d}"


class _Observer:
    BUILTIN_KIND: ClassVar[BuiltinObserverKind] = BuiltinObserverKind.COMMAND
    _timeout_ns = 1_000_000_000

    def __init__(self) -> None:
        self.operations: list[ObserverOperation] = []
        self.capabilities = ObserverCapabilities(
            evidence_types=(EvidenceValueType.INTEGER,),
            evidence_keys=("processing_count",),
            read_only=True,
            idempotent=True,
            supports_pending=True,
            stable_snapshot_ids=True,
        )

    async def invoke(self, request: ObserverRequest) -> ObserverResponse:
        self.operations.append(request.operation)
        if request.operation is ObserverOperation.CAPABILITIES:
            return ObserverResponse(
                protocol_version="1.0",
                request_id=request.request_id,
                status=ObserverResponseStatus.OK,
                capabilities=self.capabilities,
                snapshot_id="capabilities-1",
                evidence=(),
                error=None,
            )
        assert tuple(query.key for query in request.queries) == ("processing_count",)
        return ObserverResponse(
            protocol_version="1.0",
            request_id=request.request_id,
            status=ObserverResponseStatus.OK,
            capabilities=self.capabilities,
            snapshot_id="state-1",
            evidence=(
                ObserverEvidence(
                    key="processing_count",
                    value_type=EvidenceValueType.INTEGER,
                    value=1,
                ),
            ),
            error=None,
        )


class _HandshakeFailureObserver:
    BUILTIN_KIND: ClassVar[BuiltinObserverKind] = BuiltinObserverKind.COMMAND

    async def invoke(self, request: ObserverRequest) -> ObserverResponse:
        del request
        raise RuntimeError("capability adapter failure")


def _clock() -> RuntimeClock:
    return RuntimeClock(
        ClockPolicy(ClockMode.REAL),
        wall_now=lambda: WALL_TIME,
        monotonic_now=lambda: 1_000_000_000,
    )


def _count_assertion() -> ProcessingCountAssertion:
    return ProcessingCountAssertion.model_validate(
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
    )


def _unsupported_assertion() -> ResourceFieldAssertion:
    return ResourceFieldAssertion.model_validate(
        {
            "id": "resource_field",
            "type": "resource-field",
            "query": {
                "observer": "receiver_state",
                "key": "resource",
                "parameters": {},
            },
            "path": "/state",
            "comparator": "eq",
            "expected": {"value_type": "string", "value": "processed"},
            "on_unsupported": "skip",
        }
    )


async def _seed(service: JournalService) -> None:
    await service.execute(
        BatchOperation(
            (
                JournalStatement(
                    """
                    INSERT INTO runs (
                        run_id, manifest_id, state, owner_epoch, created_at
                    ) VALUES (?, ?, 'running', ?, ?)
                    """,
                    (
                        RUN_ID,
                        "a" * 64,
                        OWNER_EPOCH,
                        "2026-07-27T20:00:00.000000Z",
                    ),
                ),
                JournalStatement(
                    """
                    INSERT INTO scenarios (
                        scenario_id, run_id, ordinal, name, state
                    ) VALUES (?, ?, 0, 'scenario', 'running')
                    """,
                    (SCENARIO_ID, RUN_ID),
                ),
                JournalStatement(
                    """
                    INSERT INTO events (
                        event_id, run_id, scenario_id, ordinal,
                        event_type, fixture_blob_hash
                    ) VALUES (?, ?, ?, 0, 'event', ?)
                    """,
                    (EVENT_ID, RUN_ID, SCENARIO_ID, f"sha256:{'b' * 64}"),
                ),
                JournalStatement(
                    """
                    INSERT INTO assertions (
                        assertion_id, run_id, scenario_id, type,
                        policy_json, required, state
                    ) VALUES (?, ?, ?, 'processing-count', NULL, 1, 'pending')
                    """,
                    (COUNT_ASSERTION_ID, RUN_ID, SCENARIO_ID),
                ),
                JournalStatement(
                    """
                    INSERT INTO assertions (
                        assertion_id, run_id, scenario_id, type,
                        policy_json, required, state
                    ) VALUES (
                        ?, ?, ?, 'resource-field',
                        ?, 1, 'pending'
                    )
                    """,
                    (
                        FIELD_ASSERTION_ID,
                        RUN_ID,
                        SCENARIO_ID,
                        b'{"on_unsupported":"skip"}',
                    ),
                ),
            )
        )
    )


def _planned(
    assertion_id: str,
    observation_id: str,
    assertion: ProcessingCountAssertion | ResourceFieldAssertion,
    *,
    checkpoint: str = "after-delivery",
) -> ScenarioObserverAssertion:
    return ScenarioObserverAssertion(
        context=AssertionRuntimeContext(
            run_id=RUN_ID,
            scenario_id=SCENARIO_ID,
            assertion_id=assertion_id,
            owner_epoch=OWNER_EPOCH,
        ),
        assertion=assertion,
        observation_id=observation_id,
        checkpoint=checkpoint,
        event_id=EVENT_ID,
    )


@pytest.mark.anyio
async def test_scenario_runtime_persists_samples_evaluations_and_unsupported_policy(
    tmp_path: Path,
) -> None:
    observer = _Observer()
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        runtime = ScenarioObserverAssertionRuntime(
            observers={"receiver_state": observer},
            invocation_timeouts_ns={"receiver_state": 1_000_000_000},
            observation_repository=ObservationRepository(service),
            assertion_repository=AssertionRepository(service),
            clock=_clock(),
            owner_epoch=OWNER_EPOCH,
            fresh_id=_FreshIds(),
            request_id=_RequestIds(),
        )
        result = await runtime.run(
            (
                _planned(
                    COUNT_ASSERTION_ID,
                    COUNT_OBSERVATION_ID,
                    _count_assertion(),
                ),
                _planned(
                    FIELD_ASSERTION_ID,
                    FIELD_OBSERVATION_ID,
                    _unsupported_assertion(),
                    checkpoint="after-unsupported-check",
                ),
            )
        )

        assert observer.operations == [
            ObserverOperation.CAPABILITIES,
            ObserverOperation.OBSERVE,
        ]
        assert len(result.results) == 2
        assert result.results[0].assertion.normalized.state is AssertionState.PASSED
        assert result.results[0].verdict.category is ResultCategory.PASS
        assert result.results[1].assertion.normalized.state is AssertionState.UNSUPPORTED
        assert result.results[1].assertion.committed.evaluation.result.value == "skipped"
        assert result.results[1].verdict.category is ResultCategory.UNSUPPORTED
        assert tuple(item.observations[0].status.value for item in result.results) == (
            "ok",
            "unsupported",
        )

        rows = await service.execute(
            StatementOperation(
                JournalStatement(
                    """
                    SELECT assertion_id, state
                    FROM assertions
                    ORDER BY assertion_id
                    """
                )
            )
        )
        assert rows.rows == (
            (COUNT_ASSERTION_ID, "passed"),
            (FIELD_ASSERTION_ID, "unsupported"),
        )
        links = await service.execute(
            StatementOperation(
                JournalStatement(
                    """
                    SELECT evidence_kind, evidence_id
                    FROM evidence_links
                    ORDER BY evaluation_id
                    """
                )
            )
        )
        assert len(links.rows) == 2
        assert all(row[0] == "observation" for row in links.rows)


@pytest.mark.anyio
async def test_capability_handshake_failure_still_commits_error_sample_and_assertion(
    tmp_path: Path,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service)
        runtime = ScenarioObserverAssertionRuntime(
            observers={"receiver_state": _HandshakeFailureObserver()},
            invocation_timeouts_ns={"receiver_state": 1_000_000_000},
            observation_repository=ObservationRepository(service),
            assertion_repository=AssertionRepository(service),
            clock=_clock(),
            owner_epoch=OWNER_EPOCH,
            fresh_id=_FreshIds(),
            request_id=_RequestIds(),
        )

        result = await runtime.run(
            (
                _planned(
                    COUNT_ASSERTION_ID,
                    COUNT_OBSERVATION_ID,
                    _count_assertion(),
                ),
            )
        )

        committed = result.results[0]
        assert committed.observations[0].status.value == "error"
        assert committed.assertion.normalized.state is AssertionState.ERROR
        assert committed.verdict.category is ResultCategory.ENVIRONMENT_ERROR
