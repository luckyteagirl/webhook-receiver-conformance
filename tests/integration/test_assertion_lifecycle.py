"""Assertion lifecycle, evidence separation, verdict, and crash integration."""
# ruff: noqa: EM101, INP001, PLR2004, S105, TRY003

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

import pytest

from webhook_receiver_conformance.config.models import (
    EventualStateAssertion,
    HttpStatusAssertion,
    ProcessingCountAssertion,
    ResourceFieldAssertion,
)
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    AttemptClassification,
    AttemptEvidenceState,
    EvidenceValueType,
    ObservationState,
    RunState,
)
from webhook_receiver_conformance.domain.models import (
    AttemptEvidence,
    ResponseMetadata,
    TransportError,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory
from webhook_receiver_conformance.journal.repositories import (
    AssertionEvidenceKind,
    AssertionEvidenceReference,
    AssertionRepository,
    TransitionMutationPhase,
    TransitionRepository,
)
from webhook_receiver_conformance.journal.schema import create_run_database
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
    SqlValue,
    StatementOperation,
)
from webhook_receiver_conformance.journal.transitions import (
    EntityType,
    IllegalTransitionError,
    TransitionCommand,
)
from webhook_receiver_conformance.observers.polling import (
    ObservationPollOutcome,
    ObservationPollResult,
)
from webhook_receiver_conformance.observers.protocol import (
    ObserverCapabilities,
    ObserverEvidence,
)
from webhook_receiver_conformance.runtime.assertions import (
    BUILTIN_ASSERTION_REGISTRY,
    REDACTED_ASSERTION_VALUE,
    AssertionEvidenceBundle,
    AssertionLifecycle,
    AssertionRegistration,
    AssertionRuntimeContext,
    validate_builtin_assertion_registry,
)
from webhook_receiver_conformance.runtime.verdicts import (
    AssertionErrorOrigin,
    classify_assertion_verdict,
    reduce_terminal_verdicts,
)
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
)

if TYPE_CHECKING:
    from pathlib import Path

    from webhook_receiver_conformance.domain.identifiers import FreshIdKind

RUN_ID = "00000000-0000-4000-8000-000000000508"
MANIFEST_ID = "a" * 64
SCENARIO_ID = f"scenario_{1:026d}"
EVENT_ID = f"event_{1:026d}"
DELIVERY_ID = f"delivery_{1:026d}"
ATTEMPT_ID = f"attempt_{1:026d}"
ATTEMPT_PLAN_ID = f"attempt_plan_{1:026d}"
OBSERVATION_ID = f"observation_{1:026d}"
SAMPLE_ID = f"sample_{1:026d}"
OBSERVATION_RECORD_ID = f"record_{90:026d}"
OWNER_EPOCH = 7
WALL_TEXT = "2026-07-27T20:00:00.000000Z"
WALL_TIME = datetime(2026, 7, 27, 20, 0, tzinfo=UTC)
SECRET_CANARY = "assertion-secret-canary-must-not-persist"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _FreshFactory:
    ordinal: int = 200

    def __call__(self, kind: FreshIdKind) -> str:
        self.ordinal += 1
        return f"{kind.value}_{self.ordinal:026d}"


class _InjectedCrashError(RuntimeError):
    pass


@dataclass
class _CrashOnOccurrence:
    target: TransitionMutationPhase
    occurrence: int
    seen: int = 0

    def __call__(self, phase: object) -> None:
        if phase is not self.target:
            return
        self.seen += 1
        if self.seen == self.occurrence:
            raise _InjectedCrashError(self.target.value)


def _clock() -> RuntimeClock:
    return RuntimeClock(
        ClockPolicy(ClockMode.REAL),
        wall_now=lambda: WALL_TIME,
        monotonic_now=lambda: 1_000_000_000,
    )


def _assertion_id(ordinal: int) -> str:
    return f"assertion_{ordinal:026d}"


def _context(assertion_id: str) -> AssertionRuntimeContext:
    return AssertionRuntimeContext(
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        assertion_id=assertion_id,
        owner_epoch=OWNER_EPOCH,
    )


def _status_assertion() -> HttpStatusAssertion:
    return HttpStatusAssertion.model_validate(
        {
            "id": "accepted_status",
            "type": "http-status",
            "attempt": {"event": "payment", "mode": "last-terminal"},
            "expected": {"codes": [204]},
        }
    )


def _count_assertion(
    *,
    on_unsupported: str = "unsupported",
) -> ProcessingCountAssertion:
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
            "on_unsupported": on_unsupported,
        }
    )


def _eventual_assertion() -> EventualStateAssertion:
    return EventualStateAssertion.model_validate(
        {
            "id": "eventual_processing",
            "type": "eventual-state",
            "query": {
                "observer": "receiver_state",
                "key": "resource_state",
                "parameters": {},
            },
            "comparator": "eq",
            "expected": {"value_type": "string", "value": "processed"},
            "within": "1s",
            "poll_interval": "50ms",
        }
    )


def _secret_assertion() -> ResourceFieldAssertion:
    return ResourceFieldAssertion.model_validate(
        {
            "id": "secret_differs",
            "type": "resource-field",
            "query": {
                "observer": "receiver_state",
                "key": "resource",
                "parameters": {},
            },
            "path": "/token",
            "comparator": "ne",
            "expected": {"value_type": "string", "value": "public"},
        }
    )


def _capabilities(
    *,
    keys: tuple[str, ...] = ("processing_count",),
    types: tuple[EvidenceValueType, ...] = (EvidenceValueType.INTEGER,),
    pollable: bool = True,
) -> ObserverCapabilities:
    return ObserverCapabilities(
        evidence_types=types,
        evidence_keys=keys,
        read_only=pollable,
        idempotent=pollable,
        supports_pending=pollable,
        stable_snapshot_ids=True,
    )


def _attempt(status: int | None) -> AttemptEvidence:
    if status is None:
        return AttemptEvidence(
            record_id=f"record_{10:026d}",
            run_id=RUN_ID,
            scenario_id=SCENARIO_ID,
            event_id=EVENT_ID,
            delivery_id=DELIVERY_ID,
            attempt_id=ATTEMPT_ID,
            sequence=1,
            recorded_at=WALL_TIME,
            state=AttemptEvidenceState.CONNECTION_FAILED,
            classification=AttemptClassification.ENVIRONMENT_FAILURE,
            error=TransportError(
                category="connection_error",
                message_redacted="Connection failed before response evidence.",
                phase="connect",
            ),
        )
    return AttemptEvidence(
        record_id=f"record_{10:026d}",
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        attempt_id=ATTEMPT_ID,
        sequence=1,
        recorded_at=WALL_TIME,
        state=(
            AttemptEvidenceState.ACKNOWLEDGED
            if 200 <= status <= 299
            else AttemptEvidenceState.REJECTED
        ),
        classification=(
            AttemptClassification.RECEIVER_ACCEPTED
            if 200 <= status <= 299
            else AttemptClassification.RECEIVER_REJECTED
        ),
        response=ResponseMetadata(
            status=status,
            body_sha256=None,
            captured_bytes=0,
            truncated=False,
        ),
    )


async def _seed(
    service: JournalService,
    assertions: tuple[tuple[str, str, bytes | None], ...],
    *,
    delivery_state: str = "satisfied",
) -> None:
    statements = [
        JournalStatement(
            """
            INSERT INTO runs (
                run_id, manifest_id, state, owner_epoch, created_at
            ) VALUES (?, ?, 'running', ?, ?)
            """,
            (RUN_ID, MANIFEST_ID, OWNER_EPOCH, WALL_TEXT),
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
                event_id, run_id, scenario_id, ordinal, event_type, fixture_blob_hash
            ) VALUES (?, ?, ?, 0, 'payment.created', ?)
            """,
            (EVENT_ID, RUN_ID, SCENARIO_ID, f"sha256:{'b' * 64}"),
        ),
        JournalStatement(
            """
            INSERT INTO deliveries (
                delivery_id, run_id, scenario_id, event_id, ordinal,
                step_ordinal, logical_time_ns, required, state
            ) VALUES (?, ?, ?, ?, 0, 0, 0, 1, ?)
            """,
            (DELIVERY_ID, RUN_ID, SCENARIO_ID, EVENT_ID, delivery_state),
        ),
        JournalStatement(
            """
            INSERT INTO attempts (
                attempt_id, run_id, scenario_id, event_id, delivery_id,
                attempt_plan_id, ordinal, state, owner_epoch
            ) VALUES (?, ?, ?, ?, ?, ?, 1, 'succeeded', ?)
            """,
            (
                ATTEMPT_ID,
                RUN_ID,
                SCENARIO_ID,
                EVENT_ID,
                DELIVERY_ID,
                ATTEMPT_PLAN_ID,
                OWNER_EPOCH,
            ),
        ),
        JournalStatement(
            """
            INSERT INTO observer_series (
                observation_id, run_id, scenario_id, event_id,
                checkpoint, observer_id, state
            ) VALUES (?, ?, ?, ?, 'after-delivery', 'receiver_state', 'ok')
            """,
            (OBSERVATION_ID, RUN_ID, SCENARIO_ID, EVENT_ID),
        ),
        JournalStatement(
            """
            INSERT INTO observation_samples (
                sample_id, record_id, run_id, scenario_id, observation_id,
                sample_sequence, status, recorded_at, snapshot_id
            ) VALUES (?, ?, ?, ?, ?, 1, 'ok', ?, 'snapshot-1')
            """,
            (
                SAMPLE_ID,
                OBSERVATION_RECORD_ID,
                RUN_ID,
                SCENARIO_ID,
                OBSERVATION_ID,
                WALL_TEXT,
            ),
        ),
    ]
    statements.extend(
        JournalStatement(
            """
            INSERT INTO assertions (
                assertion_id, run_id, scenario_id, type, policy_json, required, state
            ) VALUES (?, ?, ?, ?, ?, 1, 'pending')
            """,
            (assertion_id, RUN_ID, SCENARIO_ID, assertion_type, policy),
        )
        for assertion_id, assertion_type, policy in assertions
    )
    await service.execute(BatchOperation(tuple(statements)))


async def _rows(
    service: JournalService,
    sql: str,
    parameters: tuple[SqlValue, ...] = (),
) -> tuple[tuple[object, ...], ...]:
    result = await service.execute(StatementOperation(JournalStatement(sql, parameters)))
    return result.rows


def _runtime(
    service: JournalService,
    *,
    crash_hook: _CrashOnOccurrence | None = None,
    fresh: _FreshFactory | None = None,
) -> AssertionLifecycle:
    return AssertionLifecycle(
        repository=AssertionRepository(service, crash_hook=crash_hook),
        clock=_clock(),
        fresh_id=_FreshFactory() if fresh is None else fresh,
    )


def _attempt_bundle(status: int | None) -> AssertionEvidenceBundle:
    return AssertionEvidenceBundle(
        payload=_attempt(status),
        references=(
            AssertionEvidenceReference(
                AssertionEvidenceKind.ATTEMPT,
                ATTEMPT_ID,
            ),
        ),
    )


def _observation_bundle(
    payload: tuple[ObserverEvidence, ...] | ObservationPollResult,
    *,
    sample: bool = False,
) -> AssertionEvidenceBundle:
    return AssertionEvidenceBundle(
        payload=payload,
        references=(
            AssertionEvidenceReference(
                AssertionEvidenceKind.OBSERVATION,
                SAMPLE_ID if sample else OBSERVATION_ID,
            ),
        ),
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status", "expected_state", "expected_category", "expected_exit"),
    [
        (204, AssertionState.PASSED, ResultCategory.PASS, ExitCode.PASS),
        (
            500,
            AssertionState.FAILED,
            ResultCategory.RECEIVER_FAILURE,
            ExitCode.RECEIVER_FAILURE,
        ),
        (
            None,
            AssertionState.ERROR,
            ResultCategory.ENVIRONMENT_ERROR,
            ExitCode.ENVIRONMENT_FAILURE,
        ),
    ],
)
async def test_transport_lifecycle_persists_exact_terminal_classification(
    tmp_path: Path,
    status: int | None,
    expected_state: AssertionState,
    expected_category: ResultCategory,
    expected_exit: ExitCode,
) -> None:
    assertion_id = _assertion_id(1)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service, ((assertion_id, "http-status", None),))
        result = await _runtime(service).evaluate(
            _context(assertion_id),
            _status_assertion(),
            _attempt_bundle(status),
        )

        assert result.normalized.state is expected_state
        assert result.normalized.verdict.category is expected_category
        assert result.normalized.verdict.exit_code is expected_exit
        assert await _rows(
            service,
            "SELECT state FROM assertions WHERE assertion_id = ?",
            (assertion_id,),
        ) == ((expected_state.value,),)
        assert await _rows(
            service,
            """
            SELECT result, expected_json, actual_json
            FROM assertion_evaluations
            """,
        )
        assert await _rows(
            service,
            "SELECT evidence_kind, evidence_id FROM evidence_links",
        ) == (("attempt", ATTEMPT_ID),)

        if status == 500:
            assert result.normalized.expected == {
                "statuses": [204],
                "classes": [],
            }
            assert result.normalized.actual == 500


@pytest.mark.anyio
async def test_missing_required_observation_is_error_not_receiver_failure(
    tmp_path: Path,
) -> None:
    assertion_id = _assertion_id(2)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service, ((assertion_id, "processing-count", None),))

        async def supply() -> AssertionEvidenceBundle:
            return _observation_bundle(())

        result = await _runtime(service).evaluate_observer(
            _context(assertion_id),
            _count_assertion(),
            _capabilities(),
            supply,
        )
        assert result.normalized.result is AssertionResult.ERROR
        assert result.normalized.state is AssertionState.ERROR
        assert result.normalized.verdict.category is ResultCategory.ENVIRONMENT_ERROR
        assert result.normalized.verdict.category is not ResultCategory.RECEIVER_FAILURE
        assert await _rows(
            service,
            "SELECT evidence_kind, evidence_id FROM evidence_links",
        ) == (("observation", OBSERVATION_ID),)


@pytest.mark.anyio
async def test_capability_mismatch_is_unsupported_before_polling(
    tmp_path: Path,
) -> None:
    assertion_id = _assertion_id(3)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    called = False
    async with JournalService.open(run.database_path) as service:
        await _seed(
            service,
            (
                (
                    assertion_id,
                    "processing-count",
                    b'{"on_unsupported":"unsupported"}',
                ),
            ),
        )

        async def must_not_poll() -> AssertionEvidenceBundle:
            nonlocal called
            called = True
            raise AssertionError("capability mismatch must stop before polling")

        result = await _runtime(service).evaluate_observer(
            _context(assertion_id),
            _count_assertion(),
            _capabilities(keys=("different_key",)),
            must_not_poll,
            capability_reference=AssertionEvidenceReference(
                AssertionEvidenceKind.OBSERVATION,
                OBSERVATION_ID,
            ),
        )
        assert not called
        assert result.normalized.state is AssertionState.UNSUPPORTED
        assert result.normalized.verdict.category is ResultCategory.UNSUPPORTED
        assert result.normalized.verdict.exit_code is ExitCode.UNSUPPORTED
        assert await _rows(
            service,
            "SELECT result FROM assertion_evaluations",
        ) == (("error",),)
        assert await _rows(
            service,
            "SELECT evidence_kind FROM evidence_links",
        ) == (("observation",),)


@pytest.mark.anyio
async def test_skip_policy_persists_skipped_evaluation_and_unsupported_state(
    tmp_path: Path,
) -> None:
    assertion_id = _assertion_id(4)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(
            service,
            (
                (
                    assertion_id,
                    "processing-count",
                    b'{"on_unsupported":"skip"}',
                ),
            ),
        )

        async def must_not_poll() -> AssertionEvidenceBundle:
            raise AssertionError("capability mismatch must stop before polling")

        result = await _runtime(service).evaluate_observer(
            _context(assertion_id),
            _count_assertion(on_unsupported="skip"),
            _capabilities(keys=("different_key",)),
            must_not_poll,
            capability_reference=AssertionEvidenceReference(
                AssertionEvidenceKind.OBSERVATION,
                OBSERVATION_ID,
            ),
        )
        assert result.normalized.result is AssertionResult.SKIPPED
        assert result.normalized.state is AssertionState.UNSUPPORTED
        assert await _rows(
            service,
            "SELECT result FROM assertion_evaluations",
        ) == (("skipped",),)


@pytest.mark.anyio
async def test_observer_timeout_is_environment_error_and_retains_every_sample(
    tmp_path: Path,
) -> None:
    assertion_id = _assertion_id(5)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service, ((assertion_id, "eventual-state", None),))
        poll_result = ObservationPollResult(
            outcome=ObservationPollOutcome.TIMED_OUT,
            final_state=ObservationState.TIMED_OUT,
            sample_ids=(SAMPLE_ID,),
            predicate_matched=False,
            valid_evidence_seen=False,
            deadline_elapsed=True,
            last_response=None,
        )

        async def supply() -> AssertionEvidenceBundle:
            return _observation_bundle(poll_result, sample=True)

        result = await _runtime(service).evaluate_observer(
            _context(assertion_id),
            _eventual_assertion(),
            _capabilities(
                keys=("resource_state",),
                types=(EvidenceValueType.STRING,),
            ),
            supply,
        )
        assert result.normalized.state is AssertionState.ERROR
        assert result.normalized.verdict.category is ResultCategory.ENVIRONMENT_ERROR
        assert result.normalized.verdict.category is not ResultCategory.RECEIVER_FAILURE
        assert result.committed.evaluation.evidence_refs == (SAMPLE_ID,)


@pytest.mark.anyio
async def test_attempt_and_observation_evidence_remain_separately_typed(
    tmp_path: Path,
) -> None:
    status_id = _assertion_id(6)
    count_id = _assertion_id(7)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(
            service,
            (
                (status_id, "http-status", None),
                (count_id, "processing-count", None),
            ),
        )
        runtime = _runtime(service)
        await runtime.evaluate(
            _context(status_id),
            _status_assertion(),
            _attempt_bundle(204),
        )

        async def supply() -> AssertionEvidenceBundle:
            return _observation_bundle(
                (
                    ObserverEvidence(
                        key="processing_count",
                        value_type=EvidenceValueType.INTEGER,
                        value=1,
                    ),
                )
            )

        await runtime.evaluate_observer(
            _context(count_id),
            _count_assertion(),
            _capabilities(),
            supply,
        )
        assert await _rows(
            service,
            """
            SELECT evidence_kind, evidence_id
            FROM evidence_links
            ORDER BY evidence_kind
            """,
        ) == (
            ("attempt", ATTEMPT_ID),
            ("observation", OBSERVATION_ID),
        )


@pytest.mark.anyio
async def test_terminal_evaluation_and_links_roll_back_together_on_crash(
    tmp_path: Path,
) -> None:
    assertion_id = _assertion_id(8)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    crash = _CrashOnOccurrence(TransitionMutationPhase.AFTER_APPEND, 2)
    async with JournalService.open(run.database_path) as service:
        await _seed(service, ((assertion_id, "http-status", None),))
        with pytest.raises(_InjectedCrashError):
            await _runtime(service, crash_hook=crash).evaluate(
                _context(assertion_id),
                _status_assertion(),
                _attempt_bundle(204),
            )
        assert await _rows(
            service,
            "SELECT state FROM assertions WHERE assertion_id = ?",
            (assertion_id,),
        ) == (("running",),)
        assert await _rows(
            service,
            "SELECT COUNT(*) FROM assertion_evaluations",
        ) == ((0,),)
        assert await _rows(
            service,
            "SELECT COUNT(*) FROM evidence_links",
        ) == ((0,),)
        assert await _rows(
            service,
            "SELECT COUNT(*) FROM transitions WHERE entity_type = 'assertion'",
        ) == ((1,),)

        recovered = await _runtime(service).evaluate(
            _context(assertion_id),
            _status_assertion(),
            _attempt_bundle(204),
        )
        assert recovered.normalized.state is AssertionState.PASSED
        assert await _rows(
            service,
            "SELECT COUNT(*) FROM assertion_evaluations",
        ) == ((1,),)


@pytest.mark.anyio
async def test_cancelled_assertion_has_no_fabricated_evaluation(
    tmp_path: Path,
) -> None:
    assertion_id = _assertion_id(9)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service, ((assertion_id, "http-status", None),))
        verdict = await _runtime(service).cancel(
            _context(assertion_id),
            expected_state=AssertionState.PENDING,
        )
        assert verdict.category is ResultCategory.CANCELLED
        assert verdict.exit_code is ExitCode.CANCELLED
        assert await _rows(
            service,
            "SELECT state FROM assertions WHERE assertion_id = ?",
            (assertion_id,),
        ) == (("cancelled",),)
        assert await _rows(
            service,
            "SELECT COUNT(*) FROM assertion_evaluations",
        ) == ((0,),)


@pytest.mark.anyio
async def test_sensitive_actual_value_is_redacted_before_persistence(
    tmp_path: Path,
) -> None:
    assertion_id = _assertion_id(10)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(service, ((assertion_id, "resource-field", None),))

        async def supply() -> AssertionEvidenceBundle:
            return _observation_bundle(
                (
                    ObserverEvidence(
                        key="resource",
                        value_type=EvidenceValueType.OBJECT,
                        value={"token": SECRET_CANARY},
                        sensitive=True,
                    ),
                )
            )

        result = await _runtime(service).evaluate_observer(
            _context(assertion_id),
            _secret_assertion(),
            _capabilities(
                keys=("resource",),
                types=(EvidenceValueType.OBJECT,),
            ),
            supply,
        )
        assert result.normalized.state is AssertionState.PASSED
        actual_blob = cast(
            "bytes",
            (
                await _rows(
                    service,
                    "SELECT actual_json FROM assertion_evaluations",
                )
            )[0][0],
        )
        assert SECRET_CANARY.encode() not in actual_blob
        assert REDACTED_ASSERTION_VALUE.encode() in actual_blob


@pytest.mark.anyio
async def test_run_completion_rejects_required_nonterminal_delivery(
    tmp_path: Path,
) -> None:
    assertion_id = _assertion_id(11)
    run = create_run_database(tmp_path, run_id=RUN_ID)
    async with JournalService.open(run.database_path) as service:
        await _seed(
            service,
            ((assertion_id, "http-status", None),),
            delivery_state="pending",
        )
        with pytest.raises(
            IllegalTransitionError,
            match=r"^run completion requires every required delivery",
        ):
            await TransitionRepository(service).apply(
                TransitionCommand(
                    run_id=RUN_ID,
                    transition_id="run.complete.assertion-lifecycle",
                    entity_type=EntityType.RUN,
                    entity_id=RUN_ID,
                    expected_state=RunState.RUNNING,
                    new_state=RunState.COMPLETED,
                    trigger_category="run_complete",
                    timestamp=_clock().transition_timestamp(),
                    owner_epoch=OWNER_EPOCH,
                    idempotency_key="run.complete.assertion-lifecycle",
                )
            )


def test_builtin_registry_and_contract_cases_are_locked_together() -> None:
    registrations = tuple(BUILTIN_ASSERTION_REGISTRY.values())
    validate_builtin_assertion_registry(registrations)
    with pytest.raises(
        ValueError,
        match=r"implementations and contract registrations differ",
    ):
        validate_builtin_assertion_registry(registrations[:-1])
    missing_contract = AssertionRegistration(
        type_name=registrations[0].type_name,
        config_type=registrations[0].config_type,
        family=registrations[0].family,
        contract_test_ids=("VT-ASSERT-001",),
    )
    with pytest.raises(
        ValueError,
        match=r"requires the shared contract suite",
    ):
        validate_builtin_assertion_registry(
            (missing_contract, *registrations[1:]),
        )


def test_verdict_classification_is_exact_and_durable_terminal_wins() -> None:
    unsupported = classify_assertion_verdict(
        AssertionResult.ERROR,
        AssertionState.UNSUPPORTED,
    )
    environment = classify_assertion_verdict(
        AssertionResult.ERROR,
        AssertionState.ERROR,
        error_origin=AssertionErrorOrigin.ENVIRONMENT,
    )
    assert unsupported.exit_code is ExitCode.UNSUPPORTED
    assert environment.category is ResultCategory.ENVIRONMENT_ERROR
    reduced = reduce_terminal_verdicts(
        (
            ResultCategory.RECEIVER_FAILURE,
            ResultCategory.UNSUPPORTED,
            ResultCategory.AMBIGUOUS,
        )
    )
    assert reduced.category is ResultCategory.AMBIGUOUS
    immutable = reduce_terminal_verdicts(
        (ResultCategory.CANCELLED,),
        durably_terminal=ResultCategory.PASS,
    )
    assert immutable.category is ResultCategory.PASS
