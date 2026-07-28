"""Recovery classification, ambiguity, and crash-safety tests for TASK-0206."""
# ruff: noqa: INP001

from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from webhook_receiver_conformance.domain.enums import (
    AttemptClassification,
    AttemptState,
    ObservationState,
)
from webhook_receiver_conformance.journal.integrity import verify_resume_integrity
from webhook_receiver_conformance.journal.repositories import (
    AttemptMutationPhase,
    TransitionMutationPhase,
    TransitionRepository,
)
from webhook_receiver_conformance.journal.run_lock import RunLockMetadata
from webhook_receiver_conformance.journal.schema import (
    MIGRATIONS,
    RunDatabase,
    create_run_database,
    open_journal_database,
)
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
    StatementOperation,
)
from webhook_receiver_conformance.journal.transitions import StaleOwnerEpochError
from webhook_receiver_conformance.recovery import scanner as scanner_module
from webhook_receiver_conformance.recovery.models import (
    AttemptRecoveryAction,
    DurableNoSendProof,
    ObservationRecoveryAction,
    RecoveryAmbiguity,
    RecoveryScanContext,
)
from webhook_receiver_conformance.recovery.scanner import (
    PHASE_CONTROLLED_PRE_TRANSPORT,
    PHASE_NO_CONNECTION_ESTABLISHED,
    TRIGGER_RECOVERY_INTERRUPTED_OBSERVER,
    TRIGGER_RECOVERY_INTERRUPTED_SEND,
    TRIGGER_RECOVERY_NO_SEND_PROOF,
    RecoveryIntegrityError,
    RecoveryOwnerEpochError,
    RecoveryResourceLimitError,
    RecoveryScanner,
    classify_attempt_state,
    classify_observation_state,
)
from webhook_receiver_conformance.scheduler.clocks import TransitionTimestamp

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from webhook_receiver_conformance.journal.service import SqlValue

RUN_ID = "00000000-0000-4000-8000-000000000206"
MANIFEST_ID = "a" * 64
OWNER_EPOCH = 7
WALL_TIME = datetime(2026, 7, 27, 19, 34, 56, tzinfo=UTC)
WALL_TEXT = "2026-07-27T19:34:56.000000Z"
LIVE_TIMESTAMP = TransitionTimestamp(WALL_TIME, 123_456)
FIXTURE_HASH = f"sha256:{'b' * 64}"
CANARY_TEXT = "secret-canary-do-not-retain"
EXPECTED_AUTOMATIC_TRANSITIONS = 7


def _planned(prefix: str, ordinal: int) -> str:
    return f"{prefix}{ordinal:026d}"


SCENARIO_ID = _planned("scenario_", 1)
EVENT_ID = _planned("event_", 1)
DELIVERY_ID = _planned("delivery_", 1)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass(frozen=True, slots=True)
class _AttemptSeed:
    state: AttemptState
    phase: str | None = None
    response_terminal_state: AttemptState = AttemptState.SUCCEEDED


@dataclass(frozen=True, slots=True)
class _CrashAt:
    target: TransitionMutationPhase | AttemptMutationPhase

    def __call__(self, phase: TransitionMutationPhase | AttemptMutationPhase) -> None:
        if phase is self.target:
            raise _InjectedCrashError(phase.value)


class _InjectedCrashError(RuntimeError):
    pass


def _base_statements() -> tuple[JournalStatement, ...]:
    return (
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
            ) VALUES (?, ?, 0, 'recovery', 'running')
            """,
            (SCENARIO_ID, RUN_ID),
        ),
        JournalStatement(
            """
            INSERT INTO events (
                event_id, run_id, scenario_id, ordinal, event_type,
                fixture_blob_hash
            ) VALUES (?, ?, ?, 0, 'fixture.created', ?)
            """,
            (EVENT_ID, RUN_ID, SCENARIO_ID, FIXTURE_HASH),
        ),
        JournalStatement(
            """
            INSERT INTO deliveries (
                delivery_id, run_id, scenario_id, event_id, ordinal,
                step_ordinal, logical_time_ns, state
            ) VALUES (?, ?, ?, ?, 0, 0, 0, 'active')
            """,
            (DELIVERY_ID, RUN_ID, SCENARIO_ID, EVENT_ID),
        ),
    )


def _attempt_statement(seed: _AttemptSeed, ordinal: int) -> JournalStatement:
    classification, terminal_time = _terminal_fields(seed.state)
    return JournalStatement(
        """
        INSERT INTO attempts (
            attempt_id, run_id, scenario_id, event_id, delivery_id,
            attempt_plan_id, ordinal, state, phase, outcome_category,
            terminal_recorded_at, owner_epoch
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _planned("attempt_", ordinal + 1),
            RUN_ID,
            SCENARIO_ID,
            EVENT_ID,
            DELIVERY_ID,
            _planned("attempt_plan_", ordinal + 1),
            ordinal,
            seed.state.value,
            seed.phase,
            classification,
            terminal_time,
            OWNER_EPOCH,
        ),
    )


def _schedule_statement(seed: _AttemptSeed, ordinal: int) -> JournalStatement | None:
    if seed.state not in {
        AttemptState.SCHEDULED,
        AttemptState.CLAIMED,
        AttemptState.RESPONSE_OBSERVED,
    }:
        return None
    consumed = seed.state is not AttemptState.SCHEDULED
    return JournalStatement(
        """
        INSERT INTO schedule_entries (
            schedule_entry_id, run_id, scenario_id, entity_type, entity_id,
            logical_time_ns, scenario_ordinal, step_ordinal, delivery_ordinal,
            attempt_ordinal, deterministic_tie_key, idempotency_key,
            consumed_at, consumed_by_owner_epoch
        ) VALUES (?, ?, ?, 'attempt', ?, 0, 0, 0, 0, ?, ?, ?, ?, ?)
        """,
        (
            f"recovery.schedule.{ordinal}",
            RUN_ID,
            SCENARIO_ID,
            _planned("attempt_plan_", ordinal + 1),
            ordinal,
            f"recovery.{ordinal}",
            f"recovery.schedule.{ordinal}",
            WALL_TEXT if consumed else None,
            OWNER_EPOCH if consumed else None,
        ),
    )


def _response_staging_statement(
    seed: _AttemptSeed,
    ordinal: int,
) -> JournalStatement | None:
    if seed.state is not AttemptState.RESPONSE_OBSERVED:
        return None
    terminal_state = seed.response_terminal_state
    classification, evidence_state, status, error_category, error_message, error_phase = {
        AttemptState.SUCCEEDED: (
            AttemptClassification.RECEIVER_ACCEPTED.value,
            "acknowledged",
            204,
            None,
            None,
            None,
        ),
        AttemptState.REJECTED: (
            AttemptClassification.RECEIVER_REJECTED.value,
            "rejected",
            503,
            None,
            None,
            None,
        ),
        AttemptState.TRANSPORT_FAILED: (
            AttemptClassification.ENVIRONMENT_FAILURE.value,
            "protocol_failed",
            599,
            "protocol_error",
            "bounded response failed terminal protocol validation",
            "response_body",
        ),
    }[terminal_state]
    return JournalStatement(
        """
        INSERT INTO attempt_response_staging (
            attempt_id, record_id, run_id, scenario_id, event_id,
            delivery_id, terminal_state, classification, evidence_state,
            request_method, request_url_redacted, request_body_sha256,
            request_byte_length, request_header_names_json,
            response_status, response_body_sha256, response_captured_bytes,
            response_truncated, error_category, error_message_redacted,
            error_phase
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, 'POST',
            'http://127.0.0.1/[REDACTED]', ?, 1, ?, ?, ?, 0, 0, ?, ?, ?
        )
        """,
        (
            _planned("attempt_", ordinal + 1),
            _planned("record_", ordinal + 1),
            RUN_ID,
            SCENARIO_ID,
            EVENT_ID,
            DELIVERY_ID,
            terminal_state.value,
            classification,
            evidence_state,
            FIXTURE_HASH,
            b'["content-type"]',
            status,
            FIXTURE_HASH,
            error_category,
            error_message,
            error_phase,
        ),
    )


def _observation_statement(
    state: ObservationState,
    ordinal: int,
) -> JournalStatement:
    return JournalStatement(
        """
        INSERT INTO observer_series (
            observation_id, run_id, scenario_id, checkpoint,
            observer_id, state
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            _planned("observation_", ordinal + 1),
            RUN_ID,
            SCENARIO_ID,
            f"checkpoint_{ordinal}",
            f"observer-{ordinal}",
            state.value,
        ),
    )


def _terminal_fields(state: AttemptState) -> tuple[str | None, str | None]:
    classifications = {
        AttemptState.NOT_SENT: AttemptClassification.ENVIRONMENT_FAILURE,
        AttemptState.SUCCEEDED: AttemptClassification.RECEIVER_ACCEPTED,
        AttemptState.REJECTED: AttemptClassification.RECEIVER_REJECTED,
        AttemptState.TRANSPORT_FAILED: AttemptClassification.ENVIRONMENT_FAILURE,
        AttemptState.UNKNOWN_OUTCOME: AttemptClassification.AMBIGUOUS,
        AttemptState.CANCELLED: AttemptClassification.CANCELLED,
    }
    classification = classifications.get(state)
    if classification is None:
        return (None, None)
    return (classification.value, WALL_TEXT)


async def _seed_database(
    root: Path,
    attempts: Sequence[_AttemptSeed],
    *,
    observations: Sequence[ObservationState] = (),
) -> RunDatabase:
    run = create_run_database(root, run_id=RUN_ID)
    statements = (
        *_base_statements(),
        *(_attempt_statement(seed, ordinal) for ordinal, seed in enumerate(attempts)),
        *(
            statement
            for ordinal, seed in enumerate(attempts)
            if (statement := _schedule_statement(seed, ordinal)) is not None
        ),
        *(
            statement
            for ordinal, seed in enumerate(attempts)
            if (statement := _response_staging_statement(seed, ordinal)) is not None
        ),
        *(_observation_statement(state, ordinal) for ordinal, state in enumerate(observations)),
    )
    async with JournalService.open(run.database_path) as service:
        await service.execute(BatchOperation(statements))
    return run


def _context(run: RunDatabase, *, owner_epoch: int = OWNER_EPOCH) -> RecoveryScanContext:
    return RecoveryScanContext(
        run_id=RUN_ID,
        owner_epoch=owner_epoch,
        integrity=verify_resume_integrity(run.database_path),
        owner=RunLockMetadata(
            run_id=RUN_ID,
            pid=42,
            process_start_fingerprint="test-process-start",
            hostname="test-host",
            owner_epoch=owner_epoch,
            wall_timestamp=WALL_TEXT,
        ),
    )


async def _rows(
    service: JournalService,
    sql: str,
    parameters: tuple[SqlValue, ...] = (),
) -> tuple[tuple[SqlValue, ...], ...]:
    result = await service.execute(StatementOperation(JournalStatement(sql, parameters)))
    return result.rows


async def _execute(
    service: JournalService,
    sql: str,
    parameters: tuple[SqlValue, ...] = (),
) -> None:
    await service.execute(StatementOperation(JournalStatement(sql, parameters)))


def _expected_attempt_decision(
    state: AttemptState,
    proof: DurableNoSendProof,
) -> tuple[AttemptRecoveryAction, RecoveryAmbiguity, AttemptState | None]:
    if state is AttemptState.PRE_SEND_COMMITTED:
        if proof is DurableNoSendProof.CONTROLLED_PRE_TRANSPORT:
            return (
                AttemptRecoveryAction.TERMINATE_NOT_SENT,
                RecoveryAmbiguity.NONE,
                AttemptState.NOT_SENT,
            )
        return (
            AttemptRecoveryAction.REQUIRE_PHASE_EVIDENCE,
            RecoveryAmbiguity.PHASE_EVIDENCE_REQUIRED,
            None,
        )
    if state is AttemptState.CONNECTING:
        if proof is DurableNoSendProof.NO_CONNECTION_ESTABLISHED:
            return (
                AttemptRecoveryAction.TERMINATE_NOT_SENT,
                RecoveryAmbiguity.NONE,
                AttemptState.NOT_SENT,
            )
        return (
            AttemptRecoveryAction.TERMINATE_UNKNOWN_OUTCOME,
            RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT,
            AttemptState.UNKNOWN_OUTCOME,
        )
    static = {
        AttemptState.SCHEDULED: (
            AttemptRecoveryAction.RESUME_SCHEDULED,
            RecoveryAmbiguity.NONE,
            None,
        ),
        AttemptState.CLAIMED: (
            AttemptRecoveryAction.RECLAIM_EXPIRED_CLAIM,
            RecoveryAmbiguity.NONE,
            None,
        ),
        AttemptState.SENDING: (
            AttemptRecoveryAction.TERMINATE_UNKNOWN_OUTCOME,
            RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT,
            AttemptState.UNKNOWN_OUTCOME,
        ),
        AttemptState.AWAITING_RESPONSE: (
            AttemptRecoveryAction.TERMINATE_UNKNOWN_OUTCOME,
            RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT,
            AttemptState.UNKNOWN_OUTCOME,
        ),
        AttemptState.RESPONSE_OBSERVED: (
            AttemptRecoveryAction.REDUCE_DURABLE_RESPONSE,
            RecoveryAmbiguity.NONE,
            None,
        ),
        AttemptState.NOT_SENT: (
            AttemptRecoveryAction.PRESERVE_TERMINAL,
            RecoveryAmbiguity.NONE,
            None,
        ),
        AttemptState.SUCCEEDED: (
            AttemptRecoveryAction.PRESERVE_TERMINAL,
            RecoveryAmbiguity.NONE,
            None,
        ),
        AttemptState.REJECTED: (
            AttemptRecoveryAction.PRESERVE_TERMINAL,
            RecoveryAmbiguity.NONE,
            None,
        ),
        AttemptState.TRANSPORT_FAILED: (
            AttemptRecoveryAction.PRESERVE_TERMINAL,
            RecoveryAmbiguity.NONE,
            None,
        ),
        AttemptState.UNKNOWN_OUTCOME: (
            AttemptRecoveryAction.PRESERVE_UNKNOWN_OUTCOME,
            RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT,
            None,
        ),
        AttemptState.CANCELLED: (
            AttemptRecoveryAction.PRESERVE_TERMINAL,
            RecoveryAmbiguity.NONE,
            None,
        ),
    }
    return static[state]


@pytest.mark.parametrize("state", tuple(AttemptState))
@pytest.mark.parametrize("proof", tuple(DurableNoSendProof))
def test_attempt_classifier_exhaustively_preserves_uncertainty(
    state: AttemptState,
    proof: DurableNoSendProof,
) -> None:
    decision = classify_attempt_state(state, proof)

    assert decision == _expected_attempt_decision(state, proof)
    assert decision[2] not in {
        AttemptState.SUCCEEDED,
        AttemptState.REJECTED,
        AttemptState.TRANSPORT_FAILED,
    }
    if state in {AttemptState.SENDING, AttemptState.AWAITING_RESPONSE}:
        assert decision == (
            AttemptRecoveryAction.TERMINATE_UNKNOWN_OUTCOME,
            RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT,
            AttemptState.UNKNOWN_OUTCOME,
        )
    if state is AttemptState.UNKNOWN_OUTCOME:
        assert decision == (
            AttemptRecoveryAction.PRESERVE_UNKNOWN_OUTCOME,
            RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT,
            None,
        )


@pytest.mark.parametrize("state", tuple(ObservationState))
def test_observation_classifier_covers_the_authoritative_state_set(
    state: ObservationState,
) -> None:
    action, target = classify_observation_state(state)

    if state is ObservationState.SCHEDULED:
        assert (action, target) == (
            ObservationRecoveryAction.RESUME_SCHEDULED,
            None,
        )
    elif state is ObservationState.RUNNING:
        assert (action, target) == (
            ObservationRecoveryAction.TERMINATE_INTERRUPTED_ERROR,
            ObservationState.ERROR,
        )
    else:
        assert (action, target) == (
            ObservationRecoveryAction.PRESERVE_TERMINAL,
            None,
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("target", "classification", "evidence_state"),
    [
        (
            AttemptState.SUCCEEDED,
            AttemptClassification.RECEIVER_ACCEPTED,
            "acknowledged",
        ),
        (
            AttemptState.REJECTED,
            AttemptClassification.RECEIVER_REJECTED,
            "rejected",
        ),
        (
            AttemptState.TRANSPORT_FAILED,
            AttemptClassification.ENVIRONMENT_FAILURE,
            "protocol_failed",
        ),
    ],
)
async def test_durable_response_recovery_derives_exact_terminal_result(
    tmp_path: Path,
    target: AttemptState,
    classification: AttemptClassification,
    evidence_state: str,
) -> None:
    run = await _seed_database(
        tmp_path,
        (
            _AttemptSeed(
                AttemptState.RESPONSE_OBSERVED,
                response_terminal_state=target,
            ),
        ),
    )
    async with JournalService.open(run.database_path) as service:
        scanner = RecoveryScanner(service, _context(run))
        plan = await scanner.scan()
        assert plan.attempts[0].action is AttemptRecoveryAction.REDUCE_DURABLE_RESPONSE
        assert plan.attempts[0].target_state is target
        await scanner.apply(plan, timestamp=LIVE_TIMESTAMP)

        assert await _rows(
            service,
            "SELECT state, outcome_category FROM attempts",
        ) == ((target.value, classification.value),)
        assert await _rows(
            service,
            "SELECT state, classification FROM attempt_records",
        ) == ((evidence_state, classification.value),)
        assert await _rows(
            service,
            "SELECT count(*) FROM attempt_response_staging",
        ) == ((0,),)


@pytest.mark.anyio
async def test_legacy_response_observed_migrates_to_v4_then_fails_closed(
    tmp_path: Path,
) -> None:
    run = create_run_database(
        tmp_path,
        run_id=RUN_ID,
        migrations=MIGRATIONS[:3],
    )
    legacy = open_journal_database(
        run.database_path,
        migrations=MIGRATIONS[:3],
    )
    try:
        legacy.execute("BEGIN IMMEDIATE")
        for statement in (
            *_base_statements(),
            _attempt_statement(
                _AttemptSeed(AttemptState.RESPONSE_OBSERVED),
                0,
            ),
            _schedule_statement(
                _AttemptSeed(AttemptState.RESPONSE_OBSERVED),
                0,
            ),
        ):
            assert statement is not None
            legacy.execute(statement.sql, statement.parameters)
        legacy.execute("COMMIT")
    finally:
        legacy.close()

    async with JournalService.open(run.database_path) as service:
        assert await _rows(
            service,
            "SELECT max(migration_id) FROM schema_migrations",
        ) == ((4,),)
        scanner = RecoveryScanner(service, _context(run))
        with pytest.raises(
            RecoveryIntegrityError,
            match="lacks durable response staging",
        ):
            await scanner.scan()


@pytest.mark.anyio
async def test_fresh_process_scan_and_apply_are_deterministic_conservative_and_offline(  # noqa: PLR0915
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = (
        _AttemptSeed(AttemptState.SCHEDULED),
        _AttemptSeed(AttemptState.CLAIMED),
        _AttemptSeed(AttemptState.PRE_SEND_COMMITTED),
        _AttemptSeed(
            AttemptState.PRE_SEND_COMMITTED,
            PHASE_CONTROLLED_PRE_TRANSPORT,
        ),
        _AttemptSeed(AttemptState.CONNECTING),
        _AttemptSeed(
            AttemptState.CONNECTING,
            PHASE_NO_CONNECTION_ESTABLISHED,
        ),
        _AttemptSeed(AttemptState.SENDING, PHASE_NO_CONNECTION_ESTABLISHED),
        _AttemptSeed(AttemptState.AWAITING_RESPONSE),
        _AttemptSeed(AttemptState.RESPONSE_OBSERVED),
        _AttemptSeed(AttemptState.NOT_SENT),
        _AttemptSeed(AttemptState.SUCCEEDED),
        _AttemptSeed(AttemptState.REJECTED),
        _AttemptSeed(AttemptState.TRANSPORT_FAILED),
        _AttemptSeed(AttemptState.UNKNOWN_OUTCOME),
        _AttemptSeed(AttemptState.CANCELLED),
    )
    run = await _seed_database(
        tmp_path,
        attempts,
        observations=tuple(ObservationState),
    )
    context = _context(run)

    async with JournalService.open(run.database_path) as service:
        scanner = RecoveryScanner(service, context)
        monkeypatch.setattr(socket, "socket", _forbid_network)
        before = await _rows(
            service,
            "SELECT count(*) FROM transitions WHERE run_id = ?",
            (RUN_ID,),
        )
        plan = await scanner.scan()
        second_plan = await scanner.scan()
        after = await _rows(
            service,
            "SELECT count(*) FROM transitions WHERE run_id = ?",
            (RUN_ID,),
        )

        assert plan == second_plan
        assert before == after == ((0,),)
        assert plan.performs_network_io is False
        assert plan.contains_ambiguity is True
        assert plan.automatic_transition_count == EXPECTED_AUTOMATIC_TRANSITIONS
        assert tuple(item.attempt_ordinal for item in plan.attempts) == tuple(range(len(attempts)))
        assert plan.attempts[2].action is AttemptRecoveryAction.REQUIRE_PHASE_EVIDENCE
        assert plan.attempts[3].target_state is AttemptState.NOT_SENT
        assert plan.attempts[4].target_state is AttemptState.UNKNOWN_OUTCOME
        assert plan.attempts[5].target_state is AttemptState.NOT_SENT
        assert plan.attempts[6].target_state is AttemptState.UNKNOWN_OUTCOME
        assert plan.attempts[6].durable_no_send_proof is DurableNoSendProof.NONE
        assert plan.attempts[7].target_state is AttemptState.UNKNOWN_OUTCOME
        assert plan.attempts[8].target_state is AttemptState.SUCCEEDED
        assert plan.attempts[8].response_staging is not None
        assert plan.attempts[13].action is AttemptRecoveryAction.PRESERVE_UNKNOWN_OUTCOME

        committed = await scanner.apply(plan, timestamp=LIVE_TIMESTAMP)
        replayed = await scanner.apply(plan, timestamp=LIVE_TIMESTAMP)

        assert len(committed) == EXPECTED_AUTOMATIC_TRANSITIONS
        assert all(not result.idempotent_replay for result in committed)
        assert all(result.idempotent_replay for result in replayed)
        states = await _rows(
            service,
            """
            SELECT ordinal, state, outcome_category
            FROM attempts
            WHERE run_id = ?
            ORDER BY ordinal
            """,
            (RUN_ID,),
        )
        assert states[2][1:] == (AttemptState.PRE_SEND_COMMITTED.value, None)
        assert states[3][1:] == (
            AttemptState.NOT_SENT.value,
            AttemptClassification.HARNESS_FAILURE.value,
        )
        assert states[4][1:] == (
            AttemptState.UNKNOWN_OUTCOME.value,
            AttemptClassification.AMBIGUOUS.value,
        )
        assert states[5][1:] == (
            AttemptState.NOT_SENT.value,
            AttemptClassification.ENVIRONMENT_FAILURE.value,
        )
        assert states[6][1:] == (
            AttemptState.UNKNOWN_OUTCOME.value,
            AttemptClassification.AMBIGUOUS.value,
        )
        assert states[7][1:] == (
            AttemptState.UNKNOWN_OUTCOME.value,
            AttemptClassification.AMBIGUOUS.value,
        )
        assert states[8][1:] == (
            AttemptState.SUCCEEDED.value,
            AttemptClassification.RECEIVER_ACCEPTED.value,
        )
        assert states[13][1:] == (
            AttemptState.UNKNOWN_OUTCOME.value,
            AttemptClassification.AMBIGUOUS.value,
        )
        observations = await _rows(
            service,
            """
            SELECT observation_id, state
            FROM observer_series
            WHERE run_id = ?
            ORDER BY observation_id
            """,
            (RUN_ID,),
        )
        assert observations[0][1] == ObservationState.SCHEDULED.value
        assert observations[1][1] == ObservationState.ERROR.value
        assert tuple(row[1] for row in observations[2:]) == tuple(
            state.value for state in tuple(ObservationState)[2:]
        )
        history = await TransitionRepository(service).history(RUN_ID)
        assert len(history) == EXPECTED_AUTOMATIC_TRANSITIONS
        assert all(record.causal_record_id == record.entity_id for record in history)
        assert {record.trigger_category for record in history} == {
            TRIGGER_RECOVERY_NO_SEND_PROOF,
            TRIGGER_RECOVERY_INTERRUPTED_SEND,
            TRIGGER_RECOVERY_INTERRUPTED_OBSERVER,
            "recovery_response_reduction",
        }
        assert await _rows(
            service,
            """
            SELECT attempt_ordinal, consumed_by_owner_epoch
            FROM schedule_entries
            WHERE run_id = ?
            ORDER BY attempt_ordinal
            """,
            (RUN_ID,),
        ) == ((0, None), (1, OWNER_EPOCH), (8, OWNER_EPOCH))
        attempt_records = await _rows(
            service,
            """
            SELECT
                attempts.ordinal,
                attempt_records.state,
                attempt_records.classification,
                attempt_records.error_category,
                attempt_records.error_phase
            FROM attempt_records
            JOIN attempts
              ON attempts.run_id = attempt_records.run_id
             AND attempts.attempt_id = attempt_records.attempt_id
            WHERE attempt_records.run_id = ?
            ORDER BY attempts.ordinal
            """,
            (RUN_ID,),
        )
        assert attempt_records == (
            (
                3,
                "connection_failed",
                AttemptClassification.HARNESS_FAILURE.value,
                "recovery_controlled_pre_transport",
                AttemptState.PRE_SEND_COMMITTED.value,
            ),
            (
                4,
                "unknown_outcome",
                AttemptClassification.AMBIGUOUS.value,
                "recovery_interrupted_send",
                AttemptState.CONNECTING.value,
            ),
            (
                5,
                "connection_failed",
                AttemptClassification.ENVIRONMENT_FAILURE.value,
                "recovery_no_connection",
                AttemptState.CONNECTING.value,
            ),
            (
                6,
                "unknown_outcome",
                AttemptClassification.AMBIGUOUS.value,
                "recovery_interrupted_send",
                AttemptState.SENDING.value,
            ),
            (
                7,
                "unknown_outcome",
                AttemptClassification.AMBIGUOUS.value,
                "recovery_interrupted_send",
                AttemptState.AWAITING_RESPONSE.value,
            ),
            (8, "acknowledged", AttemptClassification.RECEIVER_ACCEPTED.value, None, None),
        )
        assert await _rows(
            service,
            "SELECT count(*) FROM attempt_response_staging WHERE run_id = ?",
            (RUN_ID,),
        ) == ((0,),)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "attempt_state",
    [
        AttemptState.CONNECTING,
        AttemptState.SENDING,
        AttemptState.AWAITING_RESPONSE,
    ],
)
@pytest.mark.parametrize(
    "mutation_phase",
    [*TransitionMutationPhase, AttemptMutationPhase.AFTER_ATTEMPT_RECORD],
)
async def test_interrupted_send_recovery_is_atomic_at_every_mutation_phase(
    tmp_path: Path,
    attempt_state: AttemptState,
    mutation_phase: TransitionMutationPhase,
) -> None:
    run = await _seed_database(tmp_path, (_AttemptSeed(attempt_state),))
    context = _context(run)

    async with JournalService.open(run.database_path) as service:
        repository = TransitionRepository(
            service,
            crash_hook=_CrashAt(mutation_phase),
        )
        crashing = RecoveryScanner(
            service,
            context,
            transition_repository=repository,
        )
        plan = await crashing.scan()

        with pytest.raises(_InjectedCrashError, match=mutation_phase.value):
            await crashing.apply(plan, timestamp=LIVE_TIMESTAMP)

        assert await _rows(
            service,
            "SELECT state, outcome_category FROM attempts WHERE run_id = ?",
            (RUN_ID,),
        ) == ((attempt_state.value, None),)
        assert await _rows(
            service,
            "SELECT count(*) FROM transitions WHERE run_id = ?",
            (RUN_ID,),
        ) == ((0,),)
        assert await _rows(
            service,
            "SELECT count(*) FROM attempt_records WHERE run_id = ?",
            (RUN_ID,),
        ) == ((0,),)

        recovered = RecoveryScanner(service, context)
        recovered_plan = await recovered.scan()
        assert recovered_plan.attempts[0].target_state is AttemptState.UNKNOWN_OUTCOME
        await recovered.apply(recovered_plan, timestamp=LIVE_TIMESTAMP)
        assert await _rows(
            service,
            "SELECT state, outcome_category FROM attempts WHERE run_id = ?",
            (RUN_ID,),
        ) == (
            (
                AttemptState.UNKNOWN_OUTCOME.value,
                AttemptClassification.AMBIGUOUS.value,
            ),
        )
        assert await _rows(
            service,
            """
            SELECT state, classification, error_category, error_phase
            FROM attempt_records
            WHERE run_id = ?
            """,
            (RUN_ID,),
        ) == (
            (
                "unknown_outcome",
                AttemptClassification.AMBIGUOUS.value,
                "recovery_interrupted_send",
                attempt_state.value,
            ),
        )


@pytest.mark.anyio
async def test_decisive_no_connection_proof_is_the_only_connecting_exception(
    tmp_path: Path,
) -> None:
    run = await _seed_database(
        tmp_path,
        (
            _AttemptSeed(
                AttemptState.CONNECTING,
                PHASE_NO_CONNECTION_ESTABLISHED,
            ),
            _AttemptSeed(
                AttemptState.CONNECTING,
                PHASE_CONTROLLED_PRE_TRANSPORT,
            ),
        ),
    )
    context = _context(run)

    async with JournalService.open(run.database_path) as service:
        scanner = RecoveryScanner(service, context)
        plan = await scanner.scan()

        assert plan.attempts[0].target_state is AttemptState.NOT_SENT
        assert plan.attempts[1].target_state is AttemptState.UNKNOWN_OUTCOME
        assert plan.attempts[1].durable_no_send_proof is DurableNoSendProof.NONE
        await scanner.apply(plan, timestamp=LIVE_TIMESTAMP)
        assert await _rows(
            service,
            """
            SELECT state, outcome_category
            FROM attempts
            WHERE run_id = ?
            ORDER BY ordinal
            """,
            (RUN_ID,),
        ) == (
            (
                AttemptState.NOT_SENT.value,
                AttemptClassification.ENVIRONMENT_FAILURE.value,
            ),
            (
                AttemptState.UNKNOWN_OUTCOME.value,
                AttemptClassification.AMBIGUOUS.value,
            ),
        )


@pytest.mark.anyio
async def test_scan_rejects_owner_mismatch_without_mutation(tmp_path: Path) -> None:
    run = await _seed_database(
        tmp_path,
        (_AttemptSeed(AttemptState.CONNECTING),),
    )
    context = _context(run, owner_epoch=OWNER_EPOCH + 1)

    async with JournalService.open(run.database_path) as service:
        scanner = RecoveryScanner(service, context)
        with pytest.raises(RecoveryOwnerEpochError):
            await scanner.scan()
        assert await _rows(
            service,
            "SELECT state FROM attempts WHERE run_id = ?",
            (RUN_ID,),
        ) == ((AttemptState.CONNECTING.value,),)


@pytest.mark.anyio
async def test_apply_rejects_stale_owner_and_historical_time(
    tmp_path: Path,
) -> None:
    run = await _seed_database(
        tmp_path,
        (_AttemptSeed(AttemptState.CONNECTING),),
    )
    context = _context(run)

    async with JournalService.open(run.database_path) as service:
        scanner = RecoveryScanner(service, context)
        plan = await scanner.scan()

        with pytest.raises(ValueError, match="monotonic"):
            await scanner.apply(
                plan,
                timestamp=TransitionTimestamp.historical(WALL_TIME),
            )
        await _execute(
            service,
            "UPDATE runs SET owner_epoch = ? WHERE run_id = ?",
            (OWNER_EPOCH + 1, RUN_ID),
        )
        with pytest.raises(StaleOwnerEpochError):
            await scanner.apply(plan, timestamp=LIVE_TIMESTAMP)
        assert await _rows(
            service,
            "SELECT state FROM attempts WHERE run_id = ?",
            (RUN_ID,),
        ) == ((AttemptState.CONNECTING.value,),)
        assert await _rows(
            service,
            "SELECT count(*) FROM transitions WHERE run_id = ?",
            (RUN_ID,),
        ) == ((0,),)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("state", "classification"),
    [
        (AttemptState.SCHEDULED, AttemptClassification.HARNESS_FAILURE),
        (AttemptState.UNKNOWN_OUTCOME, AttemptClassification.RECEIVER_ACCEPTED),
    ],
)
async def test_scan_rejects_malformed_terminal_projection_fields(
    tmp_path: Path,
    state: AttemptState,
    classification: AttemptClassification,
) -> None:
    run = await _seed_database(tmp_path, (_AttemptSeed(state),))
    async with JournalService.open(run.database_path) as service:
        await _execute(
            service,
            """
            UPDATE attempts
            SET outcome_category = ?, terminal_recorded_at = ?
            WHERE run_id = ?
            """,
            (classification.value, WALL_TEXT, RUN_ID),
        )
    context = _context(run)

    async with JournalService.open(run.database_path) as service:
        with pytest.raises(RecoveryIntegrityError):
            await RecoveryScanner(service, context).scan()


@pytest.mark.anyio
async def test_scan_enforces_the_bounded_inventory_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = await _seed_database(
        tmp_path,
        (
            _AttemptSeed(AttemptState.SCHEDULED),
            _AttemptSeed(AttemptState.CLAIMED),
        ),
    )
    context = _context(run)
    monkeypatch.setattr(scanner_module, "MAX_RECOVERY_ITEMS", 1)

    async with JournalService.open(run.database_path) as service:
        with pytest.raises(RecoveryResourceLimitError):
            await RecoveryScanner(service, context).scan()


@pytest.mark.anyio
async def test_unknown_phase_text_is_not_retained_in_plan_or_diagnostics(
    tmp_path: Path,
) -> None:
    run = await _seed_database(
        tmp_path,
        (_AttemptSeed(AttemptState.SENDING, CANARY_TEXT),),
    )
    context = _context(run)

    async with JournalService.open(run.database_path) as service:
        plan = await RecoveryScanner(service, context).scan()

    assert plan.attempts[0].durable_no_send_proof is DurableNoSendProof.NONE
    assert CANARY_TEXT not in repr(plan)


def _forbid_network(*_args: object, **_kwargs: object) -> None:
    message = "recovery scanner attempted network I/O"
    raise AssertionError(message)
