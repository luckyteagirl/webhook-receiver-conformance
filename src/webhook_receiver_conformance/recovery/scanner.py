"""Bounded fresh-process recovery scanning and conservative classification."""
# ruff: noqa: C901, EM101, INP001, TRY003

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from webhook_receiver_conformance.domain.enums import (
    AttemptClassification,
    AttemptEvidenceState,
    AttemptState,
    DeliveryState,
    ObservationState,
    RunState,
)
from webhook_receiver_conformance.domain.identifiers import FreshIdKind, new_fresh_id
from webhook_receiver_conformance.domain.models import (
    RequestMetadata,
    ResponseMetadata,
    TransportError,
)
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.journal.repositories import (
    TRIGGER_ATTEMPT_OUTCOME,
    TransitionRepository,
)
from webhook_receiver_conformance.journal.service import (
    JournalService,
    JournalStatement,
    JournalTransaction,
)
from webhook_receiver_conformance.journal.transitions import (
    AttemptResponseStagingCommand,
    AttemptTerminalOutcome,
    AttemptTransportEvidenceCommand,
    CausalReference,
    CommittedTransition,
    DeliverySatisfactionEvidence,
    DeliverySatisfactionKind,
    EntityType,
    RetrySchedule,
    TransitionCommand,
)
from webhook_receiver_conformance.scheduler.clocks import TransitionTimestamp
from webhook_receiver_conformance.types import DiagnosticCode

from .models import (
    AttemptRecoveryAction,
    AttemptRecoveryItem,
    DurableNoSendProof,
    ObservationRecoveryAction,
    ObservationRecoveryItem,
    RecoveryAmbiguity,
    RecoveryPlan,
    RecoveryScanContext,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

MAX_RECOVERY_ITEMS = 100_000
SCAN_PAGE_SIZE = 1_000
_RUN_ROW_COLUMN_COUNT = 2
_ATTEMPT_ROW_COLUMN_COUNT = 14
_RESPONSE_STAGING_COLUMN_COUNT = 32
_OBSERVATION_ROW_COLUMN_COUNT = 4

PHASE_CONTROLLED_PRE_TRANSPORT = DurableNoSendProof.CONTROLLED_PRE_TRANSPORT.value
PHASE_NO_CONNECTION_ESTABLISHED = DurableNoSendProof.NO_CONNECTION_ESTABLISHED.value

TRIGGER_RECOVERY_NO_SEND_PROOF = "recovery_no_send_proof"
TRIGGER_RECOVERY_INTERRUPTED_SEND = "recovery_interrupted_send"
TRIGGER_RECOVERY_INTERRUPTED_OBSERVER = "recovery_interrupted_observer"

type AttemptClassificationDecision = tuple[
    AttemptRecoveryAction,
    RecoveryAmbiguity,
    AttemptState | None,
]
type ObservationClassificationDecision = tuple[
    ObservationRecoveryAction,
    ObservationState | None,
]

_TERMINAL_ATTEMPT_CLASSIFICATIONS: Mapping[
    AttemptState,
    frozenset[AttemptClassification],
] = MappingProxyType(
    {
        AttemptState.NOT_SENT: frozenset(
            {
                AttemptClassification.ENVIRONMENT_FAILURE,
                AttemptClassification.HARNESS_FAILURE,
            }
        ),
        AttemptState.SUCCEEDED: frozenset({AttemptClassification.RECEIVER_ACCEPTED}),
        AttemptState.REJECTED: frozenset({AttemptClassification.RECEIVER_REJECTED}),
        AttemptState.TRANSPORT_FAILED: frozenset(
            {
                AttemptClassification.ENVIRONMENT_FAILURE,
                AttemptClassification.HARNESS_FAILURE,
            }
        ),
        AttemptState.UNKNOWN_OUTCOME: frozenset({AttemptClassification.AMBIGUOUS}),
        AttemptState.CANCELLED: frozenset({AttemptClassification.CANCELLED}),
    }
)
_STATIC_ATTEMPT_DECISIONS: Mapping[
    AttemptState,
    AttemptClassificationDecision,
] = MappingProxyType(
    {
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
)


class RecoveryScannerError(RuntimeError):
    """A classified recovery scan or plan-application failure."""

    category: ErrorCategory = ErrorCategory.INTEGRITY_ERROR
    code: DiagnosticCode = DiagnosticCode("RECOVERY_SCAN_ERROR")


class RecoveryIntegrityError(RecoveryScannerError):
    """Persisted recovery input is internally inconsistent."""

    code = DiagnosticCode("RECOVERY_SCAN_INTEGRITY")


class RecoveryResourceLimitError(RecoveryScannerError):
    """The bounded recovery inventory cannot be safely materialized."""

    category = ErrorCategory.RESOURCE_LIMIT
    code = DiagnosticCode("RECOVERY_SCAN_LIMIT")


class RecoveryOwnerEpochError(RecoveryScannerError):
    """The fresh recovery owner does not match the journal owner epoch."""

    category = ErrorCategory.ILLEGAL_TRANSITION
    code = DiagnosticCode("RECOVERY_OWNER_EPOCH_MISMATCH")


@dataclass(frozen=True, slots=True)
class _AttemptRow:
    attempt_id: str
    scenario_id: str
    event_id: str
    delivery_id: str
    attempt_ordinal: int
    state: str
    phase: str | None
    outcome_category: str | None
    terminal_recorded_at: str | None
    attempt_owner_epoch: int | None
    scenario_ordinal: int
    step_ordinal: int
    delivery_ordinal: int
    predecessor_attempt_id: str | None


@dataclass(frozen=True, slots=True)
class _ObservationRow:
    observation_id: str
    scenario_id: str
    state: str
    scenario_ordinal: int


@dataclass(frozen=True, slots=True)
class _ScanRows:
    run_state: str
    owner_epoch: int
    attempts: tuple[_AttemptRow, ...]
    response_staging: tuple[tuple[object, ...], ...]
    observations: tuple[_ObservationRow, ...]


@dataclass(frozen=True, slots=True)
class _DeliveryReductionRow:
    run_id: str
    delivery_id: str
    attempt_id: str
    attempt_state: AttemptState


@dataclass(frozen=True, slots=True)
class _ScanOperation:
    run_id: str

    def execute(self, transaction: JournalTransaction) -> _ScanRows:
        run = transaction.execute(
            JournalStatement(
                "SELECT state, owner_epoch FROM runs WHERE run_id = ?",
                (self.run_id,),
            )
        )
        if len(run.rows) != 1 or len(run.rows[0]) != _RUN_ROW_COLUMN_COUNT:
            message = "recovery run projection is missing or duplicated"
            raise RecoveryIntegrityError(message)
        count = transaction.execute(
            JournalStatement(
                """
                SELECT
                    (SELECT count(*) FROM attempts WHERE run_id = ?)
                    +
                    (SELECT count(*) FROM observer_series WHERE run_id = ?)
                """,
                (self.run_id, self.run_id),
            )
        )
        if len(count.rows) != 1 or len(count.rows[0]) != 1:
            message = "recovery inventory count has an invalid shape"
            raise RecoveryIntegrityError(message)
        total = _integer(count.rows[0][0], name="recovery inventory count")
        if total > MAX_RECOVERY_ITEMS:
            message = "recovery inventory exceeds the bounded item limit"
            raise RecoveryResourceLimitError(message)
        attempts = _load_attempt_rows(transaction, self.run_id)
        response_staging = _load_response_staging_rows(transaction, self.run_id)
        observations = _load_observation_rows(transaction, self.run_id)
        if len(attempts) + len(observations) != total:
            message = "recovery inventory changed during its transaction"
            raise RecoveryIntegrityError(message)
        return _ScanRows(
            run_state=_text(run.rows[0][0], name="run state"),
            owner_epoch=_integer(run.rows[0][1], name="run owner_epoch"),
            attempts=attempts,
            response_staging=response_staging,
            observations=observations,
        )


@dataclass(frozen=True, slots=True)
class _DeliveryReductionOperation:
    run_id: str

    def execute(
        self,
        transaction: JournalTransaction,
    ) -> tuple[_DeliveryReductionRow, ...]:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT deliveries.delivery_id, attempts.attempt_id, attempts.state
                FROM deliveries
                JOIN attempts
                  ON attempts.run_id = deliveries.run_id
                 AND attempts.delivery_id = deliveries.delivery_id
                WHERE deliveries.run_id = ?
                  AND deliveries.state = 'active'
                  AND attempts.state IN (
                      'not_sent',
                      'succeeded',
                      'rejected',
                      'transport_failed',
                      'cancelled'
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM attempts AS successor
                      WHERE successor.run_id = attempts.run_id
                        AND successor.delivery_id = attempts.delivery_id
                        AND successor.ordinal > attempts.ordinal
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM schedule_entries
                      WHERE schedule_entries.run_id = deliveries.run_id
                        AND schedule_entries.scenario_id = deliveries.scenario_id
                        AND schedule_entries.delivery_ordinal = deliveries.ordinal
                        AND (
                            schedule_entries.consumed_at IS NULL
                            OR EXISTS (
                                SELECT 1
                                FROM attempts AS prepared
                                WHERE prepared.run_id = schedule_entries.run_id
                                  AND prepared.scenario_id = schedule_entries.scenario_id
                                  AND prepared.delivery_id = deliveries.delivery_id
                                  AND prepared.attempt_plan_id = schedule_entries.entity_id
                                  AND prepared.ordinal = schedule_entries.attempt_ordinal
                                  AND prepared.state = 'claimed'
                                  AND schedule_entries.consumed_by_owner_epoch = (
                                      SELECT owner_epoch
                                      FROM runs
                                      WHERE runs.run_id = schedule_entries.run_id
                                  )
                            )
                        )
                  )
                ORDER BY deliveries.scenario_id, deliveries.ordinal,
                         attempts.ordinal, attempts.attempt_id
                """,
                (self.run_id,),
            )
        )
        if len(result.rows) > MAX_RECOVERY_ITEMS:
            raise RecoveryResourceLimitError(
                "delivery recovery inventory exceeds the bounded item limit"
            )
        return tuple(
            _DeliveryReductionRow(
                run_id=self.run_id,
                delivery_id=_text(row[0], name="delivery_id"),
                attempt_id=_text(row[1], name="attempt_id"),
                attempt_state=AttemptState(_text(row[2], name="attempt state")),
            )
            for row in result.rows
        )


class RecoveryScanner:
    """Scan and atomically classify interrupted work without network effects."""

    __slots__ = ("_context", "_repository", "_service")

    def __init__(
        self,
        service: JournalService,
        context: RecoveryScanContext,
        *,
        transition_repository: TransitionRepository | None = None,
    ) -> None:
        """Bind a verified fresh owner to the sole journal writer."""
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            service,
            JournalService,
        ):
            message = "service must be a JournalService"
            raise TypeError(message)
        if type(context) is not RecoveryScanContext:
            message = "context must be a RecoveryScanContext"
            raise TypeError(message)
        if transition_repository is not None and not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            transition_repository,
            TransitionRepository,
        ):
            message = "transition_repository must be a TransitionRepository"
            raise TypeError(message)
        self._service = service
        self._context = context
        self._repository = (
            TransitionRepository(service)
            if transition_repository is None
            else transition_repository
        )

    async def scan(self) -> RecoveryPlan:
        """Return one deterministic, bounded, read-only recovery plan."""
        rows = await self._service.execute(_ScanOperation(self._context.run_id))
        if rows.owner_epoch != self._context.owner_epoch:
            message = "journal owner epoch differs from the fresh recovery owner"
            raise RecoveryOwnerEpochError(message)
        try:
            run_state = RunState(rows.run_state)
        except ValueError as error:
            message = "recovery run contains an undeclared state"
            raise RecoveryIntegrityError(message) from error
        try:
            staging_by_attempt = {
                _text(row[0], name="staged response attempt_id"): _response_staging(row)
                for row in rows.response_staging
            }
            if len(staging_by_attempt) != len(rows.response_staging):
                raise RecoveryIntegrityError(
                    "response staging contains duplicate attempt identities"
                )
            attempts = tuple(
                sorted(
                    (
                        _attempt_item(
                            self._context.run_id,
                            row,
                            staging_by_attempt.get(row.attempt_id),
                        )
                        for row in rows.attempts
                    ),
                    key=lambda item: item.deterministic_key,
                )
            )
        except RecoveryScannerError:
            raise
        except (TypeError, ValueError) as error:
            raise RecoveryIntegrityError(
                "durable response staging contains invalid evidence"
            ) from error
        if {item.attempt_id for item in attempts if item.response_staging is not None} != set(
            staging_by_attempt
        ):
            raise RecoveryIntegrityError(
                "durable response staging is not bound to response-observed attempts"
            )
        observations = tuple(
            sorted(
                (_observation_item(self._context.run_id, row) for row in rows.observations),
                key=lambda item: item.deterministic_key,
            )
        )
        return RecoveryPlan(
            run_id=self._context.run_id,
            owner_epoch=self._context.owner_epoch,
            run_state=run_state,
            attempts=attempts,
            observations=observations,
        )

    async def apply(
        self,
        plan: RecoveryPlan,
        *,
        timestamp: TransitionTimestamp,
    ) -> tuple[CommittedTransition, ...]:
        """Apply only safe automatic classifications via guarded transitions."""
        if type(plan) is not RecoveryPlan:
            message = "plan must be a RecoveryPlan"
            raise TypeError(message)
        if type(timestamp) is not TransitionTimestamp:
            message = "timestamp must be a TransitionTimestamp"
            raise TypeError(message)
        if not timestamp.is_live:
            message = "fresh-process recovery transitions require monotonic evidence"
            raise ValueError(message)
        if plan.run_id != self._context.run_id or plan.owner_epoch != self._context.owner_epoch:
            message = "recovery plan belongs to a different owner context"
            raise RecoveryOwnerEpochError(message)
        for item in plan.attempts:
            if item.action is AttemptRecoveryAction.RESUME_SCHEDULED:
                await self._repository.rebind_recoverable_attempt(
                    item.run_id,
                    item.attempt_id,
                    expected_state=AttemptState.SCHEDULED,
                    owner_epoch=plan.owner_epoch,
                )
            elif item.action is AttemptRecoveryAction.RECLAIM_EXPIRED_CLAIM:
                await self._repository.rebind_recoverable_attempt(
                    item.run_id,
                    item.attempt_id,
                    expected_state=AttemptState.CLAIMED,
                    owner_epoch=plan.owner_epoch,
                )
        committed_attempts: list[CommittedTransition] = []
        for item in plan.attempts:
            if not item.requires_transition:
                continue
            if item.response_staging is not None:
                evidence = item.response_staging.transport_evidence
            else:
                record_id = await self._repository.attempt_record_id(
                    item.run_id,
                    item.attempt_id,
                )
                evidence = _attempt_recovery_evidence(
                    item,
                    record_id=(
                        new_fresh_id(FreshIdKind.RECORD) if record_id is None else record_id
                    ),
                )
            committed_attempts.append(
                await self._repository.apply_attempt(
                    _attempt_transition(item, plan.owner_epoch, timestamp),
                    transport_evidence=evidence,
                )
            )
        committed_observations = [
            await self._repository.apply(
                _observation_transition(
                    item,
                    plan.owner_epoch,
                    timestamp,
                )
            )
            for item in plan.observations
            if item.requires_transition
        ]
        reductions = await self._service.execute(_DeliveryReductionOperation(plan.run_id))
        committed_deliveries = [
            await self._repository.apply(
                _delivery_reduction_transition(
                    item,
                    owner_epoch=plan.owner_epoch,
                    timestamp=timestamp,
                )
            )
            for item in reductions
        ]
        return (
            *committed_attempts,
            *committed_observations,
            *committed_deliveries,
        )


def classify_attempt_state(
    state: AttemptState,
    proof: DurableNoSendProof,
) -> AttemptClassificationDecision:
    """Classify one persisted attempt phase using only authoritative evidence."""
    if type(state) is not AttemptState:
        message = "state must be an AttemptState"
        raise TypeError(message)
    if type(proof) is not DurableNoSendProof:
        message = "proof must be a DurableNoSendProof"
        raise TypeError(message)
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
    return _STATIC_ATTEMPT_DECISIONS[state]


def classify_observation_state(
    state: ObservationState,
) -> ObservationClassificationDecision:
    """Classify an interrupted observation without invoking an observer."""
    if type(state) is not ObservationState:
        message = "state must be an ObservationState"
        raise TypeError(message)
    if state is ObservationState.SCHEDULED:
        return (ObservationRecoveryAction.RESUME_SCHEDULED, None)
    if state is ObservationState.RUNNING:
        return (
            ObservationRecoveryAction.TERMINATE_INTERRUPTED_ERROR,
            ObservationState.ERROR,
        )
    return (ObservationRecoveryAction.PRESERVE_TERMINAL, None)


def _load_attempt_rows(
    transaction: JournalTransaction,
    run_id: str,
) -> tuple[_AttemptRow, ...]:
    rows: list[_AttemptRow] = []
    last_attempt_id = ""
    while True:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT
                    attempts.attempt_id,
                    attempts.scenario_id,
                    attempts.event_id,
                    attempts.delivery_id,
                    attempts.ordinal,
                    attempts.state,
                    attempts.phase,
                    attempts.outcome_category,
                    attempts.terminal_recorded_at,
                    attempts.owner_epoch,
                    scenarios.ordinal,
                    deliveries.step_ordinal,
                    deliveries.ordinal,
                    attempts.predecessor_attempt_id
                FROM attempts
                JOIN scenarios
                  ON scenarios.run_id = attempts.run_id
                 AND scenarios.scenario_id = attempts.scenario_id
                JOIN deliveries
                  ON deliveries.run_id = attempts.run_id
                 AND deliveries.scenario_id = attempts.scenario_id
                 AND deliveries.event_id = attempts.event_id
                 AND deliveries.delivery_id = attempts.delivery_id
                WHERE attempts.run_id = ? AND attempts.attempt_id > ?
                ORDER BY attempts.attempt_id
                LIMIT ?
                """,
                (run_id, last_attempt_id, SCAN_PAGE_SIZE),
            )
        )
        if not result.rows:
            break
        for row in result.rows:
            parsed = _attempt_row(row)
            rows.append(parsed)
            last_attempt_id = parsed.attempt_id
        if len(result.rows) < SCAN_PAGE_SIZE:
            break
    return tuple(rows)


def _load_response_staging_rows(
    transaction: JournalTransaction,
    run_id: str,
) -> tuple[tuple[object, ...], ...]:
    rows: list[tuple[object, ...]] = []
    last_attempt_id = ""
    while True:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT
                    attempt_id, record_id, run_id, scenario_id, event_id,
                    delivery_id, terminal_state, classification, evidence_state,
                    request_method, request_url_redacted, request_body_sha256,
                    request_byte_length, request_header_names_json,
                    response_status, response_body_sha256,
                    response_captured_bytes, response_truncated,
                    error_category, error_message_redacted, error_phase,
                    response_headers_elapsed_ns,
                    retry_schedule_entry_id, retry_entity_id,
                    retry_logical_time_ns, retry_scenario_ordinal,
                    retry_step_ordinal, retry_delivery_ordinal,
                    retry_attempt_ordinal, retry_deterministic_tie_key,
                    retry_idempotency_key, retry_condition_json
                FROM attempt_response_staging
                WHERE run_id = ? AND attempt_id > ?
                ORDER BY attempt_id
                LIMIT ?
                """,
                (run_id, last_attempt_id, SCAN_PAGE_SIZE),
            )
        )
        if not result.rows:
            break
        for row in result.rows:
            if len(row) != _RESPONSE_STAGING_COLUMN_COUNT:
                raise RecoveryIntegrityError("response staging recovery row has an invalid shape")
            materialized = tuple(row)
            rows.append(materialized)
            last_attempt_id = _text(
                materialized[0],
                name="staged response attempt_id",
            )
        if len(result.rows) < SCAN_PAGE_SIZE:
            break
    return tuple(rows)


def _load_observation_rows(
    transaction: JournalTransaction,
    run_id: str,
) -> tuple[_ObservationRow, ...]:
    rows: list[_ObservationRow] = []
    last_observation_id = ""
    while True:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT
                    observer_series.observation_id,
                    observer_series.scenario_id,
                    observer_series.state,
                    scenarios.ordinal
                FROM observer_series
                JOIN scenarios
                  ON scenarios.run_id = observer_series.run_id
                 AND scenarios.scenario_id = observer_series.scenario_id
                WHERE observer_series.run_id = ?
                  AND observer_series.observation_id > ?
                ORDER BY observer_series.observation_id
                LIMIT ?
                """,
                (run_id, last_observation_id, SCAN_PAGE_SIZE),
            )
        )
        if not result.rows:
            break
        for row in result.rows:
            parsed = _observation_row(row)
            rows.append(parsed)
            last_observation_id = parsed.observation_id
        if len(result.rows) < SCAN_PAGE_SIZE:
            break
    return tuple(rows)


def _attempt_row(row: Sequence[object]) -> _AttemptRow:
    if len(row) != _ATTEMPT_ROW_COLUMN_COUNT:
        message = "attempt recovery row has an invalid shape"
        raise RecoveryIntegrityError(message)
    return _AttemptRow(
        attempt_id=_text(row[0], name="attempt_id"),
        scenario_id=_text(row[1], name="scenario_id"),
        event_id=_text(row[2], name="event_id"),
        delivery_id=_text(row[3], name="delivery_id"),
        attempt_ordinal=_integer(row[4], name="attempt ordinal"),
        state=_text(row[5], name="attempt state"),
        phase=_optional_text(row[6], name="attempt phase"),
        outcome_category=_optional_text(
            row[7],
            name="attempt outcome_category",
        ),
        terminal_recorded_at=_optional_text(
            row[8],
            name="attempt terminal_recorded_at",
        ),
        attempt_owner_epoch=_optional_integer(
            row[9],
            name="attempt owner_epoch",
        ),
        scenario_ordinal=_integer(row[10], name="scenario ordinal"),
        step_ordinal=_integer(row[11], name="step ordinal"),
        delivery_ordinal=_integer(row[12], name="delivery ordinal"),
        predecessor_attempt_id=_optional_text(
            row[13],
            name="predecessor_attempt_id",
        ),
    )


def _observation_row(row: Sequence[object]) -> _ObservationRow:
    if len(row) != _OBSERVATION_ROW_COLUMN_COUNT:
        message = "observation recovery row has an invalid shape"
        raise RecoveryIntegrityError(message)
    return _ObservationRow(
        observation_id=_text(row[0], name="observation_id"),
        scenario_id=_text(row[1], name="scenario_id"),
        state=_text(row[2], name="observation state"),
        scenario_ordinal=_integer(row[3], name="scenario ordinal"),
    )


def _attempt_item(
    run_id: str,
    row: _AttemptRow,
    response_staging: AttemptResponseStagingCommand | None,
) -> AttemptRecoveryItem:
    try:
        state = AttemptState(row.state)
    except ValueError as error:
        message = "attempt recovery row contains an undeclared state"
        raise RecoveryIntegrityError(message) from error
    _validate_attempt_projection(row, state)
    raw_proof = _durable_no_send_proof(row.phase)
    action, ambiguity, target = classify_attempt_state(state, raw_proof)
    if action is AttemptRecoveryAction.REDUCE_DURABLE_RESPONSE:
        if response_staging is None:
            raise RecoveryIntegrityError("response-observed attempt lacks durable response staging")
        target = response_staging.terminal_state
    elif response_staging is not None:
        raise RecoveryIntegrityError("non-response-observed attempt retains response staging")
    proof = (
        raw_proof if action is AttemptRecoveryAction.TERMINATE_NOT_SENT else DurableNoSendProof.NONE
    )
    return AttemptRecoveryItem(
        run_id=run_id,
        scenario_id=row.scenario_id,
        event_id=row.event_id,
        delivery_id=row.delivery_id,
        attempt_id=row.attempt_id,
        scenario_ordinal=row.scenario_ordinal,
        step_ordinal=row.step_ordinal,
        delivery_ordinal=row.delivery_ordinal,
        attempt_ordinal=row.attempt_ordinal,
        prior_state=state,
        durable_no_send_proof=proof,
        action=action,
        ambiguity=ambiguity,
        target_state=target,
        predecessor_attempt_id=row.predecessor_attempt_id,
        response_staging=response_staging,
    )


def _response_staging(
    row: Sequence[object],
) -> AttemptResponseStagingCommand:
    if len(row) != _RESPONSE_STAGING_COLUMN_COUNT:
        raise RecoveryIntegrityError("response staging recovery row has an invalid shape")
    headers_blob = row[13]
    if type(headers_blob) is not bytes:
        raise RecoveryIntegrityError("staged request header names are not a BLOB")
    try:
        headers_value = json.loads(headers_blob)
    except (UnicodeDecodeError, json.JSONDecodeError) as caught:
        raise RecoveryIntegrityError("staged request header names are malformed") from caught
    if type(headers_value) is not list or any(
        type(item) is not str for item in cast("list[object]", headers_value)
    ):
        raise RecoveryIntegrityError("staged request header names are malformed")
    request_method = _text(row[9], name="staged request method")
    if request_method != "POST":
        raise RecoveryIntegrityError("staged request method is unsupported")
    truncated = _integer(row[17], name="staged response truncated")
    if truncated not in {0, 1}:
        raise RecoveryIntegrityError("staged response truncated flag is invalid")
    error: TransportError | None = None
    if row[18] is not None:
        error = TransportError(
            category=_text(row[18], name="staged error category"),
            message_redacted=_text(
                row[19],
                name="staged redacted error message",
            ),
            phase=_optional_text(row[20], name="staged error phase"),
        )
    attempt_id = _text(row[0], name="staged response attempt_id")
    scenario_id = _text(row[3], name="staged response scenario_id")
    retry: RetrySchedule | None = None
    if row[22] is not None:
        condition = row[31]
        if condition is not None and type(condition) is not bytes:
            raise RecoveryIntegrityError("staged retry condition is not a BLOB")
        retry = RetrySchedule(
            schedule_entry_id=_text(
                row[22],
                name="staged retry schedule_entry_id",
            ),
            scenario_id=scenario_id,
            entity_type="attempt",
            entity_id=_text(row[23], name="staged retry entity_id"),
            logical_time_ns=_integer(
                row[24],
                name="staged retry logical_time_ns",
            ),
            scenario_ordinal=_integer(
                row[25],
                name="staged retry scenario ordinal",
            ),
            step_ordinal=_integer(
                row[26],
                name="staged retry step ordinal",
            ),
            delivery_ordinal=_integer(
                row[27],
                name="staged retry delivery ordinal",
            ),
            attempt_ordinal=_integer(
                row[28],
                name="staged retry attempt ordinal",
            ),
            deterministic_tie_key=_text(
                row[29],
                name="staged retry deterministic tie key",
            ),
            idempotency_key=_text(
                row[30],
                name="staged retry idempotency key",
            ),
            predecessor_attempt_id=attempt_id,
            condition_json=condition,
        )
    classification = AttemptClassification(_text(row[7], name="staged response classification"))
    return AttemptResponseStagingCommand(
        terminal_state=AttemptState(_text(row[6], name="staged response terminal state")),
        terminal_outcome=AttemptTerminalOutcome(classification, retry),
        transport_evidence=AttemptTransportEvidenceCommand(
            record_id=_text(row[1], name="staged response record_id"),
            run_id=_text(row[2], name="staged response run_id"),
            scenario_id=scenario_id,
            event_id=_text(row[4], name="staged response event_id"),
            delivery_id=_text(row[5], name="staged response delivery_id"),
            attempt_id=attempt_id,
            state=AttemptEvidenceState(_text(row[8], name="staged response evidence state")),
            classification=classification,
            request=RequestMetadata(
                method="POST",
                url_redacted=_text(
                    row[10],
                    name="staged redacted request URL",
                ),
                body_sha256=_text(
                    row[11],
                    name="staged request body digest",
                ),
                byte_length=_integer(
                    row[12],
                    name="staged request byte length",
                ),
                header_names=tuple(cast("list[str]", headers_value)),
            ),
            response=ResponseMetadata(
                status=_integer(row[14], name="staged response status"),
                body_sha256=_text(
                    row[15],
                    name="staged response body digest",
                ),
                captured_bytes=_integer(
                    row[16],
                    name="staged response captured bytes",
                ),
                truncated=bool(truncated),
            ),
            error=error,
            response_headers_elapsed_ns=_optional_integer(
                row[21],
                name="staged response headers elapsed",
            ),
        ),
    )


def _observation_item(
    run_id: str,
    row: _ObservationRow,
) -> ObservationRecoveryItem:
    try:
        state = ObservationState(row.state)
    except ValueError as error:
        message = "observation recovery row contains an undeclared state"
        raise RecoveryIntegrityError(message) from error
    action, target = classify_observation_state(state)
    return ObservationRecoveryItem(
        run_id=run_id,
        scenario_id=row.scenario_id,
        observation_id=row.observation_id,
        scenario_ordinal=row.scenario_ordinal,
        prior_state=state,
        action=action,
        target_state=target,
    )


def _validate_attempt_projection(
    row: _AttemptRow,
    state: AttemptState,
) -> None:
    is_terminal = state in _TERMINAL_ATTEMPT_CLASSIFICATIONS
    has_outcome = row.outcome_category is not None
    has_terminal_time = row.terminal_recorded_at is not None
    if not is_terminal:
        if has_outcome or has_terminal_time:
            message = "nonterminal attempt contains terminal outcome fields"
            raise RecoveryIntegrityError(message)
        return
    if not has_outcome or not has_terminal_time:
        message = "terminal attempt is missing durable outcome fields"
        raise RecoveryIntegrityError(message)
    try:
        classification = AttemptClassification(cast("str", row.outcome_category))
    except ValueError as error:
        message = "terminal attempt contains an undeclared outcome"
        raise RecoveryIntegrityError(message) from error
    if classification not in _TERMINAL_ATTEMPT_CLASSIFICATIONS[state]:
        message = "terminal attempt state and classification disagree"
        raise RecoveryIntegrityError(message)
    _validate_wall_timestamp(cast("str", row.terminal_recorded_at))


def _durable_no_send_proof(value: str | None) -> DurableNoSendProof:
    if value == PHASE_CONTROLLED_PRE_TRANSPORT:
        return DurableNoSendProof.CONTROLLED_PRE_TRANSPORT
    if value == PHASE_NO_CONNECTION_ESTABLISHED:
        return DurableNoSendProof.NO_CONNECTION_ESTABLISHED
    return DurableNoSendProof.NONE


def _attempt_transition(
    item: AttemptRecoveryItem,
    owner_epoch: int,
    timestamp: TransitionTimestamp,
) -> TransitionCommand[AttemptState]:
    if item.target_state is AttemptState.NOT_SENT:
        target = AttemptState.NOT_SENT
    elif item.target_state is AttemptState.UNKNOWN_OUTCOME:
        target = AttemptState.UNKNOWN_OUTCOME
    elif (
        item.action is AttemptRecoveryAction.REDUCE_DURABLE_RESPONSE
        and item.response_staging is not None
        and item.target_state is item.response_staging.terminal_state
    ):
        target = item.response_staging.terminal_state
    else:
        message = "attempt recovery item has no automatic terminal transition"
        raise RecoveryIntegrityError(message)
    if target is AttemptState.UNKNOWN_OUTCOME:
        classification = AttemptClassification.AMBIGUOUS
        trigger = TRIGGER_RECOVERY_INTERRUPTED_SEND
    elif item.response_staging is not None:
        classification = item.response_staging.terminal_outcome.classification
        trigger = "recovery_response_reduction"
    else:
        classification = (
            AttemptClassification.HARNESS_FAILURE
            if item.durable_no_send_proof is DurableNoSendProof.CONTROLLED_PRE_TRANSPORT
            else AttemptClassification.ENVIRONMENT_FAILURE
        )
        trigger = TRIGGER_RECOVERY_NO_SEND_PROOF
    return TransitionCommand(
        run_id=item.run_id,
        transition_id=_transition_id(item.attempt_id, target.value),
        entity_type=EntityType.ATTEMPT,
        entity_id=item.attempt_id,
        expected_state=item.prior_state,
        new_state=target,
        trigger_category=trigger,
        timestamp=timestamp,
        owner_epoch=owner_epoch,
        idempotency_key=_idempotency_key(
            item.attempt_id,
            item.prior_state.value,
            target.value,
        ),
        causal_reference=CausalReference(item.run_id, item.attempt_id),
        attempt_outcome=(
            item.response_staging.terminal_outcome
            if item.response_staging is not None
            else AttemptTerminalOutcome(classification)
        ),
    )


def _attempt_recovery_evidence(
    item: AttemptRecoveryItem,
    *,
    record_id: str,
) -> AttemptTransportEvidenceCommand:
    if item.target_state is AttemptState.NOT_SENT:
        classification = (
            AttemptClassification.HARNESS_FAILURE
            if item.durable_no_send_proof is DurableNoSendProof.CONTROLLED_PRE_TRANSPORT
            else AttemptClassification.ENVIRONMENT_FAILURE
        )
        state = AttemptEvidenceState.CONNECTION_FAILED
        category = (
            "recovery_controlled_pre_transport"
            if item.durable_no_send_proof is DurableNoSendProof.CONTROLLED_PRE_TRANSPORT
            else "recovery_no_connection"
        )
        message = "Recovery proved that no application request bytes left the harness."
    elif item.target_state is AttemptState.UNKNOWN_OUTCOME:
        classification = AttemptClassification.AMBIGUOUS
        state = AttemptEvidenceState.UNKNOWN_OUTCOME
        category = "recovery_interrupted_send"
        message = "Recovery found a possible request send without a durable response."
    else:
        message = "attempt recovery item has no automatic terminal evidence"
        raise RecoveryIntegrityError(message)
    return AttemptTransportEvidenceCommand(
        record_id=record_id,
        run_id=item.run_id,
        scenario_id=item.scenario_id,
        event_id=item.event_id,
        delivery_id=item.delivery_id,
        attempt_id=item.attempt_id,
        state=state,
        classification=classification,
        error=TransportError(
            category=category,
            message_redacted=message,
            phase=item.prior_state.value,
        ),
    )


def _observation_transition(
    item: ObservationRecoveryItem,
    owner_epoch: int,
    timestamp: TransitionTimestamp,
) -> TransitionCommand[ObservationState]:
    if item.target_state is not ObservationState.ERROR:
        message = "observation recovery item has no automatic error transition"
        raise RecoveryIntegrityError(message)
    return TransitionCommand(
        run_id=item.run_id,
        transition_id=_transition_id(
            item.observation_id,
            ObservationState.ERROR.value,
        ),
        entity_type=EntityType.OBSERVATION,
        entity_id=item.observation_id,
        expected_state=item.prior_state,
        new_state=ObservationState.ERROR,
        trigger_category=TRIGGER_RECOVERY_INTERRUPTED_OBSERVER,
        timestamp=timestamp,
        owner_epoch=owner_epoch,
        idempotency_key=_idempotency_key(
            item.observation_id,
            item.prior_state.value,
            ObservationState.ERROR.value,
        ),
        causal_reference=CausalReference(item.run_id, item.observation_id),
    )


def _delivery_reduction_transition(
    item: _DeliveryReductionRow,
    *,
    owner_epoch: int,
    timestamp: TransitionTimestamp,
) -> TransitionCommand[DeliveryState]:
    target = {
        AttemptState.SUCCEEDED: DeliveryState.SATISFIED,
        AttemptState.CANCELLED: DeliveryState.CANCELLED,
        AttemptState.NOT_SENT: DeliveryState.EXHAUSTED,
        AttemptState.REJECTED: DeliveryState.EXHAUSTED,
        AttemptState.TRANSPORT_FAILED: DeliveryState.EXHAUSTED,
    }.get(item.attempt_state)
    if target is None:
        raise RecoveryIntegrityError("delivery recovery cannot reduce from a nonterminal attempt")
    cause = CausalReference(item.run_id, item.attempt_id)
    return TransitionCommand(
        run_id=item.run_id,
        transition_id=_transition_id(item.delivery_id, target.value),
        entity_type=EntityType.DELIVERY,
        entity_id=item.delivery_id,
        expected_state=DeliveryState.ACTIVE,
        new_state=target,
        trigger_category=TRIGGER_ATTEMPT_OUTCOME,
        timestamp=timestamp,
        owner_epoch=owner_epoch,
        idempotency_key=_idempotency_key(
            item.delivery_id,
            DeliveryState.ACTIVE.value,
            target.value,
        ),
        causal_reference=cause,
        delivery_satisfaction=(
            DeliverySatisfactionEvidence(
                DeliverySatisfactionKind.ATTEMPT,
                cause,
            )
            if target is DeliveryState.SATISFIED
            else None
        ),
    )


def _transition_id(entity_id: str, target_state: str) -> str:
    return f"recovery.{entity_id}.{target_state}"


def _idempotency_key(
    entity_id: str,
    prior_state: str,
    target_state: str,
) -> str:
    return f"recovery.{entity_id}.{prior_state}.{target_state}"


def _validate_wall_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        message = "attempt terminal timestamp is malformed"
        raise RecoveryIntegrityError(message) from error
    if not value.endswith("Z") or parsed.utcoffset() != UTC.utcoffset(parsed):
        message = "attempt terminal timestamp is not canonical UTC"
        raise RecoveryIntegrityError(message)


def _text(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        message = f"{name} is not text"
        raise RecoveryIntegrityError(message)
    return value


def _optional_text(value: object, *, name: str) -> str | None:
    if value is None:
        return None
    return _text(value, name=name)


def _integer(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"{name} is not an integer"
        raise RecoveryIntegrityError(message)
    return value


def _optional_integer(value: object, *, name: str) -> int | None:
    if value is None:
        return None
    return _integer(value, name=name)
