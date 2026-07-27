"""Immutable, privacy-safe models for conservative fresh-process recovery."""
# ruff: noqa: INP001

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

from webhook_receiver_conformance.domain.enums import (
    AttemptState,
    ObservationState,
    RunState,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.journal.integrity import ResumeIntegrityReport
from webhook_receiver_conformance.journal.run_lock import (
    MAX_OWNER_EPOCH,
    RunLockMetadata,
)
from webhook_receiver_conformance.journal.transitions import MAX_SAFE_INTEGER


class DurableNoSendProof(StrEnum):
    """Closed durable phase evidence that can establish no application send."""

    NONE = "none"
    CONTROLLED_PRE_TRANSPORT = "controlled_pre_transport"
    NO_CONNECTION_ESTABLISHED = "no_connection_established"


class AttemptRecoveryAction(StrEnum):
    """Conservative action selected for one persisted attempt projection."""

    RESUME_SCHEDULED = "resume_scheduled"
    RECLAIM_EXPIRED_CLAIM = "reclaim_expired_claim"
    REQUIRE_PHASE_EVIDENCE = "require_phase_evidence"
    TERMINATE_NOT_SENT = "terminate_not_sent"
    TERMINATE_UNKNOWN_OUTCOME = "terminate_unknown_outcome"
    REDUCE_DURABLE_RESPONSE = "reduce_durable_response"
    PRESERVE_TERMINAL = "preserve_terminal"
    PRESERVE_UNKNOWN_OUTCOME = "preserve_unknown_outcome"


class ObservationRecoveryAction(StrEnum):
    """Safe action selected for one persisted observation series."""

    RESUME_SCHEDULED = "resume_scheduled"
    TERMINATE_INTERRUPTED_ERROR = "terminate_interrupted_error"
    PRESERVE_TERMINAL = "preserve_terminal"


class RecoveryAmbiguity(StrEnum):
    """Whether recovery evidence leaves a possible receiver effect unresolved."""

    NONE = "none"
    PHASE_EVIDENCE_REQUIRED = "phase_evidence_required"
    POSSIBLE_RECEIVER_EFFECT = "possible_receiver_effect"


@dataclass(frozen=True, slots=True)
class RecoveryScanContext:
    """Proof that integrity and fresh owner checks preceded recovery scanning."""

    run_id: str
    owner_epoch: int
    integrity: ResumeIntegrityReport
    owner: RunLockMetadata

    def __post_init__(self) -> None:
        """Require one matching, current, successfully verified run identity."""
        validate_run_id(self.run_id)
        _nonnegative_integer(
            self.owner_epoch,
            name="owner_epoch",
            maximum=MAX_OWNER_EPOCH,
        )
        if type(self.integrity) is not ResumeIntegrityReport:
            message = "recovery scan requires a ResumeIntegrityReport"
            raise TypeError(message)
        if type(self.owner) is not RunLockMetadata:
            message = "recovery scan requires validated RunLockMetadata"
            raise TypeError(message)
        if self.owner.run_id != self.run_id:
            message = "recovery owner belongs to a different run"
            raise ValueError(message)
        if self.owner.owner_epoch != self.owner_epoch:
            message = "recovery owner epoch differs from the scan epoch"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class AttemptRecoveryItem:
    """One normalized attempt classification without raw request or phase text."""

    run_id: str
    scenario_id: str
    event_id: str
    delivery_id: str
    attempt_id: str
    scenario_ordinal: int
    step_ordinal: int
    delivery_ordinal: int
    attempt_ordinal: int
    prior_state: AttemptState
    durable_no_send_proof: DurableNoSendProof
    action: AttemptRecoveryAction
    ambiguity: RecoveryAmbiguity
    target_state: AttemptState | None

    def __post_init__(self) -> None:
        """Validate typed identities, ordering coordinates, and action coherence."""
        validate_run_id(self.run_id)
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)
        validate_planned_id(
            self.delivery_id,
            expected_kind=PlannedIdKind.DELIVERY,
        )
        validate_fresh_id(self.attempt_id, expected_kind=FreshIdKind.ATTEMPT)
        for name, value in (
            ("scenario_ordinal", self.scenario_ordinal),
            ("step_ordinal", self.step_ordinal),
            ("delivery_ordinal", self.delivery_ordinal),
            ("attempt_ordinal", self.attempt_ordinal),
        ):
            _nonnegative_integer(value, name=name, maximum=MAX_SAFE_INTEGER)
        if type(self.prior_state) is not AttemptState:
            message = "prior_state must be an AttemptState"
            raise TypeError(message)
        if type(self.durable_no_send_proof) is not DurableNoSendProof:
            message = "durable_no_send_proof must use the closed proof enum"
            raise TypeError(message)
        if type(self.action) is not AttemptRecoveryAction:
            message = "action must be an AttemptRecoveryAction"
            raise TypeError(message)
        if type(self.ambiguity) is not RecoveryAmbiguity:
            message = "ambiguity must be a RecoveryAmbiguity"
            raise TypeError(message)
        if self.target_state is not None and type(self.target_state) is not AttemptState:
            message = "target_state must be an AttemptState or None"
            raise TypeError(message)
        _validate_attempt_action(self)

    @property
    def requires_transition(self) -> bool:
        """Return whether applying this item appends a terminal transition."""
        return self.target_state is not None

    @property
    def deterministic_key(self) -> tuple[int, int, int, int, str]:
        """Return the manifest-ordered recovery identity."""
        return (
            self.scenario_ordinal,
            self.step_ordinal,
            self.delivery_ordinal,
            self.attempt_ordinal,
            self.attempt_id,
        )


@dataclass(frozen=True, slots=True)
class ObservationRecoveryItem:
    """One observation-series classification without configured observer data."""

    run_id: str
    scenario_id: str
    observation_id: str
    scenario_ordinal: int
    prior_state: ObservationState
    action: ObservationRecoveryAction
    target_state: ObservationState | None

    def __post_init__(self) -> None:
        """Validate identities, ordering, and observation action coherence."""
        validate_run_id(self.run_id)
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_planned_id(
            self.observation_id,
            expected_kind=PlannedIdKind.OBSERVATION,
        )
        _nonnegative_integer(
            self.scenario_ordinal,
            name="scenario_ordinal",
            maximum=MAX_SAFE_INTEGER,
        )
        if type(self.prior_state) is not ObservationState:
            message = "prior_state must be an ObservationState"
            raise TypeError(message)
        if type(self.action) is not ObservationRecoveryAction:
            message = "action must be an ObservationRecoveryAction"
            raise TypeError(message)
        if self.target_state is not None and type(self.target_state) is not ObservationState:
            message = "target_state must be an ObservationState or None"
            raise TypeError(message)
        expected_target = (
            ObservationState.ERROR
            if self.action is ObservationRecoveryAction.TERMINATE_INTERRUPTED_ERROR
            else None
        )
        if self.target_state is not expected_target:
            message = "observation recovery action and target state disagree"
            raise ValueError(message)
        if (
            self.action is ObservationRecoveryAction.RESUME_SCHEDULED
            and self.prior_state is not ObservationState.SCHEDULED
        ):
            message = "only scheduled observations can resume without a transition"
            raise ValueError(message)
        if (
            self.action is ObservationRecoveryAction.TERMINATE_INTERRUPTED_ERROR
            and self.prior_state is not ObservationState.RUNNING
        ):
            message = "only an interrupted running observation becomes error"
            raise ValueError(message)
        if self.action is ObservationRecoveryAction.PRESERVE_TERMINAL and self.prior_state not in {
            ObservationState.OK,
            ObservationState.PENDING,
            ObservationState.UNSUPPORTED,
            ObservationState.ERROR,
            ObservationState.TIMED_OUT,
            ObservationState.CANCELLED,
        }:
            message = "preserved observation state is not terminal"
            raise ValueError(message)

    @property
    def requires_transition(self) -> bool:
        """Return whether applying this item appends an error transition."""
        return self.target_state is not None

    @property
    def deterministic_key(self) -> tuple[int, str]:
        """Return the manifest-ordered recovery identity."""
        return (self.scenario_ordinal, self.observation_id)


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    """One bounded, deterministic scan result with no network policy action."""

    run_id: str
    owner_epoch: int
    run_state: RunState
    attempts: tuple[AttemptRecoveryItem, ...]
    observations: tuple[ObservationRecoveryItem, ...]

    def __post_init__(self) -> None:
        """Require a same-run, unique, deterministically ordered inventory."""
        validate_run_id(self.run_id)
        _nonnegative_integer(
            self.owner_epoch,
            name="owner_epoch",
            maximum=MAX_OWNER_EPOCH,
        )
        if type(self.run_state) is not RunState:
            message = "run_state must be a RunState"
            raise TypeError(message)
        _validate_plan_inventories(self)

    @property
    def contains_ambiguity(self) -> bool:
        """Return whether any attempt needs evidence or preserves possible effect."""
        return any(item.ambiguity is not RecoveryAmbiguity.NONE for item in self.attempts)

    @property
    def automatic_transition_count(self) -> int:
        """Return the number of safe journal transitions in this plan."""
        return sum(item.requires_transition for item in self.attempts) + sum(
            item.requires_transition for item in self.observations
        )

    @property
    def performs_network_io(self) -> bool:
        """Recovery scanning and automatic classification never contact a receiver."""
        return False


_ATTEMPT_ACTION_PRIOR_STATES: Mapping[
    AttemptRecoveryAction,
    frozenset[AttemptState],
] = MappingProxyType(
    {
        AttemptRecoveryAction.RESUME_SCHEDULED: frozenset({AttemptState.SCHEDULED}),
        AttemptRecoveryAction.RECLAIM_EXPIRED_CLAIM: frozenset({AttemptState.CLAIMED}),
        AttemptRecoveryAction.REQUIRE_PHASE_EVIDENCE: frozenset({AttemptState.PRE_SEND_COMMITTED}),
        AttemptRecoveryAction.TERMINATE_NOT_SENT: frozenset(
            {
                AttemptState.PRE_SEND_COMMITTED,
                AttemptState.CONNECTING,
            }
        ),
        AttemptRecoveryAction.TERMINATE_UNKNOWN_OUTCOME: frozenset(
            {
                AttemptState.CONNECTING,
                AttemptState.SENDING,
                AttemptState.AWAITING_RESPONSE,
            }
        ),
        AttemptRecoveryAction.REDUCE_DURABLE_RESPONSE: frozenset({AttemptState.RESPONSE_OBSERVED}),
        AttemptRecoveryAction.PRESERVE_TERMINAL: frozenset(
            {
                AttemptState.NOT_SENT,
                AttemptState.SUCCEEDED,
                AttemptState.REJECTED,
                AttemptState.TRANSPORT_FAILED,
                AttemptState.CANCELLED,
            }
        ),
        AttemptRecoveryAction.PRESERVE_UNKNOWN_OUTCOME: frozenset({AttemptState.UNKNOWN_OUTCOME}),
    }
)
_ATTEMPT_ACTION_TARGETS: Mapping[
    AttemptRecoveryAction,
    AttemptState | None,
] = MappingProxyType(
    {
        AttemptRecoveryAction.TERMINATE_NOT_SENT: AttemptState.NOT_SENT,
        AttemptRecoveryAction.TERMINATE_UNKNOWN_OUTCOME: (AttemptState.UNKNOWN_OUTCOME),
    }
)
_ATTEMPT_ACTION_AMBIGUITY: Mapping[
    AttemptRecoveryAction,
    RecoveryAmbiguity,
] = MappingProxyType(
    {
        AttemptRecoveryAction.REQUIRE_PHASE_EVIDENCE: (RecoveryAmbiguity.PHASE_EVIDENCE_REQUIRED),
        AttemptRecoveryAction.TERMINATE_UNKNOWN_OUTCOME: (
            RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT
        ),
        AttemptRecoveryAction.PRESERVE_UNKNOWN_OUTCOME: (
            RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT
        ),
    }
)


def _validate_plan_inventories(plan: RecoveryPlan) -> None:
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        plan.attempts,
        tuple,
    ) or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        plan.observations,
        tuple,
    ):
        message = "recovery inventories must be immutable tuples"
        raise TypeError(message)
    if any(type(item) is not AttemptRecoveryItem for item in plan.attempts):
        message = "attempt inventory contains an invalid item"
        raise TypeError(message)
    if any(type(item) is not ObservationRecoveryItem for item in plan.observations):
        message = "observation inventory contains an invalid item"
        raise TypeError(message)
    if any(item.run_id != plan.run_id for item in plan.attempts) or any(
        item.run_id != plan.run_id for item in plan.observations
    ):
        message = "recovery inventory contains an item from another run"
        raise ValueError(message)
    if len({item.attempt_id for item in plan.attempts}) != len(plan.attempts) or len(
        {item.observation_id for item in plan.observations}
    ) != len(plan.observations):
        message = "recovery inventory contains duplicate identities"
        raise ValueError(message)
    if plan.attempts != tuple(sorted(plan.attempts, key=lambda item: item.deterministic_key)):
        message = "attempt recovery inventory is not deterministically ordered"
        raise ValueError(message)
    if plan.observations != tuple(
        sorted(plan.observations, key=lambda item: item.deterministic_key)
    ):
        message = "observation recovery inventory is not deterministically ordered"
        raise ValueError(message)


def _validate_attempt_action(item: AttemptRecoveryItem) -> None:
    expected_target = _ATTEMPT_ACTION_TARGETS.get(item.action)
    if item.target_state is not expected_target:
        message = "attempt recovery action and target state disagree"
        raise ValueError(message)
    if item.prior_state not in _ATTEMPT_ACTION_PRIOR_STATES[item.action]:
        message = f"{item.action.value} is invalid from {item.prior_state.value}"
        raise ValueError(message)
    expected_ambiguity = _ATTEMPT_ACTION_AMBIGUITY.get(
        item.action,
        RecoveryAmbiguity.NONE,
    )
    if item.ambiguity is not expected_ambiguity:
        message = "attempt recovery action and ambiguity disagree"
        raise ValueError(message)
    expected_proof = _expected_no_send_proof(item)
    if item.durable_no_send_proof is not expected_proof:
        message = "attempt recovery action carries invalid no-send proof"
        raise ValueError(message)


def _expected_no_send_proof(item: AttemptRecoveryItem) -> DurableNoSendProof:
    if item.action is not AttemptRecoveryAction.TERMINATE_NOT_SENT:
        return DurableNoSendProof.NONE
    if item.prior_state is AttemptState.PRE_SEND_COMMITTED:
        return DurableNoSendProof.CONTROLLED_PRE_TRANSPORT
    return DurableNoSendProof.NO_CONNECTION_ESTABLISHED


def _nonnegative_integer(
    value: object,
    *,
    name: str,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        message = f"{name} must be a bounded nonnegative integer"
        raise ValueError(message)
    return value
