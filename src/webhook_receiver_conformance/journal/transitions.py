"""Executable lifecycle tables and typed journal transition contracts."""
# ruff: noqa: INP001

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from webhook_receiver_conformance.domain.enums import (
    AssertionState,
    AttemptClassification,
    AttemptState,
    DeliveryState,
    ObservationState,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.scheduler.clocks import TransitionTimestamp
from webhook_receiver_conformance.types import DiagnosticCode

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_OWNER_EPOCH = 9_223_372_036_854_775_807
MAX_CONDITION_BYTES = 1_048_576
MAX_REPLAY_TRANSITIONS = 100_000

_BOUNDARY_ID = re.compile(r"[A-Za-z0-9_.:-]+")
_LOWER_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")

type LifecycleState = (
    RunState | ScenarioState | DeliveryState | AttemptState | ObservationState | AssertionState
)
type StateEdge = tuple[str, str]


class EntityType(StrEnum):
    """The six projection kinds owned by the transition ledger."""

    RUN = "run"
    SCENARIO = "scenario"
    DELIVERY = "delivery"
    ATTEMPT = "attempt"
    OBSERVATION = "observation"
    ASSERTION = "assertion"


RUN_EDGES = frozenset(
    {
        (RunState.PLANNED.value, RunState.RUNNING.value),
        (RunState.PLANNED.value, RunState.CANCELLED.value),
        (RunState.PLANNED.value, RunState.FAILED.value),
        (RunState.RUNNING.value, RunState.PAUSED.value),
        (RunState.RUNNING.value, RunState.COMPLETED.value),
        (RunState.RUNNING.value, RunState.CANCELLED.value),
        (RunState.RUNNING.value, RunState.FAILED.value),
        (RunState.PAUSED.value, RunState.RUNNING.value),
        (RunState.PAUSED.value, RunState.CANCELLED.value),
        (RunState.PAUSED.value, RunState.FAILED.value),
    }
)
SCENARIO_EDGES = frozenset(
    {
        (ScenarioState.PENDING.value, ScenarioState.ELIGIBLE.value),
        (ScenarioState.PENDING.value, ScenarioState.SKIPPED.value),
        (ScenarioState.PENDING.value, ScenarioState.ERROR.value),
        (ScenarioState.PENDING.value, ScenarioState.CANCELLED.value),
        (ScenarioState.ELIGIBLE.value, ScenarioState.RUNNING.value),
        (ScenarioState.ELIGIBLE.value, ScenarioState.SKIPPED.value),
        (ScenarioState.ELIGIBLE.value, ScenarioState.ERROR.value),
        (ScenarioState.ELIGIBLE.value, ScenarioState.CANCELLED.value),
        (ScenarioState.RUNNING.value, ScenarioState.PASSED.value),
        (ScenarioState.RUNNING.value, ScenarioState.FAILED.value),
        (ScenarioState.RUNNING.value, ScenarioState.ERROR.value),
        (ScenarioState.RUNNING.value, ScenarioState.SKIPPED.value),
        (ScenarioState.RUNNING.value, ScenarioState.AMBIGUOUS.value),
        (ScenarioState.RUNNING.value, ScenarioState.CANCELLED.value),
    }
)
DELIVERY_EDGES = frozenset(
    {
        (DeliveryState.PENDING.value, DeliveryState.ELIGIBLE.value),
        (DeliveryState.PENDING.value, DeliveryState.SKIPPED.value),
        (DeliveryState.PENDING.value, DeliveryState.CANCELLED.value),
        (DeliveryState.ELIGIBLE.value, DeliveryState.ACTIVE.value),
        (DeliveryState.ELIGIBLE.value, DeliveryState.SKIPPED.value),
        (DeliveryState.ELIGIBLE.value, DeliveryState.CANCELLED.value),
        (DeliveryState.ACTIVE.value, DeliveryState.ELIGIBLE.value),
        (DeliveryState.ACTIVE.value, DeliveryState.SATISFIED.value),
        (DeliveryState.ACTIVE.value, DeliveryState.EXHAUSTED.value),
        (DeliveryState.ACTIVE.value, DeliveryState.AMBIGUOUS.value),
        (DeliveryState.ACTIVE.value, DeliveryState.CANCELLED.value),
    }
)
ATTEMPT_EDGES = frozenset(
    {
        (AttemptState.SCHEDULED.value, AttemptState.CLAIMED.value),
        (AttemptState.SCHEDULED.value, AttemptState.CANCELLED.value),
        (AttemptState.CLAIMED.value, AttemptState.PRE_SEND_COMMITTED.value),
        (AttemptState.CLAIMED.value, AttemptState.NOT_SENT.value),
        (AttemptState.CLAIMED.value, AttemptState.CANCELLED.value),
        (AttemptState.PRE_SEND_COMMITTED.value, AttemptState.CONNECTING.value),
        (AttemptState.PRE_SEND_COMMITTED.value, AttemptState.NOT_SENT.value),
        (AttemptState.PRE_SEND_COMMITTED.value, AttemptState.CANCELLED.value),
        (AttemptState.CONNECTING.value, AttemptState.SENDING.value),
        (AttemptState.CONNECTING.value, AttemptState.NOT_SENT.value),
        (AttemptState.CONNECTING.value, AttemptState.TRANSPORT_FAILED.value),
        (AttemptState.CONNECTING.value, AttemptState.UNKNOWN_OUTCOME.value),
        (AttemptState.CONNECTING.value, AttemptState.CANCELLED.value),
        (AttemptState.SENDING.value, AttemptState.AWAITING_RESPONSE.value),
        (AttemptState.SENDING.value, AttemptState.TRANSPORT_FAILED.value),
        (AttemptState.SENDING.value, AttemptState.UNKNOWN_OUTCOME.value),
        (AttemptState.AWAITING_RESPONSE.value, AttemptState.RESPONSE_OBSERVED.value),
        (AttemptState.AWAITING_RESPONSE.value, AttemptState.TRANSPORT_FAILED.value),
        (AttemptState.AWAITING_RESPONSE.value, AttemptState.UNKNOWN_OUTCOME.value),
        (AttemptState.RESPONSE_OBSERVED.value, AttemptState.SUCCEEDED.value),
        (AttemptState.RESPONSE_OBSERVED.value, AttemptState.REJECTED.value),
        (AttemptState.RESPONSE_OBSERVED.value, AttemptState.TRANSPORT_FAILED.value),
    }
)
OBSERVATION_EDGES = frozenset(
    {
        (ObservationState.SCHEDULED.value, ObservationState.RUNNING.value),
        (ObservationState.SCHEDULED.value, ObservationState.CANCELLED.value),
        (ObservationState.RUNNING.value, ObservationState.OK.value),
        (ObservationState.RUNNING.value, ObservationState.PENDING.value),
        (ObservationState.RUNNING.value, ObservationState.UNSUPPORTED.value),
        (ObservationState.RUNNING.value, ObservationState.ERROR.value),
        (ObservationState.RUNNING.value, ObservationState.TIMED_OUT.value),
        (ObservationState.RUNNING.value, ObservationState.CANCELLED.value),
    }
)
ASSERTION_EDGES = frozenset(
    {
        (AssertionState.PENDING.value, AssertionState.RUNNING.value),
        (AssertionState.PENDING.value, AssertionState.CANCELLED.value),
        (AssertionState.RUNNING.value, AssertionState.PASSED.value),
        (AssertionState.RUNNING.value, AssertionState.FAILED.value),
        (AssertionState.RUNNING.value, AssertionState.ERROR.value),
        (AssertionState.RUNNING.value, AssertionState.UNSUPPORTED.value),
        (AssertionState.RUNNING.value, AssertionState.CANCELLED.value),
    }
)


@dataclass(frozen=True, slots=True)
class StateMachineDefinition:
    """One immutable executable lifecycle state/edge definition."""

    entity_type: EntityType
    state_type: type[StrEnum]
    initial_state: str
    states: frozenset[str]
    edges: frozenset[StateEdge]
    terminal_states: frozenset[str]

    def __post_init__(self) -> None:
        """Require a closed enum, a valid initial state, and coherent edges."""
        enum_values = frozenset(member.value for member in self.state_type)
        if enum_values != self.states:
            message = f"{self.entity_type.value} state definition differs from its enum"
            raise ValueError(message)
        if self.initial_state not in self.states:
            message = f"{self.entity_type.value} initial state is undeclared"
            raise ValueError(message)
        if any(left not in self.states or right not in self.states for left, right in self.edges):
            message = f"{self.entity_type.value} edge references an undeclared state"
            raise ValueError(message)
        if self.terminal_states != self.states - {left for left, _right in self.edges}:
            message = f"{self.entity_type.value} terminal states differ from its edge table"
            raise ValueError(message)

    def allows(self, from_state: str, to_state: str) -> bool:
        """Return whether one exact state pair is an authoritative edge."""
        return (from_state, to_state) in self.edges


def _definition(
    entity_type: EntityType,
    state_type: type[StrEnum],
    initial_state: StrEnum,
    edges: frozenset[StateEdge],
) -> StateMachineDefinition:
    states = frozenset(member.value for member in state_type)
    return StateMachineDefinition(
        entity_type=entity_type,
        state_type=state_type,
        initial_state=initial_state.value,
        states=states,
        edges=edges,
        terminal_states=states - {left for left, _right in edges},
    )


STATE_MACHINES: Mapping[EntityType, StateMachineDefinition] = MappingProxyType(
    {
        EntityType.RUN: _definition(
            EntityType.RUN,
            RunState,
            RunState.PLANNED,
            RUN_EDGES,
        ),
        EntityType.SCENARIO: _definition(
            EntityType.SCENARIO,
            ScenarioState,
            ScenarioState.PENDING,
            SCENARIO_EDGES,
        ),
        EntityType.DELIVERY: _definition(
            EntityType.DELIVERY,
            DeliveryState,
            DeliveryState.PENDING,
            DELIVERY_EDGES,
        ),
        EntityType.ATTEMPT: _definition(
            EntityType.ATTEMPT,
            AttemptState,
            AttemptState.SCHEDULED,
            ATTEMPT_EDGES,
        ),
        EntityType.OBSERVATION: _definition(
            EntityType.OBSERVATION,
            ObservationState,
            ObservationState.SCHEDULED,
            OBSERVATION_EDGES,
        ),
        EntityType.ASSERTION: _definition(
            EntityType.ASSERTION,
            AssertionState,
            AssertionState.PENDING,
            ASSERTION_EDGES,
        ),
    }
)


class TransitionError(RuntimeError):
    """A classified transition or projection failure."""

    category: ErrorCategory = ErrorCategory.ILLEGAL_TRANSITION
    code: DiagnosticCode = DiagnosticCode("JOURNAL_ILLEGAL_TRANSITION")


class IllegalTransitionError(TransitionError):
    """A requested state pair or guard is not authoritative."""


class StaleOwnerEpochError(IllegalTransitionError):
    """A writer command does not carry the current run owner epoch."""

    code = DiagnosticCode("JOURNAL_STALE_OWNER_EPOCH")


class CrossRunReferenceError(IllegalTransitionError):
    """An entity or causal reference belongs to a different run."""

    code = DiagnosticCode("JOURNAL_CROSS_RUN_REFERENCE")


class IdempotencyConflictError(TransitionError):
    """An idempotency key or transition ID names different semantics."""

    category = ErrorCategory.INTEGRITY_ERROR
    code = DiagnosticCode("JOURNAL_IDEMPOTENCY_CONFLICT")


class ProjectionIntegrityError(TransitionError):
    """Projection rows and ordered append history do not agree."""

    category = ErrorCategory.INTEGRITY_ERROR
    code = DiagnosticCode("JOURNAL_PROJECTION_INTEGRITY")


class DeliverySatisfactionKind(StrEnum):
    """Auditable evidence classes allowed to satisfy a delivery."""

    ATTEMPT = "attempt"
    ASSERTION_POLICY = "assertion_policy"


@dataclass(frozen=True, slots=True)
class CausalReference:
    """One run-scoped causal record reference persisted on a transition."""

    run_id: str
    record_id: str

    def __post_init__(self) -> None:
        """Validate run identity and the schema-bounded record token."""
        validate_run_id(self.run_id)
        _bounded_token(self.record_id, name="causal record ID", maximum=96)


@dataclass(frozen=True, slots=True)
class DeliverySatisfactionEvidence:
    """Explicit same-run evidence authorizing delivery satisfaction."""

    kind: DeliverySatisfactionKind
    cause: CausalReference

    def __post_init__(self) -> None:
        """Require exact typed satisfaction evidence."""
        if type(self.kind) is not DeliverySatisfactionKind:
            message = "delivery satisfaction kind must be a DeliverySatisfactionKind"
            raise TypeError(message)
        if type(self.cause) is not CausalReference:
            message = "delivery satisfaction cause must be a CausalReference"
            raise TypeError(message)


@dataclass(frozen=True, slots=True)
class RetrySchedule:
    """One derived persistent retry schedule inserted with a terminal outcome."""

    schedule_entry_id: str
    scenario_id: str
    entity_type: str
    entity_id: str
    logical_time_ns: int
    scenario_ordinal: int
    step_ordinal: int
    delivery_ordinal: int
    attempt_ordinal: int
    deterministic_tie_key: str
    idempotency_key: str
    predecessor_attempt_id: str
    condition_json: bytes | None = None

    def __post_init__(self) -> None:
        """Validate every persisted schedule boundary without interpreting policy."""
        _bounded_token(self.schedule_entry_id, name="schedule entry ID", maximum=96)
        validate_planned_id(self.scenario_id, expected_kind=PlannedIdKind.SCENARIO)
        _lower_identifier(self.entity_type, name="schedule entity type", maximum=64)
        _bounded_token(self.entity_id, name="schedule entity ID", maximum=96)
        _safe_integer(self.logical_time_ns, name="schedule logical time", signed=True)
        _safe_integer(self.scenario_ordinal, name="scenario ordinal")
        _safe_integer(self.step_ordinal, name="step ordinal")
        _safe_integer(self.delivery_ordinal, name="delivery ordinal")
        _safe_integer(self.attempt_ordinal, name="attempt ordinal")
        _bounded_token(
            self.deterministic_tie_key,
            name="deterministic tie key",
            maximum=256,
        )
        _bounded_token(self.idempotency_key, name="schedule idempotency key", maximum=256)
        validate_fresh_id(
            self.predecessor_attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
        if self.condition_json is not None and (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.condition_json,
                bytes,
            )
            or len(self.condition_json) > MAX_CONDITION_BYTES
        ):
            message = "retry condition_json must be bounded bytes"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class AttemptTerminalOutcome:
    """Terminal attempt projection fields plus an optional atomic retry schedule."""

    classification: AttemptClassification
    retry_schedule: RetrySchedule | None = None

    def __post_init__(self) -> None:
        """Require exact classification and retry schedule types."""
        if type(self.classification) is not AttemptClassification:
            message = "attempt classification must be an AttemptClassification"
            raise TypeError(message)
        if self.retry_schedule is not None and type(self.retry_schedule) is not RetrySchedule:
            message = "retry_schedule must be a RetrySchedule"
            raise TypeError(message)


@dataclass(frozen=True, slots=True)
class TransitionCommand[S: LifecycleState]:
    """One typed, guarded, idempotent projection transition command."""

    run_id: str
    transition_id: str
    entity_type: EntityType
    entity_id: str
    expected_state: S | None
    new_state: S
    trigger_category: str
    timestamp: TransitionTimestamp
    owner_epoch: int
    idempotency_key: str
    causal_reference: CausalReference | None = None
    logical_time_ns: int | None = None
    delivery_satisfaction: DeliverySatisfactionEvidence | None = None
    attempt_outcome: AttemptTerminalOutcome | None = None

    def __post_init__(self) -> None:
        """Validate command shape while leaving edge and database guards executable."""
        validate_run_id(self.run_id)
        if type(self.entity_type) is not EntityType:
            message = "entity_type must be an EntityType"
            raise TypeError(message)
        validate_entity_id(self.entity_type, self.entity_id, run_id=self.run_id)
        _bounded_token(self.transition_id, name="transition ID", maximum=96)
        _lower_identifier(self.trigger_category, name="trigger category", maximum=64)
        _bounded_token(self.idempotency_key, name="idempotency key", maximum=256)
        _owner_epoch(self.owner_epoch)
        if self.logical_time_ns is not None:
            _safe_integer(self.logical_time_ns, name="logical time", signed=True)
        if type(self.timestamp) is not TransitionTimestamp:
            message = "timestamp must be a TransitionTimestamp"
            raise TypeError(message)
        if (
            self.timestamp.monotonic_elapsed_ns is not None
            and self.timestamp.monotonic_elapsed_ns > MAX_SAFE_INTEGER
        ):
            message = "live monotonic elapsed time exceeds the journal boundary"
            raise ValueError(message)
        machine = state_machine(self.entity_type)
        if type(self.new_state) is not machine.state_type:
            message = f"new_state must use {machine.state_type.__name__}"
            raise TypeError(message)
        if self.expected_state is not None and type(self.expected_state) is not machine.state_type:
            message = f"expected_state must use {machine.state_type.__name__}"
            raise TypeError(message)
        if self.causal_reference is not None and type(self.causal_reference) is not CausalReference:
            message = "causal_reference must be a CausalReference"
            raise TypeError(message)
        if (
            self.delivery_satisfaction is not None
            and type(self.delivery_satisfaction) is not DeliverySatisfactionEvidence
        ):
            message = "delivery_satisfaction must be DeliverySatisfactionEvidence"
            raise TypeError(message)
        if (
            self.attempt_outcome is not None
            and type(self.attempt_outcome) is not AttemptTerminalOutcome
        ):
            message = "attempt_outcome must be AttemptTerminalOutcome"
            raise TypeError(message)


@dataclass(frozen=True, slots=True)
class TransitionRecord:
    """One normalized immutable transition ledger record."""

    transition_id: str
    run_id: str
    sequence: int
    entity_type: EntityType
    entity_id: str
    from_state: LifecycleState | None
    to_state: LifecycleState
    trigger_category: str
    causal_record_id: str | None
    timestamp: TransitionTimestamp
    logical_time_ns: int | None
    owner_epoch: int
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class CommittedTransition:
    """The durable record plus whether an idempotency replay found it."""

    record: TransitionRecord
    idempotent_replay: bool


@dataclass(frozen=True, slots=True)
class ProjectionState:
    """Lifecycle-only projection identity reconstructed from append history."""

    run_id: str
    entity_type: EntityType
    entity_id: str
    state: LifecycleState


@dataclass(frozen=True, slots=True)
class ProjectionMismatch:
    """One missing or divergent state-projection identity."""

    run_id: str
    entity_type: EntityType
    entity_id: str
    projected_state: LifecycleState | None
    replayed_state: LifecycleState | None


@dataclass(frozen=True, slots=True)
class ProjectionAudit:
    """A deterministic comparison of live and replayed lifecycle inventories."""

    projected: tuple[ProjectionState, ...]
    replayed: tuple[ProjectionState, ...]
    mismatches: tuple[ProjectionMismatch, ...]

    @property
    def matches(self) -> bool:
        """Return whether every lifecycle projection equals append history."""
        return not self.mismatches


@dataclass(frozen=True, slots=True)
class StateMachineComparison:
    """Value-level differences between executable and external definitions."""

    missing_states: frozenset[str]
    unexpected_states: frozenset[str]
    missing_edges: frozenset[StateEdge]
    unexpected_edges: frozenset[StateEdge]
    missing_initial_states: frozenset[str]
    unexpected_initial_states: frozenset[str]
    missing_terminal_states: frozenset[str]
    unexpected_terminal_states: frozenset[str]

    @property
    def matches(self) -> bool:
        """Return whether state and edge values are byte-for-value equal."""
        return not (
            self.missing_states
            or self.unexpected_states
            or self.missing_edges
            or self.unexpected_edges
            or self.missing_initial_states
            or self.unexpected_initial_states
            or self.missing_terminal_states
            or self.unexpected_terminal_states
        )


def state_machine(entity_type: EntityType) -> StateMachineDefinition:
    """Return the immutable executable definition for one entity kind."""
    if type(entity_type) is not EntityType:
        message = "entity_type must be an EntityType"
        raise TypeError(message)
    return STATE_MACHINES[entity_type]


def parse_state(entity_type: EntityType, value: object) -> LifecycleState:
    """Parse one database state through the entity's exact enum."""
    if not isinstance(value, str):
        message = f"{entity_type.value} projection state is not text"
        raise ProjectionIntegrityError(message)
    machine = state_machine(entity_type)
    try:
        return cast("LifecycleState", machine.state_type(value))
    except ValueError as error:
        message = f"{entity_type.value} projection contains an undeclared state"
        raise ProjectionIntegrityError(message) from error


def transition_allowed(
    entity_type: EntityType,
    from_state: LifecycleState,
    to_state: LifecycleState,
) -> bool:
    """Return whether the typed pair is one authoritative executable edge."""
    machine = state_machine(entity_type)
    if type(from_state) is not machine.state_type or type(to_state) is not machine.state_type:
        return False
    return machine.allows(from_state.value, to_state.value)


def compare_state_machine_definition(
    entity_type: EntityType,
    *,
    states: Iterable[str],
    edges: Iterable[StateEdge],
    initial_states: Iterable[str] | None = None,
    terminal_states: Iterable[str] | None = None,
) -> StateMachineComparison:
    """Compare a diagram/table definition with the executable state machine."""
    machine = state_machine(entity_type)
    external_states = frozenset(states)
    external_edges = frozenset(edges)
    expected_initial_states = frozenset({machine.initial_state})
    external_initial_states = (
        expected_initial_states if initial_states is None else frozenset(initial_states)
    )
    external_terminal_states = (
        machine.terminal_states if terminal_states is None else frozenset(terminal_states)
    )
    return StateMachineComparison(
        missing_states=machine.states - external_states,
        unexpected_states=external_states - machine.states,
        missing_edges=machine.edges - external_edges,
        unexpected_edges=external_edges - machine.edges,
        missing_initial_states=expected_initial_states - external_initial_states,
        unexpected_initial_states=external_initial_states - expected_initial_states,
        missing_terminal_states=machine.terminal_states - external_terminal_states,
        unexpected_terminal_states=external_terminal_states - machine.terminal_states,
    )


def replay_transition_records(
    records: Sequence[TransitionRecord],
) -> tuple[ProjectionState, ...]:
    """Replay strictly ordered history into an empty lifecycle inventory."""
    if len(records) > MAX_REPLAY_TRANSITIONS:
        message = "transition replay exceeds the bounded inventory limit"
        raise ProjectionIntegrityError(message)
    current: dict[tuple[str, EntityType, str], LifecycleState] = {}
    transition_ids: set[str] = set()
    idempotency_keys: set[tuple[str, str]] = set()
    prior_sequence: dict[str, int] = {}
    for record in records:
        if type(record) is not TransitionRecord:
            message = "transition replay accepts only TransitionRecord values"
            raise TypeError(message)
        previous_sequence = prior_sequence.get(record.run_id, 0)
        if record.sequence <= previous_sequence:
            message = "transition replay sequence is not strictly increasing"
            raise ProjectionIntegrityError(message)
        prior_sequence[record.run_id] = record.sequence
        if record.transition_id in transition_ids:
            message = "transition replay contains a duplicate transition ID"
            raise ProjectionIntegrityError(message)
        transition_ids.add(record.transition_id)
        idempotency_identity = (record.run_id, record.idempotency_key)
        if idempotency_identity in idempotency_keys:
            message = "transition replay contains a duplicate idempotency key"
            raise ProjectionIntegrityError(message)
        idempotency_keys.add(idempotency_identity)
        identity = (record.run_id, record.entity_type, record.entity_id)
        existing = current.get(identity)
        machine = state_machine(record.entity_type)
        if existing is None:
            if record.from_state is not None or record.to_state.value != machine.initial_state:
                message = "transition history does not begin at the authoritative initial state"
                raise ProjectionIntegrityError(message)
        elif record.from_state != existing or not machine.allows(
            existing.value, record.to_state.value
        ):
            message = "transition history contains an illegal or discontinuous edge"
            raise ProjectionIntegrityError(message)
        current[identity] = record.to_state
    return tuple(
        ProjectionState(
            run_id=run_id,
            entity_type=entity_type,
            entity_id=entity_id,
            state=state,
        )
        for (run_id, entity_type, entity_id), state in sorted(
            current.items(),
            key=lambda item: (
                item[0][0],
                tuple(EntityType).index(item[0][1]),
                item[0][2],
            ),
        )
    )


def compare_projection_inventories(
    projected: Sequence[ProjectionState],
    replayed: Sequence[ProjectionState],
) -> ProjectionAudit:
    """Return deterministic missing/divergent lifecycle identities."""
    projected_map = _projection_map(projected)
    replayed_map = _projection_map(replayed)
    identities = sorted(
        projected_map.keys() | replayed_map.keys(),
        key=lambda item: (item[0], tuple(EntityType).index(item[1]), item[2]),
    )
    mismatches = tuple(
        ProjectionMismatch(
            run_id=identity[0],
            entity_type=identity[1],
            entity_id=identity[2],
            projected_state=projected_map.get(identity),
            replayed_state=replayed_map.get(identity),
        )
        for identity in identities
        if projected_map.get(identity) != replayed_map.get(identity)
    )
    return ProjectionAudit(
        projected=tuple(projected),
        replayed=tuple(replayed),
        mismatches=mismatches,
    )


def _projection_map(
    inventory: Sequence[ProjectionState],
) -> dict[tuple[str, EntityType, str], LifecycleState]:
    result: dict[tuple[str, EntityType, str], LifecycleState] = {}
    for projection in inventory:
        if type(projection) is not ProjectionState:
            message = "projection inventory accepts only ProjectionState values"
            raise TypeError(message)
        identity = (
            projection.run_id,
            projection.entity_type,
            projection.entity_id,
        )
        if identity in result:
            message = "projection inventory contains a duplicate entity identity"
            raise ProjectionIntegrityError(message)
        result[identity] = projection.state
    return result


def validate_entity_id(
    entity_type: EntityType,
    entity_id: str,
    *,
    run_id: str,
) -> None:
    """Validate one entity ID against its exact lifecycle kind."""
    if entity_type is EntityType.RUN:
        validate_run_id(entity_id)
        if entity_id != run_id:
            message = "run transition entity_id must equal run_id"
            raise ValueError(message)
    elif entity_type is EntityType.SCENARIO:
        validate_planned_id(entity_id, expected_kind=PlannedIdKind.SCENARIO)
    elif entity_type is EntityType.DELIVERY:
        validate_planned_id(entity_id, expected_kind=PlannedIdKind.DELIVERY)
    elif entity_type is EntityType.ATTEMPT:
        validate_fresh_id(entity_id, expected_kind=FreshIdKind.ATTEMPT)
    elif entity_type is EntityType.OBSERVATION:
        validate_planned_id(entity_id, expected_kind=PlannedIdKind.OBSERVATION)
    else:
        validate_planned_id(entity_id, expected_kind=PlannedIdKind.ASSERTION)


def _bounded_token(value: object, *, name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or _BOUNDARY_ID.fullmatch(value) is None
    ):
        message = f"{name} must be a bounded ASCII token"
        raise ValueError(message)
    return value


def _lower_identifier(value: object, *, name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or _LOWER_IDENTIFIER.fullmatch(value) is None
    ):
        message = f"{name} must be a bounded lowercase identifier"
        raise ValueError(message)
    return value


def _safe_integer(value: object, *, name: str, signed: bool = False) -> int:
    minimum = -MAX_SAFE_INTEGER if signed else 0
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= MAX_SAFE_INTEGER
    ):
        message = f"{name} exceeds its integer boundary"
        raise ValueError(message)
    return value


def _owner_epoch(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_OWNER_EPOCH:
        message = "owner_epoch exceeds its integer boundary"
        raise ValueError(message)
    return value
