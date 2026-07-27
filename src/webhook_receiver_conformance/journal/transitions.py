"""Executable lifecycle tables and typed journal transition contracts."""
# ruff: noqa: D105, EM101, EM102, INP001, PLR2004, TRY003

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from webhook_receiver_conformance.domain.enums import (
    AssertionState,
    AttemptClassification,
    AttemptEvidenceState,
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
from webhook_receiver_conformance.domain.models import (
    RequestMetadata,
    ResponseMetadata,
    TransportError,
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
MAX_REQUEST_HEADER_NAMES = 256
MAX_REQUEST_HEADER_NAME_BYTES = 256
MAX_REQUEST_HEADER_NAMES_JSON_BYTES = 16_384

_BOUNDARY_ID = re.compile(r"[A-Za-z0-9_.:-]+")
_LOWER_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")
_LOWER_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9a-z]+")

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


class AttemptPhaseEvidence(StrEnum):
    """Closed privacy-safe progress/proof vocabulary persisted for recovery."""

    CONTROLLED_PRE_TRANSPORT = "controlled_pre_transport"
    NO_CONNECTION_ESTABLISHED = "no_connection_established"
    CONNECTION_ATTEMPT_STARTED = "connection_attempt_started"
    REQUEST_SEND_STARTED = "request_send_started"
    AWAITING_RESPONSE = "awaiting_response"
    RESPONSE_OBSERVED = "response_observed"


@dataclass(frozen=True, slots=True)
class AttemptPhaseEvidenceCommand:
    """Digest-only phase evidence committed with one attempt transition."""

    phase: AttemptPhaseEvidence
    request_blob_hash: str | None = None
    request_headers_hash: str | None = None

    def __post_init__(self) -> None:
        if type(self.phase) is not AttemptPhaseEvidence:
            raise TypeError("phase must be an AttemptPhaseEvidence")
        for value, name in (
            (self.request_blob_hash, "request body digest"),
            (self.request_headers_hash, "request headers digest"),
        ):
            if value is not None and (
                type(value) is not str
                or len(value) != 71
                or not value.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in value[7:])
            ):
                raise ValueError(f"{name} must be a lowercase sha256 digest")


@dataclass(frozen=True, slots=True)
class AttemptTransportEvidenceCommand:
    """Sanitized final attempt evidence whose ordering/times are journal-owned."""

    record_id: str
    run_id: str
    scenario_id: str
    event_id: str
    delivery_id: str
    attempt_id: str
    state: AttemptEvidenceState
    classification: AttemptClassification
    request: RequestMetadata | None = None
    response: ResponseMetadata | None = None
    error: TransportError | None = None

    def __post_init__(self) -> None:
        validate_fresh_id(self.record_id, expected_kind=FreshIdKind.RECORD)
        validate_run_id(self.run_id)
        validate_planned_id(self.scenario_id, expected_kind=PlannedIdKind.SCENARIO)
        validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)
        validate_planned_id(self.delivery_id, expected_kind=PlannedIdKind.DELIVERY)
        validate_fresh_id(self.attempt_id, expected_kind=FreshIdKind.ATTEMPT)
        if type(self.state) is not AttemptEvidenceState:
            raise TypeError("transport evidence state must be an AttemptEvidenceState")
        if type(self.classification) is not AttemptClassification:
            raise TypeError("transport evidence classification must be an AttemptClassification")
        if self.request is not None:
            if type(self.request) is not RequestMetadata:
                raise TypeError("transport request evidence must be RequestMetadata or None")
            _validate_request_metadata(self.request)
        if self.response is not None and type(self.response) is not ResponseMetadata:
            raise TypeError("transport response evidence must be ResponseMetadata or None")
        if self.error is not None:
            if type(self.error) is not TransportError:
                raise TypeError("transport error evidence must be TransportError or None")
            _validate_transport_error(self.error)
        _validate_transport_evidence_shape(self)

    @property
    def request_header_names_json(self) -> bytes | None:
        """Return the canonical bounded JSON BLOB persisted for header names."""
        return canonical_request_header_names_json(self.request)


@dataclass(frozen=True, slots=True)
class AttemptScheduleClaim:
    """Create and claim one physical attempt from one persisted schedule."""

    schedule_entry_id: str
    attempt_id: str
    attempt_plan_id: str
    event_id: str
    delivery_id: str
    predecessor_attempt_id: str | None
    condition_json: bytes | None
    claim_transition: TransitionCommand[AttemptState]

    def __post_init__(self) -> None:
        _bounded_token(self.schedule_entry_id, name="schedule entry ID", maximum=96)
        validate_fresh_id(self.attempt_id, expected_kind=FreshIdKind.ATTEMPT)
        validate_planned_id(
            self.attempt_plan_id,
            expected_kind=PlannedIdKind.ATTEMPT_PLAN,
        )
        validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)
        validate_planned_id(self.delivery_id, expected_kind=PlannedIdKind.DELIVERY)
        if self.predecessor_attempt_id is not None:
            validate_fresh_id(
                self.predecessor_attempt_id,
                expected_kind=FreshIdKind.ATTEMPT,
            )
        if self.condition_json is not None and (
            type(self.condition_json) is not bytes or len(self.condition_json) > MAX_CONDITION_BYTES
        ):
            raise ValueError("condition_json must be bounded immutable bytes")
        if type(self.claim_transition) is not TransitionCommand:
            raise TypeError("claim_transition must be a TransitionCommand")
        transition = self.claim_transition
        if (
            transition.entity_type is not EntityType.ATTEMPT
            or transition.entity_id != self.attempt_id
            or transition.expected_state is not AttemptState.SCHEDULED
            or transition.new_state is not AttemptState.CLAIMED
            or transition.causal_reference is not None
            or transition.attempt_outcome is not None
        ):
            raise ValueError("claim transition must be scheduled-to-claimed for the new attempt")


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


def _validate_request_metadata(request: RequestMetadata) -> None:
    _control_free_text(
        request.url_redacted,
        name="redacted request URL",
        maximum=2_048,
    )
    names = request.header_names
    if type(names) is not tuple or len(names) > MAX_REQUEST_HEADER_NAMES:
        raise ValueError("request header names must be a bounded canonical tuple")
    for name in names:
        if (
            type(name) is not str
            or not 1 <= len(name.encode("ascii", errors="ignore")) <= MAX_REQUEST_HEADER_NAME_BYTES
            or _LOWER_HEADER_NAME.fullmatch(name) is None
        ):
            raise ValueError("request header names must be bounded lowercase HTTP tokens")
    if names != tuple(sorted(set(names))):
        raise ValueError("request header names must be unique and canonically sorted")
    canonical_request_header_names_json(request)


def canonical_request_header_names_json(
    request: RequestMetadata | None,
) -> bytes | None:
    """Serialize sanitized request header names in their sole persisted form."""
    if request is None:
        return None
    encoded = json.dumps(
        request.header_names,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")
    if len(encoded) > MAX_REQUEST_HEADER_NAMES_JSON_BYTES:
        raise ValueError("canonical request header-name JSON exceeds its byte limit")
    return encoded


def _validate_transport_error(error: TransportError) -> None:
    _control_free_text(
        error.category,
        name="transport error category",
        maximum=128,
    )
    _control_free_text(
        error.message_redacted,
        name="redacted transport error message",
        maximum=4_096,
    )
    if error.phase is not None:
        _control_free_text(
            error.phase,
            name="transport error phase",
            maximum=64,
        )


def _validate_transport_evidence_shape(
    evidence: AttemptTransportEvidenceCommand,
) -> None:
    failure_states = {
        AttemptEvidenceState.TIMED_OUT,
        AttemptEvidenceState.CONNECTION_FAILED,
        AttemptEvidenceState.PROTOCOL_FAILED,
    }
    expected_classifications = {
        AttemptEvidenceState.ACKNOWLEDGED: frozenset({AttemptClassification.RECEIVER_ACCEPTED}),
        AttemptEvidenceState.REJECTED: frozenset({AttemptClassification.RECEIVER_REJECTED}),
        AttemptEvidenceState.TIMED_OUT: frozenset(
            {
                AttemptClassification.ENVIRONMENT_FAILURE,
                AttemptClassification.HARNESS_FAILURE,
            }
        ),
        AttemptEvidenceState.CONNECTION_FAILED: frozenset(
            {
                AttemptClassification.ENVIRONMENT_FAILURE,
                AttemptClassification.HARNESS_FAILURE,
            }
        ),
        AttemptEvidenceState.PROTOCOL_FAILED: frozenset(
            {
                AttemptClassification.ENVIRONMENT_FAILURE,
                AttemptClassification.HARNESS_FAILURE,
            }
        ),
        AttemptEvidenceState.CANCELLED: frozenset({AttemptClassification.CANCELLED}),
        AttemptEvidenceState.UNKNOWN_OUTCOME: frozenset({AttemptClassification.AMBIGUOUS}),
    }
    allowed = expected_classifications.get(evidence.state)
    if allowed is None or evidence.classification not in allowed:
        raise ValueError("transport evidence state and classification disagree")
    if evidence.state in {
        AttemptEvidenceState.ACKNOWLEDGED,
        AttemptEvidenceState.REJECTED,
    }:
        if evidence.response is None or evidence.error is not None:
            raise ValueError(
                "accepted or rejected evidence requires response metadata and no error"
            )
    elif evidence.state in failure_states | {AttemptEvidenceState.UNKNOWN_OUTCOME}:
        if evidence.error is None:
            raise ValueError("failure or unknown evidence requires a redacted transport error")
    elif evidence.response is not None:
        raise ValueError("cancelled evidence cannot contain response metadata")


def _control_free_text(value: str, *, name: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} must be bounded control-free text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} must contain Unicode scalar values") from error
    return value


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
