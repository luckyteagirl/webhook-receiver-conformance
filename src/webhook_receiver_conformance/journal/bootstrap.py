"""Atomic, deterministic projection bootstrap from one verified run manifest."""
# ruff: noqa: C901, EM101, EM102, INP001, PLR0912, PLR0913, PLR0915, S608, TRY003

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Final, cast

from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.enums import (
    AttemptClassification,
    AttemptState,
    DeliveryState,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    planned_id,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.journal.repositories import (
    TRIGGER_ATTEMPT_OUTCOME,
    _ApplyTransitionOperation,  # pyright: ignore[reportPrivateUsage]
)
from webhook_receiver_conformance.journal.service import (
    JournalService,
    JournalServiceError,
    JournalStatement,
    JournalTransaction,
    SqlValue,
)
from webhook_receiver_conformance.manifest.models import RunManifest
from webhook_receiver_conformance.scheduler.clocks import TransitionTimestamp
from webhook_receiver_conformance.types import DiagnosticCode

from .transitions import (
    CausalReference,
    DeliverySatisfactionEvidence,
    DeliverySatisfactionKind,
    EntityType,
    LifecycleState,
    TransitionCommand,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

_MAX_OWNER_EPOCH: Final = 9_223_372_036_854_775_807
_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
_MAX_BOOTSTRAP_ROWS: Final = 10_000
_MAX_PARAMETERS_PER_STATEMENT: Final = 1_024
_UTC_TIMESTAMP: Final = re.compile(
    r"(?:\d{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z"
)
_TOKEN: Final = re.compile(r"[A-Za-z0-9_.:-]+")


class JournalBootstrapError(JournalServiceError):
    """A fresh-journal bootstrap conflicts with durable journal identity."""

    code = DiagnosticCode("JOURNAL_BOOTSTRAP_CONFLICT")


@dataclass(frozen=True, slots=True)
class SeededAttempt:
    """One deterministic initial-attempt schedule identity."""

    schedule_entry_id: str
    attempt_plan_id: str
    scenario_ordinal: int
    step_ordinal: int
    delivery_ordinal: int
    attempt_ordinal: int
    condition_json: bytes | None = None

    def __post_init__(self) -> None:
        """Validate the public schedule identity contract."""
        _bounded_token(self.schedule_entry_id, "schedule_entry_id", 96)
        validate_planned_id(
            self.attempt_plan_id,
            expected_kind=PlannedIdKind.ATTEMPT_PLAN,
        )
        for value, name in (
            (self.scenario_ordinal, "scenario_ordinal"),
            (self.step_ordinal, "step_ordinal"),
            (self.delivery_ordinal, "delivery_ordinal"),
        ):
            if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
                raise ValueError(f"{name} must be a nonnegative safe integer")
        if self.attempt_ordinal != 1:
            raise ValueError("an initial seeded attempt must have ordinal 1")
        if self.condition_json is not None:
            raise ValueError("an initial seeded attempt cannot have a retry condition")


@dataclass(frozen=True, slots=True)
class JournalBootstrapRequest:
    """Verified manifest plus the fresh run identity and ownership epoch."""

    run_id: str
    owner_epoch: int
    manifest: RunManifest
    created_at: str
    seeded_attempts: tuple[SeededAttempt, ...] | None = None

    def __post_init__(self) -> None:
        """Reject invalid public-boundary values before writer submission."""
        validate_run_id(self.run_id)
        if type(self.owner_epoch) is not int or not 0 <= self.owner_epoch <= _MAX_OWNER_EPOCH:
            raise ValueError("owner_epoch must be a nonnegative SQLite int64")
        if type(self.manifest) is not RunManifest:
            raise TypeError("manifest must be a RunManifest")
        self.manifest.verify_id()
        _parse_timestamp(self.created_at)
        if self.seeded_attempts is not None and (
            type(self.seeded_attempts) is not tuple
            or any(type(item) is not SeededAttempt for item in self.seeded_attempts)
        ):
            raise TypeError("seeded_attempts must be a tuple of SeededAttempt values")


@dataclass(frozen=True, slots=True)
class JournalCompletionRequest:
    """One terminal attempt and its reduced public result."""

    run_id: str
    owner_epoch: int
    scenario_id: str
    event_id: str
    delivery_id: str
    attempt_id: str
    classification: AttemptClassification
    terminal_attempt_state: AttemptState
    result_category: ResultCategory
    completed_at: str

    def __post_init__(self) -> None:
        """Validate the completion identity and closed enum boundaries."""
        validate_run_id(self.run_id)
        if type(self.owner_epoch) is not int or not 0 <= self.owner_epoch <= _MAX_OWNER_EPOCH:
            raise ValueError("owner_epoch must be a nonnegative SQLite int64")
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
        if type(self.classification) is not AttemptClassification:
            raise TypeError("classification must be an AttemptClassification")
        if type(self.terminal_attempt_state) is not AttemptState:
            raise TypeError("terminal_attempt_state must be an AttemptState")
        if type(self.result_category) is not ResultCategory:
            raise TypeError("result_category must be a ResultCategory")
        if self.terminal_attempt_state not in _DELIVERY_STATE_BY_ATTEMPT:
            raise ValueError("terminal_attempt_state is not terminal")
        _parse_timestamp(self.completed_at)


@dataclass(frozen=True, slots=True)
class _ScheduleSeed:
    public: SeededAttempt
    run_id: str
    scenario_id: str
    entity_type: str
    entity_id: str
    logical_time_ns: int
    deterministic_tie_key: str
    idempotency_key: str

    @property
    def order_key(self) -> tuple[int, int, int, int, int, str, str]:
        return (
            self.logical_time_ns,
            self.public.scenario_ordinal,
            self.public.step_ordinal,
            self.public.delivery_ordinal,
            self.public.attempt_ordinal,
            self.deterministic_tie_key,
            self.public.schedule_entry_id,
        )

    def row(self) -> tuple[SqlValue, ...]:
        return (
            self.public.schedule_entry_id,
            self.run_id,
            self.scenario_id,
            self.entity_type,
            self.entity_id,
            self.logical_time_ns,
            self.public.scenario_ordinal,
            self.public.step_ordinal,
            self.public.delivery_ordinal,
            self.public.attempt_ordinal,
            self.deterministic_tie_key,
            self.public.condition_json,
            self.idempotency_key,
        )


@dataclass(frozen=True, slots=True)
class _BootstrapPlan:
    request: JournalBootstrapRequest
    scenarios: tuple[tuple[SqlValue, ...], ...]
    events: tuple[tuple[SqlValue, ...], ...]
    event_dependencies: tuple[tuple[SqlValue, ...], ...]
    deliveries: tuple[tuple[SqlValue, ...], ...]
    assertions: tuple[tuple[SqlValue, ...], ...]
    schedules: tuple[_ScheduleSeed, ...]

    @property
    def first_attempt(self) -> SeededAttempt:
        return min(self.schedules, key=lambda item: item.order_key).public


@dataclass(frozen=True, slots=True)
class _BootstrapOperation:
    plan: _BootstrapPlan

    def execute(self, transaction: JournalTransaction) -> SeededAttempt:
        existing = transaction.execute(
            JournalStatement(
                """
                SELECT run_id, manifest_id, owner_epoch, created_at
                FROM runs
                """
            )
        )
        if existing.rows:
            _verify_existing_bootstrap(transaction, self.plan, existing.rows)
            return self.plan.first_attempt

        request = self.plan.request
        _insert_rows(
            transaction,
            table="runs",
            columns=("run_id", "manifest_id", "state", "owner_epoch", "created_at"),
            rows=(
                (
                    request.run_id,
                    request.manifest.manifest_id,
                    "planned",
                    request.owner_epoch,
                    request.created_at,
                ),
            ),
        )
        _insert_rows(
            transaction,
            table="scenarios",
            columns=("scenario_id", "run_id", "ordinal", "name", "state", "required"),
            rows=self.plan.scenarios,
        )
        _insert_rows(
            transaction,
            table="events",
            columns=(
                "event_id",
                "run_id",
                "scenario_id",
                "ordinal",
                "event_type",
                "fixture_blob_hash",
            ),
            rows=self.plan.events,
        )
        _insert_rows(
            transaction,
            table="event_dependencies",
            columns=("run_id", "scenario_id", "event_id", "dependency_event_id"),
            rows=self.plan.event_dependencies,
        )
        _insert_rows(
            transaction,
            table="deliveries",
            columns=(
                "delivery_id",
                "run_id",
                "scenario_id",
                "event_id",
                "ordinal",
                "step_ordinal",
                "logical_time_ns",
                "state",
                "required",
            ),
            rows=self.plan.deliveries,
        )
        _insert_rows(
            transaction,
            table="assertions",
            columns=(
                "assertion_id",
                "run_id",
                "scenario_id",
                "type",
                "policy_json",
                "required",
                "state",
            ),
            rows=self.plan.assertions,
        )
        _insert_rows(
            transaction,
            table="schedule_entries",
            columns=(
                "schedule_entry_id",
                "run_id",
                "scenario_id",
                "entity_type",
                "entity_id",
                "logical_time_ns",
                "scenario_ordinal",
                "step_ordinal",
                "delivery_ordinal",
                "attempt_ordinal",
                "deterministic_tie_key",
                "condition_json",
                "idempotency_key",
            ),
            rows=tuple(item.row() for item in self.plan.schedules),
        )
        return self.plan.first_attempt


_DELIVERY_STATE_BY_ATTEMPT: Final = {
    AttemptState.SUCCEEDED: DeliveryState.SATISFIED,
    AttemptState.UNKNOWN_OUTCOME: DeliveryState.AMBIGUOUS,
    AttemptState.CANCELLED: DeliveryState.CANCELLED,
    AttemptState.NOT_SENT: DeliveryState.EXHAUSTED,
    AttemptState.REJECTED: DeliveryState.EXHAUSTED,
    AttemptState.TRANSPORT_FAILED: DeliveryState.EXHAUSTED,
}
_SCENARIO_STATE_BY_RESULT: Final = {
    ResultCategory.PASS: ScenarioState.PASSED,
    ResultCategory.RECEIVER_FAILURE: ScenarioState.FAILED,
    ResultCategory.AMBIGUOUS: ScenarioState.AMBIGUOUS,
    ResultCategory.CANCELLED: ScenarioState.CANCELLED,
    ResultCategory.ENVIRONMENT_ERROR: ScenarioState.ERROR,
    ResultCategory.HARNESS_ERROR: ScenarioState.ERROR,
    ResultCategory.INVALID_INPUT: ScenarioState.ERROR,
    ResultCategory.UNSUPPORTED: ScenarioState.ERROR,
}
_RUN_STATE_BY_RESULT: Final = {
    ResultCategory.PASS: RunState.COMPLETED,
    ResultCategory.RECEIVER_FAILURE: RunState.COMPLETED,
    ResultCategory.ENVIRONMENT_ERROR: RunState.COMPLETED,
    ResultCategory.UNSUPPORTED: RunState.COMPLETED,
    ResultCategory.AMBIGUOUS: RunState.PAUSED,
    ResultCategory.CANCELLED: RunState.CANCELLED,
    ResultCategory.HARNESS_ERROR: RunState.FAILED,
    ResultCategory.INVALID_INPUT: RunState.FAILED,
}


@dataclass(frozen=True, slots=True)
class _FinalizeOperation:
    request: JournalCompletionRequest

    def execute(self, transaction: JournalTransaction) -> None:
        request = self.request
        _verify_terminal_attempt(transaction, request)
        timestamp = TransitionTimestamp.historical(_parse_timestamp(request.completed_at))
        cause = CausalReference(request.run_id, request.attempt_id)
        delivery_state = _DELIVERY_STATE_BY_ATTEMPT[request.terminal_attempt_state]
        satisfaction = (
            DeliverySatisfactionEvidence(
                kind=DeliverySatisfactionKind.ATTEMPT,
                cause=cause,
            )
            if delivery_state is DeliveryState.SATISFIED
            else None
        )
        commands: tuple[TransitionCommand[LifecycleState], ...] = (
            _completion_command(
                request=request,
                entity_type=EntityType.DELIVERY,
                entity_id=request.delivery_id,
                expected_state=DeliveryState.ACTIVE,
                new_state=delivery_state,
                timestamp=timestamp,
                trigger_category=TRIGGER_ATTEMPT_OUTCOME,
                cause=cause,
                satisfaction=satisfaction,
            ),
            _completion_command(
                request=request,
                entity_type=EntityType.SCENARIO,
                entity_id=request.scenario_id,
                expected_state=ScenarioState.RUNNING,
                new_state=_SCENARIO_STATE_BY_RESULT[request.result_category],
                timestamp=timestamp,
                trigger_category="scenario_reduction",
                cause=cause,
            ),
            _completion_command(
                request=request,
                entity_type=EntityType.RUN,
                entity_id=request.run_id,
                expected_state=RunState.RUNNING,
                new_state=_RUN_STATE_BY_RESULT[request.result_category],
                timestamp=timestamp,
                trigger_category="run_reduction",
                cause=cause,
            ),
        )
        for command in commands:
            _ApplyTransitionOperation(command, None).execute(transaction)
        result = transaction.execute(
            JournalStatement(
                """
                UPDATE runs
                SET terminal_category = ?, terminal_at = ?
                WHERE run_id = ?
                  AND (
                    (terminal_category IS NULL AND terminal_at IS NULL)
                    OR (terminal_category = ? AND terminal_at = ?)
                  )
                """,
                (
                    request.result_category.value,
                    request.completed_at,
                    request.run_id,
                    request.result_category.value,
                    request.completed_at,
                ),
            )
        )
        if result.rowcount != 1:
            raise JournalBootstrapError("run terminal metadata conflicts with durable completion")


async def initialize(
    service: JournalService,
    request: JournalBootstrapRequest,
) -> SeededAttempt:
    """Atomically initialize a fresh journal or verify an idempotent replay."""
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        service,
        JournalService,
    ):
        raise TypeError("service must be a JournalService")
    if type(request) is not JournalBootstrapRequest:
        raise TypeError("request must be a JournalBootstrapRequest")
    plan = _build_plan(request)
    return await service.execute(_BootstrapOperation(plan))


async def finalize(
    service: JournalService,
    request: JournalCompletionRequest,
) -> None:
    """Atomically reduce terminal projections and persist the public result."""
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        service,
        JournalService,
    ):
        raise TypeError("service must be a JournalService")
    if type(request) is not JournalCompletionRequest:
        raise TypeError("request must be a JournalCompletionRequest")
    await service.execute(_FinalizeOperation(request))


class JournalLifecycleRepository:
    """Production adapter implementing runner bootstrap and completion protocols."""

    async def initialize(
        self,
        service: JournalService,
        request: JournalBootstrapRequest,
    ) -> SeededAttempt:
        """Delegate atomic manifest bootstrap."""
        return await initialize(service, request)

    async def finalize(
        self,
        service: JournalService,
        request: JournalCompletionRequest,
    ) -> None:
        """Delegate atomic terminal reduction."""
        await finalize(service, request)


def _build_plan(request: JournalBootstrapRequest) -> _BootstrapPlan:
    manifest = request.manifest
    declared_blobs = {entry.sha256 for entry in manifest.blobs}
    if len(declared_blobs) != len(manifest.blobs):
        raise ValueError("manifest blob digests must be unique")
    generator = ContextGenerator.from_normalized_seed_hash(
        bytes.fromhex(manifest.generator.normalized_seed_hash_hex)
    )
    scenarios: list[tuple[SqlValue, ...]] = []
    events: list[tuple[SqlValue, ...]] = []
    dependencies: list[tuple[SqlValue, ...]] = []
    deliveries: list[tuple[SqlValue, ...]] = []
    assertions: list[tuple[SqlValue, ...]] = []
    schedule_inputs: list[tuple[str, str, int, int, int, int, SeededAttempt | None]] = []
    supplied = _supplied_attempts(request.seeded_attempts)
    claimed_supplied: set[tuple[int, int]] = set()
    identifiers: set[str] = set()

    for scenario_ordinal, scenario in enumerate(manifest.scenarios):
        _claim_identifier(identifiers, scenario.scenario_id)
        scenarios.append(
            (
                scenario.scenario_id,
                request.run_id,
                scenario_ordinal,
                scenario.scenario_id,
                "pending",
                1,
            )
        )
        scenario_event_ids = {event.event_id for event in scenario.events}
        if len(scenario_event_ids) != len(scenario.events):
            raise ValueError("scenario event IDs must be unique")
        for event_ordinal, event in enumerate(scenario.events):
            _claim_identifier(identifiers, event.event_id)
            if event.fixture_blob not in declared_blobs:
                raise ValueError("event fixture blob is absent from manifest blobs")
            events.append(
                (
                    event.event_id,
                    request.run_id,
                    scenario.scenario_id,
                    event_ordinal,
                    event.event_type,
                    event.fixture_blob,
                )
            )
            for dependency_id in event.depends_on or ():
                if dependency_id not in scenario_event_ids or dependency_id == event.event_id:
                    raise ValueError("event dependency is outside its scenario or self-referential")
                dependencies.append(
                    (
                        request.run_id,
                        scenario.scenario_id,
                        event.event_id,
                        dependency_id,
                    )
                )
        delivery_ordinals = tuple(item.ordinal for item in scenario.deliveries)
        if delivery_ordinals != tuple(range(len(scenario.deliveries))):
            raise ValueError("delivery ordinals must be contiguous manifest order")
        for delivery in scenario.deliveries:
            _claim_identifier(identifiers, delivery.delivery_id)
            if delivery.event_id not in scenario_event_ids:
                raise ValueError("delivery event is absent from its scenario")
            if not delivery.attempt_plan:
                raise ValueError("delivery must contain an initial attempt template")
            if tuple(item.ordinal for item in delivery.attempt_plan) != tuple(
                range(1, len(delivery.attempt_plan) + 1)
            ):
                raise ValueError("attempt template ordinals must be contiguous from one")
            initial = delivery.attempt_plan[0]
            if initial.conditional_on is not None:
                raise ValueError("initial attempt template cannot be conditional")
            if initial.request_blob not in declared_blobs:
                raise ValueError("attempt request blob is absent from manifest blobs")
            step_ordinal = delivery.ordinal
            deliveries.append(
                (
                    delivery.delivery_id,
                    request.run_id,
                    scenario.scenario_id,
                    delivery.event_id,
                    delivery.ordinal,
                    step_ordinal,
                    delivery.logical_time_ns,
                    "pending",
                    1,
                )
            )
            supplied_identity = supplied.get((scenario_ordinal, delivery.ordinal))
            if supplied_identity is not None:
                claimed_supplied.add((scenario_ordinal, delivery.ordinal))
            schedule_inputs.append(
                (
                    scenario.scenario_id,
                    delivery.delivery_id,
                    scenario_ordinal,
                    step_ordinal,
                    delivery.ordinal,
                    initial.not_before_logical_ns,
                    supplied_identity,
                )
            )
        for assertion in scenario.assertions:
            _claim_identifier(identifiers, assertion.assertion_id)
            assertions.append(
                (
                    assertion.assertion_id,
                    request.run_id,
                    scenario.scenario_id,
                    assertion.type,
                    _assertion_policy(
                        cast(
                            "dict[str, object]",
                            assertion.model_dump(mode="json", exclude_none=True),
                        )
                    ),
                    1,
                    "pending",
                )
            )

    if not schedule_inputs:
        raise ValueError("bootstrap requires at least one delivery schedule")
    if set(supplied) != claimed_supplied:
        raise ValueError("supplied attempt identity does not name a manifest delivery")
    schedules = tuple(
        _schedule_seed(
            request=request,
            generator=generator,
            scenario_id=scenario_id,
            delivery_id=delivery_id,
            scenario_ordinal=scenario_ordinal,
            step_ordinal=step_ordinal,
            delivery_ordinal=delivery_ordinal,
            logical_time_ns=logical_time_ns,
            supplied=identity,
        )
        for (
            scenario_id,
            delivery_id,
            scenario_ordinal,
            step_ordinal,
            delivery_ordinal,
            logical_time_ns,
            identity,
        ) in schedule_inputs
    )
    _bounded_bootstrap_size(
        scenarios,
        events,
        dependencies,
        deliveries,
        assertions,
        schedules,
    )
    if len({item.public.schedule_entry_id for item in schedules}) != len(schedules):
        raise ValueError("initial schedule entry IDs must be unique")
    if len({item.public.attempt_plan_id for item in schedules}) != len(schedules):
        raise ValueError("initial attempt plan IDs must be unique")
    return _BootstrapPlan(
        request=request,
        scenarios=tuple(scenarios),
        events=tuple(events),
        event_dependencies=tuple(dependencies),
        deliveries=tuple(deliveries),
        assertions=tuple(assertions),
        schedules=schedules,
    )


def _schedule_seed(
    *,
    request: JournalBootstrapRequest,
    generator: ContextGenerator,
    scenario_id: str,
    delivery_id: str,
    scenario_ordinal: int,
    step_ordinal: int,
    delivery_ordinal: int,
    logical_time_ns: int,
    supplied: SeededAttempt | None,
) -> _ScheduleSeed:
    attempt_plan_id = planned_id(
        generator,
        PlannedIdKind.ATTEMPT_PLAN,
        (scenario_id, delivery_id, "1"),
    )
    identity_root = f"{scenario_id}|{delivery_id}|initial|1"
    schedule_entry_id = f"initial.{hashlib.sha256(identity_root.encode()).hexdigest()}"
    public = supplied or SeededAttempt(
        schedule_entry_id=schedule_entry_id,
        attempt_plan_id=attempt_plan_id,
        scenario_ordinal=scenario_ordinal,
        step_ordinal=step_ordinal,
        delivery_ordinal=delivery_ordinal,
        attempt_ordinal=1,
    )
    if (
        public.scenario_ordinal != scenario_ordinal
        or public.step_ordinal != step_ordinal
        or public.delivery_ordinal != delivery_ordinal
    ):
        raise ValueError("supplied attempt identity coordinates differ from the manifest")
    idempotency_root = f"idempotency|{identity_root}|{public.schedule_entry_id}"
    return _ScheduleSeed(
        public=public,
        run_id=request.run_id,
        scenario_id=scenario_id,
        entity_type="attempt",
        entity_id=public.attempt_plan_id,
        logical_time_ns=logical_time_ns,
        deterministic_tie_key=f"initial.{public.attempt_plan_id}",
        idempotency_key=(
            f"initial.schedule.{hashlib.sha256(idempotency_root.encode()).hexdigest()}"
        ),
    )


def _supplied_attempts(
    values: tuple[SeededAttempt, ...] | None,
) -> dict[tuple[int, int], SeededAttempt]:
    result: dict[tuple[int, int], SeededAttempt] = {}
    for value in values or ():
        key = (value.scenario_ordinal, value.delivery_ordinal)
        if key in result:
            raise ValueError("supplied attempt identities contain duplicate coordinates")
        result[key] = value
    return result


def _assertion_policy(assertion: dict[str, object]) -> bytes | None:
    policy = {key: assertion[key] for key in ("observer", "parameters") if key in assertion}
    if not policy:
        return None
    return json.dumps(
        policy,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _claim_identifier(claimed: set[str], identifier: str) -> None:
    if identifier in claimed:
        raise ValueError("manifest entity identifiers must be globally unique")
    claimed.add(identifier)


def _bounded_bootstrap_size(*collections: Sequence[object]) -> None:
    if sum(len(items) for items in collections) > _MAX_BOOTSTRAP_ROWS:
        raise ValueError("manifest bootstrap exceeds the journal row limit")


def _insert_rows(
    transaction: JournalTransaction,
    *,
    table: str,
    columns: tuple[str, ...],
    rows: tuple[tuple[SqlValue, ...], ...],
) -> None:
    if not rows:
        return
    width = len(columns)
    if width == 0 or any(len(row) != width for row in rows):
        raise AssertionError("bootstrap row shape differs from its columns")
    chunk_size = max(1, _MAX_PARAMETERS_PER_STATEMENT // width)
    column_sql = ", ".join(columns)
    placeholder = f"({', '.join('?' for _ in columns)})"
    for offset in range(0, len(rows), chunk_size):
        chunk = rows[offset : offset + chunk_size]
        parameters = tuple(value for row in chunk for value in row)
        result = transaction.execute(
            JournalStatement(
                f"INSERT INTO {table} ({column_sql}) VALUES "
                + ", ".join(placeholder for _ in chunk),
                parameters,
            )
        )
        if result.rowcount != len(chunk):
            raise JournalBootstrapError(f"bootstrap insert into {table} did not affect every row")


def _verify_existing_bootstrap(
    transaction: JournalTransaction,
    plan: _BootstrapPlan,
    run_rows: tuple[tuple[SqlValue, ...], ...],
) -> None:
    request = plan.request
    expected_run = (
        request.run_id,
        request.manifest.manifest_id,
        request.owner_epoch,
        request.created_at,
    )
    if run_rows != (expected_run,):
        raise JournalBootstrapError("journal already contains a different run identity")
    _verify_rows(
        transaction,
        table="scenarios",
        columns=("scenario_id", "run_id", "ordinal", "name", "required"),
        order_by=("ordinal",),
        expected=tuple(row[:4] + row[5:] for row in plan.scenarios),
    )
    _verify_rows(
        transaction,
        table="events",
        columns=(
            "event_id",
            "run_id",
            "scenario_id",
            "ordinal",
            "event_type",
            "fixture_blob_hash",
        ),
        order_by=("event_id",),
        expected=tuple(sorted(plan.events, key=lambda row: str(row[0]))),
    )
    _verify_rows(
        transaction,
        table="event_dependencies",
        columns=("run_id", "scenario_id", "event_id", "dependency_event_id"),
        order_by=("scenario_id", "event_id", "dependency_event_id"),
        expected=tuple(sorted(plan.event_dependencies, key=lambda row: tuple(map(str, row)))),
    )
    _verify_rows(
        transaction,
        table="deliveries",
        columns=(
            "delivery_id",
            "run_id",
            "scenario_id",
            "event_id",
            "ordinal",
            "step_ordinal",
            "logical_time_ns",
            "required",
        ),
        order_by=("delivery_id",),
        expected=tuple(
            sorted(
                (row[:7] + row[8:] for row in plan.deliveries),
                key=lambda row: str(row[0]),
            )
        ),
    )
    _verify_rows(
        transaction,
        table="assertions",
        columns=(
            "assertion_id",
            "run_id",
            "scenario_id",
            "type",
            "policy_json",
            "required",
        ),
        order_by=("scenario_id", "assertion_id"),
        expected=tuple(
            sorted(
                (row[:6] for row in plan.assertions),
                key=lambda row: (str(row[2]), str(row[0])),
            )
        ),
    )
    for schedule in plan.schedules:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT schedule_entry_id, run_id, scenario_id, entity_type,
                       entity_id, logical_time_ns, scenario_ordinal, step_ordinal,
                       delivery_ordinal, attempt_ordinal, deterministic_tie_key,
                       condition_json, idempotency_key
                FROM schedule_entries
                WHERE schedule_entry_id = ?
                """,
                (schedule.public.schedule_entry_id,),
            )
        )
        if result.rows != (schedule.row(),):
            raise JournalBootstrapError(
                "journal initial schedule differs from the manifest bootstrap"
            )


def _verify_rows(
    transaction: JournalTransaction,
    *,
    table: str,
    columns: tuple[str, ...],
    order_by: tuple[str, ...],
    expected: tuple[tuple[SqlValue, ...], ...],
) -> None:
    result = transaction.execute(
        JournalStatement(f"SELECT {', '.join(columns)} FROM {table} ORDER BY {', '.join(order_by)}")
    )
    if result.rows != expected:
        raise JournalBootstrapError(
            f"journal {table} inventory differs from the manifest bootstrap"
        )


def _verify_terminal_attempt(
    transaction: JournalTransaction,
    request: JournalCompletionRequest,
) -> None:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT run_id, scenario_id, event_id, delivery_id, state,
                   outcome_category, terminal_recorded_at
            FROM attempts
            WHERE attempt_id = ?
            """,
            (request.attempt_id,),
        )
    )
    if len(result.rows) != 1:
        raise JournalBootstrapError("completion attempt is missing or has conflicting identity")
    row = result.rows[0]
    if (
        row[0] != request.run_id
        or row[1] != request.scenario_id
        or row[2] != request.event_id
        or row[3] != request.delivery_id
        or row[4] != request.terminal_attempt_state.value
        or row[5] != request.classification.value
        or row[6] is None
    ):
        raise JournalBootstrapError(
            "completion request differs from durable terminal attempt evidence"
        )


def _completion_command(
    *,
    request: JournalCompletionRequest,
    entity_type: EntityType,
    entity_id: str,
    expected_state: LifecycleState,
    new_state: LifecycleState,
    timestamp: TransitionTimestamp,
    trigger_category: str,
    cause: CausalReference,
    satisfaction: DeliverySatisfactionEvidence | None = None,
) -> TransitionCommand[LifecycleState]:
    identity = (
        f"{request.run_id}|{entity_type.value}|{entity_id}|"
        f"{expected_state.value}|{new_state.value}|{request.completed_at}"
    )
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return TransitionCommand(
        run_id=request.run_id,
        transition_id=f"finalize.{digest}",
        entity_type=entity_type,
        entity_id=entity_id,
        expected_state=expected_state,
        new_state=new_state,
        trigger_category=trigger_category,
        timestamp=timestamp,
        owner_epoch=request.owner_epoch,
        idempotency_key=f"finalize.transition.{digest}",
        causal_reference=cause,
        delivery_satisfaction=satisfaction,
    )


def _validate_timestamp(value: object) -> str:
    if type(value) is not str or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise ValueError("created_at must be a canonical UTC timestamp")
    return value


def _parse_timestamp(value: object) -> datetime:
    text = _validate_timestamp(value)
    try:
        return datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError("timestamp must name a real UTC instant") from error


def _bounded_token(value: object, name: str, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _TOKEN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a bounded identifier token")
    return value


__all__ = [
    "JournalBootstrapError",
    "JournalBootstrapRequest",
    "JournalCompletionRequest",
    "JournalLifecycleRepository",
    "SeededAttempt",
    "finalize",
    "initialize",
]
