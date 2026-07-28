"""Typed persistent schedule reads, attempt leases, and full-run completion."""
# ruff: noqa: D105, D107, EM101, INP001, TRY003

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from webhook_receiver_conformance.domain.enums import RunState
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.journal.repositories import (
    TransitionRepository,
    _ApplyTransitionOperation,  # pyright: ignore[reportPrivateUsage]
)
from webhook_receiver_conformance.journal.service import (
    JournalService,
    JournalStatement,
    JournalTransaction,
)
from webhook_receiver_conformance.journal.transitions import (
    MAX_CONDITION_BYTES,
    MAX_OWNER_EPOCH,
    MAX_SAFE_INTEGER,
    AttemptScheduleClaim,
    CommittedTransition,
    EntityType,
    LifecycleState,
    TransitionCommand,
)

_UTC_TIMESTAMP = re.compile(
    r"(?:\d{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z"
)
_RUN_STATE_BY_RESULT = {
    ResultCategory.PASS: RunState.COMPLETED,
    ResultCategory.RECEIVER_FAILURE: RunState.COMPLETED,
    ResultCategory.ENVIRONMENT_ERROR: RunState.COMPLETED,
    ResultCategory.UNSUPPORTED: RunState.COMPLETED,
    ResultCategory.AMBIGUOUS: RunState.PAUSED,
    ResultCategory.CANCELLED: RunState.CANCELLED,
    ResultCategory.HARNESS_ERROR: RunState.FAILED,
    ResultCategory.INVALID_INPUT: RunState.FAILED,
}
_MAX_SCHEDULE_ENTRY_ID = 96
_MAX_TIE_KEY = 256
_SCHEDULE_ROW_WIDTH = 12


@dataclass(frozen=True, slots=True)
class PersistedScheduleEntry:
    """One unconsumed attempt schedule in its authoritative stable order."""

    schedule_entry_id: str
    run_id: str
    scenario_id: str
    attempt_plan_id: str
    logical_due_ns: int
    scenario_ordinal: int
    step_ordinal: int
    delivery_ordinal: int
    attempt_ordinal: int
    deterministic_tie_key: str
    condition_json: bytes | None
    predecessor_attempt_id: str | None

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_planned_id(
            self.attempt_plan_id,
            expected_kind=PlannedIdKind.ATTEMPT_PLAN,
        )
        if (
            type(self.schedule_entry_id) is not str
            or not 1 <= len(self.schedule_entry_id) <= _MAX_SCHEDULE_ENTRY_ID
        ):
            raise ValueError("schedule_entry_id must be bounded text")
        if type(self.logical_due_ns) is not int or not (
            -MAX_SAFE_INTEGER <= self.logical_due_ns <= MAX_SAFE_INTEGER
        ):
            raise ValueError("logical_due_ns must be a signed safe integer")
        for value, name in (
            (self.scenario_ordinal, "scenario_ordinal"),
            (self.step_ordinal, "step_ordinal"),
            (self.delivery_ordinal, "delivery_ordinal"),
            (self.attempt_ordinal, "attempt_ordinal"),
        ):
            if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
                message = f"{name} must be a nonnegative safe integer"
                raise ValueError(message)
        if (
            type(self.deterministic_tie_key) is not str
            or not 1 <= len(self.deterministic_tie_key) <= _MAX_TIE_KEY
        ):
            raise ValueError("deterministic_tie_key must be bounded text")
        if self.condition_json is not None and (
            type(self.condition_json) is not bytes or len(self.condition_json) > MAX_CONDITION_BYTES
        ):
            raise ValueError("condition_json must be bounded bytes or None")
        if self.predecessor_attempt_id is not None:
            validate_fresh_id(
                self.predecessor_attempt_id,
                expected_kind=FreshIdKind.ATTEMPT,
            )
        if (self.attempt_ordinal == 1) != (self.predecessor_attempt_id is None):
            raise ValueError("only an initial schedule may omit a predecessor")

    @property
    def order_key(self) -> tuple[int, int, int, int, int, str, str]:
        """Return the persisted deterministic ordering key."""
        return (
            self.logical_due_ns,
            self.scenario_ordinal,
            self.step_ordinal,
            self.delivery_ordinal,
            self.attempt_ordinal,
            self.deterministic_tie_key,
            self.schedule_entry_id,
        )


@dataclass(frozen=True, slots=True)
class FullRunCompletionRequest:
    """One guarded run-state reduction plus terminal public result metadata."""

    run_id: str
    owner_epoch: int
    result_category: ResultCategory
    completed_at: str
    transition: TransitionCommand[RunState]

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        if type(self.owner_epoch) is not int or not 0 <= self.owner_epoch <= MAX_OWNER_EPOCH:
            raise ValueError("owner_epoch must be a nonnegative SQLite int64")
        if type(self.result_category) is not ResultCategory:
            raise TypeError("result_category must be a ResultCategory")
        _parse_timestamp(self.completed_at)
        if type(self.transition) is not TransitionCommand:
            raise TypeError("transition must be a TransitionCommand")
        expected_state = _RUN_STATE_BY_RESULT[self.result_category]
        if (
            self.transition.run_id != self.run_id
            or self.transition.entity_type is not EntityType.RUN
            or self.transition.entity_id != self.run_id
            or self.transition.expected_state is not RunState.RUNNING
            or self.transition.new_state is not expected_state
            or self.transition.owner_epoch != self.owner_epoch
        ):
            raise ValueError("run completion transition differs from its result")


@dataclass(frozen=True, slots=True)
class _PendingScheduleOperation:
    run_id: str

    def execute(
        self,
        transaction: JournalTransaction,
    ) -> tuple[PersistedScheduleEntry, ...]:
        run = transaction.execute(
            JournalStatement(
                "SELECT 1 FROM runs WHERE run_id = ?",
                (self.run_id,),
            )
        )
        if run.rows != ((1,),):
            raise RuntimeError("pending schedule run does not exist")
        result = transaction.execute(
            JournalStatement(
                """
                SELECT schedule_entry_id, run_id, scenario_id, entity_type,
                       entity_id, logical_time_ns, scenario_ordinal,
                       step_ordinal, delivery_ordinal, attempt_ordinal,
                       deterministic_tie_key, condition_json
                FROM schedule_entries
                WHERE run_id = ? AND consumed_at IS NULL
                ORDER BY logical_time_ns, scenario_ordinal, step_ordinal,
                         delivery_ordinal, attempt_ordinal,
                         deterministic_tie_key, schedule_entry_id
                """,
                (self.run_id,),
            )
        )
        entries = tuple(_schedule_entry(row) for row in result.rows)
        if tuple(item.order_key for item in entries) != tuple(
            sorted(item.order_key for item in entries)
        ):
            raise RuntimeError("pending schedule order differs from its stable key")
        return entries


@dataclass(frozen=True, slots=True)
class _FinalizeFullRunOperation:
    request: FullRunCompletionRequest

    def execute(self, transaction: JournalTransaction) -> None:
        request = self.request
        _ApplyTransitionOperation(
            cast(
                "TransitionCommand[LifecycleState]",
                request.transition,
            ),
            None,
        ).execute(transaction)
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
            raise RuntimeError("run terminal metadata conflicts with durable completion")


class PersistentScheduleRepository:
    """Journal-owned pending-read, attempt-lease, and run-finalization adapter."""

    __slots__ = ("_service", "_transitions")

    def __init__(self, service: JournalService) -> None:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            service,
            JournalService,
        ):
            raise TypeError("service must be a JournalService")
        self._service = service
        self._transitions = TransitionRepository(service)

    async def pending(
        self,
        run_id: str,
    ) -> tuple[PersistedScheduleEntry, ...]:
        """Read every unconsumed entry in its authoritative stable order."""
        validate_run_id(run_id)
        return await self._service.execute(_PendingScheduleOperation(run_id))

    async def lease_attempt(
        self,
        claim: AttemptScheduleClaim,
    ) -> CommittedTransition:
        """Atomically consume one schedule and create its claimed attempt."""
        if type(claim) is not AttemptScheduleClaim:
            raise TypeError("claim must be an AttemptScheduleClaim")
        return await self._transitions.claim_attempt_schedule(claim)

    async def finalize_run(
        self,
        request: FullRunCompletionRequest,
    ) -> None:
        """Commit the guarded run edge and terminal metadata atomically."""
        if type(request) is not FullRunCompletionRequest:
            raise TypeError("request must be a FullRunCompletionRequest")
        await self._service.execute(_FinalizeFullRunOperation(request))


def _schedule_entry(row: tuple[object, ...]) -> PersistedScheduleEntry:
    if len(row) != _SCHEDULE_ROW_WIDTH:
        raise RuntimeError("pending schedule row has an invalid shape")
    entity_type = _text(row[3], "entity_type")
    if entity_type != "attempt":
        raise RuntimeError("full transport runner encountered non-attempt work")
    condition = row[11]
    if condition is not None and type(condition) is not bytes:
        raise RuntimeError("schedule condition is not an immutable BLOB")
    condition_json = condition
    return PersistedScheduleEntry(
        schedule_entry_id=_text(row[0], "schedule_entry_id"),
        run_id=_text(row[1], "run_id"),
        scenario_id=_text(row[2], "scenario_id"),
        attempt_plan_id=_text(row[4], "attempt_plan_id"),
        logical_due_ns=_integer(row[5], "logical_time_ns"),
        scenario_ordinal=_integer(row[6], "scenario_ordinal"),
        step_ordinal=_integer(row[7], "step_ordinal"),
        delivery_ordinal=_integer(row[8], "delivery_ordinal"),
        attempt_ordinal=_integer(row[9], "attempt_ordinal"),
        deterministic_tie_key=_text(row[10], "deterministic_tie_key"),
        condition_json=condition_json,
        predecessor_attempt_id=_predecessor(condition_json),
    )


def _predecessor(condition: bytes | None) -> str | None:
    if condition is None:
        return None
    try:
        value: object = json.loads(
            condition.decode("ascii"),
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise RuntimeError("retry schedule condition is malformed") from None
    if not isinstance(value, dict):
        raise TypeError("retry schedule condition must be an object")
    mapping = cast("dict[object, object]", value)
    predecessor = mapping.get("predecessor_attempt_id")
    if type(predecessor) is not str:
        raise RuntimeError("retry schedule condition omits its predecessor")
    validate_fresh_id(predecessor, expected_kind=FreshIdKind.ATTEMPT)
    return predecessor


def _text(value: object, name: str) -> str:
    if type(value) is not str or not value:
        message = f"{name} must be nonempty text"
        raise RuntimeError(message)
    return value


def _integer(value: object, name: str) -> int:
    if type(value) is not int:
        message = f"{name} must be an integer"
        raise RuntimeError(message)
    return value


def _parse_timestamp(value: str) -> datetime:
    if type(value) is not str or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise ValueError("completed_at must be a canonical UTC timestamp")
    parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("completed_at must use UTC")
    return parsed.astimezone(UTC)


__all__ = [
    "FullRunCompletionRequest",
    "PersistedScheduleEntry",
    "PersistentScheduleRepository",
]
