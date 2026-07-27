"""Immutable semantic projections produced before scenario compilation."""
# ruff: noqa: D105, INP001

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from webhook_receiver_conformance.config.models import (
    MAX_PROJECT_SCENARIOS,
    MAX_SCENARIO_EVENTS,
    MAX_SCENARIO_STEPS,
    FaultClass,
)
from webhook_receiver_conformance.errors import Diagnostic

MAX_USER_HEADER_BINDINGS = 100_000
MAX_USER_HEADERS_PER_DELIVERY = 128
MAX_USER_HEADER_NAME_LENGTH = 128
MAX_PROJECTION_ID_LENGTH = 64
MAX_FAULT_FIELD_PATH_LENGTH = 4096
MAX_FAULT_OPERATOR_ID_LENGTH = 128
MAX_FAULT_OCCURRENCES = len(FaultClass)
MAX_VALIDATION_DIAGNOSTICS = 50
MAX_DELIVERIES_PER_STEP = 128
MAX_ATTEMPTS_PER_DELIVERY = 32
MAX_PLANNED_DELIVERIES_PER_SCENARIO = MAX_SCENARIO_STEPS * MAX_DELIVERIES_PER_STEP
MAX_PLANNED_ATTEMPTS_PER_SCENARIO = MAX_PLANNED_DELIVERIES_PER_SCENARIO * MAX_ATTEMPTS_PER_DELIVERY
MAX_RESULT_EVENTS = MAX_PROJECT_SCENARIOS * MAX_SCENARIO_EVENTS
MAX_RESULT_PLANNED_DELIVERIES = MAX_PROJECT_SCENARIOS * MAX_PLANNED_DELIVERIES_PER_SCENARIO
MAX_RESULT_PLANNED_ATTEMPTS = MAX_PROJECT_SCENARIOS * MAX_PLANNED_ATTEMPTS_PER_SCENARIO
CONTROL_CHARACTER_LIMIT = 32
DELETE_CHARACTER_CODEPOINT = 127
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_PROFILE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_OPERATOR_ID = re.compile(r"[a-z][a-z0-9-]{0,127}")


def _bounded_integer(
    value: object,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int:
        message = f"{field_name} must be an integer"
        raise TypeError(message)
    if not minimum <= value <= maximum:
        message = f"{field_name} must be between {minimum} and {maximum}"
        raise ValueError(message)
    return value


def _bounded_text(
    value: object,
    *,
    field_name: str,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if type(value) is not str:
        message = f"{field_name} must be a string"
        raise TypeError(message)
    invalid_character = any(
        ord(character) < CONTROL_CHARACTER_LIMIT or ord(character) == DELETE_CHARACTER_CODEPOINT
        for character in value
    )
    if (
        not 1 <= len(value) <= maximum
        or invalid_character
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        message = f"{field_name} must be a bounded control-free value"
        raise ValueError(message)
    return value


def _bounded_tuple(
    value: object,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> tuple[object, ...]:
    if type(value) is not tuple:
        message = f"{field_name} must be a tuple"
        raise TypeError(message)
    entries = cast("tuple[object, ...]", value)
    if not minimum <= len(entries) <= maximum:
        message = f"{field_name} must contain between {minimum} and {maximum} entries"
        raise ValueError(message)
    return entries


def _is_exact_fault_occurrence(value: object) -> bool:
    return type(value) is FaultOccurrence


def _is_exact_scenario_semantics(value: object) -> bool:
    return type(value) is ScenarioSemantics


def _is_exact_diagnostic(value: object) -> bool:
    return type(value) is Diagnostic


class MutationStage(StrEnum):
    """Closed v0.1 mutation-pipeline stages in execution order."""

    STRUCTURAL = "structural"
    RAW_PRE_SIGN = "raw-pre-sign"
    HEADER_PRE_SIGN = "header-pre-sign"
    SIGNING = "signing"
    RAW_POST_SIGN = "raw-post-sign"
    HEADER_POST_SIGN = "header-post-sign"


@dataclass(frozen=True, slots=True)
class FaultOccurrence:
    """One first-observed fault class and its safe configuration location."""

    fault_class: FaultClass
    field_path: str
    operator_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.fault_class) is not FaultClass:
            message = "fault_class must be a FaultClass member"
            raise TypeError(message)
        _bounded_text(
            self.field_path,
            field_name="field_path",
            maximum=MAX_FAULT_FIELD_PATH_LENGTH,
        )
        if self.operator_id is not None:
            _bounded_text(
                self.operator_id,
                field_name="operator_id",
                maximum=MAX_FAULT_OPERATOR_ID_LENGTH,
                pattern=_OPERATOR_ID,
            )


@dataclass(frozen=True, slots=True)
class DeliveryUserHeaders:
    """Normalized user-supplied header names for one configured delivery step."""

    scenario_index: int
    step_index: int
    names: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.scenario_index) is not int or type(self.step_index) is not int:
            message = "header-binding indexes must be integers"
            raise TypeError(message)
        if self.scenario_index < 0 or self.step_index < 0:
            message = "header-binding indexes cannot be negative"
            raise ValueError(message)
        if type(self.names) is not tuple:
            message = "user header names must be provided as a tuple"
            raise TypeError(message)
        if len(self.names) > MAX_USER_HEADERS_PER_DELIVERY:
            message = "a delivery cannot declare more than 128 user headers"
            raise ValueError(message)
        normalized: list[str] = []
        for name in self.names:
            if (
                type(name) is not str
                or not 1 <= len(name) <= MAX_USER_HEADER_NAME_LENGTH
                or _HEADER_NAME.fullmatch(name) is None
            ):
                message = "user header names must be bounded HTTP tokens"
                raise ValueError(message)
            normalized.append(name.casefold())
        if len(normalized) != len(set(normalized)):
            message = "user header names must be unique case-insensitively"
            raise ValueError(message)
        object.__setattr__(self, "names", tuple(normalized))


def _is_delivery_user_headers(value: object) -> bool:
    return isinstance(value, DeliveryUserHeaders)


@dataclass(frozen=True, slots=True)
class ScenarioValidationContext:
    """Non-schema planning context needed for semantic header-ownership checks."""

    user_headers: tuple[DeliveryUserHeaders, ...] = ()

    def __post_init__(self) -> None:
        if type(self.user_headers) is not tuple:
            message = "user header bindings must be provided as a tuple"
            raise TypeError(message)
        if len(self.user_headers) > MAX_USER_HEADER_BINDINGS:
            message = "scenario validation context exceeds the header-binding limit"
            raise ValueError(message)
        entries: tuple[object, ...] = self.user_headers
        if any(not _is_delivery_user_headers(binding) for binding in entries):
            message = "validation context entries must be delivery user-header bindings"
            raise TypeError(message)
        keys = tuple((binding.scenario_index, binding.step_index) for binding in self.user_headers)
        if len(keys) != len(set(keys)):
            message = "user header bindings must identify unique delivery steps"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class ScenarioSemantics:
    """Bounded compiler-facing facts derived from one configured scenario."""

    scenario_id: str
    scenario_index: int
    event_ids: tuple[str, ...]
    fault_occurrences: tuple[FaultOccurrence, ...]
    planned_deliveries: int
    planned_attempts: int

    def __post_init__(self) -> None:
        _bounded_text(
            self.scenario_id,
            field_name="scenario_id",
            maximum=MAX_PROJECTION_ID_LENGTH,
            pattern=_PROFILE_NAME,
        )
        _bounded_integer(
            self.scenario_index,
            field_name="scenario_index",
            minimum=0,
            maximum=MAX_PROJECT_SCENARIOS - 1,
        )
        events = _bounded_tuple(
            self.event_ids,
            field_name="event_ids",
            minimum=1,
            maximum=MAX_SCENARIO_EVENTS,
        )
        for event_id in events:
            _bounded_text(
                event_id,
                field_name="event_id",
                maximum=MAX_PROJECTION_ID_LENGTH,
                pattern=_PROFILE_NAME,
            )
        occurrences = _bounded_tuple(
            self.fault_occurrences,
            field_name="fault_occurrences",
            minimum=0,
            maximum=MAX_FAULT_OCCURRENCES,
        )
        if any(not _is_exact_fault_occurrence(item) for item in occurrences):
            message = "fault_occurrences entries must be FaultOccurrence values"
            raise TypeError(message)
        _bounded_integer(
            self.planned_deliveries,
            field_name="planned_deliveries",
            minimum=0,
            maximum=MAX_PLANNED_DELIVERIES_PER_SCENARIO,
        )
        _bounded_integer(
            self.planned_attempts,
            field_name="planned_attempts",
            minimum=0,
            maximum=MAX_PLANNED_ATTEMPTS_PER_SCENARIO,
        )
        if self.planned_attempts < self.planned_deliveries:
            message = "planned_attempts cannot be less than planned_deliveries"
            raise ValueError(message)
        fault_classes = tuple(item.fault_class for item in self.fault_occurrences)
        if len(fault_classes) != len(set(fault_classes)):
            message = "fault occurrences must contain unique fault classes"
            raise ValueError(message)

    @property
    def fault_classes(self) -> tuple[FaultClass, ...]:
        """Return distinct fault classes in deterministic first-observed order."""
        return tuple(item.fault_class for item in self.fault_occurrences)


@dataclass(frozen=True, slots=True)
class ScenarioValidationResult:
    """One deterministic semantic-validation result and bounded diagnostics."""

    scenarios: tuple[ScenarioSemantics, ...]
    diagnostics: tuple[Diagnostic, ...]
    total_events: int
    total_planned_deliveries: int
    total_planned_attempts: int

    def __post_init__(self) -> None:
        scenarios = _bounded_tuple(
            self.scenarios,
            field_name="scenarios",
            minimum=1,
            maximum=MAX_PROJECT_SCENARIOS,
        )
        if any(not _is_exact_scenario_semantics(item) for item in scenarios):
            message = "scenarios entries must be ScenarioSemantics values"
            raise TypeError(message)
        diagnostics = _bounded_tuple(
            self.diagnostics,
            field_name="diagnostics",
            minimum=0,
            maximum=MAX_VALIDATION_DIAGNOSTICS,
        )
        if any(not _is_exact_diagnostic(item) for item in diagnostics):
            message = "diagnostics entries must be Diagnostic values"
            raise TypeError(message)
        _bounded_integer(
            self.total_events,
            field_name="total_events",
            minimum=0,
            maximum=MAX_RESULT_EVENTS,
        )
        _bounded_integer(
            self.total_planned_deliveries,
            field_name="total_planned_deliveries",
            minimum=0,
            maximum=MAX_RESULT_PLANNED_DELIVERIES,
        )
        _bounded_integer(
            self.total_planned_attempts,
            field_name="total_planned_attempts",
            minimum=0,
            maximum=MAX_RESULT_PLANNED_ATTEMPTS,
        )
        expected_totals = (
            sum(len(scenario.event_ids) for scenario in self.scenarios),
            sum(scenario.planned_deliveries for scenario in self.scenarios),
            sum(scenario.planned_attempts for scenario in self.scenarios),
        )
        if expected_totals != (
            self.total_events,
            self.total_planned_deliveries,
            self.total_planned_attempts,
        ):
            message = "validation totals must match scenario projections"
            raise ValueError(message)

    @property
    def ok(self) -> bool:
        """Return whether every semantic rule passed."""
        return not self.diagnostics

    def scenario(self, scenario_id: str) -> ScenarioSemantics | None:
        """Return the first matching scenario projection without building another map."""
        return next(
            (scenario for scenario in self.scenarios if scenario.scenario_id == scenario_id),
            None,
        )
