"""Deterministic terminal-result reduction and schema-typed run summaries."""
# ruff: noqa: C901, D105, EM101, INP001, TRY003

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from webhook_receiver_conformance.cli.exit_codes import (
    CommandSurface,
    process_exit_code,
)
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AttemptEvidenceState,
)
from webhook_receiver_conformance.domain.hashing import validate_manifest_id
from webhook_receiver_conformance.domain.identifiers import (
    PlannedIdKind,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.domain.models import (
    AggregateRunOutcome,
    ArtifactPaths,
    AssertionEvaluation,
    AttemptEvidence,
    ResultCounts,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory
from webhook_receiver_conformance.observers.protocol import ObservationRecord

if TYPE_CHECKING:
    from collections.abc import Iterable

_PRECEDENCE: Final = (
    ResultCategory.HARNESS_ERROR,
    ResultCategory.INVALID_INPUT,
    ResultCategory.AMBIGUOUS,
    ResultCategory.ENVIRONMENT_ERROR,
    ResultCategory.UNSUPPORTED,
    ResultCategory.RECEIVER_FAILURE,
    ResultCategory.CANCELLED,
    ResultCategory.PASS,
)
_PRECEDENCE_INDEX: Final = MappingProxyType(
    {category: ordinal for ordinal, category in enumerate(_PRECEDENCE)}
)
_NONTERMINAL_ATTEMPT_STATES: Final = frozenset(
    {
        AttemptEvidenceState.SCHEDULED,
        AttemptEvidenceState.LEASED,
        AttemptEvidenceState.SENDING,
    }
)


@dataclass(frozen=True, slots=True)
class ReducedResult:
    """One terminal category paired with the stable process code."""

    category: ResultCategory
    exit_code: ExitCode

    def __post_init__(self) -> None:
        if type(self.category) is not ResultCategory:
            raise TypeError("category must be a ResultCategory")
        if type(self.exit_code) is not ExitCode:
            raise TypeError("exit_code must be an ExitCode")
        if process_exit_code(self.category, surface=CommandSurface.RUN) is not self.exit_code:
            raise ValueError("result category and process exit code disagree")


@dataclass(frozen=True, slots=True)
class SummarySource:
    """Typed terminal records from which counts and the summary are derived."""

    run_id: str
    manifest_id: str
    generated_at: datetime
    scenario_ids: tuple[str, ...]
    attempts: tuple[AttemptEvidence, ...]
    observations: tuple[ObservationRecord, ...]
    assertions: tuple[AssertionEvaluation, ...]
    categories: tuple[ResultCategory, ...]
    failure_refs: tuple[str, ...]
    artifacts: ArtifactPaths
    command_surface: CommandSurface = CommandSurface.RUN
    durably_terminal: ResultCategory | None = None
    cancellation_requested: bool = False

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        validate_manifest_id(self.manifest_id)
        if type(self.generated_at) is not datetime:
            raise TypeError("generated_at must be a datetime")
        _scenario_ids(self.scenario_ids)
        _exact_tuple(self.attempts, AttemptEvidence, name="attempts")
        _exact_tuple(self.observations, ObservationRecord, name="observations")
        _exact_tuple(self.assertions, AssertionEvaluation, name="assertions")
        _category_tuple(self.categories)
        if type(self.artifacts) is not ArtifactPaths:
            raise TypeError("artifacts must be ArtifactPaths")
        if type(self.command_surface) is not CommandSurface:
            raise TypeError("command_surface must be a CommandSurface")
        if self.durably_terminal is not None and type(self.durably_terminal) is not ResultCategory:
            raise TypeError("durably_terminal must be a ResultCategory or None")
        if type(self.cancellation_requested) is not bool:
            raise TypeError("cancellation_requested must be a bool")
        _validate_terminal_records(self)
        _validate_failure_refs(self)

    @property
    def counts(self) -> ResultCounts:
        """Derive schema counts from the exact exported collections."""
        return ResultCounts(
            scenarios=len(self.scenario_ids),
            attempts=len(self.attempts),
            observations=len(self.observations),
            assertions=len(self.assertions),
        )


def pairwise_reduce(
    left: ResultCategory,
    right: ResultCategory,
) -> ResultCategory:
    """Apply the exact REPORT-022 precedence to two terminal facts."""
    if type(left) is not ResultCategory or type(right) is not ResultCategory:
        raise TypeError("pairwise reduction requires ResultCategory values")
    return left if _PRECEDENCE_INDEX[left] <= _PRECEDENCE_INDEX[right] else right


def reduce_result_categories(
    categories: Iterable[ResultCategory],
    *,
    surface: CommandSurface,
    durably_terminal: ResultCategory | None = None,
    cancellation_requested: bool = False,
) -> ReducedResult:
    """Reduce all facts while preserving an already durable terminal verdict."""
    if type(surface) is not CommandSurface:
        raise TypeError("surface must be a CommandSurface")
    if durably_terminal is not None:
        if type(durably_terminal) is not ResultCategory:
            raise TypeError("durably_terminal must be a ResultCategory or None")
        return ReducedResult(
            durably_terminal,
            process_exit_code(durably_terminal, surface=surface),
        )
    if type(cancellation_requested) is not bool:
        raise TypeError("cancellation_requested must be a bool")
    facts = tuple(categories)
    _category_tuple(facts)
    if cancellation_requested:
        facts = (*facts, ResultCategory.CANCELLED)
    if not facts:
        facts = (ResultCategory.PASS,)
    reduced = facts[0]
    for category in facts[1:]:
        reduced = pairwise_reduce(reduced, category)
    return ReducedResult(
        reduced,
        process_exit_code(reduced, surface=surface),
    )


def build_result_summary(source: SummarySource) -> AggregateRunOutcome:
    """Create one schema-typed summary with derived counts and one verdict."""
    if type(source) is not SummarySource:
        raise TypeError("source must be a SummarySource")
    result = reduce_result_categories(
        source.categories,
        surface=source.command_surface,
        durably_terminal=source.durably_terminal,
        cancellation_requested=source.cancellation_requested,
    )
    return AggregateRunOutcome(
        run_id=source.run_id,
        manifest_id=source.manifest_id,
        generated_at=source.generated_at,
        verdict=result.category,
        exit_code=result.exit_code,
        counts=source.counts,
        failure_refs=source.failure_refs,
        artifacts=source.artifacts,
    )


def _validate_terminal_records(source: SummarySource) -> None:
    scenario_ids = set(source.scenario_ids)
    record_ids: set[str] = set()
    for attempt in source.attempts:
        if attempt.run_id != source.run_id or attempt.scenario_id not in scenario_ids:
            raise ValueError("attempt record is outside the summary scope")
        if attempt.state in _NONTERMINAL_ATTEMPT_STATES:
            raise ValueError("summary attempts must be terminal")
        if attempt.record_id in record_ids:
            raise ValueError("summary record IDs must be unique")
        record_ids.add(attempt.record_id)
    for observation in source.observations:
        if observation.run_id != source.run_id or observation.scenario_id not in scenario_ids:
            raise ValueError("observation record is outside the summary scope")
        if observation.record_id in record_ids:
            raise ValueError("summary record IDs must be unique")
        record_ids.add(observation.record_id)
    for assertion in source.assertions:
        if assertion.run_id != source.run_id or assertion.scenario_id not in scenario_ids:
            raise ValueError("assertion record is outside the summary scope")
        if assertion.result is AssertionResult.PENDING:
            raise ValueError("summary assertions must be terminal")
        if assertion.record_id in record_ids:
            raise ValueError("summary record IDs must be unique")
        record_ids.add(assertion.record_id)


def _validate_failure_refs(source: SummarySource) -> None:
    if type(source.failure_refs) is not tuple:
        raise TypeError("failure_refs must be a tuple")
    available = {
        *(record.record_id for record in source.attempts),
        *(record.record_id for record in source.observations),
        *(record.record_id for record in source.assertions),
    }
    if len(set(source.failure_refs)) != len(source.failure_refs):
        raise ValueError("failure_refs must be unique")
    if not set(source.failure_refs).issubset(available):
        raise ValueError("failure_refs must reference exported records")


def _scenario_ids(values: tuple[str, ...]) -> None:
    if type(values) is not tuple:
        raise TypeError("scenario_ids must be a tuple")
    for value in values:
        validate_planned_id(value, expected_kind=PlannedIdKind.SCENARIO)
    if len(set(values)) != len(values):
        raise ValueError("scenario_ids must be unique")


def _category_tuple(values: tuple[ResultCategory, ...]) -> None:
    if type(values) is not tuple or any(type(value) is not ResultCategory for value in values):
        raise TypeError("categories must be a tuple of ResultCategory values")


def _exact_tuple(
    values: tuple[object, ...],
    item_type: type[object],
    *,
    name: str,
) -> None:
    if type(values) is not tuple or any(type(value) is not item_type for value in values):
        message = f"{name} must contain exact {item_type.__name__} values"
        raise TypeError(message)


__all__ = [
    "ReducedResult",
    "SummarySource",
    "build_result_summary",
    "pairwise_reduce",
    "reduce_result_categories",
]
