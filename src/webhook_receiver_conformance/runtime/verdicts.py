"""Deterministic terminal-result classification for runtime evidence."""
# ruff: noqa: D105, EM101, INP001, TRY003

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    AttemptClassification,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory, exit_for_result


class AssertionErrorOrigin(StrEnum):
    """Closed causes for a non-comparable assertion evaluation error."""

    ENVIRONMENT = "environment"
    HARNESS = "harness"
    INVALID_INPUT = "invalid_input"


_ERROR_RESULT: Final = MappingProxyType(
    {
        AssertionErrorOrigin.ENVIRONMENT: ResultCategory.ENVIRONMENT_ERROR,
        AssertionErrorOrigin.HARNESS: ResultCategory.HARNESS_ERROR,
        AssertionErrorOrigin.INVALID_INPUT: ResultCategory.INVALID_INPUT,
    }
)

_ATTEMPT_RESULT: Final = MappingProxyType(
    {
        AttemptClassification.PLANNED: ResultCategory.PASS,
        AttemptClassification.RECEIVER_ACCEPTED: ResultCategory.PASS,
        AttemptClassification.RECEIVER_REJECTED: ResultCategory.RECEIVER_FAILURE,
        AttemptClassification.ENVIRONMENT_FAILURE: ResultCategory.ENVIRONMENT_ERROR,
        AttemptClassification.HARNESS_FAILURE: ResultCategory.HARNESS_ERROR,
        AttemptClassification.CANCELLED: ResultCategory.CANCELLED,
        AttemptClassification.AMBIGUOUS: ResultCategory.AMBIGUOUS,
    }
)

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
    {category: index for index, category in enumerate(_PRECEDENCE)}
)


@dataclass(frozen=True, slots=True)
class TerminalVerdict:
    """One exact terminal category and its documented process exit code."""

    category: ResultCategory
    exit_code: ExitCode

    def __post_init__(self) -> None:
        if type(self.category) is not ResultCategory:
            raise TypeError("category must be a ResultCategory")
        if type(self.exit_code) is not ExitCode:
            raise TypeError("exit_code must be an ExitCode")
        if exit_for_result(self.category)[1] is not self.exit_code:
            raise ValueError("exit_code does not match terminal category")


def classify_assertion_verdict(
    result: AssertionResult,
    state: AssertionState,
    *,
    error_origin: AssertionErrorOrigin | None = None,
) -> TerminalVerdict:
    """Classify one assertion without treating invalid evidence as receiver failure."""
    if type(result) is not AssertionResult:
        raise TypeError("result must be an AssertionResult")
    if type(state) is not AssertionState:
        raise TypeError("state must be an AssertionState")
    if error_origin is not None and type(error_origin) is not AssertionErrorOrigin:
        raise TypeError("error_origin must be an AssertionErrorOrigin or None")

    if state is AssertionState.PASSED and result is AssertionResult.PASS:
        return terminal_verdict(ResultCategory.PASS)
    if state is AssertionState.FAILED and result is AssertionResult.FAIL:
        return terminal_verdict(ResultCategory.RECEIVER_FAILURE)
    if state is AssertionState.UNSUPPORTED and result in {
        AssertionResult.ERROR,
        AssertionResult.SKIPPED,
    }:
        return terminal_verdict(ResultCategory.UNSUPPORTED)
    if state is AssertionState.ERROR and result is AssertionResult.ERROR:
        if error_origin is None:
            raise ValueError("errored assertions require an explicit error origin")
        return terminal_verdict(_ERROR_RESULT[error_origin])
    if state is AssertionState.CANCELLED:
        return terminal_verdict(ResultCategory.CANCELLED)
    raise ValueError("assertion result and lifecycle state do not form a terminal verdict")


def classify_attempt_verdict(
    classification: AttemptClassification,
) -> TerminalVerdict:
    """Map one durable attempt classification to the FR-006 vocabulary."""
    if type(classification) is not AttemptClassification:
        raise TypeError("classification must be an AttemptClassification")
    return terminal_verdict(_ATTEMPT_RESULT[classification])


def reduce_terminal_verdicts(
    categories: tuple[ResultCategory, ...],
    *,
    durably_terminal: ResultCategory | None = None,
) -> TerminalVerdict:
    """Reduce facts by locked precedence while preserving a durable terminal result."""
    if (
        type(categories) is not tuple
        or not categories
        or any(type(category) is not ResultCategory for category in categories)
    ):
        raise TypeError("categories must be a nonempty tuple of ResultCategory values")
    if durably_terminal is not None:
        if type(durably_terminal) is not ResultCategory:
            raise TypeError("durably_terminal must be a ResultCategory or None")
        return terminal_verdict(durably_terminal)
    return terminal_verdict(min(categories, key=_PRECEDENCE_INDEX.__getitem__))


def terminal_verdict(category: ResultCategory) -> TerminalVerdict:
    """Return the exact category/exit pair from the public CLI contract."""
    if type(category) is not ResultCategory:
        raise TypeError("category must be a ResultCategory")
    return TerminalVerdict(category, exit_for_result(category)[1])


__all__ = [
    "AssertionErrorOrigin",
    "TerminalVerdict",
    "classify_assertion_verdict",
    "classify_attempt_verdict",
    "reduce_terminal_verdicts",
    "terminal_verdict",
]
