"""Isolated tests for deterministic terminal-verdict policy."""
# ruff: noqa: INP001

from __future__ import annotations

import pytest

from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    AttemptClassification,
)
from webhook_receiver_conformance.errors import ResultCategory, exit_for_result
from webhook_receiver_conformance.runtime.verdicts import (
    AssertionErrorOrigin,
    classify_assertion_verdict,
    classify_attempt_verdict,
    reduce_terminal_verdicts,
)


@pytest.mark.parametrize(
    ("classification", "expected"),
    [
        (AttemptClassification.PLANNED, ResultCategory.PASS),
        (AttemptClassification.RECEIVER_ACCEPTED, ResultCategory.PASS),
        (AttemptClassification.RECEIVER_REJECTED, ResultCategory.RECEIVER_FAILURE),
        (AttemptClassification.ENVIRONMENT_FAILURE, ResultCategory.ENVIRONMENT_ERROR),
        (AttemptClassification.HARNESS_FAILURE, ResultCategory.HARNESS_ERROR),
        (AttemptClassification.CANCELLED, ResultCategory.CANCELLED),
        (AttemptClassification.AMBIGUOUS, ResultCategory.AMBIGUOUS),
    ],
)
def test_attempt_classification_has_one_terminal_category(
    classification: AttemptClassification,
    expected: ResultCategory,
) -> None:
    verdict = classify_attempt_verdict(classification)

    assert verdict.category is expected
    assert verdict.exit_code is exit_for_result(expected)[1]


@pytest.mark.parametrize(
    ("result", "state", "origin", "expected"),
    [
        (
            AssertionResult.PASS,
            AssertionState.PASSED,
            None,
            ResultCategory.PASS,
        ),
        (
            AssertionResult.FAIL,
            AssertionState.FAILED,
            None,
            ResultCategory.RECEIVER_FAILURE,
        ),
        (
            AssertionResult.ERROR,
            AssertionState.UNSUPPORTED,
            None,
            ResultCategory.UNSUPPORTED,
        ),
        (
            AssertionResult.ERROR,
            AssertionState.ERROR,
            AssertionErrorOrigin.ENVIRONMENT,
            ResultCategory.ENVIRONMENT_ERROR,
        ),
        (
            AssertionResult.ERROR,
            AssertionState.ERROR,
            AssertionErrorOrigin.HARNESS,
            ResultCategory.HARNESS_ERROR,
        ),
        (
            AssertionResult.ERROR,
            AssertionState.ERROR,
            AssertionErrorOrigin.INVALID_INPUT,
            ResultCategory.INVALID_INPUT,
        ),
        (
            AssertionResult.ERROR,
            AssertionState.CANCELLED,
            None,
            ResultCategory.CANCELLED,
        ),
    ],
)
def test_assertion_lifecycle_has_one_terminal_category(
    result: AssertionResult,
    state: AssertionState,
    origin: AssertionErrorOrigin | None,
    expected: ResultCategory,
) -> None:
    verdict = classify_assertion_verdict(result, state, error_origin=origin)

    assert verdict.category is expected


def test_assertion_error_requires_an_explicit_origin() -> None:
    with pytest.raises(ValueError, match="explicit error origin"):
        classify_assertion_verdict(AssertionResult.ERROR, AssertionState.ERROR)


def test_mismatched_assertion_facts_are_rejected() -> None:
    with pytest.raises(ValueError, match="do not form a terminal verdict"):
        classify_assertion_verdict(AssertionResult.PASS, AssertionState.FAILED)


def test_terminal_reduction_uses_locked_precedence() -> None:
    verdict = reduce_terminal_verdicts(
        (
            ResultCategory.PASS,
            ResultCategory.RECEIVER_FAILURE,
            ResultCategory.AMBIGUOUS,
            ResultCategory.HARNESS_ERROR,
        )
    )

    assert verdict.category is ResultCategory.HARNESS_ERROR


def test_durable_terminal_result_cannot_be_reclassified() -> None:
    verdict = reduce_terminal_verdicts(
        (ResultCategory.HARNESS_ERROR,),
        durably_terminal=ResultCategory.RECEIVER_FAILURE,
    )

    assert verdict.category is ResultCategory.RECEIVER_FAILURE


def test_terminal_reduction_rejects_an_empty_inventory() -> None:
    with pytest.raises(TypeError, match="nonempty tuple"):
        reduce_terminal_verdicts(())
