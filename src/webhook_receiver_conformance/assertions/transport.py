"""Pure transport assertions over durable attempt evidence."""
# ruff: noqa: C901, D105, EM101, EM102, INP001, PLR0913, PLR2004, TRY003

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from webhook_receiver_conformance.config.models import (
    AcknowledgementDeadlineAssertion,
    HttpStatusAssertion,
    HttpStatusClass,
)
from webhook_receiver_conformance.domain.enums import AssertionResult
from webhook_receiver_conformance.domain.models import AttemptEvidence

type TransportAssertion = HttpStatusAssertion | AcknowledgementDeadlineAssertion
_MAX_SIGNED_INT64 = (2**63) - 1


class TransportAssertionCode(StrEnum):
    """Stable message-independent transport evaluation facts."""

    STATUS_MATCH = "status_match"
    STATUS_MISMATCH = "status_mismatch"
    RESPONSE_MISSING = "response_missing"
    HEADER_TIMING_MISSING = "header_timing_missing"
    ACKNOWLEDGEMENT_WITHIN_DEADLINE = "acknowledgement_within_deadline"
    ACKNOWLEDGEMENT_DEADLINE_EXCEEDED = "acknowledgement_deadline_exceeded"


@dataclass(frozen=True, slots=True)
class TransportAssertionInput:
    """Durable attempt evidence plus authoritative response-header latency."""

    attempt: AttemptEvidence
    response_headers_elapsed_ns: int | None = None

    def __post_init__(self) -> None:
        if type(self.attempt) is not AttemptEvidence:
            raise TypeError("attempt must be an AttemptEvidence")
        if self.response_headers_elapsed_ns is not None and (
            type(self.response_headers_elapsed_ns) is not int
            or not 0 <= self.response_headers_elapsed_ns <= _MAX_SIGNED_INT64
        ):
            raise ValueError("response_headers_elapsed_ns must be a nonnegative integer or None")


@dataclass(frozen=True, slots=True)
class TransportAssertionEvaluation:
    """Deterministic pass/fail/error facts for later journal integration."""

    assertion_id: str
    attempt_id: str
    result: AssertionResult
    code: TransportAssertionCode
    expected_statuses: tuple[int, ...] = ()
    expected_classes: tuple[HttpStatusClass, ...] = ()
    actual_status: int | None = None
    deadline_ns: int | None = None
    response_headers_elapsed_ns: int | None = None

    def __post_init__(self) -> None:
        if type(self.assertion_id) is not str or not self.assertion_id:
            raise ValueError("assertion_id must be a nonempty string")
        if type(self.attempt_id) is not str or not self.attempt_id:
            raise ValueError("attempt_id must be a nonempty string")
        if type(self.result) is not AssertionResult:
            raise TypeError("result must be an AssertionResult")
        if self.result not in {
            AssertionResult.PASS,
            AssertionResult.FAIL,
            AssertionResult.ERROR,
        }:
            raise ValueError("transport assertion result must be pass, fail, or error")
        if type(self.code) is not TransportAssertionCode:
            raise TypeError("code must be a TransportAssertionCode")
        if type(self.expected_statuses) is not tuple or any(
            type(status) is not int or not 100 <= status <= 599 for status in self.expected_statuses
        ):
            raise TypeError("expected_statuses must contain HTTP status integers")
        if type(self.expected_classes) is not tuple or any(
            type(status_class) is not HttpStatusClass for status_class in self.expected_classes
        ):
            raise TypeError("expected_classes must contain HttpStatusClass values")
        if self.actual_status is not None and (
            type(self.actual_status) is not int or not 100 <= self.actual_status <= 599
        ):
            raise ValueError("actual_status must be an HTTP status or None")
        for value, name in (
            (self.deadline_ns, "deadline_ns"),
            (self.response_headers_elapsed_ns, "response_headers_elapsed_ns"),
        ):
            if value is not None and (
                type(value) is not int or not 0 <= value <= _MAX_SIGNED_INT64
            ):
                raise ValueError(f"{name} must be a nonnegative signed-int64 integer or None")


def evaluate_transport_assertion(
    assertion: TransportAssertion,
    evidence: AttemptEvidence | TransportAssertionInput,
) -> TransportAssertionEvaluation:
    """Evaluate one supported transport assertion against exact attempt evidence."""
    if type(assertion) not in {
        HttpStatusAssertion,
        AcknowledgementDeadlineAssertion,
    }:
        raise TypeError("assertion must be a supported transport assertion")
    if type(evidence) is AttemptEvidence:
        supplied = TransportAssertionInput(evidence)
    elif type(evidence) is TransportAssertionInput:
        supplied = evidence
    else:
        raise TypeError("evidence must be AttemptEvidence or TransportAssertionInput")
    if type(assertion) is HttpStatusAssertion:
        return _evaluate_status(assertion, supplied.attempt)
    return _evaluate_acknowledgement(
        cast("AcknowledgementDeadlineAssertion", assertion),
        supplied,
    )


def _evaluate_status(
    assertion: HttpStatusAssertion,
    attempt: AttemptEvidence,
) -> TransportAssertionEvaluation:
    response = attempt.response
    codes = assertion.expected.codes or ()
    classes = assertion.expected.classes or ()
    if response is None:
        return _evaluation(
            assertion.id,
            attempt.attempt_id,
            AssertionResult.ERROR,
            TransportAssertionCode.RESPONSE_MISSING,
            expected_statuses=codes,
            expected_classes=classes,
        )
    status = response.status
    matched = status in codes or _status_class(status) in classes
    return _evaluation(
        assertion.id,
        attempt.attempt_id,
        AssertionResult.PASS if matched else AssertionResult.FAIL,
        (
            TransportAssertionCode.STATUS_MATCH
            if matched
            else TransportAssertionCode.STATUS_MISMATCH
        ),
        expected_statuses=codes,
        expected_classes=classes,
        actual_status=status,
    )


def _evaluate_acknowledgement(
    assertion: AcknowledgementDeadlineAssertion,
    supplied: TransportAssertionInput,
) -> TransportAssertionEvaluation:
    attempt = supplied.attempt
    deadline = assertion.within.nanoseconds
    if attempt.response is None:
        return _evaluation(
            assertion.id,
            attempt.attempt_id,
            AssertionResult.ERROR,
            TransportAssertionCode.RESPONSE_MISSING,
            deadline_ns=deadline,
        )
    elapsed = supplied.response_headers_elapsed_ns
    if elapsed is None:
        return _evaluation(
            assertion.id,
            attempt.attempt_id,
            AssertionResult.ERROR,
            TransportAssertionCode.HEADER_TIMING_MISSING,
            actual_status=attempt.response.status,
            deadline_ns=deadline,
        )
    within = elapsed <= deadline
    return _evaluation(
        assertion.id,
        attempt.attempt_id,
        AssertionResult.PASS if within else AssertionResult.FAIL,
        (
            TransportAssertionCode.ACKNOWLEDGEMENT_WITHIN_DEADLINE
            if within
            else TransportAssertionCode.ACKNOWLEDGEMENT_DEADLINE_EXCEEDED
        ),
        actual_status=attempt.response.status,
        deadline_ns=deadline,
        response_headers_elapsed_ns=elapsed,
    )


def _status_class(status: int) -> HttpStatusClass | None:
    if 200 <= status <= 299:
        return HttpStatusClass.SUCCESS
    if 300 <= status <= 399:
        return HttpStatusClass.REDIRECTION
    if 400 <= status <= 499:
        return HttpStatusClass.CLIENT_ERROR
    if 500 <= status <= 599:
        return HttpStatusClass.SERVER_ERROR
    return None


def _evaluation(
    assertion_id: str,
    attempt_id: str,
    result: AssertionResult,
    code: TransportAssertionCode,
    *,
    expected_statuses: tuple[int, ...] = (),
    expected_classes: tuple[HttpStatusClass, ...] = (),
    actual_status: int | None = None,
    deadline_ns: int | None = None,
    response_headers_elapsed_ns: int | None = None,
) -> TransportAssertionEvaluation:
    return TransportAssertionEvaluation(
        assertion_id=assertion_id,
        attempt_id=attempt_id,
        result=result,
        code=code,
        expected_statuses=expected_statuses,
        expected_classes=expected_classes,
        actual_status=actual_status,
        deadline_ns=deadline_ns,
        response_headers_elapsed_ns=response_headers_elapsed_ns,
    )


__all__ = [
    "TransportAssertionCode",
    "TransportAssertionEvaluation",
    "TransportAssertionInput",
    "evaluate_transport_assertion",
]
