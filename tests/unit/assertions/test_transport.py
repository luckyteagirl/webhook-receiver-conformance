"""Transport assertion evaluation from durable attempt evidence."""
# ruff: noqa: INP001, PLR2004

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from webhook_receiver_conformance.assertions.transport import (
    TransportAssertionCode,
    TransportAssertionInput,
    evaluate_transport_assertion,
)
from webhook_receiver_conformance.config.models import (
    AcknowledgementDeadlineAssertion,
    HttpStatusAssertion,
    HttpStatusClass,
)
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AttemptClassification,
    AttemptEvidenceState,
)
from webhook_receiver_conformance.domain.models import (
    AttemptEvidence,
    RequestMetadata,
    ResponseMetadata,
    TransportError,
)

RUN_ID = "00000000-0000-4000-8000-000000000001"
SCENARIO_ID = "scenario_" + ("0" * 25) + "1"
EVENT_ID = "event_" + ("0" * 25) + "1"
DELIVERY_ID = "delivery_" + ("0" * 25) + "1"
ATTEMPT_ID = "attempt_" + ("0" * 25) + "1"
RECORD_ID = "record_" + ("0" * 25) + "1"
DIGEST = "sha256:" + ("0" * 64)


def _attempt(
    status: int | None,
    *,
    terminal_elapsed_ns: int = 9_000_000_000,
    truncated: bool = False,
) -> AttemptEvidence:
    accepted = status is not None and 200 <= status <= 299
    response = (
        ResponseMetadata(
            status=status,
            body_sha256=DIGEST,
            captured_bytes=10,
            truncated=truncated,
        )
        if status is not None
        else None
    )
    return AttemptEvidence(
        record_id=RECORD_ID,
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        attempt_id=ATTEMPT_ID,
        sequence=1,
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
        monotonic_elapsed_ns=terminal_elapsed_ns,
        state=(
            AttemptEvidenceState.ACKNOWLEDGED
            if accepted
            else (
                AttemptEvidenceState.REJECTED
                if status is not None
                else AttemptEvidenceState.CONNECTION_FAILED
            )
        ),
        classification=(
            AttemptClassification.RECEIVER_ACCEPTED
            if accepted
            else (
                AttemptClassification.RECEIVER_REJECTED
                if status is not None
                else AttemptClassification.ENVIRONMENT_FAILURE
            )
        ),
        request=RequestMetadata(
            url_redacted="http://127.0.0.1/[REDACTED]",
            body_sha256=DIGEST,
            byte_length=1,
        ),
        response=response,
        error=(
            None
            if status is not None
            else TransportError(
                category="connection_error",
                message_redacted="connection failed",
            )
        ),
    )


def _status_assertion(
    *,
    codes: list[int] | None = None,
    classes: list[str] | None = None,
) -> HttpStatusAssertion:
    expected: dict[str, object] = {}
    if codes is not None:
        expected["codes"] = codes
    if classes is not None:
        expected["classes"] = classes
    return HttpStatusAssertion.model_validate(
        {
            "id": "status",
            "type": "http-status",
            "attempt": {"event": "event", "mode": "last-terminal"},
            "expected": expected,
        }
    )


def _deadline(within: str = "100ms") -> AcknowledgementDeadlineAssertion:
    return AcknowledgementDeadlineAssertion.model_validate(
        {
            "id": "ack",
            "type": "acknowledgement-deadline",
            "attempt": {"event": "event", "mode": "last-terminal"},
            "within": within,
        }
    )


@pytest.mark.parametrize("codes", [[200], [200, 202]])
def test_exact_and_membership_status_pass(codes: list[int]) -> None:
    evaluation = evaluate_transport_assertion(_status_assertion(codes=codes), _attempt(200))
    assert evaluation.result is AssertionResult.PASS
    assert evaluation.code is TransportAssertionCode.STATUS_MATCH


def test_rejection_status_can_pass_expected_membership_and_mismatch_fails() -> None:
    accepted = evaluate_transport_assertion(
        _status_assertion(codes=[400, 422]),
        _attempt(400),
    )
    mismatched = evaluate_transport_assertion(_status_assertion(codes=[200]), _attempt(400))
    assert accepted.result is AssertionResult.PASS
    assert accepted.actual_status == 400
    assert mismatched.result is AssertionResult.FAIL


def test_missing_response_is_error_not_fail() -> None:
    evaluation = evaluate_transport_assertion(_status_assertion(codes=[200]), _attempt(None))
    assert evaluation.result is AssertionResult.ERROR
    assert evaluation.code is TransportAssertionCode.RESPONSE_MISSING


@pytest.mark.parametrize(
    ("status", "expected_class", "expected_result"),
    [
        (199, "2xx", AssertionResult.FAIL),
        (200, "2xx", AssertionResult.PASS),
        (299, "2xx", AssertionResult.PASS),
        (300, "3xx", AssertionResult.PASS),
        (399, "3xx", AssertionResult.PASS),
        (400, "4xx", AssertionResult.PASS),
        (499, "4xx", AssertionResult.PASS),
        (500, "5xx", AssertionResult.PASS),
        (599, "5xx", AssertionResult.PASS),
    ],
)
def test_status_class_boundaries(
    status: int,
    expected_class: str,
    expected_result: AssertionResult,
) -> None:
    evaluation = evaluate_transport_assertion(
        _status_assertion(classes=[expected_class]),
        _attempt(status),
    )
    assert evaluation.result is expected_result
    assert evaluation.expected_classes == (HttpStatusClass(expected_class),)


def test_prompt_headers_pass_despite_delayed_body_terminal_time() -> None:
    evidence = TransportAssertionInput(
        _attempt(200, terminal_elapsed_ns=5_000_000_000, truncated=False),
        response_headers_elapsed_ns=50_000_000,
    )
    evaluation = evaluate_transport_assertion(_deadline(), evidence)
    assert evaluation.result is AssertionResult.PASS
    assert evaluation.response_headers_elapsed_ns == 50_000_000


def test_delayed_headers_fail_at_boundary_and_beyond() -> None:
    at_boundary = evaluate_transport_assertion(
        _deadline(),
        TransportAssertionInput(_attempt(200), response_headers_elapsed_ns=100_000_000),
    )
    delayed = evaluate_transport_assertion(
        _deadline(),
        TransportAssertionInput(_attempt(200), response_headers_elapsed_ns=100_000_001),
    )
    assert at_boundary.result is AssertionResult.PASS
    assert delayed.result is AssertionResult.FAIL
    assert delayed.code is TransportAssertionCode.ACKNOWLEDGEMENT_DEADLINE_EXCEEDED


@pytest.mark.parametrize(
    "evidence",
    [
        TransportAssertionInput(_attempt(200), response_headers_elapsed_ns=None),
        TransportAssertionInput(_attempt(None), response_headers_elapsed_ns=1),
    ],
)
def test_missing_timing_or_response_is_error(evidence: TransportAssertionInput) -> None:
    evaluation = evaluate_transport_assertion(_deadline(), evidence)
    assert evaluation.result is AssertionResult.ERROR


def test_terminal_elapsed_time_is_never_used_as_header_latency() -> None:
    evaluation = evaluate_transport_assertion(_deadline("1ms"), _attempt(200))
    assert evaluation.result is AssertionResult.ERROR
    assert evaluation.code is TransportAssertionCode.HEADER_TIMING_MISSING
