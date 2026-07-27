"""Hostile unit coverage for manifest-fixed retry policy."""
# ruff: noqa: INP001, PLR2004

from __future__ import annotations

from dataclasses import replace

import pytest

from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.enums import AttemptClassification
from webhook_receiver_conformance.manifest.models import AttemptTemplate, DeliveryPlan
from webhook_receiver_conformance.scheduler.retries import (
    JITTER_POLICY_VERSION,
    ClassifiedPredecessor,
    RetryDisposition,
    RetryPolicyError,
    RetryPredicate,
    derive_retry_delay_ns,
    derive_signed_jitter_ns,
    evaluate_retry,
)

SCENARIO_ID = "scenario_00000000000000000000000001"
EVENT_ID = "event_00000000000000000000000001"
DELIVERY_ID = "delivery_00000000000000000000000001"
ATTEMPT_ID = "attempt_00000000000000000000000001"
DIGEST = "sha256:" + ("0" * 64)


def _generator() -> ContextGenerator:
    return ContextGenerator.from_text_seed("retry-golden-seed")


def _template(
    ordinal: int,
    due: int,
    condition: str | None,
) -> AttemptTemplate:
    return AttemptTemplate(
        ordinal=ordinal,
        not_before_logical_ns=due,
        request_blob=DIGEST,
        headers_sha256=DIGEST,
        conditional_on=condition,
    )


def _delivery(
    condition: str = "timed_out|connection_failed|retryable_status",
) -> DeliveryPlan:
    return DeliveryPlan(
        delivery_id=DELIVERY_ID,
        event_id=EVENT_ID,
        logical_time_ns=10,
        ordinal=0,
        attempt_plan=(
            _template(1, 10, None),
            _template(2, 20, condition),
            _template(3, 40, condition),
        ),
    )


def _predecessor(
    *,
    ordinal: int = 1,
    classification: AttemptClassification = AttemptClassification.ENVIRONMENT_FAILURE,
    predicate: RetryPredicate | None = RetryPredicate.TIMED_OUT,
    logical_time_ns: int = 10,
    status_code: int | None = None,
) -> ClassifiedPredecessor:
    return ClassifiedPredecessor(
        attempt_id=ATTEMPT_ID,
        attempt_ordinal=ordinal,
        classification=classification,
        predicate=predicate,
        logical_time_ns=logical_time_ns,
        status_code=status_code,
    )


@pytest.mark.parametrize(
    ("classification", "predicate", "status"),
    [
        (AttemptClassification.ENVIRONMENT_FAILURE, RetryPredicate.TIMED_OUT, None),
        (AttemptClassification.ENVIRONMENT_FAILURE, RetryPredicate.CONNECTION_FAILED, None),
        (AttemptClassification.RECEIVER_REJECTED, RetryPredicate.RETRYABLE_STATUS, 503),
    ],
)
def test_all_retry_predicates_schedule(
    classification: AttemptClassification,
    predicate: RetryPredicate,
    status: int | None,
) -> None:
    decision = evaluate_retry(
        _delivery(),
        _predecessor(classification=classification, predicate=predicate, status_code=status),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    assert decision.disposition is RetryDisposition.SCHEDULED
    assert decision.next_attempt_ordinal == 2
    assert decision.logical_due_ns == 20
    assert decision.predecessor_attempt_id == ATTEMPT_ID
    assert decision.schedule_entry_id is not None
    assert decision.schedule_idempotency_key is not None
    assert decision.attempt_plan_id is not None


@pytest.mark.parametrize(
    "classification",
    [
        AttemptClassification.PLANNED,
        AttemptClassification.RECEIVER_ACCEPTED,
        AttemptClassification.RECEIVER_REJECTED,
        AttemptClassification.ENVIRONMENT_FAILURE,
        AttemptClassification.HARNESS_FAILURE,
        AttemptClassification.CANCELLED,
    ],
)
def test_all_noneligible_classifications_do_not_schedule(
    classification: AttemptClassification,
) -> None:
    decision = evaluate_retry(
        _delivery(),
        _predecessor(classification=classification, predicate=None),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    assert decision.disposition is RetryDisposition.INELIGIBLE
    assert not decision.should_schedule


def test_ambiguous_predecessor_is_blocked_even_when_template_matches() -> None:
    decision = evaluate_retry(
        _delivery(),
        _predecessor(
            classification=AttemptClassification.AMBIGUOUS,
            predicate=None,
        ),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    assert decision.disposition is RetryDisposition.AMBIGUOUS_BLOCKED
    assert not decision.should_schedule


def test_wrong_predicate_is_ineligible() -> None:
    decision = evaluate_retry(
        _delivery("connection_failed"),
        _predecessor(),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    assert decision.disposition is RetryDisposition.INELIGIBLE


def test_max_attempts_exhaustion_never_creates_a_later_attempt() -> None:
    decision = evaluate_retry(
        _delivery(),
        _predecessor(ordinal=3, logical_time_ns=40),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    assert decision.disposition is RetryDisposition.EXHAUSTED
    assert decision.template is None


@pytest.mark.parametrize(
    "plan",
    [
        (_template(1, 10, None), _template(3, 20, "timed_out")),
        (_template(1, 10, None), _template(2, 9, "timed_out")),
        (_template(1, 10, "timed_out"), _template(2, 20, "timed_out")),
        (_template(1, 10, None), _template(2, 20, None)),
        (_template(1, 10, None), _template(2, 20, "timed_out|timed_out")),
        (_template(1, 10, None), _template(2, 20, "not_a_predicate")),
    ],
)
def test_malformed_committed_attempt_plans_fail_closed(
    plan: tuple[AttemptTemplate, ...],
) -> None:
    delivery = _delivery().model_copy(update={"attempt_plan": plan})
    with pytest.raises(RetryPolicyError):
        evaluate_retry(
            delivery,
            _predecessor(),
            generator=_generator(),
            scenario_id=SCENARIO_ID,
        )


def test_wrong_predecessor_ordinal_is_rejected_by_next_template_check() -> None:
    malformed = _delivery().model_copy(
        update={
            "attempt_plan": (
                _template(1, 10, None),
                _template(2, 20, "timed_out"),
                _template(4, 40, "timed_out"),
            )
        }
    )
    with pytest.raises(RetryPolicyError):
        evaluate_retry(
            malformed,
            _predecessor(ordinal=2, logical_time_ns=20),
            generator=_generator(),
            scenario_id=SCENARIO_ID,
        )


def test_signed_logical_time_boundary_remains_monotonic() -> None:
    delivery = _delivery().model_copy(
        update={
            "attempt_plan": (
                _template(1, -20, None),
                _template(2, -10, "timed_out"),
            )
        }
    )
    decision = evaluate_retry(
        delivery,
        _predecessor(logical_time_ns=-20),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    assert decision.logical_due_ns == -10


def test_jitter_golden_vector_and_inclusive_bound() -> None:
    generator = _generator()
    actual = derive_signed_jitter_ns(
        generator,
        scenario_id=SCENARIO_ID,
        planned_delivery_id=DELIVERY_ID,
        attempt_ordinal=2,
        magnitude_bound_ns=1_000,
    )
    assert actual == generator.signed_retry_jitter(
        scenario_id=SCENARIO_ID,
        planned_delivery_id=DELIVERY_ID,
        attempt_ordinal=2,
        jitter_policy_version=JITTER_POLICY_VERSION,
        magnitude_bound=1_000,
    )
    assert actual == 740
    assert -1_000 <= actual <= 1_000


def test_zero_jitter_and_negative_delay_clamp() -> None:
    assert derive_retry_delay_ns(
        _generator(),
        scenario_id=SCENARIO_ID,
        planned_delivery_id=DELIVERY_ID,
        attempt_ordinal=2,
        base_delay_ns=0,
        magnitude_bound_ns=0,
    ) == (0, 0)
    delay, jitter = derive_retry_delay_ns(
        _generator(),
        scenario_id=SCENARIO_ID,
        planned_delivery_id=DELIVERY_ID,
        attempt_ordinal=6,
        base_delay_ns=0,
        magnitude_bound_ns=1_000,
    )
    assert jitter < 0
    assert delay == 0


def test_jitter_delay_overflow_fails_closed() -> None:
    with pytest.raises(OverflowError):
        derive_retry_delay_ns(
            _generator(),
            scenario_id=SCENARIO_ID,
            planned_delivery_id=DELIVERY_ID,
            attempt_ordinal=2,
            base_delay_ns=(2**63) - 1,
            magnitude_bound_ns=1_000,
        )


def test_jitter_and_decisions_are_order_independent() -> None:
    generator = _generator()
    contexts = [(SCENARIO_ID, DELIVERY_ID, ordinal) for ordinal in range(2, 10)]

    def draw(item: tuple[str, str, int]) -> int:
        return derive_signed_jitter_ns(
            generator,
            scenario_id=item[0],
            planned_delivery_id=item[1],
            attempt_ordinal=item[2],
            magnitude_bound_ns=10_000,
        )

    forward = {item: draw(item) for item in contexts}
    reverse = {item: draw(item) for item in reversed(contexts)}
    assert forward == reverse


def test_exact_replay_is_byte_identical_and_conflict_keeps_same_identity() -> None:
    first = evaluate_retry(
        _delivery(),
        _predecessor(),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    replay = evaluate_retry(
        _delivery(),
        _predecessor(),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    conflict = evaluate_retry(
        _delivery(),
        replace(_predecessor(), predicate=RetryPredicate.CONNECTION_FAILED),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    assert first == replay
    assert first.condition_json == replay.condition_json
    assert first.schedule_idempotency_key == conflict.schedule_idempotency_key
    assert first.schedule_entry_id == conflict.schedule_entry_id
    assert first.condition_json != conflict.condition_json


@pytest.mark.parametrize(
    "predecessor",
    [
        lambda: _predecessor(
            classification=AttemptClassification.RECEIVER_REJECTED,
            predicate=RetryPredicate.RETRYABLE_STATUS,
        ),
        lambda: _predecessor(
            classification=AttemptClassification.RECEIVER_ACCEPTED,
            predicate=RetryPredicate.TIMED_OUT,
        ),
        lambda: _predecessor(status_code=503),
        lambda: _predecessor(
            classification=AttemptClassification.AMBIGUOUS,
            predicate=RetryPredicate.CONNECTION_FAILED,
        ),
    ],
)
def test_inconsistent_classified_outcomes_are_rejected(
    predecessor: object,
) -> None:
    with pytest.raises(RetryPolicyError):
        predecessor()  # type: ignore[operator]


def test_policy_is_pure_and_never_invokes_transport() -> None:
    # The retry boundary accepts no HTTP executor/client/transport dependency.
    decision = evaluate_retry(
        _delivery(),
        _predecessor(),
        generator=_generator(),
        scenario_id=SCENARIO_ID,
    )
    assert decision.should_schedule
