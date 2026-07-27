"""Temporal and all-or-none receiver-state assertion tests."""
# ruff: noqa: INP001

from __future__ import annotations

import pytest

from webhook_receiver_conformance.assertions.composite import (
    CompositeAssertionCode,
    EvidencePredicateCode,
    evaluate_no_partial_side_effect_assertion,
)
from webhook_receiver_conformance.assertions.temporal import (
    TemporalAssertionCode,
    TemporalPredicateError,
    evaluate_eventual_state_assertion,
    evaluate_ordered_transition_assertion,
    eventual_state_predicate,
    ordered_transition_predicate,
)
from webhook_receiver_conformance.config.models import (
    EventualStateAssertion,
    NoPartialSideEffectAssertion,
    OrderedTransitionAssertion,
)
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    EvidenceValueType,
    ObservationState,
)
from webhook_receiver_conformance.observers.polling import (
    ObservationPollOutcome,
    ObservationPollResult,
)
from webhook_receiver_conformance.observers.protocol import (
    ObserverCapabilities,
    ObserverEvidence,
    ObserverResponse,
    ObserverResponseStatus,
    ObserverWireError,
)

REQUEST_ID = "request_01J00000000000000000000000"
SAMPLE_IDS = (
    "sample_01J00000000000000000000000",
    "sample_01J00000000000000000000001",
    "sample_01J00000000000000000000002",
)
SECRET_CANARY = "temporal-super-secret-canary"  # noqa: S105


def _query(key: str, *, observer: str = "receiver_state") -> dict[str, object]:
    return {
        "observer": observer,
        "key": key,
        "parameters": {"event": "payment"},
    }


def _ordered(*, allow_intermediate: bool = False) -> OrderedTransitionAssertion:
    return OrderedTransitionAssertion.model_validate(
        {
            "id": "order_transitions",
            "type": "ordered-transition",
            "query": _query("transitions"),
            "states": ["received", "processed"],
            "allow_intermediate": allow_intermediate,
        }
    )


def _eventual(
    *,
    expected: object = "processed",
    value_type: str = "string",
    path: str | None = None,
    on_unsupported: str = "unsupported",
) -> EventualStateAssertion:
    payload: dict[str, object] = {
        "id": "eventual_processing",
        "type": "eventual-state",
        "query": _query("resource"),
        "comparator": "eq",
        "expected": {"value_type": value_type, "value": expected},
        "within": "1s",
        "poll_interval": "50ms",
        "on_unsupported": on_unsupported,
    }
    if path is not None:
        payload["path"] = path
        payload["missing_pointer"] = "error"
    return EventualStateAssertion.model_validate(payload)


def _composite(
    *,
    on_unsupported: str = "unsupported",
    outbox_observer: str = "receiver_state",
) -> NoPartialSideEffectAssertion:
    return NoPartialSideEffectAssertion.model_validate(
        {
            "id": "atomic_order_write",
            "type": "no-partial-side-effect",
            "on_unsupported": on_unsupported,
            "predicates": [
                {
                    "name": "order_updated",
                    "query": _query("order_updated"),
                    "comparator": "eq",
                    "expected": {"value_type": "boolean", "value": True},
                },
                {
                    "name": "outbox_entry",
                    "query": _query("outbox_entry", observer=outbox_observer),
                    "comparator": "eq",
                    "expected": {"value_type": "boolean", "value": True},
                },
            ],
        }
    )


def _evidence(
    key: str,
    value_type: str,
    value: object,
    *,
    sensitive: bool = False,
) -> ObserverEvidence:
    return ObserverEvidence.model_validate(
        {
            "key": key,
            "value_type": value_type,
            "value": value,
            "sensitive": sensitive,
        }
    )


def _capabilities() -> ObserverCapabilities:
    return ObserverCapabilities(
        evidence_types=tuple(EvidenceValueType),
        evidence_keys=("transitions", "resource", "order_updated", "outbox_entry"),
        read_only=True,
        idempotent=True,
        supports_pending=True,
        stable_snapshot_ids=True,
    )


def _response(
    evidence: tuple[ObserverEvidence, ...] = (),
    *,
    status: ObserverResponseStatus = ObserverResponseStatus.OK,
) -> ObserverResponse:
    return ObserverResponse(
        protocol_version="1.0",
        request_id=REQUEST_ID,
        status=status,
        capabilities=_capabilities(),
        snapshot_id="snapshot-atomic-1" if status is ObserverResponseStatus.OK else None,
        evidence=evidence if status is ObserverResponseStatus.OK else (),
        error=(
            ObserverWireError(
                category="observer_unavailable",
                message="safe observer error",
                retryable=False,
            )
            if status is ObserverResponseStatus.ERROR
            else None
        ),
    )


def _poll(
    outcome: ObservationPollOutcome,
    *,
    response: ObserverResponse | None,
    sample_ids: tuple[str, ...] = SAMPLE_IDS,
    valid_evidence_seen: bool = False,
    deadline_elapsed: bool = False,
) -> ObservationPollResult:
    return ObservationPollResult(
        outcome=outcome,
        final_state={
            ObservationPollOutcome.MATCHED: ObservationState.OK,
            ObservationPollOutcome.MISMATCH: ObservationState.OK,
            ObservationPollOutcome.PENDING: ObservationState.PENDING,
            ObservationPollOutcome.UNSUPPORTED: ObservationState.UNSUPPORTED,
            ObservationPollOutcome.ERROR: ObservationState.ERROR,
            ObservationPollOutcome.TIMED_OUT: ObservationState.TIMED_OUT,
        }[outcome],
        sample_ids=sample_ids,
        predicate_matched=outcome is ObservationPollOutcome.MATCHED,
        valid_evidence_seen=valid_evidence_seen,
        deadline_elapsed=deadline_elapsed,
        last_response=response,
    )


def test_ordered_transition_allows_unrelated_intermediates_only_when_configured() -> None:
    evidence = (
        _evidence(
            "transitions",
            "array",
            ["received", "queued", "processed"],
        ),
    )

    prohibited = evaluate_ordered_transition_assertion(_ordered(), evidence)
    allowed = evaluate_ordered_transition_assertion(
        _ordered(allow_intermediate=True),
        evidence,
    )

    assert (prohibited.result, prohibited.code) == (
        AssertionResult.FAIL,
        TemporalAssertionCode.ORDER_MISMATCH,
    )
    assert (allowed.result, allowed.code) == (
        AssertionResult.PASS,
        TemporalAssertionCode.ORDER_MATCH,
    )


def test_ordered_transition_accepts_contiguous_sequence_with_unrelated_edges() -> None:
    result = evaluate_ordered_transition_assertion(
        _ordered(),
        (
            _evidence(
                "transitions",
                "array",
                ["created", "received", "processed", "archived"],
            ),
        ),
    )
    assert result.result is AssertionResult.PASS


def test_ordered_transition_accepts_strict_typed_timestamped_entries() -> None:
    result = evaluate_ordered_transition_assertion(
        _ordered(),
        (
            _evidence(
                "transitions",
                "array",
                [
                    {
                        "state": "received",
                        "timestamp": "2026-07-27T20:00:00.000000Z",
                    },
                    {"state": "processed"},
                ],
            ),
        ),
    )
    assert result.result is AssertionResult.PASS


@pytest.mark.parametrize(
    "transitions",
    [
        ["received", ""],
        [{"state": "received", "timestamp": None}, {"state": "processed"}],
        [{"state": "received", "extra": True}, {"state": "processed"}],
        [{"timestamp": "2026-07-27T20:00:00.000000Z"}, {"state": "processed"}],
    ],
)
def test_ordered_transition_classifies_malformed_sequence_evidence(
    transitions: list[object],
) -> None:
    result = evaluate_ordered_transition_assertion(
        _ordered(),
        (_evidence("transitions", "array", transitions),),
    )
    assert (result.result, result.code) == (
        AssertionResult.ERROR,
        TemporalAssertionCode.EVIDENCE_TYPE_MISMATCH,
    )


def test_ordered_transition_missing_duplicate_and_wrong_type_are_errors() -> None:
    assertion = _ordered()
    missing = evaluate_ordered_transition_assertion(assertion, ())
    duplicate = evaluate_ordered_transition_assertion(
        assertion,
        (
            _evidence("transitions", "array", ["received", "processed"]),
            _evidence("transitions", "array", ["received", "processed"]),
        ),
    )
    wrong_type = evaluate_ordered_transition_assertion(
        assertion,
        (_evidence("transitions", "string", "received"),),
    )
    assert missing.code is TemporalAssertionCode.EVIDENCE_MISSING
    assert duplicate.code is TemporalAssertionCode.EVIDENCE_DUPLICATE
    assert wrong_type.code is TemporalAssertionCode.EVIDENCE_TYPE_MISMATCH
    assert {missing.result, duplicate.result, wrong_type.result} == {AssertionResult.ERROR}


def test_temporal_predicates_return_bool_or_raise_classified_safe_error() -> None:
    predicate = ordered_transition_predicate(_ordered())
    assert predicate(
        _response(
            (_evidence("transitions", "array", ["received", "processed"]),),
        )
    )
    with pytest.raises(TemporalPredicateError) as captured:
        predicate(_response((_evidence("resource", "string", SECRET_CANARY, sensitive=True),)))
    assert captured.value.code is TemporalAssertionCode.EVIDENCE_MISSING
    assert SECRET_CANARY not in repr(captured.value)


def test_eventual_predicate_uses_strict_typed_comparison_and_json_pointer() -> None:
    scalar = eventual_state_predicate(_eventual(expected=1, value_type="integer"))
    pointer = eventual_state_predicate(_eventual(path="/status"))

    assert scalar(_response((_evidence("resource", "integer", 1),)))
    assert not scalar(_response((_evidence("resource", "string", "1"),)))
    assert pointer(_response((_evidence("resource", "object", {"status": "processed"}),)))


def test_eventual_match_preserves_every_sample_id_and_terminal_pass() -> None:
    response = _response((_evidence("resource", "string", "processed"),))
    result = evaluate_eventual_state_assertion(
        _eventual(),
        _poll(
            ObservationPollOutcome.MATCHED,
            response=response,
            valid_evidence_seen=True,
        ),
    )
    assert (result.result, result.code, result.terminal) == (
        AssertionResult.PASS,
        TemporalAssertionCode.EVENTUAL_MATCH,
        "pass",
    )
    assert result.sample_ids == SAMPLE_IDS


def test_eventual_deadline_with_valid_contrary_evidence_is_terminal_failure() -> None:
    response = _response((_evidence("resource", "string", "queued"),))
    result = evaluate_eventual_state_assertion(
        _eventual(),
        _poll(
            ObservationPollOutcome.TIMED_OUT,
            response=response,
            valid_evidence_seen=True,
            deadline_elapsed=True,
        ),
    )
    assert (result.result, result.code, result.terminal) == (
        AssertionResult.FAIL,
        TemporalAssertionCode.EVENTUAL_DEADLINE_MISMATCH,
        "timeout",
    )
    assert result.sample_ids == SAMPLE_IDS


@pytest.mark.parametrize(
    ("valid_evidence_seen", "deadline_elapsed"),
    [(False, True), (True, False)],
)
def test_eventual_observer_timeout_is_error_not_receiver_failure(
    valid_evidence_seen: bool,  # noqa: FBT001
    deadline_elapsed: bool,  # noqa: FBT001
) -> None:
    response = (
        _response((_evidence("resource", "string", "queued"),)) if valid_evidence_seen else None
    )
    result = evaluate_eventual_state_assertion(
        _eventual(),
        _poll(
            ObservationPollOutcome.TIMED_OUT,
            response=response,
            valid_evidence_seen=valid_evidence_seen,
            deadline_elapsed=deadline_elapsed,
        ),
    )
    assert (result.result, result.code, result.terminal) == (
        AssertionResult.ERROR,
        TemporalAssertionCode.EVENTUAL_TIMEOUT_ERROR,
        "timeout",
    )


def test_eventual_nonpollable_mismatch_is_failure() -> None:
    result = evaluate_eventual_state_assertion(
        _eventual(),
        _poll(
            ObservationPollOutcome.MISMATCH,
            response=_response((_evidence("resource", "string", "queued"),)),
            valid_evidence_seen=True,
        ),
    )
    assert (result.result, result.code) == (
        AssertionResult.FAIL,
        TemporalAssertionCode.EVENTUAL_MISMATCH,
    )


def test_eventual_unsupported_policy_is_explicit() -> None:
    unsupported = _poll(
        ObservationPollOutcome.UNSUPPORTED,
        response=_response(status=ObserverResponseStatus.UNSUPPORTED),
    )
    error = evaluate_eventual_state_assertion(_eventual(), unsupported)
    skipped = evaluate_eventual_state_assertion(
        _eventual(on_unsupported="skip"),
        unsupported,
    )
    assert (error.result, skipped.result) == (
        AssertionResult.ERROR,
        AssertionResult.SKIPPED,
    )
    assert error.code is skipped.code is TemporalAssertionCode.OBSERVER_UNSUPPORTED


def test_eventual_malformed_evidence_is_predicate_error() -> None:
    result = evaluate_eventual_state_assertion(
        _eventual(path="/status"),
        _poll(
            ObservationPollOutcome.ERROR,
            response=_response((_evidence("resource", "string", "processed"),)),
            valid_evidence_seen=True,
        ),
    )
    assert (result.result, result.code) == (
        AssertionResult.ERROR,
        TemporalAssertionCode.PREDICATE_ERROR,
    )


@pytest.mark.parametrize(
    ("values", "expected_result", "expected_code"),
    [
        ((True, True), AssertionResult.PASS, CompositeAssertionCode.ALL_PRESENT),
        ((False, False), AssertionResult.PASS, CompositeAssertionCode.NONE_PRESENT),
        (
            (True, False),
            AssertionResult.FAIL,
            CompositeAssertionCode.PARTIAL_SIDE_EFFECT,
        ),
    ],
)
def test_all_or_none_side_effects_share_one_snapshot(
    values: tuple[bool, bool],
    expected_result: AssertionResult,
    expected_code: CompositeAssertionCode,
) -> None:
    result = evaluate_no_partial_side_effect_assertion(
        _composite(),
        _response(
            (
                _evidence("order_updated", "boolean", values[0]),
                _evidence("outbox_entry", "boolean", values[1]),
            ),
        ),
    )
    assert (result.result, result.code) == (expected_result, expected_code)
    assert result.predicate_values == (
        ("order_updated", values[0]),
        ("outbox_entry", values[1]),
    )
    assert result.snapshot_id == "snapshot-atomic-1"


def test_partial_order_update_reports_both_named_predicate_values() -> None:
    result = evaluate_no_partial_side_effect_assertion(
        _composite(),
        _response(
            (
                _evidence("order_updated", "boolean", True),  # noqa: FBT003
                _evidence("outbox_entry", "boolean", False),  # noqa: FBT003
            ),
        ),
    )
    assert result.result is AssertionResult.FAIL
    assert result.predicate_values == (
        ("order_updated", True),
        ("outbox_entry", False),
    )


def test_composite_missing_evidence_is_error_with_all_predicate_names() -> None:
    result = evaluate_no_partial_side_effect_assertion(
        _composite(),
        _response((_evidence("order_updated", "boolean", True),)),  # noqa: FBT003
    )
    assert (result.result, result.code) == (
        AssertionResult.ERROR,
        CompositeAssertionCode.PREDICATE_ERROR,
    )
    assert result.predicate_values == (("order_updated", True), ("outbox_entry", None))
    assert result.predicates[1].code is EvidencePredicateCode.EVIDENCE_MISSING


def test_composite_rejects_predicates_that_cannot_share_one_snapshot() -> None:
    result = evaluate_no_partial_side_effect_assertion(
        _composite(outbox_observer="another_observer"),
        _response(
            (
                _evidence("order_updated", "boolean", True),  # noqa: FBT003
                _evidence("outbox_entry", "boolean", True),  # noqa: FBT003
            ),
        ),
    )
    assert (result.result, result.code) == (
        AssertionResult.ERROR,
        CompositeAssertionCode.SNAPSHOT_SCOPE_MISMATCH,
    )


def test_composite_unsupported_policy_and_non_ok_evidence_are_explicit() -> None:
    response = _response(status=ObserverResponseStatus.UNSUPPORTED)
    error = evaluate_no_partial_side_effect_assertion(_composite(), response)
    skipped = evaluate_no_partial_side_effect_assertion(
        _composite(on_unsupported="skip"),
        response,
    )
    assert (error.result, skipped.result) == (
        AssertionResult.ERROR,
        AssertionResult.SKIPPED,
    )
    assert error.code is skipped.code is CompositeAssertionCode.OBSERVER_UNSUPPORTED


def test_sensitive_temporal_and_composite_values_stay_out_of_repr() -> None:
    temporal = evaluate_ordered_transition_assertion(
        _ordered(),
        (
            _evidence(
                "transitions",
                "array",
                ["received", SECRET_CANARY],
                sensitive=True,
            ),
        ),
    )
    composite = evaluate_no_partial_side_effect_assertion(
        _composite(),
        _response(
            (
                _evidence(
                    "order_updated",
                    "boolean",
                    True,  # noqa: FBT003
                    sensitive=True,
                ),
                _evidence(
                    "outbox_entry",
                    "boolean",
                    False,  # noqa: FBT003
                    sensitive=True,
                ),
            ),
        ),
    )
    assert SECRET_CANARY not in repr(temporal)
    assert SECRET_CANARY not in repr(composite)
    assert all(SECRET_CANARY not in repr(item) for item in composite.predicates)
