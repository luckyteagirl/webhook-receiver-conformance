"""Contracts for immutable scenario semantic boundary models."""
# ruff: noqa: INP001, PLR0913

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from webhook_receiver_conformance.config.models import (
    MAX_PROJECT_SCENARIOS,
    MAX_SCENARIO_EVENTS,
    FaultClass,
)
from webhook_receiver_conformance.errors import Diagnostic, ErrorCategory, ResultCategory
from webhook_receiver_conformance.scenario.models import (
    MAX_FAULT_FIELD_PATH_LENGTH,
    MAX_FAULT_OCCURRENCES,
    MAX_FAULT_OPERATOR_ID_LENGTH,
    MAX_PLANNED_ATTEMPTS_PER_SCENARIO,
    MAX_PLANNED_DELIVERIES_PER_SCENARIO,
    MAX_PROJECTION_ID_LENGTH,
    MAX_RESULT_EVENTS,
    MAX_RESULT_PLANNED_ATTEMPTS,
    MAX_RESULT_PLANNED_DELIVERIES,
    MAX_USER_HEADER_BINDINGS,
    MAX_VALIDATION_DIAGNOSTICS,
    DeliveryUserHeaders,
    FaultOccurrence,
    ScenarioSemantics,
    ScenarioValidationContext,
    ScenarioValidationResult,
)
from webhook_receiver_conformance.types import DiagnosticCode


def _semantics(
    *,
    scenario_id: str = "sample",
    scenario_index: int = 0,
    event_ids: tuple[str, ...] = ("event",),
    fault_occurrences: tuple[FaultOccurrence, ...] = (),
    planned_deliveries: int = 1,
    planned_attempts: int = 1,
) -> ScenarioSemantics:
    return ScenarioSemantics(
        scenario_id=scenario_id,
        scenario_index=scenario_index,
        event_ids=event_ids,
        fault_occurrences=fault_occurrences,
        planned_deliveries=planned_deliveries,
        planned_attempts=planned_attempts,
    )


def _diagnostic() -> Diagnostic:
    return Diagnostic(
        category=ErrorCategory.PLANNING_ERROR,
        code=DiagnosticCode("SCENARIO_TEST_ERROR"),
        message="Scenario validation failed.",
        retryable=False,
        safe_details={},
        result_category=ResultCategory.INVALID_INPUT,
        user_correctable=True,
        field_path="$.scenarios[0]",
        corrective_action="Fix the scenario.",
    )


def _result(
    *,
    scenarios: tuple[ScenarioSemantics, ...] | None = None,
    diagnostics: tuple[Diagnostic, ...] = (),
    total_events: int | None = None,
    total_planned_deliveries: int | None = None,
    total_planned_attempts: int | None = None,
) -> ScenarioValidationResult:
    projections = (_semantics(),) if scenarios is None else scenarios
    return ScenarioValidationResult(
        scenarios=projections,
        diagnostics=diagnostics,
        total_events=(
            sum(len(projection.event_ids) for projection in projections)
            if total_events is None
            else total_events
        ),
        total_planned_deliveries=(
            sum(projection.planned_deliveries for projection in projections)
            if total_planned_deliveries is None
            else total_planned_deliveries
        ),
        total_planned_attempts=(
            sum(projection.planned_attempts for projection in projections)
            if total_planned_attempts is None
            else total_planned_attempts
        ),
    )


def test_user_header_binding_normalizes_case_and_is_immutable() -> None:
    binding = DeliveryUserHeaders(
        scenario_index=0,
        step_index=2,
        names=("X-Test-Signature", "Content-Type"),
    )

    assert binding.names == ("x-test-signature", "content-type")
    with pytest.raises(FrozenInstanceError):
        binding.step_index = 3  # pyright: ignore[reportAttributeAccessIssue]


@pytest.mark.parametrize(
    "name",
    [
        "",
        "space header",
        "line\nbreak",
        "x" * 129,
        "X-Unicode-\N{SNOWMAN}",
    ],
)
def test_user_header_binding_rejects_malformed_names(name: str) -> None:
    with pytest.raises(ValueError, match="HTTP tokens"):
        DeliveryUserHeaders(scenario_index=0, step_index=0, names=(name,))


def test_user_header_binding_rejects_duplicate_names_case_insensitively() -> None:
    with pytest.raises(ValueError, match="unique case-insensitively"):
        DeliveryUserHeaders(
            scenario_index=0,
            step_index=0,
            names=("X-Signature", "x-signature"),
        )


@pytest.mark.parametrize(("scenario_index", "step_index"), [(-1, 0), (0, -1)])
def test_user_header_binding_rejects_negative_indexes(
    scenario_index: int,
    step_index: int,
) -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        DeliveryUserHeaders(
            scenario_index=scenario_index,
            step_index=step_index,
            names=(),
        )


@pytest.mark.parametrize("index", [True, False, 0.0, 1.0])
def test_user_header_binding_rejects_bool_and_float_indexes(index: object) -> None:
    with pytest.raises(TypeError, match="indexes must be integers"):
        DeliveryUserHeaders(
            scenario_index=index,  # pyright: ignore[reportArgumentType]
            step_index=0,
            names=(),
        )
    with pytest.raises(TypeError, match="indexes must be integers"):
        DeliveryUserHeaders(
            scenario_index=0,
            step_index=index,  # pyright: ignore[reportArgumentType]
            names=(),
        )


def test_validation_context_rejects_duplicate_delivery_bindings() -> None:
    binding = DeliveryUserHeaders(scenario_index=0, step_index=0, names=())
    with pytest.raises(ValueError, match="unique delivery steps"):
        ScenarioValidationContext(user_headers=(binding, binding))


def test_validation_context_rejects_nonbinding_entries() -> None:
    with pytest.raises(TypeError, match="delivery user-header bindings"):
        ScenarioValidationContext(
            user_headers=(object(),),  # pyright: ignore[reportArgumentType]
        )


def test_validation_context_enforces_global_binding_limit() -> None:
    binding = DeliveryUserHeaders(scenario_index=0, step_index=0, names=())
    with pytest.raises(ValueError, match="header-binding limit"):
        ScenarioValidationContext(user_headers=(binding,) * (MAX_USER_HEADER_BINDINGS + 1))


def test_scenario_semantics_exposes_unique_fault_classes_in_order() -> None:
    semantics = ScenarioSemantics(
        scenario_id="sample",
        scenario_index=0,
        event_ids=("event",),
        fault_occurrences=(
            FaultOccurrence(
                fault_class=FaultClass.DELIVERY_DUPLICATE,
                field_path="$.scenarios[0].steps[0].deliver.count",
            ),
            FaultOccurrence(
                fault_class=FaultClass.RETRY_TIMED_OUT,
                field_path="$.scenarios[0].steps[0].deliver.retry.retry_on[0]",
            ),
        ),
        planned_deliveries=2,
        planned_attempts=4,
    )

    assert semantics.fault_classes == (
        FaultClass.DELIVERY_DUPLICATE,
        FaultClass.RETRY_TIMED_OUT,
    )


def test_scenario_semantics_rejects_duplicate_fault_occurrences() -> None:
    occurrence = FaultOccurrence(
        fault_class=FaultClass.DELIVERY_DUPLICATE,
        field_path="$.scenarios[0]",
    )
    with pytest.raises(ValueError, match="unique fault classes"):
        ScenarioSemantics(
            scenario_id="sample",
            scenario_index=0,
            event_ids=("event",),
            fault_occurrences=(occurrence, occurrence),
            planned_deliveries=1,
            planned_attempts=1,
        )


def test_validation_result_ok_and_lookup_are_total() -> None:
    semantics = ScenarioSemantics(
        scenario_id="sample",
        scenario_index=0,
        event_ids=("event",),
        fault_occurrences=(),
        planned_deliveries=1,
        planned_attempts=1,
    )
    result = ScenarioValidationResult(
        scenarios=(semantics,),
        diagnostics=(),
        total_events=1,
        total_planned_deliveries=1,
        total_planned_attempts=1,
    )

    assert result.ok
    assert result.scenario("sample") is semantics
    assert result.scenario("missing") is None


def test_fault_occurrence_accepts_exact_string_boundaries_and_is_immutable() -> None:
    occurrence = FaultOccurrence(
        fault_class=FaultClass.MUTATION_REMOVE_JSON_POINTER,
        field_path="$" + ("x" * (MAX_FAULT_FIELD_PATH_LENGTH - 1)),
        operator_id="a" + ("b" * (MAX_FAULT_OPERATOR_ID_LENGTH - 1)),
    )

    assert len(occurrence.field_path) == MAX_FAULT_FIELD_PATH_LENGTH
    assert len(occurrence.operator_id or "") == MAX_FAULT_OPERATOR_ID_LENGTH
    with pytest.raises(FrozenInstanceError):
        occurrence.field_path = "$.changed"  # pyright: ignore[reportAttributeAccessIssue]


def test_fault_occurrence_rejects_wire_string_fault_class() -> None:
    with pytest.raises(TypeError, match="fault_class must be a FaultClass member"):
        FaultOccurrence(
            fault_class="delivery:duplicate",  # pyright: ignore[reportArgumentType]
            field_path="$.scenarios[0]",
        )


@pytest.mark.parametrize(
    ("field_path", "operator_id", "message"),
    [
        (object(), None, "field_path must be a string"),
        ("$.scenarios[0]", object(), "operator_id must be a string"),
    ],
)
def test_fault_occurrence_rejects_nonstring_fields(
    field_path: object,
    operator_id: object | None,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        FaultOccurrence(
            fault_class=FaultClass.DELIVERY_DUPLICATE,
            field_path=field_path,  # pyright: ignore[reportArgumentType]
            operator_id=operator_id,  # pyright: ignore[reportArgumentType]
        )


@pytest.mark.parametrize(
    ("field_path", "operator_id", "message"),
    [
        ("x" * (MAX_FAULT_FIELD_PATH_LENGTH + 1), None, "field_path"),
        ("$.scenarios[0]", "x" * (MAX_FAULT_OPERATOR_ID_LENGTH + 1), "operator_id"),
        ("$.scenarios[0]\nsecret", None, "field_path"),
        ("$.scenarios[0]", "UPPERCASE", "operator_id"),
    ],
)
def test_fault_occurrence_rejects_unbounded_or_unsafe_strings(
    field_path: str,
    operator_id: str | None,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        FaultOccurrence(
            fault_class=FaultClass.DELIVERY_DUPLICATE,
            field_path=field_path,
            operator_id=operator_id,
        )


def test_scenario_semantics_accepts_exact_identifier_boundaries() -> None:
    identifier = "a" + ("b" * (MAX_PROJECTION_ID_LENGTH - 1))

    semantics = _semantics(scenario_id=identifier, event_ids=(identifier,))

    assert semantics.scenario_id == identifier
    assert semantics.event_ids == (identifier,)


@pytest.mark.parametrize(
    ("scenario_id", "event_ids", "message"),
    [
        ("a" * (MAX_PROJECTION_ID_LENGTH + 1), ("event",), "scenario_id"),
        ("sample", ("a" * (MAX_PROJECTION_ID_LENGTH + 1),), "event_id"),
        ("UPPERCASE", ("event",), "scenario_id"),
        ("sample", ("event\nsecret",), "event_id"),
    ],
)
def test_scenario_semantics_rejects_unbounded_or_unsafe_identifiers(
    scenario_id: str,
    event_ids: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _semantics(scenario_id=scenario_id, event_ids=event_ids)


def test_scenario_semantics_rejects_mutable_collection_inputs() -> None:
    event_ids = ["event"]
    occurrences: list[FaultOccurrence] = []

    with pytest.raises(TypeError, match="event_ids must be a tuple"):
        ScenarioSemantics(
            scenario_id="sample",
            scenario_index=0,
            event_ids=event_ids,  # pyright: ignore[reportArgumentType]
            fault_occurrences=(),
            planned_deliveries=1,
            planned_attempts=1,
        )
    with pytest.raises(TypeError, match="fault_occurrences must be a tuple"):
        ScenarioSemantics(
            scenario_id="sample",
            scenario_index=0,
            event_ids=("event",),
            fault_occurrences=occurrences,  # pyright: ignore[reportArgumentType]
            planned_deliveries=1,
            planned_attempts=1,
        )

    event_ids.append("changed")
    occurrences.append(
        FaultOccurrence(
            fault_class=FaultClass.DELIVERY_DUPLICATE,
            field_path="$.scenarios[0]",
        )
    )


@pytest.mark.parametrize(
    ("event_ids", "fault_occurrences", "message"),
    [
        ((object(),), (), "event_id must be a string"),
        (("event",), (object(),), "FaultOccurrence values"),
    ],
)
def test_scenario_semantics_rejects_invalid_tuple_members(
    event_ids: tuple[object, ...],
    fault_occurrences: tuple[object, ...],
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        ScenarioSemantics(
            scenario_id="sample",
            scenario_index=0,
            event_ids=event_ids,  # pyright: ignore[reportArgumentType]
            fault_occurrences=fault_occurrences,  # pyright: ignore[reportArgumentType]
            planned_deliveries=1,
            planned_attempts=1,
        )


@pytest.mark.parametrize("value", [True, False, 0.0, 1.0])
def test_scenario_semantics_rejects_bool_and_float_counts(value: object) -> None:
    with pytest.raises(TypeError, match="scenario_index must be an integer"):
        _semantics(scenario_index=value)  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match="planned_deliveries must be an integer"):
        _semantics(planned_deliveries=value)  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match="planned_attempts must be an integer"):
        _semantics(planned_attempts=value)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"scenario_index": -1}, "scenario_index"),
        ({"scenario_index": MAX_PROJECT_SCENARIOS}, "scenario_index"),
        ({"planned_deliveries": -1}, "planned_deliveries"),
        (
            {"planned_deliveries": MAX_PLANNED_DELIVERIES_PER_SCENARIO + 1},
            "planned_deliveries",
        ),
        ({"planned_attempts": -1}, "planned_attempts"),
        (
            {"planned_attempts": MAX_PLANNED_ATTEMPTS_PER_SCENARIO + 1},
            "planned_attempts",
        ),
    ],
)
def test_scenario_semantics_rejects_out_of_range_integers(
    overrides: dict[str, int],
    message: str,
) -> None:
    values: dict[str, object] = {
        "scenario_id": "sample",
        "scenario_index": 0,
        "event_ids": ("event",),
        "fault_occurrences": (),
        "planned_deliveries": 1,
        "planned_attempts": 1,
    }
    values.update(overrides)

    with pytest.raises(ValueError, match=message):
        ScenarioSemantics(**values)  # pyright: ignore[reportArgumentType]


def test_scenario_semantics_rejects_attempt_count_below_delivery_count() -> None:
    with pytest.raises(ValueError, match="cannot be less"):
        _semantics(planned_deliveries=2, planned_attempts=1)


def test_scenario_semantics_enforces_collection_bounds() -> None:
    occurrence = FaultOccurrence(
        fault_class=FaultClass.DELIVERY_DUPLICATE,
        field_path="$.scenarios[0]",
    )

    with pytest.raises(ValueError, match="event_ids"):
        _semantics(event_ids=())
    with pytest.raises(ValueError, match="event_ids"):
        _semantics(event_ids=("event",) * (MAX_SCENARIO_EVENTS + 1))
    with pytest.raises(ValueError, match="fault_occurrences"):
        _semantics(fault_occurrences=(occurrence,) * (MAX_FAULT_OCCURRENCES + 1))


def test_validation_result_rejects_mutable_collection_inputs_without_aliasing() -> None:
    semantics = _semantics()
    scenarios = [semantics]
    diagnostics: list[Diagnostic] = []

    with pytest.raises(TypeError, match="scenarios must be a tuple"):
        ScenarioValidationResult(
            scenarios=scenarios,  # pyright: ignore[reportArgumentType]
            diagnostics=(),
            total_events=1,
            total_planned_deliveries=1,
            total_planned_attempts=1,
        )
    with pytest.raises(TypeError, match="diagnostics must be a tuple"):
        ScenarioValidationResult(
            scenarios=(semantics,),
            diagnostics=diagnostics,  # pyright: ignore[reportArgumentType]
            total_events=1,
            total_planned_deliveries=1,
            total_planned_attempts=1,
        )

    scenarios.clear()
    diagnostics.append(_diagnostic())


@pytest.mark.parametrize(
    ("scenarios", "diagnostics", "message"),
    [
        ((object(),), (), "ScenarioSemantics values"),
        ((_semantics(),), (object(),), "Diagnostic values"),
    ],
)
def test_validation_result_rejects_invalid_tuple_members(
    scenarios: tuple[object, ...],
    diagnostics: tuple[object, ...],
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        ScenarioValidationResult(
            scenarios=scenarios,  # pyright: ignore[reportArgumentType]
            diagnostics=diagnostics,  # pyright: ignore[reportArgumentType]
            total_events=1,
            total_planned_deliveries=1,
            total_planned_attempts=1,
        )


@pytest.mark.parametrize("value", [True, False, 0.0, 1.0])
def test_validation_result_rejects_bool_and_float_totals(value: object) -> None:
    with pytest.raises(TypeError, match="total_events must be an integer"):
        _result(total_events=value)  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match="total_planned_deliveries must be an integer"):
        _result(total_planned_deliveries=value)  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match="total_planned_attempts must be an integer"):
        _result(total_planned_attempts=value)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("total_events", -1),
        ("total_events", MAX_RESULT_EVENTS + 1),
        ("total_planned_deliveries", -1),
        ("total_planned_deliveries", MAX_RESULT_PLANNED_DELIVERIES + 1),
        ("total_planned_attempts", -1),
        ("total_planned_attempts", MAX_RESULT_PLANNED_ATTEMPTS + 1),
    ],
)
def test_validation_result_rejects_out_of_range_totals(
    field_name: str,
    value: int,
) -> None:
    overrides = {field_name: value}

    with pytest.raises(ValueError, match=field_name):
        _result(**overrides)  # pyright: ignore[reportArgumentType]


def test_validation_result_enforces_collection_bounds() -> None:
    semantics = _semantics()
    diagnostic = _diagnostic()

    with pytest.raises(ValueError, match="scenarios"):
        _result(scenarios=())
    with pytest.raises(ValueError, match="scenarios"):
        _result(scenarios=(semantics,) * (MAX_PROJECT_SCENARIOS + 1))
    with pytest.raises(ValueError, match="diagnostics"):
        _result(diagnostics=(diagnostic,) * (MAX_VALIDATION_DIAGNOSTICS + 1))

    at_limit = _result(diagnostics=(diagnostic,) * MAX_VALIDATION_DIAGNOSTICS)
    assert len(at_limit.diagnostics) == MAX_VALIDATION_DIAGNOSTICS
    assert not at_limit.ok


def test_validation_result_requires_totals_to_match_projection() -> None:
    with pytest.raises(ValueError, match="must match scenario projections"):
        _result(total_events=2)


def test_validation_result_is_immutable_after_construction() -> None:
    result = _result()

    with pytest.raises(FrozenInstanceError):
        result.diagnostics = (_diagnostic(),)  # pyright: ignore[reportAttributeAccessIssue]
