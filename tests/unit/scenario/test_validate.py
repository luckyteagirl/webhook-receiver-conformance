"""Nominal, malformed, boundary, and security tests for scenario validation."""
# ruff: noqa: INP001, PLR2004

from __future__ import annotations

import builtins

import pytest

from webhook_receiver_conformance.config.models import FaultClass
from webhook_receiver_conformance.scenario.models import (
    DeliveryUserHeaders,
    ScenarioValidationContext,
)
from webhook_receiver_conformance.scenario.validate import (
    MAX_SCENARIO_DIAGNOSTICS,
    validate_project,
    validate_project_semantics,
    validate_scenarios,
)

from ._support import ConfigObject, diagnostic_codes, make_project, make_scenario


def test_raw_byte_fixture_with_generic_signer_is_provider_independent_and_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = make_project([make_scenario()])
    original_import = builtins.__import__

    def guarded_import(
        name: str,
        globals_: ConfigObject | None = None,
        locals_: ConfigObject | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name.startswith(
            ("stripe", "standard_webhooks", "webhook_receiver_conformance.signatures")
        ):
            message = "provider package import is forbidden during semantic validation"
            raise AssertionError(message)
        return original_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    result = validate_project_semantics(project)

    assert result.ok
    assert result.total_events == 1
    assert result.total_planned_deliveries == 1
    assert result.total_planned_attempts == 1
    assert result.scenarios[0].fault_classes == ()


def test_validation_aliases_return_the_same_deterministic_result() -> None:
    project = make_project([make_scenario()])

    expected = validate_project_semantics(project)

    assert validate_project(project) == expected
    assert validate_scenarios(project) == expected


def test_exact_user_signature_header_conflict_is_case_insensitive() -> None:
    project = make_project([make_scenario()])
    context = ScenarioValidationContext(
        user_headers=(
            DeliveryUserHeaders(
                scenario_index=0,
                step_index=0,
                names=("x-TEST-signature",),
            ),
        )
    )

    result = validate_project_semantics(project, context=context)

    assert diagnostic_codes(result) == ["SIG_SIGNER_HEADER_CONFLICT"]
    diagnostic = result.diagnostics[0]
    assert diagnostic.field_path == "$.scenarios[0].steps[0].deliver.signer"
    assert diagnostic.safe_details == {"conflict_source": "planned-user-header"}


def test_nonconflicting_user_header_is_allowed() -> None:
    project = make_project([make_scenario()])
    context = ScenarioValidationContext(
        user_headers=(
            DeliveryUserHeaders(
                scenario_index=0,
                step_index=0,
                names=("X-Correlation",),
            ),
        )
    )

    assert validate_project_semantics(project, context=context).ok


def test_standard_webhooks_owned_signature_header_conflicts_explicitly() -> None:
    project = make_project(
        [make_scenario(signer="standard")],
        signers={
            "standard": {
                "profile": "standard-webhooks-hmac",
                "secret": {"generated": "hmac-256"},
            }
        },
    )
    context = ScenarioValidationContext(
        user_headers=(
            DeliveryUserHeaders(
                scenario_index=0,
                step_index=0,
                names=("Webhook-Signature",),
            ),
        )
    )

    assert "SIG_SIGNER_HEADER_CONFLICT" in diagnostic_codes(
        validate_project_semantics(project, context=context)
    )


def test_standard_webhooks_custom_header_cannot_collide_with_metadata_header() -> None:
    project = make_project(
        [make_scenario(signer="standard")],
        signers={
            "standard": {
                "profile": "standard-webhooks-hmac",
                "secret": {"generated": "hmac-256"},
                "header_name": "Webhook-Id",
            }
        },
    )

    assert diagnostic_codes(validate_project_semantics(project)) == [
        "SIG_SIGNER_HEADER_INTERNAL_CONFLICT"
    ]


def test_user_framing_header_is_rejected_at_context_boundary() -> None:
    project = make_project([make_scenario()])
    context = ScenarioValidationContext(
        user_headers=(
            DeliveryUserHeaders(
                scenario_index=0,
                step_index=0,
                names=("Transfer-Encoding",),
            ),
        )
    )

    assert "SCENARIO_USER_HEADER_RESERVED" in diagnostic_codes(
        validate_project_semantics(project, context=context)
    )


@pytest.mark.parametrize(
    ("scenario_index", "step_index", "code"),
    [
        (1, 0, "SCENARIO_HEADER_CONTEXT_SCENARIO_NOT_FOUND"),
        (0, 1, "SCENARIO_HEADER_CONTEXT_DELIVERY_NOT_FOUND"),
    ],
)
def test_header_context_must_resolve_to_delivery_step(
    scenario_index: int,
    step_index: int,
    code: str,
) -> None:
    project = make_project([make_scenario()])
    context = ScenarioValidationContext(
        user_headers=(
            DeliveryUserHeaders(
                scenario_index=scenario_index,
                step_index=step_index,
                names=("X-Safe",),
            ),
        )
    )

    assert code in diagnostic_codes(validate_project_semantics(project, context=context))


def test_event_references_duplicates_and_cycles_accumulate_in_stable_order() -> None:
    scenario = make_scenario(
        events=[
            {
                "id": "first",
                "fixture": "missing",
                "depends_on": ["second", "absent"],
            },
            {"id": "second", "fixture": "payload", "depends_on": ["first"]},
            {"id": "second", "fixture": "payload"},
        ],
        steps=[
            {"deliver": {"event": "unknown", "signer": "missing"}},
            {"deliver": {"event": "first", "signer": "generic"}},
            {"deliver": {"event": "second", "signer": "generic"}},
        ],
        assertions=[
            {
                "id": "status",
                "type": "http-status",
                "attempt": {"event": "absent", "mode": "last-terminal"},
                "expected": {"codes": [200]},
            },
            {
                "id": "status",
                "type": "processing-count",
                "query": {"observer": "missing", "key": "count"},
                "comparator": "eq",
                "expected": 1,
            },
        ],
    )
    project = make_project([scenario])

    result = validate_project_semantics(project)

    assert diagnostic_codes(result) == [
        "SCENARIO_DUPLICATE_EVENT_ID",
        "SCENARIO_DUPLICATE_ASSERTION_ID",
        "SCENARIO_EVENT_FIXTURE_NOT_FOUND",
        "SCENARIO_EVENT_DEPENDENCY_NOT_FOUND",
        "SCENARIO_EVENT_DEPENDENCY_CYCLE",
        "SCENARIO_EVENT_DEPENDENCY_CYCLE",
        "SCENARIO_DELIVERY_EVENT_NOT_FOUND",
        "SCENARIO_DELIVERY_SIGNER_NOT_FOUND",
        "SCENARIO_ASSERTION_EVENT_NOT_FOUND",
        "SCENARIO_ASSERTION_OBSERVER_NOT_FOUND",
    ]
    assert validate_project_semantics(project).diagnostics == result.diagnostics


def test_duplicate_project_fixture_and_scenario_ids_are_rejected() -> None:
    project = make_project(
        [make_scenario("same"), make_scenario("same")],
        fixtures=[
            {"id": "payload", "path": "a.bin", "media_type": "application/octet-stream"},
            {"id": "payload", "path": "b.bin", "media_type": "application/octet-stream"},
        ],
    )

    codes = diagnostic_codes(validate_project_semantics(project))

    assert codes[:2] == ["SCENARIO_DUPLICATE_FIXTURE_ID", "SCENARIO_DUPLICATE_ID"]


def test_global_event_and_attempt_budgets_use_realized_counts() -> None:
    retry: ConfigObject = {
        "max_attempts": 3,
        "backoff": ["1s", "1s"],
        "retry_on": ["timed_out"],
    }
    scenario = make_scenario(count=2, retry=retry)
    project = make_project(
        [scenario],
        max_events=1,
        max_attempts=5,
    )

    result = validate_project_semantics(project)

    assert result.total_events == 1
    assert result.total_planned_deliveries == 2
    assert result.total_planned_attempts == 6
    assert "SCENARIO_ATTEMPT_LIMIT_EXCEEDED" in diagnostic_codes(result)


def test_project_event_budget_counts_across_scenarios() -> None:
    project = make_project(
        [make_scenario("first"), make_scenario("second")],
        max_events=1,
    )

    result = validate_project_semantics(project)

    assert result.total_events == 2
    assert "SCENARIO_EVENT_LIMIT_EXCEEDED" in diagnostic_codes(result)


def test_valid_concurrency_group_has_one_fault_and_matching_late_barrier() -> None:
    scenario = make_scenario(count=2, concurrency_group="release")

    result = validate_project_semantics(make_project([scenario]))

    assert result.ok
    assert result.scenarios[0].fault_classes == (FaultClass.DELIVERY_CONCURRENT,)


def test_separate_deliver_steps_for_one_event_are_a_duplicate_fault() -> None:
    scenario = make_scenario(
        steps=[
            {"deliver": {"event": "event", "signer": "generic"}},
            {"wait": "1s"},
            {"deliver": {"event": "event", "signer": "generic"}},
        ]
    )

    result = validate_project_semantics(make_project([scenario]))

    assert result.ok
    assert result.scenarios[0].fault_classes == (FaultClass.DELIVERY_DUPLICATE,)


@pytest.mark.parametrize(
    ("steps", "expected_code"),
    [
        (
            [{"deliver": {"event": "event", "concurrency_group": "release"}}],
            "SCENARIO_CONCURRENCY_GROUP_TOO_SMALL",
        ),
        (
            [
                {"deliver": {"event": "event", "count": 2, "concurrency_group": "release"}},
            ],
            "SCENARIO_CONCURRENCY_BARRIER_MISSING",
        ),
        (
            [{"barrier": "missing"}, {"deliver": {"event": "event"}}],
            "SCENARIO_BARRIER_GROUP_NOT_FOUND",
        ),
        (
            [
                {"barrier": "release"},
                {"deliver": {"event": "event", "count": 2, "concurrency_group": "release"}},
            ],
            "SCENARIO_CONCURRENCY_BARRIER_EARLY",
        ),
        (
            [
                {"deliver": {"event": "event", "count": 2, "concurrency_group": "release"}},
                {"barrier": "release"},
                {"barrier": "release"},
            ],
            "SCENARIO_CONCURRENCY_BARRIER_DUPLICATE",
        ),
    ],
)
def test_barrier_and_concurrency_errors_are_specific(
    steps: list[ConfigObject],
    expected_code: str,
) -> None:
    project = make_project([make_scenario(steps=steps)])

    assert expected_code in diagnostic_codes(validate_project_semantics(project))


def test_dependency_order_reversal_is_inferred_without_provider_metadata() -> None:
    scenario = make_scenario(
        events=[
            {"id": "parent", "fixture": "payload"},
            {"id": "child", "fixture": "payload", "depends_on": ["parent"]},
        ],
        steps=[
            {"deliver": {"event": "child", "signer": "generic"}},
            {"deliver": {"event": "parent", "signer": "generic"}},
        ],
        assertions=[
            {
                "id": "status",
                "type": "http-status",
                "attempt": {"event": "child", "mode": "all-terminal"},
                "expected": {"classes": ["2xx"]},
            }
        ],
    )

    result = validate_project_semantics(make_project([scenario]))

    assert result.ok
    assert result.scenarios[0].fault_classes == (FaultClass.DELIVERY_DEPENDENCY_ORDER_REVERSAL,)


def test_restart_and_lifecycle_references_are_validated_before_execution() -> None:
    scenario = make_scenario(
        steps=[
            {"deliver": {"event": "event", "signer": "generic"}},
            {"restart": "receiver"},
            {"restart": "missing"},
        ]
    )
    project = make_project(
        [scenario],
        observers={},
        lifecycles={
            "receiver": {
                "enabled": False,
                "stop_argv": ["receiver", "stop"],
                "start_argv": ["receiver", "start"],
                "restart_argv": ["receiver", "restart"],
                "working_directory": ".",
                "environment_allowlist": [],
                "timeout": "1s",
                "readiness_observer": "missing",
            }
        },
    )

    codes = diagnostic_codes(validate_project_semantics(project))

    assert "SCENARIO_LIFECYCLE_OBSERVER_NOT_FOUND" in codes
    assert "SCENARIO_RESTART_LIFECYCLE_DISABLED" in codes
    assert "SCENARIO_RESTART_LIFECYCLE_NOT_FOUND" in codes


def test_observe_step_and_assertion_observer_references_are_checked() -> None:
    scenario = make_scenario(
        steps=[
            {"deliver": {"event": "event"}},
            {"observe": {"observer": "missing", "checkpoint": ""}},
        ],
        assertions=[
            {
                "id": "count",
                "type": "processing-count",
                "query": {"observer": "missing", "key": "count"},
                "comparator": "eq",
                "expected": 1,
            }
        ],
    )

    codes = diagnostic_codes(validate_project_semantics(make_project([scenario])))

    assert codes == [
        "SCENARIO_OBSERVE_OBSERVER_NOT_FOUND",
        "SCENARIO_OBSERVE_CHECKPOINT_INVALID",
        "SCENARIO_ASSERTION_OBSERVER_NOT_FOUND",
    ]


def test_event_without_delivery_and_attempt_assertion_are_both_reported() -> None:
    scenario = make_scenario(
        steps=[{"wait": "1s"}],
    )

    codes = diagnostic_codes(validate_project_semantics(make_project([scenario])))

    assert codes == [
        "SCENARIO_EVENT_NOT_DELIVERED",
        "SCENARIO_ASSERTION_EVENT_NOT_DELIVERED",
    ]


def test_cumulative_waits_cannot_overflow_logical_time() -> None:
    scenario = make_scenario(
        steps=[
            {"deliver": {"event": "event"}},
            {"wait": "9223372036854775807ns"},
            {"wait": "1ns"},
        ]
    )

    assert "SCENARIO_LOGICAL_TIME_OVERFLOW" in diagnostic_codes(
        validate_project_semantics(make_project([scenario]))
    )


def test_deep_bounded_dependency_graph_uses_no_recursion() -> None:
    count = 1000
    events: list[ConfigObject] = []
    steps: list[ConfigObject] = []
    for index in range(count):
        event: ConfigObject = {
            "id": f"event_{index}",
            "fixture": "payload",
        }
        if index:
            event["depends_on"] = [f"event_{index - 1}"]
        events.append(event)
        steps.append({"deliver": {"event": f"event_{index}"}})
    scenario = make_scenario(
        events=events,
        steps=steps,
        assertions=[
            {
                "id": "status",
                "type": "http-status",
                "attempt": {"event": "event_999", "mode": "last-terminal"},
                "expected": {"classes": ["2xx"]},
            }
        ],
    )

    result = validate_project_semantics(make_project([scenario]))

    assert result.ok
    assert result.total_events == count


def test_diagnostic_accumulation_is_bounded_and_marks_omission() -> None:
    scenarios = [
        make_scenario(f"scenario_{index}", events=[{"id": "event", "fixture": "missing"}])
        for index in range(MAX_SCENARIO_DIAGNOSTICS + 5)
    ]

    result = validate_project_semantics(make_project(scenarios))

    assert len(result.diagnostics) == MAX_SCENARIO_DIAGNOSTICS
    assert result.diagnostics[-1].code == "SCENARIO_DIAGNOSTIC_LIMIT"


def test_validation_performs_no_file_network_or_process_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = make_project([make_scenario()])

    def forbidden_open(*_args: object, **_kwargs: object) -> object:
        message = "semantic validation attempted I/O"
        raise AssertionError(message)

    monkeypatch.setattr(builtins, "open", forbidden_open)

    assert validate_project_semantics(project).ok
