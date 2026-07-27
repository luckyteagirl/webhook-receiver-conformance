"""Pure, bounded semantic validation for the v0.1 scenario grammar."""
# ruff: noqa: C901, INP001, PLR0912, PLR0913, PLR0915, TC003

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

import webhook_receiver_conformance.config.models as config_models
from webhook_receiver_conformance.errors import Diagnostic, ErrorCategory, ResultCategory
from webhook_receiver_conformance.scenario.models import (
    MAX_VALIDATION_DIAGNOSTICS,
    DeliveryUserHeaders,
    FaultOccurrence,
    MutationStage,
    ScenarioSemantics,
    ScenarioValidationContext,
    ScenarioValidationResult,
)
from webhook_receiver_conformance.types import DiagnosticCode, JsonObject

MAX_SCENARIO_DIAGNOSTICS: Final = MAX_VALIDATION_DIAGNOSTICS
MAX_SEMANTIC_REFERENCE_LENGTH: Final = 4096
MIN_CONCURRENCY_GROUP_DELIVERIES: Final = 2
_HARNESS_REQUEST_HEADERS: Final = frozenset(
    {
        "connection",
        "content-type",
        "host",
        "content-length",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
    }
)
_GENERIC_SIGNATURE_HEADER: Final = "x-webhook-signature"
_STRIPE_SIGNATURE_HEADER: Final = "stripe-signature"
_STANDARD_WEBHOOK_ID_HEADER: Final = "webhook-id"
_STANDARD_WEBHOOK_TIMESTAMP_HEADER: Final = "webhook-timestamp"
_STANDARD_WEBHOOK_SIGNATURE_HEADER: Final = "webhook-signature"

_MUTATION_FAULT_CLASS: Final[Mapping[str, config_models.FaultClass]] = {
    "remove-json-pointer-v1": config_models.FaultClass.MUTATION_REMOVE_JSON_POINTER,
    "replace-json-value-v1": config_models.FaultClass.MUTATION_REPLACE_JSON_VALUE,
    "replace-json-type-v1": config_models.FaultClass.MUTATION_REPLACE_JSON_TYPE,
    "add-json-field-v1": config_models.FaultClass.MUTATION_ADD_JSON_FIELD,
    "change-event-id-field-v1": config_models.FaultClass.MUTATION_CHANGE_EVENT_ID_FIELD,
    "change-event-type-field-v1": config_models.FaultClass.MUTATION_CHANGE_EVENT_TYPE_FIELD,
    "truncate-bytes-v1": config_models.FaultClass.MUTATION_TRUNCATE_BYTES,
    "invalid-json-v1": config_models.FaultClass.MUTATION_INVALID_JSON,
    "content-type-mismatch-v1": config_models.FaultClass.MUTATION_CONTENT_TYPE_MISMATCH,
    "alter-after-signing-v1": config_models.FaultClass.MUTATION_ALTER_AFTER_SIGNING,
    "stale-signature-timestamp-v1": (config_models.FaultClass.MUTATION_STALE_SIGNATURE_TIMESTAMP),
    "wrong-signing-key-v1": config_models.FaultClass.MUTATION_WRONG_SIGNING_KEY,
    "missing-signature-v1": config_models.FaultClass.MUTATION_MISSING_SIGNATURE,
    "malformed-signature-v1": config_models.FaultClass.MUTATION_MALFORMED_SIGNATURE,
    "oversized-body-v1": config_models.FaultClass.MUTATION_OVERSIZED_BODY,
}

_MUTATION_STAGE: Final[Mapping[str, MutationStage]] = {
    "remove-json-pointer-v1": MutationStage.STRUCTURAL,
    "replace-json-value-v1": MutationStage.STRUCTURAL,
    "replace-json-type-v1": MutationStage.STRUCTURAL,
    "add-json-field-v1": MutationStage.STRUCTURAL,
    "change-event-id-field-v1": MutationStage.STRUCTURAL,
    "change-event-type-field-v1": MutationStage.STRUCTURAL,
    "truncate-bytes-v1": MutationStage.RAW_PRE_SIGN,
    "invalid-json-v1": MutationStage.RAW_PRE_SIGN,
    "content-type-mismatch-v1": MutationStage.HEADER_PRE_SIGN,
    "alter-after-signing-v1": MutationStage.RAW_POST_SIGN,
    "stale-signature-timestamp-v1": MutationStage.SIGNING,
    "wrong-signing-key-v1": MutationStage.SIGNING,
    "missing-signature-v1": MutationStage.HEADER_POST_SIGN,
    "malformed-signature-v1": MutationStage.HEADER_POST_SIGN,
    "oversized-body-v1": MutationStage.RAW_PRE_SIGN,
}
_MUTATION_STAGE_RANK: Final[Mapping[MutationStage, int]] = {
    MutationStage.STRUCTURAL: 0,
    MutationStage.RAW_PRE_SIGN: 1,
    MutationStage.HEADER_PRE_SIGN: 2,
    MutationStage.SIGNING: 3,
    MutationStage.RAW_POST_SIGN: 4,
    MutationStage.HEADER_POST_SIGN: 5,
}

_RETRY_FAULT_CLASS: Final[Mapping[config_models.RetryOn, config_models.FaultClass]] = {
    config_models.RetryOn.TIMED_OUT: config_models.FaultClass.RETRY_TIMED_OUT,
    config_models.RetryOn.CONNECTION_FAILED: (config_models.FaultClass.RETRY_CONNECTION_FAILED),
    config_models.RetryOn.RETRYABLE_STATUS: (config_models.FaultClass.RETRY_RETRYABLE_STATUS),
}

_STRUCTURAL_MUTATIONS = (
    config_models.RemoveJsonPointerMutation,
    config_models.ReplaceJsonValueMutation,
    config_models.ReplaceJsonTypeMutation,
    config_models.AddJsonFieldMutation,
    config_models.ChangeEventIdFieldMutation,
    config_models.ChangeEventTypeFieldMutation,
)
_SIGNER_REQUIRED_MUTATIONS = (
    config_models.AlterAfterSigningMutation,
    config_models.StaleSignatureTimestampMutation,
    config_models.WrongSigningKeyMutation,
    config_models.MissingSignatureMutation,
    config_models.MalformedSignatureMutation,
)
_OBSERVER_ASSERTIONS = (
    config_models.ProcessingCountAssertion,
    config_models.CallbackCountAssertion,
    config_models.JournalCountAssertion,
    config_models.ResourceExistsAssertion,
    config_models.ResourceAbsentAssertion,
    config_models.ResourceFieldAssertion,
    config_models.EventualStateAssertion,
    config_models.OrderedTransitionAssertion,
)


@dataclass(frozen=True, slots=True)
class _StructuralWrite:
    pointer: str
    operator_id: str
    index: int
    accepts_prior: bool
    destroys_descendants: bool
    add_overwrite: bool = False
    remove_ignores_missing: bool = False


@dataclass(frozen=True, slots=True)
class _GroupMember:
    step_index: int
    count: int
    event_id: str


class _Diagnostics:
    __slots__ = ("_items", "_omitted")

    def __init__(self) -> None:
        self._items: list[Diagnostic] = []
        self._omitted = False

    def add(
        self,
        *,
        code: str,
        message: str,
        field_path: str,
        corrective_action: str,
        category: ErrorCategory = ErrorCategory.PLANNING_ERROR,
        safe_details: JsonObject | None = None,
    ) -> None:
        if len(self._items) >= MAX_SCENARIO_DIAGNOSTICS:
            self._omitted = True
            return
        self._items.append(
            Diagnostic(
                category=category,
                code=DiagnosticCode(code),
                message=message,
                retryable=False,
                safe_details={} if safe_details is None else safe_details,
                result_category=ResultCategory.INVALID_INPUT,
                user_correctable=True,
                field_path=field_path,
                corrective_action=corrective_action,
            )
        )

    def finish(self) -> tuple[Diagnostic, ...]:
        if not self._omitted:
            return tuple(self._items)
        limit = Diagnostic(
            category=ErrorCategory.RESOURCE_LIMIT,
            code=DiagnosticCode("SCENARIO_DIAGNOSTIC_LIMIT"),
            message="Additional scenario errors were omitted.",
            retryable=False,
            safe_details={"maximum": MAX_SCENARIO_DIAGNOSTICS},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="$",
            corrective_action="Fix the reported errors, then validate the project again.",
        )
        if self._items:
            self._items[-1] = limit
        else:  # pragma: no cover - the limit cannot be reached with no prior item
            self._items.append(limit)
        return tuple(self._items)


class _Faults:
    __slots__ = ("_occurrences",)

    def __init__(self) -> None:
        self._occurrences: dict[config_models.FaultClass, FaultOccurrence] = {}

    def add(
        self,
        fault_class: config_models.FaultClass,
        *,
        field_path: str,
        operator_id: str | None = None,
    ) -> None:
        self._occurrences.setdefault(
            fault_class,
            FaultOccurrence(
                fault_class=fault_class,
                field_path=field_path,
                operator_id=operator_id,
            ),
        )

    def finish(self) -> tuple[FaultOccurrence, ...]:
        return tuple(self._occurrences.values())


def validate_project_semantics(
    config: config_models.ProjectConfig,
    *,
    context: ScenarioValidationContext | None = None,
) -> ScenarioValidationResult:
    """Validate all cross-object and ordered scenario rules without side effects."""
    diagnostics = _Diagnostics()
    header_context = _index_user_headers(
        config,
        ScenarioValidationContext() if context is None else context,
        diagnostics=diagnostics,
    )
    fixture_indexes = _first_indexes(
        tuple(fixture.id for fixture in config.fixtures),
        diagnostics=diagnostics,
        duplicate_code="SCENARIO_DUPLICATE_FIXTURE_ID",
        collection_path=("fixtures",),
        item_field="id",
        message="Fixture IDs must be unique.",
        corrective_action="Give every fixture a unique ID.",
    )
    scenario_indexes = _first_indexes(
        tuple(scenario.id for scenario in config.scenarios),
        diagnostics=diagnostics,
        duplicate_code="SCENARIO_DUPLICATE_ID",
        collection_path=("scenarios",),
        item_field="id",
        message="Scenario IDs must be unique.",
        corrective_action="Give every scenario a unique ID.",
    )

    _validate_lifecycle_observers(config, diagnostics=diagnostics)

    semantics: list[ScenarioSemantics] = []
    for scenario_index, scenario in enumerate(config.scenarios):
        semantics.append(
            _validate_scenario(
                config,
                scenario,
                scenario_index=scenario_index,
                fixture_indexes=fixture_indexes,
                header_context=header_context,
                diagnostics=diagnostics,
            )
        )

    _validate_baselines(
        config,
        tuple(semantics),
        scenario_indexes=scenario_indexes,
        diagnostics=diagnostics,
    )

    total_events = sum(len(scenario.events) for scenario in config.scenarios)
    total_deliveries = sum(item.planned_deliveries for item in semantics)
    total_attempts = sum(item.planned_attempts for item in semantics)
    if total_events > config.limits.max_events:
        diagnostics.add(
            code="SCENARIO_EVENT_LIMIT_EXCEEDED",
            message="The project exceeds its configured logical-event limit.",
            field_path=_field_path("limits", "max_events"),
            corrective_action="Reduce declared scenario events or raise max_events within its cap.",
            category=ErrorCategory.RESOURCE_LIMIT,
            safe_details={"limit": config.limits.max_events, "observed": total_events},
        )
    if total_attempts > config.limits.max_attempts:
        diagnostics.add(
            code="SCENARIO_ATTEMPT_LIMIT_EXCEEDED",
            message="The project exceeds its configured physical-attempt limit.",
            field_path=_field_path("limits", "max_attempts"),
            corrective_action="Reduce deliveries or retries, or raise max_attempts within its cap.",
            category=ErrorCategory.RESOURCE_LIMIT,
            safe_details={"limit": config.limits.max_attempts, "observed": total_attempts},
        )

    return ScenarioValidationResult(
        scenarios=tuple(semantics),
        diagnostics=diagnostics.finish(),
        total_events=total_events,
        total_planned_deliveries=total_deliveries,
        total_planned_attempts=total_attempts,
    )


def validate_scenarios(
    config: config_models.ProjectConfig,
    *,
    context: ScenarioValidationContext | None = None,
) -> ScenarioValidationResult:
    """Compatibility-friendly name for project scenario semantic validation."""
    return validate_project_semantics(config, context=context)


def validate_project(
    config: config_models.ProjectConfig,
    *,
    context: ScenarioValidationContext | None = None,
) -> ScenarioValidationResult:
    """Return the same pure semantic result under the application-service verb."""
    return validate_project_semantics(config, context=context)


def _validate_scenario(
    config: config_models.ProjectConfig,
    scenario: config_models.ScenarioConfig,
    *,
    scenario_index: int,
    fixture_indexes: Mapping[str, int],
    header_context: Mapping[tuple[int, int], tuple[str, ...]],
    diagnostics: _Diagnostics,
) -> ScenarioSemantics:
    base = ("scenarios", scenario_index)
    event_indexes = _first_indexes(
        tuple(event.id for event in scenario.events),
        diagnostics=diagnostics,
        duplicate_code="SCENARIO_DUPLICATE_EVENT_ID",
        collection_path=(*base, "events"),
        item_field="id",
        message="Event IDs must be unique within a scenario.",
        corrective_action="Give every event in this scenario a unique ID.",
    )
    _first_indexes(
        tuple(assertion.id for assertion in scenario.assertions),
        diagnostics=diagnostics,
        duplicate_code="SCENARIO_DUPLICATE_ASSERTION_ID",
        collection_path=(*base, "assertions"),
        item_field="id",
        message="Assertion IDs must be unique within a scenario.",
        corrective_action="Give every assertion in this scenario a unique ID.",
    )

    dependency_edges: dict[str, tuple[str, ...]] = {}
    for event_index, event in enumerate(scenario.events):
        event_path = (*base, "events", event_index)
        if event.fixture not in fixture_indexes:
            diagnostics.add(
                code="SCENARIO_EVENT_FIXTURE_NOT_FOUND",
                message="Event fixture reference does not resolve.",
                field_path=_field_path(*event_path, "fixture"),
                corrective_action="Reference one configured fixture ID.",
            )
        dependencies: list[str] = []
        for dependency_index, dependency in enumerate(event.depends_on or ()):
            dependency_path = _field_path(
                *event_path,
                "depends_on",
                dependency_index,
            )
            if dependency == event.id:
                diagnostics.add(
                    code="SCENARIO_EVENT_DEPENDENCY_SELF",
                    message="An event cannot depend on itself.",
                    field_path=dependency_path,
                    corrective_action="Remove the self-dependency.",
                )
                continue
            if dependency not in event_indexes:
                diagnostics.add(
                    code="SCENARIO_EVENT_DEPENDENCY_NOT_FOUND",
                    message="Event dependency reference does not resolve.",
                    field_path=dependency_path,
                    corrective_action="Reference another event ID in this scenario.",
                )
                continue
            dependencies.append(dependency)
        dependency_edges.setdefault(event.id, tuple(dependencies))

    cycle_members = _cycle_members(tuple(event_indexes), dependency_edges)
    for event_id in tuple(event_indexes):
        if event_id in cycle_members:
            diagnostics.add(
                code="SCENARIO_EVENT_DEPENDENCY_CYCLE",
                message="Event dependencies must form an acyclic graph.",
                field_path=_field_path(
                    *base,
                    "events",
                    event_indexes[event_id],
                    "depends_on",
                ),
                corrective_action="Remove one dependency edge from the cycle.",
            )

    faults = _Faults()
    planned_deliveries = 0
    planned_attempts = 0
    delivered_events: set[str] = set()
    first_delivery_step: dict[str, int] = {}
    event_delivery_counts: dict[str, int] = {}
    event_ungrouped_counts: dict[str, int] = {}
    event_groups: dict[str, set[str]] = {}
    group_members: dict[str, list[_GroupMember]] = {}
    barriers: dict[str, list[int]] = {}
    logical_time_ns = 0
    logical_time_overflowed = False

    for step_index, step in enumerate(scenario.steps):
        step_path = (*base, "steps", step_index)
        if isinstance(step, config_models.DeliverStep):
            action = step.deliver
            action_path = (*step_path, "deliver")
            event = (
                scenario.events[event_indexes[action.event]]
                if action.event in event_indexes
                else None
            )
            if event is None:
                diagnostics.add(
                    code="SCENARIO_DELIVERY_EVENT_NOT_FOUND",
                    message="Delivery event reference does not resolve.",
                    field_path=_field_path(*action_path, "event"),
                    corrective_action="Reference one event declared by this scenario.",
                )
            else:
                delivered_events.add(event.id)
                first_delivery_step.setdefault(event.id, step_index)
                event_delivery_counts[event.id] = (
                    event_delivery_counts.get(event.id, 0) + action.count
                )

            signer = None
            if action.signer is not None:
                if action.signer not in config.signers:
                    diagnostics.add(
                        code="SCENARIO_DELIVERY_SIGNER_NOT_FOUND",
                        message="Delivery signer reference does not resolve.",
                        field_path=_field_path(*action_path, "signer"),
                        corrective_action="Reference one configured signer profile.",
                    )
                else:
                    signer = config.signers[action.signer]

            planned_deliveries += action.count
            attempts_per_delivery = 1 if action.retry is None else action.retry.max_attempts
            planned_attempts += action.count * attempts_per_delivery
            if action.retry is not None:
                for retry_index, retry_on in enumerate(action.retry.retry_on):
                    faults.add(
                        _RETRY_FAULT_CLASS[retry_on],
                        field_path=_field_path(
                            *action_path,
                            "retry",
                            "retry_on",
                            retry_index,
                        ),
                    )

            group = action.concurrency_group
            if group is None:
                if event is not None:
                    event_ungrouped_counts[event.id] = (
                        event_ungrouped_counts.get(event.id, 0) + action.count
                    )
            elif not _valid_semantic_text(group):
                diagnostics.add(
                    code="SCENARIO_CONCURRENCY_GROUP_INVALID",
                    message="Concurrency-group name must be nonempty and bounded.",
                    field_path=_field_path(*action_path, "concurrency_group"),
                    corrective_action="Use a nonempty name no longer than 4096 characters.",
                )
                if event is not None:
                    event_ungrouped_counts[event.id] = (
                        event_ungrouped_counts.get(event.id, 0) + action.count
                    )
            else:
                group_members.setdefault(group, []).append(
                    _GroupMember(
                        step_index=step_index,
                        count=action.count,
                        event_id=action.event,
                    )
                )
                event_groups.setdefault(action.event, set()).add(group)

            if event is not None:
                fixture = (
                    config.fixtures[fixture_indexes[event.fixture]]
                    if event.fixture in fixture_indexes
                    else None
                )
                _validate_mutations(
                    config,
                    scenario,
                    scenario_index=scenario_index,
                    step_index=step_index,
                    action=action,
                    fixture=fixture,
                    signer=signer,
                    faults=faults,
                    diagnostics=diagnostics,
                )
                if signer is not None:
                    _validate_signer_headers(
                        signer,
                        user_header_names=header_context.get(
                            (scenario_index, step_index),
                            (),
                        ),
                        field_path=_field_path(*action_path, "signer"),
                        diagnostics=diagnostics,
                    )
        elif isinstance(step, config_models.WaitStep):
            if (
                not logical_time_overflowed
                and logical_time_ns > config_models.MAX_DURATION_NANOSECONDS - step.wait.nanoseconds
            ):
                diagnostics.add(
                    code="SCENARIO_LOGICAL_TIME_OVERFLOW",
                    message="Scenario waits exceed the signed 64-bit logical-time range.",
                    field_path=_field_path(*step_path, "wait"),
                    corrective_action="Reduce cumulative scenario wait durations.",
                    category=ErrorCategory.RESOURCE_LIMIT,
                )
                logical_time_overflowed = True
            elif not logical_time_overflowed:
                logical_time_ns += step.wait.nanoseconds
            continue
        elif isinstance(step, config_models.BarrierStep):
            if not _valid_semantic_text(step.barrier):
                diagnostics.add(
                    code="SCENARIO_BARRIER_NAME_INVALID",
                    message="Barrier name must be nonempty and bounded.",
                    field_path=_field_path(*step_path, "barrier"),
                    corrective_action="Use a nonempty name no longer than 4096 characters.",
                )
            else:
                barriers.setdefault(step.barrier, []).append(step_index)
        elif isinstance(step, config_models.ObserveStep):
            _validate_observe_step(
                config,
                step,
                step_path=step_path,
                diagnostics=diagnostics,
            )
        else:
            faults.add(
                config_models.FaultClass.LIFECYCLE_RESTART,
                field_path=_field_path(*step_path, "restart"),
            )
            _validate_restart_step(
                config,
                step,
                step_path=step_path,
                diagnostics=diagnostics,
            )

    for group, members in group_members.items():
        group_size = sum(member.count for member in members)
        first_member = members[0]
        group_path = _field_path(
            *base,
            "steps",
            first_member.step_index,
            "deliver",
            "concurrency_group",
        )
        if group_size < MIN_CONCURRENCY_GROUP_DELIVERIES:
            diagnostics.add(
                code="SCENARIO_CONCURRENCY_GROUP_TOO_SMALL",
                message="A concurrency group requires at least two planned deliveries.",
                field_path=group_path,
                corrective_action="Add another delivery to the group or remove the group.",
            )
        else:
            faults.add(
                config_models.FaultClass.DELIVERY_CONCURRENT,
                field_path=group_path,
            )
        releases = barriers.get(group, [])
        if not releases:
            diagnostics.add(
                code="SCENARIO_CONCURRENCY_BARRIER_MISSING",
                message="A concurrency group requires one matching barrier.",
                field_path=group_path,
                corrective_action="Add one later barrier step with the same name.",
            )
        elif len(releases) > 1:
            for release_index in releases[1:]:
                diagnostics.add(
                    code="SCENARIO_CONCURRENCY_BARRIER_DUPLICATE",
                    message="A concurrency group can be released by only one barrier.",
                    field_path=_field_path(
                        *base,
                        "steps",
                        release_index,
                        "barrier",
                    ),
                    corrective_action="Keep exactly one matching barrier step.",
                )
        if releases and releases[0] <= max(member.step_index for member in members):
            diagnostics.add(
                code="SCENARIO_CONCURRENCY_BARRIER_EARLY",
                message="A concurrency barrier must follow every member declaration.",
                field_path=_field_path(*base, "steps", releases[0], "barrier"),
                corrective_action="Move the barrier after all deliveries in its group.",
            )

    for group, releases in barriers.items():
        if group not in group_members:
            for release_index in releases:
                diagnostics.add(
                    code="SCENARIO_BARRIER_GROUP_NOT_FOUND",
                    message="Barrier does not name a configured concurrency group.",
                    field_path=_field_path(*base, "steps", release_index, "barrier"),
                    corrective_action="Name a concurrency group declared by a delivery step.",
                )

    for event_index, event in enumerate(scenario.events):
        groups = event_groups.get(event.id, set())
        if event_delivery_counts.get(event.id, 0) > 1 and (
            event_ungrouped_counts.get(event.id, 0) > 0 or len(groups) != 1
        ):
            faults.add(
                config_models.FaultClass.DELIVERY_DUPLICATE,
                field_path=_field_path(*base, "events", event_index, "id"),
            )
        if event.id not in delivered_events:
            diagnostics.add(
                code="SCENARIO_EVENT_NOT_DELIVERED",
                message="Every scenario event requires at least one planned delivery.",
                field_path=_field_path(*base, "events", event_index, "id"),
                corrective_action="Add a delivery step that references this event.",
            )
        for dependency in event.depends_on or ():
            if dependency not in first_delivery_step or event.id not in first_delivery_step:
                continue
            same_group = bool(
                event_groups.get(event.id, set()) & event_groups.get(dependency, set())
            )
            if first_delivery_step[event.id] < first_delivery_step[dependency] or same_group:
                faults.add(
                    config_models.FaultClass.DELIVERY_DEPENDENCY_ORDER_REVERSAL,
                    field_path=_field_path(*base, "events", event_index, "depends_on"),
                )

    _validate_assertions(
        config,
        scenario,
        scenario_index=scenario_index,
        event_indexes=event_indexes,
        delivered_events=delivered_events,
        diagnostics=diagnostics,
    )

    return ScenarioSemantics(
        scenario_id=scenario.id,
        scenario_index=scenario_index,
        event_ids=tuple(event.id for event in scenario.events),
        fault_occurrences=faults.finish(),
        planned_deliveries=planned_deliveries,
        planned_attempts=planned_attempts,
    )


def _validate_lifecycle_observers(
    config: config_models.ProjectConfig,
    *,
    diagnostics: _Diagnostics,
) -> None:
    for lifecycle_name, lifecycle in config.lifecycles.items():
        if lifecycle.readiness_observer not in config.observers:
            diagnostics.add(
                code="SCENARIO_LIFECYCLE_OBSERVER_NOT_FOUND",
                message="Lifecycle readiness observer reference does not resolve.",
                field_path=_field_path(
                    "lifecycles",
                    lifecycle_name,
                    "readiness_observer",
                ),
                corrective_action="Reference one configured observer profile.",
            )


def _index_user_headers(
    config: config_models.ProjectConfig,
    context: ScenarioValidationContext,
    *,
    diagnostics: _Diagnostics,
) -> dict[tuple[int, int], tuple[str, ...]]:
    indexed: dict[tuple[int, int], tuple[str, ...]] = {}
    for binding_index, binding in enumerate(context.user_headers):
        path = _field_path("scenario_validation_context", "user_headers", binding_index)
        if binding.scenario_index >= len(config.scenarios):
            diagnostics.add(
                code="SCENARIO_HEADER_CONTEXT_SCENARIO_NOT_FOUND",
                message="User-header binding does not identify a configured scenario.",
                field_path=path,
                corrective_action="Bind user headers to an existing scenario index.",
            )
            continue
        scenario = config.scenarios[binding.scenario_index]
        if binding.step_index >= len(scenario.steps) or not isinstance(
            scenario.steps[binding.step_index],
            config_models.DeliverStep,
        ):
            diagnostics.add(
                code="SCENARIO_HEADER_CONTEXT_DELIVERY_NOT_FOUND",
                message="User-header binding does not identify a delivery step.",
                field_path=path,
                corrective_action="Bind user headers to an existing delivery-step index.",
            )
            continue
        _validate_user_header_reservations(
            binding,
            field_path=path,
            diagnostics=diagnostics,
        )
        indexed[(binding.scenario_index, binding.step_index)] = binding.names
    return indexed


def _validate_user_header_reservations(
    binding: DeliveryUserHeaders,
    *,
    field_path: str,
    diagnostics: _Diagnostics,
) -> None:
    if set(binding.names) & _HARNESS_REQUEST_HEADERS:
        diagnostics.add(
            code="SCENARIO_USER_HEADER_RESERVED",
            message="User-supplied header conflicts with a harness-owned request header.",
            field_path=field_path,
            corrective_action="Remove framing, routing, proxy, and harness-generated headers.",
        )


def _validate_observe_step(
    config: config_models.ProjectConfig,
    step: config_models.ObserveStep,
    *,
    step_path: tuple[str | int, ...],
    diagnostics: _Diagnostics,
) -> None:
    if step.observe.observer not in config.observers:
        diagnostics.add(
            code="SCENARIO_OBSERVE_OBSERVER_NOT_FOUND",
            message="Observe-step observer reference does not resolve.",
            field_path=_field_path(*step_path, "observe", "observer"),
            corrective_action="Reference one configured observer profile.",
        )
    if not _valid_semantic_text(step.observe.checkpoint):
        diagnostics.add(
            code="SCENARIO_OBSERVE_CHECKPOINT_INVALID",
            message="Observe-step checkpoint must be nonempty and bounded.",
            field_path=_field_path(*step_path, "observe", "checkpoint"),
            corrective_action="Use a nonempty checkpoint no longer than 4096 characters.",
        )


def _validate_restart_step(
    config: config_models.ProjectConfig,
    step: config_models.RestartStep,
    *,
    step_path: tuple[str | int, ...],
    diagnostics: _Diagnostics,
) -> None:
    if step.restart not in config.lifecycles:
        diagnostics.add(
            code="SCENARIO_RESTART_LIFECYCLE_NOT_FOUND",
            message="Restart-step lifecycle reference does not resolve.",
            field_path=_field_path(*step_path, "restart"),
            corrective_action="Reference one configured lifecycle profile.",
        )
        return
    if not config.lifecycles[step.restart].enabled:
        diagnostics.add(
            code="SCENARIO_RESTART_LIFECYCLE_DISABLED",
            message="Restart step requires an enabled lifecycle profile.",
            field_path=_field_path(*step_path, "restart"),
            corrective_action="Enable the lifecycle profile or remove the restart step.",
        )


def _validate_assertions(
    config: config_models.ProjectConfig,
    scenario: config_models.ScenarioConfig,
    *,
    scenario_index: int,
    event_indexes: Mapping[str, int],
    delivered_events: set[str],
    diagnostics: _Diagnostics,
) -> None:
    for assertion_index, assertion in enumerate(scenario.assertions):
        assertion_path = ("scenarios", scenario_index, "assertions", assertion_index)
        if isinstance(
            assertion,
            (
                config_models.HttpStatusAssertion,
                config_models.AcknowledgementDeadlineAssertion,
            ),
        ):
            event_id = assertion.attempt.event
            if event_id not in event_indexes:
                diagnostics.add(
                    code="SCENARIO_ASSERTION_EVENT_NOT_FOUND",
                    message="Assertion attempt event reference does not resolve.",
                    field_path=_field_path(*assertion_path, "attempt", "event"),
                    corrective_action="Reference one event declared by this scenario.",
                )
            elif event_id not in delivered_events:
                diagnostics.add(
                    code="SCENARIO_ASSERTION_EVENT_NOT_DELIVERED",
                    message="Assertion selects an event with no planned delivery.",
                    field_path=_field_path(*assertion_path, "attempt", "event"),
                    corrective_action="Add a delivery for the selected event.",
                )
        elif isinstance(assertion, _OBSERVER_ASSERTIONS):
            _validate_observer_query(
                config,
                assertion.query,
                field_path=_field_path(*assertion_path, "query", "observer"),
                diagnostics=diagnostics,
            )
        else:
            for predicate_index, predicate in enumerate(assertion.predicates):
                _validate_observer_query(
                    config,
                    predicate.query,
                    field_path=_field_path(
                        *assertion_path,
                        "predicates",
                        predicate_index,
                        "query",
                        "observer",
                    ),
                    diagnostics=diagnostics,
                )


def _validate_observer_query(
    config: config_models.ProjectConfig,
    query: config_models.ObserverQuery,
    *,
    field_path: str,
    diagnostics: _Diagnostics,
) -> None:
    if query.observer not in config.observers:
        diagnostics.add(
            code="SCENARIO_ASSERTION_OBSERVER_NOT_FOUND",
            message="Assertion observer reference does not resolve.",
            field_path=field_path,
            corrective_action="Reference one configured observer profile.",
        )


def _validate_signer_headers(
    signer: config_models.SignerConfig,
    *,
    user_header_names: Sequence[str],
    field_path: str,
    diagnostics: _Diagnostics,
) -> None:
    headers = _owned_signer_headers(signer)
    if len(headers) != len(set(headers)):
        diagnostics.add(
            code="SIG_SIGNER_HEADER_INTERNAL_CONFLICT",
            message="Signer profile declares the same owned header more than once.",
            field_path=field_path,
            corrective_action=(
                "Choose a signature header distinct from the profile metadata headers."
            ),
        )
    conflicts = set(headers) & set(user_header_names)
    if conflicts:
        diagnostics.add(
            code="SIG_SIGNER_HEADER_CONFLICT",
            message="User-supplied value conflicts with a signer-owned signature header.",
            field_path=field_path,
            corrective_action="Remove the user-supplied signature header value.",
            safe_details={"conflict_source": "planned-user-header"},
        )
    if set(headers) & _HARNESS_REQUEST_HEADERS:
        diagnostics.add(
            code="SIG_SIGNER_HEADER_RESERVED",
            message="Signer-owned header conflicts with a harness-owned request header.",
            field_path=field_path,
            corrective_action="Choose a dedicated signature header.",
        )


def _owned_signer_headers(signer: config_models.SignerConfig) -> tuple[str, ...]:
    configured = None if signer.header_name is None else signer.header_name.casefold()
    if signer.profile is config_models.SignerProfile.GENERIC_HMAC_SHA256:
        return (configured or _GENERIC_SIGNATURE_HEADER,)
    if signer.profile is config_models.SignerProfile.STRIPE_V1:
        return (configured or _STRIPE_SIGNATURE_HEADER,)
    return (
        _STANDARD_WEBHOOK_ID_HEADER,
        _STANDARD_WEBHOOK_TIMESTAMP_HEADER,
        configured or _STANDARD_WEBHOOK_SIGNATURE_HEADER,
    )


def _validate_mutations(
    config: config_models.ProjectConfig,
    scenario: config_models.ScenarioConfig,
    *,
    scenario_index: int,
    step_index: int,
    action: config_models.DeliverAction,
    fixture: config_models.FixtureConfig | None,
    signer: config_models.SignerConfig | None,
    faults: _Faults,
    diagnostics: _Diagnostics,
) -> None:
    mutations = action.mutations or ()
    structural_writes: list[_StructuralWrite] = []
    invalid_json_index: int | None = None
    truncate_length: int | None = None
    signature_header_operator: tuple[str, int] | None = None
    wrong_key_index: int | None = None
    stale_timestamp_index: int | None = None
    content_type_index: int | None = None
    oversized_index: int | None = None
    alter_offsets: dict[int, int] = {}
    raw_body_destroyer: tuple[str, int] | None = None
    furthest_stage: tuple[MutationStage, str] | None = None

    for mutation_index, mutation in enumerate(mutations):
        operator_id = mutation.type
        stage = _MUTATION_STAGE[operator_id]
        mutation_path = _field_path(
            "scenarios",
            scenario_index,
            "steps",
            step_index,
            "deliver",
            "mutations",
            mutation_index,
        )
        if (
            furthest_stage is not None
            and _MUTATION_STAGE_RANK[stage] < _MUTATION_STAGE_RANK[furthest_stage[0]]
        ):
            diagnostics.add(
                code=_stage_order_code(operator_id),
                message="Mutation appears after an operator from a later pipeline stage.",
                field_path=mutation_path,
                corrective_action="Order mutations by their documented pipeline stages.",
                category=ErrorCategory.CONFLICTING_MUTATION,
                safe_details={
                    "operator": operator_id,
                    "operator_stage": stage.value,
                    "prior_operator": furthest_stage[1],
                    "prior_stage": furthest_stage[0].value,
                },
            )
        elif (
            furthest_stage is None
            or _MUTATION_STAGE_RANK[stage] > _MUTATION_STAGE_RANK[furthest_stage[0]]
        ):
            furthest_stage = (stage, operator_id)
        faults.add(
            _MUTATION_FAULT_CLASS[operator_id],
            field_path=mutation_path,
            operator_id=operator_id,
        )

        if isinstance(mutation, _STRUCTURAL_MUTATIONS):
            if fixture is not None and not _is_json_media_type(fixture.media_type):
                diagnostics.add(
                    code="MUT_STRUCTURAL_REQUIRES_JSON_FIXTURE",
                    message="Structural JSON mutation requires a JSON fixture.",
                    field_path=mutation_path,
                    corrective_action="Use a JSON media type or select a raw-byte mutation.",
                    category=ErrorCategory.MUTATION_NOT_APPLICABLE,
                    safe_details={"operator": operator_id},
                )
            if invalid_json_index is not None:
                diagnostics.add(
                    code="MUT_INVALID_JSON_BEFORE_STRUCTURAL",
                    message="Structural JSON mutation cannot follow invalid-json-v1.",
                    field_path=mutation_path,
                    corrective_action="Move structural JSON mutations before invalid-json-v1.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={
                        "operator": operator_id,
                        "prior_operator": "invalid-json-v1",
                    },
                )
            elif raw_body_destroyer is not None:
                diagnostics.add(
                    code="MUT_RAW_BYTES_BEFORE_STRUCTURAL",
                    message=(
                        "Structural JSON mutation cannot follow a destructive raw-byte mutation."
                    ),
                    field_path=mutation_path,
                    corrective_action="Place every structural mutation before raw-byte mutations.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={
                        "operator": operator_id,
                        "prior_operator": raw_body_destroyer[0],
                    },
                )
            write = _structural_write(
                mutation,
                fixture=fixture,
                mutation_index=mutation_index,
                field_path=mutation_path,
                diagnostics=diagnostics,
            )
            if write is not None:
                _validate_structural_write(
                    write,
                    prior_writes=structural_writes,
                    field_path=mutation_path,
                    diagnostics=diagnostics,
                )
                structural_writes.append(write)

        if isinstance(mutation, config_models.InvalidJsonMutation):
            if fixture is not None and not _is_json_media_type(fixture.media_type):
                diagnostics.add(
                    code="MUT_INVALID_JSON_REQUIRES_JSON_FIXTURE",
                    message="invalid-json-v1 requires bytes declared as JSON.",
                    field_path=mutation_path,
                    corrective_action="Use a JSON media type or select another raw-byte mutation.",
                    category=ErrorCategory.MUTATION_NOT_APPLICABLE,
                    safe_details={"operator": operator_id},
                )
            if invalid_json_index is not None:
                diagnostics.add(
                    code="MUT_INVALID_JSON_CONFLICT",
                    message="invalid-json-v1 cannot be applied more than once to one delivery.",
                    field_path=mutation_path,
                    corrective_action="Keep exactly one invalid-json-v1 operation.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={"operator": operator_id},
                )
            if truncate_length is not None:
                diagnostics.add(
                    code="MUT_INVALID_JSON_AFTER_TRUNCATION",
                    message="invalid-json-v1 cannot consume bytes removed by prior truncation.",
                    field_path=mutation_path,
                    corrective_action=(
                        "Apply invalid-json-v1 before truncate-bytes-v1 or separate them."
                    ),
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={
                        "operator": operator_id,
                        "prior_operator": "truncate-bytes-v1",
                    },
                )
            invalid_json_index = mutation_index
            raw_body_destroyer = (operator_id, mutation_index)

        if isinstance(mutation, config_models.TruncateBytesMutation):
            if truncate_length is not None:
                diagnostics.add(
                    code="MUT_TRUNCATE_BYTES_CONFLICT",
                    message="truncate-bytes-v1 cannot be applied more than once to one delivery.",
                    field_path=mutation_path,
                    corrective_action="Keep exactly one truncate-bytes-v1 operation.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={"operator": operator_id},
                )
            truncate_length = mutation.length
            raw_body_destroyer = (operator_id, mutation_index)

        if isinstance(mutation, config_models.ContentTypeMismatchMutation):
            if content_type_index is not None:
                diagnostics.add(
                    code="MUT_CONTENT_TYPE_MISMATCH_CONFLICT",
                    message="Two content-type-mismatch-v1 operations target the same header.",
                    field_path=mutation_path,
                    corrective_action="Keep exactly one content-type-mismatch-v1 operation.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={"operator": operator_id},
                )
            content_type_index = mutation_index

        if isinstance(mutation, config_models.OversizedBodyMutation):
            if oversized_index is not None:
                diagnostics.add(
                    code="MUT_OVERSIZED_BODY_CONFLICT",
                    message="oversized-body-v1 cannot be applied more than once to one delivery.",
                    field_path=mutation_path,
                    corrective_action="Keep exactly one oversized-body-v1 operation.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={"operator": operator_id},
                )
            if mutation.target_bytes > config.limits.max_request_bytes:
                diagnostics.add(
                    code="MUT_OVERSIZED_BODY_EXCEEDS_REQUEST_LIMIT",
                    message="oversized-body-v1 target exceeds the configured request-byte limit.",
                    field_path=_field_path(
                        "scenarios",
                        scenario_index,
                        "steps",
                        step_index,
                        "deliver",
                        "mutations",
                        mutation_index,
                        "target_bytes",
                    ),
                    corrective_action=(
                        "Lower target_bytes or raise max_request_bytes within its cap."
                    ),
                    category=ErrorCategory.INVALID_PARAMETER,
                    safe_details={
                        "operator": operator_id,
                        "limit": config.limits.max_request_bytes,
                    },
                )
            if truncate_length is not None and mutation.target_bytes > truncate_length:
                diagnostics.add(
                    code="MUT_OVERSIZED_BODY_AFTER_TRUNCATION",
                    message="oversized-body-v1 requires bytes removed by prior truncation.",
                    field_path=mutation_path,
                    corrective_action="Apply oversized-body-v1 before truncation or separate them.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={
                        "operator": operator_id,
                        "prior_operator": "truncate-bytes-v1",
                    },
                )
            oversized_index = mutation_index
            raw_body_destroyer = (operator_id, mutation_index)

        if isinstance(mutation, _SIGNER_REQUIRED_MUTATIONS) and signer is None:
            diagnostics.add(
                code=_requires_signer_code(operator_id),
                message="Mutation requires a resolved signer on the delivery.",
                field_path=mutation_path,
                corrective_action="Configure a signer for this delivery or remove the mutation.",
                category=ErrorCategory.MUTATION_NOT_APPLICABLE,
                safe_details={"operator": operator_id},
            )

        if isinstance(mutation, config_models.StaleSignatureTimestampMutation):
            if stale_timestamp_index is not None:
                diagnostics.add(
                    code="MUT_STALE_SIGNATURE_TIMESTAMP_CONFLICT",
                    message="stale-signature-timestamp-v1 cannot be applied more than once.",
                    field_path=mutation_path,
                    corrective_action="Keep exactly one stale-signature-timestamp-v1 operation.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={"operator": operator_id},
                )
            if (
                signer is not None
                and signer.profile is config_models.SignerProfile.GENERIC_HMAC_SHA256
            ):
                diagnostics.add(
                    code="MUT_STALE_SIGNATURE_TIMESTAMP_NOT_APPLICABLE",
                    message="stale-signature-timestamp-v1 requires a timestamped signer profile.",
                    field_path=mutation_path,
                    corrective_action="Use a timestamped signer or remove this mutation.",
                    category=ErrorCategory.MUTATION_NOT_APPLICABLE,
                    safe_details={"operator": operator_id},
                )
            stale_timestamp_index = mutation_index

        if isinstance(mutation, config_models.WrongSigningKeyMutation):
            if wrong_key_index is not None:
                diagnostics.add(
                    code="MUT_WRONG_SIGNING_KEY_CONFLICT",
                    message="wrong-signing-key-v1 cannot be applied more than once.",
                    field_path=mutation_path,
                    corrective_action="Keep exactly one wrong-signing-key-v1 operation.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={"operator": operator_id},
                )
            wrong_key_index = mutation_index

        if isinstance(
            mutation,
            (
                config_models.MissingSignatureMutation,
                config_models.MalformedSignatureMutation,
            ),
        ):
            if signature_header_operator is not None:
                diagnostics.add(
                    code=(
                        "MUT_MISSING_SIGNATURE_CONFLICT"
                        if isinstance(mutation, config_models.MissingSignatureMutation)
                        else "MUT_MALFORMED_SIGNATURE_CONFLICT"
                    ),
                    message="Signature-header mutation conflicts with an earlier operation.",
                    field_path=mutation_path,
                    corrective_action="Keep only one signature-header mutation per delivery.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={
                        "operator": operator_id,
                        "prior_operator": signature_header_operator[0],
                    },
                )
            else:
                signature_header_operator = (operator_id, mutation_index)

        if isinstance(mutation, config_models.AlterAfterSigningMutation):
            prior_alter = alter_offsets.get(mutation.offset)
            if prior_alter is not None:
                diagnostics.add(
                    code="MUT_ALTER_AFTER_SIGNING_RANGE_CONFLICT",
                    message="Two alter-after-signing-v1 operations target the same byte.",
                    field_path=mutation_path,
                    corrective_action="Use distinct offsets or keep one post-sign alteration.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={"operator": operator_id},
                )
            alter_offsets[mutation.offset] = mutation_index

    if truncate_length is not None:
        for offset, mutation_index in alter_offsets.items():
            if offset >= truncate_length:
                diagnostics.add(
                    code="MUT_ALTER_AFTER_TRUNCATION_RANGE",
                    message="Post-sign byte alteration lies outside the truncated body.",
                    field_path=_field_path(
                        "scenarios",
                        scenario_index,
                        "steps",
                        step_index,
                        "deliver",
                        "mutations",
                        mutation_index,
                    ),
                    corrective_action="Choose an offset below the retained truncation length.",
                    category=ErrorCategory.CONFLICTING_MUTATION,
                    safe_details={
                        "operator": "alter-after-signing-v1",
                        "prior_operator": "truncate-bytes-v1",
                    },
                )

    if wrong_key_index is not None and alter_offsets and not scenario.description:
        diagnostics.add(
            code="MUT_WRONG_KEY_ALTER_REQUIRES_PURPOSE",
            message="Combined wrong-key and post-sign alteration requires a diagnostic purpose.",
            field_path=_field_path("scenarios", scenario_index, "description"),
            corrective_action="Add a description naming the diagnostic purpose.",
            category=ErrorCategory.CONFLICTING_MUTATION,
            safe_details={
                "operator": "wrong-signing-key-v1",
                "combined_operator": "alter-after-signing-v1",
            },
        )


def _structural_write(
    mutation: config_models.MutationConfig,
    *,
    fixture: config_models.FixtureConfig | None,
    mutation_index: int,
    field_path: str,
    diagnostics: _Diagnostics,
) -> _StructuralWrite | None:
    pointer: str
    accepts_prior: bool
    destroys_descendants: bool
    add_overwrite = False
    remove_ignores_missing = False
    if isinstance(mutation, config_models.AddJsonFieldMutation):
        pointer = _join_json_pointer(mutation.pointer, mutation.name)
        accepts_prior = mutation.accept_prior_mutation
        destroys_descendants = True
        add_overwrite = mutation.overwrite
    elif isinstance(
        mutation,
        (
            config_models.RemoveJsonPointerMutation,
            config_models.ReplaceJsonValueMutation,
            config_models.ReplaceJsonTypeMutation,
        ),
    ):
        pointer = mutation.pointer
        accepts_prior = mutation.accept_prior_mutation
        destroys_descendants = True
        if isinstance(mutation, config_models.RemoveJsonPointerMutation):
            remove_ignores_missing = mutation.if_missing == "ignore"
    elif isinstance(mutation, config_models.ChangeEventIdFieldMutation):
        if fixture is None:
            return None
        pointer = fixture.event_id_pointer
        accepts_prior = mutation.accept_prior_mutation
        destroys_descendants = True
    elif isinstance(mutation, config_models.ChangeEventTypeFieldMutation):
        if fixture is None:
            return None
        pointer = fixture.event_type_pointer
        accepts_prior = mutation.accept_prior_mutation
        destroys_descendants = True
    else:
        return None

    if not _valid_json_pointer(pointer):
        diagnostics.add(
            code="MUT_FIXTURE_POINTER_INVALID",
            message="Mutation resolves through an invalid fixture JSON Pointer.",
            field_path=field_path,
            corrective_action="Configure a bounded RFC 6901 event pointer on the fixture.",
            category=ErrorCategory.INVALID_PARAMETER,
            safe_details={"operator": mutation.type},
        )
        return None
    return _StructuralWrite(
        pointer=pointer,
        operator_id=mutation.type,
        index=mutation_index,
        accepts_prior=accepts_prior,
        destroys_descendants=destroys_descendants,
        add_overwrite=add_overwrite,
        remove_ignores_missing=remove_ignores_missing,
    )


def _validate_structural_write(
    write: _StructuralWrite,
    *,
    prior_writes: Sequence[_StructuralWrite],
    field_path: str,
    diagnostics: _Diagnostics,
) -> None:
    for prior in prior_writes:
        same_pointer = write.pointer == prior.pointer
        prior_contains_current = _pointer_contains(prior.pointer, write.pointer)
        current_contains_prior = _pointer_contains(write.pointer, prior.pointer)
        add_collision = (
            same_pointer and write.operator_id == "add-json-field-v1" and not write.add_overwrite
        )
        repeated_remove = (
            same_pointer
            and write.operator_id == prior.operator_id == "remove-json-pointer-v1"
            and not write.remove_ignores_missing
        )
        if same_pointer and (not write.accepts_prior or add_collision or repeated_remove):
            diagnostics.add(
                code=(
                    "MUT_ADD_JSON_FIELD_COLLISION"
                    if add_collision
                    else (
                        "MUT_REMOVE_JSON_POINTER_CONFLICT"
                        if repeated_remove
                        else "MUT_STRUCTURAL_POINTER_CONFLICT"
                    )
                ),
                message="Structural mutations target the same JSON Pointer without an override.",
                field_path=field_path,
                corrective_action=(
                    "Remove one operation or enable every required explicit override."
                ),
                category=ErrorCategory.CONFLICTING_MUTATION,
                safe_details={
                    "operator": write.operator_id,
                    "prior_operator": prior.operator_id,
                },
            )
            return
        if (
            not same_pointer
            and (
                (prior_contains_current and prior.destroys_descendants)
                or (current_contains_prior and write.destroys_descendants)
            )
            and not write.accepts_prior
        ):
            diagnostics.add(
                code="MUT_STRUCTURAL_DEPENDENCY_CONFLICT",
                message="Structural mutation overwrites data required by another operation.",
                field_path=field_path,
                corrective_action="Separate the mutations or explicitly accept the prior mutation.",
                category=ErrorCategory.CONFLICTING_MUTATION,
                safe_details={
                    "operator": write.operator_id,
                    "prior_operator": prior.operator_id,
                },
            )
            return


def _validate_baselines(
    config: config_models.ProjectConfig,
    semantics: tuple[ScenarioSemantics, ...],
    *,
    scenario_indexes: Mapping[str, int],
    diagnostics: _Diagnostics,
) -> None:
    semantic_by_id = {
        item.scenario_id: item
        for item in semantics
        if scenario_indexes.get(item.scenario_id) == item.scenario_index
    }
    edges: dict[str, tuple[str, ...]] = {}
    for scenario_index, scenario in enumerate(config.scenarios):
        references: list[str] = []
        actual_faults = set(semantics[scenario_index].fault_classes)
        mapped_faults = {baseline.fault_class for baseline in scenario.baselines}
        if len(actual_faults) > 1:
            for fault in semantics[scenario_index].fault_classes:
                if fault not in mapped_faults:
                    diagnostics.add(
                        code="SCENARIO_BASELINE_REQUIRED",
                        message="Multi-fault scenario lacks a required one-fault baseline.",
                        field_path=_field_path(
                            "scenarios",
                            scenario_index,
                            "baselines",
                        ),
                        corrective_action="Add a baseline mapping for every included fault class.",
                        safe_details={"fault_class": fault.value},
                    )
        for baseline_index, baseline in enumerate(scenario.baselines):
            baseline_path = (
                "scenarios",
                scenario_index,
                "baselines",
                baseline_index,
            )
            if baseline.fault_class not in actual_faults:
                diagnostics.add(
                    code="SCENARIO_BASELINE_UNUSED_FAULT_CLASS",
                    message="Baseline mapping names a fault not present in this scenario.",
                    field_path=_field_path(*baseline_path, "fault_class"),
                    corrective_action="Remove the mapping or select an included fault class.",
                    safe_details={"fault_class": baseline.fault_class.value},
                )
            if baseline.scenario == scenario.id:
                diagnostics.add(
                    code="SCENARIO_BASELINE_SELF_REFERENCE",
                    message="A scenario cannot use itself as a one-fault baseline.",
                    field_path=_field_path(*baseline_path, "scenario"),
                    corrective_action="Reference a separate one-fault scenario.",
                )
                continue
            if baseline.scenario not in scenario_indexes:
                diagnostics.add(
                    code="SCENARIO_BASELINE_NOT_FOUND",
                    message="Baseline scenario reference does not resolve.",
                    field_path=_field_path(*baseline_path, "scenario"),
                    corrective_action="Reference one configured one-fault scenario ID.",
                )
                continue
            references.append(baseline.scenario)
            referenced = semantic_by_id.get(baseline.scenario)
            if referenced is None:
                continue
            if len(referenced.fault_classes) != 1:
                diagnostics.add(
                    code="SCENARIO_BASELINE_NOT_ONE_FAULT",
                    message="Referenced baseline must contain exactly one fault class.",
                    field_path=_field_path(*baseline_path, "scenario"),
                    corrective_action="Reference a scenario containing exactly the mapped fault.",
                    safe_details={"fault_count": len(referenced.fault_classes)},
                )
            elif referenced.fault_classes[0] is not baseline.fault_class:
                diagnostics.add(
                    code="SCENARIO_BASELINE_FAULT_MISMATCH",
                    message="Referenced one-fault scenario does not match the mapped fault class.",
                    field_path=_field_path(*baseline_path, "scenario"),
                    corrective_action="Reference the matching one-fault scenario.",
                    safe_details={
                        "fault_class": baseline.fault_class.value,
                        "baseline_fault_class": referenced.fault_classes[0].value,
                    },
                )
        edges.setdefault(scenario.id, tuple(references))

    cycle_members = _cycle_members(tuple(scenario_indexes), edges)
    for scenario_id in tuple(scenario_indexes):
        if scenario_id in cycle_members:
            diagnostics.add(
                code="SCENARIO_BASELINE_CYCLE",
                message="Baseline scenario references must form an acyclic graph.",
                field_path=_field_path(
                    "scenarios",
                    scenario_indexes[scenario_id],
                    "baselines",
                ),
                corrective_action="Remove one baseline reference from the cycle.",
            )


def _first_indexes(
    values: Sequence[str],
    *,
    diagnostics: _Diagnostics,
    duplicate_code: str,
    collection_path: tuple[str | int, ...],
    item_field: str,
    message: str,
    corrective_action: str,
) -> dict[str, int]:
    result: dict[str, int] = {}
    for index, value in enumerate(values):
        if value in result:
            diagnostics.add(
                code=duplicate_code,
                message=message,
                field_path=_field_path(*collection_path, index, item_field),
                corrective_action=corrective_action,
            )
        else:
            result[value] = index
    return result


def _cycle_members(
    nodes: Sequence[str],
    edges: Mapping[str, Sequence[str]],
) -> set[str]:
    color: dict[str, int] = dict.fromkeys(nodes, 0)
    parent: dict[str, str | None] = {}
    members: set[str] = set()
    for start in nodes:
        if color[start] != 0:
            continue
        color[start] = 1
        parent[start] = None
        stack: list[tuple[str, int]] = [(start, 0)]
        while stack:
            node, neighbor_index = stack[-1]
            neighbors = edges.get(node, ())
            if neighbor_index >= len(neighbors):
                color[node] = 2
                stack.pop()
                continue
            neighbor = neighbors[neighbor_index]
            stack[-1] = (node, neighbor_index + 1)
            if neighbor not in color:
                continue
            if color[neighbor] == 0:
                color[neighbor] = 1
                parent[neighbor] = node
                stack.append((neighbor, 0))
                continue
            if color[neighbor] != 1:
                continue
            members.add(neighbor)
            cursor: str | None = node
            traversed = 0
            while cursor is not None and cursor != neighbor and traversed <= len(nodes):
                members.add(cursor)
                cursor = parent.get(cursor)
                traversed += 1
    return members


def _requires_signer_code(operator_id: str) -> str:
    return {
        "alter-after-signing-v1": "MUT_ALTER_AFTER_SIGNING_REQUIRES_SIGNER",
        "stale-signature-timestamp-v1": "MUT_STALE_SIGNATURE_REQUIRES_SIGNER",
        "wrong-signing-key-v1": "MUT_WRONG_SIGNING_KEY_REQUIRES_SIGNER",
        "missing-signature-v1": "MUT_MISSING_SIGNATURE_REQUIRES_SIGNER",
        "malformed-signature-v1": "MUT_MALFORMED_SIGNATURE_REQUIRES_SIGNER",
    }[operator_id]


def _stage_order_code(operator_id: str) -> str:
    stem = operator_id.removesuffix("-v1").replace("-", "_").upper()
    return f"MUT_{stem}_STAGE_ORDER"


def _is_json_media_type(media_type: str) -> bool:
    base = media_type.partition(";")[0].strip().casefold()
    return base == "application/json" or base.endswith("+json")


def _valid_semantic_text(value: str) -> bool:
    return bool(value) and len(value) <= MAX_SEMANTIC_REFERENCE_LENGTH


def _valid_json_pointer(value: str) -> bool:
    try:
        config_models.JsonPointer(value)
    except ValueError:
        return False
    return True


def _join_json_pointer(pointer: str, name: str) -> str:
    encoded = name.replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{encoded}"


def _pointer_contains(parent: str, child: str) -> bool:
    if parent == child:
        return True
    if not parent:
        return True
    return child.startswith(f"{parent}/")


def _field_path(*parts: str | int) -> str:
    rendered = "$"
    for part in parts:
        rendered = f"{rendered}[{part}]" if isinstance(part, int) else f"{rendered}.{part}"
    return rendered
