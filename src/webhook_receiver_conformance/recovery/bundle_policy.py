"""Derive conservative recovery authorization from one verified run bundle."""
# ruff: noqa: EM101, INP001, TRY003

from __future__ import annotations

from collections import Counter
from typing import Final

from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.enums import AttemptState
from webhook_receiver_conformance.domain.identifiers import PlannedIdKind, planned_id
from webhook_receiver_conformance.manifest.models import (
    AttemptTemplate,
    DeliveryPlan,
    RunManifest,
    ScenarioPlan,
)
from webhook_receiver_conformance.recovery.models import (
    AttemptRecoveryItem,
    RecoveryAmbiguity,
    RecoveryPlan,
)
from webhook_receiver_conformance.recovery.policy import (
    BundleRecoveryPolicy,
    RedeliveryTemplate,
    ResumePolicyIntegrityError,
)
from webhook_receiver_conformance.scheduler.retries import RetryPredicate

_AMBIGUOUS_REDELIVERY_PREDICATE: Final = RetryPredicate.TIMED_OUT


def derive_bundle_recovery_policy(
    manifest: RunManifest,
    recovery_plan: RecoveryPlan,
) -> BundleRecoveryPolicy:
    """Return only exact, unused redelivery nodes authorized by the manifest.

    ``timed_out`` is the sole v1 scenario predicate that acknowledges a
    possible-send outcome. The explicit CLI ``redeliver`` selection remains a
    separate input to :class:`ResumeInvocationPolicy`; this helper never grants
    invocation consent.

    v1 has no configuration or manifest field that binds an exact decisive
    assertion set to one delivery. Observation rules therefore remain empty
    instead of inferring recovery authority from ordinary observer assertions.
    """
    if type(manifest) is not RunManifest:
        raise TypeError("manifest must be a RunManifest")
    if type(recovery_plan) is not RecoveryPlan:
        raise TypeError("recovery_plan must be a RecoveryPlan")
    try:
        manifest.verify_id()
        generator = _manifest_generator(manifest)
        scenarios = _scenario_index(manifest)
    except (TypeError, ValueError) as error:
        raise ResumePolicyIntegrityError(
            "recovery policy requires a verified, internally consistent manifest"
        ) from error

    used_ordinals = _used_attempt_ordinals(recovery_plan)
    ambiguous = tuple(
        item
        for item in recovery_plan.attempts
        if item.ambiguity is RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT
        and (
            item.prior_state is AttemptState.UNKNOWN_OUTCOME
            or item.target_state is AttemptState.UNKNOWN_OUTCOME
        )
    )
    ambiguous_scope_counts = Counter((item.scenario_id, item.delivery_id) for item in ambiguous)

    templates: list[RedeliveryTemplate] = []
    for item in ambiguous:
        scope = (item.scenario_id, item.delivery_id)
        if ambiguous_scope_counts[scope] != 1:
            continue
        scenario, delivery = _matching_delivery(item, scenarios)
        candidate = _authorized_unused_next_attempt(
            item,
            delivery,
            used_ordinals=used_ordinals.get(scope, frozenset()),
        )
        if candidate is None:
            continue
        attempt_plan_id = planned_id(
            generator,
            PlannedIdKind.ATTEMPT_PLAN,
            (scenario.scenario_id, delivery.delivery_id, str(candidate.ordinal)),
        )
        templates.append(
            RedeliveryTemplate(
                scenario_id=scenario.scenario_id,
                event_id=delivery.event_id,
                delivery_id=delivery.delivery_id,
                attempt_plan_id=attempt_plan_id,
                logical_due_ns=candidate.not_before_logical_ns,
                deterministic_tie_key=f"retry.{attempt_plan_id}",
            )
        )

    return BundleRecoveryPolicy(
        redelivery_templates=tuple(templates),
        observation_rules=(),
    )


def _manifest_generator(manifest: RunManifest) -> ContextGenerator:
    generator = ContextGenerator.from_normalized_seed_hash(
        bytes.fromhex(manifest.generator.normalized_seed_hash_hex)
    )
    if f"sha256:{generator.fingerprint}" != manifest.generator.seed_fingerprint:
        raise ValueError("manifest generator seed and fingerprint disagree")
    return generator


def _scenario_index(
    manifest: RunManifest,
) -> dict[str, tuple[int, ScenarioPlan, dict[str, DeliveryPlan]]]:
    result: dict[str, tuple[int, ScenarioPlan, dict[str, DeliveryPlan]]] = {}
    for scenario_ordinal, scenario in enumerate(manifest.scenarios):
        if scenario.scenario_id in result:
            raise ValueError("manifest scenario identities are not unique")
        if tuple(delivery.ordinal for delivery in scenario.deliveries) != tuple(
            range(len(scenario.deliveries))
        ):
            raise ValueError("manifest delivery ordinals are not contiguous")
        deliveries = {delivery.delivery_id: delivery for delivery in scenario.deliveries}
        if len(deliveries) != len(scenario.deliveries):
            raise ValueError("manifest delivery identities are not unique")
        for delivery in scenario.deliveries:
            _validate_attempt_plan(delivery)
        result[scenario.scenario_id] = (scenario_ordinal, scenario, deliveries)
    return result


def _validate_attempt_plan(delivery: DeliveryPlan) -> None:
    attempts = delivery.attempt_plan
    if not attempts or tuple(item.ordinal for item in attempts) != tuple(
        range(1, len(attempts) + 1)
    ):
        raise ValueError("manifest attempt ordinals are not contiguous")
    if attempts[0].conditional_on is not None:
        raise ValueError("manifest initial attempt cannot be conditional")
    if attempts[0].not_before_logical_ns != delivery.logical_time_ns:
        raise ValueError("manifest initial attempt due time differs from its delivery")
    previous_due = attempts[0].not_before_logical_ns
    for attempt in attempts[1:]:
        if _retry_predicates(attempt) is None:
            raise ValueError("manifest retry predicate is malformed")
        if attempt.not_before_logical_ns < previous_due:
            raise ValueError("manifest retry due times are not monotonic")
        previous_due = attempt.not_before_logical_ns


def _matching_delivery(
    item: AttemptRecoveryItem,
    scenarios: dict[str, tuple[int, ScenarioPlan, dict[str, DeliveryPlan]]],
) -> tuple[ScenarioPlan, DeliveryPlan]:
    indexed = scenarios.get(item.scenario_id)
    if indexed is None:
        raise ResumePolicyIntegrityError(
            "recovery attempt references a scenario absent from the manifest"
        )
    scenario_ordinal, scenario, deliveries = indexed
    delivery = deliveries.get(item.delivery_id)
    if (
        delivery is None
        or item.scenario_ordinal != scenario_ordinal
        or item.delivery_ordinal != delivery.ordinal
        or item.step_ordinal != delivery.ordinal
        or item.event_id != delivery.event_id
    ):
        raise ResumePolicyIntegrityError(
            "recovery attempt coordinates differ from the verified manifest"
        )
    return scenario, delivery


def _used_attempt_ordinals(
    recovery_plan: RecoveryPlan,
) -> dict[tuple[str, str], frozenset[int]]:
    mutable: dict[tuple[str, str], set[int]] = {}
    for item in recovery_plan.attempts:
        mutable.setdefault((item.scenario_id, item.delivery_id), set()).add(item.attempt_ordinal)
    return {scope: frozenset(ordinals) for scope, ordinals in mutable.items()}


def _authorized_unused_next_attempt(
    item: AttemptRecoveryItem,
    delivery: DeliveryPlan,
    *,
    used_ordinals: frozenset[int],
) -> AttemptTemplate | None:
    next_ordinal = item.attempt_ordinal + 1
    if next_ordinal > len(delivery.attempt_plan) or next_ordinal in used_ordinals:
        return None
    candidate = delivery.attempt_plan[next_ordinal - 1]
    if candidate.ordinal != next_ordinal:
        return None
    predicates = _retry_predicates(candidate)
    if predicates is None or _AMBIGUOUS_REDELIVERY_PREDICATE not in predicates:
        return None
    return candidate


def _retry_predicates(
    attempt: AttemptTemplate,
) -> frozenset[RetryPredicate] | None:
    raw = attempt.conditional_on
    if raw is None:
        return None
    pieces = raw.split("|")
    if not pieces or any(not piece for piece in pieces) or len(set(pieces)) != len(pieces):
        return None
    try:
        return frozenset(RetryPredicate(piece) for piece in pieces)
    except ValueError:
        return None


__all__ = ["derive_bundle_recovery_policy"]
