"""Recovery authorization derived only from verified immutable bundle policy."""
# ruff: noqa: INP001

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from webhook_receiver_conformance.config.loader import load_project_config
from webhook_receiver_conformance.config.models import DeliverStep, RetryOn
from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.enums import AttemptState, RunState
from webhook_receiver_conformance.domain.identifiers import PlannedIdKind, planned_id
from webhook_receiver_conformance.journal.integrity import ResumeIntegrityReport
from webhook_receiver_conformance.journal.run_lock import RunLockMetadata
from webhook_receiver_conformance.manifest.compiler import compile_run_bundle
from webhook_receiver_conformance.recovery.bundle_policy import (
    derive_bundle_recovery_policy,
    verify_bundle_recovery_manifest,
)
from webhook_receiver_conformance.recovery.models import (
    AttemptRecoveryAction,
    AttemptRecoveryItem,
    DurableNoSendProof,
    RecoveryAmbiguity,
    RecoveryPlan,
    RecoveryScanContext,
)
from webhook_receiver_conformance.recovery.policy import (
    AmbiguityPolicy,
    BundleRecoveryPolicy,
    PersistedScheduleSnapshot,
    ResumeDisposition,
    ResumeInvocationPolicy,
    ResumePolicyContext,
    ResumePolicyEngine,
    ResumePolicyIntegrityError,
)
from webhook_receiver_conformance.scheduler.clocks import TransitionTimestamp

if TYPE_CHECKING:
    from webhook_receiver_conformance.manifest.models import RunManifest

RUN_ID = "00000000-0000-4000-8000-000000000271"
OWNER_EPOCH = 4
ATTEMPT_ID = f"attempt_{1:026d}"
NEXT_ATTEMPT_ID = f"attempt_{2:026d}"
THIRD_ATTEMPT_ID = f"attempt_{3:026d}"
NEXT_ATTEMPT_ORDINAL = 2
THIRD_ATTEMPT_ORDINAL = 3
SECRET_FINGERPRINT = f"sha256:{'a' * 64}"
CREATED_AT = "2026-07-27T22:00:00Z"


def _compiled_retry_manifest(
    tmp_path: Path,
    *,
    retry_on: tuple[RetryOn, ...] = (RetryOn.TIMED_OUT,),
    max_attempts: int = 2,
) -> RunManifest:
    loaded = load_project_config(Path("examples/project-config.minimal.yaml"))
    assert loaded.config is not None
    assert loaded.project_root is not None
    config = loaded.config
    step = cast("DeliverStep", config.scenarios[0].steps[0])
    retry = step.deliver.retry
    assert retry is not None
    configured_retry = retry.model_copy(
        update={
            "max_attempts": max_attempts,
            "backoff": tuple(type(retry.jitter)("2s") for _index in range(max_attempts - 1)),
            "retry_on": retry_on,
        }
    )
    configured_action = step.deliver.model_copy(update={"retry": configured_retry})
    configured_scenario = config.scenarios[0].model_copy(
        update={
            "steps": (
                step.model_copy(update={"deliver": configured_action}),
                *config.scenarios[0].steps[1:],
            )
        }
    )
    configured = config.model_copy(update={"scenarios": (configured_scenario,)})
    return compile_run_bundle(
        configured,
        project_root=loaded.project_root,
        bundle_directory=tmp_path,
        created_at=CREATED_AT,
        seed="bundle-recovery-policy",
        secret_fingerprints={"env:WEBHOOK_TEST_SECRET": SECRET_FINGERPRINT},
        materialize=False,
    ).manifest


def _attempt(
    manifest: RunManifest,
    *,
    ordinal: int = 1,
    attempt_id: str = ATTEMPT_ID,
    state: AttemptState = AttemptState.UNKNOWN_OUTCOME,
    event_id: str | None = None,
) -> AttemptRecoveryItem:
    scenario = manifest.scenarios[0]
    delivery = scenario.deliveries[0]
    ambiguous = state is AttemptState.UNKNOWN_OUTCOME
    return AttemptRecoveryItem(
        run_id=RUN_ID,
        scenario_id=scenario.scenario_id,
        event_id=delivery.event_id if event_id is None else event_id,
        delivery_id=delivery.delivery_id,
        attempt_id=attempt_id,
        scenario_ordinal=0,
        step_ordinal=delivery.ordinal,
        delivery_ordinal=delivery.ordinal,
        attempt_ordinal=ordinal,
        prior_state=state,
        durable_no_send_proof=DurableNoSendProof.NONE,
        action=(
            AttemptRecoveryAction.PRESERVE_UNKNOWN_OUTCOME
            if ambiguous
            else AttemptRecoveryAction.PRESERVE_TERMINAL
        ),
        ambiguity=(
            RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT if ambiguous else RecoveryAmbiguity.NONE
        ),
        target_state=None,
    )


def _recovery_plan(*attempts: AttemptRecoveryItem) -> RecoveryPlan:
    return RecoveryPlan(
        run_id=RUN_ID,
        owner_epoch=OWNER_EPOCH,
        run_state=RunState.PAUSED,
        attempts=tuple(sorted(attempts, key=lambda item: item.deterministic_key)),
        observations=(),
    )


def _policy_context(plan: RecoveryPlan) -> ResumePolicyContext:
    owner = RunLockMetadata(
        run_id=RUN_ID,
        pid=271,
        process_start_fingerprint="bundle-policy-test",
        hostname="bundle-policy-host",
        owner_epoch=OWNER_EPOCH,
        wall_timestamp="2026-07-27T22:00:00.000000Z",
    )
    return ResumePolicyContext(
        scan_context=RecoveryScanContext(
            run_id=RUN_ID,
            owner_epoch=OWNER_EPOCH,
            integrity=ResumeIntegrityReport(database_bytes=1),
            owner=owner,
        ),
        recovery_plan=plan,
    )


def _timestamp() -> TransitionTimestamp:
    return TransitionTimestamp(
        datetime(2026, 7, 27, 22, 0, tzinfo=UTC),
        monotonic_elapsed_ns=271,
    )


def test_compiled_timed_out_retry_derives_exact_unused_manifest_template(
    tmp_path: Path,
) -> None:
    manifest = _compiled_retry_manifest(tmp_path)
    original = _attempt(manifest)
    recovery = _recovery_plan(original)

    policy = derive_bundle_recovery_policy(manifest, recovery)

    scenario = manifest.scenarios[0]
    delivery = scenario.deliveries[0]
    candidate = delivery.attempt_plan[1]
    generator = ContextGenerator.from_normalized_seed_hash(
        bytes.fromhex(manifest.generator.normalized_seed_hash_hex)
    )
    expected_attempt_plan_id = planned_id(
        generator,
        PlannedIdKind.ATTEMPT_PLAN,
        (scenario.scenario_id, delivery.delivery_id, "2"),
    )
    assert policy.observation_rules == ()
    assert len(policy.redelivery_templates) == 1
    template = policy.redelivery_templates[0]
    assert template.scenario_id == scenario.scenario_id
    assert template.event_id == delivery.event_id
    assert template.delivery_id == delivery.delivery_id
    assert template.attempt_plan_id == expected_attempt_plan_id
    assert template.logical_due_ns == candidate.not_before_logical_ns
    assert template.deterministic_tie_key == f"retry.{expected_attempt_plan_id}"


@pytest.mark.parametrize(
    ("use_bundle_policy", "use_cli_option"),
    [(True, False), (False, True)],
    ids=["manifest-only", "cli-only"],
)
def test_manifest_and_cli_redelivery_consent_are_each_insufficient(
    tmp_path: Path,
    *,
    use_bundle_policy: bool,
    use_cli_option: bool,
) -> None:
    manifest = _compiled_retry_manifest(tmp_path)
    recovery = _recovery_plan(_attempt(manifest))
    bundle_policy = (
        derive_bundle_recovery_policy(manifest, recovery)
        if use_bundle_policy
        else BundleRecoveryPolicy()
    )
    invocation = ResumeInvocationPolicy(
        on_ambiguous=AmbiguityPolicy.REDELIVER if use_cli_option else None
    )

    result = ResumePolicyEngine(fresh_attempt_id=lambda: NEXT_ATTEMPT_ID).build_plan(
        _policy_context(recovery),
        bundle_policy=bundle_policy,
        invocation=invocation,
        schedule=PersistedScheduleSnapshot(()),
        timestamp=_timestamp(),
    )

    assert result.disposition is ResumeDisposition.STOP_AMBIGUOUS
    assert result.redeliveries == ()
    assert result.runnable_schedule == ()


def test_dual_consent_uses_the_exact_derived_template(tmp_path: Path) -> None:
    manifest = _compiled_retry_manifest(tmp_path)
    recovery = _recovery_plan(_attempt(manifest))
    policy = derive_bundle_recovery_policy(manifest, recovery)

    result = ResumePolicyEngine(fresh_attempt_id=lambda: NEXT_ATTEMPT_ID).build_plan(
        _policy_context(recovery),
        bundle_policy=policy,
        invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
        schedule=PersistedScheduleSnapshot(()),
        timestamp=_timestamp(),
    )

    assert result.disposition is ResumeDisposition.CONTINUE
    assert len(result.redeliveries) == 1
    assert result.redeliveries[0].attempt_plan_id == policy.redelivery_templates[0].attempt_plan_id
    assert result.redeliveries[0].attempt_ordinal == NEXT_ATTEMPT_ORDINAL


def test_derivation_selects_the_immediate_next_ordinal_not_the_first_retry(
    tmp_path: Path,
) -> None:
    manifest = _compiled_retry_manifest(tmp_path, max_attempts=3)
    first = _attempt(
        manifest,
        ordinal=1,
        attempt_id=ATTEMPT_ID,
        state=AttemptState.SUCCEEDED,
    )
    ambiguous_second = _attempt(
        manifest,
        ordinal=NEXT_ATTEMPT_ORDINAL,
        attempt_id=NEXT_ATTEMPT_ID,
    )

    policy = derive_bundle_recovery_policy(
        manifest,
        _recovery_plan(first, ambiguous_second),
    )

    scenario = manifest.scenarios[0]
    delivery = scenario.deliveries[0]
    generator = ContextGenerator.from_normalized_seed_hash(
        bytes.fromhex(manifest.generator.normalized_seed_hash_hex)
    )
    expected = planned_id(
        generator,
        PlannedIdKind.ATTEMPT_PLAN,
        (
            scenario.scenario_id,
            delivery.delivery_id,
            str(THIRD_ATTEMPT_ORDINAL),
        ),
    )
    assert tuple(item.attempt_plan_id for item in policy.redelivery_templates) == (expected,)
    result = ResumePolicyEngine(fresh_attempt_id=lambda: THIRD_ATTEMPT_ID).build_plan(
        _policy_context(_recovery_plan(first, ambiguous_second)),
        bundle_policy=policy,
        invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
        schedule=PersistedScheduleSnapshot(()),
        timestamp=_timestamp(),
    )
    assert result.redeliveries[0].attempt_ordinal == THIRD_ATTEMPT_ORDINAL
    assert (
        result.redeliveries[0].schedule_item.logical_due_ns
        == delivery.attempt_plan[2].not_before_logical_ns
    )


def test_derivation_fails_closed_without_an_eligible_unused_exact_next_node(
    tmp_path: Path,
) -> None:
    connection_only = _compiled_retry_manifest(
        tmp_path / "connection-only",
        retry_on=(RetryOn.CONNECTION_FAILED,),
    )
    no_timeout_consent = derive_bundle_recovery_policy(
        connection_only,
        _recovery_plan(_attempt(connection_only)),
    )
    assert no_timeout_consent == BundleRecoveryPolicy()

    timeout_manifest = _compiled_retry_manifest(tmp_path / "already-used")
    used_next = _attempt(
        timeout_manifest,
        ordinal=2,
        attempt_id=NEXT_ATTEMPT_ID,
        state=AttemptState.SUCCEEDED,
    )
    already_used = derive_bundle_recovery_policy(
        timeout_manifest,
        _recovery_plan(_attempt(timeout_manifest), used_next),
    )
    assert already_used == BundleRecoveryPolicy()


def test_derivation_rejects_manifest_or_recovery_coordinate_mismatch(
    tmp_path: Path,
) -> None:
    manifest = _compiled_retry_manifest(tmp_path)
    tampered = manifest.model_copy(update={"configuration_digest": f"sha256:{'f' * 64}"})
    with pytest.raises(ResumePolicyIntegrityError, match="verified"):
        verify_bundle_recovery_manifest(tampered)
    with pytest.raises(ResumePolicyIntegrityError, match="verified"):
        derive_bundle_recovery_policy(tampered, _recovery_plan(_attempt(manifest)))

    generator = ContextGenerator.from_normalized_seed_hash(
        bytes.fromhex(manifest.generator.normalized_seed_hash_hex)
    )
    other_event_id = planned_id(
        generator,
        PlannedIdKind.EVENT,
        ("different", "event"),
    )
    with pytest.raises(ResumePolicyIntegrityError, match="coordinates"):
        derive_bundle_recovery_policy(
            manifest,
            _recovery_plan(_attempt(manifest, event_id=other_event_id)),
        )


def test_observe_stays_fail_closed_without_a_v1_decisive_rule(
    tmp_path: Path,
) -> None:
    manifest = _compiled_retry_manifest(tmp_path)

    policy = derive_bundle_recovery_policy(
        manifest,
        _recovery_plan(_attempt(manifest)),
    )

    # v1 assertions are not marked as a delivery-scoped decisive set, and
    # read_only/idempotent are negotiated runtime facts rather than bundle data.
    assert policy.observation_rules == ()
    result = ResumePolicyEngine().build_plan(
        _policy_context(_recovery_plan(_attempt(manifest))),
        bundle_policy=policy,
        invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.OBSERVE),
        schedule=PersistedScheduleSnapshot(()),
        timestamp=_timestamp(),
    )
    assert result.disposition is ResumeDisposition.STOP_AMBIGUOUS
    assert result.observations == ()
