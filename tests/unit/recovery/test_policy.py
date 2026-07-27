"""Hostile resume-policy contract tests for TASK-0207."""
# ruff: noqa: INP001, PLR0913, SLF001

from __future__ import annotations

import socket
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import anyio
import pytest

from webhook_receiver_conformance.domain.enums import (
    AttemptState,
    RunState,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory, exit_for_result
from webhook_receiver_conformance.journal import repositories as repository_module
from webhook_receiver_conformance.journal.integrity import (
    ResumeIntegrityError,
    ResumeIntegrityReport,
    verify_resume_integrity,
)
from webhook_receiver_conformance.journal.run_lock import RunLockMetadata
from webhook_receiver_conformance.journal.schema import create_run_database
from webhook_receiver_conformance.journal.transitions import MAX_SAFE_INTEGER
from webhook_receiver_conformance.recovery import policy as policy_module
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
    AtomicResumePolicyJournal,
    BundleRecoveryPolicy,
    ObservationReconciliationRule,
    OperatorDecisionDirective,
    OperatorVerdict,
    PersistedScheduleSnapshot,
    RecoveryDecisionKind,
    RecoveryEvidenceReference,
    RedeliveryTemplate,
    ResumeDisposition,
    ResumeInvocationPolicy,
    ResumePolicyContext,
    ResumePolicyEngine,
    ResumePolicyIntegrityError,
    ResumePolicyPlan,
    ResumePolicyResourceLimitError,
)
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
    TransitionTimestamp,
)
from webhook_receiver_conformance.scheduler.engine import (
    PersistentScheduler,
    ScheduleJournal,
    WorkLease,
)
from webhook_receiver_conformance.scheduler.queue import (
    PersistentPriorityQueue,
    ScheduleItem,
)

if TYPE_CHECKING:
    from pathlib import Path

RUN_ID = "00000000-0000-4000-8000-000000000207"
OWNER_EPOCH = 9
WALL_TIME = datetime(2026, 7, 27, 20, 7, tzinfo=UTC)
WALL_TEXT = "2026-07-27T20:07:00.000000Z"
LIVE_TIMESTAMP = TransitionTimestamp(WALL_TIME, 207_000)
DIGEST = f"sha256:{'a' * 64}"
CANARY_TEXT = "operator-canary-must-not-appear-in-repr"
PAIR_COUNT = 2
FIRST_ATTEMPT_ORDINAL = 1
NEXT_ATTEMPT_ORDINAL = 2


def _planned(prefix: str, ordinal: int) -> str:
    return f"{prefix}{ordinal:026d}"


SCENARIO_ID = _planned("scenario_", 1)
EVENT_ID = _planned("event_", 1)
DELIVERY_ID = _planned("delivery_", 1)
ATTEMPT_ID = _planned("attempt_", 1)
NEXT_ATTEMPT_ID = _planned("attempt_", 99)
ATTEMPT_PLAN_ID = _planned("attempt_plan_", 2)
OBSERVATION_ID = _planned("observation_", 1)
ASSERTION_ID = _planned("assertion_", 1)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _unknown_attempt(
    ordinal: int = 1,
    *,
    scenario_ordinal: int = 0,
    step_ordinal: int = 0,
    delivery_ordinal: int = 0,
    scenario_id: str = SCENARIO_ID,
    event_id: str = EVENT_ID,
    delivery_id: str = DELIVERY_ID,
    attempt_id: str = ATTEMPT_ID,
) -> AttemptRecoveryItem:
    return AttemptRecoveryItem(
        run_id=RUN_ID,
        scenario_id=scenario_id,
        event_id=event_id,
        delivery_id=delivery_id,
        attempt_id=attempt_id,
        scenario_ordinal=scenario_ordinal,
        step_ordinal=step_ordinal,
        delivery_ordinal=delivery_ordinal,
        attempt_ordinal=ordinal,
        prior_state=AttemptState.UNKNOWN_OUTCOME,
        durable_no_send_proof=DurableNoSendProof.NONE,
        action=AttemptRecoveryAction.PRESERVE_UNKNOWN_OUTCOME,
        ambiguity=RecoveryAmbiguity.POSSIBLE_RECEIVER_EFFECT,
        target_state=None,
    )


def _phase_ambiguous_attempt() -> AttemptRecoveryItem:
    return AttemptRecoveryItem(
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        attempt_id=ATTEMPT_ID,
        scenario_ordinal=0,
        step_ordinal=0,
        delivery_ordinal=0,
        attempt_ordinal=1,
        prior_state=AttemptState.PRE_SEND_COMMITTED,
        durable_no_send_proof=DurableNoSendProof.NONE,
        action=AttemptRecoveryAction.REQUIRE_PHASE_EVIDENCE,
        ambiguity=RecoveryAmbiguity.PHASE_EVIDENCE_REQUIRED,
        target_state=None,
    )


def _scheduled_attempt() -> AttemptRecoveryItem:
    return AttemptRecoveryItem(
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        delivery_id=DELIVERY_ID,
        attempt_id=ATTEMPT_ID,
        scenario_ordinal=0,
        step_ordinal=0,
        delivery_ordinal=0,
        attempt_ordinal=0,
        prior_state=AttemptState.SCHEDULED,
        durable_no_send_proof=DurableNoSendProof.NONE,
        action=AttemptRecoveryAction.RESUME_SCHEDULED,
        ambiguity=RecoveryAmbiguity.NONE,
        target_state=None,
    )


def _policy_context(
    *attempts: AttemptRecoveryItem,
    plan_owner_epoch: int = OWNER_EPOCH,
) -> ResumePolicyContext:
    scan = RecoveryScanContext(
        run_id=RUN_ID,
        owner_epoch=OWNER_EPOCH,
        integrity=ResumeIntegrityReport(database_bytes=1),
        owner=RunLockMetadata(
            run_id=RUN_ID,
            pid=207,
            process_start_fingerprint="policy-test-process",
            hostname="policy-test-host",
            owner_epoch=OWNER_EPOCH,
            wall_timestamp=WALL_TEXT,
        ),
    )
    ordered = tuple(sorted(attempts, key=lambda item: item.deterministic_key))
    plan = RecoveryPlan(
        run_id=RUN_ID,
        owner_epoch=plan_owner_epoch,
        run_state=RunState.PAUSED,
        attempts=ordered,
        observations=(),
    )
    return ResumePolicyContext(scan_context=scan, recovery_plan=plan)


def _schedule_item(
    index: int,
    *,
    scenario: int = 0,
    step: int = 0,
    delivery: int = 0,
    attempt: int = 2,
    due: int = 0,
) -> ScheduleItem:
    return ScheduleItem(
        schedule_entry_id=f"schedule.{index}",
        entity_id=_planned("attempt_plan_", index + 10),
        logical_due_ns=due,
        scenario_ordinal=scenario,
        step_ordinal=step,
        delivery_ordinal=delivery,
        attempt_ordinal=attempt,
        deterministic_tie_key=f"tie.{index}",
    )


def _redelivery_bundle(
    attempt: AttemptRecoveryItem | None = None,
    *,
    logical_due_ns: int = 0,
) -> BundleRecoveryPolicy:
    source = _unknown_attempt() if attempt is None else attempt
    return BundleRecoveryPolicy(
        redelivery_templates=(
            RedeliveryTemplate(
                scenario_id=source.scenario_id,
                event_id=source.event_id,
                delivery_id=source.delivery_id,
                attempt_plan_id=ATTEMPT_PLAN_ID,
                logical_due_ns=logical_due_ns,
                deterministic_tie_key="explicit-redelivery",
            ),
        ),
    )


def _observation_bundle(
    *,
    read_only: bool = True,
    idempotent: bool = True,
) -> BundleRecoveryPolicy:
    return BundleRecoveryPolicy(
        observation_rules=(
            ObservationReconciliationRule(
                scenario_id=SCENARIO_ID,
                delivery_id=DELIVERY_ID,
                observation_id=OBSERVATION_ID,
                assertion_ids=(ASSERTION_ID,),
                read_only=read_only,
                idempotent=idempotent,
            ),
        ),
    )


@dataclass(slots=True)
class _RecordingIdFactory:
    values: list[str]
    calls: int = 0

    def __call__(self) -> str:
        self.calls += 1
        if not self.values:
            message = "test identity factory exhausted"
            raise AssertionError(message)
        return self.values.pop(0)


@dataclass(slots=True)
class _MemoryPolicyJournal(AtomicResumePolicyJournal):
    physical_attempts: dict[str, AttemptState] = field(default_factory=dict[str, AttemptState])
    schedules: dict[str, ScheduleItem] = field(default_factory=dict[str, ScheduleItem])
    committed: dict[tuple[str, ...], ResumePolicyPlan] = field(
        default_factory=dict[tuple[str, ...], ResumePolicyPlan]
    )
    calls: int = 0

    async def commit_policy(self, plan: ResumePolicyPlan) -> bool:
        self.calls += 1
        key = tuple(item.decision_id for item in plan.decisions)
        existing = self.committed.get(key)
        if existing is not None:
            if existing != plan:
                message = "policy idempotency conflict"
                raise RuntimeError(message)
            return False
        for redelivery in plan.redeliveries:
            if (
                self.physical_attempts.get(redelivery.predecessor_attempt_id)
                is not AttemptState.UNKNOWN_OUTCOME
            ):
                message = "redelivery predecessor was mutated or absent"
                raise RuntimeError(message)
            if redelivery.attempt_id in self.physical_attempts:
                message = "new physical attempt identity already exists"
                raise RuntimeError(message)
            self.physical_attempts[redelivery.attempt_id] = AttemptState.SCHEDULED
            self.schedules[redelivery.schedule_item.schedule_entry_id] = redelivery.schedule_item
        self.committed[key] = plan
        return True


@dataclass(slots=True)
class _MemoryScheduleJournal(ScheduleJournal):
    entries: dict[str, ScheduleItem]
    consumed: set[str] = field(default_factory=set[str])
    consume_order: list[str] = field(default_factory=list[str])

    async def persist(self, item: ScheduleItem) -> bool:
        existing = self.entries.get(item.schedule_entry_id)
        if existing is not None:
            if existing != item:
                message = "schedule identity conflict"
                raise RuntimeError(message)
            return False
        self.entries[item.schedule_entry_id] = item
        return True

    async def consume(
        self,
        item: ScheduleItem,
        *,
        owner_epoch: int,
        timestamp: TransitionTimestamp,
    ) -> bool:
        del owner_epoch, timestamp
        if item.schedule_entry_id in self.consumed:
            return False
        self.consumed.add(item.schedule_entry_id)
        self.consume_order.append(item.schedule_entry_id)
        return True


def _clock() -> RuntimeClock:
    return RuntimeClock(
        ClockPolicy(ClockMode.REAL),
        wall_now=lambda: WALL_TIME,
        monotonic_now=lambda: 207_000,
    )


def _operator_directive(
    verdict: OperatorVerdict,
    *,
    signed: bool,
    reason: str = "operator supplied correlated evidence",
) -> OperatorDecisionDirective:
    return OperatorDecisionDirective(
        attempt_id=ATTEMPT_ID,
        verdict=verdict,
        reason=reason,
        operator_identity_fingerprint=DIGEST,
        operator_input_digest=DIGEST,
        evidence=(RecoveryEvidenceReference("record", _planned("record_", 1)),),
        signed_policy_verified=signed,
    )


def test_default_policy_stops_offline_with_ambiguity_and_exit_four(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _unknown_attempt()
    context = _policy_context(original)
    factory = _RecordingIdFactory([NEXT_ATTEMPT_ID])
    engine = ResumePolicyEngine(fresh_attempt_id=factory)
    pending = (
        _schedule_item(1),
        _schedule_item(2, scenario=1, delivery=1),
    )
    monkeypatch.setattr(socket, "socket", _forbid_network)

    plan = engine.build_plan(
        context,
        bundle_policy=BundleRecoveryPolicy(),
        invocation=ResumeInvocationPolicy(),
        schedule=PersistedScheduleSnapshot(pending),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.requested_policy is None
    assert plan.effective_policy is AmbiguityPolicy.STOP
    assert plan.disposition is ResumeDisposition.STOP_AMBIGUOUS
    assert plan.result_category is ResultCategory.AMBIGUOUS
    assert plan.exit_code is ExitCode.AMBIGUOUS
    assert plan.runnable_schedule == ()
    assert plan.deferred_schedule == tuple(sorted(pending, key=lambda item: item.order_key))
    assert not plan.delivery_execution_allowed
    assert not plan.observer_contact_allowed
    assert plan.performs_io is False
    assert factory.calls == 0
    assert context.recovery_plan.attempts == (original,)


@pytest.mark.anyio
async def test_default_stop_commit_is_idempotent_and_never_mutates_unknown() -> None:
    original = _unknown_attempt()
    context = _policy_context(original)
    engine = ResumePolicyEngine()
    plan = engine.build_plan(
        context,
        bundle_policy=BundleRecoveryPolicy(),
        invocation=ResumeInvocationPolicy(),
        schedule=PersistedScheduleSnapshot(()),
        timestamp=LIVE_TIMESTAMP,
    )
    journal = _MemoryPolicyJournal(physical_attempts={ATTEMPT_ID: AttemptState.UNKNOWN_OUTCOME})

    first = await engine.apply(plan, journal=journal)
    replay = await engine.apply(plan, journal=journal)

    assert first.commit_attempted
    assert first.newly_committed
    assert replay.idempotent_replay
    assert journal.calls == PAIR_COUNT
    assert journal.physical_attempts == {ATTEMPT_ID: AttemptState.UNKNOWN_OUTCOME}
    assert len(journal.committed) == 1


@pytest.mark.parametrize(
    ("bundle", "invocation"),
    [
        (_redelivery_bundle(), ResumeInvocationPolicy()),
        (
            BundleRecoveryPolicy(),
            ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
        ),
    ],
    ids=["config-only", "invocation-only"],
)
def test_one_sided_redelivery_consent_is_insufficient(
    bundle: BundleRecoveryPolicy,
    invocation: ResumeInvocationPolicy,
) -> None:
    factory = _RecordingIdFactory([NEXT_ATTEMPT_ID])
    plan = ResumePolicyEngine(fresh_attempt_id=factory).build_plan(
        _policy_context(_unknown_attempt()),
        bundle_policy=bundle,
        invocation=invocation,
        schedule=PersistedScheduleSnapshot((_schedule_item(1),)),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.effective_policy is AmbiguityPolicy.STOP
    assert plan.disposition is ResumeDisposition.STOP_AMBIGUOUS
    assert plan.exit_code is ExitCode.AMBIGUOUS
    assert plan.redeliveries == ()
    assert plan.runnable_schedule == ()
    assert factory.calls == 0


@pytest.mark.anyio
async def test_dual_consent_creates_distinct_next_ordinal_attempt_plan() -> None:
    original = _unknown_attempt(ordinal=1)
    context = _policy_context(original)
    factory = _RecordingIdFactory([NEXT_ATTEMPT_ID])
    engine = ResumePolicyEngine(fresh_attempt_id=factory)
    implicit_linked = _schedule_item(1, attempt=2)
    unrelated = _schedule_item(2, scenario=1, delivery=1, attempt=0)

    plan = engine.build_plan(
        context,
        bundle_policy=_redelivery_bundle(original),
        invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
        schedule=PersistedScheduleSnapshot((implicit_linked, unrelated)),
        timestamp=LIVE_TIMESTAMP,
    )

    assert factory.calls == 1
    assert plan.effective_policy is AmbiguityPolicy.REDELIVER
    assert plan.disposition is ResumeDisposition.CONTINUE
    assert plan.result_category is None
    assert len(plan.redeliveries) == 1
    redelivery = plan.redeliveries[0]
    assert redelivery.predecessor_attempt_id == ATTEMPT_ID
    assert redelivery.attempt_id == NEXT_ATTEMPT_ID
    assert redelivery.attempt_id != ATTEMPT_ID
    assert original.attempt_ordinal == FIRST_ATTEMPT_ORDINAL
    assert redelivery.attempt_ordinal == NEXT_ATTEMPT_ORDINAL
    assert redelivery.attempt_ordinal == original.attempt_ordinal + 1
    assert b'"attempt_ordinal":' not in redelivery.condition_json
    encoded_ordinal = str(NEXT_ATTEMPT_ORDINAL).encode("ascii")
    assert b'"next_attempt_ordinal":' + encoded_ordinal in redelivery.condition_json
    repository_module._validate_retry_condition(  # pyright: ignore[reportPrivateUsage]
        redelivery.condition_json,
        predecessor_attempt_id=original.attempt_id,
        next_attempt_ordinal=redelivery.attempt_ordinal,
    )
    assert redelivery.scenario_id == original.scenario_id
    assert redelivery.event_id == original.event_id
    assert redelivery.delivery_id == original.delivery_id
    assert redelivery.attempt_plan_id == ATTEMPT_PLAN_ID
    assert implicit_linked in plan.deferred_schedule
    assert implicit_linked not in plan.runnable_schedule
    assert unrelated in plan.runnable_schedule
    assert redelivery.schedule_item in plan.runnable_schedule
    assert plan.decisions[0].decision is RecoveryDecisionKind.REDELIVERY_CREATED
    journal = _MemoryPolicyJournal(physical_attempts={ATTEMPT_ID: AttemptState.UNKNOWN_OUTCOME})

    first = await engine.apply(plan, journal=journal)
    replay = await engine.apply(plan, journal=journal)

    assert first.newly_committed
    assert replay.idempotent_replay
    assert journal.physical_attempts[ATTEMPT_ID] is AttemptState.UNKNOWN_OUTCOME
    assert journal.physical_attempts[NEXT_ATTEMPT_ID] is AttemptState.SCHEDULED
    assert len(journal.schedules) == 1
    assert context.recovery_plan.attempts == (original,)


def test_phase_dependent_nonterminal_ambiguity_cannot_be_redelivered() -> None:
    ambiguous = _phase_ambiguous_attempt()
    factory = _RecordingIdFactory([NEXT_ATTEMPT_ID])

    plan = ResumePolicyEngine(fresh_attempt_id=factory).build_plan(
        _policy_context(ambiguous),
        bundle_policy=_redelivery_bundle(ambiguous),
        invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
        schedule=PersistedScheduleSnapshot(()),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.effective_policy is AmbiguityPolicy.STOP
    assert plan.exit_code is ExitCode.AMBIGUOUS
    assert plan.redeliveries == ()
    assert factory.calls == 0


@pytest.mark.parametrize(
    ("read_only", "idempotent"),
    [(False, False), (False, True), (True, False)],
)
def test_observe_requires_safe_automatic_capabilities(
    read_only: bool,  # noqa: FBT001
    idempotent: bool,  # noqa: FBT001
) -> None:
    plan = ResumePolicyEngine().build_plan(
        _policy_context(_unknown_attempt()),
        bundle_policy=_observation_bundle(
            read_only=read_only,
            idempotent=idempotent,
        ),
        invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.OBSERVE),
        schedule=PersistedScheduleSnapshot((_schedule_item(1),)),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.effective_policy is AmbiguityPolicy.STOP
    assert plan.result_category is ResultCategory.AMBIGUOUS
    assert plan.observations == ()
    assert not plan.observer_contact_allowed


def test_observe_builds_only_a_read_only_decisive_reconciliation_plan() -> None:
    plan = ResumePolicyEngine().build_plan(
        _policy_context(_unknown_attempt()),
        bundle_policy=_observation_bundle(),
        invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.OBSERVE),
        schedule=PersistedScheduleSnapshot((_schedule_item(1),)),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.effective_policy is AmbiguityPolicy.OBSERVE
    assert plan.disposition is ResumeDisposition.AWAIT_OBSERVATION
    assert plan.result_category is None
    assert plan.runnable_schedule == ()
    assert len(plan.observations) == 1
    assert plan.observations[0].observation_id == OBSERVATION_ID
    assert plan.observations[0].assertion_ids == (ASSERTION_ID,)
    assert plan.observer_contact_allowed
    assert not plan.delivery_execution_allowed
    assert plan.decisions[0].decision is RecoveryDecisionKind.OBSERVATION_REQUESTED


def test_noninteractive_operator_decision_requires_verified_signed_policy() -> None:
    plan = ResumePolicyEngine().build_plan(
        _policy_context(_unknown_attempt()),
        bundle_policy=BundleRecoveryPolicy(),
        invocation=ResumeInvocationPolicy(
            on_ambiguous=AmbiguityPolicy.OPERATOR_DECISION,
            noninteractive=True,
            operator_decisions=(_operator_directive(OperatorVerdict.PROCESSED, signed=False),),
        ),
        schedule=PersistedScheduleSnapshot((_schedule_item(1),)),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.effective_policy is AmbiguityPolicy.STOP
    assert plan.exit_code is ExitCode.AMBIGUOUS
    assert plan.runnable_schedule == ()
    assert plan.decisions[0].decision is RecoveryDecisionKind.STOPPED_AMBIGUOUS


@pytest.mark.parametrize(
    ("verdict", "expected_kind", "expected_disposition"),
    [
        (
            OperatorVerdict.PROCESSED,
            RecoveryDecisionKind.OPERATOR_PROCESSED,
            ResumeDisposition.CONTINUE,
        ),
        (
            OperatorVerdict.NOT_PROCESSED,
            RecoveryDecisionKind.OPERATOR_NOT_PROCESSED,
            ResumeDisposition.CONTINUE,
        ),
        (
            OperatorVerdict.STILL_UNKNOWN,
            RecoveryDecisionKind.OPERATOR_STILL_UNKNOWN,
            ResumeDisposition.STOP_AMBIGUOUS,
        ),
    ],
)
def test_signed_operator_decisions_preserve_attempt_and_never_resend(
    verdict: OperatorVerdict,
    expected_kind: RecoveryDecisionKind,
    expected_disposition: ResumeDisposition,
) -> None:
    original = _unknown_attempt()
    unrelated = _schedule_item(2, scenario=1, delivery=1, attempt=0)
    linked = _schedule_item(1)
    plan = ResumePolicyEngine().build_plan(
        _policy_context(original),
        bundle_policy=BundleRecoveryPolicy(),
        invocation=ResumeInvocationPolicy(
            on_ambiguous=AmbiguityPolicy.OPERATOR_DECISION,
            noninteractive=True,
            operator_decisions=(_operator_directive(verdict, signed=True),),
        ),
        schedule=PersistedScheduleSnapshot((linked, unrelated)),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.effective_policy is AmbiguityPolicy.OPERATOR_DECISION
    assert plan.disposition is expected_disposition
    assert plan.decisions[0].decision is expected_kind
    assert plan.redeliveries == ()
    assert linked not in plan.runnable_schedule
    if verdict is OperatorVerdict.STILL_UNKNOWN:
        assert plan.result_category is ResultCategory.AMBIGUOUS
        assert plan.exit_code is ExitCode.AMBIGUOUS
        assert plan.runnable_schedule == ()
    else:
        assert plan.result_category is None
        assert plan.runnable_schedule == (unrelated,)
    assert original.prior_state is AttemptState.UNKNOWN_OUTCOME


def test_operator_reason_is_hidden_from_plan_repr() -> None:
    directive = _operator_directive(
        OperatorVerdict.PROCESSED,
        signed=True,
        reason=CANARY_TEXT,
    )
    plan = ResumePolicyEngine().build_plan(
        _policy_context(_unknown_attempt()),
        bundle_policy=BundleRecoveryPolicy(),
        invocation=ResumeInvocationPolicy(
            on_ambiguous=AmbiguityPolicy.OPERATOR_DECISION,
            operator_decisions=(directive,),
        ),
        schedule=PersistedScheduleSnapshot(()),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.decisions[0].reason == CANARY_TEXT
    assert CANARY_TEXT not in repr(directive)
    assert CANARY_TEXT not in repr(plan)


@pytest.mark.anyio
async def test_due_schedule_reconstructs_and_leases_each_persisted_item_once() -> None:
    first = _schedule_item(1, due=0)
    consumed = _schedule_item(2, due=0)
    later = _schedule_item(3, scenario=1, delivery=1, due=5)
    snapshot = PersistedScheduleSnapshot(
        (later, consumed, first),
        consumed_entry_ids=frozenset({consumed.schedule_entry_id}),
    )
    engine = ResumePolicyEngine()
    plan = engine.build_plan(
        _policy_context(_scheduled_attempt()),
        bundle_policy=BundleRecoveryPolicy(),
        invocation=ResumeInvocationPolicy(),
        schedule=snapshot,
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.runnable_schedule == (first, later)
    assert engine.due_schedule(plan, 10, limit=10) == (first, later)
    assert engine.due_schedule(plan, 10, limit=10) == (first, later)
    queue = engine.reconstruct_queue(plan)
    journal = _MemoryScheduleJournal(
        entries={item.schedule_entry_id: item for item in plan.runnable_schedule}
    )
    scheduler = PersistentScheduler(
        queue,
        journal=journal,
        clock=_clock(),
        owner_epoch=OWNER_EPOCH,
    )
    leases: list[WorkLease] = []
    for _index in range(3):
        leases.extend(await scheduler.lease_due(10))

    assert tuple(lease.item for lease in leases) == (first, later)
    assert len(journal.consume_order) == len(set(journal.consume_order)) == PAIR_COUNT
    resumed = PersistentPriorityQueue.reconstruct(
        plan.runnable_schedule,
        consumed_entry_ids=frozenset(journal.consumed),
    )
    assert resumed.snapshot() == ()


def test_cancellation_without_ambiguity_returns_130_and_schedules_nothing() -> None:
    plan = ResumePolicyEngine().build_plan(
        _policy_context(_scheduled_attempt()),
        bundle_policy=BundleRecoveryPolicy(),
        invocation=ResumeInvocationPolicy(cancel_requested=True),
        schedule=PersistedScheduleSnapshot((_schedule_item(1),)),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.disposition is ResumeDisposition.CANCELLED
    assert plan.result_category is ResultCategory.CANCELLED
    assert plan.exit_code is ExitCode.CANCELLED
    assert plan.runnable_schedule == ()
    assert not plan.requires_journal_commit


def test_ambiguity_has_stronger_precedence_than_cancellation() -> None:
    plan = ResumePolicyEngine().build_plan(
        _policy_context(_unknown_attempt()),
        bundle_policy=_redelivery_bundle(),
        invocation=ResumeInvocationPolicy(
            on_ambiguous=AmbiguityPolicy.REDELIVER,
            cancel_requested=True,
        ),
        schedule=PersistedScheduleSnapshot((_schedule_item(1),)),
        timestamp=LIVE_TIMESTAMP,
    )

    assert plan.disposition is ResumeDisposition.STOP_AMBIGUOUS
    assert plan.result_category is ResultCategory.AMBIGUOUS
    assert plan.exit_code is ExitCode.AMBIGUOUS
    assert plan.redeliveries == ()


@pytest.mark.anyio
async def test_cancellation_during_atomic_policy_commit_exposes_no_partial_state() -> None:
    entered = anyio.Event()

    @dataclass(slots=True)
    class _BlockingJournal(AtomicResumePolicyJournal):
        committed: bool = False

        async def commit_policy(self, plan: ResumePolicyPlan) -> bool:
            del plan
            entered.set()
            await anyio.sleep_forever()
            self.committed = True
            return True

    engine = ResumePolicyEngine(fresh_attempt_id=_RecordingIdFactory([NEXT_ATTEMPT_ID]))
    plan = engine.build_plan(
        _policy_context(_unknown_attempt()),
        bundle_policy=_redelivery_bundle(),
        invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
        schedule=PersistedScheduleSnapshot(()),
        timestamp=LIVE_TIMESTAMP,
    )
    journal = _BlockingJournal()

    async def apply_policy() -> None:
        await engine.apply(plan, journal=journal)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(apply_policy)
        await entered.wait()
        tasks.cancel_scope.cancel()

    assert not journal.committed


def test_fresh_attempt_factory_collision_fails_closed() -> None:
    engine = ResumePolicyEngine(fresh_attempt_id=_RecordingIdFactory([ATTEMPT_ID]))

    with pytest.raises(
        ResumePolicyIntegrityError,
        match="collides",
    ):
        engine.build_plan(
            _policy_context(_unknown_attempt()),
            bundle_policy=_redelivery_bundle(),
            invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
            schedule=PersistedScheduleSnapshot(()),
            timestamp=LIVE_TIMESTAMP,
        )


def test_redelivery_ordinal_overflow_fails_before_persistence() -> None:
    original = _unknown_attempt(ordinal=MAX_SAFE_INTEGER)
    engine = ResumePolicyEngine(fresh_attempt_id=_RecordingIdFactory([NEXT_ATTEMPT_ID]))

    with pytest.raises(ResumePolicyResourceLimitError):
        engine.build_plan(
            _policy_context(original),
            bundle_policy=_redelivery_bundle(original),
            invocation=ResumeInvocationPolicy(on_ambiguous=AmbiguityPolicy.REDELIVER),
            schedule=PersistedScheduleSnapshot(()),
            timestamp=LIVE_TIMESTAMP,
        )


def test_schedule_snapshot_integrity_and_resource_caps_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _schedule_item(1)
    second = _schedule_item(2)
    with pytest.raises(ResumePolicyIntegrityError, match="absent"):
        PersistedScheduleSnapshot(
            (first,),
            consumed_entry_ids=frozenset({second.schedule_entry_id}),
        )

    monkeypatch.setattr(policy_module, "MAX_POLICY_ITEMS", 1)
    with pytest.raises(ResumePolicyResourceLimitError):
        PersistedScheduleSnapshot((first, second))
    template = _redelivery_bundle().redelivery_templates[0]
    with pytest.raises(ResumePolicyResourceLimitError):
        BundleRecoveryPolicy(redelivery_templates=(template, template))


def test_policy_context_requires_matching_verified_owner_epoch() -> None:
    with pytest.raises(ResumePolicyIntegrityError, match="disagree"):
        _policy_context(
            _unknown_attempt(),
            plan_owner_epoch=OWNER_EPOCH + 1,
        )

    error = ResumePolicyIntegrityError("integrity failed")
    assert error.result_category is ResultCategory.HARNESS_ERROR
    assert error.exit_code is ExitCode.HARNESS_FAILURE


@pytest.mark.parametrize("failure_kind", ["corrupt", "foreign-key"])
def test_integrity_failure_preserves_database_and_precedes_policy(
    tmp_path: Path,
    failure_kind: str,
) -> None:
    run = create_run_database(tmp_path, run_id=RUN_ID)
    if failure_kind == "corrupt":
        raw = run.database_path.read_bytes()
        run.database_path.write_bytes(b"not-a-sqlite-db!" + raw[16:])
    else:
        connection = sqlite3.connect(run.database_path)
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                """
                INSERT INTO scenarios (
                    scenario_id, run_id, ordinal, name, state
                ) VALUES (?, ?, 0, 'orphan', 'pending')
                """,
                (SCENARIO_ID, RUN_ID),
            )
            connection.commit()
        finally:
            connection.close()
    before = run.database_path.read_bytes()
    factory = _RecordingIdFactory([NEXT_ATTEMPT_ID])

    with pytest.raises(ResumeIntegrityError) as captured:
        verify_resume_integrity(run.database_path)

    assert captured.value.result_category is ResultCategory.HARNESS_ERROR
    assert exit_for_result(captured.value.result_category)[1] is ExitCode.HARNESS_FAILURE
    assert run.database_path.read_bytes() == before
    assert factory.calls == 0


@pytest.mark.anyio
async def test_noop_plan_does_not_call_journal() -> None:
    engine = ResumePolicyEngine()
    plan = engine.build_plan(
        _policy_context(_scheduled_attempt()),
        bundle_policy=BundleRecoveryPolicy(),
        invocation=ResumeInvocationPolicy(),
        schedule=PersistedScheduleSnapshot(()),
        timestamp=LIVE_TIMESTAMP,
    )
    journal = _MemoryPolicyJournal()

    applied = await engine.apply(plan, journal=journal)

    assert not applied.commit_attempted
    assert not applied.newly_committed
    assert journal.calls == 0


def _forbid_network(*_args: object, **_kwargs: object) -> None:
    message = "default resume policy attempted receiver contact"
    raise AssertionError(message)
