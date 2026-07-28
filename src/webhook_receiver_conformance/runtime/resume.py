"""Production orchestration for conservative local run resume."""
# ruff: noqa: D105, D107, EM101, INP001, PLR0913, TRY003

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import anyio
from anyio.to_thread import run_sync

from webhook_receiver_conformance.errors import (
    ErrorCategory,
    ExitCode,
    ResultCategory,
    exit_for_result,
)
from webhook_receiver_conformance.journal.resume import (
    ResumeJournalPreflight,
    ResumePolicyJournal,
    advance_resume_owner_epoch,
    load_resume_schedule,
    preflight_resume_journal,
)
from webhook_receiver_conformance.journal.run_lock import (
    FilesystemProbe,
    ProcessInspector,
    RunLockTakeoverEvent,
    acquire_run_lock,
)
from webhook_receiver_conformance.journal.service import JournalService
from webhook_receiver_conformance.recovery.models import (
    RecoveryPlan,
    RecoveryScanContext,
)
from webhook_receiver_conformance.recovery.policy import (
    BundleRecoveryPolicy,
    ObservationReconciliationPlan,
    PolicyApplication,
    RedeliveryAttemptPlan,
    ResumeDisposition,
    ResumeInvocationPolicy,
    ResumePolicyContext,
    ResumePolicyEngine,
    ResumePolicyPlan,
)
from webhook_receiver_conformance.recovery.scanner import RecoveryScanner
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
)
from webhook_receiver_conformance.types import DiagnosticCode

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from webhook_receiver_conformance.journal.run_lock import UtcClock
    from webhook_receiver_conformance.journal.transitions import (
        CommittedTransition,
    )


class ResumeRuntimeError(RuntimeError):
    """A classified runtime resume orchestration failure."""

    category: ErrorCategory = ErrorCategory.INTEGRITY_ERROR
    result_category: ResultCategory = ResultCategory.HARNESS_ERROR
    exit_code: ExitCode = ExitCode.HARNESS_FAILURE
    code: DiagnosticCode = DiagnosticCode("RUNTIME_RESUME_ERROR")


class ResumeCallbackRequiredError(ResumeRuntimeError):
    """An explicit external-effect policy lacks its injected callback."""

    category = ErrorCategory.CONFIGURATION_ERROR
    result_category = ResultCategory.INVALID_INPUT
    exit_code = ExitCode.INVALID_INPUT
    code = DiagnosticCode("RUNTIME_RESUME_CALLBACK_REQUIRED")


class ResumeStatus(StrEnum):
    """Closed high-level outcomes from one resume orchestration."""

    AMBIGUOUS_READ_ONLY = "ambiguous_read_only"
    CONTINUE = "continue"
    AWAIT_OBSERVATION = "await_observation"
    STOP_AMBIGUOUS = "stop_ambiguous"
    CANCELLED = "cancelled"


class RedeliveryCallback(Protocol):
    """Explicit async boundary that may execute one committed redelivery."""

    def __call__(
        self,
        plan: RedeliveryAttemptPlan,
    ) -> Awaitable[None]:
        """Execute or enqueue one already committed redelivery plan."""
        ...


class ObservationCallback(Protocol):
    """Explicit async boundary that may perform one planned observation."""

    def __call__(
        self,
        plan: ObservationReconciliationPlan,
    ) -> Awaitable[None]:
        """Perform one already committed read-only reconciliation request."""
        ...


@dataclass(frozen=True, slots=True)
class ResumeRequest:
    """Validated inputs for one local resume invocation."""

    run_directory: Path
    invocation: ResumeInvocationPolicy = field(default_factory=ResumeInvocationPolicy)
    bundle_policy: BundleRecoveryPolicy = field(default_factory=BundleRecoveryPolicy)
    take_over: bool = True

    def __post_init__(self) -> None:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.run_directory,
            Path,
        ):
            raise TypeError("run_directory must be a Path")
        if type(self.invocation) is not ResumeInvocationPolicy:
            raise TypeError("invocation must be a ResumeInvocationPolicy")
        if type(self.bundle_policy) is not BundleRecoveryPolicy:
            raise TypeError("bundle_policy must be a BundleRecoveryPolicy")
        if type(self.take_over) is not bool:
            raise TypeError("take_over must be a boolean")


@dataclass(frozen=True, slots=True)
class ResumeResult:
    """Typed, evidence-bearing result for CLI and direct runtime integration."""

    status: ResumeStatus
    run_id: str
    owner_epoch: int
    result_category: ResultCategory | None
    exit_code: ExitCode | None
    read_only: bool
    preflight: ResumeJournalPreflight
    ambiguous_attempt_ids: tuple[str, ...]
    recovery_plan: RecoveryPlan | None
    policy_plan: ResumePolicyPlan | None
    policy_application: PolicyApplication | None
    automatic_transitions: tuple[CommittedTransition, ...]
    takeover_event: RunLockTakeoverEvent | None
    redeliveries_invoked: int
    observations_invoked: int

    @property
    def receiver_contact_possible(self) -> bool:
        """Return whether an injected redelivery callback was invoked."""
        return self.redeliveries_invoked > 0

    @property
    def observer_contact_possible(self) -> bool:
        """Return whether an injected observation callback was invoked."""
        return self.observations_invoked > 0


class ResumeService:
    """Verify, take ownership, recover, apply policy, then invoke explicit effects."""

    __slots__ = (
        "_clock",
        "_filesystem_probe",
        "_hostname",
        "_lock_clock",
        "_observation",
        "_policy_engine",
        "_process_inspector",
        "_redelivery",
    )

    def __init__(
        self,
        *,
        clock: RuntimeClock | None = None,
        policy_engine: ResumePolicyEngine | None = None,
        redelivery: RedeliveryCallback | None = None,
        observation: ObservationCallback | None = None,
        filesystem_probe: FilesystemProbe | None = None,
        process_inspector: ProcessInspector | None = None,
        lock_clock: UtcClock | None = None,
        hostname: str | None = None,
    ) -> None:
        self._clock = RuntimeClock(ClockPolicy(ClockMode.REAL)) if clock is None else clock
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self._clock,
            RuntimeClock,
        ):
            raise TypeError("clock must be a RuntimeClock")
        self._policy_engine = ResumePolicyEngine() if policy_engine is None else policy_engine
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self._policy_engine,
            ResumePolicyEngine,
        ):
            raise TypeError("policy_engine must be a ResumePolicyEngine")
        if redelivery is not None and not callable(redelivery):
            raise TypeError("redelivery must be an async callable")
        if observation is not None and not callable(observation):
            raise TypeError("observation must be an async callable")
        self._redelivery = redelivery
        self._observation = observation
        self._filesystem_probe = filesystem_probe
        self._process_inspector = process_inspector
        self._lock_clock = lock_clock
        self._hostname = hostname

    async def resume(self, request: ResumeRequest) -> ResumeResult:
        """Run one structured resume without implicit network or observer work."""
        if type(request) is not ResumeRequest:
            raise TypeError("request must be a ResumeRequest")
        preflight = await run_sync(
            partial(
                preflight_resume_journal,
                request.run_directory,
            )
        )
        if request.invocation.on_ambiguous is None and preflight.contains_ambiguity:
            return _read_only_ambiguous_result(preflight)
        fresh_epoch = preflight.owner_epoch + 1
        lock = acquire_run_lock(
            preflight.run_directory,
            run_id=preflight.run_id,
            owner_epoch=fresh_epoch,
            take_over=request.take_over,
            filesystem_probe=self._filesystem_probe,
            process_inspector=self._process_inspector,
            clock=self._lock_clock,
            hostname=self._hostname,
        )
        with lock:
            async with JournalService.open(preflight.database_path) as service:
                await advance_resume_owner_epoch(
                    service,
                    run_id=preflight.run_id,
                    previous_owner_epoch=preflight.owner_epoch,
                    new_owner_epoch=fresh_epoch,
                )
                scan_context = RecoveryScanContext(
                    run_id=preflight.run_id,
                    owner_epoch=fresh_epoch,
                    integrity=preflight.integrity,
                    owner=lock.metadata,
                )
                scanner = RecoveryScanner(service, scan_context)
                recovery_plan = await scanner.scan()
                timestamp = self._clock.transition_timestamp()
                automatic = await scanner.apply(
                    recovery_plan,
                    timestamp=timestamp,
                )
                schedule = await load_resume_schedule(
                    service,
                    run_id=preflight.run_id,
                    owner_epoch=fresh_epoch,
                )
                policy_plan = self._policy_engine.build_plan(
                    ResumePolicyContext(
                        scan_context=scan_context,
                        recovery_plan=recovery_plan,
                    ),
                    bundle_policy=request.bundle_policy,
                    invocation=request.invocation,
                    schedule=schedule,
                    timestamp=timestamp,
                )
                self._require_callbacks(policy_plan)
                application = await self._policy_engine.apply(
                    policy_plan,
                    journal=ResumePolicyJournal(service),
                )
                redeliveries_invoked = await _invoke_redeliveries(
                    policy_plan,
                    callback=self._redelivery,
                )
                observations_invoked = await _invoke_observations(
                    policy_plan,
                    callback=self._observation,
                )
                return ResumeResult(
                    status=_status(policy_plan.disposition),
                    run_id=preflight.run_id,
                    owner_epoch=fresh_epoch,
                    result_category=policy_plan.result_category,
                    exit_code=policy_plan.exit_code,
                    read_only=False,
                    preflight=preflight,
                    ambiguous_attempt_ids=policy_plan.ambiguous_attempt_ids,
                    recovery_plan=recovery_plan,
                    policy_plan=policy_plan,
                    policy_application=application,
                    automatic_transitions=automatic,
                    takeover_event=lock.takeover_event,
                    redeliveries_invoked=redeliveries_invoked,
                    observations_invoked=observations_invoked,
                )

    def _require_callbacks(self, plan: ResumePolicyPlan) -> None:
        if plan.redeliveries and self._redelivery is None:
            raise ResumeCallbackRequiredError(
                "explicit redelivery policy requires an injected async callback"
            )
        if plan.observations and self._observation is None:
            raise ResumeCallbackRequiredError(
                "explicit observe policy requires an injected async callback"
            )


async def resume_run(
    request: ResumeRequest,
    *,
    clock: RuntimeClock | None = None,
    policy_engine: ResumePolicyEngine | None = None,
    redelivery: RedeliveryCallback | None = None,
    observation: ObservationCallback | None = None,
) -> ResumeResult:
    """Async convenience API for the production resume service."""
    return await ResumeService(
        clock=clock,
        policy_engine=policy_engine,
        redelivery=redelivery,
        observation=observation,
    ).resume(request)


def resume_run_sync(
    request: ResumeRequest,
    *,
    clock: RuntimeClock | None = None,
    policy_engine: ResumePolicyEngine | None = None,
    redelivery: RedeliveryCallback | None = None,
    observation: ObservationCallback | None = None,
) -> ResumeResult:
    """Run the resume service synchronously for CLI entry points."""
    return anyio.run(
        partial(
            resume_run,
            request,
            clock=clock,
            policy_engine=policy_engine,
            redelivery=redelivery,
            observation=observation,
        )
    )


def _read_only_ambiguous_result(
    preflight: ResumeJournalPreflight,
) -> ResumeResult:
    result = ResultCategory.AMBIGUOUS
    return ResumeResult(
        status=ResumeStatus.AMBIGUOUS_READ_ONLY,
        run_id=preflight.run_id,
        owner_epoch=preflight.owner_epoch,
        result_category=result,
        exit_code=exit_for_result(result)[1],
        read_only=True,
        preflight=preflight,
        ambiguous_attempt_ids=preflight.ambiguous_attempt_ids,
        recovery_plan=None,
        policy_plan=None,
        policy_application=None,
        automatic_transitions=(),
        takeover_event=None,
        redeliveries_invoked=0,
        observations_invoked=0,
    )


def _status(disposition: ResumeDisposition) -> ResumeStatus:
    return {
        ResumeDisposition.CONTINUE: ResumeStatus.CONTINUE,
        ResumeDisposition.AWAIT_OBSERVATION: (ResumeStatus.AWAIT_OBSERVATION),
        ResumeDisposition.STOP_AMBIGUOUS: ResumeStatus.STOP_AMBIGUOUS,
        ResumeDisposition.CANCELLED: ResumeStatus.CANCELLED,
    }[disposition]


async def _invoke_redeliveries(
    plan: ResumePolicyPlan,
    *,
    callback: RedeliveryCallback | None,
) -> int:
    if callback is None:
        return 0
    for redelivery in plan.redeliveries:
        await callback(redelivery)
    return len(plan.redeliveries)


async def _invoke_observations(
    plan: ResumePolicyPlan,
    *,
    callback: ObservationCallback | None,
) -> int:
    if callback is None:
        return 0
    for observation in plan.observations:
        await callback(observation)
    return len(plan.observations)
