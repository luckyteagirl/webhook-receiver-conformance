"""Minimum durable vertical slice for one local webhook delivery."""
# ruff: noqa: D105, D107, EM101, INP001, PLR0913, TRY003

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from anyio import CancelScope
from anyio.to_thread import run_sync

from webhook_receiver_conformance.assertions.transport import (
    TransportAssertionInput,
)
from webhook_receiver_conformance.config.models import (
    AcknowledgementDeadlineAssertion,
    HttpStatusAssertion,
    ProjectConfig,
)
from webhook_receiver_conformance.domain.enums import (
    AssertionState,
    AttemptClassification,
    AttemptState,
    DeliveryState,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    new_fresh_id,
    validate_fresh_id,
    validate_run_id,
)
from webhook_receiver_conformance.domain.models import (
    AggregateRunOutcome,
    ArtifactPaths,
    ResultCounts,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory
from webhook_receiver_conformance.http.evidence import HeaderOwner
from webhook_receiver_conformance.http.executor import (
    HttpAttemptCommand,
    HttpAttemptExecutor,
    HttpHeader,
    HttpLimits,
    HttpTimeouts,
)
from webhook_receiver_conformance.journal.bootstrap import (
    JournalBootstrapRequest,
    JournalCompletionRequest,
    SeededAttempt,
)
from webhook_receiver_conformance.journal.repositories import (
    AssertionEvidenceKind,
    AssertionEvidenceReference,
    AssertionRepository,
    TransitionRepository,
)
from webhook_receiver_conformance.journal.run_lock import acquire_run_lock
from webhook_receiver_conformance.journal.schema import create_run_database
from webhook_receiver_conformance.journal.service import JournalService
from webhook_receiver_conformance.journal.transitions import (
    AttemptScheduleClaim,
    EntityType,
    LifecycleState,
    TransitionCommand,
)
from webhook_receiver_conformance.manifest.compiler import (
    CompiledRunBundle,
    RealizedDeliveryExecution,
    compile_run_bundle,
)
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.policy import parse_destination_policy
from webhook_receiver_conformance.network.transport import (
    AnyIOConnector,
    AnyIOResolver,
)
from webhook_receiver_conformance.reporting.json_reports import (
    AssertionReportRecord,
    DeliveryReportRecord,
    JsonReportArtifacts,
    render_json_reports,
)
from webhook_receiver_conformance.runtime.assertions import (
    AssertionEvidenceBundle,
    AssertionLifecycle,
    AssertionRuntimeContext,
)
from webhook_receiver_conformance.runtime.attempts import (
    AttemptLifecycle,
    AttemptRuntimeContext,
)
from webhook_receiver_conformance.runtime.verdicts import (
    classify_attempt_verdict,
    reduce_terminal_verdicts,
)
from webhook_receiver_conformance.scheduler.clocks import RuntimeClock, TransitionTimestamp
from webhook_receiver_conformance.signatures.base import Signer

if TYPE_CHECKING:
    from datetime import datetime

type ExecutorFactory = Callable[[ProjectConfig, RuntimeClock], HttpAttemptExecutor]
_MANIFEST_ID_LENGTH = 64


class JournalLifecycle(Protocol):
    """Repository-owned bootstrap and completion boundary used by the runner."""

    async def initialize(
        self,
        service: JournalService,
        request: JournalBootstrapRequest,
    ) -> SeededAttempt:
        """Seed verified manifest projections and the initial schedule."""
        ...

    async def finalize(
        self,
        service: JournalService,
        request: JournalCompletionRequest,
    ) -> None:
        """Atomically reduce terminal projections and persist the result."""
        ...


@dataclass(frozen=True, slots=True)
class VerticalSliceRunRequest:
    """Resolved, secret-safe inputs for one fresh local execution."""

    config: ProjectConfig
    project_root: Path
    artifact_directory: Path
    secret_fingerprints: Mapping[str, str]
    signers: Mapping[str, Signer]
    runtime_public_authorization: str | None = None
    owner_epoch: int = 0

    def __post_init__(self) -> None:
        if type(self.config) is not ProjectConfig:
            raise TypeError("config must be a ProjectConfig")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.project_root,
            Path,
        ):
            raise TypeError("project_root must be a Path")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.artifact_directory,
            Path,
        ):
            raise TypeError("artifact_directory must be a Path")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.secret_fingerprints,
            Mapping,
        ):
            raise TypeError("secret_fingerprints must be a mapping")
        if any(
            type(key) is not str or type(value) is not str
            for key, value in self.secret_fingerprints.items()
        ):
            raise TypeError("secret_fingerprints must map strings to strings")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.signers,
            Mapping,
        ):
            raise TypeError("signers must be a mapping")
        if any(
            type(name) is not str
            or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                signer,
                Signer,
            )
            for name, signer in self.signers.items()
        ):
            raise TypeError("signers must map names to Signer implementations")
        if self.runtime_public_authorization is not None and (
            type(self.runtime_public_authorization) is not str
            or not self.runtime_public_authorization
        ):
            raise ValueError("runtime_public_authorization must be nonempty text or None")
        if type(self.owner_epoch) is not int or not 0 <= self.owner_epoch <= (1 << 63) - 1:
            raise ValueError("owner_epoch must be a nonnegative SQLite int64")


@dataclass(frozen=True, slots=True)
class VerticalSliceRunResult:
    """Terminal local paths and classifications from one fresh execution."""

    run_id: str
    manifest_id: str
    run_directory: Path
    database_path: Path
    attempt_id: str
    attempt_state: AttemptState
    classification: AttemptClassification
    result_category: ResultCategory
    exit_code: ExitCode
    summary_path: Path

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        if (
            type(self.manifest_id) is not str
            or len(self.manifest_id) != _MANIFEST_ID_LENGTH
            or any(character not in "0123456789abcdef" for character in self.manifest_id)
        ):
            raise ValueError("manifest_id must be a lowercase SHA-256 identifier")
        for value, name in (
            (self.run_directory, "run_directory"),
            (self.database_path, "database_path"),
            (self.summary_path, "summary_path"),
        ):
            if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                value,
                Path,
            ):
                message = f"{name} must be a Path"
                raise TypeError(message)
        validate_fresh_id(self.attempt_id, expected_kind=FreshIdKind.ATTEMPT)
        if type(self.attempt_state) is not AttemptState:
            raise TypeError("attempt_state must be an AttemptState")
        if type(self.classification) is not AttemptClassification:
            raise TypeError("classification must be an AttemptClassification")
        if type(self.result_category) is not ResultCategory:
            raise TypeError("result_category must be a ResultCategory")
        if type(self.exit_code) is not ExitCode:
            raise TypeError("exit_code must be an ExitCode")


class VerticalSliceRunner:
    """Compose compiler, journal, executor, assertion, and JSON-report seams."""

    __slots__ = ("_executor_factory", "_journal")

    def __init__(
        self,
        *,
        journal: JournalLifecycle,
        executor_factory: ExecutorFactory | None = None,
    ) -> None:
        if not (
            callable(getattr(journal, "initialize", None))
            and callable(getattr(journal, "finalize", None))
        ):
            raise TypeError("journal must implement initialize and finalize")
        if executor_factory is not None and not callable(executor_factory):
            raise TypeError("executor_factory must be callable")
        self._journal = journal
        self._executor_factory = _default_executor if executor_factory is None else executor_factory

    async def run(
        self,
        request: VerticalSliceRunRequest,
    ) -> VerticalSliceRunResult:
        """Execute exactly one manifest delivery with journal-first evidence."""
        if type(request) is not VerticalSliceRunRequest:
            raise TypeError("request must be a VerticalSliceRunRequest")
        _validate_configuration_scope(request.config)
        run = create_run_database(request.artifact_directory)
        clock = RuntimeClock.from_config(request.config.clock)
        with acquire_run_lock(
            run.run_directory,
            run_id=run.run_id,
            owner_epoch=request.owner_epoch,
        ):
            bundle = compile_run_bundle(
                request.config,
                project_root=request.project_root,
                bundle_directory=run.run_directory,
                secret_fingerprints=request.secret_fingerprints,
            )
            recipe, assertion = _vertical_slice(bundle, request.config)
            scenario = bundle.manifest.scenarios[0]
            delivery = scenario.deliveries[0]
            assertion_plan = scenario.assertions[0]
            async with JournalService.open(run.database_path) as service:
                seeded = await self._journal.initialize(
                    service,
                    JournalBootstrapRequest(
                        run_id=run.run_id,
                        owner_epoch=request.owner_epoch,
                        manifest=bundle.manifest,
                        created_at=bundle.manifest.created_at,
                    ),
                )
                repository = TransitionRepository(service)
                await _activate_vertical_slice(
                    repository,
                    clock=clock,
                    run_id=run.run_id,
                    owner_epoch=request.owner_epoch,
                    scenario_id=scenario.scenario_id,
                    delivery_id=delivery.delivery_id,
                    assertion_id=assertion_plan.assertion_id,
                )
                attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
                attempt_context = AttemptRuntimeContext(
                    run_id=run.run_id,
                    scenario_id=scenario.scenario_id,
                    event_id=delivery.event_id,
                    delivery_id=delivery.delivery_id,
                    attempt_id=attempt_id,
                    owner_epoch=request.owner_epoch,
                    logical_time_ns=delivery.logical_time_ns,
                    scenario_ordinal=seeded.scenario_ordinal,
                    step_ordinal=seeded.step_ordinal,
                    delivery_ordinal=seeded.delivery_ordinal,
                    attempt_ordinal=seeded.attempt_ordinal,
                )
                lifecycle = AttemptLifecycle(
                    repository=repository,
                    executor=self._executor_factory(request.config, clock),
                    clock=clock,
                )
                await lifecycle.claim(
                    _attempt_claim(
                        attempt_context,
                        seeded=seeded,
                        attempt_plan_id=seeded.attempt_plan_id,
                        timestamp=clock.transition_timestamp(),
                    )
                )
                blob = _request_blob(bundle, recipe)
                policy = parse_destination_policy(
                    request.config.receiver,
                    runtime_public_authorization=request.runtime_public_authorization,
                )
                signer = _selected_signer(recipe, request.signers)
                realized = await lifecycle.execute_realized(
                    attempt_context,
                    HttpAttemptCommand(
                        policy=policy,
                        body=blob,
                        headers=(
                            HttpHeader(
                                "content-type",
                                recipe.media_type,
                                HeaderOwner.USER,
                            ),
                        ),
                    ),
                    recipe,
                    signer=signer,
                )
                persisted = await repository.attempt_evidence(
                    run.run_id,
                    attempt_id,
                )
                if persisted is None:
                    raise RuntimeError("terminal attempt evidence was not persisted")
                assertion_result = await AssertionLifecycle(
                    repository=AssertionRepository(service),
                    clock=clock,
                ).evaluate(
                    AssertionRuntimeContext(
                        run_id=run.run_id,
                        scenario_id=scenario.scenario_id,
                        assertion_id=assertion_plan.assertion_id,
                        owner_epoch=request.owner_epoch,
                    ),
                    assertion,
                    AssertionEvidenceBundle(
                        payload=TransportAssertionInput(
                            attempt=persisted.attempt,
                            response_headers_elapsed_ns=(persisted.response_headers_elapsed_ns),
                        ),
                        references=(
                            AssertionEvidenceReference(
                                AssertionEvidenceKind.ATTEMPT,
                                attempt_id,
                            ),
                        ),
                    ),
                )
                verdict = reduce_terminal_verdicts(
                    (
                        classify_attempt_verdict(realized.lifecycle.classification).category,
                        assertion_result.normalized.verdict.category,
                    )
                )
                completed_at = clock.wall_now()
                await self._journal.finalize(
                    service,
                    JournalCompletionRequest(
                        run_id=run.run_id,
                        owner_epoch=request.owner_epoch,
                        scenario_id=scenario.scenario_id,
                        event_id=delivery.event_id,
                        delivery_id=delivery.delivery_id,
                        attempt_id=attempt_id,
                        classification=realized.lifecycle.classification,
                        terminal_attempt_state=realized.lifecycle.terminal_state,
                        result_category=verdict.category,
                        completed_at=_canonical_utc(completed_at),
                    ),
                )
                reports = render_json_reports(
                    bundle.manifest,
                    AggregateRunOutcome(
                        run_id=run.run_id,
                        manifest_id=bundle.manifest.manifest_id,
                        generated_at=completed_at,
                        verdict=verdict.category,
                        exit_code=verdict.exit_code,
                        counts=ResultCounts(
                            scenarios=1,
                            attempts=1,
                            observations=0,
                            assertions=1,
                        ),
                        artifacts=ArtifactPaths(
                            manifest="run-manifest.json",
                            deliveries="deliveries.jsonl",
                            observations="observations.jsonl",
                            assertions="assertions.jsonl",
                        ),
                    ),
                    deliveries=(
                        DeliveryReportRecord(
                            record=persisted.attempt,
                            scenario_ordinal=seeded.scenario_ordinal,
                            delivery_ordinal=seeded.delivery_ordinal,
                            attempt_ordinal=seeded.attempt_ordinal,
                        ),
                    ),
                    observations=(),
                    assertions=(
                        AssertionReportRecord(
                            record=assertion_result.committed.evaluation,
                            scenario_ordinal=seeded.scenario_ordinal,
                            assertion_ordinal=0,
                        ),
                    ),
                )
                await _install_json_reports(run.run_directory, reports)
            return VerticalSliceRunResult(
                run_id=run.run_id,
                manifest_id=bundle.manifest.manifest_id,
                run_directory=run.run_directory,
                database_path=run.database_path,
                attempt_id=attempt_id,
                attempt_state=realized.lifecycle.terminal_state,
                classification=realized.lifecycle.classification,
                result_category=verdict.category,
                exit_code=verdict.exit_code,
                summary_path=run.run_directory / "result-summary.json",
            )


def _validate_configuration_scope(config: ProjectConfig) -> None:
    if len(config.fixtures) != 1 or len(config.scenarios) != 1:
        raise ValueError("the first-run vertical slice requires one fixture and one scenario")
    scenario = config.scenarios[0]
    if len(scenario.events) != 1 or len(scenario.assertions) != 1:
        raise ValueError("the first-run vertical slice requires one event and one assertion")
    if type(scenario.assertions[0]) not in {
        HttpStatusAssertion,
        AcknowledgementDeadlineAssertion,
    }:
        raise ValueError("the first-run vertical slice requires one transport assertion")


def _vertical_slice(
    bundle: CompiledRunBundle,
    config: ProjectConfig,
) -> tuple[
    RealizedDeliveryExecution,
    HttpStatusAssertion | AcknowledgementDeadlineAssertion,
]:
    if len(bundle.manifest.scenarios) != 1 or len(bundle.realized_execution) != 1:
        raise ValueError("the compiled vertical slice must contain one realized delivery")
    scenario = bundle.manifest.scenarios[0]
    if (
        len(scenario.events) != 1
        or len(scenario.deliveries) != 1
        or len(scenario.assertions) != 1
        or len(scenario.deliveries[0].attempt_plan) != 1
    ):
        raise ValueError(
            "the compiled vertical slice must contain one event, delivery, attempt, and assertion"
        )
    assertion = config.scenarios[0].assertions[0]
    if type(assertion) not in {
        HttpStatusAssertion,
        AcknowledgementDeadlineAssertion,
    }:
        raise ValueError("the first-run vertical slice requires one transport assertion")
    typed = cast(
        "HttpStatusAssertion | AcknowledgementDeadlineAssertion",
        assertion,
    )
    if scenario.assertions[0].type != typed.type:
        raise ValueError("compiled assertion type differs from the configuration")
    return bundle.realized_execution[0], typed


async def _activate_vertical_slice(
    repository: TransitionRepository,
    *,
    clock: RuntimeClock,
    run_id: str,
    owner_epoch: int,
    scenario_id: str,
    delivery_id: str,
    assertion_id: str,
) -> None:
    transitions: tuple[
        tuple[EntityType, str, LifecycleState | None, LifecycleState, str],
        ...,
    ] = (
        (EntityType.RUN, run_id, None, RunState.PLANNED, "run_initial"),
        (
            EntityType.SCENARIO,
            scenario_id,
            None,
            ScenarioState.PENDING,
            "scenario_initial",
        ),
        (
            EntityType.DELIVERY,
            delivery_id,
            None,
            DeliveryState.PENDING,
            "delivery_initial",
        ),
        (
            EntityType.ASSERTION,
            assertion_id,
            None,
            AssertionState.PENDING,
            "assertion_initial",
        ),
        (
            EntityType.RUN,
            run_id,
            RunState.PLANNED,
            RunState.RUNNING,
            "run_started",
        ),
        (
            EntityType.SCENARIO,
            scenario_id,
            ScenarioState.PENDING,
            ScenarioState.ELIGIBLE,
            "scenario_eligible",
        ),
        (
            EntityType.SCENARIO,
            scenario_id,
            ScenarioState.ELIGIBLE,
            ScenarioState.RUNNING,
            "scenario_started",
        ),
        (
            EntityType.DELIVERY,
            delivery_id,
            DeliveryState.PENDING,
            DeliveryState.ELIGIBLE,
            "delivery_eligible",
        ),
        (
            EntityType.DELIVERY,
            delivery_id,
            DeliveryState.ELIGIBLE,
            DeliveryState.ACTIVE,
            "delivery_started",
        ),
    )
    for entity_type, entity_id, expected, new, tag in transitions:
        await repository.apply(
            TransitionCommand(
                run_id=run_id,
                transition_id=f"vertical.{tag}",
                entity_type=entity_type,
                entity_id=entity_id,
                expected_state=expected,
                new_state=new,
                trigger_category=tag,
                timestamp=clock.transition_timestamp(),
                owner_epoch=owner_epoch,
                idempotency_key=f"vertical.{tag}",
            )
        )


def _attempt_claim(
    context: AttemptRuntimeContext,
    *,
    seeded: SeededAttempt,
    attempt_plan_id: str,
    timestamp: TransitionTimestamp,
) -> AttemptScheduleClaim:
    return AttemptScheduleClaim(
        schedule_entry_id=seeded.schedule_entry_id,
        attempt_id=context.attempt_id,
        attempt_plan_id=attempt_plan_id,
        event_id=context.event_id,
        delivery_id=context.delivery_id,
        predecessor_attempt_id=None,
        condition_json=seeded.condition_json,
        claim_transition=TransitionCommand(
            run_id=context.run_id,
            transition_id=f"attempt.claim.{context.attempt_id}",
            entity_type=EntityType.ATTEMPT,
            entity_id=context.attempt_id,
            expected_state=AttemptState.SCHEDULED,
            new_state=AttemptState.CLAIMED,
            trigger_category="attempt_claimed",
            timestamp=timestamp,
            owner_epoch=context.owner_epoch,
            idempotency_key=f"attempt.claim.{context.attempt_id}",
            logical_time_ns=context.logical_time_ns,
        ),
    )


def _request_blob(
    bundle: CompiledRunBundle,
    recipe: RealizedDeliveryExecution,
) -> bytes:
    matches = tuple(item for item in bundle.blobs if item.sha256 == recipe.request_blob)
    if len(matches) != 1:
        raise ValueError("realized request blob is not uniquely present in the bundle")
    return matches[0].path.read_bytes()


def _selected_signer(
    recipe: RealizedDeliveryExecution,
    signers: Mapping[str, Signer],
) -> Signer | None:
    if recipe.signer_name is None:
        return None
    signer = signers.get(recipe.signer_name)
    if signer is None:
        raise ValueError("the realized delivery signer was not supplied")
    return signer


def _default_executor(
    config: ProjectConfig,
    clock: RuntimeClock,
) -> HttpAttemptExecutor:
    return HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=AnyIOResolver(),
            connector=AnyIOConnector(),
        ),
        timeouts=HttpTimeouts(
            connect_ns=config.receiver.timeouts.connect.nanoseconds,
            write_ns=config.receiver.timeouts.write.nanoseconds,
            read_ns=config.receiver.timeouts.read.nanoseconds,
            pool_ns=config.receiver.timeouts.pool.nanoseconds,
            total_ns=config.receiver.timeouts.total.nanoseconds,
        ),
        limits=HttpLimits(
            max_request_bytes=config.limits.max_request_bytes,
            response_capture_bytes=config.limits.max_response_capture_bytes,
        ),
        max_concurrency=config.limits.max_concurrency,
        clock=clock,
    )


async def _install_json_reports(
    run_directory: Path,
    reports: JsonReportArtifacts,
) -> None:
    with CancelScope(shield=True):
        await run_sync(
            partial(_install_json_reports_sync, run_directory, reports),
            abandon_on_cancel=False,
        )


def _install_json_reports_sync(
    run_directory: Path,
    reports: JsonReportArtifacts,
) -> None:
    files = (
        ("run-manifest.json", reports.manifest_json),
        ("deliveries.jsonl", reports.deliveries_jsonl),
        ("observations.jsonl", reports.observations_jsonl),
        ("assertions.jsonl", reports.assertions_jsonl),
        ("result-summary.json", reports.result_summary_json),
    )
    for relative_path, content in files:
        target = run_directory / relative_path
        if target.parent != run_directory or target.is_symlink():
            raise RuntimeError("report target escaped or replaced the run directory")
        temporary = run_directory / f".{relative_path}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(0o600)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = [
    "JournalLifecycle",
    "VerticalSliceRunRequest",
    "VerticalSliceRunResult",
    "VerticalSliceRunner",
]
