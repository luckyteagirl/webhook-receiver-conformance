"""Minimum durable vertical slice for one local webhook delivery."""
# ruff: noqa: D105, D107, EM101, INP001, PLR0913, TRY003, TRY004

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from anyio import CancelScope
from anyio.to_thread import run_sync

from webhook_receiver_conformance.assertions.transport import (
    TransportAssertionInput,
    evaluate_transport_assertion,
)
from webhook_receiver_conformance.config.models import (
    AcknowledgementDeadlineAssertion,
    AssertionConfig,
    AttemptMode,
    ClockConfig,
    DeliverStep,
    HttpObserverConfig,
    HttpStatusAssertion,
    HttpStatusClass,
    ProjectConfig,
    ScenarioConfig,
    SecretRef,
)
from webhook_receiver_conformance.config.schema import MAX_CONFIG_BYTES
from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    AttemptClassification,
    AttemptState,
    DeliveryState,
    EvidenceValueType,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.domain.hashing import (
    sha256_digest,
    validate_sha256_digest,
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
    AssertionEvaluation,
    AttemptEvidence,
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
    TRIGGER_ATTEMPT_OUTCOME,
    AssertionEvidenceKind,
    AssertionEvidenceReference,
    AssertionRepository,
    PersistedAttemptEvidence,
    TransitionRepository,
)
from webhook_receiver_conformance.journal.run_lock import acquire_run_lock
from webhook_receiver_conformance.journal.schedules import (
    FullRunCompletionRequest,
    PersistedScheduleEntry,
    PersistentScheduleRepository,
)
from webhook_receiver_conformance.journal.schema import (
    RunDatabase,
    create_run_database,
)
from webhook_receiver_conformance.journal.service import JournalService
from webhook_receiver_conformance.journal.transitions import (
    AttemptScheduleClaim,
    CausalReference,
    DeliverySatisfactionEvidence,
    DeliverySatisfactionKind,
    EntityType,
    LifecycleState,
    TransitionCommand,
)
from webhook_receiver_conformance.manifest.compiler import (
    EFFECTIVE_CONFIG_FILENAME,
    CompiledRunBundle,
    RealizedDeliveryExecution,
    compile_run_bundle,
    load_realized_execution,
)
from webhook_receiver_conformance.manifest.loader import (
    LoadedRunBundle,
)
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.policy import (
    DestinationPolicy,
    parse_destination_policy,
)
from webhook_receiver_conformance.network.transport import (
    AnyIOConnector,
    AnyIOResolver,
)
from webhook_receiver_conformance.observers.protocol import ObserverCapabilities
from webhook_receiver_conformance.reporting.json_reports import (
    AssertionReportRecord,
    DeliveryReportRecord,
    JsonReportArtifacts,
    ObservationReportRecord,
    render_json_reports,
)
from webhook_receiver_conformance.runtime.assertions import (
    AssertionEvidenceBundle,
    AssertionLifecycle,
    AssertionLifecycleResult,
    AssertionRuntimeContext,
)
from webhook_receiver_conformance.runtime.attempts import (
    AttemptLifecycle,
    AttemptRuntimeContext,
)
from webhook_receiver_conformance.runtime.verdicts import (
    TerminalVerdict,
    classify_attempt_verdict,
    reduce_terminal_verdicts,
)
from webhook_receiver_conformance.scheduler.barriers import (
    BarrierRelease,
    ConcurrencyWork,
    run_concurrency_groups,
)
from webhook_receiver_conformance.scheduler.clocks import RuntimeClock, TransitionTimestamp
from webhook_receiver_conformance.scheduler.retries import (
    evaluate_retry,
)
from webhook_receiver_conformance.signatures.base import Signer

if TYPE_CHECKING:
    from datetime import datetime

    from webhook_receiver_conformance.fixtures.blobs import BlobSnapshot
    from webhook_receiver_conformance.manifest.models import (
        DeliveryPlan,
        RunManifest,
        ScenarioPlan,
    )

type ExecutorFactory = Callable[[ProjectConfig, RuntimeClock], HttpAttemptExecutor]
type ClockFactory = Callable[[ClockConfig], RuntimeClock]
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
class ObserverAssertionExecution:
    """One injected observer assertion result plus exported observation records."""

    lifecycle: AssertionLifecycleResult
    observations: tuple[ObservationReportRecord, ...] = ()

    def __post_init__(self) -> None:
        if type(self.lifecycle) is not AssertionLifecycleResult:
            raise TypeError("lifecycle must be an AssertionLifecycleResult")
        if type(self.observations) is not tuple or any(
            type(item) is not ObservationReportRecord for item in self.observations
        ):
            raise TypeError("observations must contain ObservationReportRecord values")


class ObserverAssertionExecutor(Protocol):
    """Injected receiver-state assertion path; absence is explicitly unsupported."""

    async def evaluate(
        self,
        lifecycle: AssertionLifecycle,
        context: AssertionRuntimeContext,
        assertion: AssertionConfig,
        attempts: tuple[PersistedAttemptEvidence, ...],
    ) -> ObserverAssertionExecution:
        """Collect receiver evidence and persist one truthful assertion result."""
        ...


@dataclass(frozen=True, slots=True)
class ObserverAssertionRunScope:
    """Same-run durable resources available only while the journal is open."""

    service: JournalService
    clock: RuntimeClock
    config: ProjectConfig
    project_root: Path
    runtime_public_authorization: str | None
    owner_epoch: int

    def __post_init__(self) -> None:
        if type(self.service) is not JournalService:
            raise TypeError("service must be a JournalService")
        if type(self.clock) is not RuntimeClock:
            raise TypeError("clock must be a RuntimeClock")
        if type(self.config) is not ProjectConfig:
            raise TypeError("config must be a ProjectConfig")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.project_root,
            Path,
        ):
            raise TypeError("project_root must be a pathlib.Path")
        if self.runtime_public_authorization is not None and (
            type(self.runtime_public_authorization) is not str
            or not self.runtime_public_authorization
        ):
            raise ValueError("runtime_public_authorization must be nonempty text or None")
        if type(self.owner_epoch) is not int or self.owner_epoch < 0:
            raise ValueError("owner_epoch must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class ObserverAssertionCoordinates:
    """Exact manifest/report coordinates for one observer assertion."""

    scenario_ordinal: int
    assertion_ordinal: int
    observation_ordinal: int

    def __post_init__(self) -> None:
        for value, name in (
            (self.scenario_ordinal, "scenario_ordinal"),
            (self.assertion_ordinal, "assertion_ordinal"),
            (self.observation_ordinal, "observation_ordinal"),
        ):
            if type(value) is not int or value < 0:
                message = f"{name} must be a nonnegative integer"
                raise ValueError(message)


class ScopedObserverAssertionExecutor(Protocol):
    """Run-bound executor with durable scope and exact report coordinates."""

    async def evaluate_scoped(
        self,
        lifecycle: AssertionLifecycle,
        context: AssertionRuntimeContext,
        assertion: AssertionConfig,
        attempts: tuple[PersistedAttemptEvidence, ...],
        coordinates: ObserverAssertionCoordinates,
    ) -> ObserverAssertionExecution:
        """Collect and persist one observer assertion in its open run scope."""
        ...


class ObserverAssertionExecutorFactory(Protocol):
    """Bind an observer executor only after the run journal and clock exist."""

    def create(
        self,
        scope: ObserverAssertionRunScope,
    ) -> ScopedObserverAssertionExecutor:
        """Create one executor that cannot outlive the supplied open run scope."""
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
class FullRunRequest:
    """Resolved inputs for every manifest delivery in one fresh local run."""

    config: ProjectConfig
    project_root: Path
    artifact_directory: Path
    secret_fingerprints: Mapping[str, str]
    signers: Mapping[str, Signer]
    runtime_public_authorization: str | None = None
    owner_epoch: int = 0

    def __post_init__(self) -> None:
        VerticalSliceRunRequest(
            config=self.config,
            project_root=self.project_root,
            artifact_directory=self.artifact_directory,
            secret_fingerprints=self.secret_fingerprints,
            signers=self.signers,
            runtime_public_authorization=self.runtime_public_authorization,
            owner_epoch=self.owner_epoch,
        )

    @classmethod
    def from_vertical_slice(
        cls,
        request: VerticalSliceRunRequest,
    ) -> FullRunRequest:
        """Preserve the established request boundary for the compatibility facade."""
        if type(request) is not VerticalSliceRunRequest:
            raise TypeError("request must be a VerticalSliceRunRequest")
        return cls(
            config=request.config,
            project_root=request.project_root,
            artifact_directory=request.artifact_directory,
            secret_fingerprints=request.secret_fingerprints,
            signers=request.signers,
            runtime_public_authorization=request.runtime_public_authorization,
            owner_epoch=request.owner_epoch,
        )


@dataclass(frozen=True, slots=True)
class FullAttemptResult:
    """One terminal physical attempt with manifest ordering coordinates."""

    evidence: AttemptEvidence
    terminal_state: AttemptState
    scenario_ordinal: int
    delivery_ordinal: int
    attempt_ordinal: int

    def __post_init__(self) -> None:
        if type(self.evidence) is not AttemptEvidence:
            raise TypeError("evidence must be AttemptEvidence")
        if type(self.terminal_state) is not AttemptState:
            raise TypeError("terminal_state must be an AttemptState")
        for value, name in (
            (self.scenario_ordinal, "scenario_ordinal"),
            (self.delivery_ordinal, "delivery_ordinal"),
            (self.attempt_ordinal, "attempt_ordinal"),
        ):
            if type(value) is not int or value < 0:
                message = f"{name} must be nonnegative"
                raise ValueError(message)

    @property
    def attempt_id(self) -> str:
        """Return the durable physical-attempt identity."""
        return self.evidence.attempt_id

    @property
    def classification(self) -> AttemptClassification:
        """Return the terminal attempt classification."""
        return self.evidence.classification


@dataclass(frozen=True, slots=True)
class FullScenarioResult:
    """One terminal scenario reduction."""

    scenario_id: str
    result_category: ResultCategory
    state: ScenarioState


@dataclass(frozen=True, slots=True)
class FullRunResult:
    """Terminal full-run facts and complete exported evidence inventory."""

    run_id: str
    manifest_id: str
    run_directory: Path
    database_path: Path
    attempts: tuple[FullAttemptResult, ...]
    assertions: tuple[AssertionEvaluation, ...]
    observations: tuple[ObservationReportRecord, ...]
    scenarios: tuple[FullScenarioResult, ...]
    barrier_releases: tuple[BarrierRelease, ...]
    result_category: ResultCategory
    exit_code: ExitCode
    summary_path: Path

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        if type(self.manifest_id) is not str or len(self.manifest_id) != _MANIFEST_ID_LENGTH:
            raise ValueError("manifest_id must be a SHA-256 identifier")
        if not self.attempts:
            raise ValueError("a full transport run requires at least one attempt")
        if type(self.result_category) is not ResultCategory:
            raise TypeError("result_category must be a ResultCategory")
        if type(self.exit_code) is not ExitCode:
            raise TypeError("exit_code must be an ExitCode")


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
        full = await FullRunRunner(
            journal=self._journal,
            executor_factory=self._executor_factory,
        ).run(FullRunRequest.from_vertical_slice(request))
        if len(full.attempts) != 1:
            raise RuntimeError("vertical-slice compatibility produced multiple attempts")
        attempt = full.attempts[0]
        return VerticalSliceRunResult(
            run_id=full.run_id,
            manifest_id=full.manifest_id,
            run_directory=full.run_directory,
            database_path=full.database_path,
            attempt_id=attempt.attempt_id,
            attempt_state=attempt.terminal_state,
            classification=attempt.classification,
            result_category=full.result_category,
            exit_code=full.exit_code,
            summary_path=full.summary_path,
        )


@dataclass(frozen=True, slots=True)
class _AttemptExecution:
    result: FullAttemptResult
    persisted: PersistedAttemptEvidence
    delivery_terminal: bool
    delivery_verdict: TerminalVerdict | None


@dataclass(frozen=True, slots=True)
class _ExecutionBundle:
    manifest: RunManifest
    blobs: tuple[BlobSnapshot, ...]
    realized_execution: tuple[RealizedDeliveryExecution, ...]

    @classmethod
    def compiled(cls, bundle: CompiledRunBundle) -> _ExecutionBundle:
        return cls(
            manifest=bundle.manifest,
            blobs=bundle.blobs,
            realized_execution=bundle.realized_execution,
        )

    @classmethod
    def replay(
        cls,
        bundle: LoadedRunBundle,
        recipes: tuple[RealizedDeliveryExecution, ...],
    ) -> _ExecutionBundle:
        return cls(
            manifest=bundle.manifest,
            blobs=bundle.blobs,
            realized_execution=recipes,
        )


class FullRunRunner:
    """Execute all manifest deliveries through durable schedule and evidence seams."""

    __slots__ = (
        "_clock_factory",
        "_executor_factory",
        "_journal",
        "_observer_assertion_factory",
        "_observer_assertions",
    )

    def __init__(
        self,
        *,
        journal: JournalLifecycle,
        executor_factory: ExecutorFactory | None = None,
        clock_factory: ClockFactory | None = None,
        observer_assertion_executor: ObserverAssertionExecutor | None = None,
        observer_assertion_executor_factory: ObserverAssertionExecutorFactory | None = None,
    ) -> None:
        if not callable(getattr(journal, "initialize", None)):
            raise TypeError("journal must implement initialize")
        if executor_factory is not None and not callable(executor_factory):
            raise TypeError("executor_factory must be callable")
        if clock_factory is not None and not callable(clock_factory):
            raise TypeError("clock_factory must be callable")
        if observer_assertion_executor is not None and not callable(
            getattr(observer_assertion_executor, "evaluate", None)
        ):
            raise TypeError("observer_assertion_executor must implement evaluate")
        if observer_assertion_executor_factory is not None and not callable(
            getattr(observer_assertion_executor_factory, "create", None)
        ):
            raise TypeError("observer_assertion_executor_factory must implement create")
        if (
            observer_assertion_executor is not None
            and observer_assertion_executor_factory is not None
        ):
            raise ValueError("observer assertion executor and factory are mutually exclusive")
        self._journal = journal
        self._executor_factory = _default_executor if executor_factory is None else executor_factory
        self._clock_factory = _default_clock if clock_factory is None else clock_factory
        self._observer_assertions = observer_assertion_executor
        self._observer_assertion_factory = observer_assertion_executor_factory

    async def run(self, request: FullRunRequest) -> FullRunResult:
        """Compile and execute every persisted transport schedule to completion."""
        if type(request) is not FullRunRequest:
            raise TypeError("request must be a FullRunRequest")
        run = create_run_database(request.artifact_directory)
        clock = self._clock_factory(request.config.clock)
        if type(clock) is not RuntimeClock:
            raise TypeError("clock_factory must return a RuntimeClock")
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
            return await self._run_prepared(
                request,
                run=run,
                clock=clock,
                bundle=_ExecutionBundle.compiled(bundle),
            )

    async def run_loaded(
        self,
        request: FullRunRequest,
        bundle: LoadedRunBundle,
    ) -> FullRunResult:
        """Execute an already verified bundle without compiling or reading sources."""
        if type(request) is not FullRunRequest:
            raise TypeError("request must be a FullRunRequest")
        if type(bundle) is not LoadedRunBundle:
            raise TypeError("bundle must be a LoadedRunBundle")
        effective = _read_replay_effective_configuration(bundle)
        recipes = load_realized_execution(bundle.manifest, effective)
        _validate_replay_configuration(request, bundle, effective)
        run = create_run_database(request.artifact_directory)
        clock = self._clock_factory(request.config.clock)
        if type(clock) is not RuntimeClock:
            raise TypeError("clock_factory must return a RuntimeClock")
        with acquire_run_lock(
            run.run_directory,
            run_id=run.run_id,
            owner_epoch=request.owner_epoch,
        ):
            return await self._run_prepared(
                request,
                run=run,
                clock=clock,
                bundle=_ExecutionBundle.replay(bundle, recipes),
            )

    async def _run_prepared(
        self,
        request: FullRunRequest,
        *,
        run: RunDatabase,
        clock: RuntimeClock,
        bundle: _ExecutionBundle,
    ) -> FullRunResult:
        _validate_full_bundle(bundle, request.config)
        async with JournalService.open(run.database_path) as service:
            await self._journal.initialize(
                service,
                JournalBootstrapRequest(
                    run_id=run.run_id,
                    owner_epoch=request.owner_epoch,
                    manifest=bundle.manifest,
                    created_at=bundle.manifest.created_at,
                ),
            )
            transitions = TransitionRepository(service)
            schedules = PersistentScheduleRepository(service)
            await _activate_full_run(
                transitions,
                clock=clock,
                run_id=run.run_id,
                owner_epoch=request.owner_epoch,
                bundle=bundle,
            )
            executor = self._executor_factory(request.config, clock)
            if type(executor) is not HttpAttemptExecutor:
                raise TypeError("executor_factory must return HttpAttemptExecutor")
            policy = parse_destination_policy(
                request.config.receiver,
                runtime_public_authorization=request.runtime_public_authorization,
            )
            generator = ContextGenerator.from_normalized_seed_hash(
                bytes.fromhex(bundle.manifest.generator.normalized_seed_hash_hex)
            )
            attempts, delivery_verdicts, releases = await _execute_schedules(
                schedules=schedules,
                transitions=transitions,
                executor=executor,
                clock=clock,
                bundle=bundle,
                config=request.config,
                run_id=run.run_id,
                owner_epoch=request.owner_epoch,
                policy=policy,
                signers=request.signers,
                generator=generator,
            )
            scoped_observer_executor = self._scoped_observer_executor(
                service,
                clock=clock,
                request=request,
            )
            (
                assertion_records,
                observations,
                scenario_results,
            ) = await _evaluate_full_assertions(
                service=service,
                transitions=transitions,
                clock=clock,
                bundle=bundle,
                config=request.config,
                run_id=run.run_id,
                owner_epoch=request.owner_epoch,
                attempts=attempts,
                delivery_verdicts=delivery_verdicts,
                observer_executor=self._observer_assertions,
                scoped_observer_executor=scoped_observer_executor,
            )
            verdict = reduce_terminal_verdicts(
                tuple(item.result_category for item in scenario_results)
            )
            completed_at = clock.wall_now()
            await schedules.finalize_run(
                FullRunCompletionRequest(
                    run_id=run.run_id,
                    owner_epoch=request.owner_epoch,
                    result_category=verdict.category,
                    completed_at=_canonical_utc(completed_at),
                    transition=_run_completion_transition(
                        run_id=run.run_id,
                        owner_epoch=request.owner_epoch,
                        verdict=verdict,
                        timestamp=clock.transition_timestamp(),
                    ),
                )
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
                        scenarios=len(bundle.manifest.scenarios),
                        attempts=len(attempts),
                        observations=len(observations),
                        assertions=len(assertion_records),
                    ),
                    artifacts=ArtifactPaths(
                        manifest="run-manifest.json",
                        deliveries="deliveries.jsonl",
                        observations="observations.jsonl",
                        assertions="assertions.jsonl",
                    ),
                ),
                deliveries=tuple(
                    DeliveryReportRecord(
                        record=item.evidence,
                        scenario_ordinal=item.scenario_ordinal,
                        delivery_ordinal=item.delivery_ordinal,
                        attempt_ordinal=item.attempt_ordinal,
                    )
                    for item in attempts
                ),
                observations=observations,
                assertions=tuple(
                    AssertionReportRecord(
                        record=record,
                        scenario_ordinal=scenario_ordinal,
                        assertion_ordinal=assertion_ordinal,
                    )
                    for record, scenario_ordinal, assertion_ordinal in assertion_records
                ),
            )
            await _install_json_reports(run.run_directory, reports)
        return FullRunResult(
            run_id=run.run_id,
            manifest_id=bundle.manifest.manifest_id,
            run_directory=run.run_directory,
            database_path=run.database_path,
            attempts=attempts,
            assertions=tuple(item[0] for item in assertion_records),
            observations=observations,
            scenarios=scenario_results,
            barrier_releases=releases,
            result_category=verdict.category,
            exit_code=verdict.exit_code,
            summary_path=run.run_directory / "result-summary.json",
        )

    def _scoped_observer_executor(
        self,
        service: JournalService,
        *,
        clock: RuntimeClock,
        request: FullRunRequest,
    ) -> ScopedObserverAssertionExecutor | None:
        factory = self._observer_assertion_factory
        if factory is None:
            return None
        executor = factory.create(
            ObserverAssertionRunScope(
                service=service,
                clock=clock,
                config=request.config,
                project_root=request.project_root,
                runtime_public_authorization=request.runtime_public_authorization,
                owner_epoch=request.owner_epoch,
            )
        )
        if not callable(getattr(executor, "evaluate_scoped", None)):
            raise TypeError("observer assertion executor factory returned an invalid executor")
        return executor


async def _execute_schedules(  # noqa: C901
    *,
    schedules: PersistentScheduleRepository,
    transitions: TransitionRepository,
    executor: HttpAttemptExecutor,
    clock: RuntimeClock,
    bundle: _ExecutionBundle,
    config: ProjectConfig,
    run_id: str,
    owner_epoch: int,
    policy: DestinationPolicy,
    signers: Mapping[str, Signer],
    generator: ContextGenerator,
) -> tuple[
    tuple[FullAttemptResult, ...],
    Mapping[str, TerminalVerdict],
    tuple[BarrierRelease, ...],
]:
    attempts: list[_AttemptExecution] = []
    delivery_verdicts: dict[str, TerminalVerdict] = {}
    releases: list[BarrierRelease] = []
    logical_now_ns = 0

    async def execute(
        work: ConcurrencyWork[PersistedScheduleEntry],
    ) -> _AttemptExecution:
        entry = work.payload
        scenario, delivery, recipe = _scheduled_plan(bundle, entry)
        if entry.attempt_ordinal == 1:
            await _activate_delivery(
                transitions,
                clock=clock,
                run_id=run_id,
                owner_epoch=owner_epoch,
                delivery_id=delivery.delivery_id,
            )
        attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
        context = AttemptRuntimeContext(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            event_id=delivery.event_id,
            delivery_id=delivery.delivery_id,
            attempt_id=attempt_id,
            owner_epoch=owner_epoch,
            logical_time_ns=entry.logical_due_ns,
            scenario_ordinal=entry.scenario_ordinal,
            step_ordinal=entry.step_ordinal,
            delivery_ordinal=entry.delivery_ordinal,
            attempt_ordinal=entry.attempt_ordinal,
        )
        await schedules.lease_attempt(
            _schedule_claim(
                context,
                entry=entry,
                timestamp=clock.transition_timestamp(),
            )
        )
        retryable_status = _retryable_status(config, entry)
        lifecycle = AttemptLifecycle(
            repository=transitions,
            executor=executor,
            clock=clock,
        )
        realized = await lifecycle.execute_realized(
            context,
            HttpAttemptCommand(
                policy=policy,
                body=_request_blob(bundle, recipe),
                headers=(
                    HttpHeader(
                        "content-type",
                        recipe.media_type,
                        HeaderOwner.USER,
                    ),
                ),
            ),
            replace(recipe, logical_time_ns=entry.logical_due_ns),
            signer=_selected_signer(recipe, signers),
            retry_decider=lambda predecessor: evaluate_retry(
                delivery,
                predecessor,
                generator=generator,
                scenario_id=scenario.scenario_id,
            ),
            retryable_status=retryable_status,
        )
        persisted = await transitions.attempt_evidence(run_id, attempt_id)
        if persisted is None:
            raise RuntimeError("terminal attempt evidence was not persisted")
        decision = realized.lifecycle.retry_decision
        terminal = decision is None or not decision.should_schedule
        delivery_verdict = (
            classify_attempt_verdict(realized.lifecycle.classification) if terminal else None
        )
        if terminal:
            await _terminalize_delivery(
                transitions,
                context=context,
                terminal_state=realized.lifecycle.terminal_state,
                timestamp=clock.transition_timestamp(),
            )
        return _AttemptExecution(
            result=FullAttemptResult(
                evidence=persisted.attempt,
                terminal_state=realized.lifecycle.terminal_state,
                scenario_ordinal=entry.scenario_ordinal,
                delivery_ordinal=entry.delivery_ordinal,
                attempt_ordinal=entry.attempt_ordinal,
            ),
            persisted=persisted,
            delivery_terminal=terminal,
            delivery_verdict=delivery_verdict,
        )

    while True:
        pending = await schedules.pending(run_id)
        if not pending:
            break
        due_ns = pending[0].logical_due_ns
        if due_ns < logical_now_ns:
            raise RuntimeError("persistent schedule moved logical time backwards")
        await clock.sleep_logical(due_ns - logical_now_ns)
        logical_now_ns = due_ns
        due = tuple(item for item in pending if item.logical_due_ns == due_ns)
        barrier = await run_concurrency_groups(
            tuple(
                ConcurrencyWork(
                    work_id=item.schedule_entry_id,
                    concurrency_group=_concurrency_group(bundle, item),
                    ordinal=index,
                    payload=item,
                )
                for index, item in enumerate(due)
            ),
            execute,
            max_concurrency=config.limits.max_concurrency,
            monotonic_ns=clock.monotonic_now_ns,
        )
        releases.extend(barrier.releases)
        for completed in barrier.completed:
            item = completed.result
            attempts.append(item)
            if item.delivery_terminal:
                if item.delivery_verdict is None:
                    raise RuntimeError("terminal delivery lacks a verdict")
                delivery_id = item.result.evidence.delivery_id
                if delivery_id in delivery_verdicts:
                    raise RuntimeError("delivery was reduced more than once")
                delivery_verdicts[delivery_id] = item.delivery_verdict

    expected_deliveries = {
        delivery.delivery_id
        for scenario in bundle.manifest.scenarios
        for delivery in scenario.deliveries
    }
    if set(delivery_verdicts) != expected_deliveries:
        raise RuntimeError("schedule drained without every delivery becoming terminal")
    ordered_attempts = tuple(
        item.result
        for item in sorted(
            attempts,
            key=lambda item: (
                item.result.scenario_ordinal,
                item.result.delivery_ordinal,
                item.result.attempt_ordinal,
                item.result.evidence.sequence,
            ),
        )
    )
    return ordered_attempts, delivery_verdicts, tuple(releases)


async def _evaluate_full_assertions(
    *,
    service: JournalService,
    transitions: TransitionRepository,
    clock: RuntimeClock,
    bundle: _ExecutionBundle,
    config: ProjectConfig,
    run_id: str,
    owner_epoch: int,
    attempts: tuple[FullAttemptResult, ...],
    delivery_verdicts: Mapping[str, TerminalVerdict],
    observer_executor: ObserverAssertionExecutor | None,
    scoped_observer_executor: ScopedObserverAssertionExecutor | None,
) -> tuple[
    tuple[tuple[AssertionEvaluation, int, int], ...],
    tuple[ObservationReportRecord, ...],
    tuple[FullScenarioResult, ...],
]:
    assertions: list[tuple[AssertionEvaluation, int, int]] = []
    observations: list[ObservationReportRecord] = []
    scenario_results: list[FullScenarioResult] = []
    repository = AssertionRepository(service)
    persisted_by_attempt = {
        item.attempt_id: await transitions.attempt_evidence(run_id, item.attempt_id)
        for item in attempts
    }
    if any(value is None for value in persisted_by_attempt.values()):
        raise RuntimeError("assertion input attempt evidence is missing")
    persisted = cast(
        "dict[str, PersistedAttemptEvidence]",
        persisted_by_attempt,
    )

    for scenario_ordinal, (scenario, configured) in enumerate(
        zip(
            bundle.manifest.scenarios,
            config.scenarios,
            strict=True,
        )
    ):
        observation_ordinal = 0
        scenario_attempts = tuple(
            persisted[item.attempt_id]
            for item in attempts
            if item.evidence.scenario_id == scenario.scenario_id
        )
        assertion_verdicts: list[ResultCategory] = []
        for assertion_ordinal, (plan, assertion) in enumerate(
            zip(scenario.assertions, configured.assertions, strict=True)
        ):
            lifecycle = AssertionLifecycle(repository=repository, clock=clock)
            context = AssertionRuntimeContext(
                run_id=run_id,
                scenario_id=scenario.scenario_id,
                assertion_id=plan.assertion_id,
                owner_epoch=owner_epoch,
            )
            if type(assertion) in {
                HttpStatusAssertion,
                AcknowledgementDeadlineAssertion,
            }:
                result = await _evaluate_transport_selection(
                    lifecycle,
                    context=context,
                    assertion=cast(
                        "HttpStatusAssertion | AcknowledgementDeadlineAssertion",
                        assertion,
                    ),
                    configured_scenario=configured,
                    planned_scenario=scenario,
                    attempts=scenario_attempts,
                )
                execution = ObserverAssertionExecution(result)
            elif scoped_observer_executor is not None:
                execution = await scoped_observer_executor.evaluate_scoped(
                    lifecycle,
                    context,
                    assertion,
                    scenario_attempts,
                    ObserverAssertionCoordinates(
                        scenario_ordinal=scenario_ordinal,
                        assertion_ordinal=assertion_ordinal,
                        observation_ordinal=observation_ordinal,
                    ),
                )
                observation_ordinal += 1
                if type(execution) is not ObserverAssertionExecution:
                    raise TypeError("observer assertion executor returned an invalid result")
            elif observer_executor is not None:
                execution = await observer_executor.evaluate(
                    lifecycle,
                    context,
                    assertion,
                    scenario_attempts,
                )
                if type(execution) is not ObserverAssertionExecution:
                    raise TypeError("observer assertion executor returned an invalid result")
            else:
                execution = ObserverAssertionExecution(
                    await _unsupported_observer_assertion(
                        lifecycle,
                        context=context,
                        assertion=assertion,
                        attempts=scenario_attempts,
                    )
                )
            assertion_verdicts.append(execution.lifecycle.normalized.verdict.category)
            assertions.append(
                (
                    execution.lifecycle.committed.evaluation,
                    scenario_ordinal,
                    assertion_ordinal,
                )
            )
            observations.extend(execution.observations)

        delivery_categories = tuple(
            delivery_verdicts[item.delivery_id].category for item in scenario.deliveries
        )
        scenario_verdict = reduce_terminal_verdicts((*delivery_categories, *assertion_verdicts))
        scenario_state = _scenario_state(scenario_verdict.category)
        await transitions.apply(
            TransitionCommand(
                run_id=run_id,
                transition_id=f"full.scenario.finish.{scenario.scenario_id}",
                entity_type=EntityType.SCENARIO,
                entity_id=scenario.scenario_id,
                expected_state=ScenarioState.RUNNING,
                new_state=scenario_state,
                trigger_category="scenario_reduction",
                timestamp=clock.transition_timestamp(),
                owner_epoch=owner_epoch,
                idempotency_key=f"full.scenario.finish.{scenario.scenario_id}",
            )
        )
        scenario_results.append(
            FullScenarioResult(
                scenario_id=scenario.scenario_id,
                result_category=scenario_verdict.category,
                state=scenario_state,
            )
        )
    return tuple(assertions), tuple(observations), tuple(scenario_results)


async def _evaluate_transport_selection(
    lifecycle: AssertionLifecycle,
    *,
    context: AssertionRuntimeContext,
    assertion: HttpStatusAssertion | AcknowledgementDeadlineAssertion,
    configured_scenario: ScenarioConfig,
    planned_scenario: ScenarioPlan,
    attempts: tuple[PersistedAttemptEvidence, ...],
) -> AssertionLifecycleResult:
    event_id = _selected_event_id(
        configured_scenario,
        planned_scenario,
        assertion.attempt.event,
    )
    selected = tuple(item for item in attempts if item.attempt.event_id == event_id)
    if assertion.attempt.mode is AttemptMode.LAST_TERMINAL:
        selected = selected[-1:]
    if not selected:
        raise RuntimeError("transport assertion selected no terminal attempt")
    evaluated = tuple(
        evaluate_transport_assertion(
            assertion,
            TransportAssertionInput(
                attempt=item.attempt,
                response_headers_elapsed_ns=item.response_headers_elapsed_ns,
            ),
        )
        for item in selected
    )
    witness_index = next(
        (
            index
            for index, evaluation in enumerate(evaluated)
            if evaluation.result is AssertionResult.FAIL
        ),
        next(
            (
                index
                for index, evaluation in enumerate(evaluated)
                if evaluation.result is AssertionResult.ERROR
            ),
            len(evaluated) - 1,
        ),
    )
    witness = selected[witness_index]
    return await lifecycle.evaluate(
        context,
        assertion,
        AssertionEvidenceBundle(
            payload=TransportAssertionInput(
                attempt=witness.attempt,
                response_headers_elapsed_ns=witness.response_headers_elapsed_ns,
            ),
            references=tuple(
                AssertionEvidenceReference(
                    AssertionEvidenceKind.ATTEMPT,
                    item.attempt.attempt_id,
                )
                for item in selected
            ),
        ),
    )


async def _unsupported_observer_assertion(
    lifecycle: AssertionLifecycle,
    *,
    context: AssertionRuntimeContext,
    assertion: AssertionConfig,
    attempts: tuple[PersistedAttemptEvidence, ...],
) -> AssertionLifecycleResult:
    if not attempts:
        raise RuntimeError("unsupported observer assertion lacks durable scope evidence")
    return await lifecycle.evaluate_observer(
        context,
        assertion,
        ObserverCapabilities(
            evidence_types=(EvidenceValueType.NULL,),
            evidence_keys=(),
            read_only=True,
            idempotent=True,
        ),
        _unexpected_observer_supplier,
        capability_reference=AssertionEvidenceReference(
            AssertionEvidenceKind.ATTEMPT,
            attempts[-1].attempt.attempt_id,
        ),
    )


async def _unexpected_observer_supplier() -> AssertionEvidenceBundle:
    raise AssertionError("unsupported observer capability must not poll")


def _default_clock(config: ClockConfig) -> RuntimeClock:
    return RuntimeClock.from_config(config)


def _read_replay_effective_configuration(bundle: LoadedRunBundle) -> bytes:
    path = bundle.directory / EFFECTIVE_CONFIG_FILENAME
    if path.parent != bundle.directory or path.is_symlink() or not path.is_file():
        raise ValueError("verified replay bundle lacks a regular effective configuration")
    with path.open("rb") as stream:
        content = stream.read(MAX_CONFIG_BYTES + 1)
    if len(content) > MAX_CONFIG_BYTES:
        raise ValueError("replay effective configuration exceeds its resource bound")
    return content


def _validate_replay_configuration(
    request: FullRunRequest,
    bundle: LoadedRunBundle,
    effective_bytes: bytes,
) -> None:
    effective = _parse_effective_configuration(effective_bytes)
    realized = effective.pop("realized_execution", None)
    if not isinstance(realized, list):
        raise ValueError("effective configuration lacks realized execution recipes")
    project = effective.get("project")
    if not isinstance(project, dict):
        raise ValueError("effective configuration lacks a project object")
    effective_project = cast("dict[str, object]", project)
    effective_project.pop("seed_fingerprint", None)
    fresh = _fresh_effective_projection(
        request.config,
        request.secret_fingerprints,
    )
    if effective != fresh:
        raise ValueError(
            "fresh replay configuration differs from the digest-bound execution configuration"
        )
    policy = parse_destination_policy(
        request.config.receiver,
        runtime_public_authorization=request.runtime_public_authorization,
    )
    target = bundle.manifest.target_policy
    if (
        policy.target_profile.value != target.profile
        or policy.destination.host != target.authorized_host
        or policy.destination.port != target.authorized_port
    ):
        raise ValueError("fresh replay destination differs from the manifest target")


def _fresh_effective_projection(
    config: ProjectConfig,
    fingerprints: Mapping[str, str],
) -> dict[str, object]:
    wire = cast(
        "dict[str, object]",
        config.model_dump(mode="json", exclude_none=True),
    )
    project = cast("dict[str, object]", wire["project"])
    project.pop("seed", None)
    fixtures = cast("list[object]", wire["fixtures"])
    for fixture_value in fixtures:
        fixture = cast("dict[str, object]", fixture_value)
        path = cast("str", fixture.pop("path"))
        fixture["path_fingerprint"] = sha256_digest(path.encode())
        schema_path = fixture.pop("schema_path", None)
        if schema_path is not None:
            fixture["schema_path_fingerprint"] = sha256_digest(cast("str", schema_path).encode())
    signers = cast("dict[str, object]", wire["signers"])
    for name, signer in config.signers.items():
        signer_wire = cast("dict[str, object]", signers[name])
        signer_wire["secret"] = _secret_snapshot(
            signer.secret,
            fingerprints,
        )
    observers = cast("dict[str, object]", wire["observers"])
    for name, observer in config.observers.items():
        if not isinstance(observer, HttpObserverConfig):
            continue
        observer_wire = cast("dict[str, object]", observers[name])
        observer_wire["token"] = _secret_snapshot(
            observer.token,
            fingerprints,
        )
    return wire


def _secret_snapshot(
    reference: SecretRef,
    fingerprints: Mapping[str, str],
) -> dict[str, str]:
    reference_wire = cast(
        "dict[str, object]",
        reference.model_dump(mode="json"),
    )
    if len(reference_wire) != 1:
        raise ValueError("secret reference must contain one source")
    kind, raw_value = next(iter(reference_wire.items()))
    if type(raw_value) is not str:
        raise ValueError("secret reference source must be text")
    fingerprint = fingerprints.get(f"{kind}:{raw_value}")
    if fingerprint is None:
        raise ValueError("fresh replay secrets require matching safe fingerprints")
    return {
        "reference_kind": kind,
        "fingerprint": validate_sha256_digest(fingerprint),
    }


def _parse_effective_configuration(value: bytes) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("effective configuration contains a duplicate key")
            result[key] = item
        return result

    try:
        parsed: object = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("effective configuration is not strict JSON") from None
    if not isinstance(parsed, dict):
        raise ValueError("effective configuration must be an object")
    return cast("dict[str, object]", parsed)


def _validate_full_bundle(
    bundle: _ExecutionBundle,
    config: ProjectConfig,
) -> None:
    scenarios = bundle.manifest.scenarios
    if len(scenarios) != len(config.scenarios):
        raise ValueError("manifest scenario inventory differs from fresh configuration")
    recipes = {item.delivery_id: item for item in bundle.realized_execution}
    expected_delivery_count = sum(len(item.deliveries) for item in scenarios)
    if (
        len(recipes) != expected_delivery_count
        or len(bundle.realized_execution) != expected_delivery_count
    ):
        raise ValueError("realized execution inventory differs from manifest deliveries")
    for planned, configured in zip(scenarios, config.scenarios, strict=True):
        configured_deliveries = tuple(
            step.deliver
            for step in configured.steps
            if isinstance(step, DeliverStep)
            for _copy in range(step.deliver.count)
        )
        if (
            len(planned.events) != len(configured.events)
            or len(planned.deliveries) != len(configured_deliveries)
            or len(planned.assertions) != len(configured.assertions)
        ):
            raise ValueError("manifest scenario shape differs from fresh configuration")
        for assertion_plan, assertion in zip(
            planned.assertions,
            configured.assertions,
            strict=True,
        ):
            if assertion_plan.type != assertion.type:
                raise ValueError("manifest assertion type differs from fresh configuration")
        for delivery in planned.deliveries:
            recipe = recipes.get(delivery.delivery_id)
            if (
                recipe is None
                or recipe.scenario_id != planned.scenario_id
                or recipe.event_id != delivery.event_id
                or recipe.logical_time_ns != delivery.logical_time_ns
                or any(item.request_blob != recipe.request_blob for item in delivery.attempt_plan)
            ):
                raise ValueError("realized execution conflicts with manifest planning")


async def _activate_full_run(
    repository: TransitionRepository,
    *,
    clock: RuntimeClock,
    run_id: str,
    owner_epoch: int,
    bundle: _ExecutionBundle,
) -> None:
    await _apply_transition(
        repository,
        clock=clock,
        run_id=run_id,
        owner_epoch=owner_epoch,
        entity_type=EntityType.RUN,
        entity_id=run_id,
        expected=None,
        new=RunState.PLANNED,
        tag="run_initial",
    )
    for scenario in bundle.manifest.scenarios:
        await _apply_transition(
            repository,
            clock=clock,
            run_id=run_id,
            owner_epoch=owner_epoch,
            entity_type=EntityType.SCENARIO,
            entity_id=scenario.scenario_id,
            expected=None,
            new=ScenarioState.PENDING,
            tag="scenario_initial",
        )
        for delivery in scenario.deliveries:
            await _apply_transition(
                repository,
                clock=clock,
                run_id=run_id,
                owner_epoch=owner_epoch,
                entity_type=EntityType.DELIVERY,
                entity_id=delivery.delivery_id,
                expected=None,
                new=DeliveryState.PENDING,
                tag="delivery_initial",
            )
        for assertion in scenario.assertions:
            await _apply_transition(
                repository,
                clock=clock,
                run_id=run_id,
                owner_epoch=owner_epoch,
                entity_type=EntityType.ASSERTION,
                entity_id=assertion.assertion_id,
                expected=None,
                new=AssertionState.PENDING,
                tag="assertion_initial",
            )
    await _apply_transition(
        repository,
        clock=clock,
        run_id=run_id,
        owner_epoch=owner_epoch,
        entity_type=EntityType.RUN,
        entity_id=run_id,
        expected=RunState.PLANNED,
        new=RunState.RUNNING,
        tag="run_started",
    )
    for scenario in bundle.manifest.scenarios:
        await _apply_transition(
            repository,
            clock=clock,
            run_id=run_id,
            owner_epoch=owner_epoch,
            entity_type=EntityType.SCENARIO,
            entity_id=scenario.scenario_id,
            expected=ScenarioState.PENDING,
            new=ScenarioState.ELIGIBLE,
            tag="scenario_eligible",
        )
        await _apply_transition(
            repository,
            clock=clock,
            run_id=run_id,
            owner_epoch=owner_epoch,
            entity_type=EntityType.SCENARIO,
            entity_id=scenario.scenario_id,
            expected=ScenarioState.ELIGIBLE,
            new=ScenarioState.RUNNING,
            tag="scenario_started",
        )


async def _apply_transition(
    repository: TransitionRepository,
    *,
    clock: RuntimeClock,
    run_id: str,
    owner_epoch: int,
    entity_type: EntityType,
    entity_id: str,
    expected: LifecycleState | None,
    new: LifecycleState,
    tag: str,
) -> None:
    identity = f"full.{tag}.{entity_id}"
    await repository.apply(
        TransitionCommand(
            run_id=run_id,
            transition_id=identity,
            entity_type=entity_type,
            entity_id=entity_id,
            expected_state=expected,
            new_state=new,
            trigger_category=tag,
            timestamp=clock.transition_timestamp(),
            owner_epoch=owner_epoch,
            idempotency_key=identity,
        )
    )


def _scheduled_plan(
    bundle: _ExecutionBundle,
    entry: PersistedScheduleEntry,
) -> tuple[ScenarioPlan, DeliveryPlan, RealizedDeliveryExecution]:
    try:
        scenario = bundle.manifest.scenarios[entry.scenario_ordinal]
        delivery = scenario.deliveries[entry.delivery_ordinal]
    except IndexError:
        raise RuntimeError("persisted schedule ordinal is outside the manifest") from None
    if scenario.scenario_id != entry.scenario_id or delivery.ordinal != entry.delivery_ordinal:
        raise RuntimeError("persisted schedule coordinates differ from the manifest")
    recipes = tuple(
        item for item in bundle.realized_execution if item.delivery_id == delivery.delivery_id
    )
    if len(recipes) != 1:
        raise RuntimeError("scheduled delivery lacks one realized execution recipe")
    attempt = next(
        (item for item in delivery.attempt_plan if item.ordinal == entry.attempt_ordinal),
        None,
    )
    if attempt is None or attempt.request_blob != recipes[0].request_blob:
        raise RuntimeError("persisted attempt schedule differs from its attempt plan")
    return scenario, delivery, recipes[0]


async def _activate_delivery(
    repository: TransitionRepository,
    *,
    clock: RuntimeClock,
    run_id: str,
    owner_epoch: int,
    delivery_id: str,
) -> None:
    await _apply_transition(
        repository,
        clock=clock,
        run_id=run_id,
        owner_epoch=owner_epoch,
        entity_type=EntityType.DELIVERY,
        entity_id=delivery_id,
        expected=DeliveryState.PENDING,
        new=DeliveryState.ELIGIBLE,
        tag="delivery_eligible",
    )
    await _apply_transition(
        repository,
        clock=clock,
        run_id=run_id,
        owner_epoch=owner_epoch,
        entity_type=EntityType.DELIVERY,
        entity_id=delivery_id,
        expected=DeliveryState.ELIGIBLE,
        new=DeliveryState.ACTIVE,
        tag="delivery_started",
    )


def _schedule_claim(
    context: AttemptRuntimeContext,
    *,
    entry: PersistedScheduleEntry,
    timestamp: TransitionTimestamp,
) -> AttemptScheduleClaim:
    return AttemptScheduleClaim(
        schedule_entry_id=entry.schedule_entry_id,
        attempt_id=context.attempt_id,
        attempt_plan_id=entry.attempt_plan_id,
        event_id=context.event_id,
        delivery_id=context.delivery_id,
        predecessor_attempt_id=entry.predecessor_attempt_id,
        condition_json=entry.condition_json,
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


def _retryable_status(
    config: ProjectConfig,
    entry: PersistedScheduleEntry,
) -> Callable[[int], bool] | None:
    try:
        scenario = config.scenarios[entry.scenario_ordinal]
    except IndexError:
        raise RuntimeError("schedule scenario is outside fresh configuration") from None
    actions = tuple(
        step.deliver
        for step in scenario.steps
        if isinstance(step, DeliverStep)
        for _copy in range(step.deliver.count)
    )
    try:
        retry = actions[entry.delivery_ordinal].retry
    except IndexError:
        raise RuntimeError("schedule delivery is outside fresh configuration") from None
    if retry is None or retry.retryable_statuses is None:
        return None
    selectors = retry.retryable_statuses

    def selected(status: int) -> bool:
        return any(
            status // 100 == _status_class(selector)
            if type(selector) is HttpStatusClass
            else status == selector
            for selector in selectors
        )

    return selected


def _status_class(selector: HttpStatusClass) -> int:
    return {
        HttpStatusClass.SUCCESS: 2,
        HttpStatusClass.REDIRECTION: 3,
        HttpStatusClass.CLIENT_ERROR: 4,
        HttpStatusClass.SERVER_ERROR: 5,
    }[selector]


async def _terminalize_delivery(
    repository: TransitionRepository,
    *,
    context: AttemptRuntimeContext,
    terminal_state: AttemptState,
    timestamp: TransitionTimestamp,
) -> None:
    target = {
        AttemptState.SUCCEEDED: DeliveryState.SATISFIED,
        AttemptState.UNKNOWN_OUTCOME: DeliveryState.AMBIGUOUS,
        AttemptState.CANCELLED: DeliveryState.CANCELLED,
        AttemptState.NOT_SENT: DeliveryState.EXHAUSTED,
        AttemptState.REJECTED: DeliveryState.EXHAUSTED,
        AttemptState.TRANSPORT_FAILED: DeliveryState.EXHAUSTED,
    }.get(terminal_state)
    if target is None:
        raise ValueError("delivery cannot reduce from a nonterminal attempt state")
    cause = CausalReference(context.run_id, context.attempt_id)
    satisfaction = (
        DeliverySatisfactionEvidence(DeliverySatisfactionKind.ATTEMPT, cause)
        if target is DeliveryState.SATISFIED
        else None
    )
    await repository.apply(
        TransitionCommand(
            run_id=context.run_id,
            transition_id=f"full.delivery.finish.{context.delivery_id}",
            entity_type=EntityType.DELIVERY,
            entity_id=context.delivery_id,
            expected_state=DeliveryState.ACTIVE,
            new_state=target,
            trigger_category=TRIGGER_ATTEMPT_OUTCOME,
            timestamp=timestamp,
            owner_epoch=context.owner_epoch,
            idempotency_key=f"full.delivery.finish.{context.delivery_id}",
            causal_reference=cause,
            delivery_satisfaction=satisfaction,
        )
    )


def _concurrency_group(
    bundle: _ExecutionBundle,
    entry: PersistedScheduleEntry,
) -> str:
    _scenario, delivery, _recipe = _scheduled_plan(bundle, entry)
    return delivery.concurrency_group or f"ungrouped.{entry.schedule_entry_id}"


def _selected_event_id(
    configured: ScenarioConfig,
    planned: ScenarioPlan,
    event_name: str,
) -> str:
    index = next(
        (ordinal for ordinal, item in enumerate(configured.events) if item.id == event_name),
        None,
    )
    if index is None or index >= len(planned.events):
        raise RuntimeError("transport assertion references an unknown event")
    return planned.events[index].event_id


def _scenario_state(category: ResultCategory) -> ScenarioState:
    return {
        ResultCategory.PASS: ScenarioState.PASSED,
        ResultCategory.RECEIVER_FAILURE: ScenarioState.FAILED,
        ResultCategory.AMBIGUOUS: ScenarioState.AMBIGUOUS,
        ResultCategory.CANCELLED: ScenarioState.CANCELLED,
        ResultCategory.ENVIRONMENT_ERROR: ScenarioState.ERROR,
        ResultCategory.HARNESS_ERROR: ScenarioState.ERROR,
        ResultCategory.INVALID_INPUT: ScenarioState.ERROR,
        ResultCategory.UNSUPPORTED: ScenarioState.ERROR,
    }[category]


def _run_completion_transition(
    *,
    run_id: str,
    owner_epoch: int,
    verdict: TerminalVerdict,
    timestamp: TransitionTimestamp,
) -> TransitionCommand[RunState]:
    state = {
        ResultCategory.PASS: RunState.COMPLETED,
        ResultCategory.RECEIVER_FAILURE: RunState.COMPLETED,
        ResultCategory.ENVIRONMENT_ERROR: RunState.COMPLETED,
        ResultCategory.UNSUPPORTED: RunState.COMPLETED,
        ResultCategory.AMBIGUOUS: RunState.PAUSED,
        ResultCategory.CANCELLED: RunState.CANCELLED,
        ResultCategory.HARNESS_ERROR: RunState.FAILED,
        ResultCategory.INVALID_INPUT: RunState.FAILED,
    }[verdict.category]
    return TransitionCommand(
        run_id=run_id,
        transition_id="full.run.finish",
        entity_type=EntityType.RUN,
        entity_id=run_id,
        expected_state=RunState.RUNNING,
        new_state=state,
        trigger_category="run_reduction",
        timestamp=timestamp,
        owner_epoch=owner_epoch,
        idempotency_key="full.run.finish",
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


def _request_blob(
    bundle: _ExecutionBundle,
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
    "FullAttemptResult",
    "FullRunRequest",
    "FullRunResult",
    "FullRunRunner",
    "FullScenarioResult",
    "JournalLifecycle",
    "ObserverAssertionCoordinates",
    "ObserverAssertionExecution",
    "ObserverAssertionExecutor",
    "ObserverAssertionExecutorFactory",
    "ObserverAssertionRunScope",
    "ScopedObserverAssertionExecutor",
    "VerticalSliceRunRequest",
    "VerticalSliceRunResult",
    "VerticalSliceRunner",
]
