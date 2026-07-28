"""Minimum durable vertical slice for one local webhook delivery."""
# ruff: noqa: D105, D107, EM101, INP001, PLR0913, TRY003, TRY004

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import uuid
import weakref
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager, nullcontext
from dataclasses import dataclass, field, replace
from enum import StrEnum
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, BinaryIO, Protocol, cast

from anyio import CancelScope
from anyio.to_thread import run_sync

from webhook_receiver_conformance.assertions.temporal import eventual_state_predicate
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
    EventualStateAssertion,
    HttpObserverConfig,
    HttpStatusAssertion,
    HttpStatusClass,
    NoPartialSideEffectAssertion,
    ProjectConfig,
    ScenarioConfig,
    SecretRef,
    TargetProfile,
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
    ObservationState,
    ObservationStatus,
    RunState,
    ScenarioState,
)
from webhook_receiver_conformance.domain.hashing import (
    sha256_digest,
    validate_sha256_digest,
)
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    encode_crockford_ulid,
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
from webhook_receiver_conformance.journal.reporting import (
    JournalReportAssertion,
    JournalReportReader,
    JournalReportSnapshot,
)
from webhook_receiver_conformance.journal.repositories import (
    TRIGGER_ATTEMPT_OUTCOME,
    AssertionEvidenceKind,
    AssertionEvidenceReference,
    AssertionRepository,
    PersistedAttemptEvidence,
    TransitionRepository,
)
from webhook_receiver_conformance.journal.run_lock import RunLock, acquire_run_lock
from webhook_receiver_conformance.journal.schedules import (
    FullRunCompletionRequest,
    PersistedScheduleEntry,
    PersistentScheduleRepository,
)
from webhook_receiver_conformance.journal.schema import (
    JOURNAL_FILENAME,
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
    ProjectionState,
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
    load_replay_bundle,
)
from webhook_receiver_conformance.manifest.reduction import (
    materialize_verified_replay_bundle,
)
from webhook_receiver_conformance.network.dialer import DialTimeouts, PinnedDestinationDialer
from webhook_receiver_conformance.network.policy import (
    DestinationPolicy,
    parse_destination_policy,
)
from webhook_receiver_conformance.network.preflight import (
    PublicTargetPreflightEvidence,
    preflight_public_target,
)
from webhook_receiver_conformance.network.transport import (
    AnyIOConnector,
    AnyIOResolver,
)
from webhook_receiver_conformance.observers.polling import (
    ObservationPollOutcome,
    ObservationPollResult,
)
from webhook_receiver_conformance.observers.protocol import (
    ObservationRecord,
    ObserverCapabilities,
    ObserverEvidence,
    ObserverResponse,
    ObserverResponseStatus,
    ObserverWireError,
)
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
from webhook_receiver_conformance.runtime.reporting import (
    ALL_REPORT_FORMATS,
    regenerate_run_reports,
)
from webhook_receiver_conformance.runtime.resume import ResumeResult, ResumeStatus
from webhook_receiver_conformance.runtime.verdicts import (
    AssertionErrorOrigin,
    TerminalVerdict,
    classify_assertion_verdict,
    classify_attempt_verdict,
    reduce_terminal_verdicts,
    terminal_verdict,
)
from webhook_receiver_conformance.scheduler.barriers import (
    BarrierRelease,
    ConcurrencyWork,
    run_concurrency_groups,
)
from webhook_receiver_conformance.scheduler.clocks import RuntimeClock, TransitionTimestamp
from webhook_receiver_conformance.scheduler.queue import ScheduleItem
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
    """One scenario reduction, including a still-running resumable ambiguity."""

    scenario_id: str
    result_category: ResultCategory
    state: ScenarioState


@dataclass(frozen=True, slots=True)
class FullRunResult:
    """Completed or resumably paused run facts with exported evidence."""

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
class FullRunResumePreparation:
    """Read-only verified bundle identity prepared before recovery mutation."""

    run_directory: Path
    manifest_id: str
    _request: FullRunRequest = field(repr=False, compare=False)
    _bundle: _ExecutionBundle = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.run_directory,
                Path,
            )
            or not self.run_directory.is_absolute()
        ):
            raise ValueError("run_directory must be an absolute Path")
        if (
            type(self.manifest_id) is not str
            or len(self.manifest_id) != _MANIFEST_ID_LENGTH
            or any(character not in "0123456789abcdef" for character in self.manifest_id)
        ):
            raise ValueError("manifest_id must be a lowercase SHA-256 identifier")
        if type(self._bundle) is not _ExecutionBundle:
            raise TypeError("prepared resume bundle must be an _ExecutionBundle")
        if type(self._request) is not FullRunRequest:
            raise TypeError("prepared resume request must be a FullRunRequest")
        if self._bundle.manifest.manifest_id != self.manifest_id:
            raise ValueError("prepared resume bundle identity is inconsistent")

    def verified_bundle(
        self,
        request: FullRunRequest,
        run_directory: Path,
    ) -> _ExecutionBundle:
        """Return the bundle only to the exact request and directory that prepared it."""
        if request is not self._request or run_directory != self.run_directory:
            raise ValueError("resume preparation identity is inconsistent")
        return self._bundle


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


@dataclass(frozen=True, slots=True)
class _RetainedBodyLocation:
    offset: int
    byte_length: int


class _RetainedRequestBodies:
    """Private pre-gate body spool with a bounded one-body read interface."""

    __slots__ = ("_closed", "_locations", "_released", "_stream")

    def __init__(
        self,
        stream: BinaryIO,
        locations: Mapping[str, _RetainedBodyLocation],
    ) -> None:
        self._stream = stream
        self._locations = dict(locations)
        self._closed = False
        self._released = False

    @property
    def digests(self) -> frozenset[str]:
        """Return the unique runnable body digests retained in this spool."""
        return frozenset(self._locations)

    @property
    def closed(self) -> bool:
        """Return whether the spool and its index have been released."""
        return self._closed

    def read(self, digest: str) -> bytes:
        """Read and reverify one bounded body from the private retained spool."""
        if self._released:
            raise RuntimeError("validated resume request body spool is closed")
        try:
            location = self._locations[digest]
        except KeyError:
            raise RuntimeError("validated resume lacks its retained request body") from None
        self._stream.seek(location.offset)
        body = self._stream.read(location.byte_length)
        if len(body) != location.byte_length or sha256_digest(body) != digest:
            raise RuntimeError("validated resume request body spool failed integrity")
        return body

    def close(self) -> None:
        """Clear the index and close the anonymous backing file exactly once."""
        if self._closed:
            return
        self._released = True
        try:
            self._stream.close()
        finally:
            self._closed = self._stream.closed
            self._locations.clear()


class _PreparedLoadedPhase(StrEnum):
    ISSUED = "issued"
    CONSUMING = "consuming"
    CLOSED = "closed"


@dataclass(eq=False, slots=True)
class FullRunLoadedPreparation:
    """Opaque, single-use loaded execution snapshot prepared before public contact."""

    _request: FullRunRequest = field(repr=False)
    _source: LoadedRunBundle = field(repr=False)
    _bundle: _ExecutionBundle = field(repr=False)
    _request_bodies: _RetainedRequestBodies | None = field(repr=False)
    _temporary_directory: tempfile.TemporaryDirectory[str] | None = field(repr=False)
    _runner_token: object | None = field(repr=False)
    _phase: _PreparedLoadedPhase = field(
        default=_PreparedLoadedPhase.ISSUED,
        init=False,
        repr=False,
    )

    @property
    def is_closed(self) -> bool:
        """Return whether all retained snapshot resources have been released."""
        return self._phase is _PreparedLoadedPhase.CLOSED

    def claim(
        self,
        runner_token: object,
    ) -> tuple[
        FullRunRequest,
        LoadedRunBundle,
        _ExecutionBundle,
        _RetainedRequestBodies,
    ]:
        if self._phase is _PreparedLoadedPhase.CONSUMING:
            raise ValueError("prepared loaded execution is already being consumed")
        if self._phase is _PreparedLoadedPhase.CLOSED:
            raise ValueError("prepared loaded execution has already been consumed")
        if self._runner_token is not runner_token:
            raise ValueError("prepared loaded execution belongs to a different runner instance")
        request_bodies = self._request_bodies
        if type(request_bodies) is not _RetainedRequestBodies:
            raise RuntimeError("prepared loaded execution released its request body spool")
        self._phase = _PreparedLoadedPhase.CONSUMING
        return self._request, self._source, self._bundle, request_bodies

    def close(self) -> None:
        """Release the anonymous body spool and private bundle snapshot exactly once."""
        if self._phase is _PreparedLoadedPhase.CLOSED:
            return
        self._phase = _PreparedLoadedPhase.CLOSED
        request_bodies = self._request_bodies
        temporary_directory = self._temporary_directory
        self._request_bodies = None
        self._temporary_directory = None
        self._runner_token = None
        failures: list[BaseException] = []
        try:
            if request_bodies is not None:
                request_bodies.close()
        except BaseException as spool_error:  # noqa: BLE001
            failures.append(spool_error)
        try:
            if temporary_directory is not None:
                temporary_directory.cleanup()
        except BaseException as directory_error:  # noqa: BLE001
            failures.append(directory_error)
        if failures:
            _raise_cleanup_failures(
                None,
                failures,
                message="prepared loaded execution cleanup failed",
            )


def _exception_contains(
    container: BaseException,
    candidate: BaseException,
) -> bool:
    if container is candidate:
        return True
    if isinstance(container, BaseExceptionGroup):
        group = cast("BaseExceptionGroup[BaseException]", container)
        return any(_exception_contains(item, candidate) for item in group.exceptions)
    return False


def _raise_cleanup_failures(
    primary: BaseException | None,
    failures: list[BaseException],
    *,
    message: str,
) -> None:
    combined = list(failures)
    if primary is not None and not any(_exception_contains(item, primary) for item in combined):
        combined.insert(0, primary)
    if len(combined) == 1:
        raise combined[0]
    raise BaseExceptionGroup(message, combined)


@dataclass(frozen=True, slots=True)
class FullRunPublicPreflight:
    """Trusted nonce-challenge implementation injected when a runner is built."""

    dialer: PinnedDestinationDialer = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.dialer) is not PinnedDestinationDialer:
            raise TypeError("dialer must be a PinnedDestinationDialer")

    async def challenge(
        self,
        config: ProjectConfig,
        runtime_public_authorization: str | None,
    ) -> PublicTargetPreflightEvidence:
        """Run the fixed public nonce protocol; callers cannot supply evidence."""
        timeouts = config.receiver.timeouts
        evidence = await preflight_public_target(
            config.receiver,
            runtime_public_authorization=runtime_public_authorization,
            dialer=self.dialer,
            dial_timeouts=DialTimeouts(
                resolve_nanoseconds=timeouts.connect.nanoseconds,
                connect_nanoseconds=timeouts.connect.nanoseconds,
                close_nanoseconds=timeouts.pool.nanoseconds,
            ),
        )
        if type(evidence) is not PublicTargetPreflightEvidence:
            raise RuntimeError("public preflight did not return validated challenge evidence")
        return evidence


class _ResumeAuthorizationPhase(StrEnum):
    ISSUED = "issued"
    CHALLENGING = "challenging"
    CHALLENGED = "challenged"
    CONSUMING = "consuming"
    CLOSED = "closed"


@dataclass(slots=True)
class _ResumeAuthorization:
    phase: _ResumeAuthorizationPhase = _ResumeAuthorizationPhase.ISSUED
    evidence: PublicTargetPreflightEvidence | None = None


def _validate_public_challenge_evidence(
    evidence: PublicTargetPreflightEvidence,
    *,
    authorization: _ResumeAuthorization,
    registered: _ResumeAuthorization | None,
    policy: DestinationPolicy,
) -> None:
    if (
        registered is not authorization
        or authorization.phase is not _ResumeAuthorizationPhase.CHALLENGING
    ):
        raise ValueError("validated resume closed during its public challenge")
    if (
        evidence.authority != policy.destination.authority
        or evidence.challenge_path != policy.public_challenge_path
        or evidence.fixture_bytes_sent
    ):
        raise ValueError("public challenge evidence differs from the validated target")


@dataclass(eq=False, slots=True, weakref_slot=True)
class FullRunResumeValidation:
    """Offline-validated resume inputs ready for the final public contact gate."""

    request: FullRunRequest = field(repr=False, compare=False)
    result: ResumeResult = field(repr=False, compare=False)
    run: RunDatabase
    clock: RuntimeClock = field(repr=False, compare=False)
    bundle: _ExecutionBundle = field(repr=False, compare=False)
    projection_states: Mapping[
        tuple[EntityType, str],
        LifecycleState,
    ] = field(repr=False, compare=False)
    existing_attempts: tuple[FullAttemptResult, ...] = field(repr=False, compare=False)
    existing_attempt_evidence: Mapping[str, PersistedAttemptEvidence] = field(
        repr=False,
        compare=False,
    )
    initial_delivery_verdicts: Mapping[str, TerminalVerdict] = field(
        repr=False,
        compare=False,
    )
    request_bodies: _RetainedRequestBodies | None = field(repr=False, compare=False)
    executor: HttpAttemptExecutor | None = field(repr=False, compare=False)
    policy: DestinationPolicy = field(repr=False, compare=False)
    generator: ContextGenerator = field(repr=False, compare=False)
    observer_assertion_executor: ObserverAssertionExecutor | None = field(
        repr=False,
        compare=False,
    )
    scoped_observer_executor: ScopedObserverAssertionExecutor | None = field(
        repr=False,
        compare=False,
    )
    service: JournalService = field(repr=False, compare=False)
    transitions: TransitionRepository = field(repr=False, compare=False)
    schedules: PersistentScheduleRepository = field(repr=False, compare=False)
    _service_manager: AbstractAsyncContextManager[JournalService] = field(
        repr=False,
        compare=False,
    )
    _runner_token: object | None = field(repr=False, compare=False)
    _unregister: Callable[[FullRunResumeValidation], None] | None = field(
        repr=False,
        compare=False,
    )
    _closed: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:  # noqa: C901, PLR0912
        if type(self.request) is not FullRunRequest:
            raise TypeError("request must be a FullRunRequest")
        if type(self.result) is not ResumeResult:
            raise TypeError("result must be a ResumeResult")
        if type(self.run) is not RunDatabase:
            raise TypeError("run must be a RunDatabase")
        if type(self.clock) is not RuntimeClock:
            raise TypeError("clock must be a RuntimeClock")
        if type(self.bundle) is not _ExecutionBundle:
            raise TypeError("bundle must be an _ExecutionBundle")
        if type(self.executor) is not HttpAttemptExecutor:
            raise TypeError("executor must be an HttpAttemptExecutor")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.existing_attempt_evidence,
            Mapping,
        ) or any(
            type(attempt_id) is not str or type(value) is not PersistedAttemptEvidence
            for attempt_id, value in self.existing_attempt_evidence.items()
        ):
            raise TypeError("existing_attempt_evidence must map attempt IDs to persisted evidence")
        if type(self.request_bodies) is not _RetainedRequestBodies:
            raise TypeError("request_bodies must be a retained request body spool")
        if self.scoped_observer_executor is not None and not callable(
            getattr(self.scoped_observer_executor, "evaluate_scoped", None)
        ):
            raise TypeError("scoped_observer_executor must implement evaluate_scoped")
        if self.observer_assertion_executor is not None and not callable(
            getattr(self.observer_assertion_executor, "evaluate", None)
        ):
            raise TypeError("observer_assertion_executor must implement evaluate")
        if type(self.service) is not JournalService:
            raise TypeError("service must be a JournalService")
        if type(self.transitions) is not TransitionRepository:
            raise TypeError("transitions must be a TransitionRepository")
        if type(self.schedules) is not PersistentScheduleRepository:
            raise TypeError("schedules must be a PersistentScheduleRepository")
        if self.run.run_id != self.result.run_id:
            raise ValueError("validated resume run identity is inconsistent")

    @property
    def is_closed(self) -> bool:
        """Return whether this retained validation has released its journal scope."""
        return self._closed

    @property
    def retained_resources_released(self) -> bool:
        """Return whether heavyweight post-gate resources have been detached."""
        return (
            self._closed
            and self.request_bodies is None
            and self.executor is None
            and self.observer_assertion_executor is None
            and self.scoped_observer_executor is None
        )

    def require_runner(self, runner_token: object) -> None:
        """Reject cross-runner use before any contact or retained execution."""
        if self._closed or self._runner_token is not runner_token:
            raise ValueError("validated resume belongs to a different runner instance")

    async def aclose(self, error: BaseException | None = None) -> None:
        """Release the retained validated journal service exactly once."""
        if self._closed:
            return
        self._closed = True
        unregister = self._unregister
        request_bodies = self.request_bodies
        self._unregister = None
        self._runner_token = None
        self.request_bodies = None
        self.executor = None
        self.observer_assertion_executor = None
        self.scoped_observer_executor = None
        failures: list[BaseException] = []
        try:
            if unregister is not None:
                unregister(self)
        except BaseException as unregister_error:  # noqa: BLE001
            failures.append(unregister_error)
        try:
            await self._service_manager.__aexit__(
                None if error is None else type(error),
                error,
                None if error is None else error.__traceback__,
            )
        except BaseException as service_error:  # noqa: BLE001
            failures.append(service_error)
        try:
            if request_bodies is not None:
                request_bodies.close()
        except BaseException as spool_error:  # noqa: BLE001
            failures.append(spool_error)
        if failures:
            _raise_cleanup_failures(
                error,
                failures,
                message="validated resume and cleanup both failed",
            )


class FullRunRunner:
    """Execute all manifest deliveries through durable schedule and evidence seams."""

    __slots__ = (
        "_clock_factory",
        "_executor_factory",
        "_journal",
        "_observer_assertion_factory",
        "_observer_assertions",
        "_public_resume_preflight",
        "_resume_authorizations",
        "_runner_token",
    )

    def __init__(
        self,
        *,
        journal: JournalLifecycle,
        executor_factory: ExecutorFactory | None = None,
        clock_factory: ClockFactory | None = None,
        observer_assertion_executor: ObserverAssertionExecutor | None = None,
        observer_assertion_executor_factory: ObserverAssertionExecutorFactory | None = None,
        public_resume_preflight: FullRunPublicPreflight | None = None,
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
        if (
            public_resume_preflight is not None
            and type(public_resume_preflight) is not FullRunPublicPreflight
        ):
            raise TypeError("public_resume_preflight must be a FullRunPublicPreflight")
        self._journal = journal
        self._executor_factory = _default_executor if executor_factory is None else executor_factory
        self._clock_factory = _default_clock if clock_factory is None else clock_factory
        self._observer_assertions = observer_assertion_executor
        self._observer_assertion_factory = observer_assertion_executor_factory
        self._public_resume_preflight = public_resume_preflight
        self._resume_authorizations: weakref.WeakKeyDictionary[
            FullRunResumeValidation,
            _ResumeAuthorization,
        ] = weakref.WeakKeyDictionary()
        self._runner_token = object()

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
        """Prepare and execute one loaded bundle without an intervening contact gate."""
        preparation = self.prepare_loaded(request, bundle)
        return await self.run_prepared_loaded(preparation)

    def validate_loaded(
        self,
        request: FullRunRequest,
        bundle: LoadedRunBundle,
    ) -> None:
        """Validate loaded execution inputs without network or journal side effects."""
        preparation = self.prepare_loaded(request, bundle)
        preparation.close()

    def prepare_loaded(
        self,
        request: FullRunRequest,
        bundle: LoadedRunBundle,
    ) -> FullRunLoadedPreparation:
        """Freeze and verify every loaded input before a possible public nonce contact."""
        if type(request) is not FullRunRequest:
            raise TypeError("request must be a FullRunRequest")
        if type(bundle) is not LoadedRunBundle:
            raise TypeError("bundle must be a LoadedRunBundle")
        temporary_directory = tempfile.TemporaryDirectory(prefix="webhook-conformance-loaded-")
        request_bodies: _RetainedRequestBodies | None = None
        try:
            snapshot_directory = Path(temporary_directory.name) / "bundle"
            snapshot_directory.mkdir(mode=0o700)
            source = materialize_verified_replay_bundle(
                bundle,
                destination=snapshot_directory,
            )
            effective = _read_replay_effective_configuration(source)
            recipes = load_realized_execution(source.manifest, effective)
            _validate_replay_configuration(request, source, effective)
            execution_bundle = _ExecutionBundle.replay(source, recipes)
            _validate_full_bundle(execution_bundle, request.config)
            request_bodies = _materialize_required_request_bodies(
                execution_bundle,
                frozenset(recipe.request_blob for recipe in recipes),
            )
            return FullRunLoadedPreparation(
                _request=request,
                _source=source,
                _bundle=execution_bundle,
                _request_bodies=request_bodies,
                _temporary_directory=temporary_directory,
                _runner_token=self._runner_token,
            )
        except BaseException as error:
            failures: list[BaseException] = []
            try:
                if request_bodies is not None:
                    request_bodies.close()
            except BaseException as spool_error:  # noqa: BLE001
                failures.append(spool_error)
            try:
                temporary_directory.cleanup()
            except BaseException as directory_error:  # noqa: BLE001
                failures.append(directory_error)
            if failures:
                _raise_cleanup_failures(
                    error,
                    failures,
                    message="loaded execution preparation and cleanup both failed",
                )
            raise

    async def run_prepared_loaded(
        self,
        preparation: FullRunLoadedPreparation,
    ) -> FullRunResult:
        """Consume exactly one prepared loaded snapshot after its final contact gate."""
        if type(preparation) is not FullRunLoadedPreparation:
            raise TypeError("preparation must be a FullRunLoadedPreparation")
        request, source, prepared_bundle, request_bodies = preparation.claim(self._runner_token)
        primary: BaseException | None = None
        try:
            run = create_run_database(request.artifact_directory)
            clock = _require_runtime_clock(self._clock_factory(request.config.clock))
            with acquire_run_lock(
                run.run_directory,
                run_id=run.run_id,
                owner_epoch=request.owner_epoch,
            ):
                materialized = materialize_verified_replay_bundle(
                    source,
                    destination=run.run_directory,
                )
                execution_bundle = _ExecutionBundle.replay(
                    materialized,
                    prepared_bundle.realized_execution,
                )
                return await self._run_prepared(
                    request,
                    run=run,
                    clock=clock,
                    bundle=execution_bundle,
                    request_bodies=request_bodies,
                )
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                preparation.close()
            except BaseException as cleanup_error:  # noqa: BLE001
                _raise_cleanup_failures(
                    primary,
                    [cleanup_error],
                    message="loaded execution and cleanup both failed",
                )

    async def resume(
        self,
        request: FullRunRequest,
        result: ResumeResult,
        *,
        ownership: RunLock,
    ) -> FullRunResult:
        """Continue one verified run after conservative recovery planning.

        The resume service owns integrity verification, recovery classification, and
        owner-epoch advancement. This method consumes only a ``CONTINUE`` result,
        re-verifies the immutable bundle, and never bootstraps or allocates a run ID.
        """
        if type(request) is not FullRunRequest:
            raise TypeError("request must be a FullRunRequest")
        if request.config.receiver.target_profile is TargetProfile.PUBLIC_AUTHORIZED:
            raise ValueError(
                "public resume requires the explicit validate/challenge/resume capability workflow"
            )
        validation = await self.validate_resume(
            request,
            result,
            ownership=ownership,
        )
        return await self.resume_validated(
            validation,
            ownership=ownership,
        )

    async def validate_resume(  # noqa: C901, PLR0912, PLR0915
        self,
        request: FullRunRequest,
        result: ResumeResult,
        *,
        ownership: RunLock,
        preparation: FullRunResumePreparation | None = None,
    ) -> FullRunResumeValidation:
        """Validate every local resume invariant before a public contact gate."""
        if type(request) is not FullRunRequest:
            raise TypeError("request must be a FullRunRequest")
        if type(result) is not ResumeResult:
            raise TypeError("result must be a ResumeResult")
        if type(ownership) is not RunLock:
            raise TypeError("ownership must be a retained RunLock")
        plan = result.policy_plan
        if (
            result.status is not ResumeStatus.CONTINUE
            or result.read_only
            or plan is None
            or not plan.delivery_execution_allowed
        ):
            raise ValueError("runner continuation requires a mutable CONTINUE resume result")
        if (
            result.run_id != result.preflight.run_id
            or plan.run_id != result.run_id
            or plan.owner_epoch != result.owner_epoch
            or result.owner_epoch <= result.preflight.owner_epoch
        ):
            raise ValueError("resume result identity or owner epoch is inconsistent")

        run_directory = result.preflight.run_directory
        ownership.require_owner(
            run_directory,
            run_id=result.run_id,
            owner_epoch=result.owner_epoch,
        )
        if preparation is None:
            bundle = _prepare_full_resume_bundle(request, run_directory)
        else:
            if type(preparation) is not FullRunResumePreparation:
                raise TypeError("preparation must be a FullRunResumePreparation")
            bundle = preparation.verified_bundle(request, run_directory)
        run = RunDatabase(
            run_id=result.run_id,
            run_directory=run_directory,
            database_path=result.preflight.database_path,
        )
        clock = self._clock_factory(request.config.clock)
        if type(clock) is not RuntimeClock:
            raise TypeError("clock_factory must return a RuntimeClock")
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
        for recipe in bundle.realized_execution:
            _selected_signer(recipe, request.signers)
        service_manager = JournalService.open(run.database_path)
        service = await service_manager.__aenter__()
        request_bodies: _RetainedRequestBodies | None = None
        try:
            transitions = TransitionRepository(service)
            schedules = PersistentScheduleRepository(service)
            pending = await schedules.pending(run.run_id)
            _validate_resume_schedule(plan.runnable_schedule, plan.deferred_schedule, pending)

            projection_states = _projection_states(
                await transitions.projection_inventory(run.run_id)
            )
            _reject_terminal_resume_schedule_targets(
                bundle,
                pending=pending,
                projection_states=projection_states,
            )
            _validate_resume_activation_preflight(
                bundle,
                run_id=run.run_id,
                projection_states=projection_states,
            )
            initial_snapshot = await JournalReportReader(service).load(run.run_id)
            existing_attempts = _attempt_results(initial_snapshot)
            initial_delivery_verdicts = _existing_delivery_verdicts(
                bundle,
                existing_attempts,
                projection_states,
                scheduled_delivery_ids=frozenset(
                    _scheduled_plan(bundle, item)[1].delivery_id for item in pending
                ),
            )
            _validate_resume_execution_preflight(
                bundle,
                config=request.config,
                run_id=run.run_id,
                pending=pending,
                projection_states=projection_states,
                existing_attempts=existing_attempts,
                initial_delivery_verdicts=initial_delivery_verdicts,
                signers=request.signers,
            )
            existing_attempt_evidence = await _validate_resume_assertion_preflight(
                transitions=transitions,
                bundle=bundle,
                config=request.config,
                run_id=run.run_id,
                owner_epoch=result.owner_epoch,
                attempts=existing_attempts,
                delivery_verdicts=initial_delivery_verdicts,
                snapshot=initial_snapshot,
                projection_states=projection_states,
            )
            runnable_schedule_ids = {item.schedule_entry_id for item in plan.runnable_schedule}
            runnable_entries = tuple(
                item for item in pending if item.schedule_entry_id in runnable_schedule_ids
            )
            request_bodies = _materialize_request_bodies(
                bundle,
                runnable_entries,
            )
            scoped_observer_executor = self._scoped_observer_executor(
                service,
                clock=clock,
                request=request,
                owner_epoch=result.owner_epoch,
            )
            validation = FullRunResumeValidation(
                request=request,
                result=result,
                run=run,
                clock=clock,
                bundle=bundle,
                projection_states=MappingProxyType(projection_states),
                existing_attempts=existing_attempts,
                existing_attempt_evidence=MappingProxyType(existing_attempt_evidence),
                initial_delivery_verdicts=MappingProxyType(initial_delivery_verdicts),
                request_bodies=request_bodies,
                executor=executor,
                policy=policy,
                generator=generator,
                observer_assertion_executor=self._observer_assertions,
                scoped_observer_executor=scoped_observer_executor,
                service=service,
                transitions=transitions,
                schedules=schedules,
                _service_manager=service_manager,
                _runner_token=self._runner_token,
                _unregister=self._unregister_resume_validation,
            )
            self._resume_authorizations[validation] = _ResumeAuthorization()
        except BaseException as error:
            failures: list[BaseException] = []
            try:
                await service_manager.__aexit__(
                    None,
                    None,
                    None,
                )
            except BaseException as service_error:  # noqa: BLE001
                failures.append(service_error)
            try:
                if request_bodies is not None:
                    request_bodies.close()
            except BaseException as spool_error:  # noqa: BLE001
                failures.append(spool_error)
            if failures:
                _raise_cleanup_failures(
                    error,
                    failures,
                    message="resume validation and cleanup both failed",
                )
            raise
        else:
            request_bodies = None
            return validation

    def _unregister_resume_validation(
        self,
        validation: FullRunResumeValidation,
    ) -> None:
        authorization = self._resume_authorizations.pop(validation, None)
        if authorization is not None:
            authorization.phase = _ResumeAuthorizationPhase.CLOSED
            authorization.evidence = None

    def _claim_public_challenge(
        self,
        validation: FullRunResumeValidation,
    ) -> _ResumeAuthorization:
        validation.require_runner(self._runner_token)
        authorization = self._resume_authorizations.get(validation)
        if authorization is None:
            raise ValueError("validated resume is not registered with this runner")
        if authorization.phase is not _ResumeAuthorizationPhase.ISSUED:
            raise ValueError("public resume challenge is not in an issuable state")
        if validation.policy.target_profile is not TargetProfile.PUBLIC_AUTHORIZED:
            raise ValueError("a public challenge is valid only for a public target")
        if self._public_resume_preflight is None:
            raise ValueError("public resume requires a trusted runner preflight capability")
        authorization.phase = _ResumeAuthorizationPhase.CHALLENGING
        return authorization

    def _consume_resume_authorization(
        self,
        validation: FullRunResumeValidation,
    ) -> _ResumeAuthorization:
        validation.require_runner(self._runner_token)
        authorization = self._resume_authorizations.get(validation)
        if authorization is None:
            raise ValueError("validated resume is not registered with this runner")
        required_phase = (
            _ResumeAuthorizationPhase.CHALLENGED
            if validation.policy.target_profile is TargetProfile.PUBLIC_AUTHORIZED
            else _ResumeAuthorizationPhase.ISSUED
        )
        if authorization.phase is not required_phase:
            if authorization.phase is _ResumeAuthorizationPhase.CONSUMING:
                raise ValueError("validated resume is already being consumed")
            raise ValueError("validated resume lacks its required public challenge")
        authorization.phase = _ResumeAuthorizationPhase.CONSUMING
        return authorization

    async def challenge_public_resume(
        self,
        validation: FullRunResumeValidation,
        *,
        ownership: RunLock,
    ) -> None:
        """Challenge one validated public target through this runner's trusted gate."""
        if type(validation) is not FullRunResumeValidation:
            raise TypeError("validation must be a FullRunResumeValidation")
        if type(ownership) is not RunLock:
            raise TypeError("ownership must be a retained RunLock")
        claimed = False
        try:
            authorization = self._claim_public_challenge(validation)
            claimed = True
            preflight = cast("FullRunPublicPreflight", self._public_resume_preflight)
            ownership.require_owner(
                validation.run.run_directory,
                run_id=validation.result.run_id,
                owner_epoch=validation.result.owner_epoch,
            )
            authorization.phase = _ResumeAuthorizationPhase.CHALLENGING
            evidence = await preflight.challenge(
                validation.request.config,
                validation.request.runtime_public_authorization,
            )
            _validate_public_challenge_evidence(
                evidence,
                authorization=authorization,
                registered=self._resume_authorizations.get(validation),
                policy=validation.policy,
            )
            authorization.evidence = evidence
            authorization.phase = _ResumeAuthorizationPhase.CHALLENGED
        except BaseException as error:
            if claimed:
                try:
                    await validation.aclose()
                except BaseException as cleanup_error:  # noqa: BLE001
                    _raise_cleanup_failures(
                        error,
                        [cleanup_error],
                        message="public resume challenge and cleanup both failed",
                    )
            raise

    async def resume_validated(
        self,
        validation: FullRunResumeValidation,
        *,
        ownership: RunLock,
    ) -> FullRunResult:
        """Execute a validated resume immediately after its final contact gate."""
        if type(validation) is not FullRunResumeValidation:
            raise TypeError("validation must be a FullRunResumeValidation")
        if type(ownership) is not RunLock:
            raise TypeError("ownership must be a retained RunLock")
        claimed = False
        try:
            ownership.require_owner(
                validation.run.run_directory,
                run_id=validation.result.run_id,
                owner_epoch=validation.result.owner_epoch,
            )
            self._consume_resume_authorization(validation)
            claimed = True
            await _activate_resumed_run(
                validation.transitions,
                clock=validation.clock,
                run_id=validation.run.run_id,
                owner_epoch=validation.result.owner_epoch,
                bundle=validation.bundle,
                projection_states=validation.projection_states,
            )
            resumed = await self._resume_validated(validation)
        except BaseException as error:
            if claimed:
                await validation.aclose(error)
            raise
        else:
            await validation.aclose()
            return resumed

    async def prepare_resume(
        self,
        request: FullRunRequest,
        run_directory: Path,
        *,
        ownership: RunLock,
    ) -> FullRunResumePreparation:
        """Verify immutable resume inputs without ownership or external effects."""
        if type(request) is not FullRunRequest:
            raise TypeError("request must be a FullRunRequest")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            run_directory,
            Path,
        ):
            raise TypeError("run_directory must be a Path")
        if type(ownership) is not RunLock:
            raise TypeError("ownership must be a retained RunLock")
        resolved = await run_sync(partial(run_directory.resolve, strict=True))
        ownership.require_owner(
            resolved,
            run_id=ownership.metadata.run_id,
            owner_epoch=ownership.metadata.owner_epoch,
        )
        await run_sync(
            _reject_legacy_terminal_ambiguity,
            resolved / JOURNAL_FILENAME,
            ownership.metadata.run_id,
        )
        bundle = await run_sync(
            partial(
                _prepare_full_resume_bundle,
                request,
                resolved,
            )
        )
        return FullRunResumePreparation(
            run_directory=resolved,
            manifest_id=bundle.manifest.manifest_id,
            _request=request,
            _bundle=bundle,
        )

    async def _run_prepared(
        self,
        request: FullRunRequest,
        *,
        run: RunDatabase,
        clock: RuntimeClock,
        bundle: _ExecutionBundle,
        request_bodies: _RetainedRequestBodies | None = None,
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
                request_bodies=request_bodies,
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
            await _finalize_or_pause_full_run(
                schedules=schedules,
                transitions=transitions,
                run_id=run.run_id,
                owner_epoch=request.owner_epoch,
                verdict=verdict,
                completed_at=_canonical_utc(completed_at),
                timestamp=clock.transition_timestamp(),
                identity="full.run.finish",
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

    async def _resume_validated(
        self,
        validation: FullRunResumeValidation,
    ) -> FullRunResult:
        request = validation.request
        result = validation.result
        run = validation.run
        clock = validation.clock
        bundle = validation.bundle
        plan = result.policy_plan
        if plan is None:
            raise ValueError("resume continuation lacks a policy plan")
        executor = validation.executor
        if type(executor) is not HttpAttemptExecutor:
            raise RuntimeError("validated resume released its retained HTTP executor")
        request_bodies = validation.request_bodies
        if type(request_bodies) is not _RetainedRequestBodies:
            raise RuntimeError("validated resume released its retained request body spool")
        observer_executor = validation.observer_assertion_executor
        scoped_observer_executor = validation.scoped_observer_executor
        owner_epoch = result.owner_epoch
        with nullcontext(validation.service) as service:
            transitions = validation.transitions
            schedules = validation.schedules
            attempts, delivery_verdicts, releases = await _execute_schedules(
                schedules=schedules,
                transitions=transitions,
                executor=executor,
                clock=clock,
                bundle=bundle,
                config=request.config,
                run_id=run.run_id,
                owner_epoch=owner_epoch,
                policy=validation.policy,
                signers=request.signers,
                generator=validation.generator,
                request_bodies=request_bodies,
                existing_attempts=validation.existing_attempts,
                initial_delivery_verdicts=validation.initial_delivery_verdicts,
                blocked_schedule_ids=frozenset(
                    item.schedule_entry_id for item in plan.deferred_schedule
                ),
                delivery_states={
                    entity_id: cast("DeliveryState", state)
                    for (entity_type, entity_id), state in validation.projection_states.items()
                    if entity_type is EntityType.DELIVERY
                },
            )
            before_assertions = await JournalReportReader(service).load(run.run_id)
            projection_states = _projection_states(
                await transitions.projection_inventory(run.run_id)
            )
            (
                _assertion_records,
                _observations,
                scenario_results,
            ) = await _evaluate_full_assertions(
                service=service,
                transitions=transitions,
                clock=clock,
                bundle=bundle,
                config=request.config,
                run_id=run.run_id,
                owner_epoch=owner_epoch,
                attempts=attempts,
                delivery_verdicts=delivery_verdicts,
                observer_executor=observer_executor,
                scoped_observer_executor=scoped_observer_executor,
                existing_snapshot=before_assertions,
                projection_states=projection_states,
                prefetched_attempt_evidence=validation.existing_attempt_evidence,
                resume_execution=True,
            )
            verdict = reduce_terminal_verdicts(
                tuple(item.result_category for item in scenario_results)
            )
            completed_at = clock.wall_now()
            await _finalize_or_pause_full_run(
                schedules=schedules,
                transitions=transitions,
                run_id=run.run_id,
                owner_epoch=owner_epoch,
                verdict=verdict,
                completed_at=_canonical_utc(completed_at),
                timestamp=clock.transition_timestamp(),
                identity=f"resume.{owner_epoch}.run.finish",
            )
            reports = await regenerate_run_reports(
                run.run_directory,
                formats=ALL_REPORT_FORMATS,
                service=service,
            )
            if (
                reports.run_id != run.run_id
                or reports.outcome.verdict is not verdict.category
                or reports.outcome.exit_code is not verdict.exit_code
            ):
                raise RuntimeError("regenerated resume reports differ from terminal journal state")
            final_snapshot = await JournalReportReader(service).load(run.run_id)

        return FullRunResult(
            run_id=run.run_id,
            manifest_id=bundle.manifest.manifest_id,
            run_directory=run.run_directory,
            database_path=run.database_path,
            attempts=_attempt_results(final_snapshot),
            assertions=tuple(item.record for item in final_snapshot.assertions),
            observations=tuple(
                ObservationReportRecord(
                    record=item.record,
                    scenario_ordinal=item.scenario_ordinal,
                    observation_ordinal=item.observation_ordinal,
                )
                for item in final_snapshot.observations
            ),
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
        owner_epoch: int | None = None,
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
                owner_epoch=request.owner_epoch if owner_epoch is None else owner_epoch,
            )
        )
        if not callable(getattr(executor, "evaluate_scoped", None)):
            raise TypeError("observer assertion executor factory returned an invalid executor")
        return executor


async def _execute_schedules(  # noqa: C901, PLR0915
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
    request_bodies: _RetainedRequestBodies | None = None,
    existing_attempts: tuple[FullAttemptResult, ...] = (),
    initial_delivery_verdicts: Mapping[str, TerminalVerdict] | None = None,
    blocked_schedule_ids: frozenset[str] = frozenset(),
    delivery_states: dict[str, DeliveryState] | None = None,
) -> tuple[
    tuple[FullAttemptResult, ...],
    Mapping[str, TerminalVerdict],
    tuple[BarrierRelease, ...],
]:
    attempts: list[_AttemptExecution] = []
    delivery_verdicts = dict(initial_delivery_verdicts or {})
    releases: list[BarrierRelease] = []
    logical_now_ns = 0
    mutable_delivery_states = {} if delivery_states is None else delivery_states

    async def execute(
        work: ConcurrencyWork[PersistedScheduleEntry],
    ) -> _AttemptExecution:
        entry = work.payload
        scenario, delivery, recipe = _scheduled_plan(bundle, entry)
        if entry.attempt_ordinal == 1:
            await _activate_delivery_from_state(
                transitions,
                clock=clock,
                run_id=run_id,
                owner_epoch=owner_epoch,
                delivery_id=delivery.delivery_id,
                state=mutable_delivery_states.get(
                    delivery.delivery_id,
                    DeliveryState.PENDING,
                ),
            )
            mutable_delivery_states[delivery.delivery_id] = DeliveryState.ACTIVE
        attempt_id = entry.prepared_attempt_id or new_fresh_id(FreshIdKind.ATTEMPT)
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
                body=(
                    _request_blob(bundle, recipe)
                    if request_bodies is None
                    else _retained_request_body(request_bodies, recipe)
                ),
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
        if terminal and realized.lifecycle.terminal_state is not AttemptState.UNKNOWN_OUTCOME:
            await _terminalize_delivery(
                transitions,
                context=context,
                terminal_state=realized.lifecycle.terminal_state,
                timestamp=clock.transition_timestamp(),
            )
            mutable_delivery_states[delivery.delivery_id] = _delivery_state_for_attempt(
                realized.lifecycle.terminal_state
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
        pending = tuple(
            item
            for item in await schedules.pending(run_id)
            if item.schedule_entry_id not in blocked_schedule_ids
        )
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
        sorted(
            (
                *existing_attempts,
                *(item.result for item in attempts),
            ),
            key=lambda item: (
                item.scenario_ordinal,
                item.delivery_ordinal,
                item.attempt_ordinal,
                item.evidence.sequence,
            ),
        )
    )
    if len({item.attempt_id for item in ordered_attempts}) != len(ordered_attempts):
        raise RuntimeError("attempt execution inventory contains duplicate identities")
    return ordered_attempts, delivery_verdicts, tuple(releases)


async def _validate_resume_assertion_preflight(  # noqa: C901, PLR0912, PLR0915
    *,
    transitions: TransitionRepository,
    bundle: _ExecutionBundle,
    config: ProjectConfig,
    run_id: str,
    owner_epoch: int,
    attempts: tuple[FullAttemptResult, ...],
    delivery_verdicts: Mapping[str, TerminalVerdict],
    snapshot: JournalReportSnapshot,
    projection_states: Mapping[tuple[EntityType, str], LifecycleState],
) -> dict[str, PersistedAttemptEvidence]:
    """Purely validate all retained assertion and observation recovery facts."""
    existing_assertions: dict[str, JournalReportAssertion] = {}
    for item in snapshot.assertions:
        assertion_id = item.record.assertion_id
        if assertion_id in existing_assertions:
            raise RuntimeError("assertion has more than one terminal evaluation")
        existing_assertions[assertion_id] = item

    persisted: dict[str, PersistedAttemptEvidence] = {}
    for item in attempts:
        evidence = await transitions.attempt_evidence(run_id, item.attempt_id)
        if evidence is None:
            raise RuntimeError("assertion input attempt evidence is missing")
        if evidence.attempt != item.evidence:
            raise RuntimeError(
                "assertion input attempt evidence changed across journal projections"
            )
        persisted[item.attempt_id] = evidence

    planned_assertion_ids = {
        assertion.assertion_id
        for scenario in bundle.manifest.scenarios
        for assertion in scenario.assertions
    }
    projected_assertion_ids = {
        entity_id
        for (entity_type, entity_id) in projection_states
        if entity_type is EntityType.ASSERTION
    }
    if projected_assertion_ids != planned_assertion_ids:
        raise RuntimeError("resume journal assertions differ from the verified manifest")
    if not set(existing_assertions) <= planned_assertion_ids:
        raise RuntimeError("assertion evaluation refers to an unknown planned assertion")

    observation_coordinates = tuple(
        (item.record.scenario_id, item.observation_ordinal) for item in snapshot.observations
    )
    if len(set(observation_coordinates)) != len(observation_coordinates):
        raise RuntimeError("durable observation ordering contains a duplicate coordinate")
    expected_observation_ids: set[str] = set()
    consumed_observation_ids: set[str] = set()

    for scenario_ordinal, (scenario, configured) in enumerate(
        zip(bundle.manifest.scenarios, config.scenarios, strict=True)
    ):
        scenario_attempts = tuple(
            persisted[item.attempt_id]
            for item in attempts
            if item.evidence.scenario_id == scenario.scenario_id
        )
        current_scenario_state = projection_states.get((EntityType.SCENARIO, scenario.scenario_id))
        if not isinstance(current_scenario_state, ScenarioState):
            raise RuntimeError("scenario projection has a non-scenario state")
        effective_scenario_state = (
            ScenarioState.RUNNING
            if current_scenario_state in {ScenarioState.PENDING, ScenarioState.ELIGIBLE}
            else current_scenario_state
        )
        scenario_delivery_verdicts = tuple(
            delivery_verdicts.get(item.delivery_id) for item in scenario.deliveries
        )
        if any(
            verdict is not None and verdict.category is ResultCategory.AMBIGUOUS
            for verdict in scenario_delivery_verdicts
        ):
            for plan in scenario.assertions:
                assertion_state = projection_states[(EntityType.ASSERTION, plan.assertion_id)]
                if (
                    assertion_state is not AssertionState.PENDING
                    or plan.assertion_id in existing_assertions
                ):
                    raise RuntimeError("ambiguous delivery requires untouched pending assertions")
            if effective_scenario_state is not ScenarioState.RUNNING:
                raise RuntimeError(
                    "ambiguous resumable delivery requires a running scenario projection"
                )
            continue

        assertion_categories: list[ResultCategory | None] = []
        for plan, assertion in zip(
            scenario.assertions,
            configured.assertions,
            strict=True,
        ):
            assertion_state = projection_states[(EntityType.ASSERTION, plan.assertion_id)]
            if not isinstance(assertion_state, AssertionState):
                raise RuntimeError("assertion projection has a non-assertion state")
            existing = existing_assertions.get(plan.assertion_id)
            if existing is not None:
                _validate_existing_assertion_projection(
                    existing,
                    run_id=run_id,
                    scenario_id=scenario.scenario_id,
                    scenario_ordinal=scenario_ordinal,
                    assertion_type=assertion.type,
                    assertion_state=assertion_state,
                )

            durable_observations: tuple[ObservationRecord, ...] = ()
            observation_state: ObservationState | None = None
            if type(assertion) in {
                HttpStatusAssertion,
                AcknowledgementDeadlineAssertion,
            }:
                _validate_transport_assertion_preflight(
                    assertion=cast(
                        "HttpStatusAssertion | AcknowledgementDeadlineAssertion",
                        assertion,
                    ),
                    configured_scenario=configured,
                    planned_scenario=scenario,
                    attempts=scenario_attempts,
                    require_selection=(
                        all(item is not None for item in scenario_delivery_verdicts)
                        or assertion_state is not AssertionState.PENDING
                        or existing is not None
                    ),
                )
            elif scenario_attempts:
                context = AssertionRuntimeContext(
                    run_id=run_id,
                    scenario_id=scenario.scenario_id,
                    assertion_id=plan.assertion_id,
                    owner_epoch=owner_epoch,
                )
                observer_id = _configured_observer_id(assertion)
                observation_id = _runner_observation_id(
                    context,
                    observer_id=observer_id,
                    event_id=scenario_attempts[-1].attempt.event_id,
                )
                expected_observation_ids.add(observation_id)
                durable_observations = _durable_assertion_observations(
                    snapshot,
                    context=context,
                    assertion=assertion,
                    attempts=scenario_attempts,
                )
                observation_state = _assertion_observation_projection_state(
                    projection_states,
                    context=context,
                    assertion=assertion,
                    attempts=scenario_attempts,
                )
                if durable_observations:
                    consumed_observation_ids.add(observation_id)
                    if observation_state is None:
                        raise RuntimeError(
                            "durable observer evidence lacks its observation projection"
                        )
                    _recovered_observer_bundle(assertion, durable_observations)
                elif observation_state is not None:
                    raise RuntimeError(
                        "interrupted observer invocation lacks a reusable durable sample"
                    )
            elif assertion_state is not AssertionState.PENDING or existing is not None:
                raise RuntimeError("observer assertion recovery lacks attempt scope evidence")

            if assertion_state is AssertionState.PENDING:
                if existing is not None:
                    raise RuntimeError("pending assertion already has a terminal evaluation")
                assertion_categories.append(None)
                continue
            if assertion_state is AssertionState.RUNNING:
                if existing is not None:
                    raise RuntimeError("running assertion already has a terminal evaluation")
                if not durable_observations:
                    raise RuntimeError(
                        "interrupted running assertion lacks durable observation evidence"
                    )
                assertion_categories.append(None)
                continue
            if existing is None:
                if assertion_state is not AssertionState.CANCELLED:
                    raise RuntimeError("terminal assertion lacks its immutable evaluation record")
                assertion_categories.append(ResultCategory.CANCELLED)
                continue
            assertion_categories.append(_existing_assertion_category(existing))

        unresolved = any(item is None for item in scenario_delivery_verdicts) or any(
            item is None for item in assertion_categories
        )
        if unresolved:
            if effective_scenario_state is not ScenarioState.RUNNING:
                raise RuntimeError("scenario with unresolved work must retain a running projection")
            continue
        reduced = reduce_terminal_verdicts(
            tuple(verdict.category for verdict in scenario_delivery_verdicts if verdict is not None)
            + tuple(category for category in assertion_categories if category is not None)
        )
        expected_scenario_state = _scenario_state(reduced.category)
        if (
            effective_scenario_state is not ScenarioState.RUNNING
            and effective_scenario_state is not expected_scenario_state
        ):
            raise RuntimeError("terminal scenario differs from resumed evidence reduction")

    projected_observation_ids = {
        entity_id
        for (entity_type, entity_id) in projection_states
        if entity_type is EntityType.OBSERVATION
    }
    sampled_observation_ids = {item.record.observation_id for item in snapshot.observations}
    if not projected_observation_ids <= expected_observation_ids:
        raise RuntimeError("resume journal observations differ from planned assertion scope")
    if sampled_observation_ids != consumed_observation_ids:
        raise RuntimeError("durable observer evidence differs from planned assertion scope")
    return persisted


def _validate_existing_assertion_projection(
    item: JournalReportAssertion,
    *,
    run_id: str,
    scenario_id: str,
    scenario_ordinal: int,
    assertion_type: str,
    assertion_state: AssertionState,
) -> None:
    record = item.record
    if (
        item.scenario_ordinal != scenario_ordinal
        or record.run_id != run_id
        or record.scenario_id != scenario_id
        or record.type != assertion_type
        or item.assertion_state is not assertion_state
    ):
        raise RuntimeError("assertion evaluation differs from its planned projection")
    allowed_states: Mapping[AssertionResult, frozenset[AssertionState]] = {
        AssertionResult.PASS: frozenset({AssertionState.PASSED}),
        AssertionResult.FAIL: frozenset({AssertionState.FAILED}),
        AssertionResult.ERROR: frozenset({AssertionState.ERROR, AssertionState.UNSUPPORTED}),
        AssertionResult.SKIPPED: frozenset({AssertionState.UNSUPPORTED}),
        AssertionResult.PENDING: frozenset(),
    }
    if assertion_state not in allowed_states[record.result]:
        raise RuntimeError("assertion evaluation result and projection state disagree")


def _validate_transport_assertion_preflight(
    *,
    assertion: HttpStatusAssertion | AcknowledgementDeadlineAssertion,
    configured_scenario: ScenarioConfig,
    planned_scenario: ScenarioPlan,
    attempts: tuple[PersistedAttemptEvidence, ...],
    require_selection: bool,
) -> None:
    event_id = _selected_event_id(
        configured_scenario,
        planned_scenario,
        assertion.attempt.event,
    )
    selected = tuple(item for item in attempts if item.attempt.event_id == event_id)
    if assertion.attempt.mode is AttemptMode.LAST_TERMINAL:
        selected = selected[-1:]
    if require_selection and not selected:
        raise RuntimeError("transport assertion selected no terminal attempt")
    for item in selected:
        evaluate_transport_assertion(
            assertion,
            TransportAssertionInput(
                attempt=item.attempt,
                response_headers_elapsed_ns=item.response_headers_elapsed_ns,
            ),
        )


async def _evaluate_full_assertions(  # noqa: C901, PLR0912, PLR0915
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
    existing_snapshot: JournalReportSnapshot | None = None,
    projection_states: Mapping[
        tuple[EntityType, str],
        LifecycleState,
    ]
    | None = None,
    prefetched_attempt_evidence: Mapping[str, PersistedAttemptEvidence] | None = None,
    resume_execution: bool = False,
) -> tuple[
    tuple[tuple[AssertionEvaluation, int, int], ...],
    tuple[ObservationReportRecord, ...],
    tuple[FullScenarioResult, ...],
]:
    assertions: list[tuple[AssertionEvaluation, int, int]] = []
    observations = (
        []
        if existing_snapshot is None
        else [
            ObservationReportRecord(
                record=item.record,
                scenario_ordinal=item.scenario_ordinal,
                observation_ordinal=item.observation_ordinal,
            )
            for item in existing_snapshot.observations
        ]
    )
    scenario_results: list[FullScenarioResult] = []
    repository = AssertionRepository(service)
    states = {} if projection_states is None else dict(projection_states)
    existing_assertions: dict[str, JournalReportAssertion] = {}
    if existing_snapshot is not None:
        for item in existing_snapshot.assertions:
            assertion_id = item.record.assertion_id
            if assertion_id in existing_assertions:
                raise RuntimeError("assertion has more than one terminal evaluation")
            existing_assertions[assertion_id] = item
    persisted_by_attempt: dict[str, PersistedAttemptEvidence | None] = dict(
        prefetched_attempt_evidence or {}
    )
    for item in attempts:
        if item.attempt_id not in persisted_by_attempt:
            persisted_by_attempt[item.attempt_id] = await transitions.attempt_evidence(
                run_id,
                item.attempt_id,
            )
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
        observation_ordinal = 1 + max(
            (
                item.observation_ordinal
                for item in (existing_snapshot.observations if existing_snapshot else ())
                if item.record.scenario_id == scenario.scenario_id
            ),
            default=-1,
        )
        scenario_attempts = tuple(
            persisted[item.attempt_id]
            for item in attempts
            if item.evidence.scenario_id == scenario.scenario_id
        )
        delivery_categories = tuple(
            delivery_verdicts[item.delivery_id].category for item in scenario.deliveries
        )
        if ResultCategory.AMBIGUOUS in delivery_categories:
            for plan in scenario.assertions:
                assertion_state = states.get(
                    (EntityType.ASSERTION, plan.assertion_id),
                    AssertionState.PENDING,
                )
                if (
                    assertion_state is not AssertionState.PENDING
                    or plan.assertion_id in existing_assertions
                ):
                    raise RuntimeError("ambiguous delivery requires untouched pending assertions")
            current_scenario_state = states.get(
                (EntityType.SCENARIO, scenario.scenario_id),
                ScenarioState.RUNNING,
            )
            if current_scenario_state is not ScenarioState.RUNNING:
                raise RuntimeError(
                    "ambiguous resumable delivery requires a running scenario projection"
                )
            scenario_results.append(
                FullScenarioResult(
                    scenario_id=scenario.scenario_id,
                    result_category=ResultCategory.AMBIGUOUS,
                    state=ScenarioState.RUNNING,
                )
            )
            continue
        assertion_verdicts: list[ResultCategory] = []
        for assertion_ordinal, (plan, assertion) in enumerate(
            zip(scenario.assertions, configured.assertions, strict=True)
        ):
            assertion_state = states.get(
                (EntityType.ASSERTION, plan.assertion_id),
                AssertionState.PENDING,
            )
            if not isinstance(assertion_state, AssertionState):
                raise RuntimeError("assertion projection has a non-assertion state")
            existing = existing_assertions.get(plan.assertion_id)
            durable_observations = _durable_assertion_observations(
                existing_snapshot,
                context=AssertionRuntimeContext(
                    run_id=run_id,
                    scenario_id=scenario.scenario_id,
                    assertion_id=plan.assertion_id,
                    owner_epoch=owner_epoch,
                ),
                assertion=assertion,
                attempts=scenario_attempts,
            )
            interrupted_observation_state = _assertion_observation_projection_state(
                states,
                context=AssertionRuntimeContext(
                    run_id=run_id,
                    scenario_id=scenario.scenario_id,
                    assertion_id=plan.assertion_id,
                    owner_epoch=owner_epoch,
                ),
                assertion=assertion,
                attempts=scenario_attempts,
            )
            if (
                resume_execution
                and not durable_observations
                and interrupted_observation_state is not None
            ):
                raise RuntimeError(
                    "interrupted observer invocation lacks a reusable durable sample"
                )
            if assertion_state is not AssertionState.PENDING:
                if assertion_state is AssertionState.RUNNING:
                    if existing is not None:
                        raise RuntimeError("running assertion already has a terminal evaluation")
                    if not durable_observations:
                        raise RuntimeError(
                            "interrupted running assertion lacks durable observation evidence"
                        )
                    lifecycle = AssertionLifecycle(repository=repository, clock=clock)
                    context = AssertionRuntimeContext(
                        run_id=run_id,
                        scenario_id=scenario.scenario_id,
                        assertion_id=plan.assertion_id,
                        owner_epoch=owner_epoch,
                    )
                    execution = ObserverAssertionExecution(
                        await lifecycle.evaluate_recovered(
                            context,
                            assertion,
                            _recovered_observer_bundle(
                                assertion,
                                durable_observations,
                            ),
                            expected_state=AssertionState.RUNNING,
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
                    continue
                if existing is None:
                    if assertion_state is not AssertionState.CANCELLED:
                        raise RuntimeError(
                            "terminal assertion lacks its immutable evaluation record"
                        )
                    assertion_verdicts.append(ResultCategory.CANCELLED)
                    continue
                assertions.append(
                    (
                        existing.record,
                        scenario_ordinal,
                        assertion_ordinal,
                    )
                )
                assertion_verdicts.append(_existing_assertion_category(existing))
                continue
            if existing is not None:
                raise RuntimeError("pending assertion already has a terminal evaluation")
            lifecycle = AssertionLifecycle(repository=repository, clock=clock)
            context = AssertionRuntimeContext(
                run_id=run_id,
                scenario_id=scenario.scenario_id,
                assertion_id=plan.assertion_id,
                owner_epoch=owner_epoch,
            )
            if durable_observations:
                execution = ObserverAssertionExecution(
                    await lifecycle.evaluate_recovered(
                        context,
                        assertion,
                        _recovered_observer_bundle(
                            assertion,
                            durable_observations,
                        ),
                        expected_state=AssertionState.PENDING,
                    )
                )
            elif type(assertion) in {
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

        scenario_verdict = reduce_terminal_verdicts((*delivery_categories, *assertion_verdicts))
        scenario_state = _scenario_state(scenario_verdict.category)
        current_scenario_state = states.get(
            (EntityType.SCENARIO, scenario.scenario_id),
            ScenarioState.RUNNING,
        )
        if not isinstance(current_scenario_state, ScenarioState):
            raise RuntimeError("scenario projection has a non-scenario state")
        if current_scenario_state is ScenarioState.RUNNING:
            identity = (
                f"resume.{owner_epoch}.scenario.finish.{scenario.scenario_id}"
                if resume_execution
                else f"full.scenario.finish.{scenario.scenario_id}"
            )
            await transitions.apply(
                TransitionCommand(
                    run_id=run_id,
                    transition_id=identity,
                    entity_type=EntityType.SCENARIO,
                    entity_id=scenario.scenario_id,
                    expected_state=ScenarioState.RUNNING,
                    new_state=scenario_state,
                    trigger_category="scenario_reduction",
                    timestamp=clock.transition_timestamp(),
                    owner_epoch=owner_epoch,
                    idempotency_key=identity,
                )
            )
        elif current_scenario_state is not scenario_state:
            raise RuntimeError("terminal scenario differs from resumed evidence reduction")
        scenario_results.append(
            FullScenarioResult(
                scenario_id=scenario.scenario_id,
                result_category=scenario_verdict.category,
                state=scenario_state,
            )
        )
    return tuple(assertions), tuple(observations), tuple(scenario_results)


def _durable_assertion_observations(
    snapshot: JournalReportSnapshot | None,
    *,
    context: AssertionRuntimeContext,
    assertion: AssertionConfig,
    attempts: tuple[PersistedAttemptEvidence, ...],
) -> tuple[ObservationRecord, ...]:
    if snapshot is None or type(assertion) in {
        HttpStatusAssertion,
        AcknowledgementDeadlineAssertion,
    }:
        return ()
    if not attempts:
        raise RuntimeError("observer assertion recovery lacks attempt scope evidence")
    observer_id = _configured_observer_id(assertion)
    event_id = attempts[-1].attempt.event_id
    expected_id = _runner_observation_id(
        context,
        observer_id=observer_id,
        event_id=event_id,
    )
    records = tuple(
        item.record for item in snapshot.observations if item.record.observation_id == expected_id
    )
    if not records:
        return ()
    if any(
        record.run_id != context.run_id
        or record.scenario_id != context.scenario_id
        or record.observer_id != observer_id
        or record.event_id != event_id
        for record in records
    ):
        raise RuntimeError("durable observer evidence differs from assertion scope")
    ordered = tuple(sorted(records, key=lambda item: item.sample_sequence))
    if tuple(item.sample_sequence for item in ordered) != tuple(range(1, len(ordered) + 1)):
        raise RuntimeError("durable observer sample sequence is incomplete")
    return ordered


def _assertion_observation_projection_state(
    states: Mapping[tuple[EntityType, str], LifecycleState],
    *,
    context: AssertionRuntimeContext,
    assertion: AssertionConfig,
    attempts: tuple[PersistedAttemptEvidence, ...],
) -> ObservationState | None:
    if type(assertion) in {HttpStatusAssertion, AcknowledgementDeadlineAssertion}:
        return None
    if not attempts:
        raise RuntimeError("observer assertion recovery lacks attempt scope evidence")
    observation_id = _runner_observation_id(
        context,
        observer_id=_configured_observer_id(assertion),
        event_id=attempts[-1].attempt.event_id,
    )
    state = states.get((EntityType.OBSERVATION, observation_id))
    if state is not None and not isinstance(state, ObservationState):
        raise RuntimeError("observer assertion projection has a non-observation state")
    return state


def _configured_observer_id(assertion: AssertionConfig) -> str:
    if type(assertion) is NoPartialSideEffectAssertion:
        identifiers = {item.query.observer for item in assertion.predicates}
        if len(identifiers) != 1:
            raise ValueError("composite predicates must use one observer")
        return next(iter(identifiers))
    query = getattr(assertion, "query", None)
    observer_id = getattr(query, "observer", None)
    if type(observer_id) is not str or not observer_id:
        raise TypeError("observer assertion lacks a configured observer identity")
    return observer_id


def _runner_observation_id(
    context: AssertionRuntimeContext,
    *,
    observer_id: str,
    event_id: str,
) -> str:
    components = (
        "runner-observation-v1",
        context.scenario_id,
        context.assertion_id,
        event_id,
        observer_id,
    )
    digest = hashlib.sha256("\x00".join(components).encode()).digest()
    return f"observation_{encode_crockford_ulid(digest[:16])}"


def _recovered_observer_bundle(
    assertion: AssertionConfig,
    records: tuple[ObservationRecord, ...],
) -> AssertionEvidenceBundle:
    if not records:
        raise ValueError("recovered observer evaluation requires durable samples")
    poll_result = _recovered_poll_result(assertion, records)
    if type(assertion) is EventualStateAssertion:
        payload: tuple[ObserverEvidence, ...] | ObservationPollResult | ObserverResponse = (
            poll_result
        )
    elif type(assertion) is NoPartialSideEffectAssertion:
        payload = (
            poll_result.last_response
            if (
                poll_result.outcome is not ObservationPollOutcome.ERROR
                and poll_result.last_response is not None
            )
            else _recovered_error_response(records)
        )
    else:
        payload = (
            ()
            if (
                poll_result.outcome is ObservationPollOutcome.ERROR
                or poll_result.last_response is None
            )
            else poll_result.last_response.evidence
        )
    return AssertionEvidenceBundle(
        payload=payload,
        references=tuple(
            AssertionEvidenceReference(
                AssertionEvidenceKind.OBSERVATION,
                record.sample_id,
            )
            for record in records
        ),
    )


def _recovered_poll_result(
    assertion: AssertionConfig,
    records: tuple[ObservationRecord, ...],
) -> ObservationPollResult:
    terminal = records[-1]
    response_record = next(
        (record for record in reversed(records) if record.status is not ObservationStatus.TIMEOUT),
        None,
    )
    last_response = (
        None if response_record is None else _response_from_record(response_record, records)
    )
    outcome = {
        ObservationStatus.PENDING: ObservationPollOutcome.PENDING,
        ObservationStatus.UNSUPPORTED: ObservationPollOutcome.UNSUPPORTED,
        ObservationStatus.ERROR: ObservationPollOutcome.ERROR,
        ObservationStatus.TIMEOUT: ObservationPollOutcome.TIMED_OUT,
    }.get(terminal.status)
    predicate_matched = False
    if terminal.status is ObservationStatus.OK:
        if last_response is None:
            raise RuntimeError("ok durable observation lacks its response projection")
        predicate_matched = (
            eventual_state_predicate(assertion)(last_response)
            if type(assertion) is EventualStateAssertion
            else True
        )
        outcome = (
            ObservationPollOutcome.MATCHED if predicate_matched else ObservationPollOutcome.MISMATCH
        )
    if outcome is None:
        raise RuntimeError("durable observation has an unsupported terminal status")
    return ObservationPollResult(
        outcome=outcome,
        final_state={
            ObservationStatus.OK: ObservationState.OK,
            ObservationStatus.PENDING: ObservationState.PENDING,
            ObservationStatus.UNSUPPORTED: ObservationState.UNSUPPORTED,
            ObservationStatus.ERROR: ObservationState.ERROR,
            ObservationStatus.TIMEOUT: ObservationState.TIMED_OUT,
        }[terminal.status],
        sample_ids=tuple(record.sample_id for record in records),
        predicate_matched=predicate_matched,
        valid_evidence_seen=any(record.status is ObservationStatus.OK for record in records),
        deadline_elapsed=(
            terminal.status is ObservationStatus.TIMEOUT
            and terminal.error is not None
            and terminal.error.category == "observer_deadline"
        ),
        last_response=last_response,
    )


def _response_from_record(
    record: ObservationRecord,
    series: tuple[ObservationRecord, ...],
) -> ObserverResponse:
    capabilities = _recovered_capabilities(series)
    status = {
        ObservationStatus.OK: ObserverResponseStatus.OK,
        ObservationStatus.PENDING: ObserverResponseStatus.PENDING,
        ObservationStatus.UNSUPPORTED: ObserverResponseStatus.UNSUPPORTED,
        ObservationStatus.ERROR: ObserverResponseStatus.ERROR,
    }.get(record.status)
    if status is None:
        raise ValueError("timeout observation records do not project an observer response")
    return ObserverResponse(
        protocol_version="1.0",
        request_id="request_00000000000000000000000000",
        status=status,
        capabilities=capabilities,
        snapshot_id=record.snapshot_id,
        evidence=record.evidence,
        error=(
            ObserverWireError(
                category=record.error.category,
                message=None,
                retryable=False,
            )
            if status is ObserverResponseStatus.ERROR and record.error is not None
            else None
        ),
    )


def _recovered_error_response(
    records: tuple[ObservationRecord, ...],
) -> ObserverResponse:
    return ObserverResponse(
        protocol_version="1.0",
        request_id="request_00000000000000000000000000",
        status=ObserverResponseStatus.ERROR,
        capabilities=_recovered_capabilities(records),
        evidence=(),
        error=ObserverWireError(
            category="observer_runtime_error",
            message=None,
            retryable=False,
        ),
    )


def _recovered_capabilities(
    records: tuple[ObservationRecord, ...],
) -> ObserverCapabilities:
    evidence = tuple(item for record in records for item in record.evidence)
    evidence_types = tuple(dict.fromkeys(item.value_type for item in evidence))
    return ObserverCapabilities(
        evidence_types=evidence_types or (EvidenceValueType.NULL,),
        evidence_keys=tuple(dict.fromkeys(item.key for item in evidence)),
        read_only=False,
        idempotent=False,
        supports_pending=False,
        stable_snapshot_ids=False,
    )


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


def _require_runtime_clock(clock: RuntimeClock) -> RuntimeClock:
    if type(clock) is not RuntimeClock:
        raise TypeError("clock_factory must return a RuntimeClock")
    return clock


def _read_replay_effective_configuration(bundle: LoadedRunBundle) -> bytes:
    path = bundle.directory / EFFECTIVE_CONFIG_FILENAME
    if path.parent != bundle.directory or path.is_symlink() or not path.is_file():
        raise ValueError("verified replay bundle lacks a regular effective configuration")
    with path.open("rb") as stream:
        content = stream.read(MAX_CONFIG_BYTES + 1)
    if len(content) > MAX_CONFIG_BYTES:
        raise ValueError("replay effective configuration exceeds its resource bound")
    return content


def _prepare_full_resume_bundle(
    request: FullRunRequest,
    run_directory: Path,
) -> _ExecutionBundle:
    loaded = load_replay_bundle(run_directory)
    effective = _read_replay_effective_configuration(loaded)
    recipes = load_realized_execution(loaded.manifest, effective)
    _validate_replay_configuration(request, loaded, effective)
    bundle = _ExecutionBundle.replay(loaded, recipes)
    _validate_full_bundle(bundle, request.config)
    return bundle


def _reject_legacy_terminal_ambiguity(
    database_path: Path,
    run_id: str,
) -> None:
    """Reject obsolete terminal ambiguity projections through a read-only handle."""
    validated_run_id = validate_run_id(run_id)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"{database_path.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
            check_same_thread=True,
        )
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        legacy = connection.execute(
            """
            SELECT entity_type, entity_id
            FROM (
                SELECT 'delivery' AS entity_type, delivery_id AS entity_id
                FROM deliveries
                WHERE run_id = ? AND state = ?
                UNION ALL
                SELECT 'scenario' AS entity_type, scenario_id AS entity_id
                FROM scenarios
                WHERE run_id = ? AND state = ?
            )
            ORDER BY entity_type, entity_id
            LIMIT 1
            """,
            (
                validated_run_id,
                DeliveryState.AMBIGUOUS.value,
                validated_run_id,
                ScenarioState.AMBIGUOUS.value,
            ),
        ).fetchone()
    except sqlite3.Error as error:
        raise RuntimeError("resume projection inventory could not be read safely") from error
    finally:
        if connection is not None:
            connection.close()
    if legacy is not None:
        raise RuntimeError(
            "legacy terminal-ambiguous delivery or scenario projection cannot be resumed"
        )


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


def _validate_resume_schedule(
    runnable: tuple[ScheduleItem, ...],
    deferred: tuple[ScheduleItem, ...],
    pending: tuple[PersistedScheduleEntry, ...],
) -> None:
    planned = (*runnable, *deferred)
    planned_ids = tuple(item.schedule_entry_id for item in planned)
    if len(set(planned_ids)) != len(planned_ids):
        raise RuntimeError("resume runnable and deferred schedules overlap")
    pending_by_id = {item.schedule_entry_id: item for item in pending}
    if set(planned_ids) != set(pending_by_id):
        raise RuntimeError("resume policy schedule differs from current journal state")
    for item in planned:
        persisted = pending_by_id[item.schedule_entry_id]
        if item != ScheduleItem(
            schedule_entry_id=persisted.schedule_entry_id,
            entity_id=persisted.attempt_plan_id,
            logical_due_ns=persisted.logical_due_ns,
            scenario_ordinal=persisted.scenario_ordinal,
            step_ordinal=persisted.step_ordinal,
            delivery_ordinal=persisted.delivery_ordinal,
            attempt_ordinal=persisted.attempt_ordinal,
            deterministic_tie_key=persisted.deterministic_tie_key,
        ):
            raise RuntimeError("resume policy schedule semantics changed before execution")


def _projection_states(
    values: tuple[ProjectionState, ...],
) -> dict[tuple[EntityType, str], LifecycleState]:
    result: dict[tuple[EntityType, str], LifecycleState] = {}
    for item in values:
        key = (item.entity_type, item.entity_id)
        if key in result:
            raise RuntimeError("journal projection inventory contains a duplicate identity")
        result[key] = item.state
    return result


def _reject_terminal_resume_schedule_targets(
    bundle: _ExecutionBundle,
    *,
    pending: tuple[PersistedScheduleEntry, ...],
    projection_states: Mapping[tuple[EntityType, str], LifecycleState],
) -> None:
    terminal = {
        DeliveryState.SATISFIED,
        DeliveryState.EXHAUSTED,
        DeliveryState.AMBIGUOUS,
        DeliveryState.CANCELLED,
        DeliveryState.SKIPPED,
    }
    for entry in pending:
        _scenario, delivery, _recipe = _scheduled_plan(bundle, entry)
        state = projection_states.get((EntityType.DELIVERY, delivery.delivery_id))
        if not isinstance(state, DeliveryState):
            raise RuntimeError("resume delivery projection has an invalid state")
        if state in terminal:
            raise RuntimeError("pending resume schedule targets an immutable terminal delivery")


def _validate_resume_activation_preflight(
    bundle: _ExecutionBundle,
    *,
    run_id: str,
    projection_states: Mapping[tuple[EntityType, str], LifecycleState],
) -> None:
    """Check every activation prerequisite without mutating the recovered journal."""
    run_state = projection_states.get((EntityType.RUN, run_id))
    if not isinstance(run_state, RunState):
        raise RuntimeError("resume journal lacks a valid run projection")
    if run_state not in {RunState.PLANNED, RunState.PAUSED, RunState.RUNNING}:
        raise RuntimeError("a terminal run cannot be resumed for execution")
    manifest_scenario_ids = {item.scenario_id for item in bundle.manifest.scenarios}
    projected_scenario_ids = {
        entity_id
        for (entity_type, entity_id) in projection_states
        if entity_type is EntityType.SCENARIO
    }
    if projected_scenario_ids != manifest_scenario_ids:
        raise RuntimeError("resume journal scenarios differ from the verified manifest")
    for scenario_id in manifest_scenario_ids:
        state = projection_states[(EntityType.SCENARIO, scenario_id)]
        if not isinstance(state, ScenarioState):
            raise RuntimeError("resume scenario projection has an invalid state")


def _validate_resume_execution_preflight(  # noqa: C901
    bundle: _ExecutionBundle,
    *,
    config: ProjectConfig,
    run_id: str,
    pending: tuple[PersistedScheduleEntry, ...],
    projection_states: Mapping[tuple[EntityType, str], LifecycleState],
    existing_attempts: tuple[FullAttemptResult, ...],
    initial_delivery_verdicts: Mapping[str, TerminalVerdict],
    signers: Mapping[str, Signer],
) -> None:
    """Freeze all schedule-to-runtime decisions that are knowable before contact."""
    if pending != tuple(sorted(pending, key=lambda item: item.order_key)):
        raise RuntimeError("persistent resume schedule is not in deterministic order")
    if pending and pending[0].logical_due_ns < 0:
        raise RuntimeError("persistent schedule moved logical time backwards")
    existing_attempt_ids = tuple(item.attempt_id for item in existing_attempts)
    if len(set(existing_attempt_ids)) != len(existing_attempt_ids):
        raise RuntimeError("attempt execution inventory contains duplicate identities")
    prepared_attempt_ids = tuple(
        item.prepared_attempt_id for item in pending if item.prepared_attempt_id is not None
    )
    if len(set(prepared_attempt_ids)) != len(prepared_attempt_ids):
        raise RuntimeError("pending schedules reuse a prepared attempt identity")
    if set(prepared_attempt_ids) & set(existing_attempt_ids):
        raise RuntimeError("prepared schedule attempt identity already has terminal evidence")

    scheduled_delivery_ids: set[str] = set()
    existing_by_id = {item.attempt_id: item for item in existing_attempts}
    for entry in pending:
        scenario, delivery, recipe = _scheduled_plan(bundle, entry)
        if entry.run_id != run_id:
            raise RuntimeError("persisted schedule belongs to a different run")
        if delivery.delivery_id in scheduled_delivery_ids:
            raise RuntimeError("a delivery has more than one pending physical attempt")
        scheduled_delivery_ids.add(delivery.delivery_id)
        state = projection_states.get((EntityType.DELIVERY, delivery.delivery_id))
        if state not in {
            DeliveryState.PENDING,
            DeliveryState.ELIGIBLE,
            DeliveryState.ACTIVE,
            DeliveryState.AMBIGUOUS,
        }:
            raise RuntimeError("pending schedule has no valid delivery activation state")
        if (
            entry.predecessor_attempt_id is not None
            and entry.predecessor_attempt_id not in existing_by_id
        ):
            raise RuntimeError("retry schedule predecessor lacks terminal attempt evidence")
        _retryable_status(config, entry)
        _concurrency_group(bundle, entry)
        _selected_signer(recipe, signers)
        if scenario.scenario_id != entry.scenario_id:
            raise RuntimeError("persisted schedule scenario identity differs from the manifest")

    expected_delivery_ids = {
        delivery.delivery_id
        for scenario in bundle.manifest.scenarios
        for delivery in scenario.deliveries
    }
    if set(initial_delivery_verdicts) | scheduled_delivery_ids != expected_delivery_ids:
        raise RuntimeError("resume state cannot account for every planned delivery")


async def _activate_resumed_run(
    repository: TransitionRepository,
    *,
    clock: RuntimeClock,
    run_id: str,
    owner_epoch: int,
    bundle: _ExecutionBundle,
    projection_states: Mapping[tuple[EntityType, str], LifecycleState],
) -> None:
    run_state = projection_states.get((EntityType.RUN, run_id))
    if not isinstance(run_state, RunState):
        raise RuntimeError("resume journal lacks a valid run projection")
    if run_state in {RunState.PLANNED, RunState.PAUSED}:
        await _apply_resume_transition(
            repository,
            clock=clock,
            run_id=run_id,
            owner_epoch=owner_epoch,
            entity_type=EntityType.RUN,
            entity_id=run_id,
            expected=run_state,
            new=RunState.RUNNING,
            tag="run_started",
        )
    elif run_state is not RunState.RUNNING:
        raise RuntimeError("a terminal run cannot be resumed for execution")

    manifest_scenario_ids = {item.scenario_id for item in bundle.manifest.scenarios}
    projected_scenario_ids = {
        entity_id
        for (entity_type, entity_id) in projection_states
        if entity_type is EntityType.SCENARIO
    }
    if projected_scenario_ids != manifest_scenario_ids:
        raise RuntimeError("resume journal scenarios differ from the verified manifest")
    for scenario in bundle.manifest.scenarios:
        state = projection_states[(EntityType.SCENARIO, scenario.scenario_id)]
        if not isinstance(state, ScenarioState):
            raise RuntimeError("resume scenario projection has an invalid state")
        if state is ScenarioState.PENDING:
            await _apply_resume_transition(
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
            state = ScenarioState.ELIGIBLE
        if state is ScenarioState.ELIGIBLE:
            await _apply_resume_transition(
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


async def _apply_resume_transition(
    repository: TransitionRepository,
    *,
    clock: RuntimeClock,
    run_id: str,
    owner_epoch: int,
    entity_type: EntityType,
    entity_id: str,
    expected: LifecycleState,
    new: LifecycleState,
    tag: str,
) -> None:
    identity = f"resume.{owner_epoch}.{tag}.{entity_id}"
    await repository.apply(
        TransitionCommand(
            run_id=run_id,
            transition_id=identity,
            entity_type=entity_type,
            entity_id=entity_id,
            expected_state=expected,
            new_state=new,
            trigger_category=f"resume_{tag}",
            timestamp=clock.transition_timestamp(),
            owner_epoch=owner_epoch,
            idempotency_key=identity,
        )
    )


def _attempt_results(snapshot: JournalReportSnapshot) -> tuple[FullAttemptResult, ...]:
    return tuple(
        FullAttemptResult(
            evidence=item.record,
            terminal_state=item.terminal_state,
            scenario_ordinal=item.scenario_ordinal,
            delivery_ordinal=item.delivery_ordinal,
            attempt_ordinal=item.attempt_ordinal,
        )
        for item in snapshot.attempts
    )


def _existing_delivery_verdicts(
    bundle: _ExecutionBundle,
    attempts: tuple[FullAttemptResult, ...],
    projection_states: Mapping[tuple[EntityType, str], LifecycleState],
    *,
    scheduled_delivery_ids: frozenset[str] = frozenset(),
) -> dict[str, TerminalVerdict]:
    planned_ids = {
        delivery.delivery_id
        for scenario in bundle.manifest.scenarios
        for delivery in scenario.deliveries
    }
    projected_ids = {
        entity_id
        for (entity_type, entity_id) in projection_states
        if entity_type is EntityType.DELIVERY
    }
    if projected_ids != planned_ids:
        raise RuntimeError("resume journal deliveries differ from the verified manifest")
    result: dict[str, TerminalVerdict] = {}
    terminal_states = {
        DeliveryState.SATISFIED,
        DeliveryState.EXHAUSTED,
        DeliveryState.AMBIGUOUS,
        DeliveryState.CANCELLED,
    }
    for delivery_id in planned_ids:
        state = projection_states[(EntityType.DELIVERY, delivery_id)]
        if not isinstance(state, DeliveryState):
            raise RuntimeError("resume delivery projection has an invalid state")
        if state is DeliveryState.SKIPPED:
            result[delivery_id] = terminal_verdict(ResultCategory.UNSUPPORTED)
            continue
        candidates = tuple(item for item in attempts if item.evidence.delivery_id == delivery_id)
        if (
            state is DeliveryState.ACTIVE
            and delivery_id not in scheduled_delivery_ids
            and candidates
        ):
            latest = max(
                candidates,
                key=lambda item: (item.attempt_ordinal, item.evidence.sequence),
            )
            if latest.terminal_state is AttemptState.UNKNOWN_OUTCOME:
                result[delivery_id] = classify_attempt_verdict(latest.classification)
            continue
        if state not in terminal_states:
            continue
        if not candidates:
            raise RuntimeError("terminal delivery lacks physical attempt evidence")
        latest = max(
            candidates,
            key=lambda item: (item.attempt_ordinal, item.evidence.sequence),
        )
        if _delivery_state_for_attempt(latest.terminal_state) is not state:
            raise RuntimeError("terminal delivery state differs from its latest attempt")
        result[delivery_id] = classify_attempt_verdict(latest.classification)
    return result


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


async def _activate_delivery_from_state(
    repository: TransitionRepository,
    *,
    clock: RuntimeClock,
    run_id: str,
    owner_epoch: int,
    delivery_id: str,
    state: DeliveryState,
) -> None:
    if type(state) is not DeliveryState:
        raise TypeError("delivery activation state must be a DeliveryState")
    if state is DeliveryState.PENDING:
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
        state = DeliveryState.ELIGIBLE
    if state is DeliveryState.ELIGIBLE:
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
        return
    if state is not DeliveryState.ACTIVE:
        raise RuntimeError("pending schedule targets a terminal delivery")


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
    target = _delivery_state_for_attempt(terminal_state)
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


def _delivery_state_for_attempt(terminal_state: AttemptState) -> DeliveryState:
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
    return target


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


def _existing_assertion_category(item: JournalReportAssertion) -> ResultCategory:
    if item.assertion_state is AssertionState.ERROR:
        if item.record.result is not AssertionResult.ERROR:
            raise RuntimeError("errored assertion has a non-error evaluation")
        comparison = item.record.comparison
        if comparison == "snapshot_scope_mismatch":
            origin = AssertionErrorOrigin.INVALID_INPUT
        elif comparison in {
            None,
            "header_timing_missing",
            "comparator_unsupported",
            "poll_result_inconsistent",
        }:
            origin = AssertionErrorOrigin.HARNESS
        else:
            origin = AssertionErrorOrigin.ENVIRONMENT
        return classify_assertion_verdict(
            item.record.result,
            item.assertion_state,
            error_origin=origin,
        ).category
    return classify_assertion_verdict(
        item.record.result,
        item.assertion_state,
    ).category


async def _finalize_or_pause_full_run(
    *,
    schedules: PersistentScheduleRepository,
    transitions: TransitionRepository,
    run_id: str,
    owner_epoch: int,
    verdict: TerminalVerdict,
    completed_at: str,
    timestamp: TransitionTimestamp,
    identity: str,
) -> None:
    transition = _run_completion_transition(
        run_id=run_id,
        owner_epoch=owner_epoch,
        verdict=verdict,
        timestamp=timestamp,
        identity=identity,
    )
    if verdict.category is ResultCategory.AMBIGUOUS:
        await transitions.apply(transition)
        return
    await schedules.finalize_run(
        FullRunCompletionRequest(
            run_id=run_id,
            owner_epoch=owner_epoch,
            result_category=verdict.category,
            completed_at=completed_at,
            transition=transition,
        )
    )


def _run_completion_transition(
    *,
    run_id: str,
    owner_epoch: int,
    verdict: TerminalVerdict,
    timestamp: TransitionTimestamp,
    identity: str = "full.run.finish",
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
        transition_id=identity,
        entity_type=EntityType.RUN,
        entity_id=run_id,
        expected_state=RunState.RUNNING,
        new_state=state,
        trigger_category="run_reduction",
        timestamp=timestamp,
        owner_epoch=owner_epoch,
        idempotency_key=identity,
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


def _materialize_request_bodies(
    bundle: _ExecutionBundle,
    runnable: tuple[PersistedScheduleEntry, ...],
) -> _RetainedRequestBodies:
    """Stream the runnable corpus into a private verified pre-gate spool."""
    required = {_scheduled_plan(bundle, entry)[2].request_blob for entry in runnable}
    return _materialize_required_request_bodies(bundle, frozenset(required))


def _materialize_required_request_bodies(
    bundle: _ExecutionBundle,
    required: frozenset[str],
) -> _RetainedRequestBodies:
    """Stream an exact digest set into a private verified pre-gate spool."""
    snapshots: dict[str, BlobSnapshot] = {}
    for snapshot in bundle.blobs:
        if snapshot.sha256 not in required:
            continue
        if snapshot.sha256 in snapshots:
            raise ValueError("realized request blob is not uniquely present in the bundle")
        snapshots[snapshot.sha256] = snapshot
    if frozenset(snapshots) != required:
        raise ValueError("realized request blob is not uniquely present in the bundle")

    try:
        retained_stream = cast(
            "BinaryIO",
            tempfile.TemporaryFile(mode="w+b"),  # noqa: SIM115
        )
    except OSError:
        raise ValueError("verified request blob could not be materialized") from None
    locations: dict[str, _RetainedBodyLocation] = {}
    try:
        for digest in sorted(required):
            locations[digest] = _append_verified_request_body(
                retained_stream,
                snapshots[digest],
            )
        retained_stream.flush()
        _verify_retained_request_bodies(retained_stream, locations)
    except BaseException as error:
        classified = (
            ValueError("verified request blob could not be materialized")
            if isinstance(error, OSError)
            else error
        )
        try:
            retained_stream.close()
        except BaseException as close_error:  # noqa: BLE001
            _raise_cleanup_failures(
                classified,
                [close_error],
                message="request body materialization and cleanup both failed",
            )
        if classified is not error:
            raise classified from None
        raise
    return _RetainedRequestBodies(retained_stream, locations)


def _append_verified_request_body(
    retained_stream: BinaryIO,
    snapshot: BlobSnapshot,
) -> _RetainedBodyLocation:
    with snapshot.path.open("rb") as stream:
        body = stream.read(snapshot.byte_length + 1)
    if len(body) != snapshot.byte_length or sha256_digest(body) != snapshot.sha256:
        raise ValueError("verified request blob changed before public authorization")
    offset = retained_stream.tell()
    if retained_stream.write(body) != len(body):
        raise OSError
    return _RetainedBodyLocation(
        offset=offset,
        byte_length=len(body),
    )


def _verify_retained_request_bodies(
    retained_stream: BinaryIO,
    locations: Mapping[str, _RetainedBodyLocation],
) -> None:
    restore_position = retained_stream.tell()
    verification_error: BaseException | None = None
    try:
        for digest in sorted(locations):
            location = locations[digest]
            retained_stream.seek(location.offset)
            body = retained_stream.read(location.byte_length)
            if len(body) != location.byte_length or sha256_digest(body) != digest:
                raise ValueError(  # noqa: TRY301
                    "verified request blob spool failed integrity before public authorization"
                )
    except BaseException as error:  # noqa: BLE001
        verification_error = error
    try:
        retained_stream.seek(restore_position)
    except BaseException as restore_error:
        if verification_error is not None:
            _raise_cleanup_failures(
                verification_error,
                [restore_error],
                message="request body verification and position restoration both failed",
            )
        raise
    if verification_error is not None:
        raise verification_error


def _retained_request_body(
    request_bodies: _RetainedRequestBodies,
    recipe: RealizedDeliveryExecution,
) -> bytes:
    return request_bodies.read(recipe.request_blob)


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
    "FullRunPublicPreflight",
    "FullRunRequest",
    "FullRunResult",
    "FullRunResumePreparation",
    "FullRunResumeValidation",
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
