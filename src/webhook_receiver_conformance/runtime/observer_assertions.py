"""Production wiring for observer-backed assertion scenarios."""
# ruff: noqa: BLE001, D105, D107, EM101, INP001, PLR0913, TRY003

from __future__ import annotations

import hashlib
import secrets
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Protocol, cast, runtime_checkable
from urllib.parse import urljoin, urlsplit

from webhook_receiver_conformance.assertions.composite import (
    evaluate_composite_assertion,
)
from webhook_receiver_conformance.assertions.state import evaluate_state_assertion
from webhook_receiver_conformance.assertions.temporal import (
    eventual_state_predicate,
    ordered_transition_predicate,
)
from webhook_receiver_conformance.config.models import (
    AssertionConfig,
    CallbackCountAssertion,
    CommandObserverConfig,
    EventualStateAssertion,
    HttpObserverConfig,
    JournalCountAssertion,
    NoPartialSideEffectAssertion,
    OrderedTransitionAssertion,
    ProcessingCountAssertion,
    ProjectConfig,
    ReceiverConfig,
    ResourceAbsentAssertion,
    ResourceExistsAssertion,
    ResourceFieldAssertion,
    TargetProfile,
)
from webhook_receiver_conformance.config.models import (
    ObserverQuery as ConfigObserverQuery,
)
from webhook_receiver_conformance.domain.enums import AssertionResult, EvidenceValueType
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    encode_crockford_ulid,
    new_fresh_id,
    validate_planned_id,
)
from webhook_receiver_conformance.errors import Diagnostic
from webhook_receiver_conformance.http.executor import (
    HttpAttemptExecutor,
    HttpLimits,
    HttpTimeouts,
)
from webhook_receiver_conformance.journal.repositories import (
    AssertionEvidenceKind,
    AssertionEvidenceReference,
    AssertionRepository,
    ObservationRepository,
    PersistedAttemptEvidence,
)
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.policy import (
    DestinationPolicy,
    parse_destination_policy,
)
from webhook_receiver_conformance.network.transport import AnyIOConnector, AnyIOResolver
from webhook_receiver_conformance.observers.command import CommandObserver
from webhook_receiver_conformance.observers.http_probe import (
    HttpProbeObserver,
    HttpProbePolicies,
)
from webhook_receiver_conformance.observers.polling import (
    MINIMUM_POLL_INTERVAL_NS,
    ObservationPollOutcome,
    ObservationPollPlan,
    ObservationPollResult,
    PollPredicate,
)
from webhook_receiver_conformance.observers.protocol import (
    HTTP_CAPABILITIES_PATH,
    HTTP_OBSERVE_PATH,
    BuiltinObserverKind,
    Observer,
    ObserverCapabilities,
    ObserverEvidence,
    ObserverOperation,
    ObserverQuery,
    ObserverRequest,
    ObserverResponse,
    ObserverResponseStatus,
    ObserverWireError,
)
from webhook_receiver_conformance.reporting.json_reports import ObservationReportRecord
from webhook_receiver_conformance.runtime.assertions import (
    AssertionEvidenceBundle,
    AssertionLifecycle,
    AssertionLifecycleResult,
    AssertionRuntimeContext,
)
from webhook_receiver_conformance.runtime.observations import ObservationRuntime
from webhook_receiver_conformance.runtime.runner import (
    ObserverAssertionCoordinates,
    ObserverAssertionExecution,
    ObserverAssertionRunScope,
)
from webhook_receiver_conformance.runtime.verdicts import TerminalVerdict
from webhook_receiver_conformance.secrets import SecretHandle

if TYPE_CHECKING:
    from collections.abc import Sequence

    from webhook_receiver_conformance.observers.protocol import ObservationRecord
    from webhook_receiver_conformance.scheduler.clocks import RuntimeClock

type ObserverAssertionConfig = (
    ProcessingCountAssertion
    | CallbackCountAssertion
    | JournalCountAssertion
    | ResourceExistsAssertion
    | ResourceAbsentAssertion
    | ResourceFieldAssertion
    | EventualStateAssertion
    | OrderedTransitionAssertion
    | NoPartialSideEffectAssertion
)
type SingleObserverAssertion = (
    ProcessingCountAssertion
    | CallbackCountAssertion
    | JournalCountAssertion
    | ResourceExistsAssertion
    | ResourceAbsentAssertion
    | ResourceFieldAssertion
    | EventualStateAssertion
    | OrderedTransitionAssertion
)
type StateObserverAssertion = (
    ProcessingCountAssertion
    | CallbackCountAssertion
    | JournalCountAssertion
    | ResourceExistsAssertion
    | ResourceAbsentAssertion
    | ResourceFieldAssertion
)
type FreshIdFactory = Callable[[FreshIdKind], str]
type RequestIdFactory = Callable[[], str]
type ObserverExecutorFactory = Callable[
    [ProjectConfig, HttpObserverConfig, RuntimeClock],
    HttpAttemptExecutor,
]
_MAX_EXECUTABLE_ALIAS_LENGTH = 128


@dataclass(frozen=True, slots=True)
class CommandLaunchPolicy:
    """Explicit policy for the command adapter's otherwise-disabled name search."""

    executable_search_paths: tuple[Path, ...] = ()
    allowlisted_executable_names: frozenset[str] = frozenset()
    current_interpreter_aliases: frozenset[str] = frozenset()
    environment: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if type(self.executable_search_paths) is not tuple or any(
            type(item) is not Path for item in self.executable_search_paths
        ):
            raise TypeError("executable_search_paths must be a tuple of pathlib.Path values")
        if type(self.allowlisted_executable_names) is not frozenset or any(
            type(item) is not str or not item for item in self.allowlisted_executable_names
        ):
            raise TypeError("allowlisted_executable_names must contain nonempty strings")
        if type(self.current_interpreter_aliases) is not frozenset or any(
            not _safe_executable_alias(item) for item in self.current_interpreter_aliases
        ):
            raise ValueError(
                "current_interpreter_aliases must contain bounded bare executable names"
            )
        if self.environment is not None and not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            self.environment,
            Mapping,
        ):
            raise TypeError("environment must be a mapping or None")

    @classmethod
    def for_current_interpreter(
        cls,
        *aliases: str,
        environment: Mapping[str, str] | None = None,
    ) -> CommandLaunchPolicy:
        """Map explicit configured aliases to this exact Python interpreter."""
        selected = aliases or ("python",)
        return cls(
            current_interpreter_aliases=frozenset(selected),
            environment=environment,
        )


_DEFAULT_COMMAND_POLICY = CommandLaunchPolicy()


@dataclass(frozen=True, slots=True)
class ScenarioObserverAssertion:
    """One planned observer assertion and its stable journal identities."""

    context: AssertionRuntimeContext
    assertion: ObserverAssertionConfig
    observation_id: str
    checkpoint: str
    event_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.context) is not AssertionRuntimeContext:
            raise TypeError("context must be an AssertionRuntimeContext")
        if not _is_observer_assertion(self.assertion):
            raise TypeError("assertion must be a built-in observer assertion")
        validate_planned_id(
            self.observation_id,
            expected_kind=PlannedIdKind.OBSERVATION,
        )
        if (
            type(self.checkpoint) is not str
            or not self.checkpoint
            or any(character in "\r\n\x00" for character in self.checkpoint)
        ):
            raise ValueError("checkpoint must be nonempty and line-safe")
        if self.event_id is not None:
            validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)


@dataclass(frozen=True, slots=True)
class CommittedObserverAssertion:
    """Durable samples and evaluation produced for one planned assertion."""

    plan: ObservationPollPlan
    poll_result: ObservationPollResult
    observations: tuple[ObservationRecord, ...]
    assertion: AssertionLifecycleResult
    verdict: TerminalVerdict

    def __post_init__(self) -> None:
        if type(self.plan) is not ObservationPollPlan:
            raise TypeError("plan must be an ObservationPollPlan")
        if type(self.poll_result) is not ObservationPollResult:
            raise TypeError("poll_result must be an ObservationPollResult")
        if type(self.observations) is not tuple or not self.observations:
            raise ValueError("observations must contain committed samples")
        if type(self.assertion) is not AssertionLifecycleResult:
            raise TypeError("assertion must be an AssertionLifecycleResult")
        if type(self.verdict) is not TerminalVerdict:
            raise TypeError("verdict must be a TerminalVerdict")
        if self.verdict != self.assertion.normalized.verdict:
            raise ValueError("verdict must match the committed assertion evaluation")


@dataclass(frozen=True, slots=True)
class ScenarioObserverAssertionResult:
    """Ordered, complete observer-backed assertion results for one scenario."""

    scenario_id: str
    results: tuple[CommittedObserverAssertion, ...]
    terminal_verdicts: tuple[TerminalVerdict, ...]

    def __post_init__(self) -> None:
        validate_planned_id(self.scenario_id, expected_kind=PlannedIdKind.SCENARIO)
        if type(self.results) is not tuple or any(
            type(item) is not CommittedObserverAssertion for item in self.results
        ):
            raise TypeError("results must be a tuple of committed observer assertions")
        if type(self.terminal_verdicts) is not tuple or self.terminal_verdicts != tuple(
            item.verdict for item in self.results
        ):
            raise ValueError("terminal_verdicts must match results in order")


@runtime_checkable
class ObserverAdapterBuilder(Protocol):
    """Testable construction boundary for the two closed built-in adapters."""

    def build(self) -> Mapping[str, Observer]:
        """Construct every configured observer adapter."""
        ...


class ProjectObserverAdapterBuilder:
    """Build closed built-in observers with explicit process and network policies."""

    __slots__ = (
        "_clock",
        "_command_policy",
        "_config",
        "_executor_factory",
        "_http_policies",
        "_project_root",
        "_runtime_public_authorization",
        "_secrets",
    )

    def __init__(
        self,
        *,
        config: ProjectConfig,
        project_root: Path,
        observer_secrets: Mapping[str, SecretHandle],
        clock: RuntimeClock,
        command_policy: CommandLaunchPolicy = _DEFAULT_COMMAND_POLICY,
        http_policies: Mapping[str, HttpProbePolicies] | None = None,
        runtime_public_authorization: str | None = None,
        executor_factory: ObserverExecutorFactory | None = None,
    ) -> None:
        if type(config) is not ProjectConfig:
            raise TypeError("config must be a ProjectConfig")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            project_root,
            Path,
        ):
            raise TypeError("project_root must be a pathlib.Path")
        if not project_root.is_absolute():
            raise ValueError("project_root must be absolute")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            observer_secrets,
            Mapping,
        ):
            raise TypeError("observer_secrets must be a mapping")
        if type(command_policy) is not CommandLaunchPolicy:
            raise TypeError("command_policy must be a CommandLaunchPolicy")
        if http_policies is not None and not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            http_policies,
            Mapping,
        ):
            raise TypeError("http_policies must be a mapping or None")
        self._config = config
        self._project_root = project_root
        self._secrets = observer_secrets
        self._clock = clock
        self._command_policy = command_policy
        self._http_policies: Mapping[str, HttpProbePolicies] = (
            {} if http_policies is None else http_policies
        )
        self._runtime_public_authorization = runtime_public_authorization
        self._executor_factory = (
            _default_observer_executor if executor_factory is None else executor_factory
        )

    def build(self) -> Mapping[str, Observer]:
        """Construct every adapter, failing closed before scenario execution."""
        observers: dict[str, Observer] = {}
        for observer_id, observer_config in self._config.observers.items():
            if type(observer_config) is CommandObserverConfig:
                policy = self._command_policy
                observers[observer_id] = CommandObserver(
                    _apply_current_interpreter_alias(observer_config, policy),
                    project_root=self._project_root,
                    environ=policy.environment,
                    executable_search_paths=policy.executable_search_paths,
                    allowlisted_executable_names=policy.allowlisted_executable_names,
                )
                continue
            if type(observer_config) is not HttpObserverConfig:
                raise TypeError("project contains an unknown observer configuration")
            direct_token = self._secrets.get(observer_id)
            prefixed_token = self._secrets.get(f"observer:{observer_id}")
            if (
                direct_token is not None
                and prefixed_token is not None
                and direct_token is not prefixed_token
            ):
                raise ValueError("observer SecretHandle aliases must identify one handle")
            token = direct_token if direct_token is not None else prefixed_token
            if type(token) is not SecretHandle:
                message = f"HTTP observer {observer_id!r} requires its resolved SecretHandle"
                raise ValueError(message)
            policies = self._http_policies.get(observer_id)
            if policies is None:
                policies = _derive_http_policies(
                    self._config,
                    observer_config,
                    runtime_public_authorization=self._runtime_public_authorization,
                )
            observers[observer_id] = HttpProbeObserver(
                observer_config,
                policies=policies,
                executor=self._executor_factory(
                    self._config,
                    observer_config,
                    self._clock,
                ),
                token=token,
            )
        return MappingProxyType(observers)


class ScenarioObserverAssertionRuntime:
    """Run observer-backed assertions sequentially with bounded durable polling."""

    __slots__ = (
        "_assertions",
        "_clock",
        "_fresh_id",
        "_invocation_timeouts",
        "_observations",
        "_observers",
        "_owner_epoch",
        "_request_id",
    )

    def __init__(
        self,
        *,
        observers: Mapping[str, Observer],
        invocation_timeouts_ns: Mapping[str, int],
        observation_repository: ObservationRepository,
        assertion_repository: AssertionRepository,
        clock: RuntimeClock,
        owner_epoch: int,
        fresh_id: FreshIdFactory = new_fresh_id,
        request_id: RequestIdFactory | None = None,
    ) -> None:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            observers,
            Mapping,
        ) or any(
            type(key) is not str
            or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                value,
                Observer,
            )
            for key, value in observers.items()
        ):
            raise TypeError("observers must map names to Observer implementations")
        if type(owner_epoch) is not int or owner_epoch < 0:
            raise ValueError("owner_epoch must be a nonnegative integer")
        if (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                invocation_timeouts_ns,
                Mapping,
            )
            or set(invocation_timeouts_ns) != set(observers)
            or any(
                type(value) is not int or value <= 0 for value in invocation_timeouts_ns.values()
            )
        ):
            raise ValueError("invocation_timeouts_ns must provide one positive bound per observer")
        if not callable(fresh_id):
            raise TypeError("fresh_id must be callable")
        self._observers = MappingProxyType(dict(observers))
        self._invocation_timeouts = MappingProxyType(dict(invocation_timeouts_ns))
        self._observations = observation_repository
        self._assertions = AssertionLifecycle(
            repository=assertion_repository,
            clock=clock,
            fresh_id=fresh_id,
        )
        self._clock = clock
        self._owner_epoch = owner_epoch
        self._fresh_id = fresh_id
        self._request_id = _new_request_id if request_id is None else request_id

    @classmethod
    def from_project(
        cls,
        *,
        config: ProjectConfig,
        project_root: Path,
        observer_secrets: Mapping[str, SecretHandle],
        observation_repository: ObservationRepository,
        assertion_repository: AssertionRepository,
        clock: RuntimeClock,
        owner_epoch: int,
        command_policy: CommandLaunchPolicy = _DEFAULT_COMMAND_POLICY,
        http_policies: Mapping[str, HttpProbePolicies] | None = None,
        runtime_public_authorization: str | None = None,
        executor_factory: ObserverExecutorFactory | None = None,
        fresh_id: FreshIdFactory = new_fresh_id,
        request_id: RequestIdFactory | None = None,
    ) -> ScenarioObserverAssertionRuntime:
        """Build the configured adapters and return a scenario runtime."""
        observers = ProjectObserverAdapterBuilder(
            config=config,
            project_root=project_root,
            observer_secrets=observer_secrets,
            clock=clock,
            command_policy=command_policy,
            http_policies=http_policies,
            runtime_public_authorization=runtime_public_authorization,
            executor_factory=executor_factory,
        ).build()
        invocation_timeouts_ns: dict[str, int] = {}
        for name, observer_config in config.observers.items():
            if type(observer_config) is CommandObserverConfig:
                timeout_ns = observer_config.timeout.nanoseconds
            elif type(observer_config) is HttpObserverConfig:
                timeout_ns = observer_config.timeouts.total.nanoseconds
            else:
                raise TypeError("project contains an unknown observer configuration")
            invocation_timeouts_ns[name] = timeout_ns
        return cls(
            observers=observers,
            invocation_timeouts_ns=invocation_timeouts_ns,
            observation_repository=observation_repository,
            assertion_repository=assertion_repository,
            clock=clock,
            owner_epoch=owner_epoch,
            fresh_id=fresh_id,
            request_id=request_id,
        )

    async def run(
        self,
        assertions: Sequence[ScenarioObserverAssertion],
    ) -> ScenarioObserverAssertionResult:
        """Run one scenario's planned observer assertions in supplied order."""
        items = tuple(assertions)
        if not items:
            raise ValueError("a scenario requires at least one observer assertion")
        scenario_id = items[0].context.scenario_id
        if any(item.context.scenario_id != scenario_id for item in items):
            raise ValueError("all observer assertions must belong to one scenario")
        scopes = tuple(
            (
                item.event_id,
                item.checkpoint,
                _observer_id(item.assertion),
            )
            for item in items
        )
        if len(set(scopes)) != len(scopes):
            raise ValueError(
                "independent observer assertions require distinct event/checkpoint scopes"
            )
        observation_ids = tuple(item.observation_id for item in items)
        if len(set(observation_ids)) != len(observation_ids):
            raise ValueError("independent observer assertions require unique observation IDs")

        capabilities: dict[str, ObserverResponse | Diagnostic | None] = {}
        results: list[CommittedObserverAssertion] = []
        for item in items:
            observer_id = _observer_id(item.assertion)
            observer = self._observers.get(observer_id)
            if observer is None:
                message = f"configured observer {observer_id!r} is unavailable"
                raise ValueError(message)
            if observer_id not in capabilities:
                capabilities[observer_id] = await self._request_capabilities(observer)
            result = await self._run_one(
                item,
                observer_id=observer_id,
                observer=observer,
                capability_result=capabilities[observer_id],
            )
            results.append(result)
        committed = tuple(results)
        return ScenarioObserverAssertionResult(
            scenario_id=scenario_id,
            results=committed,
            terminal_verdicts=tuple(item.verdict for item in committed),
        )

    async def _request_capabilities(
        self,
        observer: Observer,
    ) -> ObserverResponse | Diagnostic | None:
        return await _request_capabilities(observer, self._request_id)

    async def _run_one(
        self,
        item: ScenarioObserverAssertion,
        *,
        observer_id: str,
        observer: Observer,
        capability_result: ObserverResponse | Diagnostic | None,
    ) -> CommittedObserverAssertion:
        return await _evaluate_planned_assertion(
            item,
            observer_id=observer_id,
            observer=observer,
            capability_result=capability_result,
            invocation_timeout_ns=self._invocation_timeouts[observer_id],
            observation_repository=self._observations,
            clock=self._clock,
            owner_epoch=self._owner_epoch,
            fresh_id=self._fresh_id,
            request_id=self._request_id,
            lifecycle=self._assertions,
        )


class ProjectObserverAssertionExecutorFactory:
    """Bind configured observer adapters to the runner's open journal and clock."""

    __slots__ = (
        "_command_policy",
        "_config",
        "_executor_factory",
        "_fresh_id",
        "_http_policies",
        "_project_root",
        "_request_id",
        "_runtime_public_authorization",
        "_secrets",
    )

    def __init__(
        self,
        *,
        config: ProjectConfig,
        project_root: Path,
        observer_secrets: Mapping[str, SecretHandle],
        command_policy: CommandLaunchPolicy = _DEFAULT_COMMAND_POLICY,
        http_policies: Mapping[str, HttpProbePolicies] | None = None,
        runtime_public_authorization: str | None = None,
        executor_factory: ObserverExecutorFactory | None = None,
        fresh_id: FreshIdFactory = new_fresh_id,
        request_id: RequestIdFactory | None = None,
    ) -> None:
        if type(config) is not ProjectConfig:
            raise TypeError("config must be a ProjectConfig")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            project_root,
            Path,
        ):
            raise TypeError("project_root must be a pathlib.Path")
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            observer_secrets,
            Mapping,
        ):
            raise TypeError("observer_secrets must be a mapping")
        if type(command_policy) is not CommandLaunchPolicy:
            raise TypeError("command_policy must be a CommandLaunchPolicy")
        if http_policies is not None and not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            http_policies,
            Mapping,
        ):
            raise TypeError("http_policies must be a mapping or None")
        if not callable(fresh_id):
            raise TypeError("fresh_id must be callable")
        if request_id is not None and not callable(request_id):
            raise TypeError("request_id must be callable or None")
        self._config = config
        self._project_root = project_root
        self._secrets = observer_secrets
        self._command_policy = command_policy
        self._http_policies = http_policies
        self._runtime_public_authorization = runtime_public_authorization
        self._executor_factory = executor_factory
        self._fresh_id = fresh_id
        self._request_id = request_id

    def create(
        self,
        scope: ObserverAssertionRunScope,
    ) -> RunnerObserverAssertionExecutor:
        """Create a runner adapter bound to the supplied open run scope."""
        if type(scope) is not ObserverAssertionRunScope:
            raise TypeError("scope must be an ObserverAssertionRunScope")
        if scope.config != self._config or scope.project_root != self._project_root:
            raise ValueError("observer factory configuration differs from the active run")
        if scope.runtime_public_authorization != self._runtime_public_authorization:
            raise ValueError("observer factory runtime authorization differs from the active run")
        observers = ProjectObserverAdapterBuilder(
            config=self._config,
            project_root=self._project_root,
            observer_secrets=self._secrets,
            clock=scope.clock,
            command_policy=self._command_policy,
            http_policies=self._http_policies,
            runtime_public_authorization=self._runtime_public_authorization,
            executor_factory=self._executor_factory,
        ).build()
        return RunnerObserverAssertionExecutor(
            observers=observers,
            invocation_timeouts_ns=_configured_invocation_timeouts(self._config),
            observation_repository=ObservationRepository(scope.service),
            clock=scope.clock,
            owner_epoch=scope.owner_epoch,
            fresh_id=self._fresh_id,
            request_id=self._request_id,
        )


class RunnerObserverAssertionExecutor:
    """Runner protocol adapter for one open journal/clock execution scope."""

    __slots__ = (
        "_capabilities",
        "_clock",
        "_fresh_id",
        "_invocation_timeouts",
        "_observations",
        "_observers",
        "_owner_epoch",
        "_request_id",
    )

    def __init__(
        self,
        *,
        observers: Mapping[str, Observer],
        invocation_timeouts_ns: Mapping[str, int],
        observation_repository: ObservationRepository,
        clock: RuntimeClock,
        owner_epoch: int,
        fresh_id: FreshIdFactory = new_fresh_id,
        request_id: RequestIdFactory | None = None,
    ) -> None:
        _validate_observer_runtime_inputs(
            observers,
            invocation_timeouts_ns=invocation_timeouts_ns,
            owner_epoch=owner_epoch,
            fresh_id=fresh_id,
        )
        self._observers = MappingProxyType(dict(observers))
        self._invocation_timeouts = MappingProxyType(dict(invocation_timeouts_ns))
        self._observations = observation_repository
        self._clock = clock
        self._owner_epoch = owner_epoch
        self._fresh_id = fresh_id
        self._request_id = _new_request_id if request_id is None else request_id
        self._capabilities: dict[str, ObserverResponse | Diagnostic | None] = {}

    async def evaluate_scoped(
        self,
        lifecycle: AssertionLifecycle,
        context: AssertionRuntimeContext,
        assertion: AssertionConfig,
        attempts: tuple[PersistedAttemptEvidence, ...],
        coordinates: ObserverAssertionCoordinates,
    ) -> ObserverAssertionExecution:
        """Collect, persist, and export one runner-selected observer assertion."""
        if type(lifecycle) is not AssertionLifecycle:
            raise TypeError("lifecycle must be an AssertionLifecycle")
        if type(context) is not AssertionRuntimeContext:
            raise TypeError("context must be an AssertionRuntimeContext")
        if not _is_observer_assertion(assertion):
            raise TypeError("runner adapter requires a built-in observer assertion")
        if (
            type(attempts) is not tuple
            or not attempts
            or any(type(item) is not PersistedAttemptEvidence for item in attempts)
        ):
            raise ValueError("runner observer assertions require persisted attempt evidence")
        if type(coordinates) is not ObserverAssertionCoordinates:
            raise TypeError("coordinates must be ObserverAssertionCoordinates")
        typed_assertion = cast("ObserverAssertionConfig", assertion)
        witness = attempts[-1]
        if (
            witness.attempt.run_id != context.run_id
            or witness.attempt.scenario_id != context.scenario_id
        ):
            raise ValueError("selected observer scope attempt differs from assertion context")
        observer_id = _observer_id(typed_assertion)
        observer = self._observers.get(observer_id)
        if observer is None:
            message = f"configured observer {observer_id!r} is unavailable"
            raise ValueError(message)
        if observer_id not in self._capabilities:
            self._capabilities[observer_id] = await _request_capabilities(
                observer,
                self._request_id,
            )
        item = ScenarioObserverAssertion(
            context=context,
            assertion=typed_assertion,
            observation_id=_runner_observation_id(
                context,
                observer_id=observer_id,
                event_id=witness.attempt.event_id,
            ),
            checkpoint=f"assertion:{context.assertion_id}",
            event_id=witness.attempt.event_id,
        )
        committed = await _evaluate_planned_assertion(
            item,
            observer_id=observer_id,
            observer=observer,
            capability_result=self._capabilities[observer_id],
            invocation_timeout_ns=self._invocation_timeouts[observer_id],
            observation_repository=self._observations,
            clock=self._clock,
            owner_epoch=self._owner_epoch,
            fresh_id=self._fresh_id,
            request_id=self._request_id,
            lifecycle=lifecycle,
        )
        return ObserverAssertionExecution(
            lifecycle=committed.assertion,
            observations=tuple(
                ObservationReportRecord(
                    record=record,
                    scenario_ordinal=coordinates.scenario_ordinal,
                    observation_ordinal=coordinates.observation_ordinal,
                )
                for record in committed.observations
            ),
        )


async def _request_capabilities(
    observer: Observer,
    request_id: RequestIdFactory,
) -> ObserverResponse | Diagnostic | None:
    request = ObserverRequest(
        protocol_version="1.0",
        request_id=request_id(),
        operation=ObserverOperation.CAPABILITIES,
    )
    try:
        return await observer.invoke(request)
    except Exception as error:
        diagnostic = getattr(error, "diagnostic", None)
        return diagnostic if type(diagnostic) is Diagnostic else None


async def _evaluate_planned_assertion(
    item: ScenarioObserverAssertion,
    *,
    observer_id: str,
    observer: Observer,
    capability_result: ObserverResponse | Diagnostic | None,
    invocation_timeout_ns: int,
    observation_repository: ObservationRepository,
    clock: RuntimeClock,
    owner_epoch: int,
    fresh_id: FreshIdFactory,
    request_id: RequestIdFactory,
    lifecycle: AssertionLifecycle,
) -> CommittedObserverAssertion:
    assertion = item.assertion
    queries = derive_observer_queries(assertion)
    handshake_failed = type(capability_result) is not ObserverResponse
    capabilities = (
        _fallback_capabilities(queries) if handshake_failed else capability_result.capabilities
    )
    request = ObserverRequest(
        protocol_version="1.0",
        request_id=request_id(),
        operation=ObserverOperation.OBSERVE,
        sample_id=fresh_id(FreshIdKind.SAMPLE),
        run_id=item.context.run_id,
        scenario_id=item.context.scenario_id,
        event_id=item.event_id,
        checkpoint=item.checkpoint,
        queries=queries,
    )
    plan = _poll_plan(
        item,
        observer_id=observer_id,
        request=request,
        capabilities=capabilities,
        invocation_timeout_ns=invocation_timeout_ns,
    )
    active_observer: Observer = observer
    if handshake_failed:
        active_observer = _FailedObserver(cast("Diagnostic | None", capability_result))
    observation_runtime = ObservationRuntime(
        observer=active_observer,
        repository=observation_repository,
        clock=clock,
        owner_epoch=owner_epoch,
        fresh_id=fresh_id,
    )
    poll_result = await observation_runtime.poll(
        plan,
        _poll_predicate(assertion),
    )
    samples = await observation_runtime.samples(plan)
    references = tuple(
        AssertionEvidenceReference(
            AssertionEvidenceKind.OBSERVATION,
            sample.sample_id,
        )
        for sample in samples
    )
    bundle = AssertionEvidenceBundle(
        payload=_assertion_payload(assertion, poll_result, request, capabilities),
        references=references,
    )

    async def supply() -> AssertionEvidenceBundle:
        return bundle

    if handshake_failed:
        assertion_result = await lifecycle.evaluate(
            item.context,
            cast("AssertionConfig", assertion),
            bundle,
        )
    else:
        assertion_result = await lifecycle.evaluate_observer(
            item.context,
            cast("AssertionConfig", assertion),
            _evaluation_capabilities(plan),
            supply,
            capability_reference=AssertionEvidenceReference(
                AssertionEvidenceKind.OBSERVATION,
                item.observation_id,
            ),
        )
    return CommittedObserverAssertion(
        plan=plan,
        poll_result=poll_result,
        observations=samples,
        assertion=assertion_result,
        verdict=assertion_result.normalized.verdict,
    )


class _CapturedObserverError(RuntimeError):
    diagnostic: Diagnostic

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.code)


class _FailedObserver:
    BUILTIN_KIND: ClassVar[BuiltinObserverKind] = BuiltinObserverKind.COMMAND
    __slots__ = ("_diagnostic",)

    def __init__(self, diagnostic: Diagnostic | None) -> None:
        self._diagnostic = diagnostic

    async def invoke(self, request: ObserverRequest) -> ObserverResponse:
        del request
        if self._diagnostic is not None:
            raise _CapturedObserverError(self._diagnostic)
        raise RuntimeError("observer capability handshake failed")


def _observer_id(assertion: ObserverAssertionConfig) -> str:
    if type(assertion) is NoPartialSideEffectAssertion:
        identifiers = {item.query.observer for item in assertion.predicates}
        if len(identifiers) != 1:
            raise ValueError("composite predicates must use one observer")
        return next(iter(identifiers))
    single = cast("SingleObserverAssertion", assertion)
    return single.query.observer


def derive_observer_queries(
    assertion: AssertionConfig,
) -> tuple[ObserverQuery, ...]:
    """Translate one built-in assertion into its exact observer wire queries."""
    if not _is_observer_assertion(assertion):
        raise TypeError("assertion must be a built-in observer assertion")
    observer_assertion = cast("ObserverAssertionConfig", assertion)
    if type(observer_assertion) is NoPartialSideEffectAssertion:
        configured: tuple[ConfigObserverQuery, ...] = tuple(
            predicate.query for predicate in observer_assertion.predicates
        )
    else:
        single = cast("SingleObserverAssertion", observer_assertion)
        configured = (single.query,)
    result: dict[str, ObserverQuery] = {}
    for query in configured:
        evidence_type = _query_type(observer_assertion, query.key)
        candidate = ObserverQuery(
            key=query.key,
            type=evidence_type,
            parameters=query.parameters.to_wire(),
        )
        previous = result.get(query.key)
        if previous is not None and previous != candidate:
            raise ValueError("duplicate observer query keys must have identical contracts")
        result[query.key] = candidate
    return tuple(result.values())


def _query_type(
    assertion: ObserverAssertionConfig,
    key: str,
) -> EvidenceValueType:
    if type(assertion) in {
        ProcessingCountAssertion,
        CallbackCountAssertion,
        JournalCountAssertion,
    }:
        return EvidenceValueType.INTEGER
    if type(assertion) in {ResourceExistsAssertion, ResourceAbsentAssertion}:
        return EvidenceValueType.BOOLEAN
    if type(assertion) is ResourceFieldAssertion:
        return EvidenceValueType.OBJECT
    if type(assertion) is OrderedTransitionAssertion:
        return EvidenceValueType.ARRAY
    if type(assertion) is EventualStateAssertion:
        return (
            EvidenceValueType.OBJECT
            if assertion.path is not None
            else _typed_value_type(assertion.expected.to_wire())
        )
    if type(assertion) is NoPartialSideEffectAssertion:
        predicate = next(item for item in assertion.predicates if item.query.key == key)
        return (
            EvidenceValueType.OBJECT
            if predicate.path is not None
            else _typed_value_type(predicate.expected.to_wire())
        )
    raise TypeError("unsupported observer assertion")


def _typed_value_type(wire: Mapping[str, object]) -> EvidenceValueType:
    value = wire.get("value_type")
    if type(value) is not str:
        raise TypeError("typed assertion value lacks a value_type")
    return EvidenceValueType(value)


def _poll_plan(
    item: ScenarioObserverAssertion,
    *,
    observer_id: str,
    request: ObserverRequest,
    capabilities: ObserverCapabilities,
    invocation_timeout_ns: int,
) -> ObservationPollPlan:
    within = getattr(item.assertion, "within", None)
    interval = getattr(item.assertion, "poll_interval", None)
    within_ns = (
        max(invocation_timeout_ns, MINIMUM_POLL_INTERVAL_NS)
        if within is None
        else within.nanoseconds
    )
    poll_interval_ns = within_ns if interval is None else interval.nanoseconds
    return ObservationPollPlan(
        observation_id=item.observation_id,
        observer_id=observer_id,
        request=request,
        capabilities=capabilities,
        within_ns=within_ns,
        poll_interval_ns=poll_interval_ns,
        invocation_timeout_ns=invocation_timeout_ns,
    )


def _poll_predicate(assertion: ObserverAssertionConfig) -> PollPredicate:
    if getattr(assertion, "within", None) is None:
        return lambda _response: True
    if type(assertion) is EventualStateAssertion:
        return eventual_state_predicate(assertion)
    if type(assertion) is OrderedTransitionAssertion:
        return ordered_transition_predicate(assertion)

    def predicate(response: ObserverResponse) -> bool:
        evaluation = (
            evaluate_composite_assertion(assertion, response)
            if type(assertion) is NoPartialSideEffectAssertion
            else evaluate_state_assertion(
                cast("StateObserverAssertion", assertion),
                response.evidence,
            )
        )
        if evaluation.result is AssertionResult.ERROR:
            raise ValueError("observer evidence could not be evaluated")
        return evaluation.result is AssertionResult.PASS

    return predicate


def _assertion_payload(
    assertion: ObserverAssertionConfig,
    poll_result: ObservationPollResult,
    request: ObserverRequest,
    capabilities: ObserverCapabilities,
) -> tuple[ObserverEvidence, ...] | ObservationPollResult | ObserverResponse:
    if type(assertion) is EventualStateAssertion:
        return poll_result
    if type(assertion) is NoPartialSideEffectAssertion:
        if (
            poll_result.outcome is not ObservationPollOutcome.ERROR
            and poll_result.last_response is not None
        ):
            return poll_result.last_response
        return ObserverResponse(
            protocol_version="1.0",
            request_id=request.request_id,
            status=ObserverResponseStatus.ERROR,
            capabilities=capabilities,
            evidence=(),
            error=ObserverWireError(
                category="observer_runtime_error",
                message=None,
                retryable=False,
            ),
        )
    return (
        ()
        if (
            poll_result.outcome is ObservationPollOutcome.ERROR or poll_result.last_response is None
        )
        else poll_result.last_response.evidence
    )


def _fallback_capabilities(
    queries: tuple[ObserverQuery, ...],
) -> ObserverCapabilities:
    evidence_types = tuple(dict.fromkeys(query.type for query in queries))
    return ObserverCapabilities(
        evidence_types=evidence_types,
        evidence_keys=tuple(query.key for query in queries),
        read_only=False,
        idempotent=False,
        max_queries=len(queries),
        supports_pending=False,
        stable_snapshot_ids=False,
    )


def _evaluation_capabilities(
    plan: ObservationPollPlan,
) -> ObserverCapabilities:
    """Expose query-limit negotiation gaps to the assertion capability lifecycle."""
    negotiation = plan.negotiation
    if negotiation.supported or not negotiation.query_limit_exceeded:
        return plan.capabilities
    first_key = plan.request.queries[0].key
    return ObserverCapabilities(
        evidence_types=plan.capabilities.evidence_types,
        evidence_keys=tuple(key for key in plan.capabilities.evidence_keys if key != first_key),
        read_only=plan.capabilities.read_only,
        idempotent=plan.capabilities.idempotent,
        max_queries=plan.capabilities.max_queries,
        supports_pending=plan.capabilities.supports_pending,
        stable_snapshot_ids=plan.capabilities.stable_snapshot_ids,
    )


def _configured_invocation_timeouts(
    config: ProjectConfig,
) -> Mapping[str, int]:
    result: dict[str, int] = {}
    for name, observer in config.observers.items():
        if type(observer) is CommandObserverConfig:
            result[name] = observer.timeout.nanoseconds
        elif type(observer) is HttpObserverConfig:
            result[name] = observer.timeouts.total.nanoseconds
        else:
            raise TypeError("project contains an unknown observer configuration")
    return MappingProxyType(result)


def _validate_observer_runtime_inputs(
    observers: Mapping[str, Observer],
    *,
    invocation_timeouts_ns: Mapping[str, int],
    owner_epoch: int,
    fresh_id: FreshIdFactory,
) -> None:
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        observers,
        Mapping,
    ) or any(
        type(key) is not str
        or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            value,
            Observer,
        )
        for key, value in observers.items()
    ):
        raise TypeError("observers must map names to Observer implementations")
    if type(owner_epoch) is not int or owner_epoch < 0:
        raise ValueError("owner_epoch must be a nonnegative integer")
    if (
        not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            invocation_timeouts_ns,
            Mapping,
        )
        or set(invocation_timeouts_ns) != set(observers)
        or any(type(value) is not int or value <= 0 for value in invocation_timeouts_ns.values())
    ):
        raise ValueError("invocation_timeouts_ns must provide one positive bound per observer")
    if not callable(fresh_id):
        raise TypeError("fresh_id must be callable")


def _runner_observation_id(
    context: AssertionRuntimeContext,
    *,
    observer_id: str,
    event_id: str,
) -> str:
    validate_planned_id(event_id, expected_kind=PlannedIdKind.EVENT)
    components = (
        "runner-observation-v1",
        context.scenario_id,
        context.assertion_id,
        event_id,
        observer_id,
    )
    digest = hashlib.sha256("\x00".join(components).encode()).digest()
    return f"observation_{encode_crockford_ulid(digest[:16])}"


def _safe_executable_alias(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_EXECUTABLE_ALIAS_LENGTH
        and Path(value).name == value
        and not any(character in "\r\n\x00" for character in value)
    )


def _apply_current_interpreter_alias(
    config: CommandObserverConfig,
    policy: CommandLaunchPolicy,
) -> CommandObserverConfig:
    alias = config.argv[0]
    if alias not in policy.current_interpreter_aliases:
        return config
    try:
        interpreter = Path(sys.executable).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("the current Python interpreter cannot be resolved") from error
    if not interpreter.is_absolute() or not interpreter.is_file():
        raise ValueError("the current Python interpreter path must be absolute")
    wire = config.to_wire()
    wire["argv"] = [str(interpreter), *config.argv[1:]]
    return CommandObserverConfig.model_validate(wire)


def _derive_http_policies(
    project: ProjectConfig,
    observer: HttpObserverConfig,
    *,
    runtime_public_authorization: str | None,
) -> HttpProbePolicies:
    if project.receiver.target_profile is TargetProfile.PUBLIC_AUTHORIZED:
        raise ValueError(
            "public HTTP observers require separately preflighted explicit endpoint policies"
        )
    base = observer.base_url.rstrip("/") + "/"
    return HttpProbePolicies(
        capabilities=_observer_destination_policy(
            project.receiver,
            urljoin(base, HTTP_CAPABILITIES_PATH.lstrip("/")),
            runtime_public_authorization=runtime_public_authorization,
        ),
        observe=_observer_destination_policy(
            project.receiver,
            urljoin(base, HTTP_OBSERVE_PATH.lstrip("/")),
            runtime_public_authorization=runtime_public_authorization,
        ),
    )


def _observer_destination_policy(
    receiver: ReceiverConfig,
    url: str,
    *,
    runtime_public_authorization: str | None,
) -> DestinationPolicy:
    parsed = urlsplit(url)
    if parsed.port is None:
        port = 443 if parsed.scheme.casefold() == "https" else 80
    else:
        port = parsed.port
    wire = receiver.to_wire()
    wire["url"] = url
    wire["allowed_ports"] = [port]
    observer_receiver = ReceiverConfig.model_validate(wire)
    return parse_destination_policy(
        observer_receiver,
        runtime_public_authorization=runtime_public_authorization,
    )


def _default_observer_executor(
    project: ProjectConfig,
    observer: HttpObserverConfig,
    clock: RuntimeClock,
) -> HttpAttemptExecutor:
    return HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=AnyIOResolver(),
            connector=AnyIOConnector(),
        ),
        timeouts=HttpTimeouts(
            connect_ns=observer.timeouts.connect.nanoseconds,
            write_ns=observer.timeouts.total.nanoseconds,
            read_ns=observer.timeouts.read.nanoseconds,
            pool_ns=observer.timeouts.total.nanoseconds,
            total_ns=observer.timeouts.total.nanoseconds,
        ),
        limits=HttpLimits(
            max_request_bytes=project.limits.max_request_bytes,
            response_capture_bytes=project.limits.max_response_capture_bytes,
        ),
        max_concurrency=project.limits.max_concurrency,
        clock=clock,
    )


def _new_request_id() -> str:
    return f"request_{encode_crockford_ulid(secrets.token_bytes(16))}"


def _is_observer_assertion(value: object) -> bool:
    return type(value) in {
        ProcessingCountAssertion,
        CallbackCountAssertion,
        JournalCountAssertion,
        ResourceExistsAssertion,
        ResourceAbsentAssertion,
        ResourceFieldAssertion,
        EventualStateAssertion,
        OrderedTransitionAssertion,
        NoPartialSideEffectAssertion,
    }


__all__ = [
    "CommandLaunchPolicy",
    "CommittedObserverAssertion",
    "ObserverAdapterBuilder",
    "ProjectObserverAdapterBuilder",
    "ProjectObserverAssertionExecutorFactory",
    "RunnerObserverAssertionExecutor",
    "ScenarioObserverAssertion",
    "ScenarioObserverAssertionResult",
    "ScenarioObserverAssertionRuntime",
    "derive_observer_queries",
]
