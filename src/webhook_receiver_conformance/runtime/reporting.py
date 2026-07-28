"""Production offline projection and installation of reports from journal truth."""
# ruff: noqa: C901, D105, EM101, INP001, PLR0911, TRY003

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from webhook_receiver_conformance.cli.exit_codes import CommandSurface
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    ObservationStatus,
)
from webhook_receiver_conformance.domain.models import (
    AggregateRunOutcome,
    ArtifactPaths,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.journal.artifacts import ArtifactRecord
from webhook_receiver_conformance.journal.reporting import (
    JournalReportAssertion,
    JournalReportAttempt,
    JournalReportObservation,
    JournalReportReader,
    JournalReportScenario,
    JournalReportSnapshot,
)
from webhook_receiver_conformance.journal.schema import JOURNAL_FILENAME
from webhook_receiver_conformance.journal.service import JournalService
from webhook_receiver_conformance.manifest.loader import load_replay_bundle
from webhook_receiver_conformance.reporting.html import (
    HtmlReportInput,
    HtmlScenarioResult,
    render_html,
)
from webhook_receiver_conformance.reporting.json_reports import (
    AssertionReportRecord,
    DeliveryReportRecord,
    FailureCausalTrace,
    ObservationReportRecord,
    render_json_reports,
)
from webhook_receiver_conformance.reporting.junit import (
    JUnitCase,
    JUnitCaseKind,
    JUnitErrorType,
    JUnitRun,
    JUnitScenario,
    render_junit,
)
from webhook_receiver_conformance.reporting.summary import (
    SummarySource,
    build_result_summary,
    reduce_result_categories,
)
from webhook_receiver_conformance.reporting.writer import (
    ReportPayloads,
    ReportWriter,
)
from webhook_receiver_conformance.runtime.verdicts import (
    classify_assertion_verdict,
    classify_attempt_verdict,
)

if TYPE_CHECKING:
    from pathlib import Path

    from webhook_receiver_conformance.manifest.models import RunManifest


class ReportFormat(StrEnum):
    """Stable report-format names accepted by the runtime adapter."""

    JSON = "json"
    JUNIT = "junit"
    HTML = "html"


ALL_REPORT_FORMATS: Final = (
    ReportFormat.JSON,
    ReportFormat.JUNIT,
    ReportFormat.HTML,
)
_PATHS_BY_FORMAT: Final = {
    ReportFormat.JSON: frozenset(
        {
            "run-manifest.json",
            "deliveries.jsonl",
            "observations.jsonl",
            "assertions.jsonl",
            "result-summary.json",
        }
    ),
    ReportFormat.JUNIT: frozenset({"junit.xml"}),
    ReportFormat.HTML: frozenset({"results.html"}),
}
_ASSERTION_ERROR_CATEGORIES: Final = frozenset(
    {
        ResultCategory.ENVIRONMENT_ERROR,
        ResultCategory.HARNESS_ERROR,
        ResultCategory.INVALID_INPUT,
    }
)


@dataclass(frozen=True, slots=True)
class ReportRegenerationResult:
    """Installed complete report set with caller-selected artifact records."""

    run_id: str
    formats: tuple[ReportFormat, ...]
    outcome: AggregateRunOutcome
    normalized_digest: str
    records: tuple[ArtifactRecord, ...]

    def __post_init__(self) -> None:
        if (
            type(self.formats) is not tuple
            or not self.formats
            or any(type(item) is not ReportFormat for item in self.formats)
            or len(set(self.formats)) != len(self.formats)
        ):
            raise ValueError("formats must contain unique ReportFormat values")
        if type(self.outcome) is not AggregateRunOutcome:
            raise TypeError("outcome must be an AggregateRunOutcome")
        if self.outcome.run_id != self.run_id:
            raise ValueError("outcome and regeneration run IDs differ")
        selected = _selected_paths(self.formats)
        if (
            type(self.records) is not tuple
            or any(type(item) is not ArtifactRecord for item in self.records)
            or frozenset(item.relative_path for item in self.records) != selected
        ):
            raise ValueError("records differ from selected report formats")


async def regenerate_run_reports(
    run_directory: Path,
    *,
    formats: tuple[ReportFormat, ...] = ALL_REPORT_FORMATS,
    service: JournalService | None = None,
) -> ReportRegenerationResult:
    """Verify local inputs, project all reports, and install them atomically.

    The complete seven-file set is always regenerated so the artifact registry remains
    coherent. ``formats`` only filters the records returned to a caller.
    """
    selected_formats = _validate_formats(formats)
    bundle = load_replay_bundle(run_directory)
    if service is not None:
        if type(service) is not JournalService:
            raise TypeError("service must be a JournalService or None")
        return await _regenerate_with_service(
            service,
            run_directory=bundle.directory,
            manifest=bundle.manifest,
            formats=selected_formats,
        )
    async with JournalService.open(bundle.directory / JOURNAL_FILENAME) as owned_service:
        return await _regenerate_with_service(
            owned_service,
            run_directory=bundle.directory,
            manifest=bundle.manifest,
            formats=selected_formats,
        )


async def _regenerate_with_service(
    service: JournalService,
    *,
    run_directory: Path,
    manifest: RunManifest,
    formats: tuple[ReportFormat, ...],
) -> ReportRegenerationResult:
    snapshot = await JournalReportReader(service).load()
    _validate_manifest_scope(snapshot, manifest)
    deliveries = tuple(
        DeliveryReportRecord(
            record=item.record,
            scenario_ordinal=item.scenario_ordinal,
            delivery_ordinal=item.delivery_ordinal,
            attempt_ordinal=item.attempt_ordinal,
        )
        for item in snapshot.attempts
    )
    observations = tuple(
        ObservationReportRecord(
            record=item.record,
            scenario_ordinal=item.scenario_ordinal,
            observation_ordinal=item.observation_ordinal,
        )
        for item in snapshot.observations
    )
    assertion_ordinals = _assertion_ordinals(manifest)
    assertions = tuple(
        AssertionReportRecord(
            record=item.record,
            scenario_ordinal=item.scenario_ordinal,
            assertion_ordinal=assertion_ordinals[
                (item.record.scenario_id, item.record.assertion_id)
            ],
        )
        for item in snapshot.assertions
    )
    categories = _result_categories(snapshot)
    traces = _causal_traces(snapshot)
    failure_refs = _failure_refs(snapshot, traces)
    outcome = build_result_summary(
        SummarySource(
            run_id=snapshot.run.run_id,
            manifest_id=snapshot.run.manifest_id,
            generated_at=_report_timestamp(snapshot),
            scenario_ids=tuple(item.scenario_id for item in snapshot.scenarios),
            attempts=tuple(item.record for item in snapshot.attempts),
            observations=tuple(item.record for item in snapshot.observations),
            assertions=tuple(item.record for item in snapshot.assertions),
            categories=categories,
            failure_refs=failure_refs,
            artifacts=ArtifactPaths(
                manifest="run-manifest.json",
                deliveries="deliveries.jsonl",
                observations="observations.jsonl",
                assertions="assertions.jsonl",
                junit="junit.xml",
                html="results.html",
            ),
            command_surface=CommandSurface.RUN,
            durably_terminal=snapshot.run.terminal_category,
            cancellation_requested=False,
        )
    )
    json_reports = render_json_reports(
        manifest,
        outcome,
        deliveries=deliveries,
        observations=observations,
        assertions=assertions,
        causal_traces=traces,
    )
    junit = render_junit(_junit_run(snapshot, manifest))
    html = render_html(
        HtmlReportInput(
            artifacts=json_reports,
            scenarios=_html_scenarios(snapshot),
        )
    )
    installed = await ReportWriter(
        service=service,
        run_directory=run_directory,
    ).regenerate(
        snapshot.run.run_id,
        ReportPayloads(
            json_reports=json_reports,
            junit_xml=junit,
            html_report=html,
        ),
    )
    selected_paths = _selected_paths(formats)
    selected_records = tuple(
        item for item in installed.records if item.relative_path in selected_paths
    )
    return ReportRegenerationResult(
        run_id=snapshot.run.run_id,
        formats=formats,
        outcome=outcome,
        normalized_digest=installed.normalized_digest,
        records=selected_records,
    )


def _validate_manifest_scope(
    snapshot: JournalReportSnapshot,
    manifest: RunManifest,
) -> None:
    if snapshot.run.manifest_id != manifest.manifest_id:
        raise ValueError("journal and verified manifest identifiers differ")
    manifest_scenarios = tuple(item.scenario_id for item in manifest.scenarios)
    journal_scenarios = tuple(item.scenario_id for item in snapshot.scenarios)
    if manifest_scenarios != journal_scenarios:
        raise ValueError("journal scenarios differ from verified manifest order")
    assertion_plans = {
        (scenario.scenario_id, assertion.assertion_id): assertion.type
        for scenario in manifest.scenarios
        for assertion in scenario.assertions
    }
    for item in snapshot.assertions:
        key = (item.record.scenario_id, item.record.assertion_id)
        if assertion_plans.get(key) != item.record.type:
            raise ValueError("journal assertion differs from verified manifest")


def _assertion_ordinals(manifest: RunManifest) -> dict[tuple[str, str], int]:
    return {
        (scenario.scenario_id, assertion.assertion_id): ordinal
        for scenario in manifest.scenarios
        for ordinal, assertion in enumerate(scenario.assertions)
    }


def _report_timestamp(snapshot: JournalReportSnapshot) -> datetime:
    value = snapshot.run.terminal_at or snapshot.run.created_at
    try:
        result = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except (TypeError, ValueError) as error:
        raise ValueError("journal report timestamp is invalid") from error
    if not value.endswith("Z") or result.utcoffset() is None:
        raise ValueError("journal report timestamp is invalid")
    return result


def _result_categories(
    snapshot: JournalReportSnapshot,
) -> tuple[ResultCategory, ...]:
    categories = [
        *(_attempt_category(item) for item in snapshot.attempts),
        *(_observation_category(item) for item in snapshot.observations),
        *(
            _assertion_category(item, snapshot.run.terminal_category)
            for item in snapshot.assertions
        ),
    ]
    return tuple(categories) or (ResultCategory.PASS,)


def _attempt_category(item: JournalReportAttempt) -> ResultCategory:
    return classify_attempt_verdict(item.record.classification).category


def _observation_category(item: JournalReportObservation) -> ResultCategory:
    return {
        ObservationStatus.OK: ResultCategory.PASS,
        ObservationStatus.UNSUPPORTED: ResultCategory.UNSUPPORTED,
        ObservationStatus.ERROR: ResultCategory.ENVIRONMENT_ERROR,
        ObservationStatus.TIMEOUT: ResultCategory.ENVIRONMENT_ERROR,
        ObservationStatus.PENDING: ResultCategory.AMBIGUOUS,
    }[item.record.status]


def _assertion_category(
    item: JournalReportAssertion,
    run_category: ResultCategory | None,
) -> ResultCategory:
    result = item.record.result
    state = item.assertion_state
    if state is AssertionState.ERROR and result is AssertionResult.ERROR:
        if run_category is not None and run_category in _ASSERTION_ERROR_CATEGORIES:
            return run_category
        return ResultCategory.HARNESS_ERROR
    return classify_assertion_verdict(result, state).category


def _failure_refs(
    snapshot: JournalReportSnapshot,
    traces: tuple[FailureCausalTrace, ...],
) -> tuple[str, ...]:
    values = [
        *(
            item.record.record_id
            for item in snapshot.attempts
            if _attempt_category(item) is not ResultCategory.PASS
        ),
        *(
            item.record.record_id
            for item in snapshot.observations
            if _observation_category(item) is not ResultCategory.PASS
        ),
        *(item.assertion_record_id for item in traces),
    ]
    return tuple(dict.fromkeys(values))


def _causal_traces(
    snapshot: JournalReportSnapshot,
) -> tuple[FailureCausalTrace, ...]:
    attempts: dict[str, JournalReportAttempt] = {}
    for item in snapshot.attempts:
        attempts[item.record.attempt_id] = item
        attempts[item.record.record_id] = item
    observations: dict[str, JournalReportObservation] = {}
    for item in snapshot.observations:
        observations[item.record.observation_id] = item
        observations[item.record.sample_id] = item
        observations[item.record.record_id] = item
    traces: list[FailureCausalTrace] = []
    for item in snapshot.assertions:
        if item.record.result is AssertionResult.PASS:
            continue
        attempt = next(
            (
                attempts[reference]
                for reference in item.record.evidence_refs
                if reference in attempts
                and attempts[reference].record.scenario_id == item.record.scenario_id
            ),
            None,
        )
        observation = next(
            (
                observations[reference]
                for reference in item.record.evidence_refs
                if reference in observations
                and observations[reference].record.scenario_id == item.record.scenario_id
            ),
            None,
        )
        if attempt is None or observation is None:
            continue
        traces.append(
            FailureCausalTrace(
                assertion_record_id=item.record.record_id,
                scenario_id=item.record.scenario_id,
                event_id=attempt.record.event_id,
                delivery_id=attempt.record.delivery_id,
                attempt_id=attempt.record.attempt_id,
                attempt_record_id=attempt.record.record_id,
                observation_id=observation.record.observation_id,
                observation_record_id=observation.record.record_id,
                assertion_id=item.record.assertion_id,
                classification=_assertion_category(item, snapshot.run.terminal_category),
                immediate_evidence_refs=item.record.evidence_refs,
            )
        )
    return tuple(traces)


def _junit_run(
    snapshot: JournalReportSnapshot,
    manifest: RunManifest,
) -> JUnitRun:
    ordinals = _assertion_ordinals(manifest)
    scenarios = tuple(
        JUnitScenario(
            scenario_id=scenario.scenario_id,
            name=scenario.name,
            ordinal=scenario.ordinal,
            cases=_junit_cases(snapshot, scenario, ordinals),
        )
        for scenario in snapshot.scenarios
    )
    return JUnitRun(
        run_id=snapshot.run.run_id,
        manifest_id=snapshot.run.manifest_id,
        scenarios=scenarios,
        expected_assertion_count=len(snapshot.assertions),
        artifact_paths=(
            "deliveries.jsonl",
            "observations.jsonl",
            "assertions.jsonl",
        ),
    )


def _junit_cases(
    snapshot: JournalReportSnapshot,
    scenario: JournalReportScenario,
    assertion_ordinals: dict[tuple[str, str], int],
) -> tuple[JUnitCase, ...]:
    cases: list[JUnitCase] = []
    scenario_attempts = tuple(
        item for item in snapshot.attempts if item.record.scenario_id == scenario.scenario_id
    )
    attempts_by_reference: dict[str, JournalReportAttempt] = {}
    for attempt in scenario_attempts:
        attempts_by_reference[attempt.record.attempt_id] = attempt
        attempts_by_reference[attempt.record.record_id] = attempt
    for item in snapshot.assertions:
        if item.record.scenario_id != scenario.scenario_id:
            continue
        category = _assertion_category(item, snapshot.run.terminal_category)
        duration = max(
            (
                _attempt_duration(attempts_by_reference[reference])
                for reference in item.record.evidence_refs
                if reference in attempts_by_reference
            ),
            default=0,
        )
        cases.append(
            _junit_case(
                case_id=f"assertion-{item.record.record_id}",
                name=item.record.type,
                kind=JUnitCaseKind.ASSERTION,
                classification=category,
                duration_ns=duration,
                message=item.record.message,
                evidence_refs=item.record.evidence_refs,
                assertion_id=item.record.assertion_id,
                assertion_ordinal=assertion_ordinals[
                    (item.record.scenario_id, item.record.assertion_id)
                ],
            )
        )
    for item in scenario_attempts:
        category = _attempt_category(item)
        if category in {ResultCategory.PASS, ResultCategory.RECEIVER_FAILURE}:
            continue
        cases.append(
            _junit_case(
                case_id=f"attempt-{item.record.record_id}",
                name=f"attempt {item.record.attempt_id}",
                kind=JUnitCaseKind.INFRASTRUCTURE,
                classification=category,
                duration_ns=_attempt_duration(item),
                message=(
                    item.record.error.message_redacted
                    if item.record.error is not None
                    else "Attempt did not produce a comparable receiver result."
                ),
                evidence_refs=(item.record.record_id,),
            )
        )
    for item in snapshot.observations:
        if item.record.scenario_id != scenario.scenario_id:
            continue
        category = _observation_category(item)
        if category is ResultCategory.PASS:
            continue
        cases.append(
            _junit_case(
                case_id=f"observation-{item.record.record_id}",
                name=f"observation {item.record.observation_id}",
                kind=JUnitCaseKind.INFRASTRUCTURE,
                classification=category,
                duration_ns=0,
                message=(
                    item.record.error.message_redacted
                    if item.record.error is not None
                    else "Observer capability is unsupported."
                ),
                evidence_refs=(item.record.record_id,),
            )
        )
    if not cases:
        fallback = _scenario_state_category(scenario, snapshot.run.terminal_category)
        if fallback is not ResultCategory.PASS:
            cases.append(
                _junit_case(
                    case_id=f"scenario-{scenario.ordinal}-result",
                    name="scenario terminal result",
                    kind=JUnitCaseKind.INFRASTRUCTURE,
                    classification=fallback,
                    duration_ns=0,
                    message="Scenario completed without a more specific exported testcase.",
                    evidence_refs=(),
                )
            )
    return tuple(cases)


def _junit_case(  # noqa: PLR0913
    *,
    case_id: str,
    name: str,
    kind: JUnitCaseKind,
    classification: ResultCategory,
    duration_ns: int,
    message: str | None,
    evidence_refs: tuple[str, ...],
    assertion_id: str | None = None,
    assertion_ordinal: int | None = None,
) -> JUnitCase:
    error_type = {
        ResultCategory.ENVIRONMENT_ERROR: JUnitErrorType.ENVIRONMENT_ERROR,
        ResultCategory.HARNESS_ERROR: JUnitErrorType.HARNESS_ERROR,
        ResultCategory.AMBIGUOUS: JUnitErrorType.AMBIGUOUS_OUTCOME,
        ResultCategory.INVALID_INPUT: JUnitErrorType.INVALID_INPUT,
    }.get(classification)
    reason_code = {
        ResultCategory.UNSUPPORTED: "UNSUPPORTED_CAPABILITY",
        ResultCategory.CANCELLED: "CANCELLED_BY_OPERATOR",
    }.get(classification)
    return JUnitCase(
        case_id=case_id,
        name=name,
        kind=kind,
        classification=classification,
        physical_duration_ns=duration_ns,
        assertion_id=assertion_id,
        assertion_ordinal=assertion_ordinal,
        message=message,
        reason_code=reason_code,
        error_type=error_type,
        evidence_refs=evidence_refs,
    )


def _attempt_duration(item: JournalReportAttempt) -> int:
    return item.record.monotonic_elapsed_ns or item.response_headers_elapsed_ns or 0


def _html_scenarios(
    snapshot: JournalReportSnapshot,
) -> tuple[HtmlScenarioResult, ...]:
    result: list[HtmlScenarioResult] = []
    for scenario in snapshot.scenarios:
        categories = [
            _scenario_state_category(scenario, snapshot.run.terminal_category),
            *(
                _attempt_category(item)
                for item in snapshot.attempts
                if item.record.scenario_id == scenario.scenario_id
            ),
            *(
                _observation_category(item)
                for item in snapshot.observations
                if item.record.scenario_id == scenario.scenario_id
            ),
            *(
                _assertion_category(item, snapshot.run.terminal_category)
                for item in snapshot.assertions
                if item.record.scenario_id == scenario.scenario_id
            ),
        ]
        classification = reduce_result_categories(
            categories,
            surface=CommandSurface.RUN,
        ).category
        result.append(
            HtmlScenarioResult(
                scenario_id=scenario.scenario_id,
                name=scenario.name,
                ordinal=scenario.ordinal,
                classification=classification,
            )
        )
    return tuple(result)


def _scenario_state_category(
    scenario: JournalReportScenario,
    run_category: ResultCategory | None,
) -> ResultCategory:
    if scenario.state == "passed":
        return ResultCategory.PASS
    if scenario.state == "failed":
        return ResultCategory.RECEIVER_FAILURE
    if scenario.state == "ambiguous":
        return ResultCategory.AMBIGUOUS
    if scenario.state == "cancelled":
        return ResultCategory.CANCELLED
    if scenario.state == "skipped":
        return ResultCategory.UNSUPPORTED
    if scenario.state == "error":
        if run_category is not None and run_category in {
            ResultCategory.ENVIRONMENT_ERROR,
            ResultCategory.HARNESS_ERROR,
            ResultCategory.INVALID_INPUT,
            ResultCategory.UNSUPPORTED,
        }:
            return run_category
        return ResultCategory.HARNESS_ERROR
    return ResultCategory.PASS


def _validate_formats(
    formats: tuple[ReportFormat, ...],
) -> tuple[ReportFormat, ...]:
    if (
        type(formats) is not tuple
        or not formats
        or any(type(item) is not ReportFormat for item in formats)
        or len(set(formats)) != len(formats)
    ):
        raise ValueError("formats must contain unique ReportFormat values")
    return formats


def _selected_paths(formats: tuple[ReportFormat, ...]) -> frozenset[str]:
    result: set[str] = set()
    for item in formats:
        result.update(_PATHS_BY_FORMAT[item])
    return frozenset(result)


__all__ = [
    "ALL_REPORT_FORMATS",
    "ReportFormat",
    "ReportRegenerationResult",
    "regenerate_run_reports",
]
