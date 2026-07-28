"""Bounded journal-owned read model for offline report regeneration."""
# ruff: noqa: D107, EM101, EM102, INP001, PLR2004, TRY003

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, cast

from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    AttemptClassification,
    AttemptEvidenceState,
    ObservationStatus,
)
from webhook_receiver_conformance.domain.identifiers import validate_run_id
from webhook_receiver_conformance.domain.models import (
    AssertionEvaluation,
    AttemptEvidence,
    RequestMetadata,
    ResponseMetadata,
    TransportError,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.observers.protocol import (
    ObservationRecord,
    ObservationRecordError,
    ObserverEvidence,
)

from .repositories import ProjectionIntegrityError
from .service import (
    MAX_RESULT_ROWS,
    JournalService,
    JournalStatement,
    JournalTransaction,
    SqlValue,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from webhook_receiver_conformance.types import JsonValue

MAX_REPORT_READ_RECORDS = 100_000
MAX_REPORT_SCENARIOS = 10_000
MAX_REPORT_EVIDENCE_LINKS = 100_000


@dataclass(frozen=True, slots=True)
class JournalReportRun:
    """Stable run identity and terminal metadata used by report reduction."""

    run_id: str
    manifest_id: str
    state: str
    created_at: str
    terminal_category: ResultCategory | None
    terminal_at: str | None


@dataclass(frozen=True, slots=True)
class JournalReportScenario:
    """One journal scenario projection in manifest order."""

    scenario_id: str
    ordinal: int
    name: str
    state: str


@dataclass(frozen=True, slots=True)
class JournalReportAttempt:
    """One terminal attempt record and its stable order coordinates."""

    record: AttemptEvidence
    scenario_ordinal: int
    delivery_ordinal: int
    attempt_ordinal: int
    response_headers_elapsed_ns: int | None


@dataclass(frozen=True, slots=True)
class JournalReportObservation:
    """One terminal observer sample and its stable journal order."""

    record: ObservationRecord
    scenario_ordinal: int
    observation_ordinal: int


@dataclass(frozen=True, slots=True)
class JournalReportAssertion:
    """One terminal assertion evaluation and its lifecycle classification."""

    record: AssertionEvaluation
    scenario_ordinal: int
    assertion_state: AssertionState


@dataclass(frozen=True, slots=True)
class JournalReportSnapshot:
    """One transactionally consistent set of authoritative report inputs."""

    run: JournalReportRun
    scenarios: tuple[JournalReportScenario, ...]
    attempts: tuple[JournalReportAttempt, ...]
    observations: tuple[JournalReportObservation, ...]
    assertions: tuple[JournalReportAssertion, ...]


class JournalReportReader:
    """Load a complete report snapshot through the service-owned connection."""

    __slots__ = ("_service",)

    def __init__(self, service: JournalService) -> None:
        if type(service) is not JournalService:
            raise TypeError("service must be a JournalService")
        self._service = service

    async def load(self, run_id: str | None = None) -> JournalReportSnapshot:
        """Load all terminal report facts in one journal transaction.

        Omitting ``run_id`` loads the database's schema-enforced sole run.
        """
        stable_run_id = None if run_id is None else validate_run_id(run_id)
        return await self._service.execute(_LoadJournalReportSnapshot(stable_run_id))


@dataclass(frozen=True, slots=True)
class _LoadJournalReportSnapshot:
    run_id: str | None

    def execute(self, transaction: JournalTransaction) -> JournalReportSnapshot:
        run = (
            _load_only_run(transaction)
            if self.run_id is None
            else _load_run(transaction, self.run_id)
        )
        run_id = run.run_id
        scenarios = _load_scenarios(transaction, run_id)
        attempts = _load_attempts(transaction, run_id)
        observations = _load_observations(transaction, run_id)
        assertions = _load_assertions(transaction, run_id)
        scenario_ids = {item.scenario_id for item in scenarios}
        if (
            any(item.record.scenario_id not in scenario_ids for item in attempts)
            or any(item.record.scenario_id not in scenario_ids for item in observations)
            or any(item.record.scenario_id not in scenario_ids for item in assertions)
        ):
            raise ProjectionIntegrityError("report evidence references a missing scenario")
        return JournalReportSnapshot(
            run=run,
            scenarios=scenarios,
            attempts=attempts,
            observations=observations,
            assertions=assertions,
        )


def _load_run(transaction: JournalTransaction, run_id: str) -> JournalReportRun:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT
                run_id, manifest_id, state, created_at,
                terminal_category, terminal_at
            FROM runs
            WHERE run_id = ?
            """,
            (run_id,),
        )
    )
    if len(result.rows) != 1 or len(result.rows[0]) != 6:
        raise ProjectionIntegrityError("report run identity is missing or not unique")
    row = result.rows[0]
    category_text = _optional_text(row[4], name="run terminal category")
    try:
        category = None if category_text is None else ResultCategory(category_text)
    except ValueError as error:
        raise ProjectionIntegrityError("run terminal category is invalid") from error
    return JournalReportRun(
        run_id=_text(row[0], name="run_id"),
        manifest_id=_text(row[1], name="manifest_id"),
        state=_text(row[2], name="run state"),
        created_at=_text(row[3], name="run created_at"),
        terminal_category=category,
        terminal_at=_optional_text(row[5], name="run terminal_at"),
    )


def _load_only_run(transaction: JournalTransaction) -> JournalReportRun:
    result = transaction.execute(
        JournalStatement(
            """
            SELECT
                run_id, manifest_id, state, created_at,
                terminal_category, terminal_at
            FROM runs
            ORDER BY run_id
            LIMIT 2
            """
        )
    )
    if len(result.rows) != 1:
        raise ProjectionIntegrityError("journal does not contain exactly one report run")
    run_id = _text(result.rows[0][0], name="run_id")
    return _load_run(transaction, run_id)


def _load_scenarios(
    transaction: JournalTransaction,
    run_id: str,
) -> tuple[JournalReportScenario, ...]:
    rows = _paged_rows(
        transaction,
        """
        SELECT scenario_id, ordinal, name, state
        FROM scenarios
        WHERE run_id = ?
        ORDER BY ordinal, scenario_id
        """,
        (run_id,),
        maximum=MAX_REPORT_SCENARIOS,
        name="scenario",
    )
    scenarios = tuple(
        JournalReportScenario(
            scenario_id=_text(row[0], name="scenario_id"),
            ordinal=_integer(row[1], name="scenario ordinal"),
            name=_text(row[2], name="scenario name"),
            state=_text(row[3], name="scenario state"),
        )
        for row in rows
    )
    if tuple(item.ordinal for item in scenarios) != tuple(range(len(scenarios))):
        raise ProjectionIntegrityError("scenario ordinals are not contiguous")
    return scenarios


def _load_attempts(
    transaction: JournalTransaction,
    run_id: str,
) -> tuple[JournalReportAttempt, ...]:
    rows = _paged_rows(
        transaction,
        """
        SELECT
            attempt_records.record_id,
            attempt_records.schema_version,
            attempt_records.run_id,
            attempt_records.scenario_id,
            attempt_records.event_id,
            attempt_records.delivery_id,
            attempt_records.attempt_id,
            attempt_records.sequence,
            attempt_records.recorded_at,
            attempt_records.logical_time_ns,
            attempt_records.monotonic_elapsed_ns,
            attempt_records.state,
            attempt_records.classification,
            attempt_records.request_method,
            attempt_records.request_url_redacted,
            attempt_records.request_body_sha256,
            attempt_records.request_byte_length,
            attempt_records.request_header_names_json,
            attempt_records.response_status,
            attempt_records.response_body_sha256,
            attempt_records.response_captured_bytes,
            attempt_records.response_truncated,
            attempt_records.error_category,
            attempt_records.error_message_redacted,
            attempt_records.error_phase,
            attempt_records.response_headers_elapsed_ns,
            scenarios.ordinal,
            deliveries.ordinal,
            attempts.ordinal
        FROM attempt_records
        JOIN attempts
          ON attempts.run_id = attempt_records.run_id
         AND attempts.attempt_id = attempt_records.attempt_id
        JOIN deliveries
          ON deliveries.run_id = attempts.run_id
         AND deliveries.delivery_id = attempts.delivery_id
        JOIN scenarios
          ON scenarios.run_id = attempts.run_id
         AND scenarios.scenario_id = attempts.scenario_id
        WHERE attempt_records.run_id = ?
        ORDER BY attempt_records.sequence, attempt_records.record_id
        """,
        (run_id,),
        maximum=MAX_REPORT_READ_RECORDS,
        name="attempt report",
    )
    return tuple(_attempt_from_row(row) for row in rows)


def _attempt_from_row(row: Sequence[object]) -> JournalReportAttempt:
    if len(row) != 29:
        raise ProjectionIntegrityError("attempt report row has an invalid shape")
    request: RequestMetadata | None = None
    if row[13] is not None:
        method = _text(row[13], name="request method")
        headers = _json_blob(row[17], name="request header names", allow_null=False)
        if (
            method != "POST"
            or type(headers) is not list
            or any(type(item) is not str for item in cast("list[object]", headers))
        ):
            raise ProjectionIntegrityError("attempt request metadata is invalid")
        request = RequestMetadata(
            method="POST",
            url_redacted=_text(row[14], name="request URL"),
            body_sha256=_text(row[15], name="request body digest"),
            byte_length=_integer(row[16], name="request byte length"),
            header_names=tuple(cast("list[str]", headers)),
        )
    response: ResponseMetadata | None = None
    if row[18] is not None:
        truncated = _integer(row[21], name="response truncated")
        if truncated not in {0, 1}:
            raise ProjectionIntegrityError("response truncated flag is invalid")
        response = ResponseMetadata(
            status=_integer(row[18], name="response status"),
            body_sha256=_optional_text(row[19], name="response body digest"),
            captured_bytes=_integer(row[20], name="response captured bytes"),
            truncated=bool(truncated),
        )
    error_record: TransportError | None = None
    if row[22] is not None:
        error_record = TransportError(
            category=_text(row[22], name="attempt error category"),
            message_redacted=_text(row[23], name="attempt error message"),
            phase=_optional_text(row[24], name="attempt error phase"),
        )
    if _text(row[1], name="attempt schema version") != "1.0":
        raise ProjectionIntegrityError("attempt report schema version is unsupported")
    try:
        record = AttemptEvidence(
            schema_version="1.0",
            record_id=_text(row[0], name="attempt record_id"),
            run_id=_text(row[2], name="attempt run_id"),
            scenario_id=_text(row[3], name="attempt scenario_id"),
            event_id=_text(row[4], name="attempt event_id"),
            delivery_id=_text(row[5], name="attempt delivery_id"),
            attempt_id=_text(row[6], name="attempt_id"),
            sequence=_integer(row[7], name="attempt sequence"),
            recorded_at=_utc_datetime(row[8], name="attempt recorded_at"),
            logical_time_ns=_optional_integer(row[9], name="attempt logical_time_ns"),
            monotonic_elapsed_ns=_optional_integer(
                row[10],
                name="attempt monotonic elapsed",
            ),
            state=AttemptEvidenceState(_text(row[11], name="attempt evidence state")),
            classification=AttemptClassification(_text(row[12], name="attempt classification")),
            request=request,
            response=response,
            error=error_record,
        )
        return JournalReportAttempt(
            record=record,
            scenario_ordinal=_integer(row[26], name="attempt scenario ordinal"),
            delivery_ordinal=_integer(row[27], name="attempt delivery ordinal"),
            attempt_ordinal=_integer(row[28], name="attempt ordinal"),
            response_headers_elapsed_ns=_optional_integer(
                row[25],
                name="response headers elapsed",
            ),
        )
    except (TypeError, ValueError) as error:
        raise ProjectionIntegrityError("attempt report evidence is invalid") from error


def _load_observations(
    transaction: JournalTransaction,
    run_id: str,
) -> tuple[JournalReportObservation, ...]:
    rows = _paged_rows(
        transaction,
        """
        SELECT
            observation_samples.record_id,
            observation_samples.run_id,
            observation_samples.scenario_id,
            observation_samples.observation_id,
            observation_samples.sample_id,
            observer_series.observer_id,
            observation_samples.sample_sequence,
            observation_samples.recorded_at,
            observation_samples.status,
            observer_series.event_id,
            observation_samples.snapshot_id,
            observation_samples.evidence_json,
            observation_samples.error_json,
            scenarios.ordinal
        FROM observation_samples
        JOIN observer_series
          ON observer_series.run_id = observation_samples.run_id
         AND observer_series.scenario_id = observation_samples.scenario_id
         AND observer_series.observation_id = observation_samples.observation_id
        JOIN scenarios
          ON scenarios.run_id = observation_samples.run_id
         AND scenarios.scenario_id = observation_samples.scenario_id
        WHERE observation_samples.run_id = ?
          AND observation_samples.status <> 'pending'
        ORDER BY
            scenarios.ordinal,
            observer_series.checkpoint,
            observer_series.observer_id,
            COALESCE(observer_series.event_id, ''),
            observation_samples.observation_id,
            observation_samples.sample_sequence,
            observation_samples.record_id
        """,
        (run_id,),
        maximum=MAX_REPORT_READ_RECORDS,
        name="observation report",
    )
    ordinals: dict[tuple[int, str], int] = {}
    next_ordinal: dict[int, int] = {}
    result: list[JournalReportObservation] = []
    for row in rows:
        if len(row) != 14:
            raise ProjectionIntegrityError("observation report row has an invalid shape")
        scenario_ordinal = _integer(row[13], name="observation scenario ordinal")
        observation_id = _text(row[3], name="observation_id")
        key = (scenario_ordinal, observation_id)
        if key not in ordinals:
            ordinal = next_ordinal.get(scenario_ordinal, 0)
            ordinals[key] = ordinal
            next_ordinal[scenario_ordinal] = ordinal + 1
        result.append(
            JournalReportObservation(
                record=_observation_from_row(row[:13]),
                scenario_ordinal=scenario_ordinal,
                observation_ordinal=ordinals[key],
            )
        )
    return tuple(result)


def _observation_from_row(row: Sequence[object]) -> ObservationRecord:
    evidence_raw = _json_blob(row[11], name="observation evidence", allow_null=False)
    error_raw = _json_blob(row[12], name="observation error", allow_null=True)
    if type(evidence_raw) is not list:
        raise ProjectionIntegrityError("observation evidence is not an array")
    try:
        return ObservationRecord(
            schema_version="1.0",
            record_id=_text(row[0], name="observation record_id"),
            run_id=_text(row[1], name="observation run_id"),
            scenario_id=_text(row[2], name="observation scenario_id"),
            observation_id=_text(row[3], name="observation_id"),
            sample_id=_text(row[4], name="observation sample_id"),
            observer_id=_text(row[5], name="observer_id"),
            sample_sequence=_integer(row[6], name="sample sequence"),
            recorded_at=_text(row[7], name="observation recorded_at"),
            status=ObservationStatus(_text(row[8], name="observation status")),
            event_id=_optional_text(row[9], name="observation event_id"),
            snapshot_id=_optional_text(row[10], name="observation snapshot_id"),
            evidence=tuple(
                ObserverEvidence.model_validate(item) for item in cast("list[object]", evidence_raw)
            ),
            error=(None if error_raw is None else ObservationRecordError.model_validate(error_raw)),
        )
    except (TypeError, ValueError) as error:
        raise ProjectionIntegrityError("observation report evidence is invalid") from error


def _load_assertions(
    transaction: JournalTransaction,
    run_id: str,
) -> tuple[JournalReportAssertion, ...]:
    rows = _paged_rows(
        transaction,
        """
        SELECT
            assertion_evaluations.evaluation_id,
            assertion_evaluations.record_id,
            assertion_evaluations.run_id,
            assertion_evaluations.scenario_id,
            assertion_evaluations.assertion_id,
            assertion_evaluations.evaluation_sequence,
            assertion_evaluations.result,
            assertion_evaluations.recorded_at,
            assertion_evaluations.expected_json,
            assertion_evaluations.actual_json,
            assertion_evaluations.comparison,
            assertion_evaluations.message,
            assertions.type,
            assertions.state,
            scenarios.ordinal
        FROM assertion_evaluations
        JOIN assertions
          ON assertions.run_id = assertion_evaluations.run_id
         AND assertions.assertion_id = assertion_evaluations.assertion_id
        JOIN scenarios
          ON scenarios.run_id = assertion_evaluations.run_id
         AND scenarios.scenario_id = assertion_evaluations.scenario_id
        WHERE assertion_evaluations.run_id = ?
          AND assertion_evaluations.result <> 'pending'
        ORDER BY
            scenarios.ordinal,
            assertion_evaluations.assertion_id,
            assertion_evaluations.evaluation_sequence,
            assertion_evaluations.record_id
        """,
        (run_id,),
        maximum=MAX_REPORT_READ_RECORDS,
        name="assertion report",
    )
    links = _load_evidence_links(transaction, run_id)
    result: list[JournalReportAssertion] = []
    for row in rows:
        if len(row) != 15:
            raise ProjectionIntegrityError("assertion report row has an invalid shape")
        evaluation_id = _text(row[0], name="evaluation_id")
        try:
            record = AssertionEvaluation(
                schema_version="1.0",
                record_id=_text(row[1], name="assertion record_id"),
                run_id=_text(row[2], name="assertion run_id"),
                scenario_id=_text(row[3], name="assertion scenario_id"),
                assertion_id=_text(row[4], name="assertion_id"),
                evaluation_sequence=_integer(row[5], name="evaluation sequence"),
                result=AssertionResult(_text(row[6], name="assertion result")),
                recorded_at=_utc_datetime(row[7], name="assertion recorded_at"),
                type=_text(row[12], name="assertion type"),
                expected=cast(
                    "JsonValue",
                    _json_blob(row[8], name="assertion expected", allow_null=True),
                ),
                actual=cast(
                    "JsonValue",
                    _json_blob(row[9], name="assertion actual", allow_null=True),
                ),
                comparison=_optional_text(row[10], name="assertion comparison"),
                evidence_refs=links.get(evaluation_id, ()),
                message=_optional_text(row[11], name="assertion message"),
            )
            result.append(
                JournalReportAssertion(
                    record=record,
                    scenario_ordinal=_integer(row[14], name="assertion scenario ordinal"),
                    assertion_state=AssertionState(_text(row[13], name="assertion state")),
                )
            )
        except (TypeError, ValueError) as error:
            raise ProjectionIntegrityError("assertion report evidence is invalid") from error
    return tuple(result)


def _load_evidence_links(
    transaction: JournalTransaction,
    run_id: str,
) -> dict[str, tuple[str, ...]]:
    rows = _paged_rows(
        transaction,
        """
        SELECT
            evidence_links.evaluation_id,
            evidence_links.ordinal,
            evidence_links.evidence_id
        FROM evidence_links
        JOIN assertion_evaluations
          ON assertion_evaluations.run_id = evidence_links.run_id
         AND assertion_evaluations.evaluation_id = evidence_links.evaluation_id
        WHERE evidence_links.run_id = ?
          AND assertion_evaluations.result <> 'pending'
        ORDER BY evidence_links.evaluation_id, evidence_links.ordinal
        """,
        (run_id,),
        maximum=MAX_REPORT_EVIDENCE_LINKS,
        name="assertion evidence link",
    )
    grouped: dict[str, list[str]] = {}
    expected_ordinals: dict[str, int] = {}
    for row in rows:
        if len(row) != 3:
            raise ProjectionIntegrityError("assertion evidence link row has an invalid shape")
        evaluation_id = _text(row[0], name="evidence evaluation_id")
        ordinal = _integer(row[1], name="evidence ordinal")
        expected = expected_ordinals.get(evaluation_id, 0)
        if ordinal != expected:
            raise ProjectionIntegrityError("assertion evidence ordinals are not contiguous")
        expected_ordinals[evaluation_id] = expected + 1
        grouped.setdefault(evaluation_id, []).append(_text(row[2], name="assertion evidence_id"))
    return {key: tuple(value) for key, value in grouped.items()}


def _paged_rows(
    transaction: JournalTransaction,
    sql: str,
    parameters: tuple[SqlValue, ...],
    *,
    maximum: int,
    name: str,
) -> tuple[tuple[SqlValue, ...], ...]:
    rows: list[tuple[SqlValue, ...]] = []
    offset = 0
    while offset < maximum:
        remaining = maximum - offset
        limit = min(MAX_RESULT_ROWS, remaining)
        page = transaction.execute(
            JournalStatement(
                f"{sql}\nLIMIT ? OFFSET ?",
                (*parameters, limit, offset),
            )
        ).rows
        rows.extend(page)
        offset += len(page)
        if len(page) < limit:
            return tuple(rows)
    overflow = transaction.execute(
        JournalStatement(
            f"{sql}\nLIMIT 1 OFFSET ?",
            (*parameters, offset),
        )
    )
    if overflow.rows:
        raise ProjectionIntegrityError(f"{name} rows exceed the report read limit")
    return tuple(rows)


def _json_blob(value: object, *, name: str, allow_null: bool) -> object:
    if value is None:
        if allow_null:
            return None
        raise ProjectionIntegrityError(f"{name} is missing")
    if type(value) is not bytes:
        raise ProjectionIntegrityError(f"{name} is not a BLOB")
    try:
        return json.loads(
            value.decode("ascii"),
            object_pairs_hook=_unique_json_object,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ProjectionIntegrityError(f"{name} is malformed") from error


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_float(_value: str) -> object:
    raise ValueError("floating-point JSON values are prohibited")


def _reject_json_constant(_value: str) -> object:
    raise ValueError("non-finite JSON values are prohibited")


def _utc_datetime(value: object, *, name: str) -> datetime:
    text = _text(value, name=name)
    try:
        parsed = datetime.fromisoformat(f"{text[:-1]}+00:00")
    except (ValueError, TypeError) as error:
        raise ProjectionIntegrityError(f"{name} is invalid") from error
    if not text.endswith("Z") or parsed.utcoffset() is None:
        raise ProjectionIntegrityError(f"{name} is invalid")
    return parsed


def _text(value: object, *, name: str) -> str:
    if type(value) is not str:
        raise ProjectionIntegrityError(f"{name} is not text")
    return value


def _optional_text(value: object, *, name: str) -> str | None:
    return None if value is None else _text(value, name=name)


def _integer(value: object, *, name: str) -> int:
    if type(value) is not int:
        raise ProjectionIntegrityError(f"{name} is not an integer")
    return value


def _optional_integer(value: object, *, name: str) -> int | None:
    return None if value is None else _integer(value, name=name)


__all__ = [
    "MAX_REPORT_EVIDENCE_LINKS",
    "MAX_REPORT_READ_RECORDS",
    "MAX_REPORT_SCENARIOS",
    "JournalReportAssertion",
    "JournalReportAttempt",
    "JournalReportObservation",
    "JournalReportReader",
    "JournalReportRun",
    "JournalReportScenario",
    "JournalReportSnapshot",
]
