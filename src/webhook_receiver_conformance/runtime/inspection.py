"""Verified offline adapter from one local run to the CLI inspection index."""
# ruff: noqa: C901, EM101, EM102, INP001, TRY003, TRY301

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from anyio.to_thread import run_sync
from pydantic import ValidationError

from webhook_receiver_conformance.cli.inspect import (
    MAX_INSPECTION_ARTIFACT_BYTES,
    MAX_INSPECTION_RECORDS,
    MAX_RAW_ARTIFACT_PATHS,
    InspectionDiagnosticLink,
    InspectionError,
    InspectionIndex,
    build_inspection_index,
)
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
)
from webhook_receiver_conformance.domain.models import AggregateRunOutcome
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.journal.artifacts import ArtifactRecord
from webhook_receiver_conformance.journal.integrity import verify_resume_integrity
from webhook_receiver_conformance.journal.reporting import (
    JournalReportAssertion,
    JournalReportAttempt,
    JournalReportObservation,
    JournalReportReader,
    JournalReportSnapshot,
)
from webhook_receiver_conformance.journal.schema import JOURNAL_FILENAME
from webhook_receiver_conformance.journal.service import (
    JournalService,
    JournalStatement,
    JournalTransaction,
)
from webhook_receiver_conformance.manifest.loader import load_replay_bundle
from webhook_receiver_conformance.reporting.json_reports import (
    FailureCausalTrace,
    JsonReportArtifacts,
    ReportCausalIndex,
)
from webhook_receiver_conformance.runtime.verdicts import (
    classify_assertion_verdict,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from webhook_receiver_conformance.manifest.loader import LoadedRunBundle
    from webhook_receiver_conformance.manifest.models import AssertionPlan, RunManifest

_SANITIZED_REPORT_PATHS: Final = (
    "run-manifest.json",
    "deliveries.jsonl",
    "observations.jsonl",
    "assertions.jsonl",
    "result-summary.json",
)
_MAX_ARTIFACT_REGISTRY_ROWS: Final = 128
_ARTIFACT_RECORD_COLUMNS: Final = 9
_MAX_REPORT_SET_BYTES: Final = 67_108_864
_READ_CHUNK_BYTES: Final = 65_536
_WINDOWS_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True, slots=True)
class _LoadArtifactRecords:
    run_id: str

    def execute(
        self,
        transaction: JournalTransaction,
    ) -> tuple[ArtifactRecord, ...]:
        result = transaction.execute(
            JournalStatement(
                """
                SELECT
                    artifact_id, run_id, relative_path, media_type,
                    byte_length, sha256, generated_at,
                    input_watermark, renderer_version
                FROM artifacts
                WHERE run_id = ?
                ORDER BY relative_path
                LIMIT ?
                """,
                (self.run_id, _MAX_ARTIFACT_REGISTRY_ROWS + 1),
            )
        )
        if len(result.rows) > _MAX_ARTIFACT_REGISTRY_ROWS:
            raise InspectionError("artifact registry exceeds the inspection limit")
        try:
            return tuple(_artifact_record(row) for row in result.rows)
        except (TypeError, ValueError) as error:
            raise InspectionError("artifact registry contains an invalid record") from error


@dataclass(frozen=True, slots=True)
class _JournalIdentity:
    device: int
    inode: int
    byte_length: int
    modified_ns: int
    changed_ns: int


async def load_inspection_index(run_directory: Path) -> InspectionIndex:
    """Verify one local run and build its exact, sanitized inspection index.

    This adapter performs no receiver, network, subprocess, or observer operation.
    Existing report bytes must match their journal registry entries and the journal
    evidence used to derive every causal edge.
    """
    bundle = load_replay_bundle(run_directory)
    database_path = bundle.directory / JOURNAL_FILENAME
    verify_resume_integrity(database_path)
    journal_before = _journal_identity(database_path)
    with tempfile.TemporaryDirectory(prefix="webhook-inspection-") as temporary:
        snapshot_path = await run_sync(
            _snapshot_journal_read_only,
            database_path,
            temporary,
        )
        try:
            async with JournalService.open(snapshot_path) as service:
                snapshot = await JournalReportReader(service).load()
                registered = await service.execute(_LoadArtifactRecords(snapshot.run.run_id))
        except ExceptionGroup as error:
            raise InspectionError("journal evidence failed integrity validation") from error
    _validate_run_scope(bundle.manifest, snapshot)
    artifacts = await run_sync(
        _read_registered_reports,
        bundle.directory,
        registered,
    )
    if _journal_identity(database_path) != journal_before:
        raise InspectionError("journal evidence changed during inspection")

    summary = _validate_report_coherence(
        bundle=bundle,
        snapshot=snapshot,
        artifacts=artifacts,
    )
    traces = _derive_causal_traces(bundle.manifest, snapshot)
    diagnostic_links = _diagnostic_links(summary, traces)
    raw_paths = _raw_blob_paths(bundle)
    return build_inspection_index(
        JsonReportArtifacts(
            manifest_json=artifacts["run-manifest.json"],
            deliveries_jsonl=artifacts["deliveries.jsonl"],
            observations_jsonl=artifacts["observations.jsonl"],
            assertions_jsonl=artifacts["assertions.jsonl"],
            result_summary_json=artifacts["result-summary.json"],
            causal_index=ReportCausalIndex(traces),
        ),
        diagnostic_links=diagnostic_links,
        raw_artifact_paths=raw_paths,
    )


def _snapshot_journal_read_only(
    database_path: Path,
    temporary_directory: str,
) -> Path:
    snapshot_path = Path(temporary_directory) / JOURNAL_FILENAME
    source: sqlite3.Connection | None = None
    destination: sqlite3.Connection | None = None
    try:
        source = sqlite3.connect(
            f"{database_path.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
            check_same_thread=True,
        )
        source.execute("PRAGMA query_only = ON")
        source.execute("PRAGMA trusted_schema = OFF")
        journal_mode = source.execute("PRAGMA journal_mode").fetchone()
        if journal_mode != ("delete",):
            raise InspectionError("inspection requires a DELETE-mode journal")
        destination = sqlite3.connect(
            snapshot_path,
            isolation_level=None,
            check_same_thread=True,
        )
        source.backup(destination)
    except InspectionError:
        raise
    except sqlite3.Error as error:
        raise InspectionError("journal read-only snapshot failed") from error
    finally:
        if destination is not None:
            destination.close()
        if source is not None:
            source.close()
    try:
        snapshot_path.chmod(0o600)
    except OSError as error:
        raise InspectionError("journal read-only snapshot is unavailable") from error
    return snapshot_path


def _journal_identity(database_path: Path) -> _JournalIdentity:
    try:
        metadata = database_path.stat(follow_symlinks=False)
    except OSError as error:
        raise InspectionError("journal database is unavailable") from error
    if not _private_regular_file(metadata):
        raise InspectionError("journal database is not a private regular file")
    return _JournalIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        byte_length=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _artifact_record(row: Sequence[object]) -> ArtifactRecord:
    if len(row) != _ARTIFACT_RECORD_COLUMNS:
        raise InspectionError("artifact registry row has an invalid shape")
    return ArtifactRecord(
        artifact_id=_text(row[0], name="artifact_id"),
        run_id=_text(row[1], name="artifact run_id"),
        relative_path=_text(row[2], name="artifact path"),
        media_type=_text(row[3], name="artifact media type"),
        byte_length=_integer(row[4], name="artifact byte length"),
        sha256=_text(row[5], name="artifact digest"),
        generated_at=_text(row[6], name="artifact timestamp"),
        input_watermark=_optional_text(row[7], name="artifact watermark"),
        renderer_version=_optional_text(row[8], name="artifact renderer"),
    )


def _read_registered_reports(
    run_directory: Path,
    records: tuple[ArtifactRecord, ...],
) -> dict[str, bytes]:
    by_path = {record.relative_path: record for record in records}
    if len(by_path) != len(records):
        raise InspectionError("artifact registry paths are not unique")
    missing = tuple(path for path in _SANITIZED_REPORT_PATHS if path not in by_path)
    if missing:
        raise InspectionError("sanitized report artifact registry is incomplete")
    total_bytes = sum(by_path[path].byte_length for path in _SANITIZED_REPORT_PATHS)
    if total_bytes > _MAX_REPORT_SET_BYTES:
        raise InspectionError("sanitized report set exceeds the inspection byte limit")
    return {
        path: _read_registered_file(run_directory, by_path[path])
        for path in _SANITIZED_REPORT_PATHS
    }


def _read_registered_file(run_directory: Path, record: ArtifactRecord) -> bytes:
    if (
        record.byte_length > MAX_INSPECTION_ARTIFACT_BYTES
        or record.relative_path not in _SANITIZED_REPORT_PATHS
    ):
        raise InspectionError("sanitized report artifact exceeds its inspection boundary")
    target = run_directory / record.relative_path
    descriptor = -1
    try:
        before = target.stat(follow_symlinks=False)
        if not _private_regular_file(before):
            raise InspectionError("sanitized report artifact is not a private regular file")
        descriptor = os.open(
            target,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not _same_content_identity(before, opened) or not _private_regular_file(opened):
            raise InspectionError("sanitized report artifact changed during secure open")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, MAX_INSPECTION_ARTIFACT_BYTES - observed + 1),
            )
            if not chunk:
                break
            observed += len(chunk)
            if observed > MAX_INSPECTION_ARTIFACT_BYTES:
                raise InspectionError("sanitized report artifact exceeds its byte limit")
            digest.update(chunk)
            chunks.append(chunk)
        after_descriptor = os.fstat(descriptor)
        after_path = target.stat(follow_symlinks=False)
    except InspectionError:
        raise
    except OSError as error:
        raise InspectionError("sanitized report artifact is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        not _same_view(before, after_path)
        or not _same_view(opened, after_descriptor)
        or not _same_content_identity(after_descriptor, after_path)
        or not _private_regular_file(after_path)
        or observed != record.byte_length
        or f"sha256:{digest.hexdigest()}" != record.sha256
    ):
        raise InspectionError("sanitized report artifact failed registry verification")
    return b"".join(chunks)


def _validate_run_scope(
    manifest: RunManifest,
    snapshot: JournalReportSnapshot,
) -> None:
    if snapshot.run.manifest_id != manifest.manifest_id:
        raise InspectionError("journal and verified manifest identifiers differ")
    if tuple(item.scenario_id for item in snapshot.scenarios) != tuple(
        item.scenario_id for item in manifest.scenarios
    ):
        raise InspectionError("journal scenarios differ from verified manifest order")
    manifest_deliveries = {
        (scenario.scenario_id, delivery.delivery_id): delivery
        for scenario in manifest.scenarios
        for delivery in scenario.deliveries
    }
    manifest_assertions = {
        (scenario.scenario_id, assertion.assertion_id): assertion
        for scenario in manifest.scenarios
        for assertion in scenario.assertions
    }
    for item in snapshot.attempts:
        delivery = manifest_deliveries.get((item.record.scenario_id, item.record.delivery_id))
        if (
            delivery is None
            or delivery.event_id != item.record.event_id
            or delivery.ordinal != item.delivery_ordinal
            or item.attempt_ordinal not in {attempt.ordinal for attempt in delivery.attempt_plan}
        ):
            raise InspectionError("journal delivery differs from verified manifest")
    for item in snapshot.assertions:
        plan = manifest_assertions.get((item.record.scenario_id, item.record.assertion_id))
        if plan is None or plan.type != item.record.type:
            raise InspectionError("journal assertion differs from verified manifest")


def _validate_report_coherence(
    *,
    bundle: LoadedRunBundle,
    snapshot: JournalReportSnapshot,
    artifacts: Mapping[str, bytes],
) -> AggregateRunOutcome:
    if artifacts["run-manifest.json"] != bundle.manifest_bytes:
        raise InspectionError("registered report manifest differs from verified bundle")
    _json_document(artifacts["result-summary.json"])
    try:
        summary = AggregateRunOutcome.model_validate_json(artifacts["result-summary.json"])
    except ValidationError as error:
        raise InspectionError("result summary is malformed") from error
    if (
        summary.run_id != snapshot.run.run_id
        or summary.manifest_id != snapshot.run.manifest_id
        or summary.counts.scenarios != len(snapshot.scenarios)
        or summary.counts.attempts != len(snapshot.attempts)
        or summary.counts.observations != len(snapshot.observations)
        or summary.counts.assertions != len(snapshot.assertions)
    ):
        raise InspectionError("result summary differs from journal evidence")
    if (
        summary.artifacts.manifest != "run-manifest.json"
        or summary.artifacts.deliveries != "deliveries.jsonl"
        or summary.artifacts.observations != "observations.jsonl"
        or summary.artifacts.assertions != "assertions.jsonl"
    ):
        raise InspectionError("result summary names unexpected sanitized artifacts")
    _compare_record_identities(
        _json_lines(artifacts["deliveries.jsonl"]),
        tuple(
            (
                item.record.record_id,
                item.record.run_id,
                item.record.scenario_id,
                item.record.event_id,
                item.record.delivery_id,
                item.record.attempt_id,
            )
            for item in snapshot.attempts
        ),
        fields=(
            "record_id",
            "run_id",
            "scenario_id",
            "event_id",
            "delivery_id",
            "attempt_id",
        ),
        name="delivery",
    )
    _compare_record_identities(
        _json_lines(artifacts["observations.jsonl"]),
        tuple(
            (
                item.record.record_id,
                item.record.run_id,
                item.record.scenario_id,
                item.record.observation_id,
                item.record.sample_id,
            )
            for item in snapshot.observations
        ),
        fields=(
            "record_id",
            "run_id",
            "scenario_id",
            "observation_id",
            "sample_id",
        ),
        name="observation",
    )
    assertion_documents = _json_lines(artifacts["assertions.jsonl"])
    _compare_record_identities(
        assertion_documents,
        tuple(
            (
                item.record.record_id,
                item.record.run_id,
                item.record.scenario_id,
                item.record.assertion_id,
            )
            for item in snapshot.assertions
        ),
        fields=("record_id", "run_id", "scenario_id", "assertion_id"),
        name="assertion",
    )
    expected_links = {
        item.record.record_id: tuple(item.record.evidence_refs) for item in snapshot.assertions
    }
    if any(
        tuple(_string_list(document.get("evidence_refs"), name="assertion evidence"))
        != expected_links[_required_text(document, "record_id")]
        for document in assertion_documents
    ):
        raise InspectionError("sanitized assertion evidence differs from the journal")
    return summary


def _compare_record_identities(
    documents: list[dict[str, object]],
    expected: tuple[tuple[str, ...], ...],
    *,
    fields: tuple[str, ...],
    name: str,
) -> None:
    if len(documents) > MAX_INSPECTION_RECORDS:
        raise InspectionError(f"{name} report exceeds the record limit")
    actual = tuple(
        tuple(_required_text(document, field) for field in fields) for document in documents
    )
    if len(set(actual)) != len(actual) or set(actual) != set(expected):
        raise InspectionError(f"sanitized {name} identities differ from the journal")


def _derive_causal_traces(
    manifest: RunManifest,
    snapshot: JournalReportSnapshot,
) -> tuple[FailureCausalTrace, ...]:
    assertion_plans = {
        (scenario.scenario_id, assertion.assertion_id): assertion
        for scenario in manifest.scenarios
        for assertion in scenario.assertions
    }
    traces: list[FailureCausalTrace] = []
    for assertion in snapshot.assertions:
        if assertion.record.result is AssertionResult.PASS:
            continue
        attempt = _exact_attempt(assertion, snapshot.attempts)
        plan = assertion_plans[(assertion.record.scenario_id, assertion.record.assertion_id)]
        observation = _exact_observation(
            assertion,
            snapshot.observations,
            plan=plan,
        )
        if observation is None:
            continue
        if (
            attempt.record.scenario_id != assertion.record.scenario_id
            or observation.record.scenario_id != assertion.record.scenario_id
            or (
                observation.record.event_id is not None
                and observation.record.event_id != attempt.record.event_id
            )
        ):
            raise InspectionError("causal evidence crosses scenario or event scope")
        traces.append(
            FailureCausalTrace(
                assertion_record_id=assertion.record.record_id,
                scenario_id=assertion.record.scenario_id,
                event_id=attempt.record.event_id,
                delivery_id=attempt.record.delivery_id,
                attempt_id=attempt.record.attempt_id,
                attempt_record_id=attempt.record.record_id,
                observation_id=observation.record.observation_id,
                observation_record_id=observation.record.record_id,
                assertion_id=assertion.record.assertion_id,
                classification=_assertion_category(assertion, snapshot),
                immediate_evidence_refs=assertion.record.evidence_refs,
            )
        )
    return tuple(traces)


def _exact_attempt(
    assertion: JournalReportAssertion,
    attempts: tuple[JournalReportAttempt, ...],
) -> JournalReportAttempt:
    references = set(assertion.record.evidence_refs)
    matches = {
        item.record.record_id: item
        for item in attempts
        if item.record.scenario_id == assertion.record.scenario_id
        and references.intersection({item.record.attempt_id, item.record.record_id})
    }
    if len(matches) != 1:
        raise InspectionError("failed assertion must resolve exactly one attempt evidence edge")
    return next(iter(matches.values()))


def _exact_observation(
    assertion: JournalReportAssertion,
    observations: tuple[JournalReportObservation, ...],
    *,
    plan: AssertionPlan,
) -> JournalReportObservation | None:
    references = set(assertion.record.evidence_refs)
    matches = {
        item.record.record_id: item
        for item in observations
        if item.record.scenario_id == assertion.record.scenario_id
        and references.intersection(
            {
                item.record.observation_id,
                item.record.sample_id,
                item.record.record_id,
            }
        )
    }
    if not matches and plan.observer is None:
        return None
    if len(matches) != 1:
        raise InspectionError("failed assertion must resolve exactly one observation evidence edge")
    return next(iter(matches.values()))


def _assertion_category(
    assertion: JournalReportAssertion,
    snapshot: JournalReportSnapshot,
) -> ResultCategory:
    if (
        assertion.assertion_state is AssertionState.ERROR
        and assertion.record.result is AssertionResult.ERROR
        and snapshot.run.terminal_category
        in {
            ResultCategory.ENVIRONMENT_ERROR,
            ResultCategory.HARNESS_ERROR,
            ResultCategory.INVALID_INPUT,
        }
    ):
        return cast("ResultCategory", snapshot.run.terminal_category)
    return classify_assertion_verdict(
        assertion.record.result,
        assertion.assertion_state,
    ).category


def _diagnostic_links(
    summary: AggregateRunOutcome,
    traces: tuple[FailureCausalTrace, ...],
) -> tuple[InspectionDiagnosticLink, ...]:
    return tuple(
        InspectionDiagnosticLink(
            diagnostic_id=diagnostic_id,
            assertion_record_id=trace.assertion_record_id,
        )
        for diagnostic_id in summary.failure_refs
        for trace in traces
        if diagnostic_id
        in {
            trace.assertion_record_id,
            trace.attempt_id,
            trace.attempt_record_id,
            trace.observation_id,
            trace.observation_record_id,
            *trace.immediate_evidence_refs,
        }
    )


def _raw_blob_paths(bundle: LoadedRunBundle) -> tuple[str, ...]:
    if len(bundle.blobs) > MAX_RAW_ARTIFACT_PATHS:
        raise InspectionError("raw blob path count exceeds the inspection limit")
    try:
        paths = tuple(
            snapshot.path.relative_to(bundle.directory).as_posix() for snapshot in bundle.blobs
        )
    except ValueError as error:
        raise InspectionError("verified blob path escaped the run directory") from error
    if len(set(paths)) != len(paths):
        raise InspectionError("verified raw blob paths are not unique")
    return paths


def _json_document(value: bytes) -> dict[str, object]:
    parsed = _json_value(value, name="JSON report")
    if not isinstance(parsed, dict):
        raise InspectionError("JSON report must contain one object")
    return cast("dict[str, object]", parsed)


def _json_lines(value: bytes) -> list[dict[str, object]]:
    if len(value) > MAX_INSPECTION_ARTIFACT_BYTES:
        raise InspectionError("JSON Lines report exceeds the inspection byte limit")
    result: list[dict[str, object]] = []
    for line in value.splitlines():
        parsed = _json_value(line, name="JSON Lines record")
        if not isinstance(parsed, dict):
            raise InspectionError("JSON Lines report records must be objects")
        result.append(cast("dict[str, object]", parsed))
        if len(result) > MAX_INSPECTION_RECORDS:
            raise InspectionError("JSON Lines report exceeds the record limit")
    return result


def _json_value(value: bytes, *, name: str) -> object:
    if len(value) > MAX_INSPECTION_ARTIFACT_BYTES:
        raise InspectionError(f"{name} exceeds the inspection byte limit")
    try:
        return json.loads(
            value,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise InspectionError(f"{name} contains malformed JSON") from error


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-JSON constant is forbidden: {value}")


def _required_text(value: Mapping[str, object], name: str) -> str:
    result = value.get(name)
    if type(result) is not str or not result:
        raise InspectionError(f"{name} must be nonempty text")
    return result


def _string_list(value: object, *, name: str) -> list[str]:
    if not isinstance(value, list):
        raise InspectionError(f"{name} must be a string array")
    values = cast("list[object]", value)
    if any(type(item) is not str for item in values):
        raise InspectionError(f"{name} must be a string array")
    return cast("list[str]", values)


def _text(value: object, *, name: str) -> str:
    if type(value) is not str or not value:
        raise InspectionError(f"{name} is invalid")
    return value


def _optional_text(value: object, *, name: str) -> str | None:
    if value is None:
        return None
    return _text(value, name=name)


def _integer(value: object, *, name: str) -> int:
    if type(value) is not int or value < 0:
        raise InspectionError(f"{name} is invalid")
    return value


def _private_regular_file(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and not bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)
    )


def _same_view(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _same_content_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


__all__ = ["load_inspection_index"]
