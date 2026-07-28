"""Stable, privacy-safe JSON artifacts and JSON Lines projections."""
# ruff: noqa: C901, D105, EM101, EM102, INP001, PLR0911, PLR0912, PLR0913, TRY003

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AttemptEvidenceState,
    EvidenceValueType,
)
from webhook_receiver_conformance.domain.hashing import validate_sha256_digest
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    validate_fresh_id,
    validate_planned_id,
)
from webhook_receiver_conformance.domain.models import (
    AggregateRunOutcome,
    AssertionEvaluation,
    AttemptEvidence,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.http.evidence import REDACTED_HEADER_VALUE
from webhook_receiver_conformance.manifest.models import RunManifest
from webhook_receiver_conformance.observers.protocol import (
    ObservationRecord,
)
from webhook_receiver_conformance.secrets import RunCorrelationHasher

if TYPE_CHECKING:
    from collections.abc import Iterable

    from webhook_receiver_conformance.types import JsonValue

MAX_REPORT_RECORDS: Final = 100_000
MAX_LOG_FIELD_CHARACTERS: Final = 4_096
MAX_LOG_FIELDS: Final = 256
MAX_LOG_DEPTH: Final = 16
MAX_PREVIEW_BYTES: Final = 65_536
MAX_MEDIA_TYPE_LENGTH: Final = 255
MAX_HEADER_NAME_LENGTH: Final = 256
PREVIEW_OMITTED = "preview_omitted"
BINARY_OMITTED = "[BINARY_OMITTED]"

_EVENT_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,127}")
_SAFE_FIELD_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,256}")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_SENSITIVE_LOG_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "key",
        "key_material",
        "proxy-authorization",
        "request_body",
        "response_body",
        "secret",
        "set-cookie",
        "stderr",
        "stdout",
        "token",
    }
)
_TERMINAL_ATTEMPT_STATES = frozenset(AttemptEvidenceState) - {
    AttemptEvidenceState.SCHEDULED,
    AttemptEvidenceState.LEASED,
    AttemptEvidenceState.SENDING,
}


@dataclass(frozen=True, slots=True)
class DeliveryReportRecord:
    """One terminal attempt plus its manifest order coordinates."""

    record: AttemptEvidence
    scenario_ordinal: int
    delivery_ordinal: int
    attempt_ordinal: int

    def __post_init__(self) -> None:
        if type(self.record) is not AttemptEvidence:
            raise TypeError("record must be an AttemptEvidence")
        _ordinal(self.scenario_ordinal, name="scenario ordinal")
        _ordinal(self.delivery_ordinal, name="delivery ordinal")
        _ordinal(self.attempt_ordinal, name="attempt ordinal", minimum=1)
        if self.record.state not in _TERMINAL_ATTEMPT_STATES:
            raise ValueError("delivery report records must be terminal")

    @property
    def order_key(self) -> tuple[int, int, int, int, str]:
        """Return the locked stable delivery JSON Lines order."""
        return (
            self.scenario_ordinal,
            self.delivery_ordinal,
            self.attempt_ordinal,
            self.record.sequence,
            self.record.record_id,
        )


@dataclass(frozen=True, slots=True)
class ObservationReportRecord:
    """One terminal observer sample plus its plan order."""

    record: ObservationRecord
    scenario_ordinal: int
    observation_ordinal: int

    def __post_init__(self) -> None:
        if type(self.record) is not ObservationRecord:
            raise TypeError("record must be an ObservationRecord")
        _ordinal(self.scenario_ordinal, name="scenario ordinal")
        _ordinal(self.observation_ordinal, name="observation ordinal")

    @property
    def order_key(self) -> tuple[int, int, int, str]:
        """Return the locked stable observation JSON Lines order."""
        return (
            self.scenario_ordinal,
            self.observation_ordinal,
            self.record.sample_sequence,
            self.record.record_id,
        )


@dataclass(frozen=True, slots=True)
class AssertionReportRecord:
    """One terminal assertion evaluation plus its manifest order."""

    record: AssertionEvaluation
    scenario_ordinal: int
    assertion_ordinal: int

    def __post_init__(self) -> None:
        if type(self.record) is not AssertionEvaluation:
            raise TypeError("record must be an AssertionEvaluation")
        _ordinal(self.scenario_ordinal, name="scenario ordinal")
        _ordinal(self.assertion_ordinal, name="assertion ordinal")
        if self.record.result is AssertionResult.PENDING:
            raise ValueError("assertion report records must be terminal")

    @property
    def order_key(self) -> tuple[int, int, int, str]:
        """Return the locked stable assertion JSON Lines order."""
        return (
            self.scenario_ordinal,
            self.assertion_ordinal,
            self.record.evaluation_sequence,
            self.record.record_id,
        )


@dataclass(frozen=True, slots=True)
class FailureCausalTrace:
    """Exact identifiers needed to inspect one failed assertion."""

    assertion_record_id: str
    scenario_id: str
    event_id: str
    delivery_id: str
    attempt_id: str
    attempt_record_id: str
    observation_id: str
    observation_record_id: str
    assertion_id: str
    classification: ResultCategory
    immediate_evidence_refs: tuple[str, ...]
    mutation_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_fresh_id(
            self.assertion_record_id,
            expected_kind=FreshIdKind.RECORD,
        )
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)
        validate_planned_id(
            self.delivery_id,
            expected_kind=PlannedIdKind.DELIVERY,
        )
        validate_fresh_id(
            self.attempt_id,
            expected_kind=FreshIdKind.ATTEMPT,
        )
        validate_fresh_id(
            self.attempt_record_id,
            expected_kind=FreshIdKind.RECORD,
        )
        validate_planned_id(
            self.observation_id,
            expected_kind=PlannedIdKind.OBSERVATION,
        )
        validate_fresh_id(
            self.observation_record_id,
            expected_kind=FreshIdKind.RECORD,
        )
        validate_planned_id(
            self.assertion_id,
            expected_kind=PlannedIdKind.ASSERTION,
        )
        if type(self.classification) is not ResultCategory:
            raise TypeError("classification must be a ResultCategory")
        if self.classification is ResultCategory.PASS:
            raise ValueError("failure traces cannot use the pass classification")
        _serialized_id_tuple(
            self.immediate_evidence_refs,
            name="immediate evidence",
        )
        if not self.immediate_evidence_refs:
            raise ValueError("failure traces require immediate evidence")
        _token_tuple(self.mutation_refs, name="mutation references")


@dataclass(frozen=True, slots=True)
class ReportCausalIndex:
    """Immutable direct lookup used by the inspect command."""

    traces: tuple[FailureCausalTrace, ...]

    def __post_init__(self) -> None:
        if type(self.traces) is not tuple or any(
            type(trace) is not FailureCausalTrace for trace in self.traces
        ):
            raise TypeError("traces must contain FailureCausalTrace values")
        identities = tuple(trace.assertion_record_id for trace in self.traces)
        if len(set(identities)) != len(identities):
            raise ValueError("failure trace assertion record IDs must be unique")

    @property
    def by_assertion_record(self) -> Mapping[str, FailureCausalTrace]:
        """Return exact, heuristic-free failed-assertion lookup."""
        return MappingProxyType({trace.assertion_record_id: trace for trace in self.traces})

    def trace_failure(self, assertion_record_id: str) -> FailureCausalTrace:
        """Return the exact causal trace or reject an unknown identifier."""
        validate_fresh_id(
            assertion_record_id,
            expected_kind=FreshIdKind.RECORD,
        )
        trace = self.by_assertion_record.get(assertion_record_id)
        if trace is None:
            raise KeyError("assertion record has no causal trace")
        return trace


@dataclass(frozen=True, slots=True)
class JsonReportArtifacts:
    """Complete in-memory stable JSON report set."""

    manifest_json: bytes
    deliveries_jsonl: bytes
    observations_jsonl: bytes
    assertions_jsonl: bytes
    result_summary_json: bytes
    causal_index: ReportCausalIndex

    def __post_init__(self) -> None:
        for name, value in (
            ("manifest_json", self.manifest_json),
            ("deliveries_jsonl", self.deliveries_jsonl),
            ("observations_jsonl", self.observations_jsonl),
            ("assertions_jsonl", self.assertions_jsonl),
            ("result_summary_json", self.result_summary_json),
        ):
            if type(value) is not bytes:
                raise TypeError(f"{name} must be bytes")
        if type(self.causal_index) is not ReportCausalIndex:
            raise TypeError("causal_index must be a ReportCausalIndex")


@dataclass(frozen=True, slots=True)
class BodyPreview:
    """Digest metadata plus an optional already-redacted JSON preview."""

    sha256: str
    byte_length: int
    media_type: str | None
    preview: JsonValue = None
    preview_omitted: bool = True

    def __post_init__(self) -> None:
        validate_sha256_digest(self.sha256)
        if type(self.byte_length) is not int or self.byte_length < 0:
            raise ValueError("byte_length must be a nonnegative integer")
        if self.media_type is not None and (
            type(self.media_type) is not str
            or not self.media_type
            or len(self.media_type) > MAX_MEDIA_TYPE_LENGTH
        ):
            raise ValueError("media_type must be bounded text or None")
        if type(self.preview_omitted) is not bool:
            raise TypeError("preview_omitted must be a bool")
        if self.preview_omitted and self.preview is not None:
            raise ValueError("omitted previews cannot retain body content")

    def wire_dict(self) -> dict[str, JsonValue]:
        """Return safe body metadata without raw bytes."""
        result: dict[str, JsonValue] = {
            "sha256": self.sha256,
            "byte_length": self.byte_length,
            "preview_omitted": self.preview_omitted,
        }
        if self.media_type is not None:
            result["media_type"] = self.media_type
        if not self.preview_omitted:
            result["preview"] = self.preview
        return result


def render_json_reports(
    manifest: RunManifest,
    summary: AggregateRunOutcome,
    *,
    deliveries: tuple[DeliveryReportRecord, ...],
    observations: tuple[ObservationReportRecord, ...],
    assertions: tuple[AssertionReportRecord, ...],
    causal_traces: tuple[FailureCausalTrace, ...] = (),
) -> JsonReportArtifacts:
    """Validate, order, redact, and render the five stable JSON artifacts."""
    _require_report_inputs(
        manifest,
        summary,
        deliveries=deliveries,
        observations=observations,
        assertions=assertions,
    )
    manifest.verify_id()
    _validate_manifest_scope(
        manifest,
        summary,
        deliveries=deliveries,
        observations=observations,
        assertions=assertions,
    )
    index = ReportCausalIndex(causal_traces)
    _validate_causal_index(
        summary,
        deliveries=deliveries,
        observations=observations,
        assertions=assertions,
        index=index,
    )
    ordered_deliveries = tuple(sorted(deliveries, key=lambda item: item.order_key))
    ordered_observations = tuple(sorted(observations, key=lambda item: item.order_key))
    ordered_assertions = tuple(sorted(assertions, key=lambda item: item.order_key))
    return JsonReportArtifacts(
        manifest_json=manifest.serialized_bytes(),
        deliveries_jsonl=_json_lines(
            tuple(_attempt_projection(item.record) for item in ordered_deliveries)
        ),
        observations_jsonl=_json_lines(
            tuple(_observation_projection(item.record) for item in ordered_observations)
        ),
        assertions_jsonl=_json_lines(
            tuple(_assertion_projection(item.record) for item in ordered_assertions)
        ),
        result_summary_json=_json_document(
            cast(
                "dict[str, object]",
                summary.model_dump(mode="json", exclude_none=True),
            )
        ),
        causal_index=index,
    )


def redact_json_preview(
    body: bytes,
    *,
    json_pointers: tuple[str, ...],
    media_type: str | None = "application/json",
    maximum_bytes: int = MAX_PREVIEW_BYTES,
) -> BodyPreview:
    """Apply exact JSON Pointer redaction and fail closed on any parse error."""
    if type(body) is not bytes:
        raise TypeError("body must be bytes")
    if type(json_pointers) is not tuple or any(
        type(pointer) is not str for pointer in json_pointers
    ):
        raise TypeError("json_pointers must be a tuple of strings")
    if len(set(json_pointers)) != len(json_pointers):
        raise ValueError("json_pointers must be unique")
    _ordinal(maximum_bytes, name="maximum preview bytes", minimum=1)
    digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
    omitted = BodyPreview(
        sha256=digest,
        byte_length=len(body),
        media_type=media_type,
    )
    if len(body) > maximum_bytes or not _is_json_media_type(media_type):
        return omitted
    try:
        parsed = json.loads(
            body.decode("utf-8"),
            parse_constant=lambda _value: _raise_invalid_json(),
        )
        _reject_nonfinite(parsed)
        redacted = cast("JsonValue", parsed)
        for pointer in json_pointers:
            redacted = _redact_pointer(redacted, pointer)
        encoded = _json_compact(redacted)
        if len(encoded) > maximum_bytes:
            return omitted
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return omitted
    return BodyPreview(
        sha256=digest,
        byte_length=len(body),
        media_type=media_type,
        preview=redacted,
        preview_omitted=False,
    )


def redacted_header_fields(
    header_names: Iterable[str],
) -> tuple[dict[str, str], ...]:
    """Render every header with the same stable value marker."""
    result: list[dict[str, str]] = []
    for name in header_names:
        if (
            type(name) is not str
            or not name
            or len(name) > MAX_HEADER_NAME_LENGTH
            or any(character in "\r\n\x00" for character in name)
        ):
            raise ValueError("header names must be bounded and line-safe")
        result.append({"name": name, "value": REDACTED_HEADER_VALUE})
    return tuple(result)


def structured_log_line(
    event: str,
    fields: Mapping[str, object],
    *,
    maximum_field_characters: int = MAX_LOG_FIELD_CHARACTERS,
) -> bytes:
    """Encode one bounded JSON log line without raw body/header/child output."""
    if type(event) is not str or _EVENT_TOKEN.fullmatch(event) is None:
        raise ValueError("event must be a bounded lowercase token")
    if len(fields) > MAX_LOG_FIELDS:
        raise ValueError("structured log field count exceeds the limit")
    _ordinal(
        maximum_field_characters,
        name="maximum log field characters",
        minimum=1,
    )
    sanitized: dict[str, JsonValue] = {"event": event}
    for raw_name, value in fields.items():
        if type(raw_name) is not str or _SAFE_FIELD_NAME.fullmatch(raw_name) is None:
            raise ValueError("structured log field names must be bounded tokens")
        sanitized[raw_name] = _sanitize_log_value(
            raw_name,
            value,
            maximum=maximum_field_characters,
            depth=0,
        )
    return _json_compact(sanitized) + b"\n"


def correlate_value(
    hasher: RunCorrelationHasher,
    value: str,
) -> str:
    """Return an ephemeral run-scoped HMAC token without exposing its key."""
    if type(hasher) is not RunCorrelationHasher:
        raise TypeError("hasher must be a RunCorrelationHasher")
    if type(value) is not str:
        raise TypeError("value must be a string")
    return hasher.correlate(value)


def _require_report_inputs(
    manifest: object,
    summary: object,
    *,
    deliveries: object,
    observations: object,
    assertions: object,
) -> None:
    if type(manifest) is not RunManifest:
        raise TypeError("manifest must be a RunManifest")
    if type(summary) is not AggregateRunOutcome:
        raise TypeError("summary must be an AggregateRunOutcome")
    _record_tuple(deliveries, DeliveryReportRecord, name="deliveries")
    _record_tuple(observations, ObservationReportRecord, name="observations")
    _record_tuple(assertions, AssertionReportRecord, name="assertions")
    if (
        len(cast("tuple[object, ...]", deliveries)) > MAX_REPORT_RECORDS
        or len(cast("tuple[object, ...]", observations)) > MAX_REPORT_RECORDS
        or len(cast("tuple[object, ...]", assertions)) > MAX_REPORT_RECORDS
    ):
        raise ValueError("report record count exceeds the limit")


def _validate_manifest_scope(
    manifest: RunManifest,
    summary: AggregateRunOutcome,
    *,
    deliveries: tuple[DeliveryReportRecord, ...],
    observations: tuple[ObservationReportRecord, ...],
    assertions: tuple[AssertionReportRecord, ...],
) -> None:
    if summary.manifest_id != manifest.manifest_id:
        raise ValueError("summary and manifest identifiers differ")
    counts = summary.counts
    if (
        counts.scenarios != len(manifest.scenarios)
        or counts.attempts != len(deliveries)
        or counts.observations != len(observations)
        or counts.assertions != len(assertions)
    ):
        raise ValueError("summary counts differ from JSON Lines records")
    identities: set[str] = set()
    for item in deliveries:
        _validate_scenario_order(manifest, item.scenario_ordinal, item.record.scenario_id)
        scenario = manifest.scenarios[item.scenario_ordinal]
        delivery = next(
            (
                candidate
                for candidate in scenario.deliveries
                if candidate.delivery_id == item.record.delivery_id
            ),
            None,
        )
        if (
            delivery is None
            or delivery.event_id != item.record.event_id
            or delivery.ordinal != item.delivery_ordinal
            or item.attempt_ordinal not in {attempt.ordinal for attempt in delivery.attempt_plan}
        ):
            raise ValueError("delivery report order differs from the manifest")
        _unique_report_identity(
            identities,
            item.record.record_id,
            item.record.attempt_id,
        )
        if item.record.run_id != summary.run_id:
            raise ValueError("delivery record has a different run_id")
    for item in observations:
        _validate_scenario_order(manifest, item.scenario_ordinal, item.record.scenario_id)
        _unique_report_identity(
            identities,
            item.record.record_id,
            item.record.sample_id,
        )
        if item.record.run_id != summary.run_id:
            raise ValueError("observation record has a different run_id")
    for item in assertions:
        _validate_scenario_order(manifest, item.scenario_ordinal, item.record.scenario_id)
        scenario = manifest.scenarios[item.scenario_ordinal]
        if (
            item.assertion_ordinal >= len(scenario.assertions)
            or scenario.assertions[item.assertion_ordinal].assertion_id != item.record.assertion_id
        ):
            raise ValueError("assertion report order differs from the manifest")
        _unique_report_identity(identities, item.record.record_id)
        if item.record.run_id != summary.run_id:
            raise ValueError("assertion record has a different run_id")


def _validate_causal_index(
    summary: AggregateRunOutcome,
    *,
    deliveries: tuple[DeliveryReportRecord, ...],
    observations: tuple[ObservationReportRecord, ...],
    assertions: tuple[AssertionReportRecord, ...],
    index: ReportCausalIndex,
) -> None:
    attempts_by_record = {item.record.record_id: item.record for item in deliveries}
    observations_by_record = {item.record.record_id: item.record for item in observations}
    assertions_by_record = {item.record.record_id: item.record for item in assertions}
    for trace in index.traces:
        attempt = attempts_by_record.get(trace.attempt_record_id)
        observation = observations_by_record.get(trace.observation_record_id)
        assertion = assertions_by_record.get(trace.assertion_record_id)
        if attempt is None or observation is None or assertion is None:
            raise ValueError("causal trace references a missing exported record")
        if (
            attempt.scenario_id != trace.scenario_id
            or attempt.event_id != trace.event_id
            or attempt.delivery_id != trace.delivery_id
            or attempt.attempt_id != trace.attempt_id
            or observation.scenario_id != trace.scenario_id
            or observation.observation_id != trace.observation_id
            or assertion.scenario_id != trace.scenario_id
            or assertion.assertion_id != trace.assertion_id
            or tuple(assertion.evidence_refs) != trace.immediate_evidence_refs
        ):
            raise ValueError("causal trace disagrees with exported record identities")
    failed_assertion_records = {
        item.record.record_id
        for item in assertions
        if item.record.result is not AssertionResult.PASS
    }
    required_traces = set(summary.failure_refs) & failed_assertion_records
    if not required_traces.issubset(index.by_assertion_record):
        raise ValueError("failed assertion summary references require causal traces")


def _attempt_projection(record: AttemptEvidence) -> dict[str, object]:
    return cast(
        "dict[str, object]",
        record.model_dump(mode="json", exclude_none=True),
    )


def _observation_projection(record: ObservationRecord) -> dict[str, object]:
    projection = record.wire_dict()
    evidence = cast("list[dict[str, object]]", projection.get("evidence", []))
    projection["evidence"] = [_redact_sensitive_observer_evidence(item) for item in evidence]
    return projection


def _assertion_projection(record: AssertionEvaluation) -> dict[str, object]:
    projection = cast(
        "dict[str, object]",
        record.model_dump(mode="json", exclude_none=True),
    )
    projection.setdefault("expected", None)
    projection.setdefault("actual", None)
    return projection


def _redact_sensitive_observer_evidence(
    item: dict[str, object],
) -> dict[str, object]:
    if item.get("sensitive") is not True:
        return item
    value_type = EvidenceValueType(cast("str", item["value_type"]))
    projection = dict(item)
    projection["value"] = {
        EvidenceValueType.NULL: None,
        EvidenceValueType.BOOLEAN: False,
        EvidenceValueType.INTEGER: 0,
        EvidenceValueType.DECIMAL_STRING: "0",
        EvidenceValueType.STRING: REDACTED_HEADER_VALUE,
        EvidenceValueType.BYTES_DIGEST: {
            "sha256": f"sha256:{'0' * 64}",
            "byte_length": 0,
        },
        EvidenceValueType.TIMESTAMP: "1970-01-01T00:00:00Z",
        EvidenceValueType.ARRAY: [],
        EvidenceValueType.OBJECT: {"redacted": True},
    }[value_type]
    return projection


def _json_lines(records: tuple[dict[str, object], ...]) -> bytes:
    return b"".join(_json_compact(record) + b"\n" for record in records)


def _json_document(value: dict[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _json_compact(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _redact_pointer(root: JsonValue, pointer: str) -> JsonValue:
    tokens = _pointer_tokens(pointer)
    if not tokens:
        return REDACTED_HEADER_VALUE
    current: JsonValue = root
    for token in tokens[:-1]:
        if isinstance(current, dict):
            if token not in current:
                return root
            current = current[token]
        elif isinstance(current, list):
            index = _array_index(token, len(current))
            if index is None:
                return root
            current = current[index]
        else:
            return root
    final = tokens[-1]
    if isinstance(current, dict):
        if final in current:
            current[final] = REDACTED_HEADER_VALUE
        return root
    if isinstance(current, list):
        index = _array_index(final, len(current))
        if index is not None:
            current[index] = REDACTED_HEADER_VALUE
    return root


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise ValueError("JSON Pointer must be empty or start with slash")
    result: list[str] = []
    for raw in pointer[1:].split("/"):
        decoded: list[str] = []
        index = 0
        while index < len(raw):
            if raw[index] != "~":
                decoded.append(raw[index])
                index += 1
                continue
            if index + 1 >= len(raw) or raw[index + 1] not in {"0", "1"}:
                raise ValueError("JSON Pointer contains an invalid escape")
            decoded.append("~" if raw[index + 1] == "0" else "/")
            index += 2
        result.append("".join(decoded))
    return tuple(result)


def _array_index(index_text: str, length: int) -> int | None:
    if index_text == "0":
        return 0 if length else None
    if (
        not index_text
        or index_text[0] == "0"
        or not index_text.isascii()
        or not index_text.isdecimal()
    ):
        return None
    index = int(index_text)
    return index if index < length else None


def _sanitize_log_value(
    field_name: str,
    value: object,
    *,
    maximum: int,
    depth: int,
) -> JsonValue:
    if depth > MAX_LOG_DEPTH:
        return PREVIEW_OMITTED
    normalized = field_name.casefold().replace("_", "-")
    if normalized in _SENSITIVE_LOG_KEYS or normalized.endswith(("-secret", "-token", "-body")):
        return REDACTED_HEADER_VALUE
    if normalized.endswith("headers"):
        if isinstance(value, Mapping):
            header_mapping = cast("Mapping[object, object]", value)
            return {str(name)[:maximum]: REDACTED_HEADER_VALUE for name in header_mapping}
        if isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            header_sequence = cast("Sequence[object]", value)
            return [
                {
                    "name": str(name)[:maximum],
                    "value": REDACTED_HEADER_VALUE,
                }
                for name in header_sequence[:MAX_LOG_FIELDS]
            ]
        return REDACTED_HEADER_VALUE
    if value is None or type(value) in {bool, int}:
        return cast("bool | int | None", value)
    if isinstance(value, float):
        return value if math.isfinite(value) else PREVIEW_OMITTED
    if isinstance(value, str):
        return value[:maximum]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return BINARY_OMITTED
    if isinstance(value, Mapping):
        nested_mapping = cast("Mapping[object, object]", value)
        if len(nested_mapping) > MAX_LOG_FIELDS:
            return PREVIEW_OMITTED
        result: dict[str, JsonValue] = {}
        for key, item in nested_mapping.items():
            name = str(key)[:maximum]
            result[name] = _sanitize_log_value(
                name,
                item,
                maximum=maximum,
                depth=depth + 1,
            )
        return result
    if isinstance(value, Sequence):
        nested_sequence = cast("Sequence[object]", value)
        return [
            _sanitize_log_value(
                field_name,
                item,
                maximum=maximum,
                depth=depth + 1,
            )
            for item in nested_sequence[:MAX_LOG_FIELDS]
        ]
    return str(value)[:maximum]


def _record_tuple(value: object, item_type: type[object], *, name: str) -> None:
    if type(value) is not tuple or any(
        type(item) is not item_type for item in cast("tuple[object, ...]", value)
    ):
        raise TypeError(f"{name} must contain exact {item_type.__name__} values")


def _validate_scenario_order(
    manifest: RunManifest,
    ordinal: int,
    scenario_id: str,
) -> None:
    if ordinal >= len(manifest.scenarios) or manifest.scenarios[ordinal].scenario_id != scenario_id:
        raise ValueError("report scenario order differs from the manifest")


def _unique_report_identity(identities: set[str], *values: str) -> None:
    for value in values:
        if value in identities:
            raise ValueError("report record and physical identities must be unique")
        identities.add(value)


def _ordinal(value: int, *, name: str, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value <= (1 << 53) - 1:
        raise ValueError(f"{name} must be a bounded integer")


def _serialized_id_tuple(values: tuple[str, ...], *, name: str) -> None:
    if type(values) is not tuple:
        raise TypeError(f"{name} must be a tuple")
    for value in values:
        try:
            validate_planned_id(value)
        except ValueError:
            validate_fresh_id(value)
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must be unique")


def _token_tuple(values: tuple[str, ...], *, name: str) -> None:
    if type(values) is not tuple or any(
        type(value) is not str or _TOKEN.fullmatch(value) is None for value in values
    ):
        raise ValueError(f"{name} must contain bounded tokens")
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must be unique")


def _is_json_media_type(value: str | None) -> bool:
    if value is None:
        return False
    media_type = value.partition(";")[0].strip().casefold()
    return media_type == "application/json" or media_type.endswith("+json")


def _reject_nonfinite(value: object) -> None:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON preview contains a non-finite number")
        return
    if isinstance(value, list):
        for item in cast("list[object]", value):
            _reject_nonfinite(item)
    elif isinstance(value, dict):
        for item in cast("dict[object, object]", value).values():
            _reject_nonfinite(item)


def _raise_invalid_json() -> None:
    raise ValueError("JSON preview contains a nonstandard constant")


__all__ = [
    "BINARY_OMITTED",
    "MAX_LOG_FIELD_CHARACTERS",
    "MAX_PREVIEW_BYTES",
    "PREVIEW_OMITTED",
    "AssertionReportRecord",
    "BodyPreview",
    "DeliveryReportRecord",
    "FailureCausalTrace",
    "JsonReportArtifacts",
    "ObservationReportRecord",
    "ReportCausalIndex",
    "correlate_value",
    "redact_json_preview",
    "redacted_header_fields",
    "render_json_reports",
    "structured_log_line",
]
