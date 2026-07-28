"""Autoescaped, no-script, CSP-constrained static HTML reporting."""
# ruff: noqa: C901, D105, EM101, EM102, INP001, TRY003, TRY004

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from types import MappingProxyType
from typing import Final, cast
from xml.etree import ElementTree as ET

from webhook_receiver_conformance.domain.identifiers import (
    PlannedIdKind,
    validate_planned_id,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.reporting.json_reports import (
    JsonReportArtifacts,
)

TEMPLATE_DIRECTORY: Final = Path(__file__).with_name("templates")
REPORT_TEMPLATE_NAME: Final = "report.html"
HTML_CSP: Final = (
    "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; "
    "img-src data:; connect-src 'none'; font-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
MAX_HTML_SCENARIOS: Final = 10_000
MAX_HTML_RECORDS: Final = 100_000
MAX_HTML_TEXT_CHARACTERS: Final = 4_096
MAX_HTML_BYTES: Final = 16 * 1024 * 1024
TEMPLATE_NAMESPACE: Final = "urn:webhook-receiver-conformance:template:v1"

_FORBIDDEN_TEMPLATE_SOURCE = (
    "<script",
    "<iframe",
    "<object",
    "<embed",
    "<form",
    "<base",
    "javascript:",
    "http://",
    "https://",
    "|safe",
    "markup",
)
_EVENT_HANDLER = re.compile(r"on[a-z]+", flags=re.IGNORECASE)
_URL_ATTRIBUTES = frozenset({"action", "formaction", "href", "poster", "src"})
_PLACEHOLDER = re.compile(r"\$\{([a-z][a-z0-9_.]*)\}")
_LOOP_TAG: Final = f"{{{TEMPLATE_NAMESPACE}}}for"
_IF_TAG: Final = f"{{{TEMPLATE_NAMESPACE}}}if"
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class HtmlScenarioResult:
    """One explicit manifest-ordered scenario classification."""

    scenario_id: str
    name: str
    ordinal: int
    classification: ResultCategory

    def __post_init__(self) -> None:
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        if type(self.name) is not str or not self.name or len(self.name) > MAX_HTML_TEXT_CHARACTERS:
            raise ValueError("scenario name must be bounded nonempty text")
        if type(self.ordinal) is not int or not 0 <= self.ordinal <= (1 << 53) - 1:
            raise ValueError("scenario ordinal must be a bounded nonnegative integer")
        if type(self.classification) is not ResultCategory:
            raise TypeError("classification must be a ResultCategory")


@dataclass(frozen=True, slots=True)
class HtmlReportInput:
    """Safe report artifacts plus explicit scenario-level classifications."""

    artifacts: JsonReportArtifacts
    scenarios: tuple[HtmlScenarioResult, ...]

    def __post_init__(self) -> None:
        if type(self.artifacts) is not JsonReportArtifacts:
            raise TypeError("artifacts must be JsonReportArtifacts")
        if type(self.scenarios) is not tuple or any(
            type(item) is not HtmlScenarioResult for item in self.scenarios
        ):
            raise TypeError("scenarios must contain HtmlScenarioResult values")
        if len(self.scenarios) > MAX_HTML_SCENARIOS:
            raise ValueError("scenario count exceeds the HTML report limit")
        identifiers = tuple(item.scenario_id for item in self.scenarios)
        ordinals = tuple(item.ordinal for item in self.scenarios)
        if len(set(identifiers)) != len(identifiers) or len(set(ordinals)) != len(ordinals):
            raise ValueError("scenario identifiers and ordinals must be unique")


@dataclass(frozen=True, slots=True)
class HtmlReportDocument:
    """One verified standalone HTML report."""

    content: bytes
    sha256: str

    def __post_init__(self) -> None:
        if type(self.content) is not bytes:
            raise TypeError("content must be bytes")
        expected = f"sha256:{hashlib.sha256(self.content).hexdigest()}"
        if self.sha256 != expected:
            raise ValueError("HTML report digest differs from its content")


@dataclass(frozen=True, slots=True)
class _ClassificationPresentation:
    category: ResultCategory
    label: str
    action: str
    css_class: str


_PRESENTATIONS: Final = MappingProxyType(
    {
        ResultCategory.PASS: _ClassificationPresentation(
            ResultCategory.PASS,
            "Pass",
            "No corrective action is required.",
            "result-pass",
        ),
        ResultCategory.RECEIVER_FAILURE: _ClassificationPresentation(
            ResultCategory.RECEIVER_FAILURE,
            "Receiver failure",
            "Inspect the failed assertion and its causal evidence, then correct receiver behavior.",
            "result-receiver",
        ),
        ResultCategory.INVALID_INPUT: _ClassificationPresentation(
            ResultCategory.INVALID_INPUT,
            "Invalid input",
            "Correct the project configuration or invocation before rerunning.",
            "result-input",
        ),
        ResultCategory.ENVIRONMENT_ERROR: _ClassificationPresentation(
            ResultCategory.ENVIRONMENT_ERROR,
            "Environment error",
            "Restore the target, observer, network, or local dependency and rerun.",
            "result-environment",
        ),
        ResultCategory.AMBIGUOUS: _ClassificationPresentation(
            ResultCategory.AMBIGUOUS,
            "Ambiguous",
            "Preserve the unknown attempt and choose an explicit observe, "
            "redeliver, or operator policy.",
            "result-ambiguous",
        ),
        ResultCategory.HARNESS_ERROR: _ClassificationPresentation(
            ResultCategory.HARNESS_ERROR,
            "Harness error",
            "Preserve the run bundle and incident identifier for harness diagnosis.",
            "result-harness",
        ),
        ResultCategory.UNSUPPORTED: _ClassificationPresentation(
            ResultCategory.UNSUPPORTED,
            "Unsupported",
            "Provide the required declared capability or explicitly skip an optional check.",
            "result-unsupported",
        ),
        ResultCategory.CANCELLED: _ClassificationPresentation(
            ResultCategory.CANCELLED,
            "Cancelled",
            "Resume or rerun when cancellation was intentional and no stronger result exists.",
            "result-cancelled",
        ),
    }
)


def render_html(report: HtmlReportInput) -> HtmlReportDocument:
    """Render and verify one standalone report with no active content."""
    if type(report) is not HtmlReportInput:
        raise TypeError("report must be an HtmlReportInput")
    context = _build_context(report)
    rendered = _template_engine().render(context)
    content = ("<!doctype html>\n" + rendered + "\n").encode()
    if len(content) > MAX_HTML_BYTES:
        raise ValueError("HTML report exceeds the output size limit")
    audit_html_report(content)
    return HtmlReportDocument(
        content=content,
        sha256=f"sha256:{hashlib.sha256(content).hexdigest()}",
    )


def audit_html_report(content: bytes) -> None:
    """Reject executable markup, external resources, or a weakened CSP."""
    if type(content) is not bytes:
        raise TypeError("content must be bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("HTML report must be UTF-8") from error
    parser = _SafetyAudit()
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError) as error:
        raise ValueError("HTML report failed the active-content audit") from error
    if parser.csp != HTML_CSP:
        raise ValueError("HTML report CSP is missing or differs from the locked policy")
    if parser.title_count != 1:
        raise ValueError("HTML report must contain exactly one title")


def template_engine_for_tests() -> _AutoescapeTemplateEngine:
    """Expose the no-escape-hatch engine for contract tests only."""
    return _template_engine()


def _template_engine() -> _AutoescapeTemplateEngine:
    return _AutoescapeTemplateEngine(TEMPLATE_DIRECTORY / REPORT_TEMPLATE_NAME)


def _validate_template_source(source: str) -> None:
    folded = source.casefold()
    for forbidden in _FORBIDDEN_TEMPLATE_SOURCE:
        if forbidden in folded:
            raise ValueError("HTML template contains a forbidden active-content escape")


@dataclass(frozen=True, slots=True)
class _AutoescapeTemplateEngine:
    """Small XML template engine whose only interpolation path autoescapes."""

    template_path: Path

    def render(self, context: Mapping[str, object]) -> str:
        """Render one template without accepting pre-rendered markup values."""
        try:
            source = self.template_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ValueError("HTML template could not be read") from error
        return self.render_source(source, context)

    def render_source(
        self,
        source: str,
        context: Mapping[str, object],
    ) -> str:
        """Render source for contract tests and the locked report template."""
        if type(source) is not str:
            raise TypeError("template source must be text")
        _validate_template_source(source)
        try:
            root = ET.fromstring(source)  # noqa: S314 - local immutable template only
        except ET.ParseError as error:
            raise ValueError("HTML template must be well-formed XML") from error
        rendered = self._expand(root, (context,))
        if len(rendered) != 1:
            raise ValueError("HTML template must render exactly one root")
        return ET.tostring(
            rendered[0],
            encoding="unicode",
            method="html",
            short_empty_elements=False,
        )

    def _expand(
        self,
        element: ET.Element[str],
        scopes: tuple[Mapping[str, object], ...],
    ) -> list[ET.Element[str]]:
        if element.tag == _LOOP_TAG:
            return self._expand_loop(element, scopes)
        if element.tag == _IF_TAG:
            return self._expand_if(element, scopes)
        if element.tag.startswith(f"{{{TEMPLATE_NAMESPACE}}}"):
            raise ValueError("HTML template uses an unknown directive")
        attributes = {
            name: self._interpolate_required(value, scopes)
            for name, value in element.attrib.items()
        }
        rendered = ET.Element(element.tag, attributes)
        rendered.text = self._interpolate(element.text, scopes)
        rendered.tail = self._interpolate(element.tail, scopes)
        for child in element:
            rendered.extend(self._expand(child, scopes))
        return [rendered]

    def _expand_loop(
        self,
        element: ET.Element[str],
        scopes: tuple[Mapping[str, object], ...],
    ) -> list[ET.Element[str]]:
        if set(element.attrib) != {"each", "as"}:
            raise ValueError("template loops require only each and as")
        alias = element.attrib["as"]
        if re.fullmatch(r"[a-z][a-z0-9_]*", alias) is None:
            raise ValueError("template loop alias is invalid")
        values = self._lookup(element.attrib["each"], scopes)
        if isinstance(values, (str, bytes, bytearray)) or not isinstance(
            values,
            Sequence,
        ):
            raise ValueError("template loop input must be a sequence")
        sequence = cast("Sequence[object]", values)
        expanded: list[ET.Element[str]] = []
        for value in sequence:
            item_scope: Mapping[str, object] = {alias: value}
            for child in element:
                expanded.extend(self._expand(child, (*scopes, item_scope)))
        self._append_directive_tail(expanded, element.tail, scopes)
        return expanded

    def _expand_if(
        self,
        element: ET.Element[str],
        scopes: tuple[Mapping[str, object], ...],
    ) -> list[ET.Element[str]]:
        if set(element.attrib) != {"test"}:
            raise ValueError("template condition requires only test")
        value = self._lookup(element.attrib["test"], scopes)
        if type(value) is not bool:
            raise ValueError("template condition must reference a bool")
        expanded: list[ET.Element[str]] = []
        if value:
            for child in element:
                expanded.extend(self._expand(child, scopes))
        self._append_directive_tail(expanded, element.tail, scopes)
        return expanded

    def _append_directive_tail(
        self,
        expanded: list[ET.Element[str]],
        tail: str | None,
        scopes: tuple[Mapping[str, object], ...],
    ) -> None:
        if not expanded or tail is None:
            return
        rendered_tail = self._interpolate(tail, scopes)
        expanded[-1].tail = (expanded[-1].tail or "") + (rendered_tail or "")

    def _interpolate(
        self,
        value: str | None,
        scopes: tuple[Mapping[str, object], ...],
    ) -> str | None:
        if value is None:
            return None

        def replace(match: re.Match[str]) -> str:
            return _scalar_text(self._lookup(match.group(1), scopes))

        rendered = _PLACEHOLDER.sub(replace, value)
        if "$" in rendered:
            raise ValueError("template contains an invalid interpolation")
        return rendered

    def _interpolate_required(
        self,
        value: str,
        scopes: tuple[Mapping[str, object], ...],
    ) -> str:
        rendered = self._interpolate(value, scopes)
        if rendered is None:
            raise AssertionError("non-null template text rendered as null")
        return rendered

    def _lookup(
        self,
        path: str,
        scopes: tuple[Mapping[str, object], ...],
    ) -> object:
        parts = path.split(".")
        current: object | None = None
        found = False
        for scope in reversed(scopes):
            if parts[0] in scope:
                current = scope[parts[0]]
                found = True
                break
        if not found:
            raise ValueError("template references an unknown context value")
        for part in parts[1:]:
            if not isinstance(current, Mapping) or part not in current:
                raise ValueError("template references an unknown nested value")
            mapping = cast("Mapping[str, object]", current)
            current = mapping[part]
        return current


def _scalar_text(value: object) -> str:
    if value is None:
        return ""
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) in {int, float}:
        return str(value)
    if type(value) is str:
        return _CONTROL_CHARACTERS.sub("\N{REPLACEMENT CHARACTER}", value)[
            :MAX_HTML_TEXT_CHARACTERS
        ]
    raise ValueError("template placeholders must resolve to scalar values")


def _build_context(report: HtmlReportInput) -> dict[str, object]:
    manifest = _json_document(report.artifacts.manifest_json)
    summary = _json_document(report.artifacts.result_summary_json)
    deliveries = _json_lines(report.artifacts.deliveries_jsonl)
    observations = _json_lines(report.artifacts.observations_jsonl)
    assertions = _json_lines(report.artifacts.assertions_jsonl)
    if (
        len(deliveries) > MAX_HTML_RECORDS
        or len(observations) > MAX_HTML_RECORDS
        or len(assertions) > MAX_HTML_RECORDS
    ):
        raise ValueError("HTML report record count exceeds the limit")
    manifest_scenarios = _object_list(manifest.get("scenarios"), name="manifest scenarios")
    ordered_results = tuple(sorted(report.scenarios, key=lambda item: item.ordinal))
    if len(ordered_results) != len(manifest_scenarios):
        raise ValueError("HTML scenario results differ from the manifest")
    scenario_views: list[dict[str, object]] = []
    for index, (result, planned) in enumerate(
        zip(ordered_results, manifest_scenarios, strict=True)
    ):
        if result.ordinal != index or planned.get("scenario_id") != result.scenario_id:
            raise ValueError("HTML scenario order differs from the manifest")
        scenario_views.append(
            _scenario_view(
                result,
                deliveries=deliveries,
                observations=observations,
                assertions=assertions,
            )
        )
    traces = tuple(
        {
            "assertion_record_id": trace.assertion_record_id,
            "scenario_id": trace.scenario_id,
            "event_id": trace.event_id,
            "delivery_id": trace.delivery_id,
            "attempt_id": trace.attempt_id,
            "attempt_record_id": trace.attempt_record_id,
            "observation_id": trace.observation_id,
            "observation_record_id": trace.observation_record_id,
            "assertion_id": trace.assertion_id,
            "classification": trace.classification.value,
            "immediate_evidence_refs": trace.immediate_evidence_refs,
            "mutation_refs": trace.mutation_refs,
        }
        for trace in report.artifacts.causal_index.traces
    )
    try:
        summary_category = ResultCategory(summary.get("verdict"))
    except (TypeError, ValueError) as error:
        raise ValueError("HTML summary has an invalid verdict") from error
    summary_presentation = _PRESENTATIONS[summary_category]
    ambiguity_attempts = tuple(
        item
        for item in deliveries
        if item.get("classification") == ResultCategory.AMBIGUOUS.value
        or item.get("state") == "unknown_outcome"
    )
    artifacts_value = summary.get("artifacts")
    if not isinstance(artifacts_value, dict):
        raise ValueError("HTML summary artifacts must be a string mapping")
    untyped_artifacts = cast("dict[object, object]", artifacts_value)
    if any(
        type(name) is not str or type(path) is not str for name, path in untyped_artifacts.items()
    ):
        raise ValueError("HTML summary artifacts must be a string mapping")
    artifacts = cast("dict[str, str]", artifacts_value)
    return {
        "csp": HTML_CSP,
        "title": "Webhook receiver conformance report",
        "summary": summary,
        "summary_presentation": _presentation_view(summary_presentation),
        "scenarios": tuple(scenario_views),
        "classification_legend": tuple(
            _presentation_view(_PRESENTATIONS[category]) for category in ResultCategory
        ),
        "ambiguity_attempts": tuple(_attempt_view(item) for item in ambiguity_attempts),
        "has_ambiguity": bool(ambiguity_attempts),
        "causal_traces": traces,
        "artifact_paths": tuple(
            {"name": name, "path": path} for name, path in sorted(artifacts.items())
        ),
        "redaction_marker": "[REDACTED]",
    }


def _scenario_view(
    result: HtmlScenarioResult,
    *,
    deliveries: list[dict[str, object]],
    observations: list[dict[str, object]],
    assertions: list[dict[str, object]],
) -> dict[str, object]:
    presentation = _PRESENTATIONS[result.classification]
    return {
        "scenario_id": result.scenario_id,
        "name": result.name,
        "ordinal": result.ordinal,
        "classification": result.classification.value,
        "presentation": _presentation_view(presentation),
        "attempts": tuple(
            _attempt_view(item)
            for item in deliveries
            if item.get("scenario_id") == result.scenario_id
        ),
        "observations": tuple(
            _observation_view(item)
            for item in observations
            if item.get("scenario_id") == result.scenario_id
        ),
        "assertions": tuple(
            _assertion_view(item)
            for item in assertions
            if item.get("scenario_id") == result.scenario_id
        ),
    }


def _attempt_view(item: dict[str, object]) -> dict[str, object]:
    request = _object_value(item.get("request"))
    response = _object_value(item.get("response"))
    error = _object_value(item.get("error"))
    header_names = _string_list(
        request.get("header_names", []),
        name="HTML request header names",
    )
    return {
        "record_id": item.get("record_id", ""),
        "event_id": item.get("event_id", ""),
        "delivery_id": item.get("delivery_id", ""),
        "attempt_id": item.get("attempt_id", ""),
        "state": item.get("state", ""),
        "classification": item.get("classification", ""),
        "recorded_at": item.get("recorded_at", ""),
        "logical_time_ns": item.get("logical_time_ns", ""),
        "monotonic_elapsed_ns": item.get("monotonic_elapsed_ns", ""),
        "request_digest": request.get("body_sha256", ""),
        "request_bytes": request.get("byte_length", ""),
        "request_url": request.get("url_redacted", ""),
        "headers": tuple({"name": name, "value": "[REDACTED]"} for name in header_names),
        "response_status": response.get("status", ""),
        "response_digest": response.get("body_sha256", ""),
        "response_bytes": response.get("captured_bytes", ""),
        "response_truncated": response.get("truncated", ""),
        "error_category": error.get("category", ""),
        "error_phase": error.get("phase", ""),
        "error_message": error.get("message_redacted", ""),
    }


def _observation_view(item: dict[str, object]) -> dict[str, object]:
    evidence = _object_list(item.get("evidence", []), name="observation evidence")
    error = _object_value(item.get("error"))
    return {
        "record_id": item.get("record_id", ""),
        "observation_id": item.get("observation_id", ""),
        "sample_id": item.get("sample_id", ""),
        "observer_id": item.get("observer_id", ""),
        "status": item.get("status", ""),
        "snapshot_id": item.get("snapshot_id", ""),
        "recorded_at": item.get("recorded_at", ""),
        "evidence": tuple(
            {
                "key": value.get("key", ""),
                "value_type": value.get("value_type", ""),
                "value": (
                    '"[REDACTED]"'
                    if value.get("sensitive") is True
                    else _display_json(value.get("value"))
                ),
                "sensitive": value.get("sensitive", False),
            }
            for value in evidence
        ),
        "error_category": error.get("category", ""),
        "error_message": error.get("message_redacted", ""),
    }


def _assertion_view(item: dict[str, object]) -> dict[str, object]:
    return {
        "record_id": item.get("record_id", ""),
        "assertion_id": item.get("assertion_id", ""),
        "type": item.get("type", ""),
        "result": item.get("result", ""),
        "recorded_at": item.get("recorded_at", ""),
        "comparison": item.get("comparison", ""),
        "expected": _display_json(item.get("expected")),
        "actual": _display_json(item.get("actual")),
        "message": item.get("message", ""),
        "evidence_refs": tuple(cast("list[str]", item.get("evidence_refs", []))),
    }


def _presentation_view(
    presentation: _ClassificationPresentation,
) -> dict[str, str]:
    return {
        "category": presentation.category.value,
        "label": presentation.label,
        "action": presentation.action,
        "css_class": presentation.css_class,
    }


def _display_json(value: object) -> str:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("HTML evidence contains an invalid JSON value") from error
    return rendered[:MAX_HTML_TEXT_CHARACTERS]


def _object_value(value: object) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("HTML record field must be a JSON object")
    untyped = cast("dict[object, object]", value)
    if any(type(key) is not str for key in untyped):
        raise ValueError("HTML record field must be a JSON object")
    return cast("dict[str, object]", value)


def _object_list(value: object, *, name: str) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list of JSON objects")
    items = cast("list[object]", value)
    for item in items:
        if not isinstance(item, dict):
            raise ValueError(f"{name} must be a list of JSON objects")
        untyped = cast("dict[object, object]", item)
        if any(type(key) is not str for key in untyped):
            raise ValueError(f"{name} must be a list of JSON objects")
    return cast("list[dict[str, object]]", value)


def _string_list(value: object, *, name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a string list")
    items = cast("list[object]", value)
    if any(type(item) is not str for item in items):
        raise ValueError(f"{name} must be a string list")
    return cast("list[str]", value)


def _reject_non_json_number(value: str) -> object:
    raise ValueError(f"non-JSON numeric constant is forbidden: {value}")


def _json_document(value: bytes) -> dict[str, object]:
    try:
        parsed = json.loads(value, parse_constant=_reject_non_json_number)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("HTML input contains invalid JSON") from error
    if not isinstance(parsed, dict):
        raise ValueError("HTML document input must be a JSON object")
    return cast("dict[str, object]", parsed)


def _json_lines(value: bytes) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    try:
        lines = value.splitlines()
        for line in lines:
            parsed = json.loads(line, parse_constant=_reject_non_json_number)
            if not isinstance(parsed, dict):
                raise ValueError("HTML JSON Lines records must be objects")
            records.append(cast("dict[str, object]", parsed))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("HTML input contains invalid JSON Lines") from error
    return records


class _SafetyAudit(HTMLParser):
    csp: str | None
    title_count: int

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.csp = None
        self.title_count = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        lowered_tag = tag.casefold()
        if lowered_tag in {"script", "iframe", "object", "embed", "base", "form"}:
            raise ValueError("active HTML element is forbidden")
        if lowered_tag == "title":
            self.title_count += 1
        for name, value in attrs:
            lowered_name = name.casefold()
            if _EVENT_HANDLER.fullmatch(lowered_name) is not None:
                raise ValueError("event-handler attributes are forbidden")
            if lowered_name in {"srcdoc", "style"}:
                raise ValueError("active-content attributes are forbidden")
            if lowered_name in _URL_ATTRIBUTES and value is not None:
                _validate_url_attribute(lowered_name, value)
        attributes = {name.casefold(): value for name, value in attrs}
        if lowered_tag == "meta":
            http_equiv = attributes.get("http-equiv") or ""
            if http_equiv.casefold() == "content-security-policy":
                if self.csp is not None:
                    raise ValueError("multiple CSP declarations are forbidden")
                self.csp = attributes.get("content")
            elif http_equiv:
                raise ValueError("non-CSP http-equiv metadata is forbidden")

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)


def _validate_url_attribute(name: str, value: str) -> None:
    folded = value.strip().casefold()
    if folded.startswith("javascript:"):
        raise ValueError("javascript URLs are forbidden")
    if name == "href" and value.startswith("#"):
        return
    if name == "src" and folded.startswith("data:image/"):
        return
    raise ValueError("external and navigable resource URLs are forbidden")


__all__ = [
    "HTML_CSP",
    "HtmlReportDocument",
    "HtmlReportInput",
    "HtmlScenarioResult",
    "audit_html_report",
    "render_html",
    "template_engine_for_tests",
]
