"""Static HTML report escaping, privacy, ambiguity, and CSP contract."""
# ruff: noqa: INP001, S105

from __future__ import annotations

import json
from html.parser import HTMLParser
from typing import Final

import pytest

from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.reporting.html import (
    HTML_CSP,
    HtmlReportInput,
    HtmlScenarioResult,
    audit_html_report,
    render_html,
    template_engine_for_tests,
)
from webhook_receiver_conformance.reporting.json_reports import (
    JsonReportArtifacts,
    ReportCausalIndex,
)

SCENARIO_ID: Final = f"scenario_{1:026d}"
ATTEMPT_ID: Final = f"attempt_{1:026d}"
DELIVERY_ID: Final = f"delivery_{1:026d}"
EVENT_ID: Final = f"event_{1:026d}"
OBSERVATION_ID: Final = f"observation_{1:026d}"
SAMPLE_ID: Final = f"sample_{1:026d}"
ASSERTION_ID: Final = f"assertion_{1:026d}"
RECORD_ID: Final = f"record_{1:026d}"
SECRET_CANARY: Final = "sensitive-observer-canary-must-not-escape"
BODY_CANARY: Final = "raw-body-canary-must-not-escape"
MALICIOUS_TEXT: Final = (
    '</title><script>pwn()</script><a href="javascript:pwn()" onclick="pwn()">&entity;</a>\x1b[31m'
)


class _MarkupInventory(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str, str | None]] = []
        self.title_data: list[str] = []
        self._in_title = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.tags.append(tag)
        self.attributes.extend((tag, name, value) for name, value in attrs)
        if tag == "title":
            self._in_title = True

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_data.append(data)


def _document(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()


def _lines(*values: object) -> bytes:
    return b"".join(_document(value) for value in values)


def _artifacts(
    *,
    verdict: ResultCategory = ResultCategory.AMBIGUOUS,
    malicious: bool = True,
) -> JsonReportArtifacts:
    untrusted = MALICIOUS_TEXT if malicious else "ordinary"
    return JsonReportArtifacts(
        manifest_json=_document(
            {
                "schema_version": "1.0",
                "scenarios": [{"scenario_id": SCENARIO_ID}],
            }
        ),
        deliveries_jsonl=_lines(
            {
                "schema_version": "1.0",
                "record_id": RECORD_ID,
                "scenario_id": SCENARIO_ID,
                "event_id": EVENT_ID,
                "delivery_id": DELIVERY_ID,
                "attempt_id": ATTEMPT_ID,
                "recorded_at": "2026-07-27T23:30:00.000000Z",
                "logical_time_ns": 1,
                "monotonic_elapsed_ns": 2,
                "state": "unknown_outcome",
                "classification": "ambiguous",
                "request": {
                    "url_redacted": untrusted,
                    "body_sha256": f"sha256:{'6' * 64}",
                    "byte_length": 123,
                    "header_names": ["Authorization", untrusted],
                    "raw_body": BODY_CANARY,
                },
                "response": {
                    "body_sha256": f"sha256:{'7' * 64}",
                    "captured_bytes": 9,
                    "truncated": True,
                    "raw_body": BODY_CANARY,
                },
            }
        ),
        observations_jsonl=_lines(
            {
                "schema_version": "1.0",
                "record_id": RECORD_ID,
                "scenario_id": SCENARIO_ID,
                "observation_id": OBSERVATION_ID,
                "sample_id": SAMPLE_ID,
                "observer_id": untrusted,
                "recorded_at": "2026-07-27T23:30:00.000000Z",
                "status": "ok",
                "snapshot_id": untrusted,
                "evidence": [
                    {
                        "key": "private_value",
                        "value_type": "string",
                        "value": SECRET_CANARY,
                        "sensitive": True,
                    },
                    {
                        "key": untrusted,
                        "value_type": "string",
                        "value": untrusted,
                        "sensitive": False,
                    },
                ],
            }
        ),
        assertions_jsonl=_lines(
            {
                "schema_version": "1.0",
                "record_id": RECORD_ID,
                "scenario_id": SCENARIO_ID,
                "assertion_id": ASSERTION_ID,
                "type": untrusted,
                "result": "error",
                "recorded_at": "2026-07-27T23:30:00.000000Z",
                "comparison": "eq",
                "expected": {"count": 1},
                "actual": {"count": 0},
                "message": untrusted,
                "evidence_refs": [ATTEMPT_ID, SAMPLE_ID],
            }
        ),
        result_summary_json=_document(
            {
                "schema_version": "1.0",
                "run_id": "00000000-0000-4000-8000-000000000604",
                "manifest_id": "1" * 64,
                "generated_at": "2026-07-27T23:30:00.000000Z",
                "verdict": verdict.value,
                "exit_code": 4,
                "counts": {
                    "scenarios": 1,
                    "attempts": 1,
                    "observations": 1,
                    "assertions": 1,
                },
                "failure_refs": [RECORD_ID],
                "artifacts": {
                    "manifest": "run-manifest.json",
                    "deliveries": untrusted,
                    "observations": "observations.jsonl",
                    "assertions": "assertions.jsonl",
                },
            }
        ),
        causal_index=ReportCausalIndex(()),
    )


def _report(
    *,
    classification: ResultCategory = ResultCategory.AMBIGUOUS,
    name: str = MALICIOUS_TEXT,
    malicious: bool = True,
) -> HtmlReportInput:
    return HtmlReportInput(
        artifacts=_artifacts(verdict=classification, malicious=malicious),
        scenarios=(
            HtmlScenarioResult(
                scenario_id=SCENARIO_ID,
                name=name,
                ordinal=0,
                classification=classification,
            ),
        ),
    )


def _inventory(content: bytes) -> _MarkupInventory:
    parser = _MarkupInventory()
    parser.feed(content.decode())
    parser.close()
    return parser


def test_report_is_deterministic_and_self_auditing() -> None:
    first = render_html(_report())
    second = render_html(_report())

    assert first == second
    assert first.sha256.startswith("sha256:")
    audit_html_report(first.content)


def test_sensitive_and_raw_body_canaries_are_absent_but_marker_remains() -> None:
    text = render_html(_report()).content.decode()

    assert SECRET_CANARY not in text
    assert BODY_CANARY not in text
    assert "[REDACTED]" in text
    assert f"sha256:{'6' * 64}" in text
    assert "123" in text


def test_unknown_attempt_has_explicit_ambiguity_section() -> None:
    text = render_html(_report()).content.decode()

    assert 'data-section="ambiguity"' in text
    assert "Unknown outcome ambiguity" in text
    assert ATTEMPT_ID in text
    assert "not classified as receiver success or transport failure" in text


def test_untrusted_markup_remains_text_and_cannot_change_title_or_links() -> None:
    document = render_html(_report()).content
    inventory = _inventory(document)
    text = document.decode()

    assert inventory.title_data == ["Webhook receiver conformance report"]
    assert "script" not in inventory.tags
    assert "a" not in inventory.tags
    assert "&lt;/title&gt;" in text
    assert "\x1b" not in text
    assert not any(name.casefold().startswith("on") for _, name, _ in inventory.attributes)
    assert not any(name in {"href", "src"} for _, name, _ in inventory.attributes)


def test_csp_is_exact_and_locks_script_and_default_sources() -> None:
    inventory = _inventory(render_html(_report()).content)
    csp_values = [
        value
        for tag, name, value in inventory.attributes
        if tag == "meta" and name == "content" and value == HTML_CSP
    ]

    assert csp_values == [HTML_CSP]
    assert "default-src 'none'" in HTML_CSP
    assert "script-src 'none'" in HTML_CSP
    assert "style-src 'unsafe-inline'" in HTML_CSP
    assert "img-src data:" in HTML_CSP


def test_all_result_classifications_have_distinct_labels_and_actions() -> None:
    text = render_html(_report(malicious=False)).content.decode()
    labels = (
        "Pass",
        "Receiver failure",
        "Invalid input",
        "Environment error",
        "Ambiguous",
        "Harness error",
        "Unsupported",
        "Cancelled",
    )

    for category in ResultCategory:
        assert f'data-classification="{category.value}"' in text
    for label in labels:
        assert f"<h3>{label}</h3>" in text
    assert text.count("corrective action") == 1
    assert text.count("correct receiver behavior") == 1
    assert text.count("configuration or invocation") == 1
    assert text.count("local dependency") == 1
    assert text.count("explicit observe") >= 1
    assert text.count("harness diagnosis") == 1
    assert text.count("declared capability") == 1
    assert text.count("cancellation was intentional") == 1


def test_template_engine_always_escapes_values_and_has_no_safe_filter() -> None:
    engine = template_engine_for_tests()
    rendered = engine.render_source(
        "<root><value>${evidence}</value></root>",
        {"evidence": MALICIOUS_TEXT},
    )

    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    with pytest.raises(ValueError, match=r"forbidden|invalid interpolation"):
        engine.render_source(
            "<root>${evidence|safe}</root>",
            {"evidence": MALICIOUS_TEXT},
        )


@pytest.mark.parametrize(
    "content",
    [
        (
            b'<html><head><meta http-equiv="Content-Security-Policy" '
            b"content=\"default-src 'none'; script-src 'none'\">"
            b"<title>x</title><script></script></head></html>"
        ),
        (
            b'<html><head><meta http-equiv="Content-Security-Policy" '
            b"content=\"default-src 'none'; script-src 'none'\">"
            b'<title>x</title></head><body onload="pwn()"></body></html>'
        ),
        (
            b'<html><head><meta http-equiv="Content-Security-Policy" '
            b"content=\"default-src 'none'; script-src 'none'\">"
            b'<title>x</title></head><body><a href="https://bad.invalid">x</a>'
            b"</body></html>"
        ),
        b"<html><head><title>x</title></head><body></body></html>",
    ],
)
def test_active_or_policy_weakened_html_fails_closed(content: bytes) -> None:
    with pytest.raises(ValueError, match=r"failed|missing|differs"):
        audit_html_report(content)


def test_scenario_results_must_match_manifest_order_exactly() -> None:
    report = HtmlReportInput(
        artifacts=_artifacts(),
        scenarios=(
            HtmlScenarioResult(
                scenario_id=SCENARIO_ID,
                name="scenario",
                ordinal=1,
                classification=ResultCategory.AMBIGUOUS,
            ),
        ),
    )

    with pytest.raises(ValueError, match="order differs"):
        render_html(report)


def test_invalid_template_escape_hatches_and_external_resources_are_rejected() -> None:
    engine = template_engine_for_tests()

    with pytest.raises(ValueError, match="forbidden"):
        engine.render_source(
            '<html><script src="https://bad.invalid/pwn.js"></script></html>',
            {},
        )
