"""JUnit suite, testcase, classification, duration, and attachment contract."""
# ruff: noqa: INP001, PLR0913, PLR2004, S105, S314

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.reporting.junit import (
    INFRASTRUCTURE_TESTCASE_PREFIX,
    JUnitCase,
    JUnitCaseKind,
    JUnitErrorType,
    JUnitRun,
    JUnitScenario,
    render_junit,
)

RUN_ID = "00000000-0000-4000-8000-000000000603"
MANIFEST_ID = "a" * 64
SCENARIO_IDS = tuple(f"scenario_{ordinal:026d}" for ordinal in range(1, 4))
ASSERTION_IDS = tuple(f"assertion_{ordinal:026d}" for ordinal in range(1, 4))
ATTEMPT_ID = f"attempt_{1:026d}"
SAMPLE_ID = f"sample_{1:026d}"
SECRET_CANARY = "fixture-secret-canary-must-not-escape"
GOLDEN = Path("tests/golden/reports/junit.xml")


def _case(
    ordinal: int,
    *,
    classification: ResultCategory,
    duration_ns: int,
    message: str | None = None,
    reason_code: str | None = None,
    error_type: JUnitErrorType | None = None,
    attachment_paths: tuple[str, ...] = (),
) -> JUnitCase:
    return JUnitCase(
        case_id=f"assertion-case-{ordinal}",
        name=f"assertion {ordinal}",
        kind=JUnitCaseKind.ASSERTION,
        classification=classification,
        physical_duration_ns=duration_ns,
        assertion_id=ASSERTION_IDS[ordinal],
        assertion_ordinal=ordinal,
        message=message,
        reason_code=reason_code,
        error_type=error_type,
        evidence_refs=(ATTEMPT_ID, SAMPLE_ID),
        attachment_paths=attachment_paths,
    )


def _infrastructure(
    case_id: str,
    *,
    classification: ResultCategory,
    error_type: JUnitErrorType,
    duration_ns: int,
    message: str,
) -> JUnitCase:
    return JUnitCase(
        case_id=case_id,
        name=case_id,
        kind=JUnitCaseKind.INFRASTRUCTURE,
        classification=classification,
        physical_duration_ns=duration_ns,
        message=message,
        error_type=error_type,
        evidence_refs=(ATTEMPT_ID,),
    )


def _run() -> JUnitRun:
    scenarios = (
        JUnitScenario(
            scenario_id=SCENARIO_IDS[0],
            name="signature rejection",
            ordinal=0,
            cases=(
                _case(
                    2,
                    classification=ResultCategory.UNSUPPORTED,
                    duration_ns=25_000_000,
                    message="Optional callback journal is unavailable.",
                    reason_code="UNSUPPORTED_CAPABILITY",
                ),
                _case(
                    0,
                    classification=ResultCategory.PASS,
                    duration_ns=100_000_000,
                ),
                _case(
                    1,
                    classification=ResultCategory.RECEIVER_FAILURE,
                    duration_ns=1_234_567_890,
                    message="processing_count expected 1 but observed 0",
                    attachment_paths=("evidence/assertion-record.json",),
                ),
            ),
        ),
        JUnitScenario(
            scenario_id=SCENARIO_IDS[1],
            name="observer timeout",
            ordinal=1,
            cases=(
                _infrastructure(
                    "observer-timeout",
                    classification=ResultCategory.ENVIRONMENT_ERROR,
                    error_type=JUnitErrorType.OBSERVER_TIMEOUT,
                    duration_ns=2_000_000_001,
                    message="Observer deadline elapsed.",
                ),
            ),
        ),
        JUnitScenario(
            scenario_id=SCENARIO_IDS[2],
            name="crash after send",
            ordinal=2,
            cases=(
                _infrastructure(
                    "unknown-outcome",
                    classification=ResultCategory.AMBIGUOUS,
                    error_type=JUnitErrorType.AMBIGUOUS_OUTCOME,
                    duration_ns=333_000_000,
                    message="Request bytes may have reached the receiver.",
                ),
            ),
        ),
    )
    return JUnitRun(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        scenarios=scenarios,
        expected_assertion_count=3,
        artifact_paths=(
            "deliveries.jsonl",
            "observations.jsonl",
            "assertions.jsonl",
        ),
    )


def _root(payload: bytes) -> ET.Element:
    return ET.fromstring(payload)


def test_three_scenarios_map_to_three_stably_named_suites() -> None:
    root = _root(render_junit(_run()))
    suites = root.findall("testsuite")
    assert len(suites) == 3
    assert [suite.get("id") for suite in suites] == list(SCENARIO_IDS)
    assert [suite.get("name") for suite in suites] == [
        f"0000:{SCENARIO_IDS[0]}:signature rejection",
        f"0001:{SCENARIO_IDS[1]}:observer timeout",
        f"0002:{SCENARIO_IDS[2]}:crash after send",
    ]


def test_assertion_and_infrastructure_counts_reconcile_at_root() -> None:
    root = _root(render_junit(_run()))
    assert root.attrib == {
        "name": f"webhook-receiver-conformance:{RUN_ID}",
        "tests": "5",
        "failures": "1",
        "errors": "2",
        "skipped": "1",
        "time": "3.692567891",
    }
    properties = {
        item.get("name"): item.get("value") for item in root.findall("./properties/property")
    }
    assert properties["assertion_testcases"] == "3"
    assert properties["infrastructure_testcases"] == "2"


def test_processing_mismatch_is_failure_not_error() -> None:
    root = _root(render_junit(_run()))
    case = root.find(".//testcase[@id='assertion-case-1']")
    assert case is not None
    assert case.find("failure") is not None
    assert case.find("error") is None
    assert case.find("failure").get("type") == "receiver_failure"  # type: ignore[union-attr]


def test_observer_timeout_and_unknown_outcome_are_distinct_errors() -> None:
    root = _root(render_junit(_run()))
    timeout = root.find(".//testcase[@id='observer-timeout']/error")
    ambiguous = root.find(".//testcase[@id='unknown-outcome']/error")
    assert timeout is not None
    assert ambiguous is not None
    assert timeout.get("type") == "observer_timeout"
    assert ambiguous.get("type") == "ambiguous_outcome"
    assert (
        root.find(".//testcase[@id='unknown-outcome']").get("name")  # type: ignore[union-attr]
        == f"{INFRASTRUCTURE_TESTCASE_PREFIX}:unknown-outcome"
    )


def test_skipped_assertion_carries_stable_reason_code() -> None:
    root = _root(render_junit(_run()))
    skipped = root.find(".//testcase[@id='assertion-case-2']/skipped")
    assert skipped is not None
    assert skipped.get("type") == "UNSUPPORTED_CAPABILITY"


def test_time_is_fixed_precision_physical_monotonic_seconds() -> None:
    root = _root(render_junit(_run()))
    failure = root.find(".//testcase[@id='assertion-case-1']")
    timeout = root.find(".//testcase[@id='observer-timeout']")
    assert failure is not None
    assert timeout is not None
    assert failure.get("time") == "1.234567890"
    assert timeout.get("time") == "2.000000001"
    assert "logical" not in render_junit(_run()).decode().casefold()


def test_attachments_are_relative_references_and_no_raw_output_is_embedded() -> None:
    payload = render_junit(_run())
    root = _root(payload)
    system_out = root.find(".//testcase[@id='assertion-case-1']/system-out")
    assert system_out is not None
    assert system_out.text == "[artifact] evidence/assertion-record.json"
    assert root.findall(".//system-err") == []
    assert SECRET_CANARY.encode() not in payload
    with pytest.raises(ValueError, match=r"relative|traversal"):
        _case(
            0,
            classification=ResultCategory.PASS,
            duration_ns=0,
            attachment_paths=("../secret.txt",),
        )


def test_untrusted_case_text_is_xml_escaped_not_markup() -> None:
    malicious = '</failure><script>alert(1)</script><x onload="boom">&entity;'
    case = _case(
        0,
        classification=ResultCategory.RECEIVER_FAILURE,
        duration_ns=1,
        message=malicious,
    )
    run = JUnitRun(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        scenarios=(
            JUnitScenario(
                scenario_id=SCENARIO_IDS[0],
                name="malicious",
                ordinal=0,
                cases=(case,),
            ),
        ),
        expected_assertion_count=1,
    )
    payload = render_junit(run)
    root = _root(payload)
    assert root.findall(".//script") == []
    assert b"<script>" not in payload
    assert b"&lt;script&gt;" in payload


@pytest.mark.parametrize(
    "case",
    [
        lambda: _case(
            0,
            classification=ResultCategory.ENVIRONMENT_ERROR,
            duration_ns=0,
        ),
        lambda: _case(
            0,
            classification=ResultCategory.AMBIGUOUS,
            duration_ns=0,
            error_type=JUnitErrorType.HARNESS_ERROR,
        ),
        lambda: _case(
            0,
            classification=ResultCategory.UNSUPPORTED,
            duration_ns=0,
        ),
        lambda: _case(
            0,
            classification=ResultCategory.PASS,
            duration_ns=-1,
        ),
    ],
)
def test_inconsistent_or_nonphysical_cases_are_rejected(case: object) -> None:
    with pytest.raises(
        ValueError,
        match=r"(require|differs|reason_code|duration)",
    ):
        case()  # type: ignore[operator]


def test_golden_junit_is_byte_identical() -> None:
    assert render_junit(_run()) == GOLDEN.read_bytes()
