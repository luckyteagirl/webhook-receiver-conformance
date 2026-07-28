"""Deterministic, bounded, secret-safe JUnit XML rendering."""
# ruff: noqa: D105, EM101, EM102, INP001, TRY003

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Final

from webhook_receiver_conformance.domain.hashing import validate_manifest_id
from webhook_receiver_conformance.domain.identifiers import (
    PlannedIdKind,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)
from webhook_receiver_conformance.errors import ResultCategory

MAX_JUNIT_CASES: Final = 100_000
MAX_JUNIT_TEXT_CHARACTERS: Final = 4_096
MAX_JUNIT_ATTACHMENTS: Final = 64
MAX_PHYSICAL_DURATION_NS: Final = (1 << 63) - 1
INFRASTRUCTURE_TESTCASE_PREFIX: Final = "__infrastructure__"

_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,127}")
_CASE_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,256}")
_CONTROL_TRANSLATION = {
    codepoint: " " for codepoint in (*range(0x20), 0x7F) if codepoint not in {0x09, 0x0A, 0x0D}
}


class JUnitCaseKind(StrEnum):
    """Whether one testcase represents an assertion or infrastructure."""

    ASSERTION = "assertion"
    INFRASTRUCTURE = "infrastructure"


class JUnitErrorType(StrEnum):
    """Stable JUnit error type attributes."""

    OBSERVER_TIMEOUT = "observer_timeout"
    ENVIRONMENT_ERROR = "environment_error"
    HARNESS_ERROR = "harness_error"
    AMBIGUOUS_OUTCOME = "ambiguous_outcome"
    INVALID_INPUT = "invalid_input"


@dataclass(frozen=True, slots=True)
class JUnitCase:
    """One preclassified assertion or infrastructure testcase."""

    case_id: str
    name: str
    kind: JUnitCaseKind
    classification: ResultCategory
    physical_duration_ns: int
    assertion_id: str | None = None
    assertion_ordinal: int | None = None
    message: str | None = None
    reason_code: str | None = None
    error_type: JUnitErrorType | None = None
    evidence_refs: tuple[str, ...] = ()
    attachment_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.case_id) is not str or _CASE_TOKEN.fullmatch(self.case_id) is None:
            raise ValueError("case_id must be a bounded token")
        _bounded_text(self.name, name="case name")
        if type(self.kind) is not JUnitCaseKind:
            raise TypeError("kind must be a JUnitCaseKind")
        if type(self.classification) is not ResultCategory:
            raise TypeError("classification must be a ResultCategory")
        _physical_duration(self.physical_duration_ns)
        if self.message is not None:
            _bounded_text(self.message, name="case message")
        _validate_case_identity(self)
        _validate_case_classification(self)
        _identifier_references(self.evidence_refs)
        _attachment_paths(self.attachment_paths)

    @property
    def testcase_name(self) -> str:
        """Return the reserved or assertion-stable testcase name."""
        if self.kind is JUnitCaseKind.INFRASTRUCTURE:
            return f"{INFRASTRUCTURE_TESTCASE_PREFIX}:{self.case_id}"
        return self.name


@dataclass(frozen=True, slots=True)
class JUnitScenario:
    """One manifest-ordered scenario suite."""

    scenario_id: str
    name: str
    ordinal: int
    cases: tuple[JUnitCase, ...]

    def __post_init__(self) -> None:
        validate_planned_id(
            self.scenario_id,
            expected_kind=PlannedIdKind.SCENARIO,
        )
        _bounded_text(self.name, name="scenario name")
        _ordinal(self.ordinal, name="scenario ordinal")
        if type(self.cases) is not tuple or any(type(item) is not JUnitCase for item in self.cases):
            raise TypeError("cases must contain JUnitCase values")
        if len(self.cases) > MAX_JUNIT_CASES:
            raise ValueError("scenario testcase count exceeds the JUnit limit")
        case_ids = tuple(item.case_id for item in self.cases)
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("scenario testcase IDs must be unique")
        assertion_ordinals = tuple(
            item.assertion_ordinal for item in self.cases if item.kind is JUnitCaseKind.ASSERTION
        )
        if len(set(assertion_ordinals)) != len(assertion_ordinals):
            raise ValueError("scenario assertion ordinals must be unique")

    @property
    def stable_name(self) -> str:
        """Return a deterministic suite name independent of wall time."""
        return f"{self.ordinal:04d}:{self.scenario_id}:{self.name}"


@dataclass(frozen=True, slots=True)
class JUnitRun:
    """One top-level run projection."""

    run_id: str
    manifest_id: str
    scenarios: tuple[JUnitScenario, ...]
    expected_assertion_count: int
    artifact_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_run_id(self.run_id)
        validate_manifest_id(self.manifest_id)
        if type(self.scenarios) is not tuple or any(
            type(item) is not JUnitScenario for item in self.scenarios
        ):
            raise TypeError("scenarios must contain JUnitScenario values")
        if len(self.scenarios) > MAX_JUNIT_CASES:
            raise ValueError("scenario count exceeds the JUnit limit")
        scenario_ids = tuple(item.scenario_id for item in self.scenarios)
        ordinals = tuple(item.ordinal for item in self.scenarios)
        if len(set(scenario_ids)) != len(scenario_ids) or len(set(ordinals)) != len(ordinals):
            raise ValueError("scenario IDs and ordinals must be unique")
        _ordinal(
            self.expected_assertion_count,
            name="expected assertion count",
        )
        actual_assertions = sum(
            item.kind is JUnitCaseKind.ASSERTION
            for scenario in self.scenarios
            for item in scenario.cases
        )
        if actual_assertions != self.expected_assertion_count:
            raise ValueError("JUnit assertion testcase count differs from the result summary")
        _attachment_paths(self.artifact_paths)


def render_junit(run: JUnitRun) -> bytes:
    """Render one stable JUnit document from preclassified facts."""
    if type(run) is not JUnitRun:
        raise TypeError("run must be a JUnitRun")
    scenarios = tuple(sorted(run.scenarios, key=lambda item: item.ordinal))
    counts = _aggregate_counts(scenarios)
    root = ET.Element(
        "testsuites",
        {
            "name": f"webhook-receiver-conformance:{run.run_id}",
            "tests": str(counts.tests),
            "failures": str(counts.failures),
            "errors": str(counts.errors),
            "skipped": str(counts.skipped),
            "time": _duration_seconds(counts.duration_ns),
        },
    )
    _properties(
        root,
        (
            ("run_id", run.run_id),
            ("manifest_id", run.manifest_id),
            ("assertion_testcases", str(run.expected_assertion_count)),
            (
                "infrastructure_testcases",
                str(counts.tests - run.expected_assertion_count),
            ),
            *((f"artifact.{ordinal}", path) for ordinal, path in enumerate(run.artifact_paths)),
        ),
    )
    for scenario in scenarios:
        root.append(_render_suite(run, scenario))
    ET.indent(root, space="  ")
    payload = ET.tostring(
        root,
        encoding="utf-8",
        xml_declaration=True,
        short_empty_elements=True,
    )
    return payload + b"\n"


@dataclass(frozen=True, slots=True)
class _Counts:
    tests: int
    failures: int
    errors: int
    skipped: int
    duration_ns: int


def _render_suite(run: JUnitRun, scenario: JUnitScenario) -> ET.Element:
    cases = tuple(sorted(scenario.cases, key=_case_order))
    counts = _aggregate_case_counts(cases)
    suite = ET.Element(
        "testsuite",
        {
            "id": scenario.scenario_id,
            "name": scenario.stable_name,
            "tests": str(counts.tests),
            "failures": str(counts.failures),
            "errors": str(counts.errors),
            "skipped": str(counts.skipped),
            "time": _duration_seconds(counts.duration_ns),
        },
    )
    _properties(
        suite,
        (
            ("run_id", run.run_id),
            ("manifest_id", run.manifest_id),
            ("scenario_id", scenario.scenario_id),
            ("scenario_ordinal", str(scenario.ordinal)),
        ),
    )
    for case in cases:
        suite.append(_render_case(scenario, case))
    return suite


def _render_case(
    scenario: JUnitScenario,
    case: JUnitCase,
) -> ET.Element:
    testcase = ET.Element(
        "testcase",
        {
            "id": case.case_id,
            "name": _xml_text(case.testcase_name),
            "classname": f"scenario.{scenario.scenario_id}",
            "time": _duration_seconds(case.physical_duration_ns),
        },
    )
    properties = (
        ("classification", case.classification.value),
        ("case_kind", case.kind.value),
        *((("assertion_id", case.assertion_id),) if case.assertion_id is not None else ()),
        *(("evidence_ref", reference) for reference in case.evidence_refs),
    )
    _properties(testcase, properties)
    if case.classification is ResultCategory.RECEIVER_FAILURE:
        failure = ET.SubElement(
            testcase,
            "failure",
            {
                "type": ResultCategory.RECEIVER_FAILURE.value,
                "message": _xml_text(case.message or "Receiver assertion failed."),
            },
        )
        failure.text = _xml_text(case.message or "Comparable evidence violated the assertion.")
    elif case.classification in {
        ResultCategory.ENVIRONMENT_ERROR,
        ResultCategory.HARNESS_ERROR,
        ResultCategory.AMBIGUOUS,
        ResultCategory.INVALID_INPUT,
    }:
        error_type = _resolved_error_type(case)
        error = ET.SubElement(
            testcase,
            "error",
            {
                "type": error_type.value,
                "message": _xml_text(case.message or "Testcase could not be compared."),
            },
        )
        error.text = _xml_text(case.message or "See referenced evidence artifacts.")
    elif case.classification in {
        ResultCategory.UNSUPPORTED,
        ResultCategory.CANCELLED,
    }:
        ET.SubElement(
            testcase,
            "skipped",
            {
                "type": case.reason_code or "",
                "message": _xml_text(case.message or "Testcase was not evaluated."),
            },
        )
    if case.attachment_paths:
        system_out = ET.SubElement(testcase, "system-out")
        system_out.text = "\n".join(f"[artifact] {path}" for path in case.attachment_paths)
    return testcase


def _properties(
    parent: ET.Element,
    values: tuple[tuple[str, str], ...],
) -> None:
    properties = ET.SubElement(parent, "properties")
    for name, value in values:
        ET.SubElement(
            properties,
            "property",
            {"name": name, "value": _xml_text(value)},
        )


def _aggregate_counts(scenarios: tuple[JUnitScenario, ...]) -> _Counts:
    counts = tuple(_aggregate_case_counts(scenario.cases) for scenario in scenarios)
    return _Counts(
        tests=sum(item.tests for item in counts),
        failures=sum(item.failures for item in counts),
        errors=sum(item.errors for item in counts),
        skipped=sum(item.skipped for item in counts),
        duration_ns=sum(item.duration_ns for item in counts),
    )


def _aggregate_case_counts(cases: tuple[JUnitCase, ...]) -> _Counts:
    return _Counts(
        tests=len(cases),
        failures=sum(item.classification is ResultCategory.RECEIVER_FAILURE for item in cases),
        errors=sum(
            item.classification
            in {
                ResultCategory.ENVIRONMENT_ERROR,
                ResultCategory.HARNESS_ERROR,
                ResultCategory.AMBIGUOUS,
                ResultCategory.INVALID_INPUT,
            }
            for item in cases
        ),
        skipped=sum(
            item.classification in {ResultCategory.UNSUPPORTED, ResultCategory.CANCELLED}
            for item in cases
        ),
        duration_ns=sum(item.physical_duration_ns for item in cases),
    )


def _case_order(case: JUnitCase) -> tuple[int, int, str]:
    if case.kind is JUnitCaseKind.ASSERTION:
        if case.assertion_ordinal is None:
            raise AssertionError("assertion case ordinal narrowing failed")
        return (0, case.assertion_ordinal, case.case_id)
    return (1, 0, case.case_id)


def _validate_case_identity(case: JUnitCase) -> None:
    if case.kind is JUnitCaseKind.ASSERTION:
        if case.assertion_id is None or case.assertion_ordinal is None:
            raise ValueError("assertion testcases require assertion identity and ordinal")
        validate_planned_id(
            case.assertion_id,
            expected_kind=PlannedIdKind.ASSERTION,
        )
        _ordinal(case.assertion_ordinal, name="assertion ordinal")
        return
    if case.assertion_id is not None or case.assertion_ordinal is not None:
        raise ValueError("infrastructure testcases cannot claim assertion identity")


def _validate_case_classification(case: JUnitCase) -> None:
    if case.classification in {
        ResultCategory.ENVIRONMENT_ERROR,
        ResultCategory.HARNESS_ERROR,
        ResultCategory.AMBIGUOUS,
        ResultCategory.INVALID_INPUT,
    }:
        if type(case.error_type) is not JUnitErrorType:
            raise ValueError("JUnit error classifications require an error_type")
    elif case.error_type is not None:
        raise ValueError("only JUnit error classifications may set error_type")
    if case.classification in {
        ResultCategory.UNSUPPORTED,
        ResultCategory.CANCELLED,
    }:
        if type(case.reason_code) is not str or _REASON_CODE.fullmatch(case.reason_code) is None:
            raise ValueError("skipped testcases require a stable reason_code")
    elif case.reason_code is not None:
        raise ValueError("only skipped testcases may set reason_code")
    if case.error_type is not None:
        _resolved_error_type(case)


def _resolved_error_type(case: JUnitCase) -> JUnitErrorType:
    expected = {
        ResultCategory.ENVIRONMENT_ERROR: {
            JUnitErrorType.OBSERVER_TIMEOUT,
            JUnitErrorType.ENVIRONMENT_ERROR,
        },
        ResultCategory.HARNESS_ERROR: {JUnitErrorType.HARNESS_ERROR},
        ResultCategory.AMBIGUOUS: {JUnitErrorType.AMBIGUOUS_OUTCOME},
        ResultCategory.INVALID_INPUT: {JUnitErrorType.INVALID_INPUT},
    }[case.classification]
    error_type = case.error_type
    if error_type is None or error_type not in expected:
        raise ValueError("JUnit error_type differs from its classification")
    return error_type


def _duration_seconds(nanoseconds: int) -> str:
    _physical_duration(nanoseconds)
    whole, fraction = divmod(nanoseconds, 1_000_000_000)
    return f"{whole}.{fraction:09d}"


def _physical_duration(value: int) -> None:
    if type(value) is not int or not 0 <= value <= MAX_PHYSICAL_DURATION_NS:
        raise ValueError("physical duration must be bounded nonnegative nanoseconds")


def _ordinal(value: int, *, name: str) -> None:
    if type(value) is not int or not 0 <= value <= (1 << 53) - 1:
        raise ValueError(f"{name} must be a bounded nonnegative integer")


def _bounded_text(value: str, *, name: str) -> None:
    if type(value) is not str or not value or len(value) > MAX_JUNIT_TEXT_CHARACTERS:
        raise ValueError(f"{name} must be bounded nonempty text")


def _xml_text(value: str) -> str:
    return value.translate(_CONTROL_TRANSLATION)[:MAX_JUNIT_TEXT_CHARACTERS]


def _identifier_references(values: tuple[str, ...]) -> None:
    if type(values) is not tuple:
        raise TypeError("evidence_refs must be a tuple")
    for value in values:
        try:
            validate_planned_id(value)
        except ValueError:
            validate_fresh_id(value)
    if len(set(values)) != len(values):
        raise ValueError("evidence_refs must be unique")


def _attachment_paths(values: tuple[str, ...]) -> None:
    if type(values) is not tuple or len(values) > MAX_JUNIT_ATTACHMENTS:
        raise ValueError("attachment_paths must be a bounded tuple")
    for value in values:
        if type(value) is not str or not value or "\\" in value:
            raise ValueError("attachment paths must be nonempty POSIX relative paths")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or not path.parts
            or ".." in path.parts
            or "." in path.parts
            or any(character in "\r\n\x00" for character in value)
            or ":" in path.parts[0]
        ):
            raise ValueError("attachment paths must stay relative and traversal-free")
    if len(set(values)) != len(values):
        raise ValueError("attachment paths must be unique")


__all__ = [
    "INFRASTRUCTURE_TESTCASE_PREFIX",
    "JUnitCase",
    "JUnitCaseKind",
    "JUnitErrorType",
    "JUnitRun",
    "JUnitScenario",
    "render_junit",
]
