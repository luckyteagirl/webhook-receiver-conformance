"""Bounded no-crash/no-leak fuzz targets for artifact and protocol inputs."""
# ruff: noqa: INP001
# pyright: reportMissingImports=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

if TYPE_CHECKING:
    from collections.abc import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers"))
import schema_validation as schema_validation_module
from schema_validation import (
    ArtifactValidationError,
    build_schema_registry,
    load_json,
    parse_html_bytes,
    parse_json_bytes,
    parse_jsonl_bytes,
    parse_xml_bytes,
    parse_yaml_bytes,
    validate_observer_protocol,
)

ROOT = Path(__file__).resolve().parents[2]
CANARY = "SECRET-CANARY-fuzz-input"
MAX_SAFE_DIAGNOSTIC_LENGTH = 256
PARSERS: tuple[tuple[str, Callable[[bytes], object]], ...] = (
    ("json", parse_json_bytes),
    ("yaml", parse_yaml_bytes),
    ("jsonl", parse_jsonl_bytes),
    ("xml", parse_xml_bytes),
    ("html", parse_html_bytes),
)


def _schema_registry() -> Any:  # noqa: ANN401
    schemas = [
        cast("dict[str, Any]", load_json(path))
        for path in sorted((ROOT / "schemas").glob("*.schema.json"))
    ]
    return build_schema_registry(schemas)


@pytest.mark.parametrize(
    "parser",
    [parser for _name, parser in PARSERS],
    ids=[name for name, _parser in PARSERS],
)
@settings(max_examples=40, deadline=500)
@given(st.binary(max_size=2048))
def test_artifact_parsers_fuzz_without_crash_or_input_leak(
    parser: Callable[[bytes], object],
    generated: bytes,
) -> None:
    payload = CANARY.encode() + generated
    try:
        parser(payload)
    except ArtifactValidationError as exc:
        diagnostic = str(exc)
        assert CANARY not in diagnostic
        assert len(diagnostic) <= MAX_SAFE_DIAGNOSTIC_LENGTH


@settings(max_examples=50, deadline=500)
@given(st.binary(max_size=2048))
def test_observer_protocol_fuzz_is_bounded_and_sanitized(generated: bytes) -> None:
    schema = cast(
        "dict[str, Any]",
        load_json(ROOT / "schemas" / "observer-request.schema.json"),
    )
    errors = validate_observer_protocol(
        CANARY.encode() + generated,
        schema,
        registry=_schema_registry(),
    )
    assert all(CANARY not in error for error in errors)
    assert all(len(error) <= MAX_SAFE_DIAGNOSTIC_LENGTH for error in errors)


@pytest.mark.parametrize(
    "parser",
    [parser for _name, parser in PARSERS],
    ids=[name for name, _parser in PARSERS],
)
def test_every_parser_enforces_the_byte_limit(
    parser: Callable[[bytes], object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(schema_validation_module, "MAX_ARTIFACT_BYTES", 8)
    with pytest.raises(ArtifactValidationError, match="exceeds 8 byte limit"):
        parser(b"x" * 9)


@pytest.mark.parametrize(
    ("parser", "payload"),
    [
        (parse_json_bytes, ("[" * 65 + "0" + "]" * 65).encode()),
        (parse_yaml_bytes, ("- " * 65 + "0\n").encode()),
        (parse_xml_bytes, ("<x>" * 65 + "</x>" * 65).encode()),
        (parse_html_bytes, ("<div>" * 65 + "</div>" * 65).encode()),
    ],
    ids=["json", "yaml", "xml", "html"],
)
def test_structured_parsers_enforce_depth_limit(
    parser: Callable[[bytes], object],
    payload: bytes,
) -> None:
    with pytest.raises(ArtifactValidationError, match="nesting depth limit"):
        parser(payload)


@pytest.mark.parametrize(
    ("parser", "payload"),
    [
        (parse_json_bytes, b"[0, 1, 2]"),
        (parse_yaml_bytes, b"[0, 1, 2]"),
        (parse_xml_bytes, b"<r><x/><x/><x/></r>"),
        (parse_html_bytes, b"<p><b></b><b></b><b></b></p>"),
    ],
    ids=["json", "yaml", "xml", "html"],
)
def test_structured_parsers_enforce_node_limit(
    parser: Callable[[bytes], object],
    payload: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(schema_validation_module, "MAX_DOCUMENT_NODES", 3)
    with pytest.raises(ArtifactValidationError, match="node limit"):
        parser(payload)


def test_parser_enforces_time_limit_without_reporting_elapsed_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock_values = iter((0.0, 3.0))
    monkeypatch.setattr(schema_validation_module, "MAX_PARSE_SECONDS", 1.0)
    monkeypatch.setattr(schema_validation_module, "monotonic", lambda: next(clock_values))
    with pytest.raises(ArtifactValidationError, match="1 second time limit"):
        parse_json_bytes(b"{}")


def test_jsonl_record_and_blank_line_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schema_validation_module, "MAX_JSONL_RECORDS", 2)
    with pytest.raises(ArtifactValidationError, match="2 record limit"):
        parse_jsonl_bytes(b"{}\n{}\n{}\n")
    with pytest.raises(ArtifactValidationError, match="blank JSONL record at line 2"):
        parse_jsonl_bytes(b"{}\n\n")


def test_yaml_cycles_and_xml_entities_are_rejected_safely() -> None:
    with pytest.raises(ArtifactValidationError, match="cycles are not supported"):
        parse_yaml_bytes(b"root: &root\n  self: *root\n")
    with pytest.raises(ArtifactValidationError, match="entity declarations are prohibited"):
        parse_xml_bytes(b'<!DOCTYPE x [<!ENTITY canary "SECRET-CANARY">]><x>&canary;</x>')
