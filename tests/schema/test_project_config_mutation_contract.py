"""Focused Stage 1 project-configuration mutation and resource contracts."""
# ruff: noqa: INP001
# pyright: reportMissingImports=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from jsonschema import Draft202012Validator

if TYPE_CHECKING:
    from webhook_receiver_conformance.types import JsonValue

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers"))
from schema_validation import load_json, load_yaml, validate_instance

ROOT = Path(__file__).resolve().parents[2]
MAX_CONFIG_BYTES = 16_777_216
MAX_CONFIG_DEPTH = 64
MAX_CONFIG_NODES = 100_000
MAX_SECRET_ROOTS = 16
MAX_PATH_LENGTH = 4096
MAX_CANONICAL_STRING_LENGTH = 4096
MAX_SAFE_INTEGER = (2**53) - 1

SCHEMA = cast(
    "dict[str, Any]",
    load_json(ROOT / "schemas" / "project-config.schema.json"),
)
COMPLETE = cast(
    "dict[str, Any]",
    load_yaml(ROOT / "examples" / "project-config.complete.yaml"),
)
MINIMAL = cast(
    "dict[str, Any]",
    load_yaml(ROOT / "examples" / "project-config.minimal.yaml"),
)

MUTATION_CASES: tuple[tuple[str, dict[str, Any], str], ...] = (
    (
        "remove-json-pointer-v1",
        {"type": "remove-json-pointer-v1", "pointer": "/data/obsolete"},
        "pointer",
    ),
    (
        "replace-json-value-v1",
        {
            "type": "replace-json-value-v1",
            "pointer": "/data/count",
            "value": {"nested": [None, True, MAX_SAFE_INTEGER]},
        },
        "value",
    ),
    (
        "replace-json-type-v1",
        {
            "type": "replace-json-type-v1",
            "pointer": "/data/count",
            "target_type": "string",
        },
        "target_type",
    ),
    (
        "add-json-field-v1",
        {
            "type": "add-json-field-v1",
            "pointer": "/data",
            "name": "unexpected_field",
            "value": "value",
        },
        "name",
    ),
    (
        "change-event-id-field-v1",
        {"type": "change-event-id-field-v1", "value": "evt_changed"},
        "value",
    ),
    (
        "change-event-type-field-v1",
        {"type": "change-event-type-field-v1", "value": "payment.changed"},
        "value",
    ),
    (
        "truncate-bytes-v1",
        {"type": "truncate-bytes-v1", "length": 0},
        "length",
    ),
    (
        "invalid-json-v1",
        {"type": "invalid-json-v1", "strategy": "truncated-object"},
        "strategy",
    ),
    (
        "content-type-mismatch-v1",
        {"type": "content-type-mismatch-v1", "media_type": "text/plain"},
        "media_type",
    ),
    (
        "alter-after-signing-v1",
        {"type": "alter-after-signing-v1", "offset": 0, "xor": 1},
        "xor",
    ),
    (
        "stale-signature-timestamp-v1",
        {"type": "stale-signature-timestamp-v1", "age": "6m"},
        "age",
    ),
    (
        "wrong-signing-key-v1",
        {"type": "wrong-signing-key-v1", "context": "wrong-key-case"},
        "context",
    ),
    (
        "missing-signature-v1",
        {"type": "missing-signature-v1"},
        "type",
    ),
    (
        "malformed-signature-v1",
        {"type": "malformed-signature-v1", "case": "invalid-encoding"},
        "case",
    ),
    (
        "oversized-body-v1",
        {
            "type": "oversized-body-v1",
            "target_bytes": 1_048_577,
            "fill": "ascii-space",
        },
        "target_bytes",
    ),
)

STRUCTURAL_MUTATION_TYPES = {
    "remove-json-pointer-v1",
    "replace-json-value-v1",
    "replace-json-type-v1",
    "add-json-field-v1",
    "change-event-id-field-v1",
    "change-event-type-field-v1",
}


def _copy_complete() -> dict[str, Any]:
    return deepcopy(COMPLETE)


def _with_mutation(mutation: dict[str, Any]) -> dict[str, Any]:
    config = _copy_complete()
    scenarios = cast("list[dict[str, Any]]", config["scenarios"])
    steps = cast("list[dict[str, Any]]", scenarios[0]["steps"])
    deliver = cast("dict[str, Any]", steps[0]["deliver"])
    deliver["mutations"] = [mutation]
    return config


def _assert_valid(config: dict[str, Any]) -> None:
    assert validate_instance(config, SCHEMA) == []


def _assert_invalid(config: dict[str, Any]) -> None:
    assert validate_instance(config, SCHEMA)


def _definition_errors(name: str, value: JsonValue) -> list[str]:
    fragment = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": f"#/$defs/{name}",
        "$defs": SCHEMA["$defs"],
    }
    return validate_instance(value, fragment)


def test_resource_limits_are_exact_top_level_schema_annotations() -> None:
    assert SCHEMA["x-resource-limits"] == {
        "MAX_CONFIG_BYTES": MAX_CONFIG_BYTES,
        "MAX_CONFIG_DEPTH": MAX_CONFIG_DEPTH,
        "MAX_CONFIG_NODES": MAX_CONFIG_NODES,
    }
    comment = cast("str", SCHEMA["$comment"])
    for declaration in (
        f"MAX_CONFIG_BYTES={MAX_CONFIG_BYTES}",
        f"MAX_CONFIG_DEPTH={MAX_CONFIG_DEPTH}",
        f"MAX_CONFIG_NODES={MAX_CONFIG_NODES}",
    ):
        assert declaration in comment
    assert "before parsing" in comment
    assert "before model construction" in comment


def test_examples_validate_with_explicit_and_defaulted_secret_roots() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    _assert_valid(COMPLETE)
    _assert_valid(MINIMAL)
    assert COMPLETE["project"]["secret_roots"] == [".secrets"]
    assert "secret_roots" not in MINIMAL["project"]
    assert SCHEMA["properties"]["project"]["properties"]["secret_roots"]["default"] == []


@pytest.mark.parametrize(
    ("mutation_type", "mutation", "_missing_field"),
    MUTATION_CASES,
    ids=[item[0] for item in MUTATION_CASES],
)
def test_every_enabled_mutation_branch_accepts_one_nominal_case(
    mutation_type: str,
    mutation: dict[str, Any],
    _missing_field: str,
) -> None:
    assert mutation["type"] == mutation_type
    _assert_valid(_with_mutation(mutation))


@pytest.mark.parametrize(
    ("_mutation_type", "mutation", "missing_field"),
    MUTATION_CASES,
    ids=[item[0] for item in MUTATION_CASES],
)
def test_every_enabled_mutation_branch_rejects_a_missing_required_field(
    _mutation_type: str,
    mutation: dict[str, Any],
    missing_field: str,
) -> None:
    incomplete = deepcopy(mutation)
    del incomplete[missing_field]
    _assert_invalid(_with_mutation(incomplete))


@pytest.mark.parametrize(
    ("_mutation_type", "mutation", "_missing_field"),
    MUTATION_CASES,
    ids=[item[0] for item in MUTATION_CASES],
)
def test_every_enabled_mutation_branch_rejects_an_irrelevant_field(
    _mutation_type: str,
    mutation: dict[str, Any],
    _missing_field: str,
) -> None:
    polluted = {**mutation, "selector": "must-not-be-accepted"}
    _assert_invalid(_with_mutation(polluted))


@pytest.mark.parametrize("mutation_type", ["invalid-utf8-v1", "duplicate-json-key-v1"])
def test_deferred_mutations_are_rejected(mutation_type: str) -> None:
    _assert_invalid(_with_mutation({"type": mutation_type}))


@pytest.mark.parametrize(
    "strategy",
    ["truncated-object", "bad-escape", "trailing-comma"],
)
def test_invalid_json_catalog_is_closed(strategy: str) -> None:
    _assert_valid(_with_mutation({"type": "invalid-json-v1", "strategy": strategy}))


@pytest.mark.parametrize(
    "case",
    [
        "invalid-encoding",
        "missing-component",
        "invalid-delimiter",
        "duplicate-component",
    ],
)
def test_malformed_signature_catalog_is_closed(case: str) -> None:
    _assert_valid(_with_mutation({"type": "malformed-signature-v1", "case": case}))


@pytest.mark.parametrize(
    "mutation",
    [
        {"type": "invalid-json-v1", "strategy": "random-corruption"},
        {"type": "malformed-signature-v1", "case": "random"},
        {
            "type": "oversized-body-v1",
            "target_bytes": 1_048_577,
            "fill": "zero-byte",
        },
        {"type": "missing-signature-v1", "header": "x-signature"},
    ],
)
def test_frozen_catalogs_and_missing_signature_selector_are_closed(
    mutation: dict[str, Any],
) -> None:
    _assert_invalid(_with_mutation(mutation))


@pytest.mark.parametrize("value", [-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER])
def test_canonical_json_accepts_safe_integer_boundaries(value: int) -> None:
    mutation = {
        "type": "replace-json-value-v1",
        "pointer": "/data/value",
        "value": {"nested": [value]},
    }
    _assert_valid(_with_mutation(mutation))


@pytest.mark.parametrize(
    "value",
    [
        -(MAX_SAFE_INTEGER + 1),
        MAX_SAFE_INTEGER + 1,
        0.5,
        -1.5,
        float("nan"),
        float("inf"),
    ],
)
def test_canonical_json_rejects_unsafe_or_noninteger_numbers(value: float) -> None:
    mutation = {
        "type": "replace-json-value-v1",
        "pointer": "/data/value",
        "value": {"nested": [value]},
    }
    _assert_invalid(_with_mutation(mutation))


def test_integral_float_rejection_is_an_explicit_loader_boundary() -> None:
    comment = cast("str", SCHEMA["$defs"]["canonical_json_value"]["$comment"]).casefold()
    assert "loader" in comment
    assert "floating-point lexical values" in comment
    assert "1 and 1.0" in comment


def test_canonical_json_strings_and_collections_are_bounded() -> None:
    assert _definition_errors("canonical_json_value", "x" * MAX_CANONICAL_STRING_LENGTH) == []
    assert _definition_errors(
        "canonical_json_value",
        "x" * (MAX_CANONICAL_STRING_LENGTH + 1),
    )
    maximum_items = cast("list[JsonValue]", [None] * 1000)
    excessive_items = cast("list[JsonValue]", [None] * 1001)
    assert _definition_errors("canonical_json_value", maximum_items) == []
    assert _definition_errors("canonical_json_value", excessive_items)


@pytest.mark.parametrize(
    "path",
    [".secrets", "secrets/nested", "secrets\\nested"],
)
def test_secret_roots_accept_bounded_project_relative_paths(path: str) -> None:
    config = _copy_complete()
    config["project"]["secret_roots"] = [path]
    _assert_valid(config)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/absolute",
        "\\absolute",
        "C:\\secrets",
        "C:secrets",
        "https://example.invalid/secrets",
        "../secrets",
        "secrets/../outside",
        "secrets\\..\\outside",
        "secrets\nforged",
    ],
)
def test_secret_roots_reject_empty_absolute_traversal_or_multiline_paths(
    path: str,
) -> None:
    config = _copy_complete()
    config["project"]["secret_roots"] = [path]
    _assert_invalid(config)


def test_secret_root_count_uniqueness_and_length_are_bounded() -> None:
    maximum = _copy_complete()
    maximum["project"]["secret_roots"] = [
        f"secret-root-{index}" for index in range(MAX_SECRET_ROOTS)
    ]
    _assert_valid(maximum)

    excessive = _copy_complete()
    excessive["project"]["secret_roots"] = [
        f"secret-root-{index}" for index in range(MAX_SECRET_ROOTS + 1)
    ]
    _assert_invalid(excessive)

    duplicate = _copy_complete()
    duplicate["project"]["secret_roots"] = [".secrets", ".secrets"]
    _assert_invalid(duplicate)

    too_long = _copy_complete()
    too_long["project"]["secret_roots"] = ["s" * (MAX_PATH_LENGTH + 1)]
    _assert_invalid(too_long)


def test_secret_file_containment_remains_an_explicit_semantic_check() -> None:
    without_roots = _copy_complete()
    without_roots["project"]["secret_roots"] = []
    _assert_valid(without_roots)
    assert "secret-file containment under project.secret_roots" in SCHEMA["$comment"]


@pytest.mark.parametrize(
    ("name", "accepted", "rejected"),
    [
        ("name", "valid_name", "Invalid-Name"),
        ("path", "x" * MAX_PATH_LENGTH, "x" * (MAX_PATH_LENGTH + 1)),
        ("json_pointer", "/data/~0escaped/~1slash", "/data/~2invalid"),
    ],
)
def test_shared_bounded_definitions_are_closed(
    name: str,
    accepted: str,
    rejected: str,
) -> None:
    assert _definition_errors(name, accepted) == []
    assert _definition_errors(name, rejected)


@pytest.mark.parametrize(
    ("mutation_type", "mutation", "_missing_field"),
    MUTATION_CASES,
    ids=[item[0] for item in MUTATION_CASES],
)
def test_accept_prior_mutation_is_only_available_to_structural_operators(
    mutation_type: str,
    mutation: dict[str, Any],
    _missing_field: str,
) -> None:
    with_accept_prior = {**mutation, "accept_prior_mutation": True}
    if mutation_type in STRUCTURAL_MUTATION_TYPES:
        _assert_valid(_with_mutation(with_accept_prior))
    else:
        _assert_invalid(_with_mutation(with_accept_prior))
