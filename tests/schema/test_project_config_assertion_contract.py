"""Closed project-configuration assertion grammar contract tests."""
# ruff: noqa: INP001
# pyright: reportMissingImports=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers"))
from schema_validation import load_json, load_yaml, validate_instance

ROOT = Path(__file__).resolve().parents[2]
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


def _query(key: str = "resource") -> dict[str, Any]:
    return {
        "observer": "receiver_state",
        "key": key,
        "parameters": {"event": "payment"},
    }


def _typed(value_type: str = "integer", value: object = 1) -> dict[str, Any]:
    return {"value_type": value_type, "value": value}


def _predicate(name: str, key: str) -> dict[str, Any]:
    return {
        "name": name,
        "query": _query(key),
        "comparator": "eq",
        "expected": _typed(),
    }


ASSERTION_CASES: tuple[tuple[str, dict[str, Any], tuple[str, ...]], ...] = (
    (
        "http-status",
        {
            "id": "http_status",
            "type": "http-status",
            "attempt": {"event": "payment", "mode": "all-terminal"},
            "expected": {"codes": [200, 204], "classes": ["2xx"]},
        },
        ("id", "type", "attempt", "expected"),
    ),
    (
        "acknowledgement-deadline",
        {
            "id": "ack_deadline",
            "type": "acknowledgement-deadline",
            "attempt": {"event": "payment", "mode": "last-terminal"},
            "within": "2s",
        },
        ("id", "type", "attempt", "within"),
    ),
    (
        "processing-count",
        {
            "id": "processing_count",
            "type": "processing-count",
            "query": _query("processing_count"),
            "comparator": "eq",
            "expected": 1,
        },
        ("id", "type", "query", "comparator", "expected"),
    ),
    (
        "callback-count",
        {
            "id": "callback_count",
            "type": "callback-count",
            "query": _query("callback_count"),
            "comparator": "lte",
            "expected": 1,
        },
        ("id", "type", "query", "comparator", "expected"),
    ),
    (
        "journal-count",
        {
            "id": "journal_count",
            "type": "journal-count",
            "query": _query("journal_count"),
            "comparator": "gte",
            "expected": 1,
        },
        ("id", "type", "query", "comparator", "expected"),
    ),
    (
        "resource-exists",
        {
            "id": "resource_exists",
            "type": "resource-exists",
            "query": _query(),
        },
        ("id", "type", "query"),
    ),
    (
        "resource-absent",
        {
            "id": "resource_absent",
            "type": "resource-absent",
            "query": _query(),
        },
        ("id", "type", "query"),
    ),
    (
        "resource-field",
        {
            "id": "resource_field",
            "type": "resource-field",
            "query": _query(),
            "path": "/status",
            "comparator": "ne",
            "expected": _typed("string", "failed"),
            "missing_pointer": "error",
        },
        ("id", "type", "query", "path", "comparator", "expected"),
    ),
    (
        "ordered-transition",
        {
            "id": "ordered_transition",
            "type": "ordered-transition",
            "query": _query("transitions"),
            "states": ["accepted", "processed"],
            "allow_intermediate": True,
        },
        ("id", "type", "query", "states"),
    ),
    (
        "no-partial-side-effect",
        {
            "id": "no_partial",
            "type": "no-partial-side-effect",
            "predicates": [
                _predicate("processing_record", "processing_count"),
                _predicate("journal_record", "journal_count"),
            ],
        },
        ("id", "type", "predicates"),
    ),
    (
        "eventual-state",
        {
            "id": "eventual_state",
            "type": "eventual-state",
            "query": _query(),
            "path": "/status",
            "comparator": "eq",
            "expected": _typed("string", "processed"),
            "missing_pointer": "fail",
            "within": "2s",
            "poll_interval": "50ms",
        },
        (
            "id",
            "type",
            "query",
            "comparator",
            "expected",
            "within",
            "poll_interval",
        ),
    ),
)

IRRELEVANT_FIELDS: dict[str, tuple[str, object]] = {
    "http-status": ("query", _query()),
    "acknowledgement-deadline": ("expected", _typed()),
    "processing-count": ("attempt", {"event": "payment", "mode": "all-terminal"}),
    "callback-count": ("path", "/status"),
    "journal-count": ("states", ["accepted", "processed"]),
    "resource-exists": ("comparator", "eq"),
    "resource-absent": ("expected", _typed()),
    "resource-field": ("attempt", {"event": "payment", "mode": "all-terminal"}),
    "ordered-transition": ("expected", _typed()),
    "no-partial-side-effect": ("query", _query()),
    "eventual-state": ("attempt", {"event": "payment", "mode": "all-terminal"}),
}

TYPED_VALUES: tuple[dict[str, Any], ...] = (
    _typed("null", None),
    _typed("boolean", value=True),
    _typed("integer", -1),
    _typed("decimal-string", "-12.50e+2"),
    _typed("string", "processed"),
    _typed(
        "bytes-digest",
        {
            "sha256": f"sha256:{'a' * 64}",
            "byte_length": 0,
            "media_type": "application/octet-stream",
        },
    ),
    _typed("timestamp", "2026-07-27T12:34:56.123456789Z"),
    _typed("array", [None, True, 1, "value"]),
    _typed("object", {"nested": [None, True, 1, "value"]}),
)

MALFORMED_TYPED_VALUES: tuple[dict[str, Any], ...] = (
    _typed("null", value=False),
    _typed("boolean", 0),
    _typed("integer", value=True),
    _typed("decimal-string", "01.0"),
    _typed("string", 1),
    _typed("bytes-digest", {"sha256": "not-a-digest", "byte_length": 0}),
    _typed("timestamp", "2026-07-27T12:34:56+00:00"),
    _typed("array", {"not": "an-array"}),
    _typed("object", ["not", "an-object"]),
    _typed("number", 1),
    {"value_type": "integer"},
    {"value_type": "integer", "value": 1, "extra": True},
)


def _copy_complete() -> dict[str, Any]:
    return deepcopy(COMPLETE)


def _config_with_assertion(assertion: dict[str, Any]) -> dict[str, Any]:
    config = _copy_complete()
    scenario = cast("dict[str, Any]", cast("list[Any]", config["scenarios"])[0])
    scenario["assertions"] = [deepcopy(assertion)]
    return config


def _assert_valid_assertion(assertion: dict[str, Any]) -> None:
    assert validate_instance(_config_with_assertion(assertion), SCHEMA) == []


def _assert_invalid_assertion(assertion: dict[str, Any]) -> None:
    assert validate_instance(_config_with_assertion(assertion), SCHEMA)


def _case(assertion_type: str) -> dict[str, Any]:
    return deepcopy(
        next(assertion for name, assertion, _required in ASSERTION_CASES if name == assertion_type)
    )


def test_assertion_schema_is_well_formed_and_examples_validate() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    assert validate_instance(MINIMAL, SCHEMA) == []
    assert validate_instance(COMPLETE, SCHEMA) == []


@pytest.mark.parametrize(
    ("assertion_type", "assertion", "_required"),
    ASSERTION_CASES,
    ids=[case[0] for case in ASSERTION_CASES],
)
def test_every_v01_assertion_branch_accepts_its_nominal_shape(
    assertion_type: str,
    assertion: dict[str, Any],
    _required: tuple[str, ...],
) -> None:
    assert assertion["type"] == assertion_type
    _assert_valid_assertion(assertion)


@pytest.mark.parametrize(
    ("assertion_type", "assertion", "missing_field"),
    [
        (assertion_type, assertion, field)
        for assertion_type, assertion, required in ASSERTION_CASES
        for field in required
    ],
)
def test_every_assertion_branch_rejects_each_missing_required_field(
    assertion_type: str,
    assertion: dict[str, Any],
    missing_field: str,
) -> None:
    candidate = deepcopy(assertion)
    del candidate[missing_field]
    assert candidate.get("type") in {assertion_type, None}
    _assert_invalid_assertion(candidate)


@pytest.mark.parametrize(
    ("assertion_type", "assertion", "_required"),
    ASSERTION_CASES,
    ids=[case[0] for case in ASSERTION_CASES],
)
def test_every_assertion_branch_rejects_an_irrelevant_field(
    assertion_type: str,
    assertion: dict[str, Any],
    _required: tuple[str, ...],
) -> None:
    field, value = IRRELEVANT_FIELDS[assertion_type]
    candidate = deepcopy(assertion)
    candidate[field] = deepcopy(value)
    _assert_invalid_assertion(candidate)


def test_custom_and_unknown_assertion_types_are_rejected() -> None:
    custom = {
        "id": "custom_assertion",
        "type": "custom",
        "query": _query(),
        "expected": _typed(),
    }
    _assert_invalid_assertion(custom)

    unknown = deepcopy(custom)
    unknown["type"] = "vendor-extension"
    _assert_invalid_assertion(unknown)


@pytest.mark.parametrize("field", ["eval", "code", "expression"])
@pytest.mark.parametrize("assertion_type", ["processing-count", "no-partial-side-effect"])
def test_hostile_executable_assertion_fields_are_rejected(
    assertion_type: str,
    field: str,
) -> None:
    assertion = _case(assertion_type)
    assertion[field] = "__import__('os').system('must-not-run')"
    _assert_invalid_assertion(assertion)


@pytest.mark.parametrize(
    "typed_value", TYPED_VALUES, ids=[item["value_type"] for item in TYPED_VALUES]
)
def test_typed_values_accept_exactly_the_nine_observer_evidence_shapes(
    typed_value: dict[str, Any],
) -> None:
    assertion = _case("resource-field")
    assertion["expected"] = typed_value
    _assert_valid_assertion(assertion)


@pytest.mark.parametrize("typed_value", MALFORMED_TYPED_VALUES)
def test_typed_values_reject_malformed_or_mismatched_shapes(
    typed_value: dict[str, Any],
) -> None:
    assertion = _case("resource-field")
    assertion["expected"] = typed_value
    _assert_invalid_assertion(assertion)


@pytest.mark.parametrize("mode", ["all-terminal", "last-terminal"])
def test_attempt_selector_accepts_only_the_two_terminal_modes(mode: str) -> None:
    assertion = _case("http-status")
    assertion["attempt"]["mode"] = mode
    _assert_valid_assertion(assertion)


@pytest.mark.parametrize("mode", ["all", "last", "first-terminal", ""])
def test_attempt_selector_rejects_unknown_modes(mode: str) -> None:
    assertion = _case("http-status")
    assertion["attempt"]["mode"] = mode
    _assert_invalid_assertion(assertion)


@pytest.mark.parametrize("field", ["event", "mode"])
def test_attempt_selector_requires_both_fields(field: str) -> None:
    assertion = _case("http-status")
    del assertion["attempt"][field]
    _assert_invalid_assertion(assertion)


def test_attempt_selector_and_observer_query_are_closed() -> None:
    attempt = _case("http-status")
    attempt["attempt"]["ordinal"] = 1
    _assert_invalid_assertion(attempt)

    query = _case("processing-count")
    query["query"]["checkpoint"] = "after_delivery"
    _assert_invalid_assertion(query)


@pytest.mark.parametrize("field", ["observer", "key"])
def test_observer_query_requires_observer_and_key(field: str) -> None:
    assertion = _case("processing-count")
    del assertion["query"][field]
    _assert_invalid_assertion(assertion)


@pytest.mark.parametrize("comparator", ["eq", "ne", "lt", "lte", "gt", "gte"])
def test_comparator_is_the_closed_six_member_set(comparator: str) -> None:
    assertion = _case("processing-count")
    assertion["comparator"] = comparator
    _assert_valid_assertion(assertion)


def test_unknown_comparator_is_rejected() -> None:
    assertion = _case("processing-count")
    assertion["comparator"] = "contains"
    _assert_invalid_assertion(assertion)


@pytest.mark.parametrize("on_unsupported", ["unsupported", "skip"])
def test_observer_assertions_accept_the_two_unsupported_policies(
    on_unsupported: str,
) -> None:
    assertion = _case("resource-exists")
    assertion["on_unsupported"] = on_unsupported
    _assert_valid_assertion(assertion)


def test_transport_assertions_reject_observer_unsupported_policy() -> None:
    assertion = _case("http-status")
    assertion["on_unsupported"] = "skip"
    _assert_invalid_assertion(assertion)


@pytest.mark.parametrize("missing_pointer", ["fail", "error"])
def test_pointer_assertions_accept_the_two_missing_pointer_policies(
    missing_pointer: str,
) -> None:
    assertion = _case("resource-field")
    assertion["missing_pointer"] = missing_pointer
    _assert_valid_assertion(assertion)


def test_missing_pointer_policy_requires_a_pointer() -> None:
    assertion = _case("eventual-state")
    del assertion["path"]
    _assert_invalid_assertion(assertion)


@pytest.mark.parametrize("field", ["within", "poll_interval"])
def test_optional_observer_polling_requires_the_within_interval_pair(field: str) -> None:
    assertion = _case("processing-count")
    assertion[field] = "1s" if field == "within" else "50ms"
    _assert_invalid_assertion(assertion)


def test_optional_observer_polling_accepts_both_fields_or_neither() -> None:
    without_polling = _case("processing-count")
    _assert_valid_assertion(without_polling)

    with_polling = deepcopy(without_polling)
    with_polling["within"] = "2s"
    with_polling["poll_interval"] = "50ms"
    _assert_valid_assertion(with_polling)


@pytest.mark.parametrize("field", ["within", "poll_interval"])
def test_eventual_state_requires_both_polling_fields(field: str) -> None:
    assertion = _case("eventual-state")
    del assertion[field]
    _assert_invalid_assertion(assertion)


def test_poll_interval_not_exceeding_within_is_a_documented_model_check() -> None:
    assertion = _case("processing-count")
    assertion["within"] = "50ms"
    assertion["poll_interval"] = "2s"
    _assert_valid_assertion(assertion)

    comment = SCHEMA["$defs"]["observer_assertion_common"]["$comment"]
    assert "poll_interval <= within" in comment


@pytest.mark.parametrize("field", ["name", "query", "comparator", "expected"])
def test_no_partial_predicate_requires_every_field(field: str) -> None:
    assertion = _case("no-partial-side-effect")
    del assertion["predicates"][0][field]
    _assert_invalid_assertion(assertion)


def test_no_partial_predicate_is_closed_and_named() -> None:
    assertion = _case("no-partial-side-effect")
    assertion["predicates"][0]["description"] = "not part of the v0.1 predicate shape"
    _assert_invalid_assertion(assertion)

    assert all(predicate["name"] for predicate in assertion["predicates"])


def test_predicate_name_uniqueness_is_a_documented_model_check() -> None:
    assertion = _case("no-partial-side-effect")
    assertion["predicates"][1]["name"] = assertion["predicates"][0]["name"]
    _assert_valid_assertion(assertion)

    comment = SCHEMA["$defs"]["assertion_no_partial_side_effect"]["$comment"]
    assert "predicate names" in comment


def test_http_status_requires_nonempty_codes_or_classes_and_rejects_unknown_classes() -> None:
    empty = _case("http-status")
    empty["expected"] = {}
    _assert_invalid_assertion(empty)

    bad_class = _case("http-status")
    bad_class["expected"] = {"classes": ["1xx"]}
    _assert_invalid_assertion(bad_class)


def test_count_assertions_require_plain_safe_integers() -> None:
    typed = _case("processing-count")
    typed["expected"] = _typed()
    _assert_invalid_assertion(typed)

    overflow = _case("processing-count")
    overflow["expected"] = 9007199254740992
    _assert_invalid_assertion(overflow)
