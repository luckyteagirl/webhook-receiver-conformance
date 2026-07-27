"""Retry and one-fault baseline project-configuration contract tests."""
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
MAX_BASELINES = 64
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

MUTATION_FAULT_CLASSES = {
    "mutation:remove-json-pointer-v1",
    "mutation:replace-json-value-v1",
    "mutation:replace-json-type-v1",
    "mutation:add-json-field-v1",
    "mutation:change-event-id-field-v1",
    "mutation:change-event-type-field-v1",
    "mutation:truncate-bytes-v1",
    "mutation:invalid-json-v1",
    "mutation:content-type-mismatch-v1",
    "mutation:alter-after-signing-v1",
    "mutation:stale-signature-timestamp-v1",
    "mutation:wrong-signing-key-v1",
    "mutation:missing-signature-v1",
    "mutation:malformed-signature-v1",
    "mutation:oversized-body-v1",
}
NON_MUTATION_FAULT_CLASSES = {
    "delivery:duplicate",
    "delivery:concurrent",
    "delivery:dependency-order-reversal",
    "retry:timed_out",
    "retry:connection_failed",
    "retry:retryable_status",
    "lifecycle:restart",
}
FAULT_CLASSES = MUTATION_FAULT_CLASSES | NON_MUTATION_FAULT_CLASSES


def _copy_minimal() -> dict[str, Any]:
    return deepcopy(MINIMAL)


def _copy_complete() -> dict[str, Any]:
    return deepcopy(COMPLETE)


def _first_scenario(config: dict[str, Any]) -> dict[str, Any]:
    return cast("dict[str, Any]", cast("list[Any]", config["scenarios"])[0])


def _first_retry(config: dict[str, Any]) -> dict[str, Any]:
    steps = cast("list[dict[str, Any]]", _first_scenario(config)["steps"])
    deliver = cast("dict[str, Any]", steps[0]["deliver"])
    return cast("dict[str, Any]", deliver["retry"])


def _config_with_retry(retry: dict[str, Any]) -> dict[str, Any]:
    config = _copy_minimal()
    steps = cast("list[dict[str, Any]]", _first_scenario(config)["steps"])
    deliver = cast("dict[str, Any]", steps[0]["deliver"])
    deliver["retry"] = deepcopy(retry)
    return config


def _config_with_baselines(baselines: list[dict[str, Any]]) -> dict[str, Any]:
    config = _copy_complete()
    _first_scenario(config)["baselines"] = deepcopy(baselines)
    return config


def _assert_valid(config: dict[str, Any]) -> None:
    assert validate_instance(config, SCHEMA) == []


def _assert_invalid(config: dict[str, Any]) -> None:
    assert validate_instance(config, SCHEMA)


def test_schema_is_well_formed_and_examples_use_explicit_retry_contract() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    _assert_valid(MINIMAL)
    _assert_valid(COMPLETE)

    assert _first_retry(_copy_minimal()) == {
        "max_attempts": 1,
        "backoff": [],
        "retry_on": [],
    }

    retry_scenario = cast("dict[str, Any]", cast("list[Any]", COMPLETE["scenarios"])[1])
    retry_step = cast("dict[str, Any]", cast("list[Any]", retry_scenario["steps"])[0])
    retry = cast("dict[str, Any]", cast("dict[str, Any]", retry_step["deliver"])["retry"])
    assert retry["retry_on"] == ["timed_out"]


@pytest.mark.parametrize("field", ["max_attempts", "backoff", "retry_on"])
def test_retry_requires_all_three_core_fields(field: str) -> None:
    retry = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": ["timed_out"],
    }
    del retry[field]
    _assert_invalid(_config_with_retry(retry))


def test_retry_object_is_closed() -> None:
    retry = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": ["timed_out"],
        "retry_count": 1,
    }
    _assert_invalid(_config_with_retry(retry))


def test_one_attempt_requires_empty_backoff_and_retry_predicates() -> None:
    valid = {"max_attempts": 1, "backoff": [], "retry_on": []}
    _assert_valid(_config_with_retry(valid))

    nonempty_backoff = deepcopy(valid)
    nonempty_backoff["backoff"] = ["0ns"]
    _assert_invalid(_config_with_retry(nonempty_backoff))

    nonempty_predicate = deepcopy(valid)
    nonempty_predicate["retry_on"] = ["timed_out"]
    _assert_invalid(_config_with_retry(nonempty_predicate))

    statuses = deepcopy(valid)
    statuses["retryable_statuses"] = [503]
    _assert_invalid(_config_with_retry(statuses))


@pytest.mark.parametrize("max_attempts", [2, 32])
def test_multiple_attempts_require_at_least_one_retry_predicate(
    max_attempts: int,
) -> None:
    invalid = {"max_attempts": max_attempts, "backoff": [], "retry_on": []}
    _assert_invalid(_config_with_retry(invalid))

    valid = deepcopy(invalid)
    valid["retry_on"] = ["connection_failed"]
    _assert_valid(_config_with_retry(valid))


@pytest.mark.parametrize("max_attempts", [0, 33, True])
def test_retry_attempt_count_is_a_bounded_integer(max_attempts: object) -> None:
    retry = {
        "max_attempts": max_attempts,
        "backoff": [],
        "retry_on": ["timed_out"],
    }
    _assert_invalid(_config_with_retry(retry))


@pytest.mark.parametrize(
    "retry_on",
    [
        ["timed_out"],
        ["connection_failed"],
        ["retryable_status"],
        ["timed_out", "connection_failed", "retryable_status"],
    ],
)
def test_retry_predicate_vocabulary_accepts_only_the_three_closed_values(
    retry_on: list[str],
) -> None:
    retry: dict[str, Any] = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": retry_on,
    }
    if "retryable_status" in retry_on:
        retry["retryable_statuses"] = [429, "5xx"]
    _assert_valid(_config_with_retry(retry))


@pytest.mark.parametrize(
    "retry_on",
    [["timeout"], ["http_5xx"], ["timed_out", "timed_out"]],
)
def test_retry_predicate_vocabulary_rejects_unknown_or_duplicate_values(
    retry_on: list[str],
) -> None:
    retry = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": retry_on,
    }
    _assert_invalid(_config_with_retry(retry))


def test_retryable_statuses_are_required_if_retryable_status_is_selected() -> None:
    missing: dict[str, Any] = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": ["retryable_status"],
    }
    _assert_invalid(_config_with_retry(missing))

    present = deepcopy(missing)
    present["retryable_statuses"] = [408, 429, "5xx"]
    _assert_valid(_config_with_retry(present))


@pytest.mark.parametrize("retry_on", [["timed_out"], ["connection_failed"]])
def test_retryable_statuses_are_forbidden_without_retryable_status_predicate(
    retry_on: list[str],
) -> None:
    retry = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": retry_on,
        "retryable_statuses": [503],
    }
    _assert_invalid(_config_with_retry(retry))


@pytest.mark.parametrize(
    "selector",
    [100, 204, 429, 599, "2xx", "3xx", "4xx", "5xx"],
)
def test_retryable_status_selector_accepts_exact_codes_and_classes(
    selector: int | str,
) -> None:
    retry = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": ["retryable_status"],
        "retryable_statuses": [selector],
    }
    _assert_valid(_config_with_retry(retry))


@pytest.mark.parametrize(
    "selectors",
    [
        [],
        [99],
        [600],
        ["1xx"],
        ["200"],
        ["5XX"],
        [503, 503],
        [True],
    ],
)
def test_retryable_status_selector_rejects_empty_invalid_or_duplicate_values(
    selectors: list[object],
) -> None:
    retry = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": ["retryable_status"],
        "retryable_statuses": selectors,
    }
    _assert_invalid(_config_with_retry(retry))


@pytest.mark.parametrize("jitter", ["0ns", "1ns", "100ms", "2s"])
def test_jitter_is_an_optional_nonnegative_duration_magnitude(jitter: str) -> None:
    retry = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": ["timed_out"],
        "jitter": jitter,
    }
    _assert_valid(_config_with_retry(retry))


@pytest.mark.parametrize(
    "jitter",
    ["-1ns", "1.5s", "01s", "9223372036854775808ns"],
)
def test_jitter_rejects_negative_fractional_noncanonical_and_overflow_values(
    jitter: str,
) -> None:
    retry = {
        "max_attempts": 2,
        "backoff": ["1s"],
        "retry_on": ["timed_out"],
        "jitter": jitter,
    }
    _assert_invalid(_config_with_retry(retry))


def test_jitter_default_and_policy_are_frozen_in_schema_annotations() -> None:
    retry_schema = cast("dict[str, Any]", SCHEMA["$defs"]["retry"])
    assert retry_schema["properties"]["jitter"]["default"] == "0ns"

    comment = cast("str", retry_schema["$comment"])
    assert "jitter-policy-v1" in comment
    assert "[-jitter, +jitter]" in comment
    assert "clamp the result at zero" in comment
    assert "Logical retry delays participate in clock scaling" in comment
    assert "transport timeouts remain physical monotonic" in comment


def test_backoff_is_bounded_and_each_value_is_an_exact_duration() -> None:
    maximum: dict[str, Any] = {
        "max_attempts": 32,
        "backoff": ["0ns"] * 31,
        "retry_on": ["timed_out"],
    }
    _assert_valid(_config_with_retry(maximum))

    excessive = deepcopy(maximum)
    excessive["backoff"].append("0ns")
    _assert_invalid(_config_with_retry(excessive))

    malformed = deepcopy(maximum)
    malformed["backoff"][0] = "1.5s"
    _assert_invalid(_config_with_retry(malformed))


def test_exact_backoff_cardinality_is_a_documented_model_check() -> None:
    deliberately_short = {
        "max_attempts": 3,
        "backoff": [],
        "retry_on": ["timed_out"],
    }
    _assert_valid(_config_with_retry(deliberately_short))

    comment = cast("str", SCHEMA["$defs"]["retry"]["$comment"])
    assert "len(backoff) == max_attempts - 1" in comment
    assert "model validation" in comment


def test_fault_class_vocabulary_exactly_covers_stage1_mutations_and_control_faults() -> None:
    actual = set(cast("list[str]", SCHEMA["$defs"]["fault_class"]["enum"]))
    assert actual == FAULT_CLASSES

    mutation_types: set[str] = set()
    mutation_schema = cast("dict[str, Any]", SCHEMA["$defs"]["mutation"])
    for branch in cast("list[dict[str, str]]", mutation_schema["oneOf"]):
        definition_name = branch["$ref"].rsplit("/", maxsplit=1)[-1]
        definition = cast("dict[str, Any]", SCHEMA["$defs"][definition_name])
        typed_branch = cast("dict[str, Any]", cast("list[Any]", definition["allOf"])[1])
        mutation_type = cast("str", typed_branch["properties"]["type"]["const"])
        mutation_types.add(f"mutation:{mutation_type}")

    assert mutation_types == MUTATION_FAULT_CLASSES


@pytest.mark.parametrize("fault_class", sorted(FAULT_CLASSES))
def test_every_finite_fault_class_token_is_accepted(fault_class: str) -> None:
    baselines = [{"fault_class": fault_class, "scenario": "sequential_duplicate"}]
    _assert_valid(_config_with_baselines(baselines))


@pytest.mark.parametrize(
    "fault_class",
    [
        "mutation:remove-json-pointer",
        "mutation:custom-v1",
        "delivery:sequential",
        "retry:timeout",
        "lifecycle:stop",
        "Delivery:duplicate",
        "",
    ],
)
def test_unknown_or_near_miss_fault_classes_are_rejected(fault_class: str) -> None:
    baselines = [{"fault_class": fault_class, "scenario": "sequential_duplicate"}]
    _assert_invalid(_config_with_baselines(baselines))


@pytest.mark.parametrize("field", ["fault_class", "scenario"])
def test_baseline_mapping_requires_both_fields(field: str) -> None:
    baseline = {
        "fault_class": "delivery:duplicate",
        "scenario": "sequential_duplicate",
    }
    del baseline[field]
    _assert_invalid(_config_with_baselines([baseline]))


def test_baseline_mapping_is_closed_and_uses_shared_scenario_name() -> None:
    extra = {
        "fault_class": "delivery:duplicate",
        "scenario": "sequential_duplicate",
        "passing": True,
    }
    _assert_invalid(_config_with_baselines([extra]))

    invalid_name = {
        "fault_class": "delivery:duplicate",
        "scenario": "../sequential-duplicate",
    }
    _assert_invalid(_config_with_baselines([invalid_name]))

    baseline_schema = cast("dict[str, Any]", SCHEMA["$defs"]["baseline"])
    assert baseline_schema["properties"]["scenario"]["$ref"] == "#/$defs/name"


def test_baseline_array_is_optional_defaults_empty_and_is_bounded() -> None:
    omitted = _copy_complete()
    assert "baselines" not in _first_scenario(omitted)
    _assert_valid(omitted)

    baselines_schema = cast(
        "dict[str, Any]",
        SCHEMA["$defs"]["scenario"]["properties"]["baselines"],
    )
    assert baselines_schema["default"] == []
    assert baselines_schema["maxItems"] == MAX_BASELINES

    baseline = {
        "fault_class": "delivery:duplicate",
        "scenario": "sequential_duplicate",
    }
    _assert_valid(_config_with_baselines([baseline] * MAX_BASELINES))
    _assert_invalid(_config_with_baselines([baseline] * (MAX_BASELINES + 1)))


def test_baseline_graph_semantics_are_explicit_model_checks() -> None:
    self_reference = {
        "fault_class": "delivery:duplicate",
        "scenario": "sequential_duplicate",
    }
    duplicate_fault_mapping = deepcopy(self_reference)
    _assert_valid(_config_with_baselines([self_reference, duplicate_fault_mapping]))

    baselines_schema = cast(
        "dict[str, Any]",
        SCHEMA["$defs"]["scenario"]["properties"]["baselines"],
    )
    comment = cast("str", baselines_schema["$comment"])
    for required_rule in (
        "fault_class values to be unique",
        "every scenario reference to resolve",
        "no reference to the containing scenario",
        "acyclic baseline graph",
        "exact coverage",
        "exactly one fault class matching",
    ):
        assert required_rule in comment
