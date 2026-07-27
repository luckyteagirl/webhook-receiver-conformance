"""Focused project-configuration schema contract tests."""
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
DEFAULT_CONCURRENCY = 10
MAX_CONCURRENCY = 50
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


def _copy_complete() -> dict[str, Any]:
    return deepcopy(COMPLETE)


def _assert_valid(config: dict[str, Any]) -> None:
    assert validate_instance(config, SCHEMA) == []


def _assert_invalid(config: dict[str, Any]) -> None:
    assert validate_instance(config, SCHEMA)


def _processing_count_assertion(config: dict[str, Any]) -> dict[str, Any]:
    assertions = cast("list[dict[str, Any]]", config["scenarios"][0]["assertions"])
    return next(assertion for assertion in assertions if assertion["type"] == "processing-count")


def test_schema_is_well_formed_and_examples_validate() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    _assert_valid(MINIMAL)
    _assert_valid(COMPLETE)
    assert MINIMAL["clock"]["scale"] == "0.01"
    assert "max_concurrency" not in MINIMAL["limits"]
    assert "tls_verify" not in COMPLETE["receiver"]


def test_max_concurrency_is_optional_with_a_bounded_default() -> None:
    concurrency = SCHEMA["properties"]["limits"]["properties"]["max_concurrency"]
    assert concurrency["default"] == DEFAULT_CONCURRENCY
    assert concurrency["maximum"] == MAX_CONCURRENCY

    omitted = _copy_complete()
    del omitted["limits"]["max_concurrency"]
    _assert_valid(omitted)

    maximum = _copy_complete()
    maximum["limits"]["max_concurrency"] = MAX_CONCURRENCY
    _assert_valid(maximum)

    excessive = _copy_complete()
    excessive["limits"]["max_concurrency"] = MAX_CONCURRENCY + 1
    _assert_invalid(excessive)


@pytest.mark.parametrize("scale", ["0.001", "0.01", "1", "99.999", "100", "100.0"])
def test_scaled_clock_accepts_exact_decimal_scale_bounds(scale: str) -> None:
    config = _copy_complete()
    config["clock"]["scale"] = scale
    _assert_valid(config)


@pytest.mark.parametrize(
    "scale",
    ["0", "-1", "0.0001", "0.000999", "100.0001", "101", "0.01\n", 0.01],
)
def test_scaled_clock_rejects_out_of_range_or_non_string_scale(scale: object) -> None:
    config = _copy_complete()
    config["clock"]["scale"] = scale
    _assert_invalid(config)


def test_clock_mode_and_scale_are_consistent() -> None:
    real = _copy_complete()
    real["clock"] = {"mode": "real", "minimum_physical_wait": "1ms"}
    _assert_valid(real)

    real_with_scale = deepcopy(real)
    real_with_scale["clock"]["scale"] = "1"
    _assert_invalid(real_with_scale)

    scaled_without_scale = _copy_complete()
    del scaled_without_scale["clock"]["scale"]
    _assert_invalid(scaled_without_scale)


@pytest.mark.parametrize(
    "duration",
    [
        "9223372036854775807ns",
        "9223372036854775us",
        "9223372036854ms",
        "9223372036s",
        "153722867m",
        "2562047h",
    ],
)
def test_duration_accepts_each_signed_int64_nanosecond_boundary(duration: str) -> None:
    validator = Draft202012Validator(SCHEMA["$defs"]["duration"])
    assert validator.is_valid(duration)


@pytest.mark.parametrize(
    "duration",
    [
        "9223372036854775808ns",
        "9223372036854776us",
        "9223372036855ms",
        "9223372037s",
        "153722868m",
        "2562048h",
        "1.5s",
        "01s",
        "-1s",
        "1s\n",
    ],
)
def test_duration_rejects_overflow_fractional_and_noncanonical_values(duration: str) -> None:
    validator = Draft202012Validator(SCHEMA["$defs"]["duration"])
    assert not validator.is_valid(duration)


@pytest.mark.parametrize("poll_interval", ["10000000ns", "10000us", "10ms", "1s"])
def test_poll_interval_accepts_ten_milliseconds_or_more(poll_interval: str) -> None:
    config = _copy_complete()
    _processing_count_assertion(config)["poll_interval"] = poll_interval
    _assert_valid(config)


@pytest.mark.parametrize("poll_interval", ["0ns", "9999999ns", "9999us", "9ms", "0s"])
def test_poll_interval_rejects_less_than_ten_milliseconds(poll_interval: str) -> None:
    config = _copy_complete()
    _processing_count_assertion(config)["poll_interval"] = poll_interval
    _assert_invalid(config)


def test_tls_verification_cannot_be_disabled_and_test_ca_is_a_bounded_path() -> None:
    for tls_verify in (False, True):
        config = _copy_complete()
        config["receiver"]["tls_verify"] = tls_verify
        _assert_invalid(config)

    with_test_ca = _copy_complete()
    with_test_ca["receiver"]["test_ca_file"] = ".certificates/test-ca.pem"
    _assert_valid(with_test_ca)

    for invalid_path in ("", "x" * 4097):
        invalid_test_ca = _copy_complete()
        invalid_test_ca["receiver"]["test_ca_file"] = invalid_path
        _assert_invalid(invalid_test_ca)


def test_http_timeouts_are_complete_positive_and_bounded() -> None:
    timeouts_schema = SCHEMA["properties"]["receiver"]["properties"]["timeouts"]
    expected_defaults = {
        "connect": "5s",
        "write": "5s",
        "read": "5s",
        "pool": "5s",
        "total": "30s",
    }
    assert {
        name: contract["default"] for name, contract in timeouts_schema["properties"].items()
    } == expected_defaults

    for name in expected_defaults:
        missing = _copy_complete()
        del missing["receiver"]["timeouts"][name]
        _assert_invalid(missing)

        zero = _copy_complete()
        zero["receiver"]["timeouts"][name] = "0s"
        _assert_invalid(zero)

        overflow = _copy_complete()
        overflow["receiver"]["timeouts"][name] = "9223372036854775808ns"
        _assert_invalid(overflow)

    misspelled = _copy_complete()
    misspelled["receiver"]["timeouts"]["conect"] = "1s"
    _assert_invalid(misspelled)


@pytest.mark.parametrize(
    "header_name",
    [
        "Host",
        "hOsT",
        "Content-Length",
        "cOnTeNt-LeNgTh",
        "Transfer-Encoding",
        "tRaNsFeR-EnCoDiNg",
        "Connection",
        "cOnNeCtIoN",
        "Proxy-Authorization",
        "pRoXy-AuThOrIzAtIoN",
    ],
)
def test_forbidden_signer_header_names_are_case_insensitive(header_name: str) -> None:
    config = _copy_complete()
    config["signers"]["test_hmac"]["header_name"] = header_name
    _assert_invalid(config)


@pytest.mark.parametrize("header_name", ["X Test Signature", "X-Test-Signature\n"])
def test_signer_header_names_require_exact_http_token_syntax(header_name: str) -> None:
    config = _copy_complete()
    config["signers"]["test_hmac"]["header_name"] = header_name
    _assert_invalid(config)


def test_generated_secret_support_is_hmac_only() -> None:
    hmac_config = _copy_complete()
    hmac_config["signers"]["test_hmac"]["secret"] = {"generated": "hmac-256"}
    _assert_valid(hmac_config)

    ed25519_config = _copy_complete()
    ed25519_config["signers"]["test_hmac"]["secret"] = {"generated": "ed25519-test"}
    _assert_invalid(ed25519_config)


def test_restart_steps_require_structured_lifecycle_configuration() -> None:
    profile = {
        "enabled": True,
        "stop_argv": ["python", "receiver_control.py", "stop"],
        "start_argv": ["python", "receiver_control.py", "start"],
        "restart_argv": ["python", "receiver_control.py", "restart"],
        "working_directory": ".",
        "environment_allowlist": ["PATH"],
        "timeout": "30s",
        "readiness_observer": "receiver_state",
    }
    configured = _copy_complete()
    configured["lifecycles"] = {"receiver_process": profile}
    configured["scenarios"][0]["steps"].append({"restart": "receiver_process"})
    _assert_valid(configured)

    unconfigured = _copy_complete()
    unconfigured["scenarios"][0]["steps"].append({"restart": "receiver_process"})
    _assert_invalid(unconfigured)

    missing_field = _copy_complete()
    incomplete_profile = deepcopy(profile)
    del incomplete_profile["restart_argv"]
    missing_field["lifecycles"] = {"receiver_process": incomplete_profile}
    _assert_invalid(missing_field)

    invalid_name = _copy_complete()
    invalid_name["lifecycles"] = {"receiver_process": profile}
    invalid_name["scenarios"][0]["steps"].append({"restart": "../receiver"})
    _assert_invalid(invalid_name)

    assert "names an enabled lifecycle profile" in SCHEMA["$comment"]
    assert "names a configured observer" in SCHEMA["$comment"]
