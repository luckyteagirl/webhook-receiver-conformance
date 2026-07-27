"""Stage A contract tests for strict immutable project-configuration models."""
# ruff: noqa: INP001, PLR2004

from __future__ import annotations

import builtins
import json
from collections import UserDict
from copy import deepcopy
from fractions import Fraction
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from webhook_receiver_conformance.config.models import (
    MAX_DURATION_NANOSECONDS,
    MAX_SAFE_INTEGER,
    CanonicalJsonValue,
    CommandObserverConfig,
    ConfigModel,
    Duration,
    EnvironmentSecretRef,
    FileSecretRef,
    FixtureConfig,
    FrozenDict,
    GeneratedSecretRef,
    GenericHmacSha256SignerConfig,
    HttpObserverConfig,
    LifecycleProfile,
    LimitsConfig,
    ObserverConfig,
    ObserverHttpTimeouts,
    PollDuration,
    PositiveDuration,
    ProjectSettings,
    RealClockConfig,
    ReceiverConfig,
    ReceiverTimeouts,
    RedactionConfig,
    ReportsConfig,
    Scale,
    ScaledClockConfig,
    SecretRef,
    SignerConfig,
    StandardWebhooksHmacSignerConfig,
    StripeV1SignerConfig,
    thaw_canonical_json,
)
from webhook_receiver_conformance.config.schema import (
    MAX_CONFIG_BYTES,
    MAX_CONFIG_DEPTH,
    MAX_CONFIG_NODES,
    MAX_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR,
    MIN_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR,
    PROJECT_CONFIG_SCHEMA_MAJOR,
    PROJECT_CONFIG_SCHEMA_VERSION,
    SUPPORTED_CONFIG_SCHEMA_VERSIONS,
    preflight_config,
    resource_limit_diagnostic,
    schema_version_diagnostic,
)
from webhook_receiver_conformance.errors import (
    ErrorCategory,
    ExitCode,
    ResultCategory,
    exit_for_result,
)
from webhook_receiver_conformance.version import VERSION_METADATA


class _ProbeModel(ConfigModel):
    value: int


class _NullableProbeModel(ConfigModel):
    explicit_null_fields = frozenset({"value"})

    value: object
    optional_label: str | None = None


def _receiver_timeouts() -> dict[str, str]:
    return {
        "connect": "5s",
        "write": "5s",
        "read": "5s",
        "pool": "5s",
        "total": "30s",
    }


def _observer_timeouts() -> dict[str, str]:
    return {"connect": "5s", "read": "5s", "total": "30s"}


def _assert_model_wire_round_trip(model: ConfigModel, model_type: type[ConfigModel]) -> None:
    wire = model.to_wire()
    detached = json.loads(json.dumps(wire))
    assert model_type.model_validate(detached) == model


def _assert_adapter_wire_round_trip(model: object, adapter: TypeAdapter[Any]) -> None:
    wire = adapter.dump_python(model, mode="json", exclude_none=True)
    detached = json.loads(json.dumps(wire))
    assert adapter.validate_python(detached) == model


def test_config_model_is_strict_frozen_closed_and_rejects_explicit_null() -> None:
    model = _ProbeModel(value=1)
    assert model.value == 1

    with pytest.raises(ValidationError):
        _ProbeModel.model_validate({"value": True})
    with pytest.raises(ValidationError):
        _ProbeModel.model_validate({"value": "1"})
    with pytest.raises(ValidationError):
        _ProbeModel.model_validate({"value": 1, "extra": "forbidden"})
    with pytest.raises(ValidationError):
        _ProbeModel.model_validate({"value": None})
    with pytest.raises(ValidationError):
        model.value = 2


def test_explicit_null_allowlist_is_narrow_and_preserved_on_wire() -> None:
    model = _NullableProbeModel.model_validate({"value": None})
    assert model.value is None
    assert model.to_wire() == {"value": None}

    with pytest.raises(ValidationError, match="cannot be null"):
        _NullableProbeModel.model_validate({"value": None, "optional_label": None})
    with pytest.raises(ValidationError, match="cannot be null"):
        ProjectSettings.model_validate(
            {
                "name": "project",
                "artifact_directory": ".artifacts",
                "seed": None,
            }
        )


def test_canonical_json_is_deeply_immutable_copy_safe_and_wire_serializable() -> None:
    source: dict[str, object] = {"nested": [{"safe": MAX_SAFE_INTEGER}, None, True, "value"]}
    value = CanonicalJsonValue(source)
    source["nested"] = ["changed"]

    assert isinstance(value.value, FrozenDict)
    nested = value.value["nested"]
    assert isinstance(nested, tuple)
    assert isinstance(nested[0], FrozenDict)
    assert nested[0]["safe"] == MAX_SAFE_INTEGER
    with pytest.raises(TypeError):
        nested[0]["safe"] = 0  # type: ignore[index]

    adapter = TypeAdapter(CanonicalJsonValue)
    wire = adapter.dump_python(value, mode="json")
    assert wire == {"nested": [{"safe": MAX_SAFE_INTEGER}, None, True, "value"]}
    assert adapter.validate_python(json.loads(json.dumps(wire))) == value
    assert thaw_canonical_json(value.value) == wire


def test_canonical_json_and_frozen_mapping_reject_direct_slot_mutation() -> None:
    source = {"nested": {"safe": 1}}
    value = CanonicalJsonValue(source)
    frozen = value.value
    assert isinstance(frozen, FrozenDict)
    source["nested"] = {"changed": True}

    with pytest.raises(AttributeError, match="FrozenDict is immutable"):
        frozen._FrozenDict__items = (("changed", True),)  # type: ignore[attr-defined]  # noqa: SLF001
    with pytest.raises(AttributeError, match="FrozenDict is immutable"):
        del frozen._FrozenDict__items  # type: ignore[attr-defined]  # noqa: SLF001
    with pytest.raises(AttributeError, match="CanonicalJsonValue is immutable"):
        value._CanonicalJsonValue__value = None  # type: ignore[attr-defined]  # noqa: SLF001
    with pytest.raises(AttributeError, match="CanonicalJsonValue is immutable"):
        del value._CanonicalJsonValue__value  # type: ignore[attr-defined]  # noqa: SLF001

    assert value.to_wire() == {"nested": {"safe": 1}}


def test_frozen_mapping_hash_matches_order_insensitive_equality() -> None:
    first = FrozenDict({"alpha": 1, "beta": 2})
    second = FrozenDict({"beta": 2, "alpha": 1})

    assert first == second
    assert hash(first) == hash(second)
    assert len({first, second}) == 1


def test_external_collections_require_json_list_and_dict_shapes() -> None:
    with pytest.raises(ValidationError, match="provided as lists"):
        ProjectSettings.model_validate(
            {
                "name": "project",
                "artifact_directory": ".artifacts",
                "secret_roots": (".secrets",),
            }
        )
    with pytest.raises(ValidationError, match="provided as dictionaries"):
        _ProbeModel.model_validate(UserDict({"value": 1}))
    with pytest.raises(TypeError, match="provided as lists"):
        CanonicalJsonValue((1,))
    with pytest.raises(TypeError, match="provided as dictionaries"):
        CanonicalJsonValue(UserDict({"value": 1}))

    assert (
        ProjectSettings(
            name="project",
            artifact_directory=".artifacts",
        ).secret_roots
        == ()
    )
    internal = FrozenDict({"value": CanonicalJsonValue([1]).value})
    assert CanonicalJsonValue(internal).to_wire() == {"value": [1]}
    existing = CanonicalJsonValue([1])
    assert TypeAdapter(CanonicalJsonValue).validate_python(existing) is existing


@pytest.mark.parametrize(
    "value",
    [
        MAX_SAFE_INTEGER + 1,
        -(MAX_SAFE_INTEGER + 1),
        0.0,
        1.5,
        float("nan"),
        float("inf"),
        "x" * 4097,
        [None] * 1001,
        {str(index): None for index in range(1001)},
        {1: "non-string-key"},
    ],
)
def test_canonical_json_rejects_unsafe_or_excessive_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        CanonicalJsonValue(value)


def test_canonical_json_depth_and_node_limits_are_enforced_iteratively() -> None:
    too_deep: object = None
    for _ in range(64):
        too_deep = [too_deep]
    with pytest.raises(ValueError, match="depth"):
        CanonicalJsonValue(too_deep)

    excessive_nodes = [[None] * 1000 for _ in range(100)]
    with pytest.raises(ValueError, match="node"):
        CanonicalJsonValue(excessive_nodes)


@pytest.mark.parametrize(
    ("wire", "nanoseconds"),
    [
        ("0ns", 0),
        ("1ns", 1),
        ("10us", 10_000),
        ("10ms", 10_000_000),
        ("10s", 10_000_000_000),
        ("2m", 120_000_000_000),
        ("1h", 3_600_000_000_000),
        ("9223372036854775807ns", MAX_DURATION_NANOSECONDS),
        ("9223372036854775us", 9_223_372_036_854_775_000),
        ("9223372036854ms", 9_223_372_036_854_000_000),
        ("9223372036s", 9_223_372_036_000_000_000),
        ("153722867m", 9_223_372_020_000_000_000),
        ("2562047h", 9_223_369_200_000_000_000),
    ],
)
def test_duration_accepts_exact_wire_values(wire: str, nanoseconds: int) -> None:
    value = TypeAdapter(Duration).validate_python(wire)
    assert str(value) == wire
    assert value.nanoseconds == nanoseconds
    assert TypeAdapter(Duration).dump_python(value, mode="json") == wire


@pytest.mark.parametrize(
    "wire",
    [
        "9223372036854775808ns",
        "9223372036854776us",
        "9223372036855ms",
        "9223372037s",
        "153722868m",
        "2562048h",
        "-1s",
        "1.5s",
        "01s",
        "1",
        "1s\n",
        1,
        True,
    ],
)
def test_duration_rejects_overflow_noncanonical_or_non_string_values(
    wire: object,
) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(Duration).validate_python(wire)


def test_positive_and_poll_duration_enforce_exact_minima() -> None:
    assert TypeAdapter(PositiveDuration).validate_python("1ns").nanoseconds == 1
    assert TypeAdapter(PollDuration).validate_python("10ms").nanoseconds == 10_000_000

    for wire in ("0ns", "0us", "0ms", "0s", "0m", "0h"):
        with pytest.raises(ValidationError):
            TypeAdapter(PositiveDuration).validate_python(wire)
    for wire in ("0ns", "9999999ns", "9999us", "9ms", "0s"):
        with pytest.raises(ValidationError):
            TypeAdapter(PollDuration).validate_python(wire)


@pytest.mark.parametrize(
    ("wire", "fraction"),
    [
        ("0.001", Fraction(1, 1000)),
        ("0.01", Fraction(1, 100)),
        ("1", Fraction(1)),
        ("1.000", Fraction(1)),
        ("99.999", Fraction(99_999, 1000)),
        ("100", Fraction(100)),
        ("100.0", Fraction(100)),
    ],
)
def test_scale_preserves_wire_string_and_exact_fraction(
    wire: str,
    fraction: Fraction,
) -> None:
    value = TypeAdapter(Scale).validate_python(wire)
    assert str(value) == wire
    assert value.fraction == fraction
    assert TypeAdapter(Scale).dump_python(value, mode="json") == wire


@pytest.mark.parametrize(
    "wire",
    ["0", "-1", "0.0001", "100.0001", "101", "01", ".01", "1e-2", "0.01\n", 0.01, True],
)
def test_scale_rejects_invalid_or_coerced_values(wire: object) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(Scale).validate_python(wire)


@pytest.mark.parametrize(
    ("payload", "expected_type"),
    [
        ({"env": "WEBHOOK_SECRET"}, EnvironmentSecretRef),
        ({"file": ".secrets/key"}, FileSecretRef),
        ({"generated": "hmac-256"}, GeneratedSecretRef),
    ],
)
def test_all_secret_reference_branches_are_strict_and_round_trip(
    payload: dict[str, str],
    expected_type: type[ConfigModel],
) -> None:
    adapter: TypeAdapter[SecretRef] = TypeAdapter(SecretRef)
    model = adapter.validate_python(payload)
    assert isinstance(model, expected_type)
    _assert_adapter_wire_round_trip(model, adapter)


@pytest.mark.parametrize(
    "payload",
    [
        {"env": "lowercase"},
        {"file": ""},
        {"generated": "ed25519-test"},
        {"env": "WEBHOOK_SECRET", "file": ".secrets/key"},
        {"env": "WEBHOOK_SECRET", "extra": True},
    ],
)
def test_secret_reference_union_rejects_invalid_or_ambiguous_shapes(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(SecretRef).validate_python(payload)


def test_project_settings_defaults_are_immutable_and_copy_safe() -> None:
    roots = [".secrets"]
    model = ProjectSettings.model_validate(
        {
            "name": "project",
            "artifact_directory": ".artifacts",
            "secret_roots": roots,
        }
    )
    roots.append("changed")

    assert model.seed is None
    assert model.secret_roots == (".secrets",)
    assert model.to_wire() == {
        "name": "project",
        "artifact_directory": ".artifacts",
        "secret_roots": [".secrets"],
    }
    _assert_model_wire_round_trip(model, ProjectSettings)


@pytest.mark.parametrize(
    "roots",
    [
        [".secrets", ".secrets"],
        [f"root-{index}" for index in range(17)],
        ["/absolute"],
        ["C:\\secrets"],
        ["../outside"],
        ["inside/../outside"],
        ["bad\npath"],
    ],
)
def test_project_settings_rejects_invalid_secret_roots(roots: list[str]) -> None:
    with pytest.raises(ValidationError):
        ProjectSettings.model_validate(
            {
                "name": "project",
                "artifact_directory": ".artifacts",
                "secret_roots": roots,
            }
        )


def test_receiver_models_cover_defaults_boundaries_and_round_trip() -> None:
    hosts = ["receiver.test"]
    ports = [443]
    model = ReceiverConfig.model_validate(
        {
            "url": "https://receiver.test/webhooks",
            "target_profile": "private-allowlist",
            "allowed_hosts": hosts,
            "allowed_ports": ports,
            "timeouts": _receiver_timeouts(),
        }
    )
    hosts.append("changed.test")
    ports.append(8443)

    assert model.allowed_hosts == ("receiver.test",)
    assert model.allowed_ports == (443,)
    assert model.public_challenge_path == "/.well-known/webhook-conformance-challenge"
    assert model.test_ca_file is None
    assert model.timeouts.total.nanoseconds == 30_000_000_000
    _assert_model_wire_round_trip(model, ReceiverConfig)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("url", "ftp://receiver.test/webhooks"),
        ("url", "https://receiver.test/\nforged"),
        ("target_profile", "public"),
        ("allowed_hosts", ["same", "same"]),
        ("allowed_hosts", ["host"] * 65),
        ("allowed_ports", [0]),
        ("allowed_ports", [65536]),
        ("allowed_ports", [443, 443]),
        ("public_challenge_path", "relative"),
        ("public_challenge_path", "/ok\nforged"),
    ],
)
def test_receiver_rejects_invalid_branch_values(field: str, value: object) -> None:
    payload: dict[str, object] = {
        "url": "http://127.0.0.1:8000/webhooks",
        "target_profile": "loopback",
        "timeouts": _receiver_timeouts(),
    }
    payload[field] = value
    with pytest.raises(ValidationError):
        ReceiverConfig.model_validate(payload)


def test_target_profile_accepts_exact_strings_but_rejects_bytes() -> None:
    payload: dict[str, object] = {
        "url": "http://127.0.0.1:8000/webhooks",
        "target_profile": b"loopback",
        "timeouts": _receiver_timeouts(),
    }
    with pytest.raises(ValidationError):
        ReceiverConfig.model_validate(payload)


def test_receiver_timeout_fields_are_required_positive_and_closed() -> None:
    for field in _receiver_timeouts():
        missing = _receiver_timeouts()
        del missing[field]
        with pytest.raises(ValidationError):
            ReceiverTimeouts.model_validate(missing)

        zero = _receiver_timeouts()
        zero[field] = "0s"
        with pytest.raises(ValidationError):
            ReceiverTimeouts.model_validate(zero)

    with pytest.raises(ValidationError):
        ReceiverTimeouts.model_validate({**_receiver_timeouts(), "conect": "1s"})


def test_fixture_config_defaults_and_strict_shape_round_trip() -> None:
    model = FixtureConfig.model_validate(
        {
            "id": "payment_succeeded",
            "path": "fixtures/payment.json",
            "media_type": "application/json",
        }
    )
    assert str(model.event_id_pointer) == "/id"
    assert str(model.event_type_pointer) == "/type"
    assert model.schema_path is None
    _assert_model_wire_round_trip(model, FixtureConfig)

    unrestricted = FixtureConfig.model_validate(
        {
            **model.to_wire(),
            "event_id_pointer": "schema-allows-a-non-pointer",
            "event_type_pointer": "",
        }
    )
    assert unrestricted.event_id_pointer == "schema-allows-a-non-pointer"
    assert unrestricted.event_type_pointer == ""


@pytest.mark.parametrize(
    ("profile", "model_type"),
    [
        ("generic-hmac-sha256", GenericHmacSha256SignerConfig),
        ("stripe-v1", StripeV1SignerConfig),
        ("standard-webhooks-hmac", StandardWebhooksHmacSignerConfig),
    ],
)
def test_all_signer_profiles_are_discriminated_strict_and_round_trip(
    profile: str,
    model_type: type[ConfigModel],
) -> None:
    adapter: TypeAdapter[SignerConfig] = TypeAdapter(SignerConfig)
    model = adapter.validate_python(
        {
            "profile": profile,
            "secret": {"env": "WEBHOOK_SECRET"},
            "header_name": "X-Test-Signature",
            "replay_window": "5m",
            "key_id": "key-1",
        }
    )
    assert isinstance(model, model_type)
    _assert_adapter_wire_round_trip(model, adapter)


@pytest.mark.parametrize(
    "header",
    [
        "Host",
        "hOsT",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Proxy-Authorization",
        "X Bad",
        "X-Test\n",
    ],
)
def test_signer_header_rejects_forbidden_or_invalid_names(header: str) -> None:
    with pytest.raises(ValidationError):
        GenericHmacSha256SignerConfig.model_validate(
            {
                "profile": "generic-hmac-sha256",
                "secret": {"generated": "hmac-256"},
                "header_name": header,
            }
        )


def test_command_observer_is_copy_safe_closed_and_round_trips() -> None:
    argv = ["python", "observer.py"]
    environment = ["TEST_DATABASE_URL"]
    model = CommandObserverConfig.model_validate(
        {
            "type": "command",
            "argv": argv,
            "timeout": "2s",
            "environment_allowlist": environment,
            "working_directory": ".",
        }
    )
    argv.append("changed")
    environment.append("CHANGED")
    assert model.argv == ("python", "observer.py")
    assert model.environment_allowlist == ("TEST_DATABASE_URL",)
    _assert_model_wire_round_trip(model, CommandObserverConfig)


def test_http_observer_and_observer_union_round_trip() -> None:
    adapter: TypeAdapter[ObserverConfig] = TypeAdapter(ObserverConfig)
    model = adapter.validate_python(
        {
            "type": "http",
            "base_url": "https://observer.test/api",
            "token": {"env": "OBSERVER_TOKEN"},
            "timeouts": _observer_timeouts(),
        }
    )
    assert isinstance(model, HttpObserverConfig)
    assert model.timeouts == ObserverHttpTimeouts.model_validate(_observer_timeouts())
    _assert_adapter_wire_round_trip(model, adapter)


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "command", "argv": [], "timeout": "1s"},
        {"type": "command", "argv": ["python"] * 65, "timeout": "1s"},
        {
            "type": "command",
            "argv": ["python"],
            "timeout": "1s",
            "environment_allowlist": ["PATH", "PATH"],
        },
        {
            "type": "http",
            "base_url": "file:///observer",
            "token": {"env": "OBSERVER_TOKEN"},
            "timeouts": {"connect": "1s", "read": "1s", "total": "1s"},
        },
        {"type": "custom"},
    ],
)
def test_observer_branches_reject_invalid_shapes(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(ObserverConfig).validate_python(payload)


def test_lifecycle_profile_defaults_and_round_trip() -> None:
    payload = {
        "stop_argv": ["python", "control.py", "stop"],
        "start_argv": ["python", "control.py", "start"],
        "restart_argv": ["python", "control.py", "restart"],
        "working_directory": ".",
        "environment_allowlist": ["PATH"],
        "timeout": "30s",
        "readiness_observer": "receiver_state",
    }
    model = LifecycleProfile.model_validate(payload)
    assert model.enabled is False
    _assert_model_wire_round_trip(model, LifecycleProfile)

    duplicate_environment = deepcopy(payload)
    duplicate_environment["environment_allowlist"] = ["PATH", "PATH"]
    with pytest.raises(ValidationError):
        LifecycleProfile.model_validate(duplicate_environment)


def test_real_and_scaled_clock_branches_are_closed_and_exact() -> None:
    real = RealClockConfig.model_validate({"mode": "real", "minimum_physical_wait": "1ms"})
    scaled = ScaledClockConfig.model_validate(
        {
            "mode": "scaled",
            "scale": "0.01",
            "minimum_physical_wait": "1ms",
        }
    )
    assert scaled.scale.fraction == Fraction(1, 100)
    _assert_model_wire_round_trip(real, RealClockConfig)
    _assert_model_wire_round_trip(scaled, ScaledClockConfig)

    with pytest.raises(ValidationError):
        RealClockConfig.model_validate({"mode": "real", "scale": "1"})
    with pytest.raises(ValidationError):
        ScaledClockConfig.model_validate({"mode": "scaled"})
    with pytest.raises(ValidationError):
        TypeAdapter(RealClockConfig | ScaledClockConfig).validate_python({"mode": "virtual"})


def test_limits_enforce_required_fields_hard_caps_and_concurrency_default() -> None:
    payload = {
        "max_events": 1000,
        "max_attempts": 5000,
        "max_request_bytes": 16_777_216,
        "max_response_capture_bytes": 1_048_576,
    }
    model = LimitsConfig.model_validate(payload)
    assert model.max_concurrency == 10
    _assert_model_wire_round_trip(model, LimitsConfig)

    for field in (
        "max_events",
        "max_attempts",
        "max_request_bytes",
        "max_response_capture_bytes",
    ):
        missing = deepcopy(payload)
        del missing[field]
        with pytest.raises(ValidationError):
            LimitsConfig.model_validate(missing)

    for field, value in (
        ("max_events", 1001),
        ("max_attempts", 5001),
        ("max_concurrency", 51),
        ("max_request_bytes", 16_777_217),
        ("max_response_capture_bytes", 1_048_577),
    ):
        invalid = deepcopy(payload)
        invalid[field] = value
        with pytest.raises(ValidationError):
            LimitsConfig.model_validate(invalid)


def test_reports_and_redaction_are_immutable_unique_and_round_trip() -> None:
    formats = ["json", "jsonl", "junit", "html"]
    headers = ["authorization", "x-test-signature"]
    pointers = ["/data/customer_email"]
    model = ReportsConfig.model_validate(
        {
            "formats": formats,
            "redaction": {
                "headers": headers,
                "json_pointers": pointers,
                "retain_raw_payloads": False,
            },
        }
    )
    formats.append("changed")
    headers.append("changed")
    pointers.append("/changed")

    assert model.formats == ("json", "jsonl", "junit", "html")
    assert model.redaction.retain_raw_payloads is False
    _assert_model_wire_round_trip(model, ReportsConfig)

    invalid_payloads: tuple[dict[str, object], ...] = (
        {
            "formats": [],
            "redaction": {
                "headers": [],
                "json_pointers": [],
                "retain_raw_payloads": False,
            },
        },
        {
            "formats": ["json", "json"],
            "redaction": {
                "headers": [],
                "json_pointers": [],
                "retain_raw_payloads": False,
            },
        },
        {
            "formats": ["sarif"],
            "redaction": {
                "headers": [],
                "json_pointers": [],
                "retain_raw_payloads": False,
            },
        },
        {
            "formats": ["json"],
            "redaction": {
                "headers": ["same", "same"],
                "json_pointers": [],
                "retain_raw_payloads": False,
            },
        },
    )
    for payload in invalid_payloads:
        with pytest.raises(ValidationError):
            ReportsConfig.model_validate(payload)


def test_redaction_requires_all_schema_required_fields() -> None:
    with pytest.raises(ValidationError):
        RedactionConfig.model_validate({"headers": [], "retain_raw_payloads": False})
    with pytest.raises(ValidationError):
        RedactionConfig.model_validate({"json_pointers": [], "retain_raw_payloads": False})
    with pytest.raises(ValidationError):
        RedactionConfig.model_validate({"headers": [], "json_pointers": []})


def test_report_format_accepts_exact_strings_but_rejects_bytes() -> None:
    with pytest.raises(ValidationError):
        ReportsConfig.model_validate(
            {
                "formats": [b"json"],
                "redaction": {
                    "headers": [],
                    "json_pointers": [],
                    "retain_raw_payloads": False,
                },
            }
        )


def test_schema_constants_match_version_metadata_and_schema_annotations() -> None:
    assert PROJECT_CONFIG_SCHEMA_MAJOR == 1
    assert PROJECT_CONFIG_SCHEMA_VERSION == VERSION_METADATA.configuration_schema == "1.0"
    assert frozenset({1}) == SUPPORTED_CONFIG_SCHEMA_VERSIONS
    assert MIN_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR == 1
    assert MAX_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR == 1
    assert MAX_CONFIG_BYTES == 16_777_216
    assert MAX_CONFIG_DEPTH == 64
    assert MAX_CONFIG_NODES == 100_000


@pytest.mark.parametrize(
    "document",
    [
        {},
        [],
        {"schema_version": "1"},
        {"schema_version": True},
        {"schema_version": False},
        {"schema_version": 0},
        {"schema_version": None},
    ],
)
def test_missing_or_invalid_schema_version_is_invalid_input(
    document: object,
) -> None:
    diagnostic = schema_version_diagnostic(document)
    assert diagnostic is not None
    assert diagnostic.category is ErrorCategory.CONFIGURATION_ERROR
    assert diagnostic.result_category is ResultCategory.INVALID_INPUT
    assert exit_for_result(diagnostic.result_category)[1] is ExitCode.INVALID_INPUT
    assert diagnostic.field_path == "schema_version"
    assert diagnostic.user_correctable is True
    assert "value" not in diagnostic.safe_details


@pytest.mark.parametrize("version", [-1, 2, 3, 999])
def test_other_integer_schema_versions_are_unsupported(version: int) -> None:
    diagnostic = schema_version_diagnostic({"schema_version": version})
    assert diagnostic is not None
    assert diagnostic.category is ErrorCategory.UNSUPPORTED_SCHEMA
    assert diagnostic.result_category is ResultCategory.UNSUPPORTED
    assert exit_for_result(diagnostic.result_category)[1] is ExitCode.UNSUPPORTED
    assert diagnostic.safe_details == {
        "supported_minimum": 1,
        "supported_maximum": 1,
        "configuration_schema": "1.0",
    }


def test_supported_schema_version_has_no_diagnostic() -> None:
    assert schema_version_diagnostic({"schema_version": 1}) is None


@pytest.mark.parametrize(
    ("document", "encoded_byte_length", "limit_name"),
    [
        ({"schema_version": 1}, MAX_CONFIG_BYTES + 1, "MAX_CONFIG_BYTES"),
        ([None] * MAX_CONFIG_NODES, None, "MAX_CONFIG_NODES"),
    ],
)
def test_resource_overflow_maps_to_bounded_invalid_input_diagnostic(
    document: object,
    encoded_byte_length: int | None,
    limit_name: str,
) -> None:
    diagnostic = resource_limit_diagnostic(
        document,
        encoded_byte_length=encoded_byte_length,
    )
    assert diagnostic is not None
    assert diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert diagnostic.result_category is ResultCategory.INVALID_INPUT
    assert exit_for_result(diagnostic.result_category)[1] is ExitCode.INVALID_INPUT
    assert diagnostic.safe_details == {
        "limit": limit_name,
        "maximum": MAX_CONFIG_BYTES if limit_name == "MAX_CONFIG_BYTES" else MAX_CONFIG_NODES,
    }
    serialized = diagnostic.model_dump_json()
    assert "schema_version" not in serialized
    assert len(serialized) < 1024


def test_resource_depth_boundaries_are_deterministic() -> None:
    at_limit: object = None
    for _ in range(MAX_CONFIG_DEPTH - 1):
        at_limit = [at_limit]
    assert resource_limit_diagnostic(at_limit) is None

    over_limit = [at_limit]
    diagnostic = resource_limit_diagnostic(over_limit)
    assert diagnostic is not None
    assert diagnostic.safe_details == {
        "limit": "MAX_CONFIG_DEPTH",
        "maximum": MAX_CONFIG_DEPTH,
    }


def test_preflight_checks_resources_before_version_and_performs_no_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_io(*_args: object, **_kwargs: object) -> None:
        msg = "preflight performed I/O"
        raise AssertionError(msg)

    monkeypatch.setattr(builtins, "open", fail_io)
    diagnostic = preflight_config(
        {"schema_version": 2},
        encoded_byte_length=MAX_CONFIG_BYTES + 1,
    )
    assert diagnostic is not None
    assert diagnostic.category is ErrorCategory.RESOURCE_LIMIT


@pytest.mark.parametrize("byte_length", [-1, True, 1.5, "1"])
def test_resource_preflight_rejects_invalid_caller_byte_counts(
    byte_length: object,
) -> None:
    with pytest.raises(ValueError, match="nonnegative integer"):
        resource_limit_diagnostic(
            {"schema_version": 1},
            encoded_byte_length=byte_length,  # type: ignore[arg-type]
        )
