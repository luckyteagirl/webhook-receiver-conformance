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

from webhook_receiver_conformance.config import models as config_models
from webhook_receiver_conformance.config.models import (
    MAX_DURATION_NANOSECONDS,
    MAX_SAFE_INTEGER,
    AddJsonFieldMutation,
    AlterAfterSigningMutation,
    BarrierStep,
    BaselineConfig,
    CanonicalJsonValue,
    ChangeEventIdFieldMutation,
    ChangeEventTypeFieldMutation,
    CommandObserverConfig,
    ConfigModel,
    ContentTypeMismatchMutation,
    DeliverStep,
    Duration,
    EnvironmentSecretRef,
    EventConfig,
    FaultClass,
    FileSecretRef,
    FixtureConfig,
    FrozenDict,
    GeneratedSecretRef,
    GenericHmacSha256SignerConfig,
    HttpObserverConfig,
    InvalidJsonMutation,
    LifecycleProfile,
    LimitsConfig,
    MalformedSignatureMutation,
    MissingSignatureMutation,
    MutationConfig,
    ObserverConfig,
    ObserverHttpTimeouts,
    ObserveStep,
    OversizedBodyMutation,
    PollDuration,
    PositiveDuration,
    ProjectSettings,
    RealClockConfig,
    ReceiverConfig,
    ReceiverTimeouts,
    RedactionConfig,
    RemoveJsonPointerMutation,
    ReplaceJsonTypeMutation,
    ReplaceJsonValueMutation,
    ReportsConfig,
    RestartStep,
    RetryConfig,
    Scale,
    ScaledClockConfig,
    SecretRef,
    SignerConfig,
    StaleSignatureTimestampMutation,
    StandardWebhooksHmacSignerConfig,
    StepConfig,
    StripeV1SignerConfig,
    TruncateBytesMutation,
    WaitStep,
    WrongSigningKeyMutation,
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
    from_iterator = FrozenDict(iter([("alpha", 1), ("beta", 2)]))

    assert first == second == from_iterator
    assert hash(first) == hash(second) == hash(from_iterator)
    assert len({first, second, from_iterator}) == 1


@pytest.mark.parametrize("duplicate_value", [1, 2])
def test_frozen_mapping_rejects_duplicate_key_iterables_deterministically(
    duplicate_value: int,
) -> None:
    with pytest.raises(
        ValueError,
        match=r"FrozenDict keys must be unique; duplicate key: 'alpha'",
    ):
        FrozenDict(
            iter(
                [
                    ("alpha", 1),
                    ("beta", 2),
                    ("alpha", duplicate_value),
                ]
            )
        )


def test_external_collections_require_json_list_and_dict_shapes() -> None:
    for roots in ((), (".secrets",)):
        with pytest.raises(ValidationError, match="provided as lists"):
            ProjectSettings.model_validate(
                {
                    "name": "project",
                    "artifact_directory": ".artifacts",
                    "secret_roots": roots,
                }
            )
    with pytest.raises(ValidationError, match="provided as dictionaries"):
        _ProbeModel.model_validate(UserDict({"value": 1}))
    for array in ((), (1,)):
        with pytest.raises(TypeError, match="provided as lists"):
            CanonicalJsonValue(array)
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
    empty_source: list[object] = []
    nested_empty: list[object] = []
    nested_values: list[object] = [2]
    nested_mapping: dict[str, object] = {"nested": nested_values}
    complex_source: list[object] = [1, nested_empty, nested_mapping]
    internal_sources: tuple[object, ...] = (empty_source, complex_source)
    for source in internal_sources:
        validated = CanonicalJsonValue(source)
        assert CanonicalJsonValue(validated.value) == validated
    existing = CanonicalJsonValue([1])
    assert TypeAdapter(CanonicalJsonValue).validate_python(existing) is existing


@pytest.mark.parametrize(
    "value",
    [
        {"nested": ()},
        {"nested": (1,)},
        [()],
        [(1,)],
        FrozenDict({"nested": ()}),
        FrozenDict({"nested": (1,)}),
    ],
)
def test_canonical_json_rejects_nested_external_tuples(value: object) -> None:
    with pytest.raises(TypeError, match="provided as lists"):
        CanonicalJsonValue(value)


@pytest.mark.parametrize("value", [(), (1,), {"nested": ()}, [{"nested": (1,)}]])
def test_mutation_canonical_json_boundary_rejects_external_tuples(
    value: object,
) -> None:
    with pytest.raises(ValidationError, match="provided as lists"):
        ReplaceJsonValueMutation.model_validate(
            {
                "type": "replace-json-value-v1",
                "pointer": "/data",
                "value": value,
            }
        )


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (
            ReceiverConfig,
            {
                "url": "http://127.0.0.1:8000/webhooks",
                "target_profile": "loopback",
                "allowed_hosts": (),
                "timeouts": {
                    "connect": "1s",
                    "write": "1s",
                    "read": "1s",
                    "pool": "1s",
                    "total": "1s",
                },
            },
        ),
        (
            ReceiverConfig,
            {
                "url": "http://127.0.0.1:8000/webhooks",
                "target_profile": "loopback",
                "allowed_ports": (8000,),
                "timeouts": {
                    "connect": "1s",
                    "write": "1s",
                    "read": "1s",
                    "pool": "1s",
                    "total": "1s",
                },
            },
        ),
        (
            CommandObserverConfig,
            {"type": "command", "argv": (), "timeout": "1s"},
        ),
        (
            CommandObserverConfig,
            {
                "type": "command",
                "argv": ["observer"],
                "timeout": "1s",
                "environment_allowlist": ("PATH",),
            },
        ),
        (
            LifecycleProfile,
            {
                "stop_argv": (),
                "start_argv": ["control", "start"],
                "restart_argv": ["control", "restart"],
                "working_directory": ".",
                "environment_allowlist": ["PATH"],
                "timeout": "1s",
                "readiness_observer": "receiver_state",
            },
        ),
        (
            RedactionConfig,
            {
                "headers": (),
                "json_pointers": [],
                "retain_raw_payloads": False,
            },
        ),
        (
            ReportsConfig,
            {
                "formats": ("json",),
                "redaction": {
                    "headers": [],
                    "json_pointers": [],
                    "retain_raw_payloads": False,
                },
            },
        ),
        (
            RetryConfig,
            {"max_attempts": 1, "backoff": (), "retry_on": []},
        ),
        (
            RetryConfig,
            {"max_attempts": 1, "backoff": [], "retry_on": ()},
        ),
        (
            RetryConfig,
            {
                "max_attempts": 2,
                "backoff": ["1s"],
                "retry_on": ["retryable_status"],
                "retryable_statuses": (500,),
            },
        ),
        (
            DeliverStep,
            {"deliver": {"event": "payment", "mutations": ()}},
        ),
        (
            EventConfig,
            {"id": "payment", "fixture": "payment_created", "depends_on": ()},
        ),
    ],
    ids=[
        "receiver-empty-hosts",
        "receiver-ports",
        "command-empty-argv",
        "command-environment",
        "lifecycle-empty-stop",
        "redaction-empty-headers",
        "report-formats",
        "retry-empty-backoff",
        "retry-empty-predicates",
        "retry-statuses",
        "deliver-empty-mutations",
        "event-empty-dependencies",
    ],
)
def test_all_configuration_sequence_boundaries_reject_external_tuples(
    model_type: type[ConfigModel],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="provided as lists"):
        model_type.model_validate(payload)


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


@pytest.mark.parametrize("name", ["xPATH", "PATHx", "xPATHy", " PATH"])
def test_environment_secret_names_require_a_whole_schema_match(name: str) -> None:
    with pytest.raises(ValidationError):
        EnvironmentSecretRef.model_validate({"env": name})


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


@pytest.mark.parametrize("name", ["xPATH", "PATHx", "xPATHy", " PATH"])
def test_command_observer_environment_names_require_a_whole_schema_match(
    name: str,
) -> None:
    with pytest.raises(ValidationError):
        CommandObserverConfig.model_validate(
            {
                "type": "command",
                "argv": ["observer"],
                "timeout": "1s",
                "environment_allowlist": [name],
            }
        )


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


@pytest.mark.parametrize("name", ["xPATH", "PATHx", "xPATHy", " PATH"])
def test_http_observer_token_environment_name_requires_a_whole_schema_match(
    name: str,
) -> None:
    with pytest.raises(ValidationError):
        HttpObserverConfig.model_validate(
            {
                "type": "http",
                "base_url": "https://observer.test/api",
                "token": {"env": name},
                "timeouts": _observer_timeouts(),
            }
        )


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


MUTATION_CASES: tuple[
    tuple[dict[str, object], type[ConfigModel], tuple[str, ...]],
    ...,
] = (
    (
        {"type": "remove-json-pointer-v1", "pointer": "/data/obsolete"},
        RemoveJsonPointerMutation,
        ("type", "pointer"),
    ),
    (
        {
            "type": "replace-json-value-v1",
            "pointer": "/data/value",
            "value": {"nested": [None, True, MAX_SAFE_INTEGER]},
        },
        ReplaceJsonValueMutation,
        ("type", "pointer", "value"),
    ),
    (
        {
            "type": "replace-json-type-v1",
            "pointer": "/data/value",
            "target_type": "string",
        },
        ReplaceJsonTypeMutation,
        ("type", "pointer", "target_type"),
    ),
    (
        {
            "type": "add-json-field-v1",
            "pointer": "/data",
            "name": "new_field",
            "value": {"enabled": True},
        },
        AddJsonFieldMutation,
        ("type", "pointer", "name", "value"),
    ),
    (
        {"type": "change-event-id-field-v1", "value": "evt_changed"},
        ChangeEventIdFieldMutation,
        ("type", "value"),
    ),
    (
        {"type": "change-event-type-field-v1", "value": "payment.changed"},
        ChangeEventTypeFieldMutation,
        ("type", "value"),
    ),
    (
        {"type": "truncate-bytes-v1", "length": 0},
        TruncateBytesMutation,
        ("type", "length"),
    ),
    (
        {"type": "invalid-json-v1", "strategy": "truncated-object"},
        InvalidJsonMutation,
        ("type", "strategy"),
    ),
    (
        {"type": "content-type-mismatch-v1", "media_type": "text/plain"},
        ContentTypeMismatchMutation,
        ("type", "media_type"),
    ),
    (
        {"type": "alter-after-signing-v1", "offset": 0, "xor": 1},
        AlterAfterSigningMutation,
        ("type", "offset", "xor"),
    ),
    (
        {"type": "stale-signature-timestamp-v1", "age": "6m"},
        StaleSignatureTimestampMutation,
        ("type", "age"),
    ),
    (
        {"type": "wrong-signing-key-v1", "context": "negative-test"},
        WrongSigningKeyMutation,
        ("type", "context"),
    ),
    (
        {"type": "missing-signature-v1"},
        MissingSignatureMutation,
        ("type",),
    ),
    (
        {"type": "malformed-signature-v1", "case": "invalid-encoding"},
        MalformedSignatureMutation,
        ("type", "case"),
    ),
    (
        {
            "type": "oversized-body-v1",
            "target_bytes": 1_048_577,
            "fill": "ascii-space",
        },
        OversizedBodyMutation,
        ("type", "target_bytes", "fill"),
    ),
)

STRUCTURAL_MUTATION_TYPES = frozenset(
    {
        "remove-json-pointer-v1",
        "replace-json-value-v1",
        "replace-json-type-v1",
        "add-json-field-v1",
        "change-event-id-field-v1",
        "change-event-type-field-v1",
    }
)

FAULT_CLASS_VALUES = frozenset(
    {
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
        "delivery:duplicate",
        "delivery:concurrent",
        "delivery:dependency-order-reversal",
        "retry:timed_out",
        "retry:connection_failed",
        "retry:retryable_status",
        "lifecycle:restart",
    }
)


@pytest.mark.parametrize(
    ("payload", "expected_type", "_required_fields"),
    MUTATION_CASES,
    ids=[str(case[0]["type"]) for case in MUTATION_CASES],
)
def test_every_mutation_branch_is_strictly_tagged_and_round_trips(
    payload: dict[str, object],
    expected_type: type[ConfigModel],
    _required_fields: tuple[str, ...],
) -> None:
    adapter: TypeAdapter[MutationConfig] = TypeAdapter(MutationConfig)
    model = adapter.validate_python(deepcopy(payload))
    assert type(model) is expected_type
    _assert_adapter_wire_round_trip(model, adapter)


@pytest.mark.parametrize(
    ("payload", "_expected_type", "required_fields"),
    MUTATION_CASES,
    ids=[str(case[0]["type"]) for case in MUTATION_CASES],
)
def test_every_mutation_branch_rejects_missing_required_and_extra_fields(
    payload: dict[str, object],
    _expected_type: type[ConfigModel],
    required_fields: tuple[str, ...],
) -> None:
    adapter: TypeAdapter[MutationConfig] = TypeAdapter(MutationConfig)
    for field in required_fields:
        missing = deepcopy(payload)
        del missing[field]
        with pytest.raises(ValidationError):
            adapter.validate_python(missing)

    extra = deepcopy(payload)
    extra["selector"] = "not-a-mutation-field"
    with pytest.raises(ValidationError):
        adapter.validate_python(extra)


@pytest.mark.parametrize(
    "tag",
    [
        "remove-json-pointer",
        "invalid-utf8-v1",
        "duplicate-json-key-v1",
        "custom-v1",
        b"missing-signature-v1",
        None,
    ],
)
def test_mutation_union_rejects_unknown_deferred_and_non_string_tags(tag: object) -> None:
    adapter: TypeAdapter[MutationConfig] = TypeAdapter(MutationConfig)
    with pytest.raises(ValidationError):
        adapter.validate_python({"type": tag})


@pytest.mark.parametrize(
    ("payload", "_expected_type", "_required_fields"),
    MUTATION_CASES,
    ids=[str(case[0]["type"]) for case in MUTATION_CASES],
)
def test_accept_prior_mutation_is_only_available_for_structural_mutations(
    payload: dict[str, object],
    _expected_type: type[ConfigModel],
    _required_fields: tuple[str, ...],
) -> None:
    adapter: TypeAdapter[MutationConfig] = TypeAdapter(MutationConfig)
    candidate = deepcopy(payload)
    candidate["accept_prior_mutation"] = True
    if payload["type"] in STRUCTURAL_MUTATION_TYPES:
        model = adapter.validate_python(candidate)
        assert model.to_wire()["accept_prior_mutation"] is True
    else:
        with pytest.raises(ValidationError):
            adapter.validate_python(candidate)


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "replace-json-value-v1", "pointer": "/data/value", "value": None},
        {"type": "add-json-field-v1", "pointer": "/data", "name": "value", "value": None},
    ],
)
def test_mutation_value_fields_preserve_explicit_canonical_json_null(
    payload: dict[str, object],
) -> None:
    adapter: TypeAdapter[MutationConfig] = TypeAdapter(MutationConfig)
    model = adapter.validate_python(payload)
    assert model.to_wire()["value"] is None


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "remove-json-pointer-v1", "pointer": None},
        {"type": "replace-json-type-v1", "pointer": "/data", "target_type": None},
        {"type": "truncate-bytes-v1", "length": None},
        {"type": "invalid-json-v1", "strategy": None},
        {"type": "missing-signature-v1", "accept_prior_mutation": None},
    ],
)
def test_non_value_mutation_fields_reject_explicit_null(payload: dict[str, object]) -> None:
    adapter: TypeAdapter[MutationConfig] = TypeAdapter(MutationConfig)
    with pytest.raises(ValidationError):
        adapter.validate_python(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "remove-json-pointer-v1", "pointer": "not/a/pointer"},
        {
            "type": "replace-json-type-v1",
            "pointer": "/data",
            "target_type": "number",
        },
        {"type": "invalid-json-v1", "strategy": "invalid-utf8"},
        {"type": "alter-after-signing-v1", "offset": -1, "xor": 1},
        {"type": "alter-after-signing-v1", "offset": 16_777_216, "xor": 1},
        {"type": "alter-after-signing-v1", "offset": 0, "xor": 0},
        {"type": "alter-after-signing-v1", "offset": 0, "xor": 256},
        {"type": "truncate-bytes-v1", "length": -1},
        {"type": "truncate-bytes-v1", "length": 16_777_217},
        {"type": "truncate-bytes-v1", "length": True},
        {"type": "truncate-bytes-v1", "length": 1.0},
        {"type": "malformed-signature-v1", "case": "bad"},
        {"type": "oversized-body-v1", "target_bytes": 0, "fill": "ascii-space"},
        {"type": "oversized-body-v1", "target_bytes": 16_777_217, "fill": "ascii-space"},
        {"type": "oversized-body-v1", "target_bytes": 1, "fill": "zero"},
        {"type": "stale-signature-timestamp-v1", "age": "0s"},
        {"type": "wrong-signing-key-v1", "context": ""},
    ],
)
def test_mutation_branch_catalogs_bounds_and_scalar_types_are_exact(
    payload: dict[str, object],
) -> None:
    adapter: TypeAdapter[MutationConfig] = TypeAdapter(MutationConfig)
    with pytest.raises(ValidationError):
        adapter.validate_python(payload)


@pytest.mark.parametrize(
    ("model_type", "field", "values", "base_payload"),
    [
        (
            RemoveJsonPointerMutation,
            "if_missing",
            ("error", "ignore"),
            {"type": "remove-json-pointer-v1", "pointer": "/data"},
        ),
        (
            ReplaceJsonTypeMutation,
            "target_type",
            ("null", "boolean", "integer", "string", "array", "object"),
            {"type": "replace-json-type-v1", "pointer": "/data"},
        ),
        (
            InvalidJsonMutation,
            "strategy",
            ("truncated-object", "bad-escape", "trailing-comma"),
            {"type": "invalid-json-v1"},
        ),
        (
            MalformedSignatureMutation,
            "case",
            (
                "invalid-encoding",
                "missing-component",
                "invalid-delimiter",
                "duplicate-component",
            ),
            {"type": "malformed-signature-v1"},
        ),
    ],
)
def test_mutation_closed_subcatalogs_accept_every_exact_value(
    model_type: type[ConfigModel],
    field: str,
    values: tuple[str, ...],
    base_payload: dict[str, object],
) -> None:
    for value in values:
        payload = {**base_payload, field: value}
        model = model_type.model_validate(payload)
        assert model.to_wire()[field] == value


@pytest.mark.parametrize("length", [0, 16_777_216])
def test_truncate_byte_boundaries_are_accepted(length: int) -> None:
    model = TruncateBytesMutation.model_validate({"type": "truncate-bytes-v1", "length": length})
    assert model.length == length


@pytest.mark.parametrize("target_bytes", [1, 16_777_216])
def test_oversized_body_boundaries_are_accepted(target_bytes: int) -> None:
    model = OversizedBodyMutation.model_validate(
        {
            "type": "oversized-body-v1",
            "target_bytes": target_bytes,
            "fill": "ascii-space",
        }
    )
    assert model.target_bytes == target_bytes


def test_mutation_canonical_json_is_deeply_immutable_copy_safe_and_integer_only() -> None:
    source: dict[str, object] = {"items": [1, {"allowed": True}]}
    model = ReplaceJsonValueMutation.model_validate(
        {"type": "replace-json-value-v1", "pointer": "/data", "value": source}
    )
    source["items"] = ["changed"]
    source["later"] = False
    assert model.to_wire()["value"] == {"items": [1, {"allowed": True}]}

    for invalid_value in (1.5, b"bytes", MAX_SAFE_INTEGER + 1):
        with pytest.raises(ValidationError):
            ReplaceJsonValueMutation.model_validate(
                {
                    "type": "replace-json-value-v1",
                    "pointer": "/data",
                    "value": invalid_value,
                }
            )


def test_retry_policy_valid_forms_are_frozen_copy_safe_and_round_trip() -> None:
    one_attempt = RetryConfig.model_validate({"max_attempts": 1, "backoff": [], "retry_on": []})
    assert one_attempt.jitter == Duration("0ns")
    _assert_model_wire_round_trip(one_attempt, RetryConfig)

    backoff = ["100ms", "1s"]
    retry_on = ["timed_out", "retryable_status"]
    selectors: list[object] = [408, 429, "5xx"]
    model = RetryConfig.model_validate(
        {
            "max_attempts": 3,
            "backoff": backoff,
            "retry_on": retry_on,
            "retryable_statuses": selectors,
            "jitter": "10ms",
        }
    )
    backoff.append("2s")
    retry_on.clear()
    selectors.append(503)
    assert model.backoff == (Duration("100ms"), Duration("1s"))
    assert tuple(str(item) for item in model.retry_on) == (
        "timed_out",
        "retryable_status",
    )
    assert len(model.retryable_statuses or ()) == 3
    _assert_model_wire_round_trip(model, RetryConfig)


@pytest.mark.parametrize(
    "payload",
    [
        {"max_attempts": 0, "backoff": [], "retry_on": []},
        {"max_attempts": 33, "backoff": [], "retry_on": []},
        {"max_attempts": True, "backoff": [], "retry_on": []},
        {"max_attempts": 2, "backoff": [], "retry_on": ["timed_out"]},
        {
            "max_attempts": 2,
            "backoff": ["1s", "2s"],
            "retry_on": ["timed_out"],
        },
        {"max_attempts": 1, "backoff": [], "retry_on": ["timed_out"]},
        {"max_attempts": 2, "backoff": ["1s"], "retry_on": []},
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["timed_out", "timed_out"],
        },
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["retryable_status"],
        },
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["timed_out"],
            "retryable_statuses": [500],
        },
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["retryable_status"],
            "retryable_statuses": [],
        },
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["retryable_status"],
            "retryable_statuses": [500, 500],
        },
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["retryable_status"],
            "retryable_statuses": [99],
        },
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["retryable_status"],
            "retryable_statuses": [600],
        },
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["retryable_status"],
            "retryable_statuses": ["1xx"],
        },
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["retryable_status"],
            "retryable_statuses": [True],
        },
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["retryable_status"],
            "retryable_statuses": [b"5xx"],
        },
        {"max_attempts": 2, "backoff": ("1s",), "retry_on": ["timed_out"]},
        {"max_attempts": 2, "backoff": ["1s"], "retry_on": ("timed_out",)},
    ],
)
def test_retry_policy_rejects_invalid_cardinality_dependencies_and_types(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        RetryConfig.model_validate(payload)


@pytest.mark.parametrize("missing", ["max_attempts", "backoff", "retry_on"])
def test_retry_policy_requires_all_core_fields(missing: str) -> None:
    payload: dict[str, object] = {
        "max_attempts": 1,
        "backoff": [],
        "retry_on": [],
    }
    del payload[missing]
    with pytest.raises(ValidationError):
        RetryConfig.model_validate(payload)


@pytest.mark.parametrize("selector", [100, 599, "2xx", "3xx", "4xx", "5xx"])
def test_retry_status_selector_boundaries_and_classes_are_accepted(
    selector: int | str,
) -> None:
    model = RetryConfig.model_validate(
        {
            "max_attempts": 2,
            "backoff": ["1s"],
            "retry_on": ["retryable_status"],
            "retryable_statuses": [selector],
        }
    )
    assert len(model.retryable_statuses or ()) == 1


@pytest.mark.parametrize("fault_class", sorted(FAULT_CLASS_VALUES))
def test_every_fault_class_is_exact_and_round_trips(fault_class: str) -> None:
    model = BaselineConfig.model_validate({"fault_class": fault_class, "scenario": "one_fault"})
    assert isinstance(model.fault_class, FaultClass)
    assert model.fault_class.value == fault_class
    _assert_model_wire_round_trip(model, BaselineConfig)


@pytest.mark.parametrize(
    "fault_class",
    ["mutation:remove-json-pointer", "retry:timeout", "custom", b"delivery:duplicate", None],
)
def test_baseline_rejects_unknown_or_non_string_fault_classes(
    fault_class: object,
) -> None:
    with pytest.raises(ValidationError):
        BaselineConfig.model_validate({"fault_class": fault_class, "scenario": "one_fault"})


def test_baseline_is_closed_and_requires_both_fields() -> None:
    for payload in (
        {"fault_class": "delivery:duplicate"},
        {"scenario": "one_fault"},
        {
            "fault_class": "delivery:duplicate",
            "scenario": "one_fault",
            "extra": True,
        },
    ):
        with pytest.raises(ValidationError):
            BaselineConfig.model_validate(payload)


STEP_CASES: tuple[tuple[dict[str, object], type[ConfigModel]], ...] = (
    (
        {
            "deliver": {
                "event": "payment",
                "mutations": [
                    {"type": "missing-signature-v1"},
                    {
                        "type": "replace-json-value-v1",
                        "pointer": "/data/status",
                        "value": "changed",
                    },
                ],
                "timeout": "5s",
                "retry": {
                    "max_attempts": 2,
                    "backoff": ["100ms"],
                    "retry_on": ["connection_failed"],
                },
            }
        },
        DeliverStep,
    ),
    ({"wait": "1s"}, WaitStep),
    ({"barrier": "release"}, BarrierStep),
    (
        {"observe": {"observer": "receiver_state", "checkpoint": "after"}},
        ObserveStep,
    ),
    ({"restart": "receiver_process"}, RestartStep),
)


@pytest.mark.parametrize(
    ("payload", "expected_type"),
    STEP_CASES,
    ids=["deliver", "wait", "barrier", "observe", "restart"],
)
def test_all_five_step_families_are_closed_immutable_and_round_trip(
    payload: dict[str, object],
    expected_type: type[ConfigModel],
) -> None:
    adapter: TypeAdapter[StepConfig] = TypeAdapter(StepConfig)
    model = adapter.validate_python(deepcopy(payload))
    assert type(model) is expected_type
    _assert_adapter_wire_round_trip(model, adapter)
    with pytest.raises(ValidationError):
        adapter.validate_python({**deepcopy(payload), "extra": True})


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"custom": {}},
        {"deliver": {"event": "payment"}, "wait": "1s"},
        {"deliver": {}},
        {"wait": None},
        {"wait": "1.0s"},
        {"barrier": ""},
        {"barrier": b"release"},
        {"observe": {"observer": "receiver_state"}},
        {"observe": {"checkpoint": "after"}},
        {
            "observe": {
                "observer": "receiver_state",
                "checkpoint": "after",
                "extra": True,
            }
        },
        {"restart": "Receiver"},
    ],
)
def test_step_union_rejects_ambiguous_malformed_and_coerced_forms(
    payload: dict[str, object],
) -> None:
    adapter: TypeAdapter[StepConfig] = TypeAdapter(StepConfig)
    with pytest.raises(ValidationError):
        adapter.validate_python(payload)


@pytest.mark.parametrize("count", [1, 128])
def test_deliver_count_boundaries_are_accepted(count: int) -> None:
    model = DeliverStep.model_validate({"deliver": {"event": "payment", "count": count}})
    assert model.deliver.count == count


@pytest.mark.parametrize("count", [0, 129, True, 1.0, "1"])
def test_deliver_count_out_of_range_and_coerced_forms_are_rejected(
    count: object,
) -> None:
    with pytest.raises(ValidationError):
        DeliverStep.model_validate({"deliver": {"event": "payment", "count": count}})


def test_deliver_mutations_are_bounded_frozen_and_copy_safe() -> None:
    mutations: list[dict[str, object]] = [{"type": "missing-signature-v1"}]
    model = DeliverStep.model_validate({"deliver": {"event": "payment", "mutations": mutations}})
    mutations.append({"type": "missing-signature-v1"})
    assert len(model.deliver.mutations or ()) == 1
    assert model.deliver.count == 1

    with pytest.raises(ValidationError):
        DeliverStep.model_validate(
            {
                "deliver": {
                    "event": "payment",
                    "mutations": [{"type": "missing-signature-v1"}] * 17,
                }
            }
        )
    with pytest.raises(ValidationError):
        DeliverStep.model_validate(
            {
                "deliver": {
                    "event": "payment",
                    "mutations": ({"type": "missing-signature-v1"},),
                }
            }
        )


def test_event_config_is_closed_frozen_unique_and_round_trips() -> None:
    dependencies = ["created", "authorized"]
    model = EventConfig.model_validate(
        {"id": "captured", "fixture": "payment", "depends_on": dependencies}
    )
    dependencies.append("changed")
    assert model.depends_on == ("created", "authorized")
    _assert_model_wire_round_trip(model, EventConfig)

    for payload in (
        {"id": "captured"},
        {"fixture": "payment"},
        {"id": "Captured", "fixture": "payment"},
        {
            "id": "captured",
            "fixture": "payment",
            "depends_on": ["created", "created"],
        },
        {"id": "captured", "fixture": "payment", "depends_on": ("created",)},
        {"id": "captured", "fixture": "payment", "extra": True},
    ):
        with pytest.raises(ValidationError):
            EventConfig.model_validate(payload)


def _minimal_scenario_payload() -> dict[str, object]:
    return {
        "id": "happy_path",
        "events": [{"id": "payment", "fixture": "payment_created"}],
        "steps": [{"deliver": {"event": "payment"}}],
    }


def test_stage_b1_scenario_support_is_private_bounded_and_round_trips() -> None:
    scenario_type = config_models._ScenarioConfigBase  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    payload = _minimal_scenario_payload()
    model = scenario_type.model_validate(payload)
    assert model.failure_policy.value == "continue-scenario"
    assert model.baselines == ()
    _assert_model_wire_round_trip(model, scenario_type)
    assert not hasattr(config_models, "ScenarioConfig")

    for policy in ("continue-scenario", "stop-scenario", "stop-run"):
        candidate = _minimal_scenario_payload()
        candidate["failure_policy"] = policy
        assert scenario_type.model_validate(candidate).failure_policy.value == policy


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("events", ()),
        ("events", ({"id": "payment", "fixture": "payment_created"},)),
        ("steps", ()),
        ("steps", ({"wait": "1s"},)),
        ("baselines", ()),
        (
            "baselines",
            ({"fault_class": "delivery:duplicate", "scenario": "duplicate_once"},),
        ),
    ],
)
def test_stage_b1_scenario_sequence_boundaries_reject_all_external_tuples(
    field: str,
    value: tuple[object, ...],
) -> None:
    scenario_type = config_models._ScenarioConfigBase  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    payload = _minimal_scenario_payload()
    payload[field] = value
    with pytest.raises(ValidationError, match="provided as lists"):
        scenario_type.model_validate(payload)


def test_stage_b1_scenario_bounds_uniqueness_and_exact_types() -> None:
    scenario_type = config_models._ScenarioConfigBase  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    duplicate_baseline = _minimal_scenario_payload()
    duplicate_baseline["baselines"] = [
        {"fault_class": "delivery:duplicate", "scenario": "duplicate_once"},
        {"fault_class": "delivery:duplicate", "scenario": "duplicate_twice"},
    ]

    invalid_payloads = (
        {"id": "empty_events", "events": [], "steps": [{"wait": "1s"}]},
        {
            "id": "empty_steps",
            "events": [{"id": "payment", "fixture": "payment_created"}],
            "steps": [],
        },
        duplicate_baseline,
        {
            "id": "bad_policy",
            "events": [{"id": "payment", "fixture": "payment_created"}],
            "steps": [{"wait": "1s"}],
            "failure_policy": "continue",
        },
        {
            "id": "bad_policy",
            "events": [{"id": "payment", "fixture": "payment_created"}],
            "steps": [{"wait": "1s"}],
            "failure_policy": b"continue-scenario",
        },
        {
            "id": "tuple_events",
            "events": ({"id": "payment", "fixture": "payment_created"},),
            "steps": [{"wait": "1s"}],
        },
        {
            "id": "tuple_steps",
            "events": [{"id": "payment", "fixture": "payment_created"}],
            "steps": ({"wait": "1s"},),
        },
    )
    for payload in invalid_payloads:
        with pytest.raises(ValidationError):
            scenario_type.model_validate(payload)


def test_stage_b1_scenario_maximum_collection_bounds() -> None:
    scenario_type = config_models._ScenarioConfigBase  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    payload = _minimal_scenario_payload()
    payload["events"] = [
        {"id": f"event_{index}", "fixture": "payment_created"} for index in range(1001)
    ]
    with pytest.raises(ValidationError):
        scenario_type.model_validate(payload)

    payload = _minimal_scenario_payload()
    payload["steps"] = [{"wait": "1ns"}] * 10_001
    with pytest.raises(ValidationError):
        scenario_type.model_validate(payload)

    payload = _minimal_scenario_payload()
    payload["baselines"] = [
        {
            "fault_class": fault_class,
            "scenario": "one_fault",
        }
        for fault_class in sorted(FAULT_CLASS_VALUES)
    ] * 3
    with pytest.raises(ValidationError):
        scenario_type.model_validate(payload)


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
