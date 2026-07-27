"""Contract tests for stable diagnostic and version primitives."""
# ruff: noqa: INP001

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest
from pydantic import ValidationError

from webhook_receiver_conformance.errors import (
    DEBUG_ENVIRONMENT_VARIABLE,
    INTERNAL_ERROR_CODE,
    RESULT_TO_EXIT,
    CliExitCategory,
    DebugPolicy,
    Diagnostic,
    DiagnosticLocation,
    ErrorCategory,
    ExitCode,
    ResultCategory,
    exit_for_result,
    format_unexpected_exception,
    new_incident_id,
    normalize_unexpected_exception,
)
from webhook_receiver_conformance.types import DiagnosticCode, EntityId, IncidentId
from webhook_receiver_conformance.version import VERSION_METADATA, VersionMetadata

MAX_SAFE_DIAGNOSTIC_BYTES = 1024

RESULT_VALUES = {
    "pass",
    "receiver_failure",
    "environment_error",
    "harness_error",
    "ambiguous",
    "invalid_input",
    "unsupported",
    "cancelled",
}

ERROR_VALUES = {
    "configuration_error",
    "unsupported_schema",
    "secret_reference_error",
    "resource_limit",
    "planning_error",
    "fixture_error",
    "unsupported_capability",
    "journal_busy",
    "illegal_transition",
    "integrity_error",
    "migration_error",
    "schedule_error",
    "deadlock",
    "cancelled",
    "connect_timeout",
    "read_timeout",
    "write_timeout",
    "pool_timeout",
    "tls_error",
    "connection_error",
    "protocol_error",
    "response_too_large",
    "key_unavailable",
    "unsupported_algorithm",
    "signing_error",
    "mutation_not_applicable",
    "conflicting_mutation",
    "invalid_parameter",
    "observer_timeout",
    "observer_protocol_error",
    "observer_process_error",
    "observer_http_error",
    "observer_auth_error",
    "assertion_error",
    "evidence_missing",
    "unsupported_assertion",
    "report_error",
    "artifact_integrity_error",
    "output_limit",
    "lifecycle_disabled",
    "process_error",
    "readiness_timeout",
    "schema_validation_error",
    "internal_error",
}


def test_authoritative_enum_values_are_exhaustive() -> None:
    assert {item.value for item in ResultCategory} == RESULT_VALUES
    assert {item.value for item in ErrorCategory} == ERROR_VALUES


def test_result_to_exit_mapping_is_total_and_preserves_distinct_names() -> None:
    assert set(RESULT_TO_EXIT) == set(ResultCategory)
    assert exit_for_result(ResultCategory.ENVIRONMENT_ERROR) == (
        CliExitCategory.ENVIRONMENT_FAILURE,
        ExitCode.ENVIRONMENT_FAILURE,
    )
    assert exit_for_result(ResultCategory.HARNESS_ERROR) == (
        CliExitCategory.HARNESS_FAILURE,
        ExitCode.HARNESS_FAILURE,
    )


def test_configuration_resource_limit_is_invalid_input_with_safe_remediation() -> None:
    diagnostic = Diagnostic(
        category=ErrorCategory.RESOURCE_LIMIT,
        code=DiagnosticCode("CFG_RESOURCE_LIMIT"),
        message="Configuration exceeds a bounded input limit.",
        retryable=False,
        safe_details={
            "input_class": "configuration",
            "limit_name": "document_bytes",
            "limit": 16_777_216,
            "observed": "over_limit",
        },
        result_category=ResultCategory.INVALID_INPUT,
        user_correctable=True,
        field_path="$",
        corrective_action="Reduce the configuration document below the supported limit.",
    )

    assert exit_for_result(diagnostic.result_category) == (
        CliExitCategory.INVALID_INPUT,
        ExitCode.INVALID_INPUT,
    )
    assert diagnostic.retryable is False
    assert diagnostic.user_correctable is True
    assert diagnostic.field_path == "$"
    assert diagnostic.corrective_action is not None
    assert diagnostic.incident_id is None
    encoded = diagnostic.model_dump_json()
    assert len(encoded.encode()) < MAX_SAFE_DIAGNOSTIC_BYTES
    assert "secret-canary" not in encoded


def test_diagnostic_serialization_round_trip_is_strict_and_immutable() -> None:
    diagnostic = Diagnostic(
        category=ErrorCategory.CONFIGURATION_ERROR,
        code=DiagnosticCode("CFG_UNKNOWN_FIELD"),
        message="Unknown field.",
        location=DiagnosticLocation(path="project.yaml", line=42, column=9),
        retryable=False,
        safe_details={"rule": "unknown-field", "count": 1},
        result_category=ResultCategory.INVALID_INPUT,
        user_correctable=True,
        field_path="scenarios[0].deliver.retryy",
        corrective_action="Remove the unknown field.",
    )
    encoded = diagnostic.model_dump_json()
    assert Diagnostic.model_validate_json(encoded) == diagnostic
    with pytest.raises(ValidationError):
        Diagnostic.model_validate({**diagnostic.model_dump(), "unknown": True})
    with pytest.raises(ValidationError):
        diagnostic.message = "changed"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("message", " "),
        ("message", "unsafe\x1b[31m"),
        ("field_path", ""),
        ("field_path", "receiver.url\nnext"),
        ("entity_id", "attempt id"),
        ("incident_id", "incident=id"),
    ],
)
def test_diagnostic_rejects_empty_or_terminal_unsafe_text(
    field: str,
    value: str,
) -> None:
    values: dict[str, object] = {
        "category": ErrorCategory.CONFIGURATION_ERROR,
        "code": DiagnosticCode("CFG_INVALID"),
        "message": "Configuration is invalid.",
        "retryable": False,
        "result_category": ResultCategory.INVALID_INPUT,
    }
    values[field] = value
    with pytest.raises(ValidationError):
        Diagnostic.model_validate(values)


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_diagnostic_rejects_nonfinite_nested_safe_details(number: float) -> None:
    with pytest.raises(ValidationError, match="non-finite JSON numbers"):
        Diagnostic(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code=DiagnosticCode("CFG_INVALID"),
            message="Configuration is invalid.",
            retryable=False,
            safe_details={"nested": [{"number": number}]},
            result_category=ResultCategory.INVALID_INPUT,
        )


def test_diagnostic_location_rejects_empty_and_control_paths() -> None:
    for path in ("", " ", "project.yaml\rforged"):
        with pytest.raises(ValidationError):
            DiagnosticLocation(path=path)


@pytest.mark.parametrize(
    ("field_path", "entity_id", "corrective_action"),
    [
        (None, None, "Fix it."),
        ("receiver.url", None, ""),
        (None, EntityId("attempt_01"), " "),
        ("receiver.url", None, None),
    ],
)
def test_user_correctable_diagnostic_requires_reference_and_one_action(
    field_path: str | None,
    entity_id: EntityId | None,
    corrective_action: str | None,
) -> None:
    with pytest.raises(ValidationError):
        Diagnostic(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code=DiagnosticCode("CFG_INVALID"),
            message="Configuration is invalid.",
            retryable=False,
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path=field_path,
            entity_id=entity_id,
            corrective_action=corrective_action,
        )


def test_entity_remediation_is_valid() -> None:
    diagnostic = Diagnostic(
        category=ErrorCategory.OBSERVER_PROTOCOL_ERROR,
        code=DiagnosticCode("OBS_BAD_RESPONSE"),
        message="Observer response is invalid.",
        retryable=False,
        result_category=ResultCategory.INVALID_INPUT,
        user_correctable=True,
        entity_id=EntityId("observer_01"),
        corrective_action="Return one valid observer response object.",
    )
    assert diagnostic.entity_id == "observer_01"


def _raise_canary_crash() -> None:
    canary_local = "local-secret-canary"
    message = f"message-secret-canary {canary_local} authorization=Bearer-secret"
    raise RuntimeError(message)


def _capture_canary_crash() -> RuntimeError:
    try:
        _raise_canary_crash()
    except RuntimeError as exception:
        return exception
    raise AssertionError  # pragma: no cover


def test_default_crash_format_is_private() -> None:
    exception = _capture_canary_crash()
    diagnostic = normalize_unexpected_exception(
        exception,
        incident_id=IncidentId("incident_test"),
    )
    rendered = format_unexpected_exception(
        exception,
        diagnostic,
        debug_policy=DebugPolicy(explicit=False, environment=False),
    )
    assert diagnostic.code == INTERNAL_ERROR_CODE
    assert diagnostic.result_category is ResultCategory.HARNESS_ERROR
    assert diagnostic.safe_details == {"exception_type": "RuntimeError"}
    serialized = diagnostic.model_dump_json()
    assert "secret-canary" not in serialized
    assert "Bearer-secret" not in serialized
    assert rendered == (
        "HARNESS_INTERNAL_ERROR: An internal harness error occurred.\n"
        "incident_id: incident_test\n"
        "exception_type: RuntimeError"
    )
    assert "Traceback" not in rendered
    assert "secret-canary" not in rendered
    assert "Bearer-secret" not in rendered


def test_debug_crash_format_contains_frames_but_no_messages_or_locals() -> None:
    exception = _capture_canary_crash()
    diagnostic = normalize_unexpected_exception(
        exception,
        incident_id=IncidentId("incident_debug"),
    )
    rendered = format_unexpected_exception(
        exception,
        diagnostic,
        debug_policy=DebugPolicy.resolve(
            explicit=False,
            environ={DEBUG_ENVIRONMENT_VARIABLE: "true"},
        ),
    )
    assert "Traceback (frame metadata only):" in rendered
    assert 'File "' in rendered
    assert "<sha256:" in rendered
    assert "in _raise_canary_crash" in rendered
    assert __file__ not in rendered
    assert "secret-canary" not in rendered
    assert "Bearer-secret" not in rendered
    assert "secret_local" not in rendered


def test_crash_formatter_rejects_an_unrelated_diagnostic() -> None:
    diagnostic = Diagnostic(
        category=ErrorCategory.CONFIGURATION_ERROR,
        code=DiagnosticCode("CFG_INVALID"),
        message="Configuration is invalid.",
        retryable=False,
        result_category=ResultCategory.INVALID_INPUT,
    )
    with pytest.raises(ValueError, match="normalized internal-error"):
        format_unexpected_exception(
            RuntimeError("secret-canary"),
            diagnostic,
            debug_policy=DebugPolicy(),
        )


def test_generated_incident_ids_are_opaque_bounded_tokens() -> None:
    first = new_incident_id()
    second = new_incident_id()
    assert first != second
    assert first.startswith("incident_")
    assert len(first) == len("incident_") + 32
    assert set(first.removeprefix("incident_")) <= set("0123456789abcdef")


@pytest.mark.parametrize(
    ("environment_value", "expected"),
    [
        ("1", True),
        (" TRUE ", True),
        ("yes", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("unexpected", False),
        ("", False),
    ],
)
def test_debug_policy_environment_gate_is_explicit(
    environment_value: str,
    *,
    expected: bool,
) -> None:
    policy = DebugPolicy.resolve(
        explicit=False,
        environ={DEBUG_ENVIRONMENT_VARIABLE: environment_value},
    )
    assert policy.enabled is expected


def test_version_metadata_is_independent_and_preserves_schema_strings() -> None:
    assert (
        VersionMetadata(
            package="0.1.0",
            configuration_schema="1.0",
            manifest_schema="1.0",
            observer_protocol="1.0",
            report_schema="1.0",
            task_index_schema="1.0",
            generator_algorithm="hmac-sha256-context-v1",
            sqlite_user_version=1,
        )
        == VERSION_METADATA
    )
    serialized = json.loads(json.dumps(VERSION_METADATA.as_dict()))
    for key in (
        "configuration_schema",
        "manifest_schema",
        "observer_protocol",
        "report_schema",
        "task_index_schema",
    ):
        assert serialized[key] == "1.0"
        assert isinstance(serialized[key], str)
    changed = replace(VERSION_METADATA, package="0.1.1")
    assert changed.configuration_schema == VERSION_METADATA.configuration_schema
    with pytest.raises(FrozenInstanceError):
        VERSION_METADATA.package = "0.2.0"  # pyright: ignore[reportAttributeAccessIssue]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("package", "1.0"),
        ("package", "01.0.0"),
        ("configuration_schema", "1"),
        ("manifest_schema", "1.0.0"),
        ("observer_protocol", "v1.0"),
        ("report_schema", ""),
        ("task_index_schema", "01.0"),
        ("generator_algorithm", "HMAC-SHA256-v1"),
        ("generator_algorithm", ""),
        ("sqlite_user_version", -1),
        ("sqlite_user_version", True),
    ],
)
def test_version_metadata_rejects_malformed_boundary_values(
    field: str,
    value: object,
) -> None:
    values = dict[str, object](VERSION_METADATA.as_dict())
    values[field] = value
    with pytest.raises(ValueError, match="must be"):
        VersionMetadata(**values)  # pyright: ignore[reportArgumentType]
