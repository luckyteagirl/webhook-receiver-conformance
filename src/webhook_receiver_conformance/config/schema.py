"""Pure Stage A project-configuration schema preflight helpers."""
# ruff: noqa: INP001

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from webhook_receiver_conformance.errors import Diagnostic, ErrorCategory, ResultCategory
from webhook_receiver_conformance.types import DiagnosticCode
from webhook_receiver_conformance.version import VERSION_METADATA

PROJECT_CONFIG_SCHEMA_MAJOR = 1
PROJECT_CONFIG_SCHEMA_VERSION = VERSION_METADATA.configuration_schema
SUPPORTED_CONFIG_SCHEMA_VERSIONS = frozenset({PROJECT_CONFIG_SCHEMA_MAJOR})
MIN_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR = min(SUPPORTED_CONFIG_SCHEMA_VERSIONS)
MAX_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR = max(SUPPORTED_CONFIG_SCHEMA_VERSIONS)

MAX_CONFIG_BYTES = 16_777_216
MAX_CONFIG_DEPTH = 64
MAX_CONFIG_NODES = 100_000


def schema_version_diagnostic(document: object) -> Diagnostic | None:
    """Classify the root schema version without inspecting other fields."""
    if not isinstance(document, Mapping):
        return _configuration_diagnostic(
            code="CFG_SCHEMA_VERSION_REQUIRED",
            message="Configuration must be an object containing schema_version.",
            corrective_action="Set schema_version to integer 1 at the document root.",
        )

    if "schema_version" not in document:
        return _configuration_diagnostic(
            code="CFG_SCHEMA_VERSION_REQUIRED",
            message="Configuration schema_version is required.",
            corrective_action="Add schema_version: 1 at the document root.",
        )

    root = cast("Mapping[object, object]", document)
    version = root["schema_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version == 0:
        return _configuration_diagnostic(
            code="CFG_SCHEMA_VERSION_INVALID",
            message="Configuration schema_version must be a positive integer.",
            corrective_action="Set schema_version to integer 1.",
        )

    if version not in SUPPORTED_CONFIG_SCHEMA_VERSIONS:
        return Diagnostic(
            category=ErrorCategory.UNSUPPORTED_SCHEMA,
            code=DiagnosticCode("CFG_SCHEMA_VERSION_UNSUPPORTED"),
            message="Configuration schema version is unsupported.",
            retryable=False,
            safe_details={
                "supported_minimum": MIN_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR,
                "supported_maximum": MAX_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR,
                "configuration_schema": PROJECT_CONFIG_SCHEMA_VERSION,
            },
            result_category=ResultCategory.UNSUPPORTED,
            user_correctable=True,
            field_path="schema_version",
            corrective_action="Migrate the configuration to schema_version 1.",
        )

    return None


def resource_limit_diagnostic(
    document: object,
    *,
    encoded_byte_length: int | None = None,
) -> Diagnostic | None:
    """Return a bounded resource diagnostic without performing I/O."""
    if encoded_byte_length is not None:
        length = _validated_byte_length(encoded_byte_length)
        if length > MAX_CONFIG_BYTES:
            return _resource_diagnostic("MAX_CONFIG_BYTES", MAX_CONFIG_BYTES)

    stack: list[tuple[object, int]] = [(document, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_CONFIG_NODES:
            return _resource_diagnostic("MAX_CONFIG_NODES", MAX_CONFIG_NODES)
        if depth > MAX_CONFIG_DEPTH:
            return _resource_diagnostic("MAX_CONFIG_DEPTH", MAX_CONFIG_DEPTH)

        if isinstance(value, Mapping):
            mapping = cast("Mapping[object, object]", value)
            stack.extend((item, depth + 1) for item in mapping.values())
        elif isinstance(value, (list, tuple)):
            sequence = cast("list[object] | tuple[object, ...]", value)
            stack.extend((item, depth + 1) for item in sequence)

    return None


def preflight_config(
    document: object,
    *,
    encoded_byte_length: int | None = None,
) -> Diagnostic | None:
    """Apply resource and version preflight in deterministic security order."""
    resource_error = resource_limit_diagnostic(
        document,
        encoded_byte_length=encoded_byte_length,
    )
    if resource_error is not None:
        return resource_error
    return schema_version_diagnostic(document)


def _configuration_diagnostic(
    *,
    code: str,
    message: str,
    corrective_action: str,
) -> Diagnostic:
    return Diagnostic(
        category=ErrorCategory.CONFIGURATION_ERROR,
        code=DiagnosticCode(code),
        message=message,
        retryable=False,
        safe_details={
            "supported_minimum": MIN_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR,
            "supported_maximum": MAX_SUPPORTED_PROJECT_CONFIG_SCHEMA_MAJOR,
        },
        result_category=ResultCategory.INVALID_INPUT,
        user_correctable=True,
        field_path="schema_version",
        corrective_action=corrective_action,
    )


def _resource_diagnostic(limit_name: str, maximum: int) -> Diagnostic:
    return Diagnostic(
        category=ErrorCategory.RESOURCE_LIMIT,
        code=DiagnosticCode("CFG_RESOURCE_LIMIT"),
        message="Configuration exceeds a resource limit.",
        retryable=False,
        safe_details={"limit": limit_name, "maximum": maximum},
        result_category=ResultCategory.INVALID_INPUT,
        user_correctable=True,
        field_path="$",
        corrective_action="Reduce the configuration size or structural complexity.",
    )


def _validated_byte_length(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        msg = "encoded_byte_length must be a nonnegative integer"
        raise ValueError(msg)
    return value
