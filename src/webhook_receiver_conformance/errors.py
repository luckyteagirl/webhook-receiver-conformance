"""Stable, privacy-safe error and terminal-result primitives."""

from __future__ import annotations

import hashlib
import math
import os
import re
import uuid
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from webhook_receiver_conformance.types import (
    DiagnosticCode,
    EntityId,
    IncidentId,
    JsonObject,
    JsonValue,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

DEBUG_ENVIRONMENT_VARIABLE = "WEBHOOK_CONFORMANCE_DEBUG"
INTERNAL_ERROR_CODE = DiagnosticCode("HARNESS_INTERNAL_ERROR")
_DIAGNOSTIC_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,127}")
_BOUNDARY_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_C0_CONTROL_LIMIT = 32
_DELETE_CONTROL_CODEPOINT = 127


class ResultCategory(StrEnum):
    """Authoritative FR-006 terminal result values."""

    PASS = "pass"  # noqa: S105
    RECEIVER_FAILURE = "receiver_failure"
    ENVIRONMENT_ERROR = "environment_error"
    HARNESS_ERROR = "harness_error"
    AMBIGUOUS = "ambiguous"
    INVALID_INPUT = "invalid_input"
    UNSUPPORTED = "unsupported"
    CANCELLED = "cancelled"


class CliExitCategory(StrEnum):
    """CLI failure-form names, which intentionally differ from FR-006."""

    PASS = "pass"  # noqa: S105
    RECEIVER_FAILURE = "receiver_failure"
    INVALID_INPUT = "invalid_input"
    ENVIRONMENT_FAILURE = "environment_failure"
    AMBIGUOUS = "ambiguous"
    HARNESS_FAILURE = "harness_failure"
    UNSUPPORTED = "unsupported"
    CANCELLED = "cancelled"


class ExitCode(IntEnum):
    """Documented CLI process exit codes."""

    PASS = 0
    RECEIVER_FAILURE = 1
    INVALID_INPUT = 2
    ENVIRONMENT_FAILURE = 3
    AMBIGUOUS = 4
    HARNESS_FAILURE = 5
    UNSUPPORTED = 6
    CANCELLED = 130


RESULT_TO_EXIT: Mapping[ResultCategory, tuple[CliExitCategory, ExitCode]] = {
    ResultCategory.PASS: (CliExitCategory.PASS, ExitCode.PASS),
    ResultCategory.RECEIVER_FAILURE: (
        CliExitCategory.RECEIVER_FAILURE,
        ExitCode.RECEIVER_FAILURE,
    ),
    ResultCategory.ENVIRONMENT_ERROR: (
        CliExitCategory.ENVIRONMENT_FAILURE,
        ExitCode.ENVIRONMENT_FAILURE,
    ),
    ResultCategory.HARNESS_ERROR: (
        CliExitCategory.HARNESS_FAILURE,
        ExitCode.HARNESS_FAILURE,
    ),
    ResultCategory.AMBIGUOUS: (CliExitCategory.AMBIGUOUS, ExitCode.AMBIGUOUS),
    ResultCategory.INVALID_INPUT: (CliExitCategory.INVALID_INPUT, ExitCode.INVALID_INPUT),
    ResultCategory.UNSUPPORTED: (CliExitCategory.UNSUPPORTED, ExitCode.UNSUPPORTED),
    ResultCategory.CANCELLED: (CliExitCategory.CANCELLED, ExitCode.CANCELLED),
}


class ErrorCategory(StrEnum):
    """Stable component error categories documented by specification/16."""

    CONFIGURATION_ERROR = "configuration_error"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    SECRET_REFERENCE_ERROR = "secret_reference_error"  # noqa: S105
    RESOURCE_LIMIT = "resource_limit"
    PLANNING_ERROR = "planning_error"
    FIXTURE_ERROR = "fixture_error"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    JOURNAL_BUSY = "journal_busy"
    ILLEGAL_TRANSITION = "illegal_transition"
    INTEGRITY_ERROR = "integrity_error"
    MIGRATION_ERROR = "migration_error"
    SCHEDULE_ERROR = "schedule_error"
    DEADLOCK = "deadlock"
    CANCELLED = "cancelled"
    CONNECT_TIMEOUT = "connect_timeout"
    READ_TIMEOUT = "read_timeout"
    WRITE_TIMEOUT = "write_timeout"
    POOL_TIMEOUT = "pool_timeout"
    TLS_ERROR = "tls_error"
    CONNECTION_ERROR = "connection_error"
    PROTOCOL_ERROR = "protocol_error"
    RESPONSE_TOO_LARGE = "response_too_large"
    KEY_UNAVAILABLE = "key_unavailable"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    SIGNING_ERROR = "signing_error"
    MUTATION_NOT_APPLICABLE = "mutation_not_applicable"
    CONFLICTING_MUTATION = "conflicting_mutation"
    INVALID_PARAMETER = "invalid_parameter"
    OBSERVER_TIMEOUT = "observer_timeout"
    OBSERVER_PROTOCOL_ERROR = "observer_protocol_error"
    OBSERVER_PROCESS_ERROR = "observer_process_error"
    OBSERVER_HTTP_ERROR = "observer_http_error"
    OBSERVER_AUTH_ERROR = "observer_auth_error"
    ASSERTION_ERROR = "assertion_error"
    EVIDENCE_MISSING = "evidence_missing"
    UNSUPPORTED_ASSERTION = "unsupported_assertion"
    REPORT_ERROR = "report_error"
    ARTIFACT_INTEGRITY_ERROR = "artifact_integrity_error"
    OUTPUT_LIMIT = "output_limit"
    LIFECYCLE_DISABLED = "lifecycle_disabled"
    PROCESS_ERROR = "process_error"
    READINESS_TIMEOUT = "readiness_timeout"
    SCHEMA_VALIDATION_ERROR = "schema_validation_error"
    INTERNAL_ERROR = "internal_error"


class DiagnosticLocation(BaseModel):
    """Optional source location associated with a diagnostic."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        """Reject empty or terminal-unsafe source paths."""
        if value is not None and (not value.strip() or _contains_control_character(value)):
            msg = "diagnostic location path must be nonempty and control-character free"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def require_one_coordinate(self) -> DiagnosticLocation:
        """Reject empty location objects."""
        if self.path is None and self.line is None and self.column is None:
            msg = "a diagnostic location must contain path, line, or column"
            raise ValueError(msg)
        return self


class Diagnostic(BaseModel):
    """Strict immutable normalized diagnostic/error envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    category: ErrorCategory
    code: DiagnosticCode
    message: str = Field(min_length=1)
    location: DiagnosticLocation | None = None
    retryable: bool
    safe_details: JsonObject = Field(default_factory=dict)
    cause_category: ErrorCategory | None = None
    result_category: ResultCategory
    incident_id: IncidentId | None = None
    user_correctable: bool = False
    field_path: str | None = None
    entity_id: EntityId | None = None
    corrective_action: str | None = None

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: DiagnosticCode) -> DiagnosticCode:
        """Require a bounded, machine-stable diagnostic code."""
        if _DIAGNOSTIC_CODE.fullmatch(value) is None:
            msg = "diagnostic code must use uppercase ASCII letters, digits, and underscores"
            raise ValueError(msg)
        return value

    @field_validator("message", "corrective_action")
    @classmethod
    def reject_control_characters(cls, value: str | None) -> str | None:
        """Keep terminal-facing text single-line and control-character free."""
        if value is not None:
            if not value.strip():
                msg = "diagnostic text must not be empty or whitespace"
                raise ValueError(msg)
            if _contains_control_character(value):
                msg = "diagnostic text must not contain control characters"
                raise ValueError(msg)
        return value

    @field_validator("entity_id", "incident_id")
    @classmethod
    def validate_boundary_identifier(
        cls,
        value: EntityId | IncidentId | None,
    ) -> EntityId | IncidentId | None:
        """Keep record identifiers bounded and safe for diagnostic rendering."""
        if value is not None and _BOUNDARY_IDENTIFIER.fullmatch(value) is None:
            msg = "diagnostic identifiers must be bounded ASCII tokens"
            raise ValueError(msg)
        return value

    @field_validator("field_path")
    @classmethod
    def validate_field_path(cls, value: str | None) -> str | None:
        """Reject empty or terminal-unsafe field paths."""
        if value is not None and (not value.strip() or _contains_control_character(value)):
            msg = "field_path must be nonempty and control-character free"
            raise ValueError(msg)
        return value

    @field_validator("safe_details")
    @classmethod
    def validate_safe_details(cls, value: JsonObject) -> JsonObject:
        """Require details to remain losslessly JSON serializable."""
        _reject_nonfinite_json_numbers(value)
        return value

    @model_validator(mode="after")
    def enforce_remediation_and_incident(self) -> Diagnostic:
        """Enforce the actionable-diagnostic and internal-incident contracts."""
        if self.user_correctable:
            if self.field_path is None and self.entity_id is None:
                msg = "a user-correctable diagnostic requires a field_path or entity_id"
                raise ValueError(msg)
            if self.corrective_action is None or not self.corrective_action.strip():
                msg = "a user-correctable diagnostic requires one nonempty corrective_action"
                raise ValueError(msg)
        elif self.corrective_action is not None:
            msg = "corrective_action is only valid for a user-correctable diagnostic"
            raise ValueError(msg)
        if self.result_category is ResultCategory.HARNESS_ERROR and self.incident_id is None:
            msg = "a harness_error diagnostic requires an incident_id"
            raise ValueError(msg)
        return self


class DebugPolicy(BaseModel):
    """Explicit traceback policy combining a flag and the documented environment key."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    explicit: bool = False
    environment: bool = False

    @property
    def enabled(self) -> bool:
        """Return whether either explicit debug control is enabled."""
        return self.explicit or self.environment

    @classmethod
    def resolve(
        cls,
        *,
        explicit: bool,
        environ: Mapping[str, str] | None = None,
    ) -> DebugPolicy:
        """Resolve an explicit flag and the documented environment variable."""
        source = os.environ if environ is None else environ
        raw_value = source.get(DEBUG_ENVIRONMENT_VARIABLE, "")
        environment = raw_value.strip().casefold() in {"1", "true", "yes", "on"}
        return cls(explicit=explicit, environment=environment)


def exit_for_result(result: ResultCategory) -> tuple[CliExitCategory, ExitCode]:
    """Return the explicit CLI category and process code for a terminal result."""
    return RESULT_TO_EXIT[result]


def new_incident_id() -> IncidentId:
    """Generate an opaque incident identifier."""
    return IncidentId(f"incident_{uuid.uuid4().hex}")


def normalize_unexpected_exception(
    exception: BaseException,
    *,
    incident_id: IncidentId | None = None,
) -> Diagnostic:
    """Normalize an unexpected exception without retaining its message or traceback."""
    exception_type = _safe_exception_type(exception)
    return Diagnostic(
        category=ErrorCategory.INTERNAL_ERROR,
        code=INTERNAL_ERROR_CODE,
        message="An internal harness error occurred.",
        retryable=False,
        safe_details={"exception_type": exception_type},
        result_category=ResultCategory.HARNESS_ERROR,
        incident_id=new_incident_id() if incident_id is None else incident_id,
    )


def format_unexpected_exception(
    exception: BaseException,
    diagnostic: Diagnostic,
    *,
    debug_policy: DebugPolicy,
) -> str:
    """Format a crash diagnostic, optionally adding message-free frame metadata."""
    if (
        diagnostic.category is not ErrorCategory.INTERNAL_ERROR
        or diagnostic.code != INTERNAL_ERROR_CODE
        or diagnostic.result_category is not ResultCategory.HARNESS_ERROR
        or diagnostic.incident_id is None
    ):
        msg = "unexpected exceptions require a normalized internal-error diagnostic"
        raise ValueError(msg)
    lines = [
        f"{INTERNAL_ERROR_CODE}: An internal harness error occurred.",
        f"incident_id: {diagnostic.incident_id}",
        f"exception_type: {_safe_exception_type(exception)}",
    ]
    if debug_policy.enabled:
        lines.append("Traceback (frame metadata only):")
        lines.extend(_format_traceback_frames(exception.__traceback__))
    return "\n".join(lines)


def _safe_exception_type(exception: BaseException) -> str:
    name = type(exception).__name__
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) else "Exception"


def _format_traceback_frames(traceback: TracebackType | None) -> list[str]:
    lines: list[str] = []
    current = traceback
    while current is not None:
        code = current.tb_frame.f_code
        filename_hash = hashlib.sha256(
            code.co_filename.encode("utf-8", errors="surrogatepass")
        ).hexdigest()[:16]
        function_name = (
            code.co_name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", code.co_name) else "callable"
        )
        lines.append(
            f'File "<sha256:{filename_hash}>", line {current.tb_lineno}, in {function_name}'
        )
        current = current.tb_next
    return lines


def _contains_control_character(value: str) -> bool:
    return any(
        ord(character) < _C0_CONTROL_LIMIT or ord(character) == _DELETE_CONTROL_CODEPOINT
        for character in value
    )


def _reject_nonfinite_json_numbers(value: JsonValue) -> None:
    if isinstance(value, float):
        if not math.isfinite(value):
            msg = "safe_details must not contain non-finite JSON numbers"
            raise ValueError(msg)
        return
    if isinstance(value, list):
        for item in value:
            _reject_nonfinite_json_numbers(item)
        return
    if isinstance(value, dict):
        for item in value.values():
            _reject_nonfinite_json_numbers(item)
