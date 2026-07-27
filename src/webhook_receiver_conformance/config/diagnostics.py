"""Privacy-safe diagnostics for project-configuration loading."""
# ruff: noqa: INP001, PLR0913

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic import ValidationError
    from pydantic_core import ErrorDetails

from webhook_receiver_conformance.errors import (
    Diagnostic,
    DiagnosticLocation,
    ErrorCategory,
    ResultCategory,
)
from webhook_receiver_conformance.types import DiagnosticCode, JsonObject

MAX_CONFIG_DIAGNOSTICS = 50

type ConfigPathPart = str | int
type ConfigFieldPath = tuple[ConfigPathPart, ...]
type SourceLocations = Mapping[ConfigFieldPath, tuple[int, int]]
type StrPath = str | PathLike[str]

_SAFE_FIELD_PART = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_CONTROL_CHARACTER_LIMIT = 32
_DELETE_CHARACTER_CODEPOINT = 127
_MAX_RENDERED_FIELD_PART = 128
_MAX_RENDERED_FIELD_PATH = 1024


def configuration_diagnostic(
    *,
    code: str,
    message: str,
    field_path: str,
    corrective_action: str,
    source_path: StrPath | None = None,
    line: int | None = None,
    column: int | None = None,
    safe_details: JsonObject | None = None,
    category: ErrorCategory = ErrorCategory.CONFIGURATION_ERROR,
    result_category: ResultCategory = ResultCategory.INVALID_INPUT,
) -> Diagnostic:
    """Create one normalized user-correctable configuration diagnostic."""
    return Diagnostic(
        category=category,
        code=DiagnosticCode(code),
        message=message,
        location=_location(source_path=source_path, line=line, column=column),
        retryable=False,
        safe_details={} if safe_details is None else safe_details,
        result_category=result_category,
        user_correctable=True,
        field_path=field_path,
        corrective_action=corrective_action,
    )


def validation_diagnostics(
    error: ValidationError,
    *,
    source_path: StrPath,
    source_locations: SourceLocations,
) -> tuple[Diagnostic, ...]:
    """Convert bounded Pydantic failures without copying rejected input values."""
    diagnostics: list[Diagnostic] = []
    for details in error.errors(
        include_url=False,
        include_context=False,
        include_input=False,
    ):
        if len(diagnostics) == MAX_CONFIG_DIAGNOSTICS:
            break
        path = _error_path(details)
        line, column = _nearest_source_location(path, source_locations)
        code, message, corrective_action = _validation_copy(details)
        diagnostics.append(
            configuration_diagnostic(
                code=code,
                message=message,
                field_path=format_field_path(path),
                corrective_action=corrective_action,
                source_path=source_path,
                line=line,
                column=column,
                safe_details={"rule": str(details["type"])},
            )
        )
    if len(error.errors(include_url=False, include_context=False, include_input=False)) > len(
        diagnostics
    ):
        diagnostics[-1] = configuration_diagnostic(
            code="CFG_DIAGNOSTIC_LIMIT",
            message="Additional configuration errors were omitted.",
            field_path="$",
            corrective_action="Fix the reported errors, then validate the configuration again.",
            source_path=source_path,
            safe_details={"maximum": MAX_CONFIG_DIAGNOSTICS},
        )
    return tuple(diagnostics)


def format_field_path(path: Sequence[ConfigPathPart]) -> str:
    """Render a stable field path without interpreting user values."""
    if not path:
        return "$"
    rendered = "$"
    for part in path:
        if isinstance(part, int):
            rendered = f"{rendered}[{part}]"
        elif len(part) <= _MAX_RENDERED_FIELD_PART and _SAFE_FIELD_PART.fullmatch(part) is not None:
            rendered = f"{rendered}.{part}"
        elif _contains_control_character(part) or len(part) > _MAX_RENDERED_FIELD_PART:
            rendered = f"{rendered}['<invalid-key>']"
        else:
            escaped = part.replace("\\", "\\\\").replace("'", "\\'")
            rendered = f"{rendered}['{escaped}']"
        if len(rendered) > _MAX_RENDERED_FIELD_PATH:
            return "$['<path-omitted>']"
    return rendered


def safe_source_label(path: StrPath) -> str:
    """Return a location label that cannot inject terminal controls."""
    value = str(Path(path))
    if not value or _contains_control_character(value):
        return "<configuration>"
    return value


def _validation_copy(details: ErrorDetails) -> tuple[str, str, str]:
    error_type = str(details["type"])
    if error_type == "extra_forbidden":
        return (
            "CFG_UNKNOWN_FIELD",
            "Configuration contains an unknown field.",
            "Remove the field or use a field declared by schema version 1.",
        )
    if error_type == "missing":
        return (
            "CFG_REQUIRED_FIELD",
            "Configuration is missing a required field.",
            "Add the required field using the schema version 1 contract.",
        )
    return (
        "CFG_MODEL_INVALID",
        "Configuration field does not satisfy the schema version 1 contract.",
        "Correct the field type or value using the schema version 1 contract.",
    )


def _error_path(details: ErrorDetails) -> ConfigFieldPath:
    return tuple(details["loc"])


def _nearest_source_location(
    path: ConfigFieldPath,
    locations: SourceLocations,
) -> tuple[int | None, int | None]:
    candidate = path
    while candidate:
        location = locations.get(candidate)
        if location is not None:
            return location
        candidate = candidate[:-1]
    return locations.get((), (None, None))


def _location(
    *,
    source_path: StrPath | None,
    line: int | None,
    column: int | None,
) -> DiagnosticLocation | None:
    if source_path is None and line is None and column is None:
        return None
    return DiagnosticLocation(
        path=None if source_path is None else safe_source_label(source_path),
        line=line,
        column=column,
    )


def _contains_control_character(value: str) -> bool:
    return any(
        ord(character) < _CONTROL_CHARACTER_LIMIT or ord(character) == _DELETE_CHARACTER_CODEPOINT
        for character in value
    )
