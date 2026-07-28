"""Independently versioned package and serialized-contract metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass

_SEMANTIC_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_SCHEMA_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_ALGORITHM_VERSION = re.compile(r"[a-z0-9][a-z0-9-]{0,127}")


@dataclass(frozen=True, slots=True)
class VersionMetadata:
    """Versions supported by this package build."""

    package: str
    configuration_schema: str
    manifest_schema: str
    observer_protocol: str
    report_schema: str
    task_index_schema: str
    generator_algorithm: str
    sqlite_user_version: int

    def __post_init__(self) -> None:
        """Reject malformed or accidentally coupled compatibility metadata."""
        if _SEMANTIC_VERSION.fullmatch(self.package) is None:
            msg = "package must be a semantic version"
            raise ValueError(msg)
        for name, value in (
            ("configuration_schema", self.configuration_schema),
            ("manifest_schema", self.manifest_schema),
            ("observer_protocol", self.observer_protocol),
            ("report_schema", self.report_schema),
            ("task_index_schema", self.task_index_schema),
        ):
            if _SCHEMA_VERSION.fullmatch(value) is None:
                msg = f"{name} must be an independent major.minor version"
                raise ValueError(msg)
        if _ALGORITHM_VERSION.fullmatch(self.generator_algorithm) is None:
            msg = "generator_algorithm must be a bounded lowercase version token"
            raise ValueError(msg)
        _validate_sqlite_user_version(self.sqlite_user_version)

    def as_dict(self) -> dict[str, str | int]:
        """Return a JSON-compatible representation without coercing schema versions."""
        return {
            "package": self.package,
            "configuration_schema": self.configuration_schema,
            "manifest_schema": self.manifest_schema,
            "observer_protocol": self.observer_protocol,
            "report_schema": self.report_schema,
            "task_index_schema": self.task_index_schema,
            "generator_algorithm": self.generator_algorithm,
            "sqlite_user_version": self.sqlite_user_version,
        }


def _validate_sqlite_user_version(value: object) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        msg = "sqlite_user_version must be a nonnegative integer"
        raise ValueError(msg)


VERSION_METADATA = VersionMetadata(
    package="0.1.0",
    configuration_schema="1.0",
    manifest_schema="1.0",
    observer_protocol="1.0",
    report_schema="1.0",
    task_index_schema="1.0",
    generator_algorithm="hmac-sha256-context-v1",
    sqlite_user_version=4,
)
