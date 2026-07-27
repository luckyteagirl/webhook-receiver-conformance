"""Independently versioned package and serialized-contract metadata."""

from __future__ import annotations

from dataclasses import dataclass


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


VERSION_METADATA = VersionMetadata(
    package="0.1.0",
    configuration_schema="1.0",
    manifest_schema="1.0",
    observer_protocol="1.0",
    report_schema="1.0",
    task_index_schema="1.0",
    generator_algorithm="hmac-sha256-context-v1",
    sqlite_user_version=1,
)
