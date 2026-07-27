"""Common JSON-compatible and nominal boundary types."""

from __future__ import annotations

from typing import NewType

DiagnosticCode = NewType("DiagnosticCode", str)
EntityId = NewType("EntityId", str)
IncidentId = NewType("IncidentId", str)
Sha256Digest = NewType("Sha256Digest", str)

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
