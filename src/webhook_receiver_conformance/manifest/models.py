"""Strict immutable models for the v1 realized run manifest."""
# ruff: noqa: D101, D102, EM101, INP001, TC001, TRY003

from __future__ import annotations

import json
import re
from typing import Annotated, Literal, Self, cast

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
)

from webhook_receiver_conformance.config.models import CanonicalJsonValue
from webhook_receiver_conformance.domain.hashing import (
    canonical_manifest_bytes,
    compute_manifest_id,
    validate_manifest_id,
    validate_sha256_digest,
)
from webhook_receiver_conformance.domain.identifiers import (
    PlannedIdKind,
    validate_planned_id,
)

MAX_SAFE_INTEGER = (1 << 53) - 1
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z")


class ManifestModel(BaseModel):
    """Frozen strict manifest boundary."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        use_enum_values=False,
    )


Sha256 = Annotated[StrictStr, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
SafeInteger = Annotated[StrictInt, Field(ge=-MAX_SAFE_INTEGER, le=MAX_SAFE_INTEGER)]
SafeNonnegativeInteger = Annotated[StrictInt, Field(ge=0, le=MAX_SAFE_INTEGER)]


def _wire_array(value: object) -> object:
    return tuple(cast("list[object]", value)) if isinstance(value, list) else value


type WireTuple[T] = Annotated[tuple[T, ...], BeforeValidator(_wire_array)]


class ToolSnapshot(ManifestModel):
    version: StrictStr
    python: StrictStr
    dependencies_digest: Sha256 | None = None


class GeneratorSnapshot(ManifestModel):
    algorithm: Literal["hmac-sha256-context-v1"]
    seed_fingerprint: Sha256
    normalized_seed_hash_hex: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]


class EnvironmentSnapshot(ManifestModel):
    os: StrictStr
    architecture: StrictStr
    timezone: Literal["UTC"] | None = None


class TargetPolicySnapshot(ManifestModel):
    profile: Literal["loopback", "private-allowlist", "public-authorized"]
    authorized_host: StrictStr
    authorized_port: Annotated[StrictInt, Field(ge=1, le=65535)]
    challenge_fingerprint: Sha256 | None = None


class BlobEntry(ManifestModel):
    sha256: Sha256
    byte_length: SafeNonnegativeInteger
    media_type: StrictStr


class EventPlan(ManifestModel):
    event_id: StrictStr
    event_type: StrictStr
    fixture_blob: Sha256
    depends_on: WireTuple[StrictStr] | None = None

    @field_validator("event_id")
    @classmethod
    def event_id_kind(cls, value: str) -> str:
        return validate_planned_id(value, expected_kind=PlannedIdKind.EVENT)


class AttemptTemplate(ManifestModel):
    ordinal: Annotated[StrictInt, Field(ge=1, le=MAX_SAFE_INTEGER)]
    not_before_logical_ns: SafeInteger
    request_blob: Sha256
    headers_sha256: Sha256
    conditional_on: StrictStr | None = None


class DeliveryPlan(ManifestModel):
    delivery_id: StrictStr
    event_id: StrictStr
    logical_time_ns: SafeInteger
    ordinal: SafeNonnegativeInteger
    concurrency_group: StrictStr | None = None
    attempt_plan: WireTuple[AttemptTemplate]

    @field_validator("delivery_id")
    @classmethod
    def delivery_id_kind(cls, value: str) -> str:
        return validate_planned_id(value, expected_kind=PlannedIdKind.DELIVERY)

    @field_validator("event_id")
    @classmethod
    def referenced_event_kind(cls, value: str) -> str:
        return validate_planned_id(value, expected_kind=PlannedIdKind.EVENT)


class AssertionPlan(ManifestModel):
    assertion_id: StrictStr
    type: StrictStr
    observer: StrictStr | None = None
    parameters: dict[StrictStr, CanonicalJsonValue] | None = None

    @field_validator("assertion_id")
    @classmethod
    def assertion_id_kind(cls, value: str) -> str:
        return validate_planned_id(value, expected_kind=PlannedIdKind.ASSERTION)


class ScenarioPlan(ManifestModel):
    scenario_id: StrictStr
    events: WireTuple[EventPlan]
    deliveries: WireTuple[DeliveryPlan]
    assertions: WireTuple[AssertionPlan]

    @field_validator("scenario_id")
    @classmethod
    def scenario_id_kind(cls, value: str) -> str:
        return validate_planned_id(value, expected_kind=PlannedIdKind.SCENARIO)


class RunManifest(ManifestModel):
    """Execution-agnostic immutable manifest whose ID binds its content."""

    schema_version: Literal["1.0"]
    manifest_id: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    created_at: StrictStr
    tool: ToolSnapshot
    generator: GeneratorSnapshot
    configuration_digest: Sha256
    environment: EnvironmentSnapshot
    target_policy: TargetPolicySnapshot
    blobs: WireTuple[BlobEntry]
    scenarios: WireTuple[ScenarioPlan]

    @field_validator("created_at")
    @classmethod
    def canonical_utc(cls, value: str) -> str:
        if _UTC.fullmatch(value) is None:
            raise ValueError("created_at must be a canonical UTC timestamp")
        return value

    def to_wire(self) -> dict[str, object]:
        """Return a detached JSON-compatible representation."""
        return cast(
            "dict[str, object]",
            self.model_dump(mode="json", exclude_none=True),
        )

    def canonical_bytes(self) -> bytes:
        """Return canonical content bytes, omitting only manifest_id."""
        return canonical_manifest_bytes(self.to_wire())

    def serialized_bytes(self) -> bytes:
        """Return stable human-readable artifact bytes."""
        return (
            json.dumps(
                self.to_wire(),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode()

    def verify_id(self) -> None:
        """Reject content that no longer matches its manifest identifier."""
        validate_manifest_id(self.manifest_id)
        if compute_manifest_id(self.to_wire()) != self.manifest_id:
            raise ValueError("manifest_id does not match canonical manifest content")

    @classmethod
    def from_wire(cls, value: object, *, verify: bool = True) -> Self:
        manifest = cls.model_validate(value)
        if verify:
            manifest.verify_id()
        return manifest

    @classmethod
    def from_bytes(cls, value: bytes, *, verify: bool = True) -> Self:
        if type(value) is not bytes:
            raise TypeError("manifest input must be bytes")
        decoded = json.loads(
            value,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ValueError("floating-point manifest values are prohibited")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite manifest values are prohibited")
            ),
        )
        return cls.from_wire(decoded, verify=verify)


def validate_blob_entries(entries: tuple[BlobEntry, ...]) -> None:
    """Validate digest syntax and uniqueness for one manifest blob table."""
    seen: set[str] = set()
    for entry in entries:
        validate_sha256_digest(entry.sha256)
        if entry.sha256 in seen:
            raise ValueError("manifest blobs must have unique digests")
        seen.add(entry.sha256)


__all__ = [
    "AssertionPlan",
    "AttemptTemplate",
    "BlobEntry",
    "DeliveryPlan",
    "EnvironmentSnapshot",
    "EventPlan",
    "GeneratorSnapshot",
    "RunManifest",
    "ScenarioPlan",
    "TargetPolicySnapshot",
    "ToolSnapshot",
    "validate_blob_entries",
]
