"""Strict execution, planned-entity, and evidence identifier primitives."""
# ruff: noqa: INP001

from __future__ import annotations

import re
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from webhook_receiver_conformance.determinism.generator import ContextGenerator

PLANNED_ID_ALGORITHM = "planned-id-v1"
_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_DECODE = {character: index for index, character in enumerate(_CROCKFORD_ALPHABET)}
_ULID_LENGTH = 26
_ULID_BYTES = 16
_UUID_VERSION = 4
_SURROGATE_MIN = 0xD800
_SURROGATE_MAX = 0xDFFF
_RUN_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_MAX_NATURAL_KEY_BYTES = 4096


class PlannedIdKind(StrEnum):
    """Replay-stable manifest-planned entity prefixes."""

    SCENARIO = "scenario"
    EVENT = "event"
    DELIVERY = "delivery"
    ATTEMPT_PLAN = "attempt_plan"
    OBSERVATION = "observation"
    ASSERTION = "assertion"


class FreshIdKind(StrEnum):
    """Fresh physical/evidence entity prefixes."""

    ATTEMPT = "attempt"
    SAMPLE = "sample"
    EVALUATION = "evaluation"
    RECORD = "record"


class IdentifierCollisionError(ValueError):
    """A serialized ID was claimed by two distinct source identities."""


def new_run_id() -> str:
    """Return an independently generated canonical lowercase UUIDv4."""
    return str(uuid.uuid4())


def validate_run_id(value: str) -> str:
    """Validate and return a canonical lowercase UUIDv4 run ID."""
    text = _require_string(value, name="run_id")
    if _RUN_ID.fullmatch(text) is None:
        message = "run_id must be a canonical lowercase UUIDv4"
        raise ValueError(message)
    parsed = uuid.UUID(text)
    if parsed.version != _UUID_VERSION or parsed.variant != uuid.RFC_4122 or str(parsed) != text:
        message = "run_id must be a canonical lowercase UUIDv4"
        raise ValueError(message)
    return text


def planned_id(
    generator: ContextGenerator,
    kind: PlannedIdKind,
    natural_key: Sequence[str],
) -> str:
    """Derive one type-prefixed stable ID from a natural-key context.

    The full 128-bit ULID payload is deterministic. Its leading 48 bits are not
    a wall-clock timestamp and must not be used for temporal ordering.
    """
    entity_kind = _require_planned_kind(kind)
    components = _validate_natural_key(natural_key)
    raw = generator.draw_bytes(
        (PLANNED_ID_ALGORITHM, entity_kind.value, *components),
        _ULID_BYTES,
    )
    return f"{entity_kind.value}_{encode_crockford_ulid(raw)}"


def validate_planned_id(
    value: str,
    *,
    expected_kind: PlannedIdKind | None = None,
) -> str:
    """Validate a stable planned ID and optionally enforce its type prefix."""
    kind, _ = parse_planned_id(value)
    if expected_kind is not None and kind is not _require_planned_kind(expected_kind):
        message = f"planned identifier must use the {expected_kind.value}_ prefix"
        raise ValueError(message)
    return value


def parse_planned_id(value: str) -> tuple[PlannedIdKind, bytes]:
    """Return the type and decoded 128-bit ULID payload of a planned ID."""
    text = _require_string(value, name="planned identifier")
    for kind in PlannedIdKind:
        prefix = f"{kind.value}_"
        if text.startswith(prefix):
            return kind, decode_crockford_ulid(text.removeprefix(prefix))
    message = "planned identifier has an unknown or physical-entity prefix"
    raise ValueError(message)


def new_fresh_id(kind: FreshIdKind) -> str:
    """Return a separately generated non-replay-stable physical/evidence ID."""
    entity_kind = _require_fresh_kind(kind)
    return f"{entity_kind.value}_{encode_crockford_ulid(secrets.token_bytes(_ULID_BYTES))}"


def validate_fresh_id(
    value: str,
    *,
    expected_kind: FreshIdKind | None = None,
) -> str:
    """Validate a fresh physical/evidence ID and optionally enforce its prefix."""
    kind, _ = parse_fresh_id(value)
    if expected_kind is not None and kind is not _require_fresh_kind(expected_kind):
        message = f"fresh identifier must use the {expected_kind.value}_ prefix"
        raise ValueError(message)
    return value


def parse_fresh_id(value: str) -> tuple[FreshIdKind, bytes]:
    """Return the type and decoded 128-bit payload of a fresh ID."""
    text = _require_string(value, name="fresh identifier")
    if any(text.startswith(f"{kind.value}_") for kind in PlannedIdKind):
        message = "fresh identifier must not use a planned-entity prefix"
        raise ValueError(message)
    for kind in FreshIdKind:
        prefix = f"{kind.value}_"
        if text.startswith(prefix):
            return kind, decode_crockford_ulid(text.removeprefix(prefix))
    message = "fresh identifier has an unknown or planned-entity prefix"
    raise ValueError(message)


def encode_crockford_ulid(value: bytes) -> str:
    """Encode exactly 128 bits using canonical uppercase Crockford Base32."""
    if not isinstance(value, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
        message = "ULID payload must be bytes"
        raise TypeError(message)
    if len(value) != _ULID_BYTES:
        message = "ULID payload must be exactly 16 bytes"
        raise ValueError(message)
    integer = int.from_bytes(value, "big")
    encoded = ["0"] * _ULID_LENGTH
    for index in range(_ULID_LENGTH - 1, -1, -1):
        encoded[index] = _CROCKFORD_ALPHABET[integer & 0x1F]
        integer >>= 5
    return "".join(encoded)


def decode_crockford_ulid(value: str) -> bytes:
    """Decode a canonical 26-character Crockford ULID payload."""
    text = _require_string(value, name="ULID payload")
    if len(text) != _ULID_LENGTH:
        message = "ULID payload must contain exactly 26 characters"
        raise ValueError(message)
    integer = 0
    try:
        for character in text:
            integer = (integer << 5) | _CROCKFORD_DECODE[character]
    except KeyError as error:
        message = "ULID payload must use canonical uppercase Crockford Base32"
        raise ValueError(message) from error
    if integer >= 1 << (_ULID_BYTES * 8):
        message = "ULID payload exceeds 128 bits"
        raise ValueError(message)
    return integer.to_bytes(_ULID_BYTES, "big")


def _empty_claims() -> dict[str, tuple[str, ...]]:
    return {}


@dataclass(slots=True)
class PlannedIdRegistry:
    """Detect distinct natural keys claiming one planned identifier."""

    _claims: dict[str, tuple[str, ...]] = field(
        default_factory=_empty_claims,
        init=False,
    )

    def claim(self, identifier: str, natural_key: Sequence[str]) -> None:
        """Record a claim, allowing only an idempotent claim by the same key."""
        stable_id = validate_planned_id(identifier)
        source = _validate_natural_key(natural_key)
        existing = self._claims.get(stable_id)
        if existing is None:
            self._claims[stable_id] = source
            return
        if existing != source:
            message = f"planned identifier collision: {stable_id}"
            raise IdentifierCollisionError(message)


def _validate_natural_key(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        message = "natural_key must be a nonempty sequence of strings"
        raise TypeError(message)
    if not value:
        message = "natural_key must not be empty"
        raise ValueError(message)
    components: list[str] = []
    for component in cast("Sequence[object]", value):
        if not isinstance(component, str):
            message = "natural_key components must be strings"
            raise TypeError(message)
        if not component:
            message = "natural_key components must not be empty"
            raise ValueError(message)
        if any(_SURROGATE_MIN <= ord(character) <= _SURROGATE_MAX for character in component):
            message = "natural_key components must contain Unicode scalar values"
            raise ValueError(message)
        if len(component.encode("utf-8")) > _MAX_NATURAL_KEY_BYTES:
            message = "natural_key component exceeds the 4096-byte boundary"
            raise ValueError(message)
        components.append(component)
    return tuple(components)


def _require_planned_kind(value: object) -> PlannedIdKind:
    if not isinstance(value, PlannedIdKind):
        message = "kind must be a PlannedIdKind"
        raise TypeError(message)
    return value


def _require_fresh_kind(value: object) -> FreshIdKind:
    if not isinstance(value, FreshIdKind):
        message = "kind must be a FreshIdKind"
        raise TypeError(message)
    return value


def _require_string(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        message = f"{name} must be a string"
        raise TypeError(message)
    return value
