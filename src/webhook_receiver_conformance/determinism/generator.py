"""Versioned, stateless deterministic generation for non-secret test data.

This generator is not suitable for signing keys, tokens, passwords, or other
security secrets. Its purpose is reproducible conformance-test planning.
"""
# ruff: noqa: INP001

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

ALGORITHM_ID = "hmac-sha256-context-v1"
MESSAGE_DOMAIN_SEPARATOR = b"wrch-prng-v1\x00"
SEED_FINGERPRINT_DOMAIN_SEPARATOR = b"seed-fingerprint-v1\x00"
INITIAL_COUNTER = 0

_DIGEST_SIZE = hashlib.sha256().digest_size
_NORMALIZED_SEED_SIZE = _DIGEST_SIZE
_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1


def normalize_text_seed(seed: str) -> bytes:
    """Normalize a textual seed to the frozen 32-byte generator key."""
    text = _validate_text(seed, name="text seed")
    return hashlib.sha256(text.encode("utf-8")).digest()


def validate_normalized_seed_hash(seed_hash: bytes) -> bytes:
    """Return an immutable, validated normalized seed hash."""
    if not isinstance(seed_hash, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
        message = "normalized seed hash must be bytes"
        raise TypeError(message)
    if len(seed_hash) != _NORMALIZED_SEED_SIZE:
        message = "normalized seed hash must be exactly 32 bytes"
        raise ValueError(message)
    return seed_hash


def seed_fingerprint(seed_hash: bytes) -> str:
    """Return the stable, non-secret fingerprint of a normalized seed hash."""
    normalized = validate_normalized_seed_hash(seed_hash)
    return hashlib.sha256(SEED_FINGERPRINT_DOMAIN_SEPARATOR + normalized).hexdigest()


def encode_context(context: Sequence[str]) -> bytes:
    """Encode a nonempty UTF-8 context path with uint32 big-endian lengths."""
    components = _validate_context(context)

    encoded = bytearray()
    for component in components:
        component_bytes = component.encode("utf-8")
        component_length = len(component_bytes)
        if component_length > _UINT32_MAX:
            message = "context component exceeds uint32 byte length"
            raise ValueError(message)
        encoded.extend(component_length.to_bytes(4, "big"))
        encoded.extend(component_bytes)
    return bytes(encoded)


@dataclass(frozen=True, slots=True)
class ContextGenerator:
    """A stateless HMAC-SHA256 context generator for reproducible test data."""

    normalized_seed_hash: bytes

    def __post_init__(self) -> None:
        """Validate the key even when the constructor is called directly."""
        validate_normalized_seed_hash(self.normalized_seed_hash)

    @classmethod
    def from_text_seed(cls, seed: str) -> ContextGenerator:
        """Build a generator from a UTF-8 textual seed."""
        return cls(normalize_text_seed(seed))

    @classmethod
    def from_normalized_seed_hash(cls, seed_hash: bytes) -> ContextGenerator:
        """Build a generator from an already normalized 32-byte seed hash."""
        return cls(validate_normalized_seed_hash(seed_hash))

    @property
    def algorithm_id(self) -> str:
        """Return the frozen generator algorithm identifier."""
        return ALGORITHM_ID

    @property
    def fingerprint(self) -> str:
        """Return the stable non-secret seed fingerprint."""
        return seed_fingerprint(self.normalized_seed_hash)

    def draw_bytes(self, context: Sequence[str], length: int) -> bytes:
        """Return exactly ``length`` deterministic bytes for ``context``."""
        requested_length = _validate_nonnegative_integer(length, name="length")
        encoded_context = encode_context(context)
        block_count = (requested_length + _DIGEST_SIZE - 1) // _DIGEST_SIZE
        if block_count > _UINT64_MAX - INITIAL_COUNTER + 1:
            message = "requested length exceeds the uint64 counter space"
            raise OverflowError(message)
        if requested_length == 0:
            return b""

        output = bytearray()
        for counter in range(INITIAL_COUNTER, INITIAL_COUNTER + block_count):
            output.extend(self._block(encoded_context, counter))
        return bytes(output[:requested_length])

    def bounded_int(
        self,
        context: Sequence[str],
        lower: int,
        upper: int,
    ) -> int:
        """Sample an unbiased integer from the half-open range [lower, upper)."""
        lower_bound = _validate_integer(lower, name="lower")
        upper_bound = _validate_integer(upper, name="upper")
        if lower_bound >= upper_bound:
            message = "bounded range must satisfy lower < upper"
            raise ValueError(message)

        encoded_context = encode_context(context)
        span = upper_bound - lower_bound
        width = max(1, ((span - 1).bit_length() + 7) // 8)
        sample_space = 1 << (width * 8)
        rejection_limit = sample_space - (sample_space % span)

        offset = 0
        while True:
            candidate = int.from_bytes(
                self._stream_slice(encoded_context, offset, width),
                "big",
            )
            if candidate < rejection_limit:
                return lower_bound + (candidate % span)
            offset += width

    def signed_retry_jitter(
        self,
        *,
        scenario_id: str,
        planned_delivery_id: str,
        attempt_ordinal: int,
        jitter_policy_version: str,
        magnitude_bound: int,
    ) -> int:
        """Return jitter in the inclusive range [-magnitude_bound, +bound]."""
        scenario = _validate_nonempty_text(scenario_id, name="scenario_id")
        delivery = _validate_nonempty_text(
            planned_delivery_id,
            name="planned_delivery_id",
        )
        policy = _validate_nonempty_text(
            jitter_policy_version,
            name="jitter_policy_version",
        )
        ordinal = _validate_nonnegative_integer(
            attempt_ordinal,
            name="attempt_ordinal",
        )
        if ordinal > _UINT64_MAX:
            message = "attempt_ordinal exceeds uint64"
            raise OverflowError(message)
        bound = _validate_nonnegative_integer(
            magnitude_bound,
            name="magnitude_bound",
        )
        return self.bounded_int(
            (
                "retry-jitter",
                scenario,
                delivery,
                str(ordinal),
                policy,
            ),
            -bound,
            bound + 1,
        )

    def _block(self, encoded_context: bytes, counter: int) -> bytes:
        if counter < INITIAL_COUNTER or counter > _UINT64_MAX:
            message = "counter exceeds uint64"
            raise OverflowError(message)
        message = MESSAGE_DOMAIN_SEPARATOR + encoded_context + counter.to_bytes(8, "big")
        return hmac.digest(self.normalized_seed_hash, message, "sha256")

    def _stream_slice(
        self,
        encoded_context: bytes,
        offset: int,
        length: int,
    ) -> bytes:
        first_block = offset // _DIGEST_SIZE
        last_offset = offset + length
        block_count = (last_offset + _DIGEST_SIZE - 1) // _DIGEST_SIZE - first_block
        first_counter = INITIAL_COUNTER + first_block
        if first_counter > _UINT64_MAX or block_count > _UINT64_MAX - first_counter + 1:
            message = "rejection sampling exhausted the uint64 counter space"
            raise OverflowError(message)
        stream = b"".join(
            self._block(encoded_context, counter)
            for counter in range(first_counter, first_counter + block_count)
        )
        start = offset % _DIGEST_SIZE
        return stream[start : start + length]


def _validate_integer(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"{name} must be an integer"
        raise TypeError(message)
    return value


def _validate_nonnegative_integer(value: object, *, name: str) -> int:
    integer = _validate_integer(value, name=name)
    if integer < 0:
        message = f"{name} must be nonnegative"
        raise ValueError(message)
    return integer


def _validate_nonempty_text(value: object, *, name: str) -> str:
    text = _validate_text(value, name=name)
    if not text:
        message = f"{name} must not be empty"
        raise ValueError(message)
    return text


def _validate_text(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        message = f"{name} must be a string"
        raise TypeError(message)
    return value


def _validate_context(context: object) -> tuple[str, ...]:
    if isinstance(context, (str, bytes)) or not isinstance(context, Sequence):
        message = "context must be a sequence of strings"
        raise TypeError(message)
    if not context:
        message = "context path must not be empty"
        raise ValueError(message)
    validated: list[str] = []
    for component in cast("Sequence[object]", context):
        if not isinstance(component, str):
            message = "context components must be strings"
            raise TypeError(message)
        if not component:
            message = "context components must not be empty"
            raise ValueError(message)
        validated.append(component)
    return tuple(validated)
