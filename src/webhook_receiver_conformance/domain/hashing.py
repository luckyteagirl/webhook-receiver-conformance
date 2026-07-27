"""Canonical manifest and prefixed SHA-256 hashing primitives."""
# ruff: noqa: INP001

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import cast

SHA256_PREFIX = "sha256:"
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MANIFEST_ID = re.compile(r"[0-9a-f]{64}")
_MAX_IJSON_INTEGER = (1 << 53) - 1
_SURROGATE_MIN = 0xD800
_SURROGATE_MAX = 0xDFFF

type CanonicalJson = bool | int | str | list[CanonicalJson] | dict[str, CanonicalJson] | None


def sha256_digest(value: bytes) -> str:
    """Return a schema-compatible prefixed SHA-256 digest."""
    if not isinstance(value, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
        message = "digest input must be bytes"
        raise TypeError(message)
    return f"{SHA256_PREFIX}{hashlib.sha256(value).hexdigest()}"


def validate_sha256_digest(value: str) -> str:
    """Validate and return a prefixed lowercase SHA-256 digest."""
    text = _require_string(value, name="SHA-256 digest")
    if _SHA256_DIGEST.fullmatch(text) is None:
        message = "SHA-256 digest must use sha256: plus 64 lowercase hexadecimal characters"
        raise ValueError(message)
    return text


def validate_manifest_id(value: str) -> str:
    """Validate and return a raw lowercase manifest SHA-256 identifier."""
    text = _require_string(value, name="manifest_id")
    if _MANIFEST_ID.fullmatch(text) is None:
        message = "manifest_id must contain 64 lowercase hexadecimal characters"
        raise ValueError(message)
    return text


def canonical_json_bytes(value: CanonicalJson) -> bytes:
    """Serialize the lossless I-JSON subset used by valid manifests.

    Floating-point values and integers outside the exactly interoperable
    binary64 integer range are rejected instead of being rounded.
    """
    return _encode_canonical(value, active_containers=set()).encode("utf-8")


def canonical_manifest_bytes(manifest: Mapping[str, object]) -> bytes:
    """Canonicalize an immutable manifest, omitting only root ``manifest_id``.

    ``run_id`` is execution/journal identity and is prohibited from the
    immutable manifest rather than silently excluded from its content hash.
    """
    if not isinstance(manifest, Mapping):  # pyright: ignore[reportUnnecessaryIsInstance]
        message = "manifest must be a mapping"
        raise TypeError(message)
    projected: dict[str, CanonicalJson] = {}
    for key, value in manifest.items():
        if not isinstance(key, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            message = "manifest object keys must be strings"
            raise TypeError(message)
        if key == "run_id":
            message = "run_id is execution identity and must not appear in an immutable manifest"
            raise ValueError(message)
        if key != "manifest_id":
            projected[key] = _validate_json_value(value, active_containers=set())
    return canonical_json_bytes(projected)


def compute_manifest_id(manifest: Mapping[str, object]) -> str:
    """Hash the canonical manifest projection as raw lowercase hexadecimal."""
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def _encode_canonical(value: CanonicalJson, *, active_containers: set[int]) -> str:
    if isinstance(value, list):
        return _encode_array(value, active_containers=active_containers)
    if isinstance(value, dict):
        return _encode_object(value, active_containers=active_containers)
    return _encode_scalar(value)


def _encode_scalar(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not -_MAX_IJSON_INTEGER <= value <= _MAX_IJSON_INTEGER:
            message = "canonical JSON integer exceeds the lossless I-JSON range"
            raise ValueError(message)
        return str(value)
    if isinstance(value, str):
        _validate_unicode_scalar_string(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    message = f"unsupported canonical JSON value type: {type(value).__name__}"
    raise TypeError(message)


def _encode_array(value: list[CanonicalJson], *, active_containers: set[int]) -> str:
    marker = id(value)
    if marker in active_containers:
        message = "canonical JSON must not contain reference cycles"
        raise ValueError(message)
    active_containers.add(marker)
    try:
        return (
            "["
            + ",".join(
                _encode_canonical(item, active_containers=active_containers) for item in value
            )
            + "]"
        )
    finally:
        active_containers.remove(marker)


def _encode_object(value: dict[str, CanonicalJson], *, active_containers: set[int]) -> str:
    marker = id(value)
    if marker in active_containers:
        message = "canonical JSON must not contain reference cycles"
        raise ValueError(message)
    active_containers.add(marker)
    try:
        encoded_members: list[str] = []
        for key in sorted(value, key=_utf16_sort_key):
            encoded_key = _encode_canonical(key, active_containers=active_containers)
            encoded_value = _encode_canonical(value[key], active_containers=active_containers)
            encoded_members.append(f"{encoded_key}:{encoded_value}")
        return "{" + ",".join(encoded_members) + "}"
    finally:
        active_containers.remove(marker)


def _validate_json_value(
    value: object,
    *,
    active_containers: set[int],
) -> CanonicalJson:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        message = "canonical manifest JSON does not permit floating-point values"
        raise TypeError(message)
    if isinstance(value, list):
        items = cast("list[object]", value)
        marker = id(items)
        if marker in active_containers:
            message = "canonical JSON must not contain reference cycles"
            raise ValueError(message)
        active_containers.add(marker)
        try:
            return [
                _validate_json_value(item, active_containers=active_containers) for item in items
            ]
        finally:
            active_containers.remove(marker)
    if isinstance(value, dict):
        items = cast("dict[object, object]", value)
        marker = id(items)
        if marker in active_containers:
            message = "canonical JSON must not contain reference cycles"
            raise ValueError(message)
        active_containers.add(marker)
        converted: dict[str, CanonicalJson] = {}
        try:
            for key, item in items.items():
                if not isinstance(key, str):
                    message = "canonical JSON object keys must be strings"
                    raise TypeError(message)
                converted[key] = _validate_json_value(
                    item,
                    active_containers=active_containers,
                )
            return converted
        finally:
            active_containers.remove(marker)
    message = f"unsupported canonical JSON value type: {type(value).__name__}"
    raise TypeError(message)


def _utf16_sort_key(value: str) -> bytes:
    _validate_unicode_scalar_string(value)
    return value.encode("utf-16-be")


def _validate_unicode_scalar_string(value: str) -> None:
    if any(_SURROGATE_MIN <= ord(character) <= _SURROGATE_MAX for character in value):
        message = "canonical JSON strings must contain Unicode scalar values"
        raise ValueError(message)


def _require_string(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        message = f"{name} must be a string"
        raise TypeError(message)
    return value
