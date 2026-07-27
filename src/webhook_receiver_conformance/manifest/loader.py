"""Bounded, side-effect-free loader for immutable replay bundles."""
# ruff: noqa: C901, D107, EM101, INP001, PLR0912, TRY003, TRY301

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, cast

from pydantic import ValidationError

from webhook_receiver_conformance.domain.hashing import (
    canonical_manifest_bytes,
    compute_manifest_id,
    sha256_digest,
)
from webhook_receiver_conformance.errors import (
    Diagnostic,
    ErrorCategory,
    ResultCategory,
)
from webhook_receiver_conformance.fixtures.blobs import (
    BlobSnapshot,
    BlobStore,
    BlobStoreError,
)
from webhook_receiver_conformance.fixtures.loader import HARD_MAX_FIXTURE_BYTES
from webhook_receiver_conformance.manifest.compiler import MANIFEST_FILENAME
from webhook_receiver_conformance.manifest.models import (
    RunManifest,
    validate_blob_entries,
)
from webhook_receiver_conformance.types import DiagnosticCode

MAX_MANIFEST_BYTES: Final = 16_777_216
MAX_MANIFEST_NODES: Final = 1_000_000
MAX_MANIFEST_DEPTH: Final = 64
MAX_BUNDLE_BLOBS: Final = 100_000
MAX_BUNDLE_BLOB_BYTES: Final = 1_073_741_824
SUPPORTED_MANIFEST_MAJOR: Final = 1
MAX_VERSION_COMPONENT_DIGITS: Final = 10
_NORMALIZED_VOLATILE_FIELDS: Final = frozenset({"created_at", "environment", "manifest_id"})
_WINDOWS_REPARSE_ATTRIBUTE: Final = 0x400
_READ_CHUNK_BYTES: Final = 1_048_576


class BundleLoadError(Exception):
    """A classified, privacy-safe replay bundle rejection."""

    diagnostic: Diagnostic

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.code)


@dataclass(frozen=True, slots=True)
class LoadedRunBundle:
    """Verified immutable replay inputs sourced only from bundle artifacts."""

    directory: Path
    manifest: RunManifest
    manifest_bytes: bytes = field(repr=False)
    blobs: tuple[BlobSnapshot, ...]
    normalized_digest: str


def load_replay_bundle(directory: Path) -> LoadedRunBundle:
    """Load and verify one bundle without source, secret, generator, or network access."""
    root = _validate_bundle_directory(directory)
    manifest_bytes = _read_manifest(root)
    wire = _parse_manifest(manifest_bytes)
    _verify_manifest_identity(wire)
    _require_supported_major(wire)
    try:
        manifest = RunManifest.from_wire(wire, verify=True)
        validate_blob_entries(manifest.blobs)
    except (TypeError, ValueError, ValidationError, RecursionError) as error:
        raise _invalid_manifest("MANIFEST_SCHEMA_INVALID") from error

    if len(manifest.blobs) > MAX_BUNDLE_BLOBS:
        raise _resource_error("MANIFEST_BLOB_COUNT_LIMIT", MAX_BUNDLE_BLOBS)
    declared_total = sum(entry.byte_length for entry in manifest.blobs)
    if declared_total > MAX_BUNDLE_BLOB_BYTES:
        raise _resource_error("MANIFEST_BLOB_TOTAL_LIMIT", MAX_BUNDLE_BLOB_BYTES)
    _verify_blob_references(manifest)

    store = BlobStore(root)
    snapshots: list[BlobSnapshot] = []
    for entry in manifest.blobs:
        if entry.byte_length > HARD_MAX_FIXTURE_BYTES:
            raise _resource_error("MANIFEST_BLOB_SIZE_LIMIT", HARD_MAX_FIXTURE_BYTES)
        snapshot = BlobSnapshot(
            sha256=entry.sha256,
            byte_length=entry.byte_length,
            media_type=entry.media_type,
            path=store.path_for(entry.sha256),
        )
        try:
            store.verify(snapshot)
        except BlobStoreError as error:
            raise BundleLoadError(error.diagnostic) from error
        snapshots.append(snapshot)

    return LoadedRunBundle(
        directory=root,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        blobs=tuple(snapshots),
        normalized_digest=normalized_manifest_digest(manifest),
    )


def normalized_manifest_digest(manifest: RunManifest) -> str:
    """Return the cross-version digest of all guaranteed immutable fields."""
    if type(manifest) is not RunManifest:
        raise TypeError("manifest must be a RunManifest")
    manifest.verify_id()
    projection = manifest.to_wire()
    for field_name in _NORMALIZED_VOLATILE_FIELDS:
        projection.pop(field_name, None)
    return sha256_digest(canonical_manifest_bytes(projection))


def _validate_bundle_directory(directory: Path) -> Path:
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        directory,
        Path,
    ):
        raise TypeError("directory must be a pathlib.Path")
    absolute = directory.absolute()
    try:
        metadata = absolute.lstat()
    except OSError as error:
        raise _path_error("BUNDLE_DIRECTORY_INVALID") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_windows_reparse(metadata)
    ):
        raise _path_error("BUNDLE_DIRECTORY_INVALID")
    return absolute


def _read_manifest(root: Path) -> bytes:
    directory_descriptor: int | None = None
    try:
        if os.name != "nt" and hasattr(os, "O_DIRECTORY"):
            directory_flags = (
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            directory_descriptor = os.open(root, directory_flags)
            before = os.stat(
                MANIFEST_FILENAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        else:
            before = (root / MANIFEST_FILENAME).lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_windows_reparse(before)
        ):
            raise OSError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            MANIFEST_FILENAME if directory_descriptor is not None else root / MANIFEST_FILENAME,
            flags,
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise _path_error("MANIFEST_FILE_INVALID") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size < 0
            or opened.st_size > MAX_MANIFEST_BYTES
            or not _same_file(before, opened)
        ):
            if opened.st_size > MAX_MANIFEST_BYTES:
                raise _resource_error("MANIFEST_BYTE_LIMIT", MAX_MANIFEST_BYTES)
            raise _path_error("MANIFEST_FILE_INVALID")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, MAX_MANIFEST_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_MANIFEST_BYTES:
                raise _resource_error("MANIFEST_BYTE_LIMIT", MAX_MANIFEST_BYTES)
        after = os.fstat(descriptor)
        if not _same_open_file(opened, after) or total != after.st_size:
            raise _path_error("MANIFEST_FILE_CHANGED")
        return b"".join(chunks)
    finally:
        os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _parse_manifest(value: bytes) -> dict[str, object]:
    try:
        parsed = json.loads(
            value.decode("utf-8"),
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except UnicodeDecodeError as error:
        raise _invalid_manifest("MANIFEST_UTF8_INVALID") from error
    except json.JSONDecodeError as error:
        raise _invalid_manifest("MANIFEST_JSON_INVALID") from error
    except RecursionError as error:
        raise _resource_error("MANIFEST_DEPTH_LIMIT", MAX_MANIFEST_DEPTH) from error
    except ValueError as error:
        raise _invalid_manifest("MANIFEST_JSON_INVALID") from error
    if type(parsed) is not dict:
        raise _invalid_manifest("MANIFEST_ROOT_INVALID")
    typed = cast("dict[str, object]", parsed)
    _validate_tree_bounds(typed)
    return typed


def _validate_tree_bounds(root: dict[str, object]) -> None:
    pending: list[tuple[object, int]] = [(root, 1)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_MANIFEST_NODES:
            raise _resource_error("MANIFEST_NODE_LIMIT", MAX_MANIFEST_NODES)
        if depth > MAX_MANIFEST_DEPTH:
            raise _resource_error("MANIFEST_DEPTH_LIMIT", MAX_MANIFEST_DEPTH)
        if type(value) is dict:
            pending.extend((item, depth + 1) for item in cast("dict[str, object]", value).values())
        elif type(value) is list:
            pending.extend((item, depth + 1) for item in cast("list[object]", value))


def _verify_manifest_identity(wire: dict[str, object]) -> None:
    manifest_id = wire.get("manifest_id")
    if type(manifest_id) is not str:
        raise _invalid_manifest("MANIFEST_ID_INVALID")
    try:
        computed = compute_manifest_id(wire)
    except (TypeError, ValueError, RecursionError) as error:
        raise _invalid_manifest("MANIFEST_CANONICAL_INVALID") from error
    if manifest_id != computed:
        raise _integrity_error("MANIFEST_ID_MISMATCH")


def _require_supported_major(wire: dict[str, object]) -> None:
    version = wire.get("schema_version")
    if type(version) is not str:
        raise _invalid_manifest("MANIFEST_VERSION_INVALID")
    major_text, separator, minor_text = version.partition(".")
    if (
        not separator
        or "." in minor_text
        or not _canonical_version_component(major_text)
        or not _canonical_version_component(minor_text)
    ):
        raise _invalid_manifest("MANIFEST_VERSION_INVALID")
    if major_text != str(SUPPORTED_MANIFEST_MAJOR):
        raise BundleLoadError(
            Diagnostic(
                category=ErrorCategory.UNSUPPORTED_SCHEMA,
                code=DiagnosticCode("MANIFEST_MAJOR_UNSUPPORTED"),
                message="The run manifest major version is unsupported.",
                retryable=False,
                safe_details={"supported_major": SUPPORTED_MANIFEST_MAJOR},
                result_category=ResultCategory.UNSUPPORTED,
                user_correctable=True,
                field_path="schema_version",
                corrective_action="Use a compatible harness version for this run bundle.",
            )
        )


def _canonical_version_component(value: str) -> bool:
    return (
        1 <= len(value) <= MAX_VERSION_COMPONENT_DIGITS
        and value.isascii()
        and value.isdecimal()
        and (value == "0" or not value.startswith("0"))
    )


def _verify_blob_references(manifest: RunManifest) -> None:
    declared = {entry.sha256 for entry in manifest.blobs}
    referenced = {
        event.fixture_blob for scenario in manifest.scenarios for event in scenario.events
    } | {
        attempt.request_blob
        for scenario in manifest.scenarios
        for delivery in scenario.deliveries
        for attempt in delivery.attempt_plan
    }
    if not referenced <= declared:
        raise _integrity_error("MANIFEST_BLOB_REFERENCE_MISSING")


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _same_open_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        _same_file(left, right)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def _is_windows_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & _WINDOWS_REPARSE_ATTRIBUTE)


def _reject_float(_value: str) -> object:
    raise ValueError("floating-point manifest values are prohibited")


def _reject_constant(_value: str) -> object:
    raise ValueError("non-finite manifest values are prohibited")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest object key")
        result[key] = value
    return result


def _invalid_manifest(code: str) -> BundleLoadError:
    return BundleLoadError(
        Diagnostic(
            category=ErrorCategory.SCHEMA_VALIDATION_ERROR,
            code=DiagnosticCode(code),
            message="The run manifest is malformed or violates its schema.",
            retryable=False,
            safe_details={},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="run-manifest.json",
            corrective_action="Re-plan the bundle with a compatible harness.",
        )
    )


def _integrity_error(code: str) -> BundleLoadError:
    return BundleLoadError(
        Diagnostic(
            category=ErrorCategory.ARTIFACT_INTEGRITY_ERROR,
            code=DiagnosticCode(code),
            message="The run bundle failed immutable artifact verification.",
            retryable=False,
            safe_details={},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="run-manifest.json",
            corrective_action="Re-plan the run bundle from trusted inputs.",
        )
    )


def _resource_error(code: str, maximum: int) -> BundleLoadError:
    return BundleLoadError(
        Diagnostic(
            category=ErrorCategory.RESOURCE_LIMIT,
            code=DiagnosticCode(code),
            message="The run bundle exceeds a bounded loader resource limit.",
            retryable=False,
            safe_details={"maximum": maximum},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="run-manifest.json",
            corrective_action="Reduce the bundle to the supported resource limits.",
        )
    )


def _path_error(code: str) -> BundleLoadError:
    return BundleLoadError(
        Diagnostic(
            category=ErrorCategory.ARTIFACT_INTEGRITY_ERROR,
            code=DiagnosticCode(code),
            message="The run bundle path is missing, unsafe, or changed during verification.",
            retryable=False,
            safe_details={},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="run-manifest.json",
            corrective_action="Use an intact local run bundle without links or path indirection.",
        )
    )


__all__ = [
    "BundleLoadError",
    "LoadedRunBundle",
    "load_replay_bundle",
    "normalized_manifest_digest",
]
