"""Secure artifact snapshotting and transactional digest-registry replacement."""
# ruff: noqa: D401, FBT003, INP001, PLR2004, SIM105, TRY300, TRY301

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Final

from anyio import CancelScope
from anyio.lowlevel import checkpoint
from anyio.to_thread import run_sync

from webhook_receiver_conformance.domain.identifiers import validate_run_id
from webhook_receiver_conformance.errors import ErrorCategory, ResultCategory
from webhook_receiver_conformance.journal.service import (
    JournalService,
    JournalStatement,
    JournalTransaction,
)
from webhook_receiver_conformance.types import DiagnosticCode

DEFAULT_MAX_ARTIFACT_BYTES: Final = 67_108_864
DEFAULT_MAX_REGISTRY_BYTES: Final = 67_108_864
HARD_MAX_REGISTRY_BYTES: Final = 1_073_741_824
MAX_ARTIFACTS_PER_REPLACEMENT: Final = 128
MAX_RELATIVE_PATH_CHARACTERS: Final = 1_024
MAX_MEDIA_TYPE_CHARACTERS: Final = 255
MAX_RENDERER_VERSION_CHARACTERS: Final = 128
HASH_CHUNK_BYTES: Final = 65_536
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_MEDIA_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
_WINDOWS_RESERVED = re.compile(
    r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?",
    flags=re.IGNORECASE,
)
_WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_BINARY_FLAG = getattr(os, "O_BINARY", 0)
_NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY_FLAG = getattr(os, "O_DIRECTORY", 0)
_ARTIFACT_ID_DOMAIN = b"webhook-receiver-conformance:artifact-registry:v1\0"


class ArtifactRegistryError(RuntimeError):
    """A safe classified artifact snapshot or registry failure."""

    category: ErrorCategory = ErrorCategory.ARTIFACT_INTEGRITY_ERROR
    result_category: ResultCategory = ResultCategory.HARNESS_ERROR
    code: DiagnosticCode = DiagnosticCode("ARTIFACT_REGISTRY_ERROR")


class ArtifactPathError(ArtifactRegistryError):
    """An artifact path escaped containment or was not a private regular file."""

    code = DiagnosticCode("ARTIFACT_PATH_INVALID")


class ArtifactOutputLimitError(ArtifactRegistryError):
    """Artifact materialization exceeded a configured bounded output limit."""

    category = ErrorCategory.OUTPUT_LIMIT
    code = DiagnosticCode("ARTIFACT_OUTPUT_LIMIT")


class ArtifactRegistryIntegrityError(ArtifactRegistryError):
    """The committed registry or retained file identity did not match."""

    code = DiagnosticCode("ARTIFACT_REGISTRY_INTEGRITY")


@dataclass(frozen=True, slots=True)
class ArtifactRegistration:
    """One generated artifact to snapshot and register."""

    relative_path: str
    media_type: str
    generated_at: str
    input_watermark: str | None = None
    renderer_version: str | None = None

    def __post_init__(self) -> None:
        """Validate all metadata before filesystem or journal activity."""
        _validate_relative_path(self.relative_path)
        _validate_media_type(self.media_type)
        _validate_timestamp(self.generated_at)
        if self.input_watermark is not None and (
            type(self.input_watermark) is not str or _SHA256.fullmatch(self.input_watermark) is None
        ):
            message = "artifact input watermark must be a lowercase SHA-256 digest"
            raise ArtifactRegistryError(message)
        if self.renderer_version is not None:
            _validate_safe_text(
                self.renderer_version,
                field_name="renderer version",
                maximum=MAX_RENDERER_VERSION_CHARACTERS,
            )


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """One committed registry row derived from exact file bytes."""

    artifact_id: str
    run_id: str
    relative_path: str
    media_type: str
    byte_length: int
    sha256: str
    generated_at: str
    input_watermark: str | None
    renderer_version: str | None

    def __post_init__(self) -> None:
        """Reject malformed projections from SQLite or custom callers."""
        if (
            type(self.artifact_id) is not str
            or not 1 <= len(self.artifact_id) <= 96
            or any(
                character
                not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-"
                for character in self.artifact_id
            )
        ):
            message = "artifact ID is malformed"
            raise ArtifactRegistryIntegrityError(message)
        validate_run_id(self.run_id)
        _validate_relative_path(self.relative_path)
        _validate_media_type(self.media_type)
        if type(self.byte_length) is not int or self.byte_length < 0:
            message = "artifact byte length is malformed"
            raise ArtifactRegistryIntegrityError(message)
        if type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None:
            message = "artifact digest is malformed"
            raise ArtifactRegistryIntegrityError(message)
        _validate_timestamp(self.generated_at)
        if self.input_watermark is not None and (
            type(self.input_watermark) is not str or _SHA256.fullmatch(self.input_watermark) is None
        ):
            message = "artifact watermark is malformed"
            raise ArtifactRegistryIntegrityError(message)
        if self.renderer_version is not None:
            _validate_safe_text(
                self.renderer_version,
                field_name="renderer version",
                maximum=MAX_RENDERER_VERSION_CHARACTERS,
            )


@dataclass(frozen=True, slots=True)
class ArtifactRegistryLimits:
    """Bounded file count and total bytes for one atomic replacement."""

    max_artifacts: int = MAX_ARTIFACTS_PER_REPLACEMENT
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES
    max_total_bytes: int = DEFAULT_MAX_REGISTRY_BYTES

    def __post_init__(self) -> None:
        """Reject unbounded or contradictory registry limits."""
        _bounded_integer(
            self.max_artifacts,
            field_name="artifact count",
            minimum=1,
            maximum=MAX_ARTIFACTS_PER_REPLACEMENT,
        )
        _bounded_integer(
            self.max_artifact_bytes,
            field_name="artifact byte limit",
            minimum=1,
            maximum=HARD_MAX_REGISTRY_BYTES,
        )
        _bounded_integer(
            self.max_total_bytes,
            field_name="registry byte limit",
            minimum=1,
            maximum=HARD_MAX_REGISTRY_BYTES,
        )
        if self.max_artifact_bytes > self.max_total_bytes:
            message = "per-artifact limit cannot exceed the registry total limit"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    device: int
    inode: int
    byte_length: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int


@dataclass(slots=True)
class _PreparedArtifact:
    descriptor: int
    target: Path
    record: ArtifactRecord
    descriptor_snapshot: _FileSnapshot
    path_snapshot: _FileSnapshot

    def verify(self) -> None:
        """Revalidate retained descriptor and pathname without reading file data."""
        try:
            descriptor_metadata = os.fstat(self.descriptor)
            path_metadata = self.target.stat(follow_symlinks=False)
        except OSError as error:
            message = "artifact became unavailable after secure snapshotting"
            raise ArtifactRegistryIntegrityError(message) from error
        if (
            not _private_regular_file(descriptor_metadata)
            or not _private_regular_file(path_metadata)
            or _snapshot(descriptor_metadata) != self.descriptor_snapshot
            or _snapshot(path_metadata) != self.path_snapshot
            or not _same_file_content_identity(
                self.descriptor_snapshot,
                self.path_snapshot,
            )
        ):
            message = "artifact identity or bytes changed during registry replacement"
            raise ArtifactRegistryIntegrityError(message)

    def close(self) -> None:
        """Close the retained descriptor exactly once."""
        descriptor = self.descriptor
        self.descriptor = -1
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class _ReplaceArtifactRegistry:
    run_id: str
    prepared: tuple[_PreparedArtifact, ...]

    def execute(
        self,
        transaction: JournalTransaction,
    ) -> tuple[ArtifactRecord, ...]:
        """Perform constant-time identity checks and one bounded SQL replacement."""
        for item in self.prepared:
            item.verify()
        run = transaction.execute(
            JournalStatement(
                "SELECT 1 FROM runs WHERE run_id = ?",
                (self.run_id,),
            )
        )
        if run.rows != ((1,),):
            message = "artifact registry run does not exist"
            raise ArtifactRegistryIntegrityError(message)
        transaction.execute(
            JournalStatement(
                "DELETE FROM artifacts WHERE run_id = ?",
                (self.run_id,),
            )
        )
        for item in self.prepared:
            record = item.record
            transaction.execute(
                JournalStatement(
                    """
                    INSERT INTO artifacts (
                        artifact_id, run_id, relative_path, media_type,
                        byte_length, sha256, generated_at,
                        input_watermark, renderer_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.artifact_id,
                        record.run_id,
                        record.relative_path,
                        record.media_type,
                        record.byte_length,
                        record.sha256,
                        record.generated_at,
                        record.input_watermark,
                        record.renderer_version,
                    ),
                )
            )
        result = transaction.execute(
            JournalStatement(
                """
                SELECT artifact_id, run_id, relative_path, media_type,
                       byte_length, sha256, generated_at,
                       input_watermark, renderer_version
                FROM artifacts
                WHERE run_id = ?
                ORDER BY relative_path
                """,
                (self.run_id,),
            )
        )
        committed = tuple(_record_from_row(row) for row in result.rows)
        expected = tuple(sorted((item.record for item in self.prepared), key=_record_path))
        if committed != expected:
            message = "artifact registry rows do not match the prepared file snapshots"
            raise ArtifactRegistryIntegrityError(message)
        return committed


class ArtifactRegistry:
    """Bind secure file snapshots to the service-owned journal transaction."""

    __slots__ = ("_limits", "_run_directory", "_run_directory_identity", "_service")

    def __init__(
        self,
        *,
        service: JournalService,
        run_directory: str | os.PathLike[str],
        limits: ArtifactRegistryLimits | None = None,
    ) -> None:
        """Validate stable service, path, and resource boundaries."""
        if type(service) is not JournalService:
            message = "artifact registry requires a JournalService"
            raise TypeError(message)
        self._service = service
        self._run_directory, self._run_directory_identity = _validated_run_directory(run_directory)
        self._limits = ArtifactRegistryLimits() if limits is None else limits
        if type(self._limits) is not ArtifactRegistryLimits:
            message = "artifact registry limits must be ArtifactRegistryLimits"
            raise TypeError(message)

    async def replace(
        self,
        run_id: str,
        registrations: tuple[ArtifactRegistration, ...],
    ) -> tuple[ArtifactRecord, ...]:
        """Replace one run's complete registry in one writer transaction."""
        stable_run_id = validate_run_id(run_id)
        stable_registrations = _validate_registrations(
            registrations,
            limits=self._limits,
        )
        prepared: tuple[_PreparedArtifact, ...] = ()
        with CancelScope(shield=True):
            prepared = await run_sync(
                partial(
                    _prepare_artifacts,
                    self._run_directory,
                    self._run_directory_identity,
                    stable_run_id,
                    stable_registrations,
                    self._limits,
                ),
                abandon_on_cancel=False,
            )
        try:
            # Snapshotting is pre-transaction work. Deliver cancellation that
            # arrived while the descriptor was shielded before accepting a journal
            # mutation; once execute() accepts the write, commit-wins applies.
            await checkpoint()
            committed = await self._service.execute(
                _ReplaceArtifactRegistry(
                    run_id=stable_run_id,
                    prepared=prepared,
                )
            )
            for item in prepared:
                item.verify()
            return committed
        finally:
            for item in prepared:
                item.close()


async def replace_artifact_registry(
    service: JournalService,
    run_directory: str | os.PathLike[str],
    run_id: str,
    registrations: tuple[ArtifactRegistration, ...],
    *,
    limits: ArtifactRegistryLimits | None = None,
) -> tuple[ArtifactRecord, ...]:
    """Convenience entry point for one complete transactional replacement."""
    registry = ArtifactRegistry(
        service=service,
        run_directory=run_directory,
        limits=limits,
    )
    return await registry.replace(run_id, registrations)


def _prepare_artifacts(
    root: Path,
    root_identity: _DirectoryIdentity,
    run_id: str,
    registrations: tuple[ArtifactRegistration, ...],
    limits: ArtifactRegistryLimits,
) -> tuple[_PreparedArtifact, ...]:
    prepared: list[_PreparedArtifact] = []
    total_bytes = 0
    try:
        _verify_run_directory(root, expected=root_identity)
        for registration in registrations:
            parts = PurePosixPath(registration.relative_path).parts
            descriptor, target = _open_contained_file(root, parts)
            try:
                _verify_run_directory(root, expected=root_identity)
                metadata = os.fstat(descriptor)
                if not _private_regular_file(metadata):
                    message = "generated artifact must be one private regular file"
                    raise ArtifactPathError(message)
                if metadata.st_size > limits.max_artifact_bytes:
                    message = "generated artifact exceeds its output byte limit"
                    raise ArtifactOutputLimitError(message)
                total_bytes += metadata.st_size
                if total_bytes > limits.max_total_bytes:
                    message = "generated artifact set exceeds its total output byte limit"
                    raise ArtifactOutputLimitError(message)
                digest, observed_bytes = _hash_descriptor(
                    descriptor,
                    maximum=limits.max_artifact_bytes,
                )
                after = os.fstat(descriptor)
                if (
                    observed_bytes != metadata.st_size
                    or _snapshot(after) != _snapshot(metadata)
                    or not _private_regular_file(after)
                ):
                    message = "generated artifact changed while it was hashed"
                    raise ArtifactRegistryIntegrityError(message)
                path_metadata = target.stat(follow_symlinks=False)
                descriptor_snapshot = _snapshot(after)
                path_snapshot = _snapshot(path_metadata)
                if not _private_regular_file(path_metadata) or not _same_file_content_identity(
                    path_snapshot,
                    descriptor_snapshot,
                ):
                    message = "generated artifact path changed while it was hashed"
                    raise ArtifactRegistryIntegrityError(message)
                record = ArtifactRecord(
                    artifact_id=_artifact_id(run_id, registration.relative_path),
                    run_id=run_id,
                    relative_path=registration.relative_path,
                    media_type=registration.media_type,
                    byte_length=observed_bytes,
                    sha256=digest,
                    generated_at=registration.generated_at,
                    input_watermark=registration.input_watermark,
                    renderer_version=registration.renderer_version,
                )
            except BaseException:
                os.close(descriptor)
                raise
            prepared.append(
                _PreparedArtifact(
                    descriptor=descriptor,
                    target=target,
                    record=record,
                    descriptor_snapshot=descriptor_snapshot,
                    path_snapshot=path_snapshot,
                )
            )
        return tuple(prepared)
    except BaseException:
        for item in prepared:
            item.close()
        raise


def _open_contained_file(root: Path, parts: tuple[str, ...]) -> tuple[int, Path]:
    target = root.joinpath(*parts)
    if os.name != "posix":
        before = _safe_lstat(target)
        descriptor = _open_readonly(target)
        try:
            after = _safe_lstat(target)
            descriptor_metadata = os.fstat(descriptor)
            if not _same_file_content_identity(
                _snapshot(before),
                _snapshot(after),
            ) or not _same_file_content_identity(
                _snapshot(after),
                _snapshot(descriptor_metadata),
            ):
                message = "artifact path changed during secure open"
                raise ArtifactPathError(message)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, target

    directory_descriptors: list[int] = []
    try:
        directory_descriptor = os.open(
            root,
            os.O_RDONLY | _DIRECTORY_FLAG | _NOFOLLOW_FLAG,
        )
        directory_descriptors.append(directory_descriptor)
        for component in parts[:-1]:
            directory_descriptor = os.open(
                component,
                os.O_RDONLY | _DIRECTORY_FLAG | _NOFOLLOW_FLAG,
                dir_fd=directory_descriptor,
            )
            directory_descriptors.append(directory_descriptor)
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | _BINARY_FLAG | _NOFOLLOW_FLAG,
            dir_fd=directory_descriptor,
        )
        os.set_inheritable(descriptor, False)
        return descriptor, target
    except OSError as error:
        message = "artifact path is unavailable or traverses a link"
        raise ArtifactPathError(message) from error
    finally:
        for directory_descriptor in reversed(directory_descriptors):
            try:
                os.close(directory_descriptor)
            except OSError:
                pass


def _open_readonly(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | _BINARY_FLAG | _NOFOLLOW_FLAG,
        )
        os.set_inheritable(descriptor, False)
        return descriptor
    except OSError as error:
        message = "artifact path is unavailable or unsafe to open"
        raise ArtifactPathError(message) from error


def _hash_descriptor(descriptor: int, *, maximum: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    observed = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, min(HASH_CHUNK_BYTES, maximum - observed + 1))
        if not chunk:
            break
        observed += len(chunk)
        if observed > maximum:
            message = "generated artifact exceeds its output byte limit"
            raise ArtifactOutputLimitError(message)
        digest.update(chunk)
    return f"sha256:{digest.hexdigest()}", observed


def _validated_run_directory(
    value: str | os.PathLike[str],
) -> tuple[Path, _DirectoryIdentity]:
    try:
        raw = os.fspath(value)
    except TypeError as error:
        message = "run directory must be a filesystem path"
        raise ArtifactPathError(message) from error
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if type(raw) is not str or not raw or "\x00" in raw or len(raw) > 4_096:
        message = "run directory path is empty, malformed, or unbounded"
        raise ArtifactPathError(message)
    path = Path(raw).absolute()
    current = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        current /= part
        metadata = _safe_lstat(current)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or (current == path and not stat.S_ISDIR(metadata.st_mode))
        ):
            message = "run directory cannot traverse links or non-directories"
            raise ArtifactPathError(message)
    metadata = _safe_lstat(path)
    return path, _directory_identity(metadata)


def _verify_run_directory(
    path: Path,
    *,
    expected: _DirectoryIdentity,
) -> None:
    current, identity = _validated_run_directory(path)
    if current != path or identity != expected:
        message = "run directory identity changed during artifact snapshotting"
        raise ArtifactPathError(message)


def _validate_registrations(
    value: tuple[ArtifactRegistration, ...],
    *,
    limits: ArtifactRegistryLimits,
) -> tuple[ArtifactRegistration, ...]:
    if (
        type(value) is not tuple
        or not 1 <= len(value) <= limits.max_artifacts
        or any(type(item) is not ArtifactRegistration for item in value)
    ):
        message = "artifact registrations must be a bounded nonempty tuple"
        raise ArtifactRegistryError(message)
    paths = tuple(item.relative_path for item in value)
    comparison_paths = tuple(os.path.normcase(path) for path in paths)
    if len(paths) != len(set(paths)) or len(paths) != len(set(comparison_paths)):
        message = "artifact registration paths must be unique"
        raise ArtifactRegistryError(message)
    return value


def _validate_relative_path(value: object) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_RELATIVE_PATH_CHARACTERS
        or "\\" in value
        or ":" in value
        or _contains_control(value)
        or unicodedata.normalize("NFC", value) != value
    ):
        message = "artifact relative path is malformed or unbounded"
        raise ArtifactPathError(message)
    path = PurePosixPath(value)
    parts = path.parts
    if (
        path.is_absolute()
        or str(path) != value
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or any(_windows_reserved_component(part) for part in parts)
    ):
        message = "artifact path must be a normalized contained relative path"
        raise ArtifactPathError(message)


def _windows_reserved_component(value: str) -> bool:
    return value.endswith((" ", ".")) or _WINDOWS_RESERVED.fullmatch(value.rstrip(" .")) is not None


def _validate_media_type(value: object) -> None:
    if (
        type(value) is not str
        or not 3 <= len(value) <= MAX_MEDIA_TYPE_CHARACTERS
        or _contains_control(value)
    ):
        message = "artifact media type is malformed or unbounded"
        raise ArtifactRegistryError(message)
    try:
        value.encode("ascii")
    except UnicodeError as error:
        message = "artifact media type must be ASCII"
        raise ArtifactRegistryError(message) from error
    main, separator, parameters = value.partition(";")
    media_type, slash, subtype = main.partition("/")
    if (
        slash != "/"
        or _MEDIA_TOKEN.fullmatch(media_type) is None
        or _MEDIA_TOKEN.fullmatch(subtype) is None
    ):
        message = "artifact media type must contain valid type and subtype tokens"
        raise ArtifactRegistryError(message)
    if separator:
        for parameter in parameters.split(";"):
            name, equals, parameter_value = parameter.strip().partition("=")
            if (
                equals != "="
                or _MEDIA_TOKEN.fullmatch(name) is None
                or not parameter_value
                or _contains_control(parameter_value)
            ):
                message = "artifact media type parameter is malformed"
                raise ArtifactRegistryError(message)


def _validate_timestamp(value: object) -> None:
    if type(value) is not str or _UTC_TIMESTAMP.fullmatch(value) is None:
        message = "artifact generated_at must be a bounded UTC timestamp"
        raise ArtifactRegistryError(message)
    try:
        datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as error:
        message = "artifact generated_at is not a real UTC timestamp"
        raise ArtifactRegistryError(message) from error


def _validate_safe_text(value: str, *, field_name: str, maximum: int) -> None:
    if not 1 <= len(value) <= maximum or _contains_control(value):
        message = f"artifact {field_name} is empty, unsafe, or unbounded"
        raise ArtifactRegistryError(message)


def _contains_control(value: str) -> bool:
    return any(
        ord(character) < 32 or ord(character) == 127 or unicodedata.category(character) == "Cf"
        for character in value
    )


def _safe_lstat(path: Path) -> os.stat_result:
    try:
        return path.stat(follow_symlinks=False)
    except OSError as error:
        message = "artifact path contains an unavailable component"
        raise ArtifactPathError(message) from error


def _private_regular_file(metadata: os.stat_result) -> bool:
    return stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and not _is_reparse(metadata)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)


def _snapshot(metadata: os.stat_result) -> _FileSnapshot:
    return _FileSnapshot(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        byte_length=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _same_file_content_identity(
    left: _FileSnapshot,
    right: _FileSnapshot,
) -> bool:
    """Compare cross-view file facts while retaining view-local ctime evidence."""
    return (
        left.device == right.device
        and left.inode == right.inode
        and left.byte_length == right.byte_length
        and left.modified_ns == right.modified_ns
    )


def _directory_identity(metadata: os.stat_result) -> _DirectoryIdentity:
    if not stat.S_ISDIR(metadata.st_mode):
        message = "run directory is not a directory"
        raise ArtifactPathError(message)
    return _DirectoryIdentity(device=metadata.st_dev, inode=metadata.st_ino)


def _artifact_id(run_id: str, relative_path: str) -> str:
    digest = hashlib.sha256()
    digest.update(_ARTIFACT_ID_DOMAIN)
    digest.update(run_id.encode("ascii"))
    digest.update(b"\0")
    digest.update(relative_path.encode("utf-8"))
    return f"artifact_{digest.hexdigest()[:32]}"


def _record_path(record: ArtifactRecord) -> str:
    return record.relative_path


def _record_from_row(row: tuple[object, ...]) -> ArtifactRecord:
    if len(row) != 9:
        message = "artifact registry query returned an invalid row shape"
        raise ArtifactRegistryIntegrityError(message)
    (
        artifact_id,
        run_id,
        relative_path,
        media_type,
        byte_length,
        sha256,
        generated_at,
        input_watermark,
        renderer_version,
    ) = row
    if (
        type(artifact_id) is not str
        or type(run_id) is not str
        or type(relative_path) is not str
        or type(media_type) is not str
        or type(byte_length) is not int
        or type(sha256) is not str
        or type(generated_at) is not str
        or (input_watermark is not None and type(input_watermark) is not str)
        or (renderer_version is not None and type(renderer_version) is not str)
    ):
        message = "artifact registry query returned invalid field types"
        raise ArtifactRegistryIntegrityError(message)
    return ArtifactRecord(
        artifact_id=artifact_id,
        run_id=run_id,
        relative_path=relative_path,
        media_type=media_type,
        byte_length=byte_length,
        sha256=sha256,
        generated_at=generated_at,
        input_watermark=input_watermark,
        renderer_version=renderer_version,
    )


def _bounded_integer(
    value: object,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        message = f"{field_name} must be an integer from {minimum} through {maximum}"
        raise ValueError(message)
