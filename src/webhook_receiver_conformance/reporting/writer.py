"""Atomic, local-only report installation and digest registration."""
# ruff: noqa: D105, D107, D401, EM101, EM102, FBT003, INP001, PLR0913, PLR2004, PTH105, TRY003

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

from anyio import CancelScope
from anyio.to_thread import run_sync

from webhook_receiver_conformance.domain.identifiers import validate_run_id
from webhook_receiver_conformance.errors import ErrorCategory, ResultCategory
from webhook_receiver_conformance.journal.artifacts import (
    ArtifactRecord,
    ArtifactRegistration,
    ArtifactRegistry,
    ArtifactRegistryLimits,
)
from webhook_receiver_conformance.journal.service import JournalService
from webhook_receiver_conformance.reporting.html import (
    HtmlReportDocument,
)
from webhook_receiver_conformance.reporting.json_reports import (
    JsonReportArtifacts,
)
from webhook_receiver_conformance.types import DiagnosticCode

if TYPE_CHECKING:
    from collections.abc import Callable

MAX_REPORT_ARTIFACT_BYTES: Final = 67_108_864
MAX_REPORT_SET_BYTES: Final = 67_108_864
REPORT_RENDERER_VERSION: Final = "reporter-1.0"
GOLDEN_COMPATIBILITY_REVIEW_MARKER: Final = "report-golden-compatibility-v1"
_BINARY_FLAG: Final = getattr(os, "O_BINARY", 0)
_NOFOLLOW_FLAG: Final = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY_FLAG: Final = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC_FLAG: Final = getattr(os, "O_CLOEXEC", 0)
_WINDOWS_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_NORMALIZED_DIGEST_DOMAIN: Final = b"webhook-receiver-conformance:normalized-report-set:v1\0"


class ReportWriterError(RuntimeError):
    """One classified, secret-safe report installation failure."""

    category: ErrorCategory = ErrorCategory.ARTIFACT_INTEGRITY_ERROR
    result_category: ResultCategory = ResultCategory.HARNESS_ERROR
    code: DiagnosticCode = DiagnosticCode("REPORT_WRITE_ERROR")


class ReportPathError(ReportWriterError):
    """The run directory or an artifact target failed confinement checks."""

    code = DiagnosticCode("REPORT_PATH_INVALID")


class ReportOutputLimitError(ReportWriterError):
    """The rendered report set exceeded its bounded output policy."""

    category = ErrorCategory.OUTPUT_LIMIT
    code = DiagnosticCode("REPORT_OUTPUT_LIMIT")


class ReportContractError(ReportWriterError):
    """Built-in reporter implementations and contract registrations differ."""

    code = DiagnosticCode("REPORT_CONTRACT_REGISTRY_INVALID")


class ReportWriteCheckpoint(Protocol):
    """Injectable crash point used by deterministic recovery tests."""

    def __call__(self, phase: str, relative_path: str) -> None:
        """Observe one bounded file-installation boundary."""


@dataclass(frozen=True, slots=True)
class ReporterContractRegistration:
    """One built-in report format and its mandatory compatibility evidence."""

    implementation_id: str
    artifact_paths: tuple[str, ...]
    contract_test_ids: tuple[str, ...]
    compatibility_review_marker: str

    def __post_init__(self) -> None:
        for value in (
            self.implementation_id,
            self.compatibility_review_marker,
        ):
            if (
                type(value) is not str
                or not value
                or len(value) > 128
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
            ):
                raise ReportContractError("report contract metadata is malformed")
        if (
            type(self.artifact_paths) is not tuple
            or not self.artifact_paths
            or any(type(value) is not str or not value for value in self.artifact_paths)
            or len(set(self.artifact_paths)) != len(self.artifact_paths)
        ):
            raise ReportContractError("report contract artifact paths are malformed")
        if (
            type(self.contract_test_ids) is not tuple
            or not self.contract_test_ids
            or any(
                type(value) is not str or not value.startswith("VT-")
                for value in self.contract_test_ids
            )
            or len(set(self.contract_test_ids)) != len(self.contract_test_ids)
        ):
            raise ReportContractError("report contract test identifiers are malformed")


BUILTIN_REPORTER_IMPLEMENTATIONS: Final = (
    "json-v1",
    "junit-v1",
    "html-v1",
)
BUILTIN_REPORTER_CONTRACTS: Final = (
    ReporterContractRegistration(
        implementation_id="json-v1",
        artifact_paths=(
            "run-manifest.json",
            "deliveries.jsonl",
            "observations.jsonl",
            "assertions.jsonl",
            "result-summary.json",
        ),
        contract_test_ids=(
            "VT-REPORT-001",
            "VT-REPORT-002",
            "VT-REPORT-003",
            "VT-REPORT-004",
            "VT-REPORT-005",
        ),
        compatibility_review_marker=GOLDEN_COMPATIBILITY_REVIEW_MARKER,
    ),
    ReporterContractRegistration(
        implementation_id="junit-v1",
        artifact_paths=("junit.xml",),
        contract_test_ids=("VT-REPORT-010", "VT-REPORT-011", "VT-REPORT-016"),
        compatibility_review_marker=GOLDEN_COMPATIBILITY_REVIEW_MARKER,
    ),
    ReporterContractRegistration(
        implementation_id="html-v1",
        artifact_paths=("results.html",),
        contract_test_ids=("VT-REPORT-017", "VT-REPORT-018", "VT-REPORT-019"),
        compatibility_review_marker=GOLDEN_COMPATIBILITY_REVIEW_MARKER,
    ),
)


def validate_reporter_contracts(
    implementations: tuple[str, ...] = BUILTIN_REPORTER_IMPLEMENTATIONS,
    registrations: tuple[
        ReporterContractRegistration,
        ...,
    ] = BUILTIN_REPORTER_CONTRACTS,
) -> None:
    """Fail closed when a built-in reporter lacks contract and review evidence."""
    if type(implementations) is not tuple or any(
        type(value) is not str or not value for value in implementations
    ):
        raise ReportContractError("reporter implementations must be a nonempty tuple")
    if type(registrations) is not tuple or any(
        type(value) is not ReporterContractRegistration for value in registrations
    ):
        raise ReportContractError("report contract registrations are malformed")
    implementation_ids = tuple(item.implementation_id for item in registrations)
    if (
        not implementations
        or len(set(implementations)) != len(implementations)
        or len(set(implementation_ids)) != len(implementation_ids)
        or set(implementations) != set(implementation_ids)
    ):
        raise ReportContractError("reporter implementations and contract registrations differ")
    if any(
        item.compatibility_review_marker != GOLDEN_COMPATIBILITY_REVIEW_MARKER
        for item in registrations
    ):
        raise ReportContractError("report golden compatibility review marker is missing")


@dataclass(frozen=True, slots=True)
class ReportPayloads:
    """The complete seven-file report set produced from one journal snapshot."""

    json_reports: JsonReportArtifacts
    junit_xml: bytes
    html_report: HtmlReportDocument

    def __post_init__(self) -> None:
        if type(self.json_reports) is not JsonReportArtifacts:
            raise TypeError("json_reports must be JsonReportArtifacts")
        if (
            type(self.junit_xml) is not bytes
            or not self.junit_xml
            or len(self.junit_xml) > MAX_REPORT_ARTIFACT_BYTES
        ):
            raise ReportOutputLimitError("JUnit output must be bounded nonempty bytes")
        if type(self.html_report) is not HtmlReportDocument:
            raise TypeError("html_report must be HtmlReportDocument")


@dataclass(frozen=True, slots=True)
class ReportWriteResult:
    """One completely installed and transactionally registered report set."""

    records: tuple[ArtifactRecord, ...]
    normalized_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.records) is not tuple
            or len(self.records) != len(_REPORT_FILE_SPECS)
            or any(type(value) is not ArtifactRecord for value in self.records)
        ):
            raise TypeError("records must contain the complete artifact registry")
        if (
            type(self.normalized_digest) is not str
            or _SHA256.fullmatch(self.normalized_digest) is None
        ):
            raise ValueError("normalized_digest must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class _ReportFileSpec:
    relative_path: str
    media_type: str


@dataclass(frozen=True, slots=True)
class _ReportFile:
    spec: _ReportFileSpec
    content: bytes


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _TargetIdentity:
    device: int
    inode: int
    mode: int
    links: int


_REPORT_FILE_SPECS: Final = (
    _ReportFileSpec("run-manifest.json", "application/json"),
    _ReportFileSpec("deliveries.jsonl", "application/x-ndjson"),
    _ReportFileSpec("observations.jsonl", "application/x-ndjson"),
    _ReportFileSpec("assertions.jsonl", "application/x-ndjson"),
    _ReportFileSpec("result-summary.json", "application/json"),
    _ReportFileSpec("junit.xml", "application/xml"),
    _ReportFileSpec("results.html", "text/html; charset=utf-8"),
)


class ReportWriter:
    """Install complete report sets without network access or run-state mutation."""

    __slots__ = (
        "_checkpoint",
        "_registry",
        "_renderer_version",
        "_run_directory",
        "_run_directory_identity",
    )

    def __init__(
        self,
        *,
        service: JournalService,
        run_directory: str | os.PathLike[str],
        registry_limits: ArtifactRegistryLimits | None = None,
        renderer_version: str = REPORT_RENDERER_VERSION,
        checkpoint: ReportWriteCheckpoint | None = None,
    ) -> None:
        validate_reporter_contracts()
        if type(service) is not JournalService:
            raise TypeError("report writer requires a JournalService")
        if (
            type(renderer_version) is not str
            or not renderer_version
            or len(renderer_version) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in renderer_version)
        ):
            raise ValueError("renderer_version must be bounded safe text")
        if checkpoint is not None and not callable(checkpoint):
            raise TypeError("checkpoint must be callable or None")
        directory, identity = _validated_run_directory(run_directory)
        self._run_directory = directory
        self._run_directory_identity = identity
        self._renderer_version = renderer_version
        self._checkpoint = checkpoint
        self._registry = ArtifactRegistry(
            service=service,
            run_directory=directory,
            limits=registry_limits,
        )

    async def regenerate(
        self,
        run_id: str,
        payloads: ReportPayloads,
    ) -> ReportWriteResult:
        """Atomically replace all targets, then replace their registry in one transaction."""
        stable_run_id = validate_run_id(run_id)
        if type(payloads) is not ReportPayloads:
            raise TypeError("payloads must be ReportPayloads")
        files = _report_files(payloads)
        normalized_digest = _normalized_digest(files)
        generated_at = _summary_generated_at(payloads.json_reports.result_summary_json)
        registrations = tuple(
            ArtifactRegistration(
                relative_path=item.spec.relative_path,
                media_type=item.spec.media_type,
                generated_at=generated_at,
                input_watermark=normalized_digest,
                renderer_version=self._renderer_version,
            )
            for item in files
        )
        records: tuple[ArtifactRecord, ...] = ()
        with CancelScope(shield=True):
            await run_sync(
                partial(
                    _install_report_files,
                    self._run_directory,
                    self._run_directory_identity,
                    files,
                    self._checkpoint,
                ),
                abandon_on_cancel=False,
            )
            records = await self._registry.replace(stable_run_id, registrations)
        expected_paths = tuple(sorted(item.spec.relative_path for item in files))
        if tuple(item.relative_path for item in records) != expected_paths:
            raise ReportWriterError("registered report paths differ from installed files")
        return ReportWriteResult(
            records=records,
            normalized_digest=normalized_digest,
        )


async def regenerate_reports(
    service: JournalService,
    run_directory: str | os.PathLike[str],
    run_id: str,
    payloads: ReportPayloads,
    *,
    registry_limits: ArtifactRegistryLimits | None = None,
    renderer_version: str = REPORT_RENDERER_VERSION,
) -> ReportWriteResult:
    """Convenience entry point for one local-only report regeneration."""
    writer = ReportWriter(
        service=service,
        run_directory=run_directory,
        registry_limits=registry_limits,
        renderer_version=renderer_version,
    )
    return await writer.regenerate(run_id, payloads)


def _report_files(payloads: ReportPayloads) -> tuple[_ReportFile, ...]:
    json_reports = payloads.json_reports
    values = (
        json_reports.manifest_json,
        json_reports.deliveries_jsonl,
        json_reports.observations_jsonl,
        json_reports.assertions_jsonl,
        json_reports.result_summary_json,
        payloads.junit_xml,
        payloads.html_report.content,
    )
    files = tuple(
        _ReportFile(spec=spec, content=content)
        for spec, content in zip(_REPORT_FILE_SPECS, values, strict=True)
    )
    total = 0
    for item in files:
        if type(item.content) is not bytes or len(item.content) > MAX_REPORT_ARTIFACT_BYTES:
            raise ReportOutputLimitError("one report artifact exceeds its byte limit")
        total += len(item.content)
        if total > MAX_REPORT_SET_BYTES:
            raise ReportOutputLimitError("complete report set exceeds its byte limit")
    return files


def _normalized_digest(files: tuple[_ReportFile, ...]) -> str:
    digest = hashlib.sha256(_NORMALIZED_DIGEST_DOMAIN)
    for item in files:
        path = item.spec.relative_path.encode()
        digest.update(len(path).to_bytes(4, "big"))
        digest.update(path)
        digest.update(len(item.content).to_bytes(8, "big"))
        digest.update(item.content)
    return f"sha256:{digest.hexdigest()}"


def _summary_generated_at(content: bytes) -> str:
    if len(content) > MAX_REPORT_ARTIFACT_BYTES:
        raise ReportOutputLimitError("result summary exceeds its byte limit")
    try:
        parsed: object = json.loads(
            content,
            parse_constant=_reject_non_json_number,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ReportWriterError("result summary is invalid JSON") from error
    if not isinstance(parsed, dict):
        raise ReportWriterError("result summary must be a JSON object")
    summary = cast("dict[str, object]", parsed)
    generated_at = summary.get("generated_at")
    if type(generated_at) is not str:
        raise ReportWriterError("result summary generated_at is missing")
    return generated_at


def _reject_non_json_number(value: str) -> object:
    raise ValueError(f"non-JSON numeric constant is forbidden: {value}")


def _validated_run_directory(
    value: str | os.PathLike[str],
) -> tuple[Path, _DirectoryIdentity]:
    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise ReportPathError("run directory must be a filesystem path") from error
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if type(raw) is not str or not raw or "\x00" in raw or len(raw) > 4_096:
        raise ReportPathError("run directory path is malformed or unbounded")
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
            raise ReportPathError("run directory cannot traverse links")
    if os.name == "posix":
        try:
            path.chmod(0o700)
        except OSError as error:
            raise ReportPathError("run directory permissions could not be tightened") from error
    metadata = _safe_lstat(path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReportPathError("run directory is not a directory")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ReportPathError("run directory is not owner-only")
    return path, _DirectoryIdentity(metadata.st_dev, metadata.st_ino)


def _verify_run_directory(path: Path, identity: _DirectoryIdentity) -> None:
    _, observed = _validated_run_directory(path)
    if observed != identity:
        raise ReportPathError("run directory identity changed during report generation")


def _install_report_files(
    root: Path,
    root_identity: _DirectoryIdentity,
    files: tuple[_ReportFile, ...],
    checkpoint: ReportWriteCheckpoint | None,
) -> None:
    _verify_run_directory(root, root_identity)
    if os.name == "posix":
        _install_report_files_posix(root, root_identity, files, checkpoint)
    else:
        _install_report_files_portable(root, root_identity, files, checkpoint)
    _verify_run_directory(root, root_identity)


def _install_report_files_posix(
    root: Path,
    root_identity: _DirectoryIdentity,
    files: tuple[_ReportFile, ...],
    checkpoint: ReportWriteCheckpoint | None,
) -> None:
    try:
        directory_descriptor = os.open(
            root,
            os.O_RDONLY | _DIRECTORY_FLAG | _NOFOLLOW_FLAG | _CLOEXEC_FLAG,
        )
    except OSError as error:
        raise ReportPathError("run directory could not be opened securely") from error
    try:
        metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or _DirectoryIdentity(metadata.st_dev, metadata.st_ino) != root_identity
        ):
            raise ReportPathError("opened run directory identity differs")
        for item in files:
            _replace_one_posix(directory_descriptor, item, checkpoint)
    finally:
        os.close(directory_descriptor)


def _replace_one_posix(
    directory_descriptor: int,
    item: _ReportFile,
    checkpoint: ReportWriteCheckpoint | None,
) -> None:
    target_name = item.spec.relative_path
    temporary_name = f".{target_name}.tmp-{secrets.token_hex(16)}"
    descriptor = -1
    try:
        before = _target_identity_at(directory_descriptor, target_name)
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY_FLAG | _NOFOLLOW_FLAG | _CLOEXEC_FLAG,
            0o600,
            dir_fd=directory_descriptor,
        )
        os.set_inheritable(descriptor, False)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, item.content)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(item.content)
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ReportPathError("temporary report file failed integrity checks")
        _checkpoint(checkpoint, "temporary_fsynced", target_name)
        if _target_identity_at(directory_descriptor, target_name) != before:
            raise ReportPathError("report target changed before atomic replacement")
        os.replace(
            temporary_name,
            target_name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
        _checkpoint(checkpoint, "target_replaced", target_name)
        after = os.stat(
            target_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        _verify_installed_file(after, len(item.content))
    except OSError as error:
        raise ReportPathError("report artifact could not be replaced atomically") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ReportPathError("temporary report artifact could not be removed") from error


def _install_report_files_portable(
    root: Path,
    root_identity: _DirectoryIdentity,
    files: tuple[_ReportFile, ...],
    checkpoint: ReportWriteCheckpoint | None,
) -> None:
    for item in files:
        _verify_run_directory(root, root_identity)
        _replace_one_portable(root, root_identity, item, checkpoint)


def _replace_one_portable(
    root: Path,
    root_identity: _DirectoryIdentity,
    item: _ReportFile,
    checkpoint: ReportWriteCheckpoint | None,
) -> None:
    target = root / item.spec.relative_path
    temporary = root / f".{target.name}.tmp-{secrets.token_hex(16)}"
    descriptor = -1
    try:
        before = _target_identity_path(target)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY_FLAG | _NOFOLLOW_FLAG | _CLOEXEC_FLAG,
            0o600,
        )
        os.set_inheritable(descriptor, False)
        _write_all(descriptor, item.content)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        _verify_installed_file(metadata, len(item.content))
        os.close(descriptor)
        descriptor = -1
        _checkpoint(checkpoint, "temporary_fsynced", item.spec.relative_path)
        _verify_run_directory(root, root_identity)
        if _target_identity_path(target) != before:
            raise ReportPathError("report target changed before atomic replacement")
        os.replace(temporary, target)
        try:
            target.chmod(0o600)
        except OSError as error:
            raise ReportPathError("report permissions could not be tightened") from error
        _checkpoint(checkpoint, "target_replaced", item.spec.relative_path)
        _verify_run_directory(root, root_identity)
        _verify_installed_file(_safe_lstat(target), len(item.content))
    except OSError as error:
        raise ReportPathError("report artifact could not be replaced atomically") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ReportPathError("temporary report artifact could not be removed") from error


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise ReportWriterError("report write made no forward progress")
        written += count


def _target_identity_at(
    directory_descriptor: int,
    name: str,
) -> _TargetIdentity | None:
    try:
        metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    _verify_replaceable_target(metadata)
    return _TargetIdentity(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
    )


def _target_identity_path(path: Path) -> _TargetIdentity | None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    _verify_replaceable_target(metadata)
    return _TargetIdentity(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
    )


def _verify_replaceable_target(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or _is_reparse(metadata):
        raise ReportPathError("existing report target is not one private regular file")


def _verify_installed_file(metadata: os.stat_result, expected_bytes: int) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or _is_reparse(metadata)
        or metadata.st_size != expected_bytes
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077)
    ):
        raise ReportPathError("installed report file failed integrity checks")


def _safe_lstat(path: Path) -> os.stat_result:
    try:
        return path.stat(follow_symlinks=False)
    except OSError as error:
        raise ReportPathError("report path contains an unavailable component") from error


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)


def _checkpoint(
    callback: Callable[[str, str], None] | None,
    phase: str,
    relative_path: str,
) -> None:
    if callback is not None:
        callback(phase, relative_path)


__all__ = [
    "BUILTIN_REPORTER_CONTRACTS",
    "BUILTIN_REPORTER_IMPLEMENTATIONS",
    "GOLDEN_COMPATIBILITY_REVIEW_MARKER",
    "REPORT_RENDERER_VERSION",
    "ReportContractError",
    "ReportOutputLimitError",
    "ReportPathError",
    "ReportPayloads",
    "ReportWriteCheckpoint",
    "ReportWriteResult",
    "ReportWriter",
    "ReportWriterError",
    "ReporterContractRegistration",
    "regenerate_reports",
    "validate_reporter_contracts",
]
