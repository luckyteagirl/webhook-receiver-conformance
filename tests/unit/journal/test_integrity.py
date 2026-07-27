"""Integrity and artifact-registry contracts for TASK-0205."""
# ruff: noqa: INP001, PLR2004, SLF001

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import anyio
import pytest
from anyio.to_thread import run_sync

import webhook_receiver_conformance.journal.artifacts as artifact_module
from webhook_receiver_conformance.errors import ErrorCategory, ResultCategory
from webhook_receiver_conformance.journal.artifacts import (
    ArtifactOutputLimitError,
    ArtifactPathError,
    ArtifactRecord,
    ArtifactRegistration,
    ArtifactRegistry,
    ArtifactRegistryError,
    ArtifactRegistryIntegrityError,
    ArtifactRegistryLimits,
)
from webhook_receiver_conformance.journal.connection import connect_writer_database
from webhook_receiver_conformance.journal.integrity import (
    ResumeDatabasePathError,
    ResumeIntegrityError,
    verify_resume_integrity,
)
from webhook_receiver_conformance.journal.schema import (
    JOURNAL_FILENAME,
    RunDatabase,
    create_run_database,
)
from webhook_receiver_conformance.journal.service import (
    JournalService,
    JournalStatement,
    JournalWriteIntegrityError,
    StatementOperation,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

RUN_ID = "00000000-0000-4000-8000-000000000001"
OTHER_RUN_ID = "00000000-0000-4000-8000-000000000002"
MANIFEST_ID = "a" * 64
TIMESTAMP = "2026-07-27T12:34:56.000000Z"
WATERMARK = f"sha256:{'b' * 64}"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _run_database(tmp_path: Path) -> RunDatabase:
    return create_run_database(tmp_path, run_id=RUN_ID)


def _file_digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _registration(
    relative_path: str,
    *,
    media_type: str = "application/json",
) -> ArtifactRegistration:
    return ArtifactRegistration(
        relative_path=relative_path,
        media_type=media_type,
        generated_at=TIMESTAMP,
        input_watermark=WATERMARK,
        renderer_version="renderer-1.0",
    )


async def _seed_run(service: JournalService, *, run_id: str = RUN_ID) -> None:
    await service.execute(
        StatementOperation(
            JournalStatement(
                """
                INSERT INTO runs (run_id, manifest_id, state, created_at)
                VALUES (?, ?, 'planned', ?)
                """,
                (run_id, MANIFEST_ID, TIMESTAMP),
            )
        )
    )


async def _artifact_rows(
    service: JournalService,
    *,
    run_id: str = RUN_ID,
) -> tuple[tuple[object, ...], ...]:
    result = await service.execute(
        StatementOperation(
            JournalStatement(
                """
                SELECT relative_path, media_type, byte_length, sha256,
                       generated_at, input_watermark, renderer_version
                FROM artifacts
                WHERE run_id = ?
                ORDER BY relative_path
                """,
                (run_id,),
            )
        )
    )
    return result.rows


def test_valid_resume_runs_read_only_checks_and_preserves_exact_database(
    tmp_path: Path,
) -> None:
    run = _run_database(tmp_path)
    before = run.database_path.read_bytes()

    report = verify_resume_integrity(run.database_path)

    assert report.quick_check == "ok"
    assert report.foreign_key_violations == 0
    assert report.read_only
    assert report.database_bytes == len(before)
    assert run.database_path.read_bytes() == before


def test_corrupt_database_fails_as_harness_error_without_repair_or_replacement(
    tmp_path: Path,
) -> None:
    database = tmp_path / JOURNAL_FILENAME
    corrupt = b"not-a-sqlite-database\x00diagnostic-canary"
    database.write_bytes(corrupt)
    before_identity = database.stat().st_ino

    with pytest.raises(ResumeIntegrityError) as captured:
        verify_resume_integrity(database)

    assert captured.value.category is ErrorCategory.INTEGRITY_ERROR
    assert captured.value.result_category is ResultCategory.HARNESS_ERROR
    assert "diagnostic-canary" not in str(captured.value)
    assert database.read_bytes() == corrupt
    assert database.stat().st_ino == before_identity
    assert not list(tmp_path.glob("*backup*"))


def test_foreign_key_violation_fails_before_resume_and_preserves_database(
    tmp_path: Path,
) -> None:
    run = _run_database(tmp_path)
    connection = sqlite3.connect(run.database_path, isolation_level=None)
    try:
        connection.execute(
            """
            INSERT INTO artifacts (
                artifact_id, run_id, relative_path, media_type,
                byte_length, sha256, generated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "artifact_orphan",
                OTHER_RUN_ID,
                "reports/orphan.json",
                "application/json",
                0,
                f"sha256:{'0' * 64}",
                TIMESTAMP,
            ),
        )
    finally:
        connection.close()
    before = run.database_path.read_bytes()

    with pytest.raises(ResumeIntegrityError) as captured:
        verify_resume_integrity(run.database_path)

    assert captured.value.check == "foreign_key_check"
    assert captured.value.result_category is ResultCategory.HARNESS_ERROR
    assert run.database_path.read_bytes() == before


def test_resume_rejects_database_symlinks_and_hardlinks(tmp_path: Path) -> None:
    run = _run_database(tmp_path)
    hardlink = tmp_path / "hardlinked.sqlite3"
    os.link(run.database_path, hardlink)

    with pytest.raises(ResumeDatabasePathError):
        verify_resume_integrity(run.database_path)
    with pytest.raises(ResumeDatabasePathError):
        verify_resume_integrity(hardlink)

    symlink = tmp_path / "linked.sqlite3"
    try:
        symlink.symlink_to(run.database_path)
    except OSError:
        return
    with pytest.raises(ResumeDatabasePathError):
        verify_resume_integrity(symlink)


@pytest.mark.anyio
async def test_registry_records_exact_file_metadata_and_is_idempotent(
    tmp_path: Path,
) -> None:
    run = _run_database(tmp_path)
    reports = run.run_directory / "reports"
    reports.mkdir()
    summary = reports / "result-summary.json"
    summary.write_bytes(b'{"result":"pass"}\n')
    registration = _registration("reports/result-summary.json")

    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        registry = ArtifactRegistry(service=service, run_directory=run.run_directory)
        first = await registry.replace(RUN_ID, (registration,))
        second = await registry.replace(RUN_ID, (registration,))
        rows = await _artifact_rows(service)

    assert first == second
    assert len(first) == 1
    record = first[0]
    assert record.relative_path == "reports/result-summary.json"
    assert record.media_type == "application/json"
    assert record.byte_length == summary.stat().st_size
    assert record.sha256 == _file_digest(summary)
    assert record.input_watermark == WATERMARK
    assert record.renderer_version == "renderer-1.0"
    assert rows == (
        (
            record.relative_path,
            record.media_type,
            record.byte_length,
            record.sha256,
            TIMESTAMP,
            WATERMARK,
            "renderer-1.0",
        ),
    )
    assert "pass" not in repr(record)


@pytest.mark.anyio
async def test_regeneration_replaces_complete_set_and_updates_digest_atomically(
    tmp_path: Path,
) -> None:
    run = _run_database(tmp_path)
    reports = run.run_directory / "reports"
    reports.mkdir()
    first_path = reports / "first.json"
    removed_path = reports / "removed.xml"
    first_path.write_bytes(b'{"version":1}')
    removed_path.write_bytes(b"<old/>")

    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        registry = ArtifactRegistry(service=service, run_directory=run.run_directory)
        initial = await registry.replace(
            RUN_ID,
            (
                _registration("reports/first.json"),
                _registration("reports/removed.xml", media_type="application/xml"),
            ),
        )
        first_path.write_bytes(b'{"version":2}')
        regenerated = await registry.replace(
            RUN_ID,
            (_registration("reports/first.json"),),
        )
        rows = await _artifact_rows(service)

    assert len(initial) == 2
    assert len(regenerated) == 1
    assert regenerated[0].artifact_id == initial[0].artifact_id
    assert regenerated[0].sha256 != initial[0].sha256
    assert regenerated[0].sha256 == _file_digest(first_path)
    assert rows[0][0] == "reports/first.json"
    assert len(rows) == 1


@pytest.mark.anyio
async def test_sql_failure_rolls_back_delete_and_all_partial_registry_inserts(
    tmp_path: Path,
) -> None:
    run = _run_database(tmp_path)
    reports = run.run_directory / "reports"
    reports.mkdir()
    first_path = reports / "first.json"
    second_path = reports / "second.json"
    first_path.write_bytes(b"first-v1")
    second_path.write_bytes(b"second")

    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        registry = ArtifactRegistry(service=service, run_directory=run.run_directory)
        await registry.replace(RUN_ID, (_registration("reports/first.json"),))
        original_rows = await _artifact_rows(service)
        await service.execute(
            StatementOperation(
                JournalStatement(
                    """
                    CREATE TRIGGER artifact_test_failure
                    BEFORE INSERT ON artifacts
                    WHEN NEW.relative_path = 'reports/second.json'
                    BEGIN
                        SELECT RAISE(ABORT, 'injected artifact failure');
                    END
                    """
                )
            )
        )
        first_path.write_bytes(b"first-v2")
        with pytest.raises(JournalWriteIntegrityError):
            await registry.replace(
                RUN_ID,
                (
                    _registration("reports/first.json"),
                    _registration("reports/second.json"),
                ),
            )
        after_rows = await _artifact_rows(service)

    assert after_rows == original_rows


@pytest.mark.anyio
async def test_identity_change_between_snapshot_and_transaction_fails_without_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run_database(tmp_path)
    reports = run.run_directory / "reports"
    reports.mkdir()
    artifact = reports / "result.json"
    artifact.write_bytes(b"stable")
    original_prepare = artifact_module._prepare_artifacts  # pyright: ignore[reportPrivateUsage]

    def mutate_after_prepare(
        root: Path,
        root_identity: artifact_module._DirectoryIdentity,  # pyright: ignore[reportPrivateUsage]
        run_id: str,
        registrations: tuple[ArtifactRegistration, ...],
        limits: ArtifactRegistryLimits,
    ) -> tuple[artifact_module._PreparedArtifact, ...]:  # pyright: ignore[reportPrivateUsage]
        prepared = original_prepare(
            root,
            root_identity,
            run_id,
            registrations,
            limits,
        )
        before = artifact.stat()
        artifact.write_bytes(b"mutate")
        os.utime(
            artifact,
            ns=(before.st_atime_ns, before.st_mtime_ns),
        )
        return prepared

    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        registry = ArtifactRegistry(service=service, run_directory=run.run_directory)
        monkeypatch.setattr(artifact_module, "_prepare_artifacts", mutate_after_prepare)
        with pytest.raises(ArtifactRegistryIntegrityError):
            await registry.replace(
                RUN_ID,
                (_registration("reports/result.json"),),
            )
        assert await _artifact_rows(service) == ()


@pytest.mark.anyio
async def test_hashing_occurs_outside_begin_immediate_writer_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run_database(tmp_path)
    reports = run.run_directory / "reports"
    reports.mkdir()
    (reports / "result.json").write_bytes(b"bounded")
    factory = _TrackingFactory()
    original_read = artifact_module.os.read

    def guarded_read(descriptor: int, length: int) -> bytes:
        assert not factory.connections[0].in_transaction
        return original_read(descriptor, length)

    monkeypatch.setattr(artifact_module.os, "read", guarded_read)
    async with JournalService.open(
        run.database_path,
        connection_factory=factory,
    ) as service:
        await _seed_run(service)
        registry = ArtifactRegistry(service=service, run_directory=run.run_directory)
        records = await registry.replace(
            RUN_ID,
            (_registration("reports/result.json"),),
        )

    assert len(records) == 1


@pytest.mark.anyio
async def test_cancellation_during_snapshot_closes_retained_file_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run_database(tmp_path)
    reports = run.run_directory / "reports"
    reports.mkdir()
    (reports / "result.json").write_bytes(b"cancellation-canary")
    opened = threading.Event()
    descriptors: list[int] = []
    original_open = artifact_module._open_contained_file  # pyright: ignore[reportPrivateUsage]
    original_hash = artifact_module._hash_descriptor  # pyright: ignore[reportPrivateUsage]

    def recording_open(root: Path, parts: tuple[str, ...]) -> tuple[int, Path]:
        descriptor, target = original_open(root, parts)
        descriptors.append(descriptor)
        opened.set()
        return descriptor, target

    def slow_hash(descriptor: int, *, maximum: int) -> tuple[str, int]:
        time.sleep(0.05)
        return original_hash(descriptor, maximum=maximum)

    monkeypatch.setattr(artifact_module, "_open_contained_file", recording_open)
    monkeypatch.setattr(artifact_module, "_hash_descriptor", slow_hash)
    completed = False
    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        registry = ArtifactRegistry(service=service, run_directory=run.run_directory)

        async def replace() -> None:
            nonlocal completed
            await registry.replace(
                RUN_ID,
                (_registration("reports/result.json"),),
            )
            completed = True

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(replace)
            await run_sync(opened.wait)
            task_group.cancel_scope.cancel()

        assert await _artifact_rows(service) == ()

    assert not completed
    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError, match=r"handle is invalid|Bad file descriptor"):
            os.fstat(descriptor)


@dataclass(slots=True)
class _TrackingFactory:
    connections: list[sqlite3.Connection] = field(default_factory=list[sqlite3.Connection])

    def __call__(
        self,
        database_path: str | os.PathLike[str],
        *,
        create: bool,
        busy_timeout_ms: int,
    ) -> sqlite3.Connection:
        connection = connect_writer_database(
            database_path,
            create=create,
            busy_timeout_ms=busy_timeout_ms,
        )
        self.connections.append(connection)
        return connection


@pytest.mark.anyio
@pytest.mark.parametrize(
    "relative_path",
    [
        "../secret",
        "reports/../secret",
        "/absolute.json",
        r"reports\result.json",
        "C:/result.json",
        "./result.json",
        "reports//result.json",
        "reports/NUL.txt",
        "reports/result.json.",
        "reports/\x1bsecret.json",
    ],
)
async def test_registry_rejects_traversal_devices_and_unnormalized_paths(
    tmp_path: Path,
    relative_path: str,
) -> None:
    run = _run_database(tmp_path)
    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        registry = ArtifactRegistry(service=service, run_directory=run.run_directory)
        with pytest.raises(ArtifactPathError):
            await registry.replace(RUN_ID, (_registration(relative_path),))
        assert await _artifact_rows(service) == ()


@pytest.mark.anyio
async def test_registry_rejects_symlink_hardlink_directory_and_secret_canary(
    tmp_path: Path,
) -> None:
    run = _run_database(tmp_path)
    reports = run.run_directory / "reports"
    reports.mkdir()
    original = reports / "original.json"
    hardlink = reports / "hardlink.json"
    original.write_bytes(b"artifact-secret-canary")
    os.link(original, hardlink)
    directory = reports / "directory.json"
    directory.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"outside-secret-canary")
    symlink = reports / "symlink.json"
    symlink_created = True
    try:
        symlink.symlink_to(outside)
    except OSError:
        symlink_created = False

    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        registry = ArtifactRegistry(service=service, run_directory=run.run_directory)
        for relative_path in (
            "reports/original.json",
            "reports/hardlink.json",
            "reports/directory.json",
        ):
            with pytest.raises(ArtifactRegistryError) as captured:
                await registry.replace(RUN_ID, (_registration(relative_path),))
            assert "secret-canary" not in str(captured.value)
        if symlink_created:
            with pytest.raises(ArtifactRegistryError) as captured:
                await registry.replace(
                    RUN_ID,
                    (_registration("reports/symlink.json"),),
                )
            assert "outside-secret-canary" not in str(captured.value)
        assert await _artifact_rows(service) == ()


@pytest.mark.anyio
async def test_artifact_size_boundary_and_registration_count_are_bounded(
    tmp_path: Path,
) -> None:
    run = _run_database(tmp_path)
    reports = run.run_directory / "reports"
    reports.mkdir()
    boundary = reports / "boundary.bin"
    boundary.write_bytes(b"1234")
    oversized = reports / "oversized.bin"
    oversized.write_bytes(b"12345")
    limits = ArtifactRegistryLimits(
        max_artifacts=2,
        max_artifact_bytes=4,
        max_total_bytes=8,
    )

    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        registry = ArtifactRegistry(
            service=service,
            run_directory=run.run_directory,
            limits=limits,
        )
        accepted = await registry.replace(
            RUN_ID,
            (_registration("reports/boundary.bin", media_type="application/octet-stream"),),
        )
        with pytest.raises(ArtifactOutputLimitError):
            await registry.replace(
                RUN_ID,
                (
                    _registration(
                        "reports/oversized.bin",
                        media_type="application/octet-stream",
                    ),
                ),
            )
        with pytest.raises(ArtifactRegistryError):
            await registry.replace(
                RUN_ID,
                (
                    _registration("reports/boundary.bin"),
                    _registration("reports/boundary.bin"),
                    _registration("reports/boundary.bin"),
                ),
            )

    assert accepted[0].byte_length == 4


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ArtifactRegistration("report.json", "not-a-media-type", TIMESTAMP),
        lambda: ArtifactRegistration("report.json", "application/json", "not-time"),
        lambda: ArtifactRegistration(
            "report.json",
            "application/json",
            TIMESTAMP,
            input_watermark="sha256:ABC",
        ),
        lambda: ArtifactRegistration(
            "report.json",
            "application/json",
            TIMESTAMP,
            renderer_version="secret\rvalue",
        ),
    ],
)
def test_registration_metadata_is_strict_and_safe(
    factory: Callable[[], ArtifactRegistration],
) -> None:
    with pytest.raises(ArtifactRegistryError) as captured:
        factory()

    assert "secret" not in str(captured.value)


def test_artifact_record_requires_lowercase_digest() -> None:
    with pytest.raises(ArtifactRegistryIntegrityError):
        ArtifactRecord(
            artifact_id="artifact_test",
            run_id=RUN_ID,
            relative_path="reports/result.json",
            media_type="application/json",
            byte_length=1,
            sha256=f"sha256:{'A' * 64}",
            generated_at=TIMESTAMP,
            input_watermark=None,
            renderer_version=None,
        )
