"""Contract, integrity, and crash-cleanup tests for the fixture blob store."""
# ruff: noqa: INP001, PLR0913, PLR2004, S603, S607, SLF001

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import replace
from typing import TYPE_CHECKING, NoReturn

import pytest

from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.fixtures import blobs
from webhook_receiver_conformance.fixtures.blobs import (
    BlobSnapshot,
    BlobStore,
    BlobStoreError,
    snapshot_blob,
    verify_blob,
)
from webhook_receiver_conformance.fixtures.loader import HARD_MAX_FIXTURE_BYTES
from webhook_receiver_conformance.types import DiagnosticCode

if TYPE_CHECKING:
    from pathlib import Path


def _make_symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as error:
        pytest.skip(f"symlinks unavailable on this platform: {error}")


def _make_directory_junction(link: Path, target: Path) -> None:
    completed = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip(f"directory junctions unavailable: {completed.stderr}")


def test_snapshot_uses_content_addressed_layout_and_exact_bytes(tmp_path: Path) -> None:
    body = b"\x00exact\r\nfixture\xff"
    snapshot = snapshot_blob(
        tmp_path / "run",
        body,
        media_type="application/octet-stream",
    )
    raw_digest = sha256_digest(body).removeprefix("sha256:")

    assert snapshot.path == tmp_path / "run" / "blobs" / "sha256" / raw_digest[:2] / raw_digest
    assert snapshot.path.read_bytes() == body
    assert snapshot.to_manifest_entry() == {
        "sha256": sha256_digest(body),
        "byte_length": len(body),
        "media_type": "application/octet-stream",
    }
    assert verify_blob(tmp_path / "run", snapshot) == snapshot.path


def test_snapshot_is_idempotent_and_one_byte_changes_address(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "run")
    first = store.snapshot(b"abc", media_type="text/plain")
    repeated = store.snapshot(b"abc", media_type="text/plain")
    changed = store.snapshot(b"abd", media_type="text/plain")

    assert first == repeated
    assert changed.sha256 != first.sha256
    assert changed.path != first.path
    assert first.path.read_bytes() == b"abc"
    assert changed.path.read_bytes() == b"abd"


def test_existing_corruption_fails_verification_and_resnapshot(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "run")
    snapshot = store.snapshot(b"trusted", media_type="text/plain")
    snapshot.path.write_bytes(b"corrupt")

    with pytest.raises(BlobStoreError) as verify_error:
        store.verify(snapshot)
    assert verify_error.value.diagnostic.code == DiagnosticCode("BLOB_INTEGRITY_ERROR")
    assert verify_error.value.diagnostic.category is ErrorCategory.ARTIFACT_INTEGRITY_ERROR

    with pytest.raises(BlobStoreError) as snapshot_error:
        store.snapshot(b"trusted", media_type="text/plain")
    assert snapshot_error.value.diagnostic.code == DiagnosticCode("BLOB_INTEGRITY_ERROR")
    assert snapshot.path.read_bytes() == b"corrupt"


def test_missing_blob_verification_is_classified_and_does_not_create_directories(
    tmp_path: Path,
) -> None:
    run_directory = tmp_path / "missing-run"
    digest = sha256_digest(b"missing")
    raw_digest = digest.removeprefix("sha256:")
    snapshot = BlobSnapshot(
        sha256=digest,
        byte_length=7,
        media_type="text/plain",
        path=run_directory / "blobs" / "sha256" / raw_digest[:2] / raw_digest,
    )

    with pytest.raises(BlobStoreError) as captured:
        BlobStore(run_directory).verify(snapshot)

    assert captured.value.diagnostic.code == DiagnosticCode("BLOB_INTEGRITY_ERROR")
    assert not run_directory.exists()


def test_declared_length_or_path_mismatch_fails_verification(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "run")
    snapshot = store.snapshot(b"payload", media_type="text/plain")

    with pytest.raises(BlobStoreError):
        store.verify(replace(snapshot, byte_length=snapshot.byte_length + 1))
    with pytest.raises(BlobStoreError):
        store.verify(replace(snapshot, path=tmp_path / "elsewhere"))
    with pytest.raises(BlobStoreError):
        store.verify(replace(snapshot, sha256="not-a-digest"))


def test_existing_symlink_collision_never_reads_or_overwrites_external_canary(
    tmp_path: Path,
) -> None:
    body = b"planned"
    store = BlobStore(tmp_path / "run")
    destination = store.path_for(sha256_digest(body))
    destination.parent.mkdir(parents=True)
    external = tmp_path / "external-blob-canary.bin"
    external.write_bytes(b"DO-NOT-OVERWRITE")
    _make_symlink(destination, external)

    with pytest.raises(BlobStoreError) as captured:
        store.snapshot(body, media_type="application/octet-stream")

    assert captured.value.diagnostic.code == DiagnosticCode("BLOB_INTEGRITY_ERROR")
    assert external.read_bytes() == b"DO-NOT-OVERWRITE"
    diagnostic_json = captured.value.diagnostic.model_dump_json()
    assert external.name not in diagnostic_json
    assert "DO-NOT-OVERWRITE" not in diagnostic_json


def test_symlink_run_directory_cannot_redirect_blob_writes(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    run_link = tmp_path / "run"
    _make_symlink(run_link, external)

    with pytest.raises(BlobStoreError):
        BlobStore(run_link).snapshot(b"payload", media_type="text/plain")

    assert list(external.iterdir()) == []


def test_write_failure_removes_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_write(_descriptor: int, _body: object) -> NoReturn:
        raise OSError

    monkeypatch.setattr(blobs.os, "write", fail_write)
    with pytest.raises(BlobStoreError) as captured:
        BlobStore(tmp_path / "run").snapshot(b"payload", media_type="text/plain")

    assert captured.value.diagnostic.code == DiagnosticCode("BLOB_WRITE_FAILED")
    assert list((tmp_path / "run").rglob(".tmp-*")) == []


def test_atomic_collision_verifies_the_winner_and_removes_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"identical-racing-winner"
    store = BlobStore(tmp_path / "run")
    destination = store.path_for(sha256_digest(body))

    def racing_link(
        _source: object,
        _destination: object,
        **_kwargs: object,
    ) -> NoReturn:
        destination.write_bytes(body)
        raise FileExistsError

    if os.name == "nt":

        def racing_rename(
            *,
            os_handle: int,
            root_handle: int,
            name: str,
        ) -> NoReturn:
            del os_handle, root_handle, name
            destination.write_bytes(body)
            raise FileExistsError

        monkeypatch.setattr(blobs, "_windows_rename_handle", racing_rename)
    else:
        monkeypatch.setattr(blobs.os, "link", racing_link)
    snapshot = store.snapshot(body, media_type="text/plain")

    assert snapshot.path.read_bytes() == body
    assert list((tmp_path / "run").rglob(".tmp-*")) == []


def test_cancellation_removes_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def cancel_write(_descriptor: int, _body: object) -> NoReturn:
        raise KeyboardInterrupt

    monkeypatch.setattr(blobs.os, "write", cancel_write)
    with pytest.raises(KeyboardInterrupt):
        BlobStore(tmp_path / "run").snapshot(b"payload", media_type="text/plain")

    assert list((tmp_path / "run").rglob(".tmp-*")) == []


def test_new_posix_run_directories_and_blob_request_owner_only_modes(
    tmp_path: Path,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX permission bits are not authoritative on this platform")

    prior_umask = os.umask(0)
    try:
        snapshot = BlobStore(tmp_path / "run").snapshot(b"payload", media_type="text/plain")
    finally:
        os.umask(prior_umask)

    assert stat.S_IMODE((tmp_path / "run").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "run" / "blobs").stat().st_mode) == 0o700
    assert stat.S_IMODE(snapshot.path.stat().st_mode) == 0o600


def test_empty_blob_is_supported_and_verified(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "run")
    snapshot = store.snapshot(b"", media_type="application/octet-stream")
    assert snapshot.byte_length == 0
    assert snapshot.path.read_bytes() == b""
    assert store.verify(snapshot) == snapshot.path


def test_blob_hard_limit_is_classified_before_creating_run_directory(tmp_path: Path) -> None:
    run_directory = tmp_path / "run"
    with pytest.raises(BlobStoreError) as captured:
        BlobStore(run_directory).snapshot(
            b"x" * (HARD_MAX_FIXTURE_BYTES + 1),
            media_type="application/octet-stream",
        )

    assert captured.value.diagnostic.code == DiagnosticCode("BLOB_RESOURCE_LIMIT")
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert captured.value.diagnostic.safe_details == {
        "limit": "max_request_bytes_hard",
        "maximum": HARD_MAX_FIXTURE_BYTES,
    }
    assert not run_directory.exists()


def test_verify_hard_limit_is_classified_before_any_file_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = BlobStore(tmp_path / "run")
    digest = sha256_digest(b"bounded")
    snapshot = BlobSnapshot(
        sha256=digest,
        byte_length=HARD_MAX_FIXTURE_BYTES + 1,
        media_type="application/octet-stream",
        path=store.path_for(digest),
    )

    def forbidden_operation(*_args: object, **_kwargs: object) -> NoReturn:
        pytest.fail("no file operation")

    monkeypatch.setattr(blobs.os, "open", forbidden_operation)
    monkeypatch.setattr(blobs.os, "read", forbidden_operation)
    monkeypatch.setattr(blobs, "_windows_open_path", forbidden_operation)

    with pytest.raises(BlobStoreError) as captured:
        store.verify(snapshot)

    assert captured.value.diagnostic.code == DiagnosticCode("BLOB_RESOURCE_LIMIT")
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert not store.run_directory.exists()


def test_windows_ancestor_junction_swap_cannot_redirect_blob_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction race")
    run_directory = tmp_path / "run"
    (run_directory / "blobs").mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    real_windows_open = blobs._windows_open_path  # pyright: ignore[reportPrivateUsage]
    real_write = blobs.os.write
    swapped = False
    writes = 0

    def racing_windows_open(path: Path, *, directory: bool) -> int:
        nonlocal swapped
        handle = real_windows_open(path, directory=directory)
        if directory and not swapped:
            swapped = True
            (run_directory / "blobs").rename(run_directory / "blobs-before-swap")
            _make_directory_junction(run_directory / "blobs", external)
        return handle

    def recording_write(descriptor: int, body: object) -> int:
        nonlocal writes
        writes += 1
        return real_write(descriptor, body)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(blobs, "_windows_open_path", racing_windows_open)
    monkeypatch.setattr(blobs.os, "write", recording_write)

    with pytest.raises(BlobStoreError):
        BlobStore(run_directory).snapshot(b"payload", media_type="text/plain")

    assert swapped is True
    assert writes == 0
    assert list(external.iterdir()) == []


def test_windows_ancestor_junction_swap_cannot_redirect_blob_verify_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction race")
    run_directory = tmp_path / "run"
    store = BlobStore(run_directory)
    snapshot = store.snapshot(b"payload", media_type="text/plain")
    external = tmp_path / "external"
    external_blob = (
        external
        / "sha256"
        / snapshot.sha256.removeprefix("sha256:")[:2]
        / snapshot.sha256.removeprefix("sha256:")
    )
    external_blob.parent.mkdir(parents=True)
    external_blob.write_bytes(b"EXTERNAL-CANARY")
    real_windows_open = blobs._windows_open_path  # pyright: ignore[reportPrivateUsage]
    real_read = blobs.os.read
    swapped = False
    reads = 0

    def racing_windows_open(path: Path, *, directory: bool) -> int:
        nonlocal swapped
        handle = real_windows_open(path, directory=directory)
        if directory and not swapped:
            swapped = True
            (run_directory / "blobs").rename(run_directory / "blobs-before-swap")
            _make_directory_junction(run_directory / "blobs", external)
        return handle

    def recording_read(descriptor: int, length: int) -> bytes:
        nonlocal reads
        reads += 1
        return real_read(descriptor, length)

    monkeypatch.setattr(blobs, "_windows_open_path", racing_windows_open)
    monkeypatch.setattr(blobs.os, "read", recording_read)

    with pytest.raises(BlobStoreError):
        store.verify(snapshot)

    assert swapped is True
    assert reads == 0
    assert external_blob.read_bytes() == b"EXTERNAL-CANARY"


def test_windows_post_pin_shard_junction_swap_fails_without_external_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction race")
    run_directory = tmp_path / "run"
    external = tmp_path / "external"
    external.mkdir()
    renamed_shard: Path | None = None
    real_open_tree = blobs._open_blob_tree_windows  # pyright: ignore[reportPrivateUsage]
    writes = 0

    def racing_open_tree(
        selected_run: Path,
        shard_name: str,
        *,
        create: bool,
    ) -> object:
        nonlocal renamed_shard
        tree = real_open_tree(selected_run, shard_name, create=create)
        renamed_shard = tree.shard.with_name(f"{tree.shard.name}-before-swap")
        tree.shard.rename(renamed_shard)
        _make_directory_junction(tree.shard, external)
        return tree

    def forbidden_write(_descriptor: int, _body: object) -> NoReturn:
        nonlocal writes
        writes += 1
        pytest.fail("post-pin shard substitution must fail before writing")

    monkeypatch.setattr(blobs, "_open_blob_tree_windows", racing_open_tree)
    monkeypatch.setattr(blobs.os, "write", forbidden_write)

    with pytest.raises(BlobStoreError):
        BlobStore(run_directory).snapshot(b"payload", media_type="text/plain")

    assert writes == 0
    assert list(external.iterdir()) == []
    assert renamed_shard is not None
    (run_directory / "blobs" / "sha256" / renamed_shard.name.removesuffix("-before-swap")).rmdir()
    renamed_shard.rmdir()


def test_windows_post_pin_shard_junction_swap_fails_without_external_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction race")
    run_directory = tmp_path / "run"
    store = BlobStore(run_directory)
    snapshot = store.snapshot(b"payload", media_type="text/plain")
    raw_digest = snapshot.sha256.removeprefix("sha256:")
    external = tmp_path / "external"
    external.mkdir()
    external_blob = external / raw_digest
    external_blob.write_bytes(b"payload")
    renamed_shard: Path | None = None
    real_open_tree = blobs._open_blob_tree_windows  # pyright: ignore[reportPrivateUsage]
    reads = 0

    def racing_open_tree(
        selected_run: Path,
        shard_name: str,
        *,
        create: bool,
    ) -> object:
        nonlocal renamed_shard
        tree = real_open_tree(selected_run, shard_name, create=create)
        renamed_shard = tree.shard.with_name(f"{tree.shard.name}-before-swap")
        tree.shard.rename(renamed_shard)
        _make_directory_junction(tree.shard, external)
        return tree

    def forbidden_read(_descriptor: int, _length: int) -> NoReturn:
        nonlocal reads
        reads += 1
        pytest.fail("post-pin shard substitution must fail before reading")

    monkeypatch.setattr(blobs, "_open_blob_tree_windows", racing_open_tree)
    monkeypatch.setattr(blobs.os, "read", forbidden_read)

    with pytest.raises(BlobStoreError):
        store.verify(snapshot)

    assert reads == 0
    assert external_blob.read_bytes() == b"payload"
    assert renamed_shard is not None
    (run_directory / "blobs" / "sha256" / renamed_shard.name.removesuffix("-before-swap")).rmdir()
    (renamed_shard / raw_digest).unlink()
    renamed_shard.rmdir()


@pytest.mark.parametrize(
    ("attack_call", "parent_parts", "created_child"),
    [
        (1, (), "blobs"),
        (2, ("blobs",), "sha256"),
        (3, ("blobs", "sha256"), "23"),
    ],
)
def test_windows_tree_construction_uses_parent_handle_relative_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack_call: int,
    parent_parts: tuple[str, ...],
    created_child: str,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction race")
    run_directory = tmp_path / "run"
    external = tmp_path / "external"
    external.mkdir()
    canary = external / "external-metadata-canary"
    canary.write_bytes(b"UNCHANGED")
    real_relative_open = blobs._windows_open_relative_handle  # pyright: ignore[reportPrivateUsage]
    directory_calls = 0
    writes = 0
    renamed_parent: Path | None = None
    canonical_parent: Path | None = None

    def racing_relative_open(
        root_handle: int,
        name: str,
        *,
        desired_access: int,
        share_access: int,
        create_disposition: int,
        directory: bool = False,
    ) -> int:
        nonlocal canonical_parent, directory_calls, renamed_parent
        if directory:
            directory_calls += 1
            if directory_calls == attack_call:
                canonical_parent = run_directory.joinpath(*parent_parts)
                renamed_parent = canonical_parent.with_name(f"{canonical_parent.name}-before-swap")
                canonical_parent.rename(renamed_parent)
                _make_directory_junction(canonical_parent, external)
        return real_relative_open(
            root_handle,
            name,
            desired_access=desired_access,
            share_access=share_access,
            create_disposition=create_disposition,
            directory=directory,
        )

    def forbidden_write(_descriptor: int, _body: object) -> NoReturn:
        nonlocal writes
        writes += 1
        pytest.fail("tree substitution must fail before any blob-body write")

    monkeypatch.setattr(blobs, "_windows_open_relative_handle", racing_relative_open)
    monkeypatch.setattr(blobs.os, "write", forbidden_write)

    with pytest.raises(BlobStoreError) as captured:
        BlobStore(run_directory).snapshot(b"payload", media_type="text/plain")

    assert captured.value.diagnostic.code == DiagnosticCode("BLOB_WRITE_FAILED")
    assert directory_calls == attack_call
    assert writes == 0
    assert canary.read_bytes() == b"UNCHANGED"
    assert {path.name for path in external.iterdir()} == {canary.name}
    assert canonical_parent is not None
    assert renamed_parent is not None
    canonical_parent.rmdir()
    created_path = renamed_parent / created_child
    if created_path.exists():
        created_path.rmdir()
    renamed_parent.rmdir()


@pytest.mark.parametrize(
    ("body", "media_type", "error_type"),
    [
        (bytearray(b"mutable"), "text/plain", TypeError),
        (b"payload", "", ValueError),
        (b"payload", "x" * 256, ValueError),
        (b"payload", 1, TypeError),
    ],
)
def test_blob_inputs_are_strict(
    tmp_path: Path,
    body: object,
    media_type: object,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        BlobStore(tmp_path / "run").snapshot(
            body,  # pyright: ignore[reportArgumentType]
            media_type=media_type,  # pyright: ignore[reportArgumentType]
        )
