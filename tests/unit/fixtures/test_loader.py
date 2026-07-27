"""Contract and security tests for exact-byte fixture loading."""
# ruff: noqa: INP001, PLR0915, PLR2004, S603, S607, SLF001

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import NoReturn

import pytest
from jsonschema import Draft202012Validator

from webhook_receiver_conformance.config.models import FixtureConfig
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.errors import ErrorCategory, ResultCategory
from webhook_receiver_conformance.fixtures import loader as fixture_loader
from webhook_receiver_conformance.fixtures.loader import (
    DEFAULT_MAX_FIXTURE_BYTES,
    HARD_MAX_FIXTURE_BYTES,
    FixtureLoadError,
    load_fixture,
    load_fixture_bytes,
)
from webhook_receiver_conformance.types import DiagnosticCode

PROJECT_ROOT = Path(__file__).parents[3]


def _fixture(path: str, *, media_type: str = "application/octet-stream") -> FixtureConfig:
    return FixtureConfig.model_validate(
        {
            "id": "payload",
            "path": path,
            "media_type": media_type,
        }
    )


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


def test_load_fixture_preserves_arbitrary_bytes_and_emits_manifest_metadata(
    tmp_path: Path,
) -> None:
    body = b"\x00\xff\r\nnot-utf8:\x80"
    source = tmp_path / "fixtures" / "payload.bin"
    source.parent.mkdir()
    source.write_bytes(body)

    loaded = load_fixture(
        _fixture("fixtures/payload.bin"),
        project_root=tmp_path,
    )

    assert loaded.body == body
    assert loaded.byte_length == len(body)
    assert loaded.blob_sha256 == sha256_digest(body)
    assert loaded.sha256 == loaded.blob_sha256
    assert loaded.source_path == "fixtures/payload.bin"
    assert "not-utf8" not in repr(loaded)
    assert "fixtures/payload.bin" not in repr(loaded)
    assert loaded.to_manifest_entry() == {
        "fixture_id": "payload",
        "blob_sha256": sha256_digest(body),
        "byte_length": len(body),
        "media_type": "application/octet-stream",
        "source_path": "fixtures/payload.bin",
    }
    schema = json.loads(
        (PROJECT_ROOT / "schemas" / "fixture-manifest.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(  # pyright: ignore[reportUnknownMemberType]
        {
            "schema_version": "1.0",
            "fixtures": [loaded.to_manifest_entry()],
        }
    )


def test_changing_one_byte_changes_the_fixture_digest(tmp_path: Path) -> None:
    source = tmp_path / "payload.bin"
    source.write_bytes(b"abc")
    first = load_fixture(_fixture("payload.bin"), project_root=tmp_path)

    source.write_bytes(b"abd")
    second = load_fixture(_fixture("payload.bin"), project_root=tmp_path)

    assert first.body != second.body
    assert first.blob_sha256 != second.blob_sha256


def test_default_one_mib_boundary_passes_and_one_byte_more_is_classified(
    tmp_path: Path,
) -> None:
    source = tmp_path / "sensitive-canary-name.bin"
    source.write_bytes(b"x" * DEFAULT_MAX_FIXTURE_BYTES)
    assert len(load_fixture_bytes(tmp_path, source.name)) == DEFAULT_MAX_FIXTURE_BYTES

    source.write_bytes(b"x" * (DEFAULT_MAX_FIXTURE_BYTES + 1))
    with pytest.raises(FixtureLoadError) as captured:
        load_fixture(_fixture(source.name), project_root=tmp_path)

    diagnostic = captured.value.diagnostic
    assert diagnostic.code == DiagnosticCode("FIXTURE_RESOURCE_LIMIT")
    assert diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert diagnostic.result_category is ResultCategory.INVALID_INPUT
    assert diagnostic.safe_details == {
        "limit": "max_request_bytes",
        "maximum": DEFAULT_MAX_FIXTURE_BYTES,
    }
    serialized = diagnostic.model_dump_json()
    assert source.name not in serialized
    assert "xxxxxxxx" not in serialized


def test_configured_limit_and_hard_limit_boundaries_are_exact(tmp_path: Path) -> None:
    source = tmp_path / "fixture.bin"
    source.write_bytes(b"1234")
    assert load_fixture_bytes(tmp_path, source.name, max_bytes=4) == b"1234"

    source.write_bytes(b"12345")
    with pytest.raises(FixtureLoadError) as captured:
        load_fixture_bytes(tmp_path, source.name, max_bytes=4)
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert captured.value.diagnostic.safe_details["maximum"] == 4

    with pytest.raises(ValueError, match="between 1 and"):
        load_fixture_bytes(tmp_path, source.name, max_bytes=HARD_MAX_FIXTURE_BYTES + 1)
    with pytest.raises(TypeError):
        load_fixture_bytes(tmp_path, source.name, max_bytes=True)


def test_known_oversized_fixture_is_rejected_before_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "oversized.bin"
    source.write_bytes(b"12345")

    def forbidden_read(_descriptor: int, _length: int) -> bytes:
        pytest.fail("known oversized fixture must not be read")

    monkeypatch.setattr(fixture_loader.os, "read", forbidden_read)
    with pytest.raises(FixtureLoadError) as captured:
        load_fixture_bytes(tmp_path, source.name, max_bytes=4)
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT


def test_hard_body_boundary_passes_and_one_byte_more_fails(tmp_path: Path) -> None:
    source = tmp_path / "fixture.bin"
    source.write_bytes(b"x" * HARD_MAX_FIXTURE_BYTES)
    assert (
        len(
            load_fixture_bytes(
                tmp_path,
                source.name,
                max_bytes=HARD_MAX_FIXTURE_BYTES,
            )
        )
        == HARD_MAX_FIXTURE_BYTES
    )

    source.write_bytes(b"x" * (HARD_MAX_FIXTURE_BYTES + 1))
    with pytest.raises(FixtureLoadError) as captured:
        load_fixture_bytes(
            tmp_path,
            source.name,
            max_bytes=HARD_MAX_FIXTURE_BYTES,
        )
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert captured.value.diagnostic.safe_details["maximum"] == HARD_MAX_FIXTURE_BYTES


@pytest.mark.parametrize(
    "path",
    [
        "../external.bin",
        ".",
        "",
    ],
)
def test_noncontained_paths_are_rejected_without_path_leakage(
    tmp_path: Path,
    path: str,
) -> None:
    with pytest.raises(FixtureLoadError) as captured:
        load_fixture_bytes(tmp_path, path)

    assert captured.value.diagnostic.code == DiagnosticCode("FIXTURE_PATH_REJECTED")
    assert captured.value.diagnostic.category is ErrorCategory.FIXTURE_ERROR
    assert captured.value.diagnostic.safe_details == {}


def test_absolute_path_is_rejected_without_reading_external_canary(tmp_path: Path) -> None:
    external = tmp_path.parent / "external-fixture-canary.bin"
    external.write_bytes(b"DO-NOT-READ")

    with pytest.raises(FixtureLoadError) as captured:
        load_fixture_bytes(tmp_path, str(external))

    assert captured.value.diagnostic.code == DiagnosticCode("FIXTURE_PATH_REJECTED")


def test_static_symlink_escape_is_rejected_without_canary_leakage(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    external = tmp_path / "external-secret-canary.bin"
    external.write_bytes(b"EXTERNAL-CANARY-CONTENT")
    link = project / "payload.bin"
    _make_symlink(link, external)

    with pytest.raises(FixtureLoadError) as captured:
        load_fixture(_fixture("payload.bin"), project_root=project)

    diagnostic_json = captured.value.diagnostic.model_dump_json()
    assert captured.value.diagnostic.code == DiagnosticCode("FIXTURE_PATH_REJECTED")
    assert external.name not in diagnostic_json
    assert "EXTERNAL-CANARY-CONTENT" not in diagnostic_json
    assert external.read_bytes() == b"EXTERNAL-CANARY-CONTENT"


def test_racing_path_substitution_is_rejected_before_any_fixture_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    nested = project / "nested"
    nested.mkdir()
    fixture = nested / "payload.bin"
    fixture.write_bytes(b"safe")
    external = tmp_path / "external"
    external.mkdir()
    external_fixture = external / fixture.name
    external_fixture.write_bytes(b"EXTERNAL-RACE-CANARY")

    real_open = fixture_loader.os.open
    real_read = fixture_loader.os.read
    swapped = False
    reads = 0
    if os.name == "nt":
        real_windows_open = fixture_loader._windows_open_path  # pyright: ignore[reportPrivateUsage]

        def racing_windows_open(path: Path, *, directory: bool) -> int:
            nonlocal swapped
            handle = real_windows_open(path, directory=directory)
            if directory and not swapped:
                swapped = True
                nested.rename(project / "nested-before-swap")
                _make_directory_junction(nested, external)
            return handle

        def forbidden_read(_descriptor: int, _length: int) -> NoReturn:
            pytest.fail("no read")

        monkeypatch.setattr(fixture_loader, "_windows_open_path", racing_windows_open)
        monkeypatch.setattr(fixture_loader.os, "read", forbidden_read)

        with pytest.raises(FixtureLoadError):
            load_fixture(_fixture("nested/payload.bin"), project_root=project)

        assert swapped is True
        assert external_fixture.read_bytes() == b"EXTERNAL-RACE-CANARY"
        return

    uses_directory_descriptors = (
        fixture_loader.os.open in fixture_loader.os.supports_dir_fd
        and hasattr(fixture_loader.os, "O_NOFOLLOW")
    )
    if uses_directory_descriptors:
        probe = project / "probe"
        _make_symlink(probe, external)
        probe.unlink()

    def racing_open(
        path: str | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and Path(path).name == fixture.name:
            swapped = True
            if uses_directory_descriptors:
                fixture.unlink()
                fixture.symlink_to(external_fixture)
            else:
                return real_open(external_fixture, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    def recording_read(descriptor: int, length: int) -> bytes:
        nonlocal reads
        reads += 1
        return real_read(descriptor, length)

    monkeypatch.setattr(fixture_loader.os, "open", racing_open)
    monkeypatch.setattr(fixture_loader.os, "read", recording_read)

    with pytest.raises(FixtureLoadError):
        load_fixture(_fixture("nested/payload.bin"), project_root=project)

    assert swapped is True
    assert reads == 0
    assert external_fixture.read_bytes() == b"EXTERNAL-RACE-CANARY"


def test_non_regular_fixture_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "directory").mkdir()
    with pytest.raises(FixtureLoadError) as captured:
        load_fixture_bytes(tmp_path, "directory")
    assert captured.value.diagnostic.code == DiagnosticCode("FIXTURE_NOT_REGULAR")


@pytest.mark.parametrize("extension", [".zip", ".tar", ".tgz", ".tar.gz"])
def test_archive_extensions_are_opaque_raw_bytes(
    tmp_path: Path,
    extension: str,
) -> None:
    body = b"PK\x03\x04../must-not-extract\x00raw-archive-fixture"
    source = tmp_path / f"payload{extension}"
    source.write_bytes(body)

    assert load_fixture_bytes(tmp_path, source.name) == body
    assert not (tmp_path / "must-not-extract").exists()
