"""Hostile run-bundle replay-loader tests for TASK-0110."""
# ruff: noqa: INP001, TC001, TC003

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

import webhook_receiver_conformance.manifest.loader as loader_module
from webhook_receiver_conformance.config.loader import load_project_config
from webhook_receiver_conformance.config.models import DeliverStep, ProjectConfig
from webhook_receiver_conformance.domain.hashing import compute_manifest_id
from webhook_receiver_conformance.errors import ErrorCategory, ResultCategory
from webhook_receiver_conformance.manifest.compiler import (
    MANIFEST_FILENAME,
    CompiledRunBundle,
    compile_run_bundle,
)
from webhook_receiver_conformance.manifest.loader import (
    MAX_MANIFEST_BYTES,
    BundleLoadError,
    load_replay_bundle,
    normalized_manifest_digest,
)
from webhook_receiver_conformance.manifest.models import RunManifest

_CREATED_AT = "2026-07-26T20:00:00Z"
_SEED = "task-0110-replay-seed"
_INVALID_TRANSFORMS: list[tuple[Callable[[bytes], bytes], str]] = [
    (
        lambda value: value.replace(
            b'{\n  "blobs"',
            b'{\n  "blobs": [],\n  "blobs"',
            1,
        ),
        "MANIFEST_JSON_INVALID",
    ),
    (lambda _value: b"{", "MANIFEST_JSON_INVALID"),
    (lambda _value: b"\xff", "MANIFEST_UTF8_INVALID"),
    (
        lambda _value: (b"[" * 100) + b"0" + (b"]" * 100),
        "MANIFEST_ROOT_INVALID",
    ),
]


def _compile(directory: Path) -> CompiledRunBundle:
    loaded = load_project_config("examples/project-config.minimal.yaml")
    assert loaded.config is not None
    assert loaded.project_root is not None
    config = _unsigned(loaded.config)
    return compile_run_bundle(
        config,
        project_root=loaded.project_root,
        bundle_directory=directory,
        seed=_SEED,
        created_at=_CREATED_AT,
        python_version="3.13.5",
        dependencies_digest="sha256:" + ("00" * 32),
        secret_fingerprints={
            "env:WEBHOOK_TEST_SECRET": "sha256:" + ("a5" * 32),
        },
    )


def _unsigned(config: ProjectConfig) -> ProjectConfig:
    step = cast("DeliverStep", config.scenarios[0].steps[0])
    action = step.deliver.model_copy(update={"signer": None})
    scenario = config.scenarios[0].model_copy(
        update={
            "steps": (
                step.model_copy(update={"deliver": action}),
                *config.scenarios[0].steps[1:],
            )
        }
    )
    return config.model_copy(update={"scenarios": (scenario,)})


def test_loads_only_verified_bundle_artifacts_with_stable_digest(tmp_path: Path) -> None:
    compiled = _compile(tmp_path)

    loaded = load_replay_bundle(tmp_path)

    assert loaded.manifest == compiled.manifest
    assert loaded.manifest_bytes == compiled.manifest_bytes
    assert (
        loaded.normalized_digest
        == "sha256:f31ef8908be16f4fd76d2c1dcb21ca6bd0f710b07c84dd610cfdb8c2e2e855c0"
    )
    assert normalized_manifest_digest(loaded.manifest) == loaded.normalized_digest
    assert tuple(blob.sha256 for blob in loaded.blobs) == tuple(
        blob.sha256 for blob in compiled.blobs
    )
    assert all(blob.path.is_relative_to(tmp_path) for blob in loaded.blobs)


def test_normalized_digest_excludes_schema_declared_volatile_fields(tmp_path: Path) -> None:
    compiled = _compile(tmp_path)
    wire = compiled.manifest.to_wire()
    wire["created_at"] = "2026-07-27T20:00:00Z"
    wire["environment"] = {
        "os": "different-os",
        "architecture": "different-architecture",
        "timezone": "UTC",
    }
    wire["manifest_id"] = compute_manifest_id(wire)
    changed_volatile_fields = RunManifest.from_wire(wire)

    assert normalized_manifest_digest(changed_volatile_fields) == (
        normalized_manifest_digest(compiled.manifest)
    )


def test_loader_has_no_source_fixture_secret_generator_or_network_inputs(tmp_path: Path) -> None:
    _compile(tmp_path)
    signature = str(loader_module.load_replay_bundle.__annotations__)

    loaded = load_replay_bundle(tmp_path)

    assert set(loader_module.load_replay_bundle.__annotations__) == {"directory", "return"}
    assert "secret" not in signature.casefold()
    assert "fixture" not in signature.casefold()
    assert loaded.manifest.scenarios


def test_changed_manifest_content_is_rejected_by_canonical_id(tmp_path: Path) -> None:
    _compile(tmp_path)
    path = tmp_path / MANIFEST_FILENAME
    wire = json.loads(path.read_bytes())
    wire["tool"]["version"] = "tampered"
    path.write_text(json.dumps(wire), encoding="utf-8")

    with pytest.raises(BundleLoadError) as captured:
        load_replay_bundle(tmp_path)

    assert captured.value.diagnostic.code == "MANIFEST_ID_MISMATCH"
    assert captured.value.diagnostic.category is ErrorCategory.ARTIFACT_INTEGRITY_ERROR


def test_unknown_major_is_unsupported_before_any_blob_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _compile(tmp_path)
    path = tmp_path / MANIFEST_FILENAME
    wire = json.loads(path.read_bytes())
    wire["schema_version"] = "2.0"
    wire["manifest_id"] = compute_manifest_id(wire)
    path.write_text(json.dumps(wire), encoding="utf-8")
    blob_accesses = 0

    def forbidden_verify(*_args: object, **_kwargs: object) -> None:
        nonlocal blob_accesses
        blob_accesses += 1
        pytest.fail("unknown major must fail before blob access")

    monkeypatch.setattr(loader_module.BlobStore, "verify", forbidden_verify)

    with pytest.raises(BundleLoadError) as captured:
        load_replay_bundle(tmp_path)

    assert captured.value.diagnostic.code == "MANIFEST_MAJOR_UNSUPPORTED"
    assert captured.value.diagnostic.result_category is ResultCategory.UNSUPPORTED
    assert blob_accesses == 0


def test_unbounded_version_component_is_classified_without_integer_conversion(
    tmp_path: Path,
) -> None:
    _compile(tmp_path)
    path = tmp_path / MANIFEST_FILENAME
    wire = json.loads(path.read_bytes())
    wire["schema_version"] = ("9" * 1_000) + ".0"
    wire["manifest_id"] = compute_manifest_id(wire)
    path.write_text(json.dumps(wire), encoding="utf-8")

    with pytest.raises(BundleLoadError) as captured:
        load_replay_bundle(tmp_path)

    assert captured.value.diagnostic.code == "MANIFEST_VERSION_INVALID"


@pytest.mark.parametrize(
    ("transform", "expected_code"),
    _INVALID_TRANSFORMS,
)
def test_duplicate_malformed_and_recursive_json_fail_closed(
    tmp_path: Path,
    transform: Callable[[bytes], bytes],
    expected_code: str,
) -> None:
    _compile(tmp_path)
    path = tmp_path / MANIFEST_FILENAME
    path.write_bytes(transform(path.read_bytes()))

    with pytest.raises(BundleLoadError) as captured:
        load_replay_bundle(tmp_path)

    assert captured.value.diagnostic.code == expected_code


def test_manifest_byte_limit_is_checked_before_json_parsing(tmp_path: Path) -> None:
    tmp_path.mkdir(exist_ok=True)
    path = tmp_path / MANIFEST_FILENAME
    with path.open("wb") as stream:
        stream.truncate(MAX_MANIFEST_BYTES + 1)

    with pytest.raises(BundleLoadError) as captured:
        load_replay_bundle(tmp_path)

    assert captured.value.diagnostic.code == "MANIFEST_BYTE_LIMIT"
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT


def test_missing_and_digest_mismatched_blobs_fail_before_replay(tmp_path: Path) -> None:
    compiled = _compile(tmp_path)
    victim = compiled.blobs[0].path
    original = victim.read_bytes()
    victim.unlink()
    with pytest.raises(BundleLoadError) as missing:
        load_replay_bundle(tmp_path)
    assert missing.value.diagnostic.code == "BLOB_INTEGRITY_ERROR"

    victim.parent.mkdir(parents=True, exist_ok=True)
    victim.write_bytes(original + b"x")
    with pytest.raises(BundleLoadError) as changed:
        load_replay_bundle(tmp_path)
    assert changed.value.diagnostic.code == "BLOB_INTEGRITY_ERROR"


def test_manifest_and_bundle_symlinks_are_rejected(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _compile(bundle)
    linked_manifest = tmp_path / "linked-manifest"
    try:
        linked_manifest.symlink_to(bundle / MANIFEST_FILENAME)
    except OSError:
        pytest.skip("symlink creation unavailable")
    (bundle / MANIFEST_FILENAME).unlink()
    linked_manifest.replace(bundle / MANIFEST_FILENAME)

    with pytest.raises(BundleLoadError) as manifest_error:
        load_replay_bundle(bundle)

    assert manifest_error.value.diagnostic.code == "MANIFEST_FILE_INVALID"

    directory_link = tmp_path / "bundle-link"
    try:
        directory_link.symlink_to(bundle, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation unavailable")
    with pytest.raises(BundleLoadError) as directory_error:
        load_replay_bundle(directory_link)
    assert directory_error.value.diagnostic.code == "BUNDLE_DIRECTORY_INVALID"
