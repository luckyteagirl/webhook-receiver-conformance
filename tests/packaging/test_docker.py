"""OCI distribution contracts for the local conformance harness image."""
# ruff: noqa: INP001, PLR2004, S108, S603, S607

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "webhook-receiver-conformance:contract-test"


def _docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        cwd=ROOT,
        check=check,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=300,
    )


@pytest.fixture(scope="module")
def image() -> str:
    if shutil.which("docker") is None:
        pytest.skip("Docker is unavailable")
    available = _docker("info", "--format", "{{.OSType}}", check=False)
    if available.returncode != 0 or available.stdout.strip() != "linux":
        pytest.skip("A Linux Docker daemon is unavailable")
    _docker(
        "build",
        "--pull=false",
        "--tag",
        IMAGE,
        "--build-arg",
        "OCI_REVISION=contract-test",
        ".",
    )
    return IMAGE


def test_image_is_digest_pinned_and_has_no_credential_copy_paths() -> None:
    dockerfile = ROOT.joinpath("Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.count("@sha256:") == 2
    assert "COPY . " not in dockerfile
    assert ".git" in ROOT.joinpath(".dockerignore").read_text(encoding="utf-8")


def test_image_runs_installed_cli_as_non_root(image: str) -> None:
    version = _docker("run", "--rm", image, "--json", "version")
    identity = _docker("run", "--rm", "--entrypoint", "id", image, "-u")
    document = json.loads(version.stdout)
    assert document["package"] == "0.1.0"
    assert int(identity.stdout.strip()) == 65532


def test_read_only_root_supports_writable_artifact_mount(image: str) -> None:
    volume = f"webhook-conformance-test-{uuid.uuid4()}"
    _docker("volume", "create", volume)
    try:
        common = (
            "run",
            "--rm",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--mount",
            f"type=volume,src={volume},dst=/artifacts",
            image,
        )
        initialized = _docker(*common, "init", "/artifacts/project")
        validated = _docker(
            *common,
            "validate",
            "--config",
            "/artifacts/project/webhook-conformance.yaml",
        )
        ownership = _docker(
            "run",
            "--rm",
            "--entrypoint",
            "stat",
            "--mount",
            f"type=volume,src={volume},dst=/artifacts",
            image,
            "-c",
            "%u:%g",
            "/artifacts/project/webhook-conformance.yaml",
        )
        assert "Initialized" in initialized.stdout
        assert "Configuration valid" in validated.stdout
        assert ownership.stdout.strip() == "65532:65532"
    finally:
        _docker("volume", "rm", volume, check=False)
