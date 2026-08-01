"""Publication hygiene and public-document contract tests."""
# ruff: noqa: INP001

from __future__ import annotations

import socket
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import cast

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.check_ste_docs import validate_documents  # noqa: E402
from scripts.sanitize_junit_evidence import sanitized_junit  # noqa: E402


def test_public_documents_pass_mechanical_ste_checks() -> None:
    assert validate_documents(ROOT) == []


def test_repository_license_is_declared_and_present() -> None:
    project = ROOT.joinpath("pyproject.toml").read_text(encoding="utf-8")
    license_text = ROOT.joinpath("LICENSE").read_text(encoding="utf-8")

    assert 'license = "Apache-2.0"' in project
    assert 'license-files = ["LICENSE"]' in project
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text


def test_repository_identity_is_public_and_consistent() -> None:
    project = ROOT.joinpath("pyproject.toml").read_text(encoding="utf-8")
    codeowners = ROOT.joinpath(".github/CODEOWNERS").read_text(encoding="utf-8")
    conduct = ROOT.joinpath("CODE_OF_CONDUCT.md").read_text(encoding="utf-8")

    repository = "https://github.com/luckyteagirl/webhook-receiver-conformance"
    assert f'Homepage = "{repository}"' in project
    assert f'Source = "{repository}"' in project
    assert "* @luckyteagirl" in codeowners
    assert "@luckyteagirl" in conduct


def test_action_example_uses_read_only_permissions_and_all_action_inputs() -> None:
    example = ROOT.joinpath("examples/github-action-workflow.yml")
    document = cast(
        "dict[str, object]",
        yaml.load(example.read_text(encoding="utf-8"), Loader=yaml.BaseLoader),  # noqa: S506
    )
    permissions = cast("dict[str, str]", document["permissions"])
    serialized = example.read_text(encoding="utf-8")

    assert permissions == {"contents": "read"}
    assert "contents: write" not in serialized
    assert "packages: write" not in serialized
    assert "id-token: write" not in serialized
    assert 'include-raw-artifacts: "false"' in serialized
    assert "actions/upload-artifact@" in serialized

    action = cast(
        "dict[str, object]",
        yaml.safe_load(ROOT.joinpath("action.yml").read_text(encoding="utf-8")),
    )
    action_inputs = cast("dict[str, object]", action["inputs"])
    action_outputs = cast("dict[str, object]", action["outputs"])
    documentation = ROOT.joinpath("docs/github-action.md").read_text(encoding="utf-8")
    for name in (*action_inputs, *action_outputs):
        assert f"| `{name}` |" in documentation


def test_junit_sanitizer_removes_workspace_and_hostname() -> None:
    workspace = ROOT
    hostname = socket.gethostname()
    source = (
        f'<testsuites><testsuite hostname="{hostname}">'
        f'<testcase><skipped message="{workspace}\\tests\\test_one.py" />'
        "</testcase></testsuite></testsuites>"
    ).encode()

    sanitized = sanitized_junit(
        source,
        workspace=workspace,
        private_hostname=hostname,
    )
    root = ET.fromstring(sanitized)  # noqa: S314

    assert str(workspace).encode() not in sanitized
    assert hostname.encode() not in sanitized
    assert b"WORKSPACE" in sanitized
    suite = root.find("testsuite")
    assert suite is not None
    assert suite.get("hostname") == "local-host"


def test_tracked_junit_evidence_contains_only_public_location_values() -> None:
    evidence = ROOT.joinpath("validation/evidence/windows-cpython-3.12.junit.xml").read_bytes()
    root = ET.fromstring(evidence)  # noqa: S314
    suite = root.find("testsuite")

    assert suite is not None
    assert suite.get("hostname") == "local-host"
    assert b"WORKSPACE" in evidence
    assert b"C:\\Users\\" not in evidence
