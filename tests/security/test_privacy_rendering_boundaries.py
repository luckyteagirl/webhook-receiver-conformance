"""Secret, terminal, log-record, HTML, schema, and action privacy regressions."""
# ruff: noqa: INP001, S105

from __future__ import annotations

import json
import re
from importlib.metadata import distribution
from pathlib import Path

from typer.testing import CliRunner

from webhook_receiver_conformance.cli.main import app
from webhook_receiver_conformance.reporting.html import (
    HTML_CSP,
    template_engine_for_tests,
)

ROOT = Path(__file__).resolve().parents[2]
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
SECRET = "security-regression-secret-canary"


def test_plan_directory_contains_no_resolved_secret(tmp_path: Path) -> None:
    runner = CliRunner()
    project = tmp_path / "project"
    initialized = runner.invoke(app, ["init", str(project)])
    assert initialized.exit_code == 0
    bundle = project / "bundle"
    planned = runner.invoke(
        app,
        [
            "--json",
            "plan",
            "--config",
            str(project / "webhook-conformance.yaml"),
            "--out",
            str(bundle),
        ],
        env={"WEBHOOK_TEST_SECRET": SECRET},
    )
    assert planned.exit_code == 0, planned.stderr
    for path in bundle.rglob("*"):
        if path.is_file():
            assert SECRET.encode() not in path.read_bytes()


def test_hostile_diagnostic_text_cannot_emit_terminal_controls(tmp_path: Path) -> None:
    hostile = tmp_path / "bad-\x1b]8;;https://invalid\x07link.yaml"
    result = CliRunner().invoke(
        app,
        ["validate", "--config", str(hostile)],
        env={"NO_COLOR": "1"},
    )
    rendered = result.stdout + result.stderr
    assert ANSI.search(rendered) is None
    assert "\x07" not in rendered


def test_json_encoding_prevents_forged_records() -> None:
    hostile = "first\nsecond\rthird\x1b[31m"
    encoded = json.dumps({"message": hostile}, ensure_ascii=True, separators=(",", ":")) + "\n"
    assert encoded.count("\n") == 1
    assert "\r" not in encoded
    assert "\x1b" not in encoded
    assert "\\n" in encoded
    assert "\\r" in encoded
    assert "\\u001b" in encoded


def test_template_autoescapes_every_evidence_context_and_has_locked_csp() -> None:
    hostile = '</p><script>alert(1)</script><a href="javascript:alert(1)">'
    rendered = template_engine_for_tests().render_source(
        '<div xmlns:t="urn:webhook-conformance:template">${value}</div>',
        {"value": hostile},
    )
    assert "<script>" not in rendered
    assert "<a " not in rendered
    assert "&lt;script&gt;" in rendered
    template = ROOT.joinpath(
        "src/webhook_receiver_conformance/reporting/templates/report.html"
    ).read_text(encoding="utf-8")
    assert "|safe" not in template.casefold()
    assert "script-src 'none'" in HTML_CSP


def test_configuration_has_no_tls_verification_bypass() -> None:
    schema_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in ROOT.joinpath("schemas").rglob("*.json")
    ).casefold()
    assert '"verify"' not in schema_text
    assert "verify=false" not in schema_text


def test_installed_distribution_exposes_only_the_owned_console_script() -> None:
    entry_points = list(distribution("webhook-receiver-conformance").entry_points)
    assert [
        (entry.group, entry.name, entry.value)
        for entry in entry_points
    ] == [
        (
            "console_scripts",
            "webhook-conformance",
            "webhook_receiver_conformance.cli:run_cli",
        )
    ]


def test_action_defaults_to_redacted_artifacts_and_least_privilege() -> None:
    action = ROOT.joinpath("action.yml").read_text(encoding="utf-8")
    wrapper = ROOT.joinpath(".github/actions/run_action.py").read_text(encoding="utf-8")
    package_workflow = ROOT.joinpath(
        ".github/workflows/package-test.yml"
    ).read_text(encoding="utf-8")
    assert 'default: "false"' in action
    assert '"blobs"' not in wrapper.split("_SAFE_ARTIFACT_NAMES", 1)[1].split(")", 1)[0]
    assert "permissions:\n  contents: read" in package_workflow
    assert "contents: write" not in package_workflow
