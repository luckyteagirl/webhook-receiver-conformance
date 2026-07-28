"""Filesystem confinement and argv-only child-process security regressions."""
# ruff: noqa: INP001, PERF401, PLR2004, SIM102

from __future__ import annotations

import ast
import os
import stat
import sys
from pathlib import Path

import pytest

from webhook_receiver_conformance.config.loader import load_project_config
from webhook_receiver_conformance.config.models import CommandObserverConfig
from webhook_receiver_conformance.journal.schema import create_run_database
from webhook_receiver_conformance.observers.command import CommandObserver, CommandObserverError

ROOT = Path(__file__).resolve().parents[2]
MINIMAL = ROOT / "examples" / "project-config.minimal.yaml"


@pytest.mark.parametrize(
    "output",
    [
        "/absolute/output",
        "../escape",
        "reports/../../escape",
        r"reports\alternate",
        "C:/drive/output",
        r"C:\drive\output",
        r"\\server\share",
        "//server/share",
    ],
)
def test_output_escape_forms_are_rejected(output: str) -> None:
    result = load_project_config(MINIMAL, overrides={"output": output})
    assert not result.ok
    assert str(result.diagnostics[0].code).startswith("CFG_CLI_OUTPUT_")


def test_fixture_traversal_and_directory_paths_fail_validation(tmp_path: Path) -> None:
    config = tmp_path / "project.yaml"
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    config.write_text(
        MINIMAL.read_text(encoding="utf-8").replace(
            "path: fixtures/payment_succeeded.json",
            "path: ../outside.json",
        ),
        encoding="utf-8",
    )
    result = load_project_config(config)
    assert not result.ok
    assert str(result.diagnostics[0].code).startswith("CFG_PATH_")


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode contract")
def test_run_directory_and_database_are_owner_only(tmp_path: Path) -> None:
    created = create_run_database(tmp_path)
    assert stat.S_IMODE(created.run_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(created.database_path.stat().st_mode) == 0o600


def test_path_search_is_disabled_without_explicit_policy(tmp_path: Path) -> None:
    config = CommandObserverConfig.model_validate(
        {
            "type": "command",
            "argv": ["python", "-c", "print('{}')"],
            "timeout": "1s",
        }
    )
    with pytest.raises(CommandObserverError) as captured:
        CommandObserver(config, project_root=tmp_path)
    assert str(captured.value.diagnostic.code) == "OBSERVER_PATH_SEARCH_FORBIDDEN"


@pytest.mark.anyio
async def test_shell_metacharacters_remain_one_literal_argument(tmp_path: Path) -> None:
    marker = tmp_path / "shell-marker"
    hostile = f"literal;&|>$({marker})"
    code = (
        "import json,sys;"
        "request=json.loads(sys.stdin.buffer.read());"
        "print(json.dumps({"
        "'protocol_version':'1.0','request_id':request['request_id'],"
        "'status':'ok','capabilities':{"
        "'evidence_types':['integer'],'evidence_keys':['processing_count'],"
        "'read_only':True,'idempotent':True,'max_queries':64,"
        "'supports_pending':True,'stable_snapshot_ids':True},"
        "'snapshot_id':sys.argv[1],"
        "'evidence':[],'error':None}))"
    )
    config = CommandObserverConfig.model_validate(
        {
            "type": "command",
            "argv": [sys.executable, "-c", code, hostile],
            "timeout": "2s",
        }
    )
    observer = CommandObserver(config, project_root=tmp_path)
    from webhook_receiver_conformance.observers.protocol import (  # noqa: PLC0415
        ObserverOperation,
        ObserverRequest,
    )

    response = await observer.invoke(
        ObserverRequest.model_validate(
            {
                    "protocol_version": "1.0",
                    "request_id": "request_01J00000000000000000000000",
                    "operation": ObserverOperation.CAPABILITIES.value,
                }
        )
    )
    assert response.snapshot_id == hostile
    assert not marker.exists()


def test_source_tree_has_no_shell_true_or_command_string_launcher() -> None:
    violations: list[str] = []
    for path in ROOT.joinpath("src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    violations.append(f"{path}: shell=True")
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "os" and node.func.attr in {"popen", "system"}:
                    violations.append(f"{path}: os.{node.func.attr}")
    assert violations == []
