"""Isolated contract tests for the TASK-0810 objective-evidence validator."""
# ruff: noqa: INP001

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import TYPE_CHECKING, cast

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.validate_task_0810_evidence import (  # noqa: E402
    EXPECTATIONS,
    EvidenceExpectation,
    main,
    validate_evidence,
)

if TYPE_CHECKING:
    import pytest

IMPLEMENTATION_COMMIT = "1" * 40


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _path(root: Path, relative_path: str) -> Path:
    return root.joinpath(*relative_path.split("/"))


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _artifact_paths() -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                artifact_path
                for expectation in EXPECTATIONS
                for artifact_path in expectation.artifact_paths
            }
            | {"uv.lock"}
        )
    )


def _traceability_links() -> list[dict[str, str]]:
    return [
        {
            "task_id": "TASK-0810",
            "test_id": expectation.test_id,
            "requirement_id": expectation.requirement_id,
            "evidence_artifact": expectation.evidence_path,
        }
        for expectation in EXPECTATIONS
    ]


def _record(root: Path, expectation: EvidenceExpectation) -> dict[str, object]:
    return {
        "schema_version": 1,
        "test_id": expectation.test_id,
        "requirement_id": expectation.requirement_id,
        "status": "passed",
        "implementation_commit": IMPLEMENTATION_COMMIT,
        "command": expectation.command,
        "exit_code": 0,
        "test_nodes": list(expectation.test_nodes),
        "artifact_sha256s": {
            artifact_path: _sha256(_path(root, artifact_path))
            for artifact_path in expectation.artifact_paths
        },
        "environment": {
            "python_implementation": "CPython",
            "python_version": "3.12.11",
            "platform": "win32",
            "uv_lock_sha256": _sha256(root / "uv.lock"),
        },
    }


def _materialize_valid_repository(root: Path) -> None:
    for artifact_path in _artifact_paths():
        if artifact_path == "machine/traceability.json":
            continue
        path = _path(root, artifact_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"carrier:{artifact_path}\n", encoding="utf-8")
    _write_json(
        root / "machine" / "traceability.json",
        {
            "schema_version": "1.0.0-draft.1",
            "links": _traceability_links(),
        },
    )
    for expectation in EXPECTATIONS:
        _write_json(_path(root, expectation.evidence_path), _record(root, expectation))


def _load_record(root: Path, expectation: EvidenceExpectation) -> dict[str, object]:
    value = cast(
        "object",
        json.loads(_path(root, expectation.evidence_path).read_text(encoding="utf-8")),
    )
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


def test_exact_fourteen_record_set_is_accepted_offline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _materialize_valid_repository(tmp_path)

    assert validate_evidence(tmp_path, implementation_commit=IMPLEMENTATION_COMMIT) == ()
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "--implementation-commit",
                IMPLEMENTATION_COMMIT,
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.out == "validated 14 TASK-0810 evidence records\n"
    assert captured.err == ""


def test_missing_and_unexpected_vt_paths_are_rejected(tmp_path: Path) -> None:
    _materialize_valid_repository(tmp_path)
    missing = EXPECTATIONS[0]
    _path(tmp_path, missing.evidence_path).unlink()
    _write_json(tmp_path / "validation" / "evidence" / "VT-EXTRA.json", {})

    errors = validate_evidence(tmp_path, implementation_commit=IMPLEMENTATION_COMMIT)

    assert f"{missing.evidence_path}: required evidence record is missing" in errors
    assert any("unexpected VT record" in error and "VT-EXTRA.json" in error for error in errors)


def test_path_bound_identifiers_commit_command_and_nodes_are_rejected_on_mismatch(
    tmp_path: Path,
) -> None:
    _materialize_valid_repository(tmp_path)
    expectation = EXPECTATIONS[0]
    record = _load_record(tmp_path, expectation)
    record["test_id"] = "VT-TEST-020"
    record["requirement_id"] = "TEST-020"
    record["implementation_commit"] = "2" * 40
    record["command"] = "uv run pytest -q"
    record["test_nodes"] = ["tests/not-the-proof.py::test_wrong"]
    _write_json(_path(tmp_path, expectation.evidence_path), record)

    errors = validate_evidence(tmp_path, implementation_commit=IMPLEMENTATION_COMMIT)

    assert any("test_id does not match" in error for error in errors)
    assert any("requirement_id does not match" in error for error in errors)
    assert any("implementation_commit does not match" in error for error in errors)
    assert any("command does not match" in error for error in errors)
    assert any("test_nodes do not match" in error for error in errors)


def test_failing_status_and_nonzero_exit_code_are_rejected(tmp_path: Path) -> None:
    _materialize_valid_repository(tmp_path)
    expectation = EXPECTATIONS[1]
    record = _load_record(tmp_path, expectation)
    record["status"] = "failed"
    record["exit_code"] = 1
    _write_json(_path(tmp_path, expectation.evidence_path), record)

    errors = validate_evidence(tmp_path, implementation_commit=IMPLEMENTATION_COMMIT)

    assert f"{expectation.evidence_path}: status must be passed" in errors
    assert f"{expectation.evidence_path}: exit_code must be integer zero" in errors


def test_closed_record_artifact_and_environment_shapes_are_enforced(tmp_path: Path) -> None:
    _materialize_valid_repository(tmp_path)
    expectation = EXPECTATIONS[2]
    record = _load_record(tmp_path, expectation)
    record["unexpected"] = True
    artifacts = cast("dict[str, object]", record["artifact_sha256s"])
    artifacts["not/a/carrier.txt"] = "sha256:" + ("0" * 64)
    environment = cast("dict[str, object]", record["environment"])
    environment["python_implementation"] = "PyPy"
    environment["platform"] = "plan9"
    environment["uv_lock_sha256"] = "sha256:" + ("0" * 64)
    environment["unexpected"] = "field"
    _write_json(_path(tmp_path, expectation.evidence_path), record)

    errors = validate_evidence(tmp_path, implementation_commit=IMPLEMENTATION_COMMIT)

    assert any("fields do not match the closed record contract" in error for error in errors)
    assert any("artifact_sha256s paths do not match" in error for error in errors)
    assert any("environment fields do not match" in error for error in errors)
    assert any("python_implementation must be CPython" in error for error in errors)
    assert any("environment.platform is not supported" in error for error in errors)
    assert any("environment.uv_lock_sha256 does not match uv.lock" in error for error in errors)


def test_carrier_artifact_tampering_is_rejected(tmp_path: Path) -> None:
    _materialize_valid_repository(tmp_path)
    expectation = EXPECTATIONS[3]
    artifact_path = next(
        path
        for path in expectation.artifact_paths
        if path not in {"machine/requirements.yaml", "machine/traceability.json"}
    )
    _path(tmp_path, artifact_path).write_text("tampered\n", encoding="utf-8")

    errors = validate_evidence(tmp_path, implementation_commit=IMPLEMENTATION_COMMIT)

    assert f"{expectation.evidence_path}: {artifact_path} SHA-256 does not match" in errors


def test_duplicate_json_fields_are_rejected(tmp_path: Path) -> None:
    _materialize_valid_repository(tmp_path)
    expectation = EXPECTATIONS[4]
    _path(tmp_path, expectation.evidence_path).write_text(
        '{"schema_version":1,"schema_version":1}\n',
        encoding="utf-8",
    )

    errors = validate_evidence(tmp_path, implementation_commit=IMPLEMENTATION_COMMIT)

    assert f"{expectation.evidence_path}: JSON object contains a duplicate field" in errors


def test_task_traceability_must_name_the_same_exact_fourteen_records(tmp_path: Path) -> None:
    _materialize_valid_repository(tmp_path)
    traceability_path = tmp_path / "machine" / "traceability.json"
    traceability = cast(
        "dict[str, object]",
        json.loads(traceability_path.read_text(encoding="utf-8")),
    )
    links = cast("list[dict[str, str]]", traceability["links"])
    links.pop()
    extra = deepcopy(links[0])
    extra["test_id"] = "VT-EXTRA"
    extra["requirement_id"] = "EXTRA-001"
    extra["evidence_artifact"] = "validation/evidence/VT-EXTRA.json"
    links.append(extra)
    _write_json(traceability_path, traceability)

    errors = validate_evidence(tmp_path, implementation_commit=IMPLEMENTATION_COMMIT)

    assert any("missing VT-TEST-020/TEST-020 link" in error for error in errors)
    assert any("contains 1 unexpected TASK-0810 link" in error for error in errors)


def test_validator_rejects_an_unbound_commit_before_reading_files(tmp_path: Path) -> None:
    assert validate_evidence(tmp_path, implementation_commit="HEAD") == (
        "validator: implementation commit must be 40 lowercase hexadecimal characters",
    )
