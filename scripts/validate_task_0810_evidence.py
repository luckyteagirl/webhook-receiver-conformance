"""Validate the closed, local TASK-0810 objective-evidence record set."""
# ruff: noqa: C901, EM101, EM102, INP001, ISC004, T201, TRY003

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

ROOT: Final = Path(__file__).resolve().parents[1]
TASK_ID: Final = "TASK-0810"
_RECORD_SCHEMA_VERSION: Final = 1
_MAX_RECORD_BYTES: Final = 64 * 1024
_MAX_TRACEABILITY_BYTES: Final = 1024 * 1024
_MAX_EVIDENCE_DIRECTORY_ENTRIES: Final = 256
_COMMIT: Final = re.compile(r"^[0-9a-f]{40}$")
_PYTHON_VERSION: Final = re.compile(r"^3\.(?:12|13|14)\.[0-9]+$")
_SHA256: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_PLATFORMS: Final = frozenset({"darwin", "linux", "win32"})
_RECORD_FIELDS: Final = frozenset(
    {
        "schema_version",
        "test_id",
        "requirement_id",
        "status",
        "implementation_commit",
        "command",
        "exit_code",
        "test_nodes",
        "artifact_sha256s",
        "environment",
    }
)
_ENVIRONMENT_FIELDS: Final = frozenset(
    {
        "python_implementation",
        "python_version",
        "platform",
        "uv_lock_sha256",
    }
)
_COMMON_ARTIFACTS: Final = (
    "machine/requirements.yaml",
    "machine/traceability.json",
)


class EvidenceReadError(ValueError):
    """A local evidence input could not be decoded safely."""


@dataclass(frozen=True, slots=True)
class EvidenceExpectation:
    """The immutable proof contract for one TASK-0810 verification test."""

    evidence_path: str
    test_id: str
    requirement_id: str
    command: str
    test_nodes: tuple[str, ...]
    artifact_paths: tuple[str, ...]


def _pytest_command(nodes: tuple[str, ...]) -> str:
    return "uv run pytest -q " + " ".join(nodes)


def _artifacts(*paths: str) -> tuple[str, ...]:
    return tuple(sorted({*_COMMON_ARTIFACTS, *paths}))


def _expectation(
    requirement_id: str,
    *,
    nodes: tuple[str, ...],
    artifacts: tuple[str, ...],
) -> EvidenceExpectation:
    test_id = f"VT-{requirement_id}"
    return EvidenceExpectation(
        evidence_path=f"validation/evidence/{test_id}.json",
        test_id=test_id,
        requirement_id=requirement_id,
        command=_pytest_command(nodes),
        test_nodes=nodes,
        artifact_paths=_artifacts(*artifacts),
    )


EXPECTATIONS: Final = (
    _expectation(
        "API-005",
        nodes=(
            "tests/packaging/test_deferred_release_contracts.py"
            "::test_plugin_metadata_has_required_experimental_stability_enum",
            "tests/packaging/test_deferred_release_contracts.py"
            "::test_every_plugin_category_has_no_entry_point_or_runtime_discovery",
        ),
        artifacts=(
            "pyproject.toml",
            "schemas/plugin-metadata.schema.json",
            "tests/packaging/test_deferred_release_contracts.py",
        ),
    ),
    _expectation(
        "ASSERT-017",
        nodes=(
            "tests/schema/test_project_config_assertion_contract.py"
            "::test_custom_and_unknown_assertion_types_are_rejected",
            "tests/schema/test_project_config_assertion_contract.py"
            "::test_hostile_executable_assertion_fields_are_rejected",
        ),
        artifacts=(
            "schemas/project-config.schema.json",
            "tests/schema/test_project_config_assertion_contract.py",
        ),
    ),
    _expectation(
        "COMPAT-009",
        nodes=(
            "tests/packaging/test_deferred_release_contracts.py"
            "::test_default_dependency_and_lock_graph_exclude_http2",
        ),
        artifacts=(
            "pyproject.toml",
            "tests/e2e/test_vertical_slice.py",
            "tests/packaging/test_deferred_release_contracts.py",
            "uv.lock",
        ),
    ),
    _expectation(
        "MUT-020",
        nodes=(
            "tests/schema/test_project_config_mutation_contract.py"
            "::test_deferred_mutations_are_rejected[duplicate-json-key-v1]",
        ),
        artifacts=(
            "schemas/project-config.schema.json",
            "tests/schema/test_project_config_mutation_contract.py",
        ),
    ),
    _expectation(
        "MUT-021",
        nodes=(
            "tests/schema/test_project_config_mutation_contract.py"
            "::test_deferred_mutations_are_rejected[invalid-utf8-v1]",
        ),
        artifacts=(
            "schemas/project-config.schema.json",
            "tests/schema/test_project_config_mutation_contract.py",
        ),
    ),
    _expectation(
        "MUT-022",
        nodes=(
            "tests/integration/test_reduced_bundle_replay.py"
            "::test_vt_mut_022_replays_after_hypothesis_database_and_sources_are_deleted",
        ),
        artifacts=(
            "src/webhook_receiver_conformance/manifest/reduction.py",
            "tests/integration/test_reduced_bundle_replay.py",
        ),
    ),
    _expectation(
        "OBS-021",
        nodes=(
            "tests/packaging/test_deferred_release_contracts.py"
            "::test_core_and_lock_have_no_external_database_telemetry_or_queue_drivers",
        ),
        artifacts=(
            "pyproject.toml",
            "tests/packaging/test_deferred_release_contracts.py",
            "uv.lock",
        ),
    ),
    _expectation(
        "OBS-022",
        nodes=(
            "tests/packaging/test_deferred_release_contracts.py"
            "::test_deferred_roadmap_names_enabling_adrs_prerequisites_and_future_tests",
        ),
        artifacts=(
            "specification/27-roadmap-and-milestones.md",
            "tests/packaging/test_deferred_release_contracts.py",
        ),
    ),
    _expectation(
        "OPS-014",
        nodes=(
            "tests/packaging/test_deferred_release_contracts.py"
            "::test_release_publish_job_has_every_required_dag_prerequisite",
        ),
        artifacts=(
            ".github/workflows/release.yml",
            "tests/packaging/test_deferred_release_contracts.py",
        ),
    ),
    _expectation(
        "SIG-017",
        nodes=(
            "tests/schema/test_project_config_contract.py"
            "::test_generated_secret_support_is_hmac_only",
            "tests/packaging/test_deferred_release_contracts.py"
            "::test_deferred_roadmap_names_enabling_adrs_prerequisites_and_future_tests",
        ),
        artifacts=(
            "schemas/project-config.schema.json",
            "specification/27-roadmap-and-milestones.md",
            "tests/packaging/test_deferred_release_contracts.py",
            "tests/schema/test_project_config_contract.py",
        ),
    ),
    _expectation(
        "TEST-001",
        nodes=(
            "tests/schema/test_unit_coverage_inventory.py"
            "::test_inventory_is_complete_well_formed_and_sorted",
            "tests/schema/test_unit_coverage_inventory.py"
            "::test_every_self_declared_pure_module_is_in_the_inventory",
        ),
        artifacts=(
            "tests/schema/test_unit_coverage_inventory.py",
            "validation/unit-test-coverage-inventory.json",
        ),
    ),
    _expectation(
        "TEST-009",
        nodes=(
            "tests/packaging/test_deferred_release_contracts.py"
            "::test_stable_release_mutation_gate_is_explicit_and_v0_1_is_deferred",
        ),
        artifacts=(
            "checklists/release-readiness.md",
            "tests/packaging/test_deferred_release_contracts.py",
        ),
    ),
    _expectation(
        "TEST-019",
        nodes=(
            "tests/unit/test_leak_guard.py"
            "::test_real_inspector_detects_and_releases_current_process_listener",
            "tests/unit/test_leak_guard.py::test_real_inspector_detects_and_releases_child_process",
            "tests/unit/test_leak_guard.py::test_pytest_session_fails_for_leaked_listener",
            "tests/unit/test_leak_guard.py::test_pytest_session_fails_and_cleans_up_leaked_child",
        ),
        artifacts=(
            "tests/conftest.py",
            "tests/helpers/leak_guard.py",
            "tests/unit/test_leak_guard.py",
        ),
    ),
    _expectation(
        "TEST-020",
        nodes=(
            "tests/schema/test_artifact_validation.py"
            "::test_task_index_empty_execution_evidence_is_rejected",
            "tests/schema/test_artifact_validation.py"
            "::test_task_index_blank_execution_evidence_is_rejected",
        ),
        artifacts=(
            "machine/task-index.yaml",
            "schemas/task-index.schema.json",
            "scripts/validate_artifacts.py",
            "tests/schema/test_artifact_validation.py",
        ),
    ),
)
EXPECTED_BY_PATH: Final[Mapping[str, EvidenceExpectation]] = MappingProxyType(
    {expectation.evidence_path: expectation for expectation in EXPECTATIONS}
)
EXPECTED_PATHS: Final = tuple(expectation.evidence_path for expectation in EXPECTATIONS)
_ALL_ARTIFACT_PATHS: Final = tuple(
    sorted(
        {path for expectation in EXPECTATIONS for path in expectation.artifact_paths} | {"uv.lock"}
    )
)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceReadError("JSON object contains a duplicate field")
        result[key] = value
    return result


def _reject_non_finite(_value: str) -> None:
    raise EvidenceReadError("JSON document contains a non-finite number")


def _read_json_object(path: Path, *, maximum_bytes: int) -> dict[str, object]:
    try:
        stat = path.stat()
    except OSError as error:
        raise EvidenceReadError("file cannot be inspected") from error
    if not path.is_file() or path.is_symlink():
        raise EvidenceReadError("path must be a regular, non-symlink file")
    if stat.st_size > maximum_bytes:
        raise EvidenceReadError(f"file exceeds the {maximum_bytes}-byte limit")
    try:
        text = path.read_text(encoding="utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except UnicodeDecodeError as error:
        raise EvidenceReadError("file is not UTF-8") from error
    except json.JSONDecodeError as error:
        raise EvidenceReadError("file is not valid JSON") from error
    except OSError as error:
        raise EvidenceReadError("file cannot be read") from error
    if not isinstance(value, dict):
        raise EvidenceReadError("JSON document must be an object")
    return cast("dict[str, object]", value)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _safe_label(value: str) -> str:
    encoded = value.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    return encoded[:160]


def _validate_traceability(root: Path) -> list[str]:
    relative_path = "machine/traceability.json"
    try:
        document = _read_json_object(
            root / relative_path,
            maximum_bytes=_MAX_TRACEABILITY_BYTES,
        )
    except EvidenceReadError as error:
        return [f"{relative_path}: {error}"]

    links = document.get("links")
    if not isinstance(links, list):
        return [f"{relative_path}: links must be an array"]

    actual: list[tuple[str, str, str]] = []
    malformed_count = 0
    for item in cast("list[object]", links):
        if not isinstance(item, dict):
            continue
        link = cast("dict[object, object]", item)
        if link.get("task_id") != TASK_ID:
            continue
        test_id = link.get("test_id")
        requirement_id = link.get("requirement_id")
        evidence_path = link.get("evidence_artifact")
        if not all(isinstance(value, str) for value in (test_id, requirement_id, evidence_path)):
            malformed_count += 1
            continue
        actual.append(
            (
                cast("str", test_id),
                cast("str", requirement_id),
                cast("str", evidence_path),
            )
        )

    expected = {
        (
            expectation.test_id,
            expectation.requirement_id,
            expectation.evidence_path,
        )
        for expectation in EXPECTATIONS
    }
    actual_set = set(actual)
    errors: list[str] = []
    if malformed_count:
        errors.append(
            f"{relative_path}: {malformed_count} {TASK_ID} link(s) have malformed identifiers"
        )
    if len(actual) != len(actual_set):
        errors.append(f"{relative_path}: {TASK_ID} links must be unique")
    for test_id, requirement_id, evidence_path in sorted(expected - actual_set):
        errors.append(
            f"{relative_path}: missing {test_id}/{requirement_id} link to {evidence_path}"
        )
    unexpected_count = len(actual_set - expected)
    if unexpected_count:
        errors.append(f"{relative_path}: contains {unexpected_count} unexpected {TASK_ID} link(s)")
    if len(actual) != len(EXPECTATIONS):
        errors.append(f"{relative_path}: {TASK_ID} must have exactly {len(EXPECTATIONS)} links")
    return errors


def _collect_evidence_paths(root: Path) -> tuple[set[str], list[str]]:
    directory = root / "validation" / "evidence"
    if not directory.is_dir() or directory.is_symlink():
        return set(), ["validation/evidence: must be a local directory"]
    try:
        entries = tuple(directory.iterdir())
    except OSError:
        return set(), ["validation/evidence: directory cannot be read"]
    if len(entries) > _MAX_EVIDENCE_DIRECTORY_ENTRIES:
        return set(), [
            "validation/evidence: "
            f"directory exceeds the {_MAX_EVIDENCE_DIRECTORY_ENTRIES}-entry limit"
        ]
    paths = {
        entry.relative_to(root).as_posix() for entry in entries if entry.name.startswith("VT-")
    }
    return paths, []


def _collect_artifact_digests(root: Path) -> tuple[dict[str, str], list[str]]:
    resolved_root = root.resolve()
    digests: dict[str, str] = {}
    errors: list[str] = []
    for relative_path in _ALL_ARTIFACT_PATHS:
        path = root.joinpath(*relative_path.split("/"))
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            errors.append(f"{relative_path}: required carrier artifact is missing")
            continue
        if not resolved.is_relative_to(resolved_root) or not path.is_file() or path.is_symlink():
            errors.append(f"{relative_path}: carrier artifact must be a local regular file")
            continue
        try:
            digests[relative_path] = _file_sha256(path)
        except OSError:
            errors.append(f"{relative_path}: carrier artifact cannot be read")
    return digests, errors


def _validate_environment(
    *,
    record_path: str,
    value: object,
    artifact_digests: Mapping[str, str],
) -> list[str]:
    if not isinstance(value, dict):
        return [f"{record_path}: environment must be an object"]
    environment = cast("dict[object, object]", value)
    errors: list[str] = []
    if frozenset(environment) != _ENVIRONMENT_FIELDS:
        errors.append(f"{record_path}: environment fields do not match the closed contract")
    if environment.get("python_implementation") != "CPython":
        errors.append(f"{record_path}: environment.python_implementation must be CPython")
    python_version = environment.get("python_version")
    if not isinstance(python_version, str) or _PYTHON_VERSION.fullmatch(python_version) is None:
        errors.append(
            f"{record_path}: environment.python_version must be a supported release version"
        )
    if environment.get("platform") not in _PLATFORMS:
        errors.append(f"{record_path}: environment.platform is not supported")
    lock_digest = environment.get("uv_lock_sha256")
    if not isinstance(lock_digest, str) or _SHA256.fullmatch(lock_digest) is None:
        errors.append(f"{record_path}: environment.uv_lock_sha256 is not canonical")
    expected_lock_digest = artifact_digests.get("uv.lock")
    if expected_lock_digest is not None and lock_digest != expected_lock_digest:
        errors.append(f"{record_path}: environment.uv_lock_sha256 does not match uv.lock")
    return errors


def _validate_artifact_sha256s(
    *,
    record_path: str,
    value: object,
    expectation: EvidenceExpectation,
    artifact_digests: Mapping[str, str],
) -> list[str]:
    if not isinstance(value, dict):
        return [f"{record_path}: artifact_sha256s must be an object"]
    recorded = cast("dict[object, object]", value)
    errors: list[str] = []
    if set(recorded) != set(expectation.artifact_paths):
        errors.append(f"{record_path}: artifact_sha256s paths do not match the proof contract")
        return errors
    for artifact_path in expectation.artifact_paths:
        recorded_digest = recorded.get(artifact_path)
        if not isinstance(recorded_digest, str) or _SHA256.fullmatch(recorded_digest) is None:
            errors.append(f"{record_path}: {artifact_path} SHA-256 is not canonical")
            continue
        actual_digest = artifact_digests.get(artifact_path)
        if actual_digest is not None and recorded_digest != actual_digest:
            errors.append(f"{record_path}: {artifact_path} SHA-256 does not match")
    return errors


def _validate_record(
    *,
    root: Path,
    expectation: EvidenceExpectation,
    implementation_commit: str,
    artifact_digests: Mapping[str, str],
) -> list[str]:
    record_path = expectation.evidence_path
    try:
        record = _read_json_object(
            root.joinpath(*record_path.split("/")),
            maximum_bytes=_MAX_RECORD_BYTES,
        )
    except EvidenceReadError as error:
        return [f"{record_path}: {error}"]

    errors: list[str] = []
    if frozenset(record) != _RECORD_FIELDS:
        errors.append(f"{record_path}: fields do not match the closed record contract")
    if (
        not isinstance(record.get("schema_version"), int)
        or isinstance(record.get("schema_version"), bool)
        or record.get("schema_version") != _RECORD_SCHEMA_VERSION
    ):
        errors.append(f"{record_path}: schema_version must be {_RECORD_SCHEMA_VERSION}")
    if record.get("test_id") != expectation.test_id:
        errors.append(f"{record_path}: test_id does not match its traceability path")
    if record.get("requirement_id") != expectation.requirement_id:
        errors.append(f"{record_path}: requirement_id does not match its traceability link")
    if record.get("status") != "passed":
        errors.append(f"{record_path}: status must be passed")
    recorded_commit = record.get("implementation_commit")
    if (
        not isinstance(recorded_commit, str)
        or _COMMIT.fullmatch(recorded_commit) is None
        or recorded_commit != implementation_commit
    ):
        errors.append(f"{record_path}: implementation_commit does not match the bound commit")
    if record.get("command") != expectation.command:
        errors.append(f"{record_path}: command does not match the exact verification command")
    exit_code = record.get("exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or exit_code != 0:
        errors.append(f"{record_path}: exit_code must be integer zero")
    if record.get("test_nodes") != list(expectation.test_nodes):
        errors.append(f"{record_path}: test_nodes do not match the exact verification nodes")
    errors.extend(
        _validate_artifact_sha256s(
            record_path=record_path,
            value=record.get("artifact_sha256s"),
            expectation=expectation,
            artifact_digests=artifact_digests,
        )
    )
    errors.extend(
        _validate_environment(
            record_path=record_path,
            value=record.get("environment"),
            artifact_digests=artifact_digests,
        )
    )
    return errors


def validate_evidence(
    root: Path = ROOT,
    *,
    implementation_commit: str,
) -> tuple[str, ...]:
    """Validate all and only the 14 TASK-0810 evidence records without mutation."""
    if _COMMIT.fullmatch(implementation_commit) is None:
        return ("validator: implementation commit must be 40 lowercase hexadecimal characters",)

    errors = _validate_traceability(root)
    actual_paths, path_errors = _collect_evidence_paths(root)
    errors.extend(path_errors)
    expected_paths = set(EXPECTED_PATHS)
    for missing_path in sorted(expected_paths - actual_paths):
        errors.append(f"{missing_path}: required evidence record is missing")
    for unexpected_path in sorted(actual_paths - expected_paths):
        errors.append(f"validation/evidence: unexpected VT record {_safe_label(unexpected_path)}")

    artifact_digests, artifact_errors = _collect_artifact_digests(root)
    errors.extend(artifact_errors)
    for expectation in EXPECTATIONS:
        if expectation.evidence_path not in actual_paths:
            continue
        errors.extend(
            _validate_record(
                root=root,
                expectation=expectation,
                implementation_commit=implementation_commit,
                artifact_digests=artifact_digests,
            )
        )
    return tuple(sorted(errors))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--implementation-commit",
        required=True,
        help="40-character lowercase commit bound by every evidence record",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help=argparse.SUPPRESS,
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the deterministic offline validator."""
    options = _parser().parse_args(arguments)
    root = cast("Path", options.root)
    implementation_commit = cast("str", options.implementation_commit)
    errors = validate_evidence(root, implementation_commit=implementation_commit)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"validated {len(EXPECTATIONS)} {TASK_ID} evidence records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
