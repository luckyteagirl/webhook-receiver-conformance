"""Verify and execute the authoritative P0 crash-consistency evidence matrix."""
# ruff: noqa: EM101, INP001, ISC004, PLR2004, PTH101, PTH105, S603, S607, T201, TRY003

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import stat
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from webhook_receiver_conformance.journal.schema import (
    MIGRATIONS,
    migration_crash_points,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

ROOT: Final = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class CrashBoundary:
    """One P0 crash point and the tests that prove its recovery contract."""

    boundary_id: str
    crash_point: str
    persisted_state: str
    resume_behavior: str
    ambiguity: str
    evidence: tuple[str, ...]
    priority: str = "P0"


_ATOMIC = (
    "tests/unit/journal/test_transitions.py"
    "::test_crash_at_each_atomic_boundary_rolls_back_every_write"
)
_RECOVERY = (
    "tests/unit/recovery/test_scanner.py"
    "::test_interrupted_send_recovery_is_atomic_at_every_mutation_phase"
)
_MIGRATIONS = (
    "tests/unit/journal/test_migrations.py"
    "::test_every_v1_statement_crash_boundary_preserves_v0_or_committed_v1"
)
_LATER_MIGRATIONS = (
    "tests/unit/journal/test_migrations.py"
    "::test_later_migration_crash_preserves_complete_prior_version"
)

CRASH_MATRIX: Final = (
    CrashBoundary(
        "CRASH-P0-001",
        "before owner or claim acquisition",
        "scheduled",
        "claim normally",
        "none",
        (_ATOMIC,),
    ),
    CrashBoundary(
        "CRASH-P0-002",
        "after claim before pre-send commit",
        "claimed",
        "expire or reclaim claim",
        "none",
        (
            "tests/unit/journal/test_transitions.py"
            "::test_claim_attempt_schedule_crash_rolls_back_every_mutation",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-003",
        "after pre-send commit before transport",
        "pre_send_committed",
        "recover conservatively from durable phase evidence",
        "controlled point proves not_sent",
        (
            "tests/integration/test_attempt_lifecycle.py"
            "::test_preconnection_failure_is_not_sent_and_retry_is_atomic",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-004",
        "during DNS connect or TLS before application bytes",
        "connecting",
        "not_sent only with decisive proof otherwise unknown_outcome",
        "phase-dependent",
        (
            "tests/unit/recovery/test_scanner.py"
            "::test_decisive_no_connection_proof_is_the_only_connecting_exception",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-005",
        "after application bytes before response",
        "sending or awaiting_response",
        "stop or explicitly reconcile",
        "unknown_outcome",
        (
            "tests/integration/test_attempt_lifecycle.py"
            "::test_post_connection_timeout_is_unknown",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-006",
        "after durable response before classification",
        "response_observed",
        "derive terminal classification from durable response",
        "none",
        (
            "tests/integration/test_assertion_lifecycle.py"
            "::test_transport_lifecycle_persists_exact_terminal_classification",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-007",
        "after terminal attempt before retry schedule",
        "terminal attempt and retry schedule in one transaction",
        "audit atomic derived schedule",
        "none",
        (
            "tests/unit/journal/test_transitions.py"
            "::test_terminal_attempt_and_derived_retry_schedule_are_one_operation",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-008",
        "after retry schedule commit",
        "terminal attempt plus schedule entry",
        "claim schedule exactly once",
        "none",
        (_RECOVERY,),
    ),
    CrashBoundary(
        "CRASH-P0-009",
        "during observer invocation",
        "observation scheduled or running",
        "terminate child and append classified terminal sample",
        "observer evidence only",
        (
            "tests/integration/test_observation_lifecycle.py"
            "::test_hanging_observer_is_terminated_and_persisted_as_timeout",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-010",
        "after observer response before sample commit",
        "no terminal sample",
        "re-query same logical request with fresh sample ID",
        "not a delivery ambiguity",
        (
            "tests/integration/test_observation_lifecycle.py"
            "::test_terminal_sample_and_state_roll_back_at_every_atomic_boundary",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-011",
        "after sample commit before assertion commit",
        "sample durable assertion pending",
        "reevaluate idempotently",
        "none",
        (
            "tests/integration/test_assertion_lifecycle.py"
            "::test_terminal_evaluation_and_links_roll_back_together_on_crash",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-012",
        "during report generation",
        "journal truth plus old target or complete new target",
        "regenerate offline",
        "none",
        (
            "tests/integration/test_report_regeneration.py"
            "::test_termination_preserves_old_or_complete_new_target",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-013",
        "around every migration statement and ledger boundary",
        "complete prior or complete next schema version",
        "reopen and validate migration ledger",
        "none",
        (_MIGRATIONS, _LATER_MIGRATIONS),
    ),
    CrashBoundary(
        "CRASH-P0-014",
        "cancellation after known transition",
        "durable known transition without fabricated receiver result",
        "resume from durable state",
        "none",
        (
            "tests/integration/test_cancellation.py"
            "::test_known_transition_survives_cancellation_without_receiver_result",
        ),
    ),
    CrashBoundary(
        "CRASH-P0-015",
        "projection loss after committed transitions",
        "append-only transition history",
        "rebuild identical projection rows",
        "none",
        (
            "tests/unit/journal/test_transitions.py"
            "::test_ordered_history_rebuilds_identical_lifecycle_projections",
        ),
    ),
)


def verify_matrix(root: Path = ROOT) -> tuple[str, ...]:
    """Return verification errors for missing, duplicate, or stale evidence."""
    errors: list[str] = []
    identifiers = tuple(boundary.boundary_id for boundary in CRASH_MATRIX)
    if len(identifiers) != len(set(identifiers)):
        errors.append("duplicate crash boundary identifier")
    for boundary in CRASH_MATRIX:
        if boundary.priority != "P0" or not boundary.evidence:
            errors.append(f"{boundary.boundary_id}: uncovered P0 boundary")
        for node_id in boundary.evidence:
            error = _verify_node_id(root, node_id)
            if error is not None:
                errors.append(f"{boundary.boundary_id}: {error}")
    return tuple(errors)


def build_report(
    *,
    execution: dict[str, object] | None = None,
    root: Path = ROOT,
) -> dict[str, object]:
    """Build one deterministic machine-readable crash coverage report."""
    errors = verify_matrix(root)
    covered = sum(
        1
        for boundary in CRASH_MATRIX
        if boundary.priority == "P0"
        and boundary.evidence
        and all(_verify_node_id(root, node_id) is None for node_id in boundary.evidence)
    )
    total = sum(boundary.priority == "P0" for boundary in CRASH_MATRIX)
    return {
        "schema_version": "1.0",
        "matrix": [asdict(boundary) for boundary in CRASH_MATRIX],
        "migration_failpoints": [
            {
                "migration_id": migration.migration_id,
                "points": len(migration_crash_points(migration)),
            }
            for migration in MIGRATIONS
        ],
        "coverage": {
            "p0_total": total,
            "p0_covered": covered,
            "p0_percent": 0 if total == 0 else (covered * 100) // total,
            "uncovered": list(errors),
        },
        "execution": execution,
    }


def execute_evidence(root: Path = ROOT) -> dict[str, object]:
    """Run each unique evidence node and retain hashes instead of raw child output."""
    nodes = tuple(dict.fromkeys(node for boundary in CRASH_MATRIX for node in boundary.evidence))
    environment = {
        key: value
        for key, value in os.environ.items()
        if not any(token in key.casefold() for token in ("secret", "token", "password", "key"))
    }
    environment.update({"NO_COLOR": "1", "PYTHONHASHSEED": "0"})
    completed = subprocess.run(
        ["uv", "run", "pytest", "-q", *nodes],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        timeout=900,
    )
    stdout = completed.stdout
    stderr = completed.stderr
    return {
        "command": "uv run pytest -q <crash-evidence-nodes>",
        "exit_code": completed.returncode,
        "node_count": len(nodes),
        "stdout_sha256": f"sha256:{hashlib.sha256(stdout).hexdigest()}",
        "stderr_sha256": f"sha256:{hashlib.sha256(stderr).hexdigest()}",
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    """Atomically install a report without following an existing symlink."""
    destination = path.resolve(strict=False)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("crash report target must be a regular file")
    payload = (
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def _verify_node_id(root: Path, node_id: str) -> str | None:
    path_text, separator, function_name = node_id.partition("::")
    if not separator or not function_name.startswith("test_"):
        return f"invalid evidence node ID {node_id}"
    path = root / path_text
    if not path.is_file():
        return f"missing evidence file {path_text}"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path_text)
    except (OSError, SyntaxError, UnicodeError):
        return f"unreadable evidence file {path_text}"
    functions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if function_name not in functions:
        return f"missing evidence function {function_name}"
    return None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", action="store_true")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Verify, optionally execute, and render the crash matrix."""
    options = _parser().parse_args(arguments)
    execution = execute_evidence() if options.execute else None
    report = build_report(execution=execution)
    if options.output is not None:
        write_report(options.output, report)
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    coverage = cast("dict[str, object]", report["coverage"])
    if coverage["p0_percent"] != 100 or coverage["uncovered"]:
        return 1
    if execution is not None and execution["exit_code"] != 0:
        return 1
    if options.verify and verify_matrix():
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
