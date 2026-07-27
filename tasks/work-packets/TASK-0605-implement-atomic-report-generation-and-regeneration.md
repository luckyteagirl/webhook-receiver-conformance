# TASK-0605 — Implement atomic report generation and regeneration

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-06-reporting |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0205, TASK-0601, TASK-0603, TASK-0604 |
| Blocks | TASK-0606, TASK-0711, TASK-0806 |
| Parallel group | None |
| Requirements | DATA-019, DATA-020, FR-011, PERF-007, REL-010, REPORT-021, SEC-015, SEC-017, TEST-002, TEST-005 |
| Tests | VT-DATA-019, VT-DATA-020, VT-FR-011, VT-PERF-007, VT-REL-010, VT-REPORT-021, VT-SEC-015, VT-SEC-017, VT-TEST-002, VT-TEST-005 |
| ADRs | ADR-007 |

## Objective

Write reports through temporary files, fsync/rename safely, register digests, and regenerate idempotently.

## Rationale

Implements DATA-019, DATA-020, FR-011, PERF-007, REL-010, REPORT-021, SEC-015, SEC-017 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/reporting/writer.py

**Allowed files**

- src/webhook_receiver_conformance/reporting/writer.py
- tests/integration/test_report_regeneration.py

**Forbidden files**

- schemas/** unless explicitly listed
- machine/**
- specification/**
- unowned migrations
- public interfaces owned by another task

## Authoritative inputs

- machine/requirements.yaml
- machine/decisions.yaml
- machine/task-index.yaml
- specification/16-interfaces-and-contracts.md

## Interfaces

- **Owned:** ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML
- **Consumed:** ARC-HTTP, ARC-JOURNAL, ARC-RECOVERY, ARC-REF, ARC-REPORT-HTML, ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-SCHED, ARC-SECRET, ARC-TARGET

## Implementation scope

Write reports through temporary files, fsync/rename safely, register digests, and regenerate idempotently.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Report regeneration succeeds while all network access is denied.
- Regeneration updates the registry transactionally and every registered digest matches the file.
- Report-generation termination leaves either the old valid artifact or the new valid artifact, never a partial target file.
- A normalized digest comparison is equal across two regenerations.
- POSIX tests observe mode 0600 for files and 0700 for run directories subject to umask tightening.
- A race-resistant symlink test cannot read or overwrite an external canary file.
- Resume or report regenerates artifacts from the journal without sending traffic.
- The locked report corpus meets the percentile budget.
- Adding a built-in implementation without registering the contract tests fails CI.
- Golden updates require an explicit compatibility review marker.

## Commands to run

```bash
uv run pytest -q tests/integration/test_report_regeneration.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/reporting/writer.py
- tests/integration/test_report_regeneration.py

## Completion evidence

- Passing evidence for VT-DATA-019
- Passing evidence for VT-DATA-020
- Passing evidence for VT-FR-011
- Passing evidence for VT-PERF-007
- Passing evidence for VT-REL-010
- Passing evidence for VT-REPORT-021
- Passing evidence for VT-SEC-015
- Passing evidence for VT-SEC-017
- Passing evidence for VT-TEST-002
- Passing evidence for VT-TEST-005

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
