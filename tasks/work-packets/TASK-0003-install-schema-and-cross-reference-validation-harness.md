# TASK-0003 — Install schema and cross-reference validation harness

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-00-foundation |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0001 |
| Blocks | TASK-0104, TASK-0501 |
| Parallel group | PG-00A |
| Requirements | COMPAT-006, DATA-007, DX-006, REPORT-007, STATE-014, TEST-008, TEST-020 |
| Tests | VT-COMPAT-006, VT-DATA-007, VT-DX-006, VT-REPORT-007, VT-STATE-014, VT-TEST-008, VT-TEST-020 |
| ADRs | ADR-008, ADR-015 |

## Objective

Create test helpers that validate JSON Schema examples, identifier references, and golden artifacts.

## Rationale

Implements COMPAT-006, DATA-007, DX-006, REPORT-007, STATE-014, TEST-008, TEST-020 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- scripts/validate_artifacts.py

**Allowed files**

- tests/schema/**
- tests/helpers/schema_validation.py
- scripts/validate_artifacts.py

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

- **Owned:** No public interface; task owns only listed implementation files.
- **Consumed:** ARC-CLI, ARC-JOURNAL, ARC-PACKAGE, ARC-RECOVERY, ARC-REF, ARC-REPORT-HTML, ARC-REPORT-JSON, ARC-REPORT-JUNIT

## Implementation scope

Create test helpers that validate JSON Schema examples, identifier references, and golden artifacts.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Schema validation rejects a persisted record without schema_version.
- A generated comparison test detects any diagram/table mismatch.
- The schema annotations and determinism document name run_id, wall timestamps, durations, and environment observations as volatile.
- A compatibility matrix defines reader behavior for same-major additions and unknown major versions.
- Schema validation runs on both examples in CI.
- Fuzz targets enforce size/time limits and preserve no-crash/no-leak invariants.
- task-index validation rejects a task with empty commands_to_run or completion_evidence.

## Commands to run

```bash
uv run pytest -q tests/schema/** tests/helpers/schema_validation.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- tests/schema/**
- tests/helpers/schema_validation.py
- scripts/validate_artifacts.py

## Completion evidence

- Passing evidence for VT-COMPAT-006
- Passing evidence for VT-DATA-007
- Passing evidence for VT-DX-006
- Passing evidence for VT-REPORT-007
- Passing evidence for VT-STATE-014
- Passing evidence for VT-TEST-008
- Passing evidence for VT-TEST-020

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
