# TASK-0603 — Implement JUnit XML renderer

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-06-reporting |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0602 |
| Blocks | TASK-0605 |
| Parallel group | PG-06B |
| Requirements | REPORT-009, REPORT-010, REPORT-011, REPORT-012, REPORT-013, REPORT-014, REPORT-015, REPORT-016 |
| Tests | VT-REPORT-009, VT-REPORT-010, VT-REPORT-011, VT-REPORT-012, VT-REPORT-013, VT-REPORT-014, VT-REPORT-015, VT-REPORT-016 |
| ADRs | ADR-025 |

## Objective

Map scenarios and assertions to suites/testcases with defined failure, error, skip, duration, and attachment semantics.

## Rationale

Implements REPORT-009, REPORT-010, REPORT-011, REPORT-012, REPORT-013, REPORT-014, REPORT-015, REPORT-016 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/reporting/junit.py

**Allowed files**

- src/webhook_receiver_conformance/reporting/junit.py
- tests/unit/reporting/test_junit.py
- tests/golden/reports/junit.xml

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
- **Consumed:** ARC-REPORT-HTML, ARC-REPORT-JSON, ARC-REPORT-JUNIT

## Implementation scope

Map scenarios and assertions to suites/testcases with defined failure, error, skip, duration, and attachment semantics.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- JUnit uses error and HTML uses an ambiguity section for an unknown attempt.
- A run with three scenarios contains three suites with stable names and IDs.
- Assertion counts and infrastructure testcase counts reconcile with the result summary.
- A processing_count mismatch appears as failure and not error.
- Observer timeout and unknown_outcome appear as errors with distinct type attributes.
- The skipped element includes a stable reason code.
- Logical scaled durations are not substituted for physical testcase time.
- No fixture body or secret is embedded in system-out or system-err.

## Commands to run

```bash
uv run pytest -q tests/unit/reporting/test_junit.py tests/golden/reports/junit.xml
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/reporting/junit.py
- tests/unit/reporting/test_junit.py
- tests/golden/reports/junit.xml

## Completion evidence

- Passing evidence for VT-REPORT-009
- Passing evidence for VT-REPORT-010
- Passing evidence for VT-REPORT-011
- Passing evidence for VT-REPORT-012
- Passing evidence for VT-REPORT-013
- Passing evidence for VT-REPORT-014
- Passing evidence for VT-REPORT-015
- Passing evidence for VT-REPORT-016

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
