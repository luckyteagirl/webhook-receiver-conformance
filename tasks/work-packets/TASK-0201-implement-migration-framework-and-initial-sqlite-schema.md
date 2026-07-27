# TASK-0201 — Implement migration framework and initial SQLite schema

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-02-journal-and-state |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0102 |
| Blocks | TASK-0202, TASK-0204 |
| Parallel group | PG-02A |
| Requirements | DATA-001, DATA-009, DATA-017, REL-015, SEC-015, STATE-001, TEST-015 |
| Tests | VT-DATA-001, VT-DATA-009, VT-DATA-017, VT-REL-015, VT-SEC-015, VT-STATE-001, VT-TEST-015 |
| ADRs | ADR-004 |

## Objective

Create versioned forward-only migrations for runs, scenarios, events, deliveries, attempts, transitions, observations, assertions, and artifacts.

## Rationale

Implements DATA-001, DATA-009, DATA-017, REL-015, SEC-015, STATE-001, TEST-015 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/journal/migrations/**
- src/webhook_receiver_conformance/journal/schema.py

**Allowed files**

- src/webhook_receiver_conformance/journal/migrations/**
- src/webhook_receiver_conformance/journal/schema.py
- tests/unit/journal/test_migrations.py

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

- **Owned:** ARC-JOURNAL
- **Consumed:** ARC-JOURNAL, ARC-RECOVERY, ARC-REF, ARC-SECRET, ARC-TARGET

## Implementation scope

Create versioned forward-only migrations for runs, scenarios, events, deliveries, attempts, transitions, observations, assertions, and artifacts.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Two executions of one bundle create distinct run directories and never share a database file.
- Direct insertion of an invalid state or duplicate scoped identifier fails at the database boundary.
- A changed applied migration checksum aborts startup; a new migration applies once and records its checksum.
- The run-state transition table rejects every undeclared state value.
- POSIX tests observe mode 0600 for files and 0700 for run directories subject to umask tightening.
- Crash-point tests around every migration statement preserve a valid migration ledger.
- Migration output passes integrity, foreign-key, and projection-rebuild checks.

## Commands to run

```bash
uv run pytest -q tests/unit/journal/test_migrations.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/journal/migrations/**
- src/webhook_receiver_conformance/journal/schema.py
- tests/unit/journal/test_migrations.py

## Completion evidence

- Passing evidence for VT-DATA-001
- Passing evidence for VT-DATA-009
- Passing evidence for VT-DATA-017
- Passing evidence for VT-REL-015
- Passing evidence for VT-SEC-015
- Passing evidence for VT-STATE-001
- Passing evidence for VT-TEST-015

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
