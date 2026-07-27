# TASK-0204 — Implement run-directory ownership lock

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-02-journal-and-state |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0201 |
| Blocks | TASK-0311 |
| Parallel group | PG-02B |
| Requirements | DATA-016, REL-012 |
| Tests | VT-DATA-016, VT-REL-012 |
| ADRs | None |

## Objective

Acquire an atomic local lock, diagnose active owners, and support explicit stale-lock takeover.

## Rationale

Implements DATA-016, REL-012 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/journal/run_lock.py

**Allowed files**

- src/webhook_receiver_conformance/journal/run_lock.py
- tests/unit/journal/test_run_lock.py

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

- **Owned:** ARC-JOURNAL, ARC-LOCK
- **Consumed:** ARC-JOURNAL, ARC-RECOVERY

## Implementation scope

Acquire an atomic local lock, diagnose active owners, and support explicit stale-lock takeover.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Never auto-break a lock owned by a live local process; reject network-filesystem operation where detected.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A detected network mount fails with unsupported status before database creation.
- A live owner blocks takeover and a dead same-host owner can be taken over with an audit event.

## Commands to run

```bash
uv run pytest -q tests/unit/journal/test_run_lock.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/journal/run_lock.py
- tests/unit/journal/test_run_lock.py

## Completion evidence

- Passing evidence for VT-DATA-016
- Passing evidence for VT-REL-012

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
