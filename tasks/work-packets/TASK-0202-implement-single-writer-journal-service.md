# TASK-0202 — Implement single-writer journal service

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-02-journal-and-state |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0201 |
| Blocks | TASK-0203, TASK-0205 |
| Parallel group | PG-02B |
| Requirements | COMPAT-004, DATA-008, DATA-012, DATA-013, DATA-014, DATA-015 |
| Tests | VT-COMPAT-004, VT-DATA-008, VT-DATA-012, VT-DATA-013, VT-DATA-014, VT-DATA-015 |
| ADRs | ADR-021 |

## Objective

Serialize SQLite operations through one dedicated service and explicit BEGIN IMMEDIATE transactions.

## Rationale

Implements COMPAT-004, DATA-008, DATA-012, DATA-013, DATA-014, DATA-015 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/journal/service.py
- src/webhook_receiver_conformance/journal/connection.py

**Allowed files**

- src/webhook_receiver_conformance/journal/service.py
- src/webhook_receiver_conformance/journal/connection.py
- tests/unit/journal/test_service.py

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
- **Consumed:** ARC-JOURNAL, ARC-PACKAGE

## Implementation scope

Serialize SQLite operations through one dedicated service and explicit BEGIN IMMEDIATE transactions.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Enable foreign_keys, trusted_schema=OFF, DELETE journal mode, synchronous=EXTRA, and parameterized SQL only.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- An orphan attempt insert fails and PRAGMA foreign_keys reports 1.
- Startup fails if SQLite does not report delete mode after configuration.
- Connection initialization reads PRAGMA synchronous as 3.
- A SQL trace test finds no implicit write transaction in the journal repository.
- Concurrent callers are serialized and no second write connection is opened.
- An injected older version produces unsupported before database creation.

## Commands to run

```bash
uv run pytest -q tests/unit/journal/test_service.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/journal/service.py
- src/webhook_receiver_conformance/journal/connection.py
- tests/unit/journal/test_service.py

## Completion evidence

- Passing evidence for VT-COMPAT-004
- Passing evidence for VT-DATA-008
- Passing evidence for VT-DATA-012
- Passing evidence for VT-DATA-013
- Passing evidence for VT-DATA-014
- Passing evidence for VT-DATA-015

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
