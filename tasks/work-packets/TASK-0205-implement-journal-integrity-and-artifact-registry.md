# TASK-0205 — Implement journal integrity and artifact registry

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-02-journal-and-state |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0202 |
| Blocks | TASK-0311, TASK-0601, TASK-0605 |
| Parallel group | PG-02C |
| Requirements | DATA-018, DATA-019, REL-013 |
| Tests | VT-DATA-018, VT-DATA-019, VT-REL-013 |
| ADRs | None |

## Objective

Run integrity checks, record artifact digests, and make artifact regeneration idempotent.

## Rationale

Implements DATA-018, DATA-019, REL-013 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/journal/integrity.py
- src/webhook_receiver_conformance/journal/artifacts.py

**Allowed files**

- src/webhook_receiver_conformance/journal/integrity.py
- src/webhook_receiver_conformance/journal/artifacts.py
- tests/unit/journal/test_integrity.py

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
- **Consumed:** ARC-JOURNAL, ARC-RECOVERY

## Implementation scope

Run integrity checks, record artifact digests, and make artifact regeneration idempotent.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A deliberately corrupt or referentially invalid database fails with harness_error before delivery.
- Regeneration updates the registry transactionally and every registered digest matches the file.
- No automatic repair or replacement occurs and exit classification is harness_error.

## Commands to run

```bash
uv run pytest -q tests/unit/journal/test_integrity.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/journal/integrity.py
- src/webhook_receiver_conformance/journal/artifacts.py
- tests/unit/journal/test_integrity.py

## Completion evidence

- Passing evidence for VT-DATA-018
- Passing evidence for VT-DATA-019
- Passing evidence for VT-REL-013

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
