# TASK-0509 — Implement observer-assisted ambiguity reconciliation

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-05-observers-and-assertions |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0207, TASK-0504, TASK-0508 |
| Blocks | TASK-0801 |
| Parallel group | None |
| Requirements | OBS-016, REL-005 |
| Tests | VT-OBS-016, VT-REL-005 |
| ADRs | None |

## Objective

Resolve an ambiguous delivery only when configured observations uniquely establish the required business result.

## Rationale

Implements OBS-016, REL-005 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/recovery/reconcile.py

**Allowed files**

- src/webhook_receiver_conformance/recovery/reconcile.py
- tests/integration/test_reconcile.py

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

- **Owned:** ARC-RECOVERY
- **Consumed:** ARC-JOURNAL, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-RECOVERY

## Implementation scope

Resolve an ambiguous delivery only when configured observations uniquely establish the required business result.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A non-read-only observer is limited to one explicit invocation and cannot reconcile ambiguity.
- Inconclusive, pending, unsupported, or contradictory evidence leaves the delivery ambiguous.

## Commands to run

```bash
uv run pytest -q tests/integration/test_reconcile.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/recovery/reconcile.py
- tests/integration/test_reconcile.py

## Completion evidence

- Passing evidence for VT-OBS-016
- Passing evidence for VT-REL-005

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
