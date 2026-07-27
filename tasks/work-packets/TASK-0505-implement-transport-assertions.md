# TASK-0505 — Implement transport assertions

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-05-observers-and-assertions |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0309 |
| Blocks | TASK-0508 |
| Parallel group | PG-05C |
| Requirements | ASSERT-001, ASSERT-002, ASSERT-003 |
| Tests | VT-ASSERT-001, VT-ASSERT-002, VT-ASSERT-003 |
| ADRs | None |

## Objective

Evaluate status, status class, rejection, and acknowledgment-deadline assertions from attempt evidence.

## Rationale

Implements ASSERT-001, ASSERT-002, ASSERT-003 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/assertions/transport.py

**Allowed files**

- src/webhook_receiver_conformance/assertions/transport.py
- tests/unit/assertions/test_transport.py

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

- **Owned:** ARC-ASSERT
- **Consumed:** ARC-ASSERT

## Implementation scope

Evaluate status, status class, rejection, and acknowledgment-deadline assertions from attempt evidence.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- 200 exact and [200,202] membership cases pass; a missing response produces error rather than fail.
- Boundary status values 199, 200, 299, 300, 399, 400, 499, 500, and 599 are classified correctly.
- A delayed-body response with prompt headers passes while delayed headers fail.

## Commands to run

```bash
uv run pytest -q tests/unit/assertions/test_transport.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/assertions/transport.py
- tests/unit/assertions/test_transport.py

## Completion evidence

- Passing evidence for VT-ASSERT-001
- Passing evidence for VT-ASSERT-002
- Passing evidence for VT-ASSERT-003

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
