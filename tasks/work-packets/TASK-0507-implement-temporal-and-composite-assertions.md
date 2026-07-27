# TASK-0507 — Implement temporal and composite assertions

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-05-observers-and-assertions |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0504, TASK-0506 |
| Blocks | TASK-0508 |
| Parallel group | PG-05D |
| Requirements | ASSERT-010, ASSERT-011, ASSERT-012 |
| Tests | VT-ASSERT-010, VT-ASSERT-011, VT-ASSERT-012 |
| ADRs | None |

## Objective

Evaluate ordered transitions, eventual state, and all-or-none side-effect assertions with explicit error semantics.

## Rationale

Implements ASSERT-010, ASSERT-011, ASSERT-012 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/assertions/temporal.py
- src/webhook_receiver_conformance/assertions/composite.py

**Allowed files**

- src/webhook_receiver_conformance/assertions/temporal.py
- src/webhook_receiver_conformance/assertions/composite.py
- tests/unit/assertions/test_temporal.py

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

Evaluate ordered transitions, eventual state, and all-or-none side-effect assertions with explicit error semantics.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Intermediate unrelated transitions are permitted only when the assertion configuration allows them.
- A receiver with an order update but missing outbox entry fails with both predicate values shown.
- The final report includes every sample ID and the terminal pass or timeout.

## Commands to run

```bash
uv run pytest -q tests/unit/assertions/test_temporal.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/assertions/temporal.py
- src/webhook_receiver_conformance/assertions/composite.py
- tests/unit/assertions/test_temporal.py

## Completion evidence

- Passing evidence for VT-ASSERT-010
- Passing evidence for VT-ASSERT-011
- Passing evidence for VT-ASSERT-012

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
