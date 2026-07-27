# TASK-0506 — Implement receiver-state assertions

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-05-observers-and-assertions |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0501 |
| Blocks | TASK-0507 |
| Parallel group | PG-05C |
| Requirements | ASSERT-004, ASSERT-005, ASSERT-006, ASSERT-007, ASSERT-008, ASSERT-009 |
| Tests | VT-ASSERT-004, VT-ASSERT-005, VT-ASSERT-006, VT-ASSERT-007, VT-ASSERT-008, VT-ASSERT-009 |
| ADRs | ADR-010 |

## Objective

Evaluate processing count, resource existence/absence, typed field comparison, callback count, and journal count.

## Rationale

Implements ASSERT-004, ASSERT-005, ASSERT-006, ASSERT-007, ASSERT-008, ASSERT-009 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/assertions/state.py

**Allowed files**

- src/webhook_receiver_conformance/assertions/state.py
- tests/unit/assertions/test_state.py

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

Evaluate processing count, resource existence/absence, typed field comparison, callback count, and journal count.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Duplicate delivery to the correct receiver yields count 1 and the no-idempotency receiver yields count 2.
- Reference observer evidence produces deterministic pass/fail for both forms.
- Integer 1 does not equal string "1".
- Decimal 0.10 equals 0.1 under numeric comparison while retaining source representation in evidence.
- The correct receiver outbox callback count remains one under duplicate delivery.
- A reference inbox contains one logical event record after concurrent duplicates.

## Commands to run

```bash
uv run pytest -q tests/unit/assertions/test_state.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/assertions/state.py
- tests/unit/assertions/test_state.py

## Completion evidence

- Passing evidence for VT-ASSERT-004
- Passing evidence for VT-ASSERT-005
- Passing evidence for VT-ASSERT-006
- Passing evidence for VT-ASSERT-007
- Passing evidence for VT-ASSERT-008
- Passing evidence for VT-ASSERT-009

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
