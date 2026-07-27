# TASK-0508 — Integrate assertion lifecycle and verdict classification

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-05-observers-and-assertions |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0505, TASK-0507, TASK-0203 |
| Blocks | TASK-0509, TASK-0601, TASK-0602, TASK-0701 |
| Parallel group | None |
| Requirements | ASSERT-013, ASSERT-014, ASSERT-015, ASSERT-016, FR-002, FR-006, OBS-020, STATE-006, STATE-012, TEST-002 |
| Tests | VT-ASSERT-013, VT-ASSERT-014, VT-ASSERT-015, VT-ASSERT-016, VT-FR-002, VT-FR-006, VT-OBS-020, VT-STATE-006, VT-STATE-012, VT-TEST-002 |
| ADRs | None |

## Objective

Persist assertion evaluations and distinguish receiver failure, unsupported capability, environment error, harness error, and ambiguity.

## Rationale

Implements ASSERT-013, ASSERT-014, ASSERT-015, ASSERT-016, FR-002, FR-006, OBS-020, STATE-006 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/runtime/assertions.py
- src/webhook_receiver_conformance/runtime/verdicts.py

**Allowed files**

- src/webhook_receiver_conformance/runtime/assertions.py
- src/webhook_receiver_conformance/runtime/verdicts.py
- tests/integration/test_assertion_lifecycle.py

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
- **Consumed:** ARC-ASSERT, ARC-HTTP, ARC-JOURNAL, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-RECOVERY, ARC-REF, ARC-REPORT-JSON

## Implementation scope

Persist assertion evaluations and distinguish receiver failure, unsupported capability, environment error, harness error, and ambiguity.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The result schema stores attempt evidence and observation evidence in different typed collections linked by identifiers.
- Exactly one terminal result enum is present in every result summary.
- Assertion lifecycle tests cover every terminal classification.
- Completion is rejected until every required delivery is terminal under policy.
- An unsupported processing_count assertion yields exit code 6 under fail-on-unsupported policy.
- Missing optional diagnostic evidence does not affect pass; missing required evidence produces error.
- A comparison mismatch produces receiver_failure and cites actual/expected values.
- Observer timeout never becomes a receiver assertion failure.
- Capability mismatch is visible before observer polling begins.
- Adding a built-in implementation without registering the contract tests fails CI.

## Commands to run

```bash
uv run pytest -q tests/integration/test_assertion_lifecycle.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/runtime/assertions.py
- src/webhook_receiver_conformance/runtime/verdicts.py
- tests/integration/test_assertion_lifecycle.py

## Completion evidence

- Passing evidence for VT-ASSERT-013
- Passing evidence for VT-ASSERT-014
- Passing evidence for VT-ASSERT-015
- Passing evidence for VT-ASSERT-016
- Passing evidence for VT-FR-002
- Passing evidence for VT-FR-006
- Passing evidence for VT-OBS-020
- Passing evidence for VT-STATE-006
- Passing evidence for VT-STATE-012
- Passing evidence for VT-TEST-002

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
