# TASK-0710 — Crash-after-effect-before-ack receiver

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-07-reference-receivers |
| Priority | P0 |
| Complexity | small |
| Dependencies | TASK-0701 |
| Blocks | TASK-0711 |
| Parallel group | PG-07A |
| Requirements | TEST-020 |
| Tests | VT-TEST-020 |
| ADRs | None |

## Objective

Implement one isolated flawed receiver whose primary intentional defect is: Crash after committing the side effect and before returning an acknowledgment.

## Rationale

Implements TEST-020 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- reference_receivers/flawed/crash-after-effect-before-ack-receiver/**

**Allowed files**

- reference_receivers/flawed/crash-after-effect-before-ack-receiver/**
- tests/e2e/test_crash_after_effect_before_ack_receiver.py

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

- **Owned:** ARC-REF
- **Consumed:** ARC-REF

## Implementation scope

Implement one isolated flawed receiver whose primary intentional defect is: Crash after committing the side effect and before returning an acknowledgment.

## Explicit non-goals

- Do not introduce additional defects that obscure the expected scenario failure.

## Security constraints

The defect must remain confined to the test receiver and must not weaken shared libraries.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- task-index validation rejects a task with empty commands_to_run or completion_evidence.

## Commands to run

```bash
uv run pytest -q tests/e2e/test_crash_after_effect_before_ack_receiver.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- reference_receivers/flawed/crash-after-effect-before-ack-receiver/**
- tests/e2e/test_crash_after_effect_before_ack_receiver.py

## Completion evidence

- Passing evidence for VT-TEST-020

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
