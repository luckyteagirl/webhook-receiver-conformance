# TASK-0304 — Implement retry and deterministic jitter policies

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0103, TASK-0302 |
| Blocks | TASK-0309 |
| Parallel group | PG-03B |
| Requirements | SCHED-013, SCHED-016, SCHED-017 |
| Tests | VT-SCHED-013, VT-SCHED-016, VT-SCHED-017 |
| ADRs | None |

## Objective

Evaluate retry predicates and derive stable backoff/jitter without HTTP-client implicit retries.

## Rationale

Implements SCHED-013, SCHED-016, SCHED-017 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/scheduler/retries.py

**Allowed files**

- src/webhook_receiver_conformance/scheduler/retries.py
- tests/unit/scheduler/test_retries.py

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

- **Owned:** ARC-SCHED
- **Consumed:** ARC-CLOCK, ARC-MANIFEST, ARC-SCHED

## Implementation scope

Evaluate retry predicates and derive stable backoff/jitter without HTTP-client implicit retries.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The same bundle yields the same signed jitter value regardless of task execution order.
- HTTP transport retries are disabled and every second attempt has a journaled retry decision.
- Manifest replay makes the same next-attempt decision for the same predecessor result.

## Commands to run

```bash
uv run pytest -q tests/unit/scheduler/test_retries.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/scheduler/retries.py
- tests/unit/scheduler/test_retries.py

## Completion evidence

- Passing evidence for VT-SCHED-013
- Passing evidence for VT-SCHED-016
- Passing evidence for VT-SCHED-017

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
