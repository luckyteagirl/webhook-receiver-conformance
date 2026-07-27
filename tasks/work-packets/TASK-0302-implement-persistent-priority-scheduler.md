# TASK-0302 — Implement persistent priority scheduler

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0203, TASK-0301 |
| Blocks | TASK-0303, TASK-0304, TASK-0311 |
| Parallel group | None |
| Requirements | SCHED-014, SCHED-018, TEST-003, TEST-004 |
| Tests | VT-SCHED-014, VT-SCHED-018, VT-TEST-003, VT-TEST-004 |
| ADRs | None |

## Objective

Schedule due work with stable tie-breaking and persist every schedule transition.

## Rationale

Implements SCHED-014, SCHED-018, TEST-003, TEST-004 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/scheduler/queue.py
- src/webhook_receiver_conformance/scheduler/engine.py

**Allowed files**

- src/webhook_receiver_conformance/scheduler/queue.py
- src/webhook_receiver_conformance/scheduler/engine.py
- tests/unit/scheduler/test_queue.py

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
- **Consumed:** ARC-CLOCK, ARC-REF, ARC-SCHED

## Implementation scope

Schedule due work with stable tie-breaking and persist every schedule transition.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A golden schedule with equal due times remains byte-identical across supported platforms.
- Resume schedules every due item exactly once unless policy creates an explicit new physical attempt.
- Hypothesis profiles run deterministic CI settings and retain minimized reproducers as explicit bundles where relevant.
- Random action sequences preserve invariants and shrink to a replayable action list.

## Commands to run

```bash
uv run pytest -q tests/unit/scheduler/test_queue.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/scheduler/queue.py
- src/webhook_receiver_conformance/scheduler/engine.py
- tests/unit/scheduler/test_queue.py

## Completion evidence

- Passing evidence for VT-SCHED-014
- Passing evidence for VT-SCHED-018
- Passing evidence for VT-TEST-003
- Passing evidence for VT-TEST-004

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
