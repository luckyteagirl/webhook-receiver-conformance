# TASK-0303 — Implement barriers and concurrency groups

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0302 |
| Blocks | None |
| Parallel group | PG-03B |
| Requirements | FR-009, PERF-004, PERF-005, SCHED-015, SEC-026 |
| Tests | VT-FR-009, VT-PERF-004, VT-PERF-005, VT-SCHED-015, VT-SEC-026 |
| ADRs | None |

## Objective

Release grouped deliveries through structured concurrency without claiming simultaneous network arrival.

## Rationale

Implements FR-009, PERF-004, PERF-005, SCHED-015, SEC-026 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/scheduler/barriers.py

**Allowed files**

- src/webhook_receiver_conformance/scheduler/barriers.py
- tests/unit/scheduler/test_barriers.py

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
- **Consumed:** ARC-CLOCK, ARC-CONFIG, ARC-HTTP, ARC-SCHED, ARC-SECRET, ARC-TARGET

## Implementation scope

Release grouped deliveries through structured concurrency without claiming simultaneous network arrival.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A concurrency value of 51 is rejected when the v0.1 hard limit is 50.
- Reports label actual monotonic start times and never use the term simultaneous as a guarantee.
- Task creation never exceeds the configured cap under duplicate and retry scenarios.
- Omitted configuration realizes concurrency 10 in the effective snapshot.
- 50 validates and 51 fails before task creation.

## Commands to run

```bash
uv run pytest -q tests/unit/scheduler/test_barriers.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/scheduler/barriers.py
- tests/unit/scheduler/test_barriers.py

## Completion evidence

- Passing evidence for VT-FR-009
- Passing evidence for VT-PERF-004
- Passing evidence for VT-PERF-005
- Passing evidence for VT-SCHED-015
- Passing evidence for VT-SEC-026

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
