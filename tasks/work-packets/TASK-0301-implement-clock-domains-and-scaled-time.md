# TASK-0301 — Implement clock domains and scaled time

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0102 |
| Blocks | TASK-0302, TASK-0308 |
| Parallel group | PG-03A |
| Requirements | SCHED-001, SCHED-002, SCHED-003, SCHED-004, SCHED-005, SCHED-006, SCHED-007, SCHED-019, STATE-009 |
| Tests | VT-SCHED-001, VT-SCHED-002, VT-SCHED-003, VT-SCHED-004, VT-SCHED-005, VT-SCHED-006, VT-SCHED-007, VT-SCHED-019, VT-STATE-009 |
| ADRs | ADR-005, ADR-006, ADR-021, ADR-023 |

## Objective

Implement UTC wall timestamps, monotonic durations, logical nanoseconds, and real/scaled clock modes.

## Rationale

Implements SCHED-001, SCHED-002, SCHED-003, SCHED-004, SCHED-005, SCHED-006, SCHED-007, SCHED-019 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/scheduler/clocks.py

**Allowed files**

- src/webhook_receiver_conformance/scheduler/clocks.py
- tests/unit/scheduler/test_clocks.py

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

- **Owned:** ARC-CLOCK, ARC-SCHED, ARC-LOCK
- **Consumed:** ARC-CLOCK, ARC-JOURNAL, ARC-RECOVERY, ARC-SCHED

## Implementation scope

Implement UTC wall timestamps, monotonic durations, logical nanoseconds, and real/scaled clock modes.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Live transitions contain both fields while imported historical records explicitly mark unavailable monotonic values.
- Scheduler ordering remains unchanged when the system wall clock jumps.
- A simulated wall-clock jump does not change a timeout result.
- Schema validation rejects overflow and fractional logical durations.
- A 100-millisecond logical wait completes within the documented test tolerance in real mode.
- A scale outside the range fails validation and a scale of 0.01 maps 10 logical seconds to 100 physical milliseconds.
- Virtual mode is available only to unit-test clock implementations and is rejected in project configuration.
- Changing the schedule scale does not change a configured 2-second HTTP timeout.
- A clock-injection test records the discontinuity while monotonic scheduling continues.

## Commands to run

```bash
uv run pytest -q tests/unit/scheduler/test_clocks.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/scheduler/clocks.py
- tests/unit/scheduler/test_clocks.py

## Completion evidence

- Passing evidence for VT-SCHED-001
- Passing evidence for VT-SCHED-002
- Passing evidence for VT-SCHED-003
- Passing evidence for VT-SCHED-004
- Passing evidence for VT-SCHED-005
- Passing evidence for VT-SCHED-006
- Passing evidence for VT-SCHED-007
- Passing evidence for VT-SCHED-019
- Passing evidence for VT-STATE-009

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
