# TASK-0807 — Implement quality-attribute budget tests

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | medium |
| Dependencies | TASK-0711 |
| Blocks | TASK-0810 |
| Parallel group | PG-08B |
| Requirements | PERF-001, PERF-002, PERF-003, PERF-006, PERF-007, PERF-008, TEST-017 |
| Tests | VT-PERF-001, VT-PERF-002, VT-PERF-003, VT-PERF-006, VT-PERF-007, VT-PERF-008, VT-TEST-017 |
| ADRs | ADR-020 |

## Objective

Measure startup, compilation, memory, disk, and bounded attempt throughput against declared non-load-test budgets.

## Rationale

Implements PERF-001, PERF-002, PERF-003, PERF-006, PERF-007, PERF-008, TEST-017 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- scripts/benchmark.py

**Allowed files**

- tests/performance/**
- scripts/benchmark.py

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

- **Owned:** No public interface; task owns only listed implementation files.
- **Consumed:** ARC-HTTP, ARC-REF, ARC-SCHED

## Implementation scope

Measure startup, compilation, memory, disk, and bounded attempt throughput against declared non-load-test budgets.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Thirty measured invocations meet the percentile budget.
- The locked benchmark corpus meets the percentile budget without network access.
- Peak RSS measurement remains within budget.
- The benchmark reports per-attempt growth and remains within budget.
- The locked report corpus meets the percentile budget.
- The cancellation benchmark exits within budget with response streams closed.
- The final scorecard links each PERF requirement to measured evidence.

## Commands to run

```bash
uv run pytest -q tests/performance/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- tests/performance/**
- scripts/benchmark.py

## Completion evidence

- Passing evidence for VT-PERF-001
- Passing evidence for VT-PERF-002
- Passing evidence for VT-PERF-003
- Passing evidence for VT-PERF-006
- Passing evidence for VT-PERF-007
- Passing evidence for VT-PERF-008
- Passing evidence for VT-TEST-017

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
