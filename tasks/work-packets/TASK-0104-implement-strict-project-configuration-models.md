# TASK-0104 — Implement strict project configuration models

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0102, TASK-0003 |
| Blocks | TASK-0105, TASK-0106, TASK-0107, TASK-0108, TASK-0305 |
| Parallel group | PG-01B |
| Requirements | CFG-001, CFG-003, CFG-014, FR-009, HTTP-001, HTTP-006, HTTP-013, HTTP-017, OBS-017, PERF-004, PERF-005, SCHED-003, SCHED-005, SCHED-006, SEC-025 |
| Tests | VT-CFG-001, VT-CFG-003, VT-CFG-014, VT-FR-009, VT-HTTP-001, VT-HTTP-006, VT-HTTP-013, VT-HTTP-017, VT-OBS-017, VT-PERF-004, VT-PERF-005, VT-SCHED-003, VT-SCHED-005, VT-SCHED-006, VT-SEC-025 |
| ADRs | ADR-005, ADR-019, ADR-021, ADR-023 |

## Objective

Implement strict Pydantic models that match project-config.schema.json and reject unknown fields.

## Rationale

Implements CFG-001, CFG-003, CFG-014, FR-009, HTTP-001, HTTP-006, HTTP-013, HTTP-017 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/config/models.py
- src/webhook_receiver_conformance/config/schema.py

**Allowed files**

- src/webhook_receiver_conformance/config/models.py
- src/webhook_receiver_conformance/config/schema.py
- tests/unit/config/test_models.py

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

- **Owned:** ARC-CONFIG
- **Consumed:** ARC-CLOCK, ARC-CONFIG, ARC-HTTP, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-SCHED, ARC-SECRET, ARC-TARGET

## Implementation scope

Implement strict Pydantic models that match project-config.schema.json and reject unknown fields.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A concurrency value of 51 is rejected when the v0.1 hard limit is 50.
- The minimal example parses and validates with schema_version 1.
- A misspelled timeout field fails validation instead of being ignored.
- schema_version 2 fails with exit code 6 and identifies the supported version range.
- Schema validation rejects overflow and fractional logical durations.
- A scale outside the range fails validation and a scale of 0.01 maps 10 logical seconds to 100 physical milliseconds.
- Virtual mode is available only to unit-test clock implementations and is rejected in project configuration.
- Project configuration rejects other methods in v0.1.
- Each forbidden header fails before manifest creation.
- Each timeout type has an isolated fault test and distinct error classification.
- A configured limit greater than 16777216 bytes fails validation.
- A smaller value fails validation and no busy loop occurs.
- Each input class has a boundary test and a classified resource_limit diagnostic.
- Omitted configuration realizes concurrency 10 in the effective snapshot.
- 50 validates and 51 fails before task creation.

## Commands to run

```bash
uv run pytest -q tests/unit/config/test_models.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/config/models.py
- src/webhook_receiver_conformance/config/schema.py
- tests/unit/config/test_models.py

## Completion evidence

- Passing evidence for VT-CFG-001
- Passing evidence for VT-CFG-003
- Passing evidence for VT-CFG-014
- Passing evidence for VT-FR-009
- Passing evidence for VT-HTTP-001
- Passing evidence for VT-HTTP-006
- Passing evidence for VT-HTTP-013
- Passing evidence for VT-HTTP-017
- Passing evidence for VT-OBS-017
- Passing evidence for VT-PERF-004
- Passing evidence for VT-PERF-005
- Passing evidence for VT-SCHED-003
- Passing evidence for VT-SCHED-005
- Passing evidence for VT-SCHED-006
- Passing evidence for VT-SEC-025

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
