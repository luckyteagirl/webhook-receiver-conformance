# TASK-0103 — Implement deterministic byte generator

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0002 |
| Blocks | TASK-0109, TASK-0304 |
| Parallel group | PG-01A |
| Requirements | DATA-006, SCHED-008, SCHED-009, SCHED-010, SCHED-012, SCHED-013, TEST-003, TEST-005 |
| Tests | VT-DATA-006, VT-SCHED-008, VT-SCHED-009, VT-SCHED-010, VT-SCHED-012, VT-SCHED-013, VT-TEST-003, VT-TEST-005 |
| ADRs | ADR-003, ADR-008, ADR-023 |

## Objective

Implement the versioned context-derived HMAC-SHA256 byte generator and unbiased integer sampling.

## Rationale

Implements DATA-006, SCHED-008, SCHED-009, SCHED-010, SCHED-012, SCHED-013, TEST-003, TEST-005 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/determinism/generator.py

**Allowed files**

- src/webhook_receiver_conformance/determinism/generator.py
- tests/unit/determinism/test_generator.py
- tests/golden/prng-v1.json

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

- **Owned:** ARC-PRNG, ARC-REPORT-JSON
- **Consumed:** ARC-CLOCK, ARC-MANIFEST, ARC-PRNG, ARC-REF, ARC-SCHED

## Implementation scope

Implement the versioned context-derived HMAC-SHA256 byte generator and unbiased integer sampling.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Do not reuse signing secrets as generator seeds; use constant, versioned domain separators.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Golden vectors remain stable across supported Python versions and insertion of unrelated entities.
- Published golden vectors match on Python 3.12, 3.13, and 3.14.
- Adding an unrelated event does not change existing IDs, jitter, or mutation values.
- Equivalent byte input through text and explicit seed-hash forms yields the documented normalized key.
- Property tests confirm every value is in range and golden vectors define rejection behavior.
- The same bundle yields the same signed jitter value regardless of task execution order.
- Hypothesis profiles run deterministic CI settings and retain minimized reproducers as explicit bundles where relevant.
- Golden updates require an explicit compatibility review marker.

## Commands to run

```bash
uv run pytest -q tests/unit/determinism/test_generator.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/determinism/generator.py
- tests/unit/determinism/test_generator.py
- tests/golden/prng-v1.json

## Completion evidence

- Passing evidence for VT-DATA-006
- Passing evidence for VT-SCHED-008
- Passing evidence for VT-SCHED-009
- Passing evidence for VT-SCHED-010
- Passing evidence for VT-SCHED-012
- Passing evidence for VT-SCHED-013
- Passing evidence for VT-TEST-003
- Passing evidence for VT-TEST-005

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
