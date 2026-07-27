# TASK-0701 — Implement correct reference receiver

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-07-reference-receivers |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0407, TASK-0508 |
| Blocks | TASK-0702, TASK-0703, TASK-0704, TASK-0705, TASK-0706, TASK-0707, TASK-0708, TASK-0709, TASK-0710 |
| Parallel group | None |
| Requirements | FR-003, OBS-013, PRIV-009, SIG-004, SIG-006, SIG-018, TEST-012 |
| Tests | VT-FR-003, VT-OBS-013, VT-PRIV-009, VT-SIG-004, VT-SIG-006, VT-SIG-018, VT-TEST-012 |
| ADRs | ADR-024 |

## Objective

Implement raw-body verification, replay-window enforcement, atomic inbox/business/outbox processing, delayed dependency resolution, and read-only test probes.

## Rationale

Implements FR-003, OBS-013, PRIV-009, SIG-004, SIG-006, SIG-018, TEST-012 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- reference_receivers/correct/**

**Allowed files**

- reference_receivers/correct/**
- tests/e2e/test_correct_receiver.py

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
- **Consumed:** ARC-OBS-CMD, ARC-OBS-HTTP, ARC-REF, ARC-REPORT-HTML, ARC-SECRET

## Implementation scope

Implement raw-body verification, replay-window enforcement, atomic inbox/business/outbox processing, delayed dependency resolution, and read-only test probes.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The complete P0 corpus produces a pass verdict and exit code 0 against REF-CORRECT-001.
- Static and unit tests confirm hmac.compare_digest or an equivalent constant-time primitive is used.
- A stale timestamp fails transport rejection and produces no business-state evidence.
- Time-controlled rotation tests cover old-only, overlap, and new-only windows.
- Two different state snapshots cannot share a snapshot_id in the reference observer.
- The reference observer returns only requested capabilities and evidence names.
- The corpus matrix has no unexpected fail, error, unsupported, or ambiguous result.

## Commands to run

```bash
uv run pytest -q tests/e2e/test_correct_receiver.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- reference_receivers/correct/**
- tests/e2e/test_correct_receiver.py

## Completion evidence

- Passing evidence for VT-FR-003
- Passing evidence for VT-OBS-013
- Passing evidence for VT-PRIV-009
- Passing evidence for VT-SIG-004
- Passing evidence for VT-SIG-006
- Passing evidence for VT-SIG-018
- Passing evidence for VT-TEST-012

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
