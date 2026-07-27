# TASK-0207 — Implement resume policy engine

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-02-journal-and-state |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0206 |
| Blocks | TASK-0509, TASK-0806 |
| Parallel group | None |
| Requirements | CLI-005, DATA-018, REL-004, REL-006, REL-007, REL-013, SCHED-018 |
| Tests | VT-CLI-005, VT-DATA-018, VT-REL-004, VT-REL-006, VT-REL-007, VT-REL-013, VT-SCHED-018 |
| ADRs | ADR-004, ADR-008, ADR-009 |

## Objective

Apply stop, observe, or explicit redelivery policy to recoverable and ambiguous work.

## Rationale

Implements CLI-005, DATA-018, REL-004, REL-006, REL-007, REL-013, SCHED-018 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/recovery/policy.py

**Allowed files**

- src/webhook_receiver_conformance/recovery/policy.py
- tests/unit/recovery/test_policy.py

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

- **Owned:** ARC-RECOVERY
- **Consumed:** ARC-CLI, ARC-CLOCK, ARC-JOURNAL, ARC-RECOVERY, ARC-SCHED

## Implementation scope

Apply stop, observe, or explicit redelivery policy to recoverable and ambiguous work.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- `webhook-conformance resume --help` exits 0 and the command contract test demonstrates its stated job.
- A deliberately corrupt or referentially invalid database fails with harness_error before delivery.
- Resume schedules every due item exactly once unless policy creates an explicit new physical attempt.
- resume without --on-ambiguous does not contact the receiver and exits 4.
- The original unknown attempt remains immutable and the new attempt has the next ordinal and a distinct attempt_id.
- Config-only or CLI-only consent is insufficient.
- No automatic repair or replacement occurs and exit classification is harness_error.

## Commands to run

```bash
uv run pytest -q tests/unit/recovery/test_policy.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/recovery/policy.py
- tests/unit/recovery/test_policy.py

## Completion evidence

- Passing evidence for VT-CLI-005
- Passing evidence for VT-DATA-018
- Passing evidence for VT-REL-004
- Passing evidence for VT-REL-006
- Passing evidence for VT-REL-007
- Passing evidence for VT-REL-013
- Passing evidence for VT-SCHED-018

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
