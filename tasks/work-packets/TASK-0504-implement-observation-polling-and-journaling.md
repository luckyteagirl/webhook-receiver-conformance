# TASK-0504 — Implement observation polling and journaling

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-05-observers-and-assertions |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0502, TASK-0503, TASK-0203 |
| Blocks | TASK-0507, TASK-0509, TASK-0806 |
| Parallel group | None |
| Requirements | ASSERT-012, OBS-008, OBS-012, OBS-016, OBS-017, OBS-018, PRIV-005, REL-009, STATE-005 |
| Tests | VT-ASSERT-012, VT-OBS-008, VT-OBS-012, VT-OBS-016, VT-OBS-017, VT-OBS-018, VT-PRIV-005, VT-REL-009, VT-STATE-005 |
| ADRs | None |

## Objective

Poll pending evidence within a monotonic deadline and persist every sample and classification.

## Rationale

Implements ASSERT-012, OBS-008, OBS-012, OBS-016, OBS-017, OBS-018, PRIV-005, REL-009 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/observers/polling.py
- src/webhook_receiver_conformance/runtime/observations.py

**Allowed files**

- src/webhook_receiver_conformance/observers/polling.py
- src/webhook_receiver_conformance/runtime/observations.py
- tests/integration/test_observation_lifecycle.py

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

- **Owned:** ARC-OBS-CMD, ARC-OBS-HTTP
- **Consumed:** ARC-ASSERT, ARC-JOURNAL, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-RECOVERY, ARC-REPORT-HTML, ARC-SECRET

## Implementation scope

Poll pending evidence within a monotonic deadline and persist every sample and classification.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Observer lifecycle tests cover every terminal classification.
- A hanging observer is terminated and persisted as timed_out.
- A retried observation uses the same logical request_id and a new sample_id.
- A non-read-only observer is limited to one explicit invocation and cannot reconcile ambiguity.
- A smaller value fails validation and no busy loop occurs.
- Pending responses become timed_out at the deadline and do not continue in the background.
- The final report includes every sample ID and the terminal pass or timeout.
- A byte scan of the journal finds no canary secret.
- A non-idempotent observer error is terminal and not retried.

## Commands to run

```bash
uv run pytest -q tests/integration/test_observation_lifecycle.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/observers/polling.py
- src/webhook_receiver_conformance/runtime/observations.py
- tests/integration/test_observation_lifecycle.py

## Completion evidence

- Passing evidence for VT-ASSERT-012
- Passing evidence for VT-OBS-008
- Passing evidence for VT-OBS-012
- Passing evidence for VT-OBS-016
- Passing evidence for VT-OBS-017
- Passing evidence for VT-OBS-018
- Passing evidence for VT-PRIV-005
- Passing evidence for VT-REL-009
- Passing evidence for VT-STATE-005

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
