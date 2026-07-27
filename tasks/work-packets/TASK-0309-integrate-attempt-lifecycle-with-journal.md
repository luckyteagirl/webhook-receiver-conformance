# TASK-0309 — Integrate attempt lifecycle with journal

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0203, TASK-0304, TASK-0308 |
| Blocks | TASK-0310, TASK-0311, TASK-0407, TASK-0505, TASK-0806 |
| Parallel group | None |
| Requirements | HTTP-020, HTTP-021, PRIV-005, REL-001, REL-003, REL-006, REL-008, STATE-004 |
| Tests | VT-HTTP-020, VT-HTTP-021, VT-PRIV-005, VT-REL-001, VT-REL-003, VT-REL-006, VT-REL-008, VT-STATE-004 |
| ADRs | ADR-004, ADR-009 |

## Objective

Persist pre-send intent, transport phase evidence, terminal classification, and retry scheduling at defined transaction boundaries.

## Rationale

Implements HTTP-020, HTTP-021, PRIV-005, REL-001, REL-003, REL-006, REL-008, STATE-004 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/runtime/attempts.py

**Allowed files**

- src/webhook_receiver_conformance/runtime/attempts.py
- tests/integration/test_attempt_lifecycle.py

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
- **Consumed:** ARC-HTTP, ARC-JOURNAL, ARC-RECOVERY, ARC-REPORT-HTML, ARC-SECRET, ARC-TARGET

## Implementation scope

Persist pre-send intent, transport phase evidence, terminal classification, and retry scheduling at defined transaction boundaries.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The attempt-state model and SQL checks contain the same state set.
- DNS failure and connection refusal yield not_sent with no unknown_outcome.
- Write/read timeout tests never claim the receiver did not process the request.
- A byte scan of the journal finds no canary secret.
- Crash before connection leaves a durable attempt requiring recovery classification.
- Resolver rejection and connection refusal are eligible for configured retry without ambiguity.
- The original unknown attempt remains immutable and the new attempt has the next ordinal and a distinct attempt_id.
- Crash after outcome commit cannot omit or duplicate the derived retry schedule.

## Commands to run

```bash
uv run pytest -q tests/integration/test_attempt_lifecycle.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/runtime/attempts.py
- tests/integration/test_attempt_lifecycle.py

## Completion evidence

- Passing evidence for VT-HTTP-020
- Passing evidence for VT-HTTP-021
- Passing evidence for VT-PRIV-005
- Passing evidence for VT-REL-001
- Passing evidence for VT-REL-003
- Passing evidence for VT-REL-006
- Passing evidence for VT-REL-008
- Passing evidence for VT-STATE-004

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
