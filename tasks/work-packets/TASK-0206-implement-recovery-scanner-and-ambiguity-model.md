# TASK-0206 — Implement recovery scanner and ambiguity model

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-02-journal-and-state |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0203 |
| Blocks | TASK-0207 |
| Parallel group | None |
| Requirements | REL-002, STATE-011 |
| Tests | VT-REL-002, VT-STATE-011 |
| ADRs | ADR-009 |

## Objective

Classify incomplete attempts and observations after process interruption without inventing a known outcome.

## Rationale

Implements REL-002, STATE-011 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/recovery/scanner.py
- src/webhook_receiver_conformance/recovery/models.py

**Allowed files**

- src/webhook_receiver_conformance/recovery/scanner.py
- src/webhook_receiver_conformance/recovery/models.py
- tests/unit/recovery/test_scanner.py

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
- **Consumed:** ARC-JOURNAL, ARC-RECOVERY

## Implementation scope

Classify incomplete attempts and observations after process interruption without inventing a known outcome.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Resume never changes an unknown attempt to succeeded or failed.
- Crash tests at each phase produce unknown_outcome unless durable evidence proves no connection was established.

## Commands to run

```bash
uv run pytest -q tests/unit/recovery/test_scanner.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/recovery/scanner.py
- src/webhook_receiver_conformance/recovery/models.py
- tests/unit/recovery/test_scanner.py

## Completion evidence

- Passing evidence for VT-REL-002
- Passing evidence for VT-STATE-011

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
