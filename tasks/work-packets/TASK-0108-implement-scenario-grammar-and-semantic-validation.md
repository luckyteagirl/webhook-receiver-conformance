# TASK-0108 — Implement scenario grammar and semantic validation

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0102, TASK-0104 |
| Blocks | TASK-0109 |
| Parallel group | PG-01B |
| Requirements | FR-008, FR-010, MUT-018, SIG-003 |
| Tests | VT-FR-008, VT-FR-010, VT-MUT-018, VT-SIG-003 |
| ADRs | None |

## Objective

Validate events, dependencies, delivery steps, waits, barriers, mutations, observers, and assertions before execution.

## Rationale

Implements FR-008, FR-010, MUT-018, SIG-003 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/scenario/models.py
- src/webhook_receiver_conformance/scenario/validate.py

**Allowed files**

- src/webhook_receiver_conformance/scenario/models.py
- src/webhook_receiver_conformance/scenario/validate.py
- tests/unit/scenario/**

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
- **Consumed:** ARC-COMPILER, ARC-MUT, ARC-SIGN

## Implementation scope

Validate events, dependencies, delivery steps, waits, barriers, mutations, observers, and assertions before execution.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Semantic validation rejects a multi-fault scenario that lacks required baseline scenario IDs.
- A raw-byte fixture using the generic signer executes without importing a provider package.
- A user-supplied signature header fails planning instead of being silently overwritten.
- Structural JSON after invalid-json and two conflicting signature-removal operations fail with operator-specific diagnostics.

## Commands to run

```bash
uv run pytest -q tests/unit/scenario/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/scenario/models.py
- src/webhook_receiver_conformance/scenario/validate.py
- tests/unit/scenario/**

## Completion evidence

- Passing evidence for VT-FR-008
- Passing evidence for VT-FR-010
- Passing evidence for VT-MUT-018
- Passing evidence for VT-SIG-003

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
