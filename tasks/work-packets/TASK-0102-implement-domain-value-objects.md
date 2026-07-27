# TASK-0102 — Implement domain value objects

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0002 |
| Blocks | TASK-0104, TASK-0108, TASK-0201, TASK-0301, TASK-0501 |
| Parallel group | PG-01A |
| Requirements | API-001, FR-002 |
| Tests | VT-API-001, VT-FR-002 |
| ADRs | None |

## Objective

Implement immutable models for runs, scenarios, logical events, deliveries, attempts, observations, assertions, and outcomes.

## Rationale

Implements API-001, FR-002 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/domain/models.py
- src/webhook_receiver_conformance/domain/enums.py

**Allowed files**

- src/webhook_receiver_conformance/domain/models.py
- src/webhook_receiver_conformance/domain/enums.py
- tests/unit/domain/test_models.py

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
- **Consumed:** ARC-ASSERT, ARC-COMPILER, ARC-HTTP

## Implementation scope

Implement immutable models for runs, scenarios, logical events, deliveries, attempts, observations, assertions, and outcomes.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The result schema stores attempt evidence and observation evidence in different typed collections linked by identifiers.
- Static type checking reports no untyped public service method and contract tests cover serialization boundaries.

## Commands to run

```bash
uv run pytest -q tests/unit/domain/test_models.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/domain/models.py
- src/webhook_receiver_conformance/domain/enums.py
- tests/unit/domain/test_models.py

## Completion evidence

- Passing evidence for VT-API-001
- Passing evidence for VT-FR-002

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
