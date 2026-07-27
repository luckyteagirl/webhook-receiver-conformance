# TASK-0405 — Implement structural JSON mutations

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-04-signers-and-mutations |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0404 |
| Blocks | TASK-0407 |
| Parallel group | PG-04C |
| Requirements | MUT-004, MUT-005, MUT-006, MUT-007, MUT-008, MUT-009, MUT-010, MUT-011 |
| Tests | VT-MUT-004, VT-MUT-005, VT-MUT-006, VT-MUT-007, VT-MUT-008, VT-MUT-009, VT-MUT-010, VT-MUT-011 |
| ADRs | ADR-012 |

## Objective

Implement JSON Pointer removal, replacement, type replacement, field addition, event-ID change, and event-type change.

## Rationale

Implements MUT-004, MUT-005, MUT-006, MUT-007, MUT-008, MUT-009, MUT-010, MUT-011 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/mutations/json_ops.py

**Allowed files**

- src/webhook_receiver_conformance/mutations/json_ops.py
- tests/unit/mutations/test_json_ops.py

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

- **Owned:** ARC-MUT, ARC-REPORT-JSON
- **Consumed:** ARC-MUT

## Implementation scope

Implement JSON Pointer removal, replacement, type replacement, field addition, event-ID change, and event-type change.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Golden vectors define UTF-8, separators, escaping, and key-order behavior.
- A raw invalid-JSON fixture receives unsupported_input rather than an implicit replacement value.
- Removing an existing pointer succeeds and a missing pointer follows the configured error policy.
- The manifest stores the pointer and exact replacement JSON value.
- A number-to-string mutation produces the documented serialized value.
- The operator rejects an existing target field unless overwrite=true is explicitly represented.
- Evidence shows different provider payload ID and stable harness logical event identity.
- The configured JSON Pointer changes while all unrelated fields remain equal.

## Commands to run

```bash
uv run pytest -q tests/unit/mutations/test_json_ops.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/mutations/json_ops.py
- tests/unit/mutations/test_json_ops.py

## Completion evidence

- Passing evidence for VT-MUT-004
- Passing evidence for VT-MUT-005
- Passing evidence for VT-MUT-006
- Passing evidence for VT-MUT-007
- Passing evidence for VT-MUT-008
- Passing evidence for VT-MUT-009
- Passing evidence for VT-MUT-010
- Passing evidence for VT-MUT-011

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
