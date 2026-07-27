# TASK-0407 — Integrate signers and mutations into manifest and executor

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-04-signers-and-mutations |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0405, TASK-0406, TASK-0309 |
| Blocks | TASK-0701, TASK-0805 |
| Parallel group | None |
| Requirements | MUT-002 |
| Tests | VT-MUT-002 |
| ADRs | ADR-012 |

## Objective

Realize mutation parameters during planning and produce exact signed bytes during execution.

## Rationale

Implements MUT-002 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/manifest/compiler.py
- src/webhook_receiver_conformance/runtime/attempts.py

**Allowed files**

- src/webhook_receiver_conformance/manifest/compiler.py
- src/webhook_receiver_conformance/runtime/attempts.py
- tests/integration/test_signing_mutation_flow.py

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

- **Owned:** ARC-COMPILER, ARC-MANIFEST, ARC-SIGN, ARC-MUT
- **Consumed:** ARC-MUT

## Implementation scope

Realize mutation parameters during planning and produce exact signed bytes during execution.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Replay invokes no random generator and produces the same mutated blob digest.

## Commands to run

```bash
uv run pytest -q tests/integration/test_signing_mutation_flow.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/manifest/compiler.py
- src/webhook_receiver_conformance/runtime/attempts.py
- tests/integration/test_signing_mutation_flow.py

## Completion evidence

- Passing evidence for VT-MUT-002

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
