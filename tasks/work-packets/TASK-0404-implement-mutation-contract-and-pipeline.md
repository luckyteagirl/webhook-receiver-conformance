# TASK-0404 — Implement mutation contract and pipeline

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-04-signers-and-mutations |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0107, TASK-0401 |
| Blocks | TASK-0405, TASK-0406 |
| Parallel group | PG-04A |
| Requirements | MUT-001, MUT-003, MUT-018, MUT-019, SIG-009, SIG-010 |
| Tests | VT-MUT-001, VT-MUT-003, VT-MUT-018, VT-MUT-019, VT-SIG-009, VT-SIG-010 |
| ADRs | ADR-011, ADR-012, ADR-024 |

## Objective

Apply versioned pre-sign structural, pre-sign raw, signer, and post-sign mutations in a fixed order.

## Rationale

Implements MUT-001, MUT-003, MUT-018, MUT-019, SIG-009, SIG-010 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/mutations/base.py
- src/webhook_receiver_conformance/mutations/pipeline.py

**Allowed files**

- src/webhook_receiver_conformance/mutations/base.py
- src/webhook_receiver_conformance/mutations/pipeline.py
- tests/unit/mutations/test_pipeline.py

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

- **Owned:** ARC-MUT
- **Consumed:** ARC-MUT, ARC-SIGN

## Implementation scope

Apply versioned pre-sign structural, pre-sign raw, signer, and post-sign mutations in a fixed order.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The wrong-key fingerprint differs from the valid key fingerprint and the reference receiver rejects it.
- The signature header remains unchanged while the delivered body digest changes.
- Manifest schema rejects an operator without id or version.
- A golden pipeline test records each intermediate digest and matches the documented order.
- Structural JSON after invalid-json and two conflicting signature-removal operations fail with operator-specific diagnostics.
- A replaced sensitive value is absent from logs and HTML while its redacted marker remains.

## Commands to run

```bash
uv run pytest -q tests/unit/mutations/test_pipeline.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/mutations/base.py
- src/webhook_receiver_conformance/mutations/pipeline.py
- tests/unit/mutations/test_pipeline.py

## Completion evidence

- Passing evidence for VT-MUT-001
- Passing evidence for VT-MUT-003
- Passing evidence for VT-MUT-018
- Passing evidence for VT-MUT-019
- Passing evidence for VT-SIG-009
- Passing evidence for VT-SIG-010

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
