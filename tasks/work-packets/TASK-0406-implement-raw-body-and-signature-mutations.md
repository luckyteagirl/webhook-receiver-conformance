# TASK-0406 — Implement raw-body and signature mutations

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-04-signers-and-mutations |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0402, TASK-0403, TASK-0404 |
| Blocks | TASK-0407 |
| Parallel group | PG-04C |
| Requirements | MUT-012, MUT-013, MUT-014, MUT-015, MUT-016, MUT-017, SIG-007, SIG-008, SIG-009, SIG-010 |
| Tests | VT-MUT-012, VT-MUT-013, VT-MUT-014, VT-MUT-015, VT-MUT-016, VT-MUT-017, VT-SIG-007, VT-SIG-008, VT-SIG-009, VT-SIG-010 |
| ADRs | ADR-011, ADR-024 |

## Objective

Implement truncation, invalid JSON, content-type mismatch, post-sign alteration, stale timestamp, wrong key, missing signature, and malformed signature.

## Rationale

Implements MUT-012, MUT-013, MUT-014, MUT-015, MUT-016, MUT-017, SIG-007, SIG-008 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/mutations/raw_ops.py
- src/webhook_receiver_conformance/mutations/signature_ops.py

**Allowed files**

- src/webhook_receiver_conformance/mutations/raw_ops.py
- src/webhook_receiver_conformance/mutations/signature_ops.py
- tests/unit/mutations/test_raw_ops.py

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

- **Owned:** ARC-SIGN, ARC-MUT
- **Consumed:** ARC-MUT, ARC-SIGN

## Implementation scope

Implement truncation, invalid JSON, content-type mismatch, post-sign alteration, stale timestamp, wrong key, missing signature, and malformed signature.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The resulting attempt contains no owned signature header and remains otherwise byte-identical.
- Malformed output is deterministic and identified by mutation ID/version.
- The wrong-key fingerprint differs from the valid key fingerprint and the reference receiver rejects it.
- The signature header remains unchanged while the delivered body digest changes.
- Retained count zero through body length is validated and output digest is deterministic.
- Each catalog case is named and reproduced from the manifest.
- Body bytes remain equal while Content-Type changes to the realized value.
- The pre-alter signed digest and delivered digest are both recorded.
- Reports never collapse the four cases into a generic invalid_signature label.
- Expansion beyond the hard limit fails at planning rather than allocating the requested body.

## Commands to run

```bash
uv run pytest -q tests/unit/mutations/test_raw_ops.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/mutations/raw_ops.py
- src/webhook_receiver_conformance/mutations/signature_ops.py
- tests/unit/mutations/test_raw_ops.py

## Completion evidence

- Passing evidence for VT-MUT-012
- Passing evidence for VT-MUT-013
- Passing evidence for VT-MUT-014
- Passing evidence for VT-MUT-015
- Passing evidence for VT-MUT-016
- Passing evidence for VT-MUT-017
- Passing evidence for VT-SIG-007
- Passing evidence for VT-SIG-008
- Passing evidence for VT-SIG-009
- Passing evidence for VT-SIG-010

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
