# TASK-0401 — Implement signer contract and generic HMAC-SHA256

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-04-signers-and-mutations |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0106, TASK-0107 |
| Blocks | TASK-0402, TASK-0403, TASK-0404 |
| Parallel group | PG-04A |
| Requirements | API-004, FR-010, SIG-001, SIG-002, SIG-003, SIG-005, SIG-011, SIG-016, TEST-002 |
| Tests | VT-API-004, VT-FR-010, VT-SIG-001, VT-SIG-002, VT-SIG-003, VT-SIG-005, VT-SIG-011, VT-SIG-016, VT-TEST-002 |
| ADRs | ADR-011, ADR-013, ADR-022, ADR-024 |

## Objective

Implement exact-byte HMAC signing with versioned header templates and deterministic test vectors.

## Rationale

Implements API-004, FR-010, SIG-001, SIG-002, SIG-003, SIG-005, SIG-011, SIG-016 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/signatures/base.py
- src/webhook_receiver_conformance/signatures/hmac_generic.py

**Allowed files**

- src/webhook_receiver_conformance/signatures/base.py
- src/webhook_receiver_conformance/signatures/hmac_generic.py
- tests/unit/signatures/test_hmac_generic.py

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

- **Owned:** ARC-SIGN
- **Consumed:** ARC-COMPILER, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-REF, ARC-SECRET, ARC-SIGN

## Implementation scope

Implement exact-byte HMAC signing with versioned header templates and deterministic test vectors.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Use hmac.compare_digest in verification helpers and never expose keys in evidence.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A raw-byte fixture using the generic signer executes without importing a provider package.
- Every built-in implementation passes the same protocol conformance suite.
- Published generic HMAC test vectors match exactly.
- Whitespace-only fixture changes alter the signature as defined by the adapter.
- A user-supplied signature header fails planning instead of being silently overwritten.
- Scaled replay produces the same signature timestamp and signature bytes as the source bundle.
- Signer constructors accept secret handles and cannot serialize raw key bytes into models.
- The generator requests 32 bytes from secrets.token_bytes and stores only the secret reference and fingerprint.
- Adding a built-in implementation without registering the contract tests fails CI.

## Commands to run

```bash
uv run pytest -q tests/unit/signatures/test_hmac_generic.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/signatures/base.py
- src/webhook_receiver_conformance/signatures/hmac_generic.py
- tests/unit/signatures/test_hmac_generic.py

## Completion evidence

- Passing evidence for VT-API-004
- Passing evidence for VT-FR-010
- Passing evidence for VT-SIG-001
- Passing evidence for VT-SIG-002
- Passing evidence for VT-SIG-003
- Passing evidence for VT-SIG-005
- Passing evidence for VT-SIG-011
- Passing evidence for VT-SIG-016
- Passing evidence for VT-TEST-002

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
