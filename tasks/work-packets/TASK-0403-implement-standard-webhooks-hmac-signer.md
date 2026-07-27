# TASK-0403 — Implement Standard Webhooks HMAC signer

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-04-signers-and-mutations |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0401 |
| Blocks | TASK-0406 |
| Parallel group | PG-04B |
| Requirements | SIG-013, SIG-015, TEST-005 |
| Tests | VT-SIG-013, VT-SIG-015, VT-TEST-005 |
| ADRs | ADR-024 |

## Objective

Generate Standard Webhooks HMAC signatures, IDs, timestamps, multiple signatures, and rotation cases.

## Rationale

Implements SIG-013, SIG-015, TEST-005 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/signatures/standard_webhooks.py

**Allowed files**

- src/webhook_receiver_conformance/signatures/standard_webhooks.py
- tests/unit/signatures/test_standard_webhooks.py
- tests/golden/signatures/standard-webhooks.json

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

- **Owned:** ARC-SIGN, ARC-REPORT-JSON
- **Consumed:** ARC-REF, ARC-SIGN

## Implementation scope

Generate Standard Webhooks HMAC signatures, IDs, timestamps, multiple signatures, and rotation cases.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A golden header contains two independently verifiable v1 signatures in deterministic order.
- Golden vectors match webhook-id, webhook-timestamp, and webhook-signature semantics.
- Golden updates require an explicit compatibility review marker.

## Commands to run

```bash
uv run pytest -q tests/unit/signatures/test_standard_webhooks.py tests/golden/signatures/standard-webhooks.json
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/signatures/standard_webhooks.py
- tests/unit/signatures/test_standard_webhooks.py
- tests/golden/signatures/standard-webhooks.json

## Completion evidence

- Passing evidence for VT-SIG-013
- Passing evidence for VT-SIG-015
- Passing evidence for VT-TEST-005

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
