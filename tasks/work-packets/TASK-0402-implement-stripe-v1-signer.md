# TASK-0402 — Implement Stripe v1 signer

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-04-signers-and-mutations |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0401 |
| Blocks | TASK-0406 |
| Parallel group | PG-04B |
| Requirements | SIG-014, TEST-005 |
| Tests | VT-SIG-014, VT-TEST-005 |
| ADRs | None |

## Objective

Generate Stripe-compatible timestamped signatures, multiple v1 values, and invalid variants.

## Rationale

Implements SIG-014, TEST-005 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/signatures/stripe.py

**Allowed files**

- src/webhook_receiver_conformance/signatures/stripe.py
- tests/unit/signatures/test_stripe.py
- tests/golden/signatures/stripe.json

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

Generate Stripe-compatible timestamped signatures, multiple v1 values, and invalid variants.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Golden vectors match the documented timestamp-dot-payload signing input and header form.
- Golden updates require an explicit compatibility review marker.

## Commands to run

```bash
uv run pytest -q tests/unit/signatures/test_stripe.py tests/golden/signatures/stripe.json
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/signatures/stripe.py
- tests/unit/signatures/test_stripe.py
- tests/golden/signatures/stripe.json

## Completion evidence

- Passing evidence for VT-SIG-014
- Passing evidence for VT-TEST-005

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
