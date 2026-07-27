# TASK-0307 — Implement public-target preflight

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0305, TASK-0306 |
| Blocks | TASK-0805 |
| Parallel group | None |
| Requirements | CLI-017, HTTP-024, SEC-003, SEC-004 |
| Tests | VT-CLI-017, VT-HTTP-024, VT-SEC-003, VT-SEC-004 |
| ADRs | ADR-014 |

## Objective

Require exact allowlisting, runtime authorization, and a matching receiver challenge before any public delivery.

## Rationale

Implements CLI-017, HTTP-024, SEC-003, SEC-004 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/network/preflight.py

**Allowed files**

- src/webhook_receiver_conformance/network/preflight.py
- tests/unit/network/test_preflight.py

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

- **Owned:** ARC-REF
- **Consumed:** ARC-CLI, ARC-SECRET, ARC-TARGET

## Implementation scope

Require exact allowlisting, runtime authorization, and a matching receiver challenge before any public delivery.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Do not send fixture data during preflight; use a dedicated nonce challenge and no redirects.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A public target fails before preflight when the authorization argument is absent or does not match.
- A missing, stale, redirected, or mismatched challenge aborts the run before fixture delivery.
- Omitting any one gate prevents DNS resolution and delivery.
- A replayed, missing, wrong-host, or expired challenge fails closed.

## Commands to run

```bash
uv run pytest -q tests/unit/network/test_preflight.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/network/preflight.py
- tests/unit/network/test_preflight.py

## Completion evidence

- Passing evidence for VT-CLI-017
- Passing evidence for VT-HTTP-024
- Passing evidence for VT-SEC-003
- Passing evidence for VT-SEC-004

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
