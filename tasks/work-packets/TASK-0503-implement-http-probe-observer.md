# TASK-0503 — Implement HTTP probe observer

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-05-observers-and-assertions |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0501, TASK-0308 |
| Blocks | TASK-0504, TASK-0805 |
| Parallel group | PG-05B |
| Requirements | DX-007, OBS-008, OBS-009, OBS-010, OBS-011, OBS-019, SEC-009, SEC-010 |
| Tests | VT-DX-007, VT-OBS-008, VT-OBS-009, VT-OBS-010, VT-OBS-011, VT-OBS-019, VT-SEC-009, VT-SEC-010 |
| ADRs | ADR-003 |

## Objective

Invoke authenticated capabilities and observe endpoints through the guarded HTTP transport.

## Rationale

Implements DX-007, OBS-008, OBS-009, OBS-010, OBS-011, OBS-019, SEC-009, SEC-010 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/observers/http_probe.py

**Allowed files**

- src/webhook_receiver_conformance/observers/http_probe.py
- tests/unit/observers/test_http_probe.py

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

- **Owned:** ARC-HTTP, ARC-OBS-CMD, ARC-OBS-HTTP
- **Consumed:** ARC-CLI, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-SECRET, ARC-TARGET

## Implementation scope

Invoke authenticated capabilities and observe endpoints through the guarded HTTP transport.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A hanging observer is terminated and persisted as timed_out.
- Contract tests validate methods, paths, request IDs, and schemas.
- Missing or wrong credentials produce observer error without response-body leakage.
- Observer URLs cannot bypass blocked address classes or redirects.
- Sensitive evidence and child stderr values are absent from every default artifact.
- 301 through 308 responses create no follow-up request.
- Proxy environment variables do not receive any test request.
- Both examples pass the same observer test kit.

## Commands to run

```bash
uv run pytest -q tests/unit/observers/test_http_probe.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/observers/http_probe.py
- tests/unit/observers/test_http_probe.py

## Completion evidence

- Passing evidence for VT-DX-007
- Passing evidence for VT-OBS-008
- Passing evidence for VT-OBS-009
- Passing evidence for VT-OBS-010
- Passing evidence for VT-OBS-011
- Passing evidence for VT-OBS-019
- Passing evidence for VT-SEC-009
- Passing evidence for VT-SEC-010

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
