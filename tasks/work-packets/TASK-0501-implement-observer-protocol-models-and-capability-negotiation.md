# TASK-0501 — Implement observer protocol models and capability negotiation

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-05-observers-and-assertions |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0102, TASK-0003 |
| Blocks | TASK-0502, TASK-0503, TASK-0506 |
| Parallel group | PG-05A |
| Requirements | API-004, ASSERT-016, OBS-001, OBS-009, OBS-012, OBS-013, OBS-014, OBS-015, OBS-016, OBS-020, PRIV-009, REL-009, TEST-002 |
| Tests | VT-API-004, VT-ASSERT-016, VT-OBS-001, VT-OBS-009, VT-OBS-012, VT-OBS-013, VT-OBS-014, VT-OBS-015, VT-OBS-016, VT-OBS-020, VT-PRIV-009, VT-REL-009, VT-TEST-002 |
| ADRs | ADR-010, ADR-013, ADR-022 |

## Objective

Implement versioned capabilities, observe requests, responses, evidence values, and error categories.

## Rationale

Implements API-004, ASSERT-016, OBS-001, OBS-009, OBS-012, OBS-013, OBS-014, OBS-015 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/observers/protocol.py
- schemas/observer-evidence.schema.json
- schemas/observer-request.schema.json
- schemas/observer-response.schema.json
- schemas/observation-record.schema.json

**Allowed files**

- src/webhook_receiver_conformance/observers/protocol.py
- schemas/observer-evidence.schema.json
- schemas/observer-request.schema.json
- schemas/observer-response.schema.json
- schemas/observation-record.schema.json
- tests/unit/observers/test_protocol.py

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

- **Owned:** ARC-OBS-CMD, ARC-OBS-HTTP
- **Consumed:** ARC-ASSERT, ARC-JOURNAL, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-RECOVERY, ARC-REF, ARC-REPORT-HTML, ARC-SECRET, ARC-SIGN

## Implementation scope

Implement versioned capabilities, observe requests, responses, evidence values, and error categories.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Every built-in implementation passes the same protocol conformance suite.
- The harness rejects an observer that does not return protocol version and supported evidence types.
- Contract tests validate methods, paths, request IDs, and schemas.
- A retried observation uses the same logical request_id and a new sample_id.
- Two different state snapshots cannot share a snapshot_id in the reference observer.
- Binary bytes are represented by digest/metadata rather than embedded arbitrary bytes.
- Every response has exactly one status and the harness maps it deterministically.
- A non-read-only observer is limited to one explicit invocation and cannot reconcile ambiguity.
- An unsupported processing_count assertion yields exit code 6 under fail-on-unsupported policy.
- Capability mismatch is visible before observer polling begins.
- The reference observer returns only requested capabilities and evidence names.
- A non-idempotent observer error is terminal and not retried.
- Adding a built-in implementation without registering the contract tests fails CI.

## Commands to run

```bash
uv run pytest -q tests/unit/observers/test_protocol.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/observers/protocol.py
- schemas/observer-evidence.schema.json
- schemas/observer-request.schema.json
- schemas/observer-response.schema.json
- schemas/observation-record.schema.json
- tests/unit/observers/test_protocol.py

## Completion evidence

- Passing evidence for VT-API-004
- Passing evidence for VT-ASSERT-016
- Passing evidence for VT-OBS-001
- Passing evidence for VT-OBS-009
- Passing evidence for VT-OBS-012
- Passing evidence for VT-OBS-013
- Passing evidence for VT-OBS-014
- Passing evidence for VT-OBS-015
- Passing evidence for VT-OBS-016
- Passing evidence for VT-OBS-020
- Passing evidence for VT-PRIV-009
- Passing evidence for VT-REL-009
- Passing evidence for VT-TEST-002

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
