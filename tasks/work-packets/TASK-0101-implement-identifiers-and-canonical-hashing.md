# TASK-0101 — Implement identifiers and canonical hashing

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0002 |
| Blocks | TASK-0107, TASK-0109 |
| Parallel group | PG-01A |
| Requirements | DATA-002, DATA-005, DATA-006 |
| Tests | VT-DATA-002, VT-DATA-005, VT-DATA-006 |
| ADRs | ADR-004, ADR-008 |

## Objective

Implement execution-only UUIDv4 run IDs, raw run-agnostic canonical-manifest hashes, type-prefixed planned-entity IDs, prefixed blob hashes, and collision checks.

## Rationale

Implements DATA-002, DATA-005, DATA-006 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/domain/identifiers.py
- src/webhook_receiver_conformance/domain/hashing.py

**Allowed files**

- src/webhook_receiver_conformance/domain/identifiers.py
- src/webhook_receiver_conformance/domain/hashing.py
- tests/unit/domain/test_identifiers.py

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

- **Owned:** No public interface; task owns only listed implementation files.
- **Consumed:** ARC-JOURNAL, ARC-MANIFEST, ARC-PRNG

## Implementation scope

Implement UUIDv4 run IDs outside the manifest, raw canonical-manifest hashes that omit only `manifest_id`, the integer-only I-JSON-safe canonical profile, type-prefixed planned-entity IDs, prefixed blob hashes, and collision checks.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Replay creates a new run_id while preserving the same manifest_id.
- The immutable manifest contains no `run_id` and its hash projection omits only `manifest_id`.
- Canonicalization rejects floating-point values and integers outside `-(2^53-1)` through `2^53-1`.
- Cross-language golden vectors produce the documented digest.
- Golden vectors remain stable across supported Python versions and insertion of unrelated entities.

## Commands to run

```bash
uv run pytest -q tests/unit/domain/test_identifiers.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/domain/identifiers.py
- src/webhook_receiver_conformance/domain/hashing.py
- tests/unit/domain/test_identifiers.py

## Completion evidence

- Passing evidence for VT-DATA-002
- Passing evidence for VT-DATA-005
- Passing evidence for VT-DATA-006

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
