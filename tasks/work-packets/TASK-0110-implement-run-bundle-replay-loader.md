# TASK-0110 — Implement run-bundle replay loader

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0109 |
| Blocks | TASK-0311 |
| Parallel group | None |
| Requirements | CLI-006, COMPAT-007, DATA-004, FR-012, REL-014, TEST-014 |
| Tests | VT-CLI-006, VT-COMPAT-007, VT-DATA-004, VT-FR-012, VT-REL-014, VT-TEST-014 |
| ADRs | None |

## Objective

Load and verify an existing bundle without rediscovering fixtures or invoking random generation.

## Rationale

Implements CLI-006, COMPAT-007, DATA-004, FR-012, REL-014, TEST-014 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/manifest/loader.py

**Allowed files**

- src/webhook_receiver_conformance/manifest/loader.py
- tests/unit/manifest/test_loader.py

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

- **Owned:** ARC-MANIFEST
- **Consumed:** ARC-CLI, ARC-JOURNAL, ARC-MANIFEST, ARC-PACKAGE, ARC-RECOVERY, ARC-REF

## Implementation scope

Load and verify an existing bundle without rediscovering fixtures or invoking random generation.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Replay ignores changed source fixture files and uses only verified bundle blobs.
- `webhook-conformance replay --help` exits 0 and the command contract test demonstrates its stated job.
- The loader rejects a manifest whose canonical content no longer matches manifest_id.
- No receiver connection occurs after bundle verification failure.
- Unknown major produces unsupported with no fixture file reads beyond manifest verification.
- A normalized cross-version digest matches the golden digest.

## Commands to run

```bash
uv run pytest -q tests/unit/manifest/test_loader.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/manifest/loader.py
- tests/unit/manifest/test_loader.py

## Completion evidence

- Passing evidence for VT-CLI-006
- Passing evidence for VT-COMPAT-007
- Passing evidence for VT-DATA-004
- Passing evidence for VT-FR-012
- Passing evidence for VT-REL-014
- Passing evidence for VT-TEST-014

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
