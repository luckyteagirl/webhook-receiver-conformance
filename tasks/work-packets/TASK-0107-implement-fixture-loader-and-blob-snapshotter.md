# TASK-0107 — Implement fixture loader and blob snapshotter

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0101, TASK-0104 |
| Blocks | TASK-0109, TASK-0401, TASK-0404 |
| Parallel group | PG-01C |
| Requirements | DATA-003, HTTP-016, SEC-015, SEC-017, SEC-018, SEC-025 |
| Tests | VT-DATA-003, VT-HTTP-016, VT-SEC-015, VT-SEC-017, VT-SEC-018, VT-SEC-025 |
| ADRs | ADR-004, ADR-007 |

## Objective

Load exact fixture bytes, enforce size limits, hash content, and snapshot blobs into a run bundle.

## Rationale

Implements DATA-003, HTTP-016, SEC-015, SEC-017, SEC-018, SEC-025 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/fixtures/loader.py
- src/webhook_receiver_conformance/fixtures/blobs.py

**Allowed files**

- src/webhook_receiver_conformance/fixtures/loader.py
- src/webhook_receiver_conformance/fixtures/blobs.py
- tests/unit/fixtures/**

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

- **Owned:** ARC-FIXTURE, ARC-OBS-CMD, ARC-OBS-HTTP
- **Consumed:** ARC-FIXTURE, ARC-HTTP, ARC-MANIFEST, ARC-SECRET, ARC-TARGET

## Implementation scope

Load exact fixture bytes, enforce size limits, hash content, and snapshot blobs into a run bundle.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Constrain paths to the project root, reject symlink escapes, and do not decode arbitrary bytes unless an operation requires it.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Changing one byte changes the blob digest and causes bundle verification to fail until re-planned.
- A 1 MiB body passes and a body one byte larger fails under default configuration.
- POSIX tests observe mode 0600 for files and 0700 for run directories subject to umask tightening.
- A race-resistant symlink test cannot read or overwrite an external canary file.
- Archive extensions are treated as raw fixtures and no extraction library is invoked.
- Each input class has a boundary test and a classified resource_limit diagnostic.

## Commands to run

```bash
uv run pytest -q tests/unit/fixtures/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/fixtures/loader.py
- src/webhook_receiver_conformance/fixtures/blobs.py
- tests/unit/fixtures/**

## Completion evidence

- Passing evidence for VT-DATA-003
- Passing evidence for VT-HTTP-016
- Passing evidence for VT-SEC-015
- Passing evidence for VT-SEC-017
- Passing evidence for VT-SEC-018
- Passing evidence for VT-SEC-025

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
