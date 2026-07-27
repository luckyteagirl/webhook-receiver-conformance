# TASK-0001 — Create package and quality-tool foundation

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-00-foundation |
| Priority | P0 |
| Complexity | medium |
| Dependencies | None |
| Blocks | TASK-0002, TASK-0003, TASK-0004 |
| Parallel group | None |
| Requirements | API-003, COMPAT-002, OPS-001, SEC-027 |
| Tests | VT-API-003, VT-COMPAT-002, VT-OPS-001, VT-SEC-027 |
| ADRs | ADR-002, ADR-013, ADR-017 |

## Objective

Create the PEP 621 package skeleton, uv lockfile, strict lint/type/test configuration, and source layout.

## Rationale

Implements API-003, COMPAT-002, OPS-001, SEC-027 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- pyproject.toml
- uv.lock
- src/webhook_receiver_conformance/**
- .python-version

**Allowed files**

- pyproject.toml
- uv.lock
- src/webhook_receiver_conformance/**
- tests/conftest.py
- .python-version

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

- **Owned:** ARC-LOCK
- **Consumed:** ARC-ACTION, ARC-COMPILER, ARC-PACKAGE, ARC-SECRET, ARC-TARGET

## Implementation scope

Create the PEP 621 package skeleton, uv lockfile, strict lint/type/test configuration, and source layout.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- No entry-point group is loaded by the v0.1 runtime.
- Installed packages cannot alter runtime behavior through plugin entry points.
- Package metadata and documentation do not claim PyPy or free-threaded support.
- A build metadata inspection finds no setup.py metadata source.

## Commands to run

```bash
uv run pytest -q tests/conftest.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- pyproject.toml
- uv.lock
- src/webhook_receiver_conformance/**
- tests/conftest.py
- .python-version

## Completion evidence

- Passing evidence for VT-API-003
- Passing evidence for VT-COMPAT-002
- Passing evidence for VT-OPS-001
- Passing evidence for VT-SEC-027

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
