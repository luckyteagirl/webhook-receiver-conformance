# TASK-0802 — Create non-root Docker distribution

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | medium |
| Dependencies | TASK-0801 |
| Blocks | TASK-0808 |
| Parallel group | PG-08A |
| Requirements | OPS-003, OPS-005, OPS-006, TEST-016 |
| Tests | VT-OPS-003, VT-OPS-005, VT-OPS-006, VT-TEST-016 |
| ADRs | ADR-017 |

## Objective

Build a minimal pinned image that runs without root and preserves local artifact ownership.

## Rationale

Implements OPS-003, OPS-005, OPS-006, TEST-016 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- Dockerfile
- .dockerignore

**Allowed files**

- Dockerfile
- .dockerignore
- tests/packaging/test_docker.py

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
- **Consumed:** ARC-ACTION, ARC-PACKAGE, ARC-REF

## Implementation scope

Build a minimal pinned image that runs without root and preserves local artifact ownership.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Use a non-root UID, a read-only base filesystem where practical, and no embedded credentials.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Both artifacts install into clean environments and run version plus the minimal example.
- Container inspection and runtime id show a nonzero UID.
- A read-only root filesystem run succeeds with writable mounts.
- Release validation records the command and artifact digest for every distribution surface.

## Commands to run

```bash
uv run pytest -q tests/packaging/test_docker.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- Dockerfile
- .dockerignore
- tests/packaging/test_docker.py

## Completion evidence

- Passing evidence for VT-OPS-003
- Passing evidence for VT-OPS-005
- Passing evidence for VT-OPS-006
- Passing evidence for VT-TEST-016

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
