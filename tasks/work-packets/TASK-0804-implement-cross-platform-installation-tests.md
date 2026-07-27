# TASK-0804 — Implement cross-platform installation tests

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | medium |
| Dependencies | TASK-0801 |
| Blocks | TASK-0808 |
| Parallel group | PG-08A |
| Requirements | COMPAT-001, COMPAT-003, COMPAT-004, COMPAT-008, OPS-003, OPS-004, TEST-010, TEST-014, TEST-016 |
| Tests | VT-COMPAT-001, VT-COMPAT-003, VT-COMPAT-004, VT-COMPAT-008, VT-OPS-003, VT-OPS-004, VT-TEST-010, VT-TEST-014, VT-TEST-016 |
| ADRs | ADR-001, ADR-002, ADR-017, ADR-022 |

## Objective

Build and install wheel/sdist through pipx and uvx on Linux, macOS, and Windows.

## Rationale

Implements COMPAT-001, COMPAT-003, COMPAT-004, COMPAT-008, OPS-003, OPS-004, TEST-010, TEST-014 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- .github/workflows/package-test.yml
- scripts/package_smoke.py

**Allowed files**

- .github/workflows/package-test.yml
- tests/packaging/**
- scripts/package_smoke.py

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

- **Owned:** ARC-PACKAGE
- **Consumed:** ARC-ACTION, ARC-PACKAGE, ARC-REF

## Implementation scope

Build and install wheel/sdist through pipx and uvx on Linux, macOS, and Windows.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- CI and package-smoke tests pass on all three versions.
- Locked end-to-end smoke tests pass on all three operating systems.
- An injected older version produces unsupported before database creation.
- Windows and POSIX generate the same manifest path strings for the same project tree.
- Both artifacts install into clean environments and run version plus the minimal example.
- Package smoke tests exercise both paths where the tool is available.
- No supported-platform job is allowed to be continue-on-error.
- A normalized cross-version digest matches the golden digest.
- Release validation records the command and artifact digest for every distribution surface.

## Commands to run

```bash
uv run pytest -q tests/packaging/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- .github/workflows/package-test.yml
- tests/packaging/**
- scripts/package_smoke.py

## Completion evidence

- Passing evidence for VT-COMPAT-001
- Passing evidence for VT-COMPAT-003
- Passing evidence for VT-COMPAT-004
- Passing evidence for VT-COMPAT-008
- Passing evidence for VT-OPS-003
- Passing evidence for VT-OPS-004
- Passing evidence for VT-TEST-010
- Passing evidence for VT-TEST-014
- Passing evidence for VT-TEST-016

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
