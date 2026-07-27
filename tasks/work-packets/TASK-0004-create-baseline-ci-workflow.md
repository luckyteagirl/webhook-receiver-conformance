# TASK-0004 — Create baseline CI workflow

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-00-foundation |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0001 |
| Blocks | None |
| Parallel group | PG-00A |
| Requirements | COMPAT-001, COMPAT-003, OPS-002, OPS-012, TEST-010, TEST-018 |
| Tests | VT-COMPAT-001, VT-COMPAT-003, VT-OPS-002, VT-OPS-012, VT-TEST-010, VT-TEST-018 |
| ADRs | ADR-001, ADR-002 |

## Objective

Run locked lint, type, unit, schema, and packaging checks on supported Python versions.

## Rationale

Implements COMPAT-001, COMPAT-003, OPS-002, OPS-012, TEST-010, TEST-018 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- .github/workflows/ci.yml
- .github/dependabot.yml

**Allowed files**

- .github/workflows/ci.yml
- .github/dependabot.yml

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

Run locked lint, type, unit, schema, and packaging checks on supported Python versions.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- CI and package-smoke tests pass on all three versions.
- Locked end-to-end smoke tests pass on all three operating systems.
- CI fails when pyproject dependencies and uv.lock diverge.
- Dependabot groups and CODEOWNERS/review guidance identify sensitive dependency classes.
- No supported-platform job is allowed to be continue-on-error.
- Core CI contains no automatic test retry plugin or retry loop.

## Commands to run

```bash
uv run pytest -q tests
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- .github/workflows/ci.yml
- .github/dependabot.yml

## Completion evidence

- Passing evidence for VT-COMPAT-001
- Passing evidence for VT-COMPAT-003
- Passing evidence for VT-OPS-002
- Passing evidence for VT-OPS-012
- Passing evidence for VT-TEST-010
- Passing evidence for VT-TEST-018

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
