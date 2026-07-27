# TASK-0810 — Run final convergence and release-readiness gate

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | large |
| Dependencies | TASK-0803, TASK-0805, TASK-0806, TASK-0807, TASK-0808, TASK-0809 |
| Blocks | None |
| Parallel group | None |
| Requirements | API-005, ASSERT-017, COMPAT-009, MUT-020, MUT-021, MUT-022, OBS-021, OBS-022, OPS-014, SIG-017, TEST-001, TEST-009, TEST-019, TEST-020 |
| Tests | VT-API-005, VT-ASSERT-017, VT-COMPAT-009, VT-MUT-020, VT-MUT-021, VT-MUT-022, VT-OBS-021, VT-OBS-022, VT-OPS-014, VT-SIG-017, VT-TEST-001, VT-TEST-009, VT-TEST-019, VT-TEST-020 |
| ADRs | None |

## Objective

Run every locked verification command, resolve cross-artifact drift, and produce objective release evidence.

## Rationale

Implements API-005, ASSERT-017, COMPAT-009, MUT-020, MUT-021, MUT-022, OBS-021, OBS-022 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- CHANGELOG.md

**Allowed files**

- validation/**
- CHANGELOG.md

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
- **Consumed:** ARC-ACTION, ARC-ASSERT, ARC-COMPILER, ARC-MUT, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-PACKAGE, ARC-REF, ARC-SIGN

## Implementation scope

Run every locked verification command, resolve cross-artifact drift, and produce objective release evidence.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- plugin-metadata.schema.json contains an experimental stability enum and is unused by v0.1 runtime discovery.
- The v0.1 config schema rejects ed25519 while the roadmap names the enabling ADR and tests.
- The v0.1 schema rejects this operator with unsupported status.
- The v0.1 schema rejects this operator with unsupported status.
- The reduced bundle replays independently after the Hypothesis example database is deleted.
- No database driver other than SQLite journal support is a core dependency.
- The roadmap records adapter prerequisites without runtime placeholders.
- v0.1 supports composition of built-in typed predicates but no eval or code expression field.
- Default dependencies do not install h2 and reference tests use HTTP/1.1.
- The release workflow has explicit dependencies on every required job.
- Coverage inventory maps each listed component to one or more unit test modules.
- The release-readiness checklist defines the mutation score floor and surviving-mutant review.
- Leak checks find no child process or listening socket after the suite.
- task-index validation rejects a task with empty commands_to_run or completion_evidence.

## Commands to run

```bash
uv run pytest -q tests
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- validation/**
- CHANGELOG.md

## Completion evidence

- Passing evidence for VT-API-005
- Passing evidence for VT-ASSERT-017
- Passing evidence for VT-COMPAT-009
- Passing evidence for VT-MUT-020
- Passing evidence for VT-MUT-021
- Passing evidence for VT-MUT-022
- Passing evidence for VT-OBS-021
- Passing evidence for VT-OBS-022
- Passing evidence for VT-OPS-014
- Passing evidence for VT-SIG-017
- Passing evidence for VT-TEST-001
- Passing evidence for VT-TEST-009
- Passing evidence for VT-TEST-019
- Passing evidence for VT-TEST-020

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
