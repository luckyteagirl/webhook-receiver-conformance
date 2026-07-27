# TASK-0711 — Implement reference scenario corpus

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-07-reference-receivers |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0702, TASK-0703, TASK-0704, TASK-0705, TASK-0706, TASK-0707, TASK-0708, TASK-0709, TASK-0710, TASK-0605 |
| Blocks | TASK-0807, TASK-0809 |
| Parallel group | None |
| Requirements | FR-001, FR-003, FR-004, TEST-011, TEST-012, TEST-013, TEST-019 |
| Tests | VT-FR-001, VT-FR-003, VT-FR-004, VT-TEST-011, VT-TEST-012, VT-TEST-013, VT-TEST-019 |
| ADRs | ADR-001, ADR-008 |

## Objective

Run the correct receiver and every flawed receiver against the mapped scenario corpus and verify exact expected outcomes.

## Rationale

Implements FR-001, FR-003, FR-004, TEST-011, TEST-012, TEST-013, TEST-019 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- examples/scenarios/**

**Allowed files**

- examples/scenarios/**
- tests/e2e/test_reference_corpus.py
- tests/golden/reference-corpus/**

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

- **Owned:** ARC-REF
- **Consumed:** ARC-CLI, ARC-COMPILER, ARC-REF

## Implementation scope

Run the correct receiver and every flawed receiver against the mapped scenario corpus and verify exact expected outcomes.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- An end-to-end reference run succeeds with outbound networking blocked except for the configured local receiver.
- The complete P0 corpus produces a pass verdict and exit code 0 against REF-CORRECT-001.
- The reference-corpus matrix matches every expected pass and failure with no unexplained failure.
- The e2e job can reach only loopback or its isolated container network.
- The corpus matrix has no unexpected fail, error, unsupported, or ambiguous result.
- Every flawed receiver row in the corpus matrix has one primary violated requirement set.
- Leak checks find no child process or listening socket after the suite.

## Commands to run

```bash
uv run pytest -q tests/e2e/test_reference_corpus.py tests/golden/reference-corpus/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- examples/scenarios/**
- tests/e2e/test_reference_corpus.py
- tests/golden/reference-corpus/**

## Completion evidence

- Passing evidence for VT-FR-001
- Passing evidence for VT-FR-003
- Passing evidence for VT-FR-004
- Passing evidence for VT-TEST-011
- Passing evidence for VT-TEST-012
- Passing evidence for VT-TEST-013
- Passing evidence for VT-TEST-019

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
