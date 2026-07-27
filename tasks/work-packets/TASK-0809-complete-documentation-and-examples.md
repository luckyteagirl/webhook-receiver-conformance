# TASK-0809 — Complete documentation and examples

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | large |
| Dependencies | TASK-0711, TASK-0801 |
| Blocks | TASK-0810 |
| Parallel group | PG-08C |
| Requirements | COMPAT-002, COMPAT-005, COMPAT-006, DX-001, DX-006, DX-007, DX-010, FR-005, OPS-004, OPS-009, OPS-010, PERF-009, REPORT-023, SEC-035 |
| Tests | VT-COMPAT-002, VT-COMPAT-005, VT-COMPAT-006, VT-DX-001, VT-DX-006, VT-DX-007, VT-DX-010, VT-FR-005, VT-OPS-004, VT-OPS-009, VT-OPS-010, VT-PERF-009, VT-REPORT-023, VT-SEC-035 |
| ADRs | ADR-017, ADR-018 |

## Objective

Document the five-minute path, concepts, schemas, observer integration, failure diagnosis, and extension boundaries.

## Rationale

Implements COMPAT-002, COMPAT-005, COMPAT-006, DX-001, DX-006, DX-007, DX-010, FR-005 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- README.md
- examples/**

**Allowed files**

- README.md
- docs/**
- examples/**

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
- **Consumed:** ARC-ACTION, ARC-CLI, ARC-COMPILER, ARC-HTTP, ARC-PACKAGE, ARC-REPORT-HTML, ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-SCHED, ARC-SECRET, ARC-TARGET

## Implementation scope

Document the five-minute path, concepts, schemas, observer integration, failure diagnosis, and extension boundaries.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A repository-wide terminology test finds no prohibited exactly-once delivery claim outside explanatory rejection text.
- No SARIF reporter is registered and documentation explains JUnit/JSON selection.
- The threat model labels unmapped requirements rather than forcing an identifier.
- Documentation contains no RPS capacity claim for receivers.
- Package metadata and documentation do not claim PyPy or free-threaded support.
- Documentation and diagnostics state the boundary and its data-integrity rationale.
- A compatibility matrix defines reader behavior for same-major additions and unknown major versions.
- A scripted documentation test follows only published commands and completes under five minutes on the reference runner.
- Schema validation runs on both examples in CI.
- Both examples pass the same observer test kit.
- README and AGENTS.md define precedence and link every normative source artifact.
- Package smoke tests exercise both paths where the tool is available.
- Release policy defines breaking changes for CLI, config, manifest, observer protocol, and Python API.
- Version command prints each version and compatibility documentation maps them.

## Commands to run

```bash
uv run pytest -q tests
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- README.md
- docs/**
- examples/**

## Completion evidence

- Passing evidence for VT-COMPAT-002
- Passing evidence for VT-COMPAT-005
- Passing evidence for VT-COMPAT-006
- Passing evidence for VT-DX-001
- Passing evidence for VT-DX-006
- Passing evidence for VT-DX-007
- Passing evidence for VT-DX-010
- Passing evidence for VT-FR-005
- Passing evidence for VT-OPS-004
- Passing evidence for VT-OPS-009
- Passing evidence for VT-OPS-010
- Passing evidence for VT-PERF-009
- Passing evidence for VT-REPORT-023
- Passing evidence for VT-SEC-035

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
