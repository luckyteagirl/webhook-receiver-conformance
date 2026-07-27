# TASK-0002 — Define error taxonomy and common primitives

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-00-foundation |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0001 |
| Blocks | TASK-0101, TASK-0102, TASK-0103 |
| Parallel group | PG-00A |
| Requirements | API-001, API-002, CLI-014, DX-002, DX-003, OPS-010, PRIV-012 |
| Tests | VT-API-001, VT-API-002, VT-CLI-014, VT-DX-002, VT-DX-003, VT-OPS-010, VT-PRIV-012 |
| ADRs | ADR-013, ADR-019 |

## Objective

Implement stable error categories, result status enums, common type aliases, and version metadata.

## Rationale

Implements API-001, API-002, CLI-014, DX-002, DX-003, OPS-010, PRIV-012 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/errors.py
- src/webhook_receiver_conformance/types.py
- src/webhook_receiver_conformance/version.py

**Allowed files**

- src/webhook_receiver_conformance/errors.py
- src/webhook_receiver_conformance/types.py
- src/webhook_receiver_conformance/version.py
- tests/unit/test_errors.py

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
- **Consumed:** ARC-ACTION, ARC-CLI, ARC-COMPILER, ARC-PACKAGE, ARC-REPORT-HTML, ARC-SECRET

## Implementation scope

Implement stable error categories, result status enums, common type aliases, and version metadata.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A forced internal error prints an incident ID by default and a traceback only with --debug or the documented environment variable.
- Static type checking reports no untyped public service method and contract tests cover serialization boundaries.
- Fault injection in each major component produces a documented error category at the runner boundary.
- Forced crashes contain only IDs, hashes, safe exception type, and incident code.
- Snapshot tests cover representative config, target, observer, assertion, and recovery diagnostics.
- CLI snapshots contain concise diagnostics only.
- Version command prints each version and compatibility documentation maps them.

## Commands to run

```bash
uv run pytest -q tests/unit/test_errors.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/errors.py
- src/webhook_receiver_conformance/types.py
- src/webhook_receiver_conformance/version.py
- tests/unit/test_errors.py

## Completion evidence

- Passing evidence for VT-API-001
- Passing evidence for VT-API-002
- Passing evidence for VT-CLI-014
- Passing evidence for VT-DX-002
- Passing evidence for VT-DX-003
- Passing evidence for VT-OPS-010
- Passing evidence for VT-PRIV-012

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
