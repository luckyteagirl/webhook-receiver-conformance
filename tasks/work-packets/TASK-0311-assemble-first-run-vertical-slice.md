# TASK-0311 — Assemble first run vertical slice

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0110, TASK-0204, TASK-0205, TASK-0302, TASK-0309, TASK-0310 |
| Blocks | TASK-0801 |
| Parallel group | None |
| Requirements | CLI-004, DATA-001, FR-001, PRIV-010 |
| Tests | VT-CLI-004, VT-DATA-001, VT-FR-001, VT-PRIV-010 |
| ADRs | ADR-001, ADR-004, ADR-007 |

## Objective

Compile one fixture, send one attempt to a local receiver, journal evidence, and emit a structured summary.

## Rationale

Implements CLI-004, DATA-001, FR-001, PRIV-010 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/runtime/runner.py
- src/webhook_receiver_conformance/cli/run.py

**Allowed files**

- src/webhook_receiver_conformance/runtime/runner.py
- src/webhook_receiver_conformance/cli/run.py
- tests/e2e/test_vertical_slice.py

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

- **Owned:** ARC-CLI
- **Consumed:** ARC-CLI, ARC-COMPILER, ARC-JOURNAL, ARC-REPORT-HTML, ARC-SECRET

## Implementation scope

Compile one fixture, send one attempt to a local receiver, journal evidence, and emit a structured summary.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- An end-to-end reference run succeeds with outbound networking blocked except for the configured local receiver.
- `webhook-conformance run --help` exits 0 and the command contract test demonstrates its stated job.
- Two executions of one bundle create distinct run directories and never share a database file.
- A complete run performs no upload and no automatic retention deletion.

## Commands to run

```bash
uv run pytest -q tests/e2e/test_vertical_slice.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/runtime/runner.py
- src/webhook_receiver_conformance/cli/run.py
- tests/e2e/test_vertical_slice.py

## Completion evidence

- Passing evidence for VT-CLI-004
- Passing evidence for VT-DATA-001
- Passing evidence for VT-FR-001
- Passing evidence for VT-PRIV-010

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
