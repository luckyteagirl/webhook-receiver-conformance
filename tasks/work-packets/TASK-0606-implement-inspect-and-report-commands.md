# TASK-0606 — Implement inspect and report commands

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-06-reporting |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0605 |
| Blocks | TASK-0801 |
| Parallel group | None |
| Requirements | CLI-007, CLI-008, DX-005, FR-007, PRIV-008, REPORT-008 |
| Tests | VT-CLI-007, VT-CLI-008, VT-DX-005, VT-FR-007, VT-PRIV-008, VT-REPORT-008 |
| ADRs | ADR-001 |

## Objective

Expose causal inspection and offline report regeneration without contacting a receiver.

## Rationale

Implements CLI-007, CLI-008, DX-005, FR-007, PRIV-008, REPORT-008 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/cli/inspect.py
- src/webhook_receiver_conformance/cli/report.py

**Allowed files**

- src/webhook_receiver_conformance/cli/inspect.py
- src/webhook_receiver_conformance/cli/report.py
- tests/cli/test_inspect_report.py

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

- **Owned:** ARC-CLI, ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML
- **Consumed:** ARC-CLI, ARC-JOURNAL, ARC-REPORT-HTML, ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-SECRET

## Implementation scope

Expose causal inspection and offline report regeneration without contacting a receiver.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The inspect command traverses all required identifiers from a failed assertion without heuristic matching.
- `webhook-conformance inspect --help` exits 0 and the command contract test demonstrates its stated job.
- `webhook-conformance report --help` exits 0 and the command contract test demonstrates its stated job.
- A signature rejection links mutation, delivery, attempt response, and no-processing observation.
- Inspect requires an explicit raw-artifact option and a TTY warning for blob paths.
- Every identifier type returns the linked causal chain in human and JSON modes.

## Commands to run

```bash
uv run pytest -q tests/cli/test_inspect_report.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/cli/inspect.py
- src/webhook_receiver_conformance/cli/report.py
- tests/cli/test_inspect_report.py

## Completion evidence

- Passing evidence for VT-CLI-007
- Passing evidence for VT-CLI-008
- Passing evidence for VT-DX-005
- Passing evidence for VT-FR-007
- Passing evidence for VT-PRIV-008
- Passing evidence for VT-REPORT-008

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
