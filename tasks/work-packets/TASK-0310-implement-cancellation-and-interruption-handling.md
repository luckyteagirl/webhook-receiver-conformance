# TASK-0310 — Implement cancellation and interruption handling

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0309 |
| Blocks | TASK-0311 |
| Parallel group | None |
| Requirements | CLI-015, HTTP-026, PERF-008, REL-011 |
| Tests | VT-CLI-015, VT-HTTP-026, VT-PERF-008, VT-REL-011 |
| ADRs | ADR-020 |

## Objective

Cancel task groups, close response streams, persist known transitions, and exit with the documented interrupted status.

## Rationale

Implements CLI-015, HTTP-026, PERF-008, REL-011 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/runtime/cancellation.py

**Allowed files**

- src/webhook_receiver_conformance/runtime/cancellation.py
- tests/integration/test_cancellation.py

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
- **Consumed:** ARC-CLI, ARC-HTTP, ARC-JOURNAL, ARC-RECOVERY, ARC-SCHED, ARC-TARGET

## Implementation scope

Cancel task groups, close response streams, persist known transitions, and exit with the documented interrupted status.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- SIGINT during an active attempt exits 130 and leaves a resumable journal.
- Resource-leak tests show no open pooled response after each terminal path.
- A cancelled run contains no fabricated terminal receiver result.
- The cancellation benchmark exits within budget with response streams closed.

## Commands to run

```bash
uv run pytest -q tests/integration/test_cancellation.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/runtime/cancellation.py
- tests/integration/test_cancellation.py

## Completion evidence

- Passing evidence for VT-CLI-015
- Passing evidence for VT-HTTP-026
- Passing evidence for VT-PERF-008
- Passing evidence for VT-REL-011

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
