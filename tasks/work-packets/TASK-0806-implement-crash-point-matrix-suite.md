# TASK-0806 — Implement crash-point matrix suite

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | large |
| Dependencies | TASK-0207, TASK-0309, TASK-0504, TASK-0605 |
| Blocks | TASK-0810 |
| Parallel group | PG-08B |
| Requirements | DATA-011, DATA-020, HTTP-021, PRIV-012, REL-001, REL-002, REL-008, REL-010, REL-011, REL-015, REL-016, STATE-013, TEST-006 |
| Tests | VT-DATA-011, VT-DATA-020, VT-HTTP-021, VT-PRIV-012, VT-REL-001, VT-REL-002, VT-REL-008, VT-REL-010, VT-REL-011, VT-REL-015, VT-REL-016, VT-STATE-013, VT-TEST-006 |
| ADRs | ADR-004, ADR-007, ADR-009 |

## Objective

Inject process termination at every documented persistence/network/observer/report boundary and verify resume evidence.

## Rationale

Implements DATA-011, DATA-020, HTTP-021, PRIV-012, REL-001, REL-002, REL-008, REL-010 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- scripts/crash_harness.py

**Allowed files**

- tests/crash/**
- scripts/crash_harness.py

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
- **Consumed:** ARC-HTTP, ARC-JOURNAL, ARC-RECOVERY, ARC-REF, ARC-REPORT-HTML, ARC-SECRET, ARC-TARGET

## Implementation scope

Inject process termination at every documented persistence/network/observer/report boundary and verify resume evidence.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Crash injection cannot produce a transition without its projection or a projection without its transition.
- Report-generation termination leaves either the old valid artifact or the new valid artifact, never a partial target file.
- A rebuild test deletes projections, replays transitions into a temporary database, and obtains identical rows.
- Write/read timeout tests never claim the receiver did not process the request.
- Forced crashes contain only IDs, hashes, safe exception type, and incident code.
- Crash before connection leaves a durable attempt requiring recovery classification.
- Crash tests at each phase produce unknown_outcome unless durable evidence proves no connection was established.
- Crash after outcome commit cannot omit or duplicate the derived retry schedule.
- Resume or report regenerates artifacts from the journal without sending traffic.
- A cancelled run contains no fabricated terminal receiver result.
- Crash-point tests around every migration statement preserve a valid migration ledger.
- A generated matrix report has no uncovered P0 crash point.
- The generated crash coverage matrix reports 100 percent P0 boundary coverage.

## Commands to run

```bash
uv run pytest -q tests/crash/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- tests/crash/**
- scripts/crash_harness.py

## Completion evidence

- Passing evidence for VT-DATA-011
- Passing evidence for VT-DATA-020
- Passing evidence for VT-HTTP-021
- Passing evidence for VT-PRIV-012
- Passing evidence for VT-REL-001
- Passing evidence for VT-REL-002
- Passing evidence for VT-REL-008
- Passing evidence for VT-REL-010
- Passing evidence for VT-REL-011
- Passing evidence for VT-REL-015
- Passing evidence for VT-REL-016
- Passing evidence for VT-STATE-013
- Passing evidence for VT-TEST-006

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
