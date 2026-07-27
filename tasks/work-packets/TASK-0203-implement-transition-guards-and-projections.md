# TASK-0203 — Implement transition guards and projections

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-02-journal-and-state |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0202 |
| Blocks | TASK-0206, TASK-0302, TASK-0309, TASK-0504, TASK-0508 |
| Parallel group | None |
| Requirements | DATA-009, DATA-010, DATA-011, DATA-014, REL-008, STATE-001, STATE-002, STATE-003, STATE-004, STATE-005, STATE-006, STATE-007, STATE-008, STATE-009, STATE-010, STATE-011, STATE-012, STATE-013, STATE-014, TEST-003, TEST-004 |
| Tests | VT-DATA-009, VT-DATA-010, VT-DATA-011, VT-DATA-014, VT-REL-008, VT-STATE-001, VT-STATE-002, VT-STATE-003, VT-STATE-004, VT-STATE-005, VT-STATE-006, VT-STATE-007, VT-STATE-008, VT-STATE-009, VT-STATE-010, VT-STATE-011, VT-STATE-012, VT-STATE-013, VT-STATE-014, VT-TEST-003, VT-TEST-004 |
| ADRs | ADR-003, ADR-009 |

## Objective

Append transitions and update current-state projections atomically while rejecting illegal state changes.

## Rationale

Implements DATA-009, DATA-010, DATA-011, DATA-014, REL-008, STATE-001, STATE-002, STATE-003 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/journal/transitions.py
- src/webhook_receiver_conformance/journal/repositories.py

**Allowed files**

- src/webhook_receiver_conformance/journal/transitions.py
- src/webhook_receiver_conformance/journal/repositories.py
- tests/unit/journal/test_transitions.py

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

- **Owned:** ARC-JOURNAL
- **Consumed:** ARC-JOURNAL, ARC-RECOVERY, ARC-REF

## Implementation scope

Append transitions and update current-state projections atomically while rejecting illegal state changes.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Direct insertion of an invalid state or duplicate scoped identifier fails at the database boundary.
- A completed attempt has an ordered transition history that can reconstruct its current state.
- Crash injection cannot produce a transition without its projection or a projection without its transition.
- A SQL trace test finds no implicit write transaction in the journal repository.
- The run-state transition table rejects every undeclared state value.
- Scenario projection tests cover every legal and illegal transition.
- The delivery state machine cannot become satisfied without a qualifying terminal attempt or explicit assertion policy.
- The attempt-state model and SQL checks contain the same state set.
- Observer lifecycle tests cover every terminal classification.
- Assertion lifecycle tests cover every terminal classification.
- Property tests generate state pairs and confirm only declared edges commit.
- A retry transition points to the predecessor attempt outcome that made it eligible.
- Live transitions contain both fields while imported historical records explicitly mark unavailable monotonic values.
- All terminal-to-nonterminal transition attempts fail atomically.
- Resume never changes an unknown attempt to succeeded or failed.
- Completion is rejected until every required delivery is terminal under policy.
- A rebuild test deletes projections, replays transitions into a temporary database, and obtains identical rows.
- A generated comparison test detects any diagram/table mismatch.
- Crash after outcome commit cannot omit or duplicate the derived retry schedule.
- Hypothesis profiles run deterministic CI settings and retain minimized reproducers as explicit bundles where relevant.
- Random action sequences preserve invariants and shrink to a replayable action list.

## Commands to run

```bash
uv run pytest -q tests/unit/journal/test_transitions.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/journal/transitions.py
- src/webhook_receiver_conformance/journal/repositories.py
- tests/unit/journal/test_transitions.py

## Completion evidence

- Passing evidence for VT-DATA-009
- Passing evidence for VT-DATA-010
- Passing evidence for VT-DATA-011
- Passing evidence for VT-DATA-014
- Passing evidence for VT-REL-008
- Passing evidence for VT-STATE-001
- Passing evidence for VT-STATE-002
- Passing evidence for VT-STATE-003
- Passing evidence for VT-STATE-004
- Passing evidence for VT-STATE-005
- Passing evidence for VT-STATE-006
- Passing evidence for VT-STATE-007
- Passing evidence for VT-STATE-008
- Passing evidence for VT-STATE-009
- Passing evidence for VT-STATE-010
- Passing evidence for VT-STATE-011
- Passing evidence for VT-STATE-012
- Passing evidence for VT-STATE-013
- Passing evidence for VT-STATE-014
- Passing evidence for VT-TEST-003
- Passing evidence for VT-TEST-004

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
