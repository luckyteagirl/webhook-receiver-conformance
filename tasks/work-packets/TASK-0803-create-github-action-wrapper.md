# TASK-0803 — Create GitHub Action wrapper

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | medium |
| Dependencies | TASK-0801 |
| Blocks | TASK-0810 |
| Parallel group | PG-08A |
| Requirements | OPS-005, OPS-007, OPS-008, PRIV-010, PRIV-011, SEC-028, SEC-029, TEST-016 |
| Tests | VT-OPS-005, VT-OPS-007, VT-OPS-008, VT-PRIV-010, VT-PRIV-011, VT-SEC-028, VT-SEC-029, VT-TEST-016 |
| ADRs | ADR-017, ADR-022 |

## Objective

Expose locked inputs, stable outputs, exit behavior, and artifact paths through a composite or container action.

## Rationale

Implements OPS-005, OPS-007, OPS-008, PRIV-010, PRIV-011, SEC-028, SEC-029, TEST-016 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- action.yml
- .github/actions/**

**Allowed files**

- action.yml
- .github/actions/**
- tests/packaging/test_action.py

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

- **Owned:** ARC-ACTION
- **Consumed:** ARC-ACTION, ARC-PACKAGE, ARC-REF, ARC-REPORT-HTML, ARC-SECRET, ARC-TARGET

## Implementation scope

Expose locked inputs, stable outputs, exit behavior, and artifact paths through a composite or container action.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Use least-privilege default permissions and do not upload raw fixture bodies unless explicitly configured.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The action documentation and example workflow use contents: read and omit write scopes.
- Default action artifacts contain redacted reports and no blobs directory.
- A complete run performs no upload and no automatic retention deletion.
- The action summary names sensitive artifact classes before upload.
- Container inspection and runtime id show a nonzero UID.
- action.yml input definitions match action contract tests and documentation.
- A workflow integration test consumes every output.
- Release validation records the command and artifact digest for every distribution surface.

## Commands to run

```bash
uv run pytest -q tests/packaging/test_action.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- action.yml
- .github/actions/**
- tests/packaging/test_action.py

## Completion evidence

- Passing evidence for VT-OPS-005
- Passing evidence for VT-OPS-007
- Passing evidence for VT-OPS-008
- Passing evidence for VT-PRIV-010
- Passing evidence for VT-PRIV-011
- Passing evidence for VT-SEC-028
- Passing evidence for VT-SEC-029
- Passing evidence for VT-TEST-016

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
