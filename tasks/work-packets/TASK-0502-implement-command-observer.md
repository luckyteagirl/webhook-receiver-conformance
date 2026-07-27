# TASK-0502 — Implement command observer

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-05-observers-and-assertions |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0501 |
| Blocks | TASK-0504 |
| Parallel group | PG-05B |
| Requirements | DX-007, OBS-001, OBS-002, OBS-003, OBS-004, OBS-005, OBS-006, OBS-007, OBS-008, OBS-019, SEC-017, SEC-019, SEC-020, SEC-021, SEC-025 |
| Tests | VT-DX-007, VT-OBS-001, VT-OBS-002, VT-OBS-003, VT-OBS-004, VT-OBS-005, VT-OBS-006, VT-OBS-007, VT-OBS-008, VT-OBS-019, VT-SEC-017, VT-SEC-019, VT-SEC-020, VT-SEC-021, VT-SEC-025 |
| ADRs | ADR-010 |

## Objective

Invoke a read-only observer by argv with bounded JSON stdin/stdout/stderr and no shell interpolation.

## Rationale

Implements DX-007, OBS-001, OBS-002, OBS-003, OBS-004, OBS-005, OBS-006, OBS-007 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/observers/command.py

**Allowed files**

- src/webhook_receiver_conformance/observers/command.py
- tests/unit/observers/test_command.py

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

- **Owned:** ARC-OBS-CMD, ARC-OBS-HTTP
- **Consumed:** ARC-CLI, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-SECRET, ARC-TARGET

## Implementation scope

Invoke a read-only observer by argv with bounded JSON stdin/stdout/stderr and no shell interpolation.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Use shell=False, an environment allowlist, bounded output, a controlled working directory, and a hard timeout.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The harness rejects an observer that does not return protocol version and supported evidence types.
- Metacharacters in an argument reach the child literally and do not invoke another process.
- The child receives exactly one newline-terminated JSON object matching observer-request.schema.json.
- Leading prose, a second JSON object, or invalid UTF-8 produces observer error.
- A child exceeding either cap is terminated and classified observer_output_limit.
- An unrelated parent secret environment variable is absent in the child.
- A traversal or symlink escape working directory fails validation.
- A hanging observer is terminated and persisted as timed_out.
- Sensitive evidence and child stderr values are absent from every default artifact.
- A race-resistant symlink test cannot read or overwrite an external canary file.
- Static analysis and tests find no shell=True or command-string execution path.
- PATH search is disabled unless a specific allowlisted executable name policy is configured.
- Hanging and output-flooding children are terminated and classified.
- Each input class has a boundary test and a classified resource_limit diagnostic.
- Both examples pass the same observer test kit.

## Commands to run

```bash
uv run pytest -q tests/unit/observers/test_command.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/observers/command.py
- tests/unit/observers/test_command.py

## Completion evidence

- Passing evidence for VT-DX-007
- Passing evidence for VT-OBS-001
- Passing evidence for VT-OBS-002
- Passing evidence for VT-OBS-003
- Passing evidence for VT-OBS-004
- Passing evidence for VT-OBS-005
- Passing evidence for VT-OBS-006
- Passing evidence for VT-OBS-007
- Passing evidence for VT-OBS-008
- Passing evidence for VT-OBS-019
- Passing evidence for VT-SEC-017
- Passing evidence for VT-SEC-019
- Passing evidence for VT-SEC-020
- Passing evidence for VT-SEC-021
- Passing evidence for VT-SEC-025

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
