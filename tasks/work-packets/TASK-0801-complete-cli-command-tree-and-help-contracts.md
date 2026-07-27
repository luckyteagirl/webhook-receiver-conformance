# TASK-0801 — Complete CLI command tree and help contracts

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | large |
| Dependencies | TASK-0311, TASK-0509, TASK-0606 |
| Blocks | TASK-0802, TASK-0803, TASK-0804, TASK-0809 |
| Parallel group | None |
| Requirements | CFG-006, CFG-012, CFG-014, CLI-001, CLI-002, CLI-003, CLI-004, CLI-005, CLI-006, CLI-007, CLI-008, CLI-009, CLI-010, CLI-011, CLI-012, CLI-013, CLI-014, CLI-015, CLI-016, CLI-017, DATA-021, DX-002, DX-003, DX-004, DX-009, PRIV-008, REL-004, REL-007, SEC-022 |
| Tests | VT-CFG-006, VT-CFG-012, VT-CFG-014, VT-CLI-001, VT-CLI-002, VT-CLI-003, VT-CLI-004, VT-CLI-005, VT-CLI-006, VT-CLI-007, VT-CLI-008, VT-CLI-009, VT-CLI-010, VT-CLI-011, VT-CLI-012, VT-CLI-013, VT-CLI-014, VT-CLI-015, VT-CLI-016, VT-CLI-017, VT-DATA-021, VT-DX-002, VT-DX-003, VT-DX-004, VT-DX-009, VT-PRIV-008, VT-REL-004, VT-REL-007, VT-SEC-022 |
| ADRs | ADR-004, ADR-008, ADR-016 |

## Objective

Implement init, validate, plan, run, resume, replay, inspect, report, and version with tested stdout/stderr behavior.

## Rationale

Implements CFG-006, CFG-012, CFG-014, CLI-001, CLI-002, CLI-003, CLI-004, CLI-005 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/cli/**

**Allowed files**

- src/webhook_receiver_conformance/cli/**
- tests/cli/**

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
- **Consumed:** ARC-CLI, ARC-CONFIG, ARC-JOURNAL, ARC-RECOVERY, ARC-REPORT-HTML, ARC-SECRET, ARC-TARGET

## Implementation scope

Implement init, validate, plan, run, resume, replay, inspect, report, and version with tested stdout/stderr behavior.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A CLI attempt to override an undeclared signer or target-policy field is rejected.
- The validate command succeeds with network syscalls denied and observer executables unavailable.
- schema_version 2 fails with exit code 6 and identifies the supported version range.
- `webhook-conformance init --help` exits 0 and the command contract test demonstrates its stated job.
- `webhook-conformance validate --help` exits 0 and the command contract test demonstrates its stated job.
- `webhook-conformance plan --help` exits 0 and the command contract test demonstrates its stated job.
- `webhook-conformance run --help` exits 0 and the command contract test demonstrates its stated job.
- `webhook-conformance resume --help` exits 0 and the command contract test demonstrates its stated job.
- `webhook-conformance replay --help` exits 0 and the command contract test demonstrates its stated job.
- `webhook-conformance inspect --help` exits 0 and the command contract test demonstrates its stated job.
- `webhook-conformance report --help` exits 0 and the command contract test demonstrates its stated job.
- `webhook-conformance version --help` exits 0 and the command contract test demonstrates its stated job.
- JSON mode emits one valid JSON document on stdout and sends progress and diagnostics to stderr.
- A failed validation leaves stdout empty in default mode and writes the diagnostic to stderr.
- CI mode fails closed when a confirmation would otherwise be required.
- Captured output and NO_COLOR output contain no ANSI escape sequences.
- A forced internal error prints an incident ID by default and a traceback only with --debug or the documented environment variable.
- SIGINT during an active attempt exits 130 and leaves a resumable journal.
- Each terminal result category maps to exactly one documented exit code across run, resume, and replay.
- A public target fails before preflight when the authorization argument is absent or does not match.
- A deletion test leaves external symlink targets unchanged.
- Malicious fixture and observer strings cannot change terminal title, color, cursor, or hyperlinks.
- Inspect requires an explicit raw-artifact option and a TTY warning for blob paths.
- resume without --on-ambiguous does not contact the receiver and exits 4.
- Config-only or CLI-only consent is insufficient.
- Snapshot tests cover representative config, target, observer, assertion, and recovery diagnostics.
- CLI snapshots contain concise diagnostics only.
- The preview is generated solely from the bundle and contains no secrets.
- run, resume, and replay print or record the destination; validate, plan, inspect, and report perform none.

## Commands to run

```bash
uv run pytest -q tests/cli/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/cli/**
- tests/cli/**

## Completion evidence

- Passing evidence for VT-CFG-006
- Passing evidence for VT-CFG-012
- Passing evidence for VT-CFG-014
- Passing evidence for VT-CLI-001
- Passing evidence for VT-CLI-002
- Passing evidence for VT-CLI-003
- Passing evidence for VT-CLI-004
- Passing evidence for VT-CLI-005
- Passing evidence for VT-CLI-006
- Passing evidence for VT-CLI-007
- Passing evidence for VT-CLI-008
- Passing evidence for VT-CLI-009
- Passing evidence for VT-CLI-010
- Passing evidence for VT-CLI-011
- Passing evidence for VT-CLI-012
- Passing evidence for VT-CLI-013
- Passing evidence for VT-CLI-014
- Passing evidence for VT-CLI-015
- Passing evidence for VT-CLI-016
- Passing evidence for VT-CLI-017
- Passing evidence for VT-DATA-021
- Passing evidence for VT-DX-002
- Passing evidence for VT-DX-003
- Passing evidence for VT-DX-004
- Passing evidence for VT-DX-009
- Passing evidence for VT-PRIV-008
- Passing evidence for VT-REL-004
- Passing evidence for VT-REL-007
- Passing evidence for VT-SEC-022

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
