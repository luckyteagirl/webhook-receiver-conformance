# TASK-0805 — Implement security regression suite

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | large |
| Dependencies | TASK-0307, TASK-0407, TASK-0503, TASK-0604 |
| Blocks | TASK-0810 |
| Parallel group | PG-08B |
| Requirements | SEC-001, SEC-002, SEC-003, SEC-004, SEC-005, SEC-006, SEC-007, SEC-008, SEC-009, SEC-010, SEC-011, SEC-012, SEC-013, SEC-015, SEC-016, SEC-017, SEC-019, SEC-020, SEC-021, SEC-022, SEC-023, SEC-024, SEC-025, SEC-026, SEC-027, SEC-028, SEC-029, TEST-003, TEST-007, TEST-008 |
| Tests | VT-SEC-001, VT-SEC-002, VT-SEC-003, VT-SEC-004, VT-SEC-005, VT-SEC-006, VT-SEC-007, VT-SEC-008, VT-SEC-009, VT-SEC-010, VT-SEC-011, VT-SEC-012, VT-SEC-013, VT-SEC-015, VT-SEC-016, VT-SEC-017, VT-SEC-019, VT-SEC-020, VT-SEC-021, VT-SEC-022, VT-SEC-023, VT-SEC-024, VT-SEC-025, VT-SEC-026, VT-SEC-027, VT-SEC-028, VT-SEC-029, VT-TEST-003, VT-TEST-007, VT-TEST-008 |
| ADRs | ADR-014, ADR-018 |

## Objective

Test SSRF controls, DNS pinning, path confinement, command invocation, redaction, terminal safety, HTML encoding, and resource caps.

## Rationale

Implements SEC-001, SEC-002, SEC-003, SEC-004, SEC-005, SEC-006, SEC-007, SEC-008 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- tests/security/**

**Allowed files**

- tests/security/**

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
- **Consumed:** ARC-REF, ARC-SECRET, ARC-TARGET

## Implementation scope

Test SSRF controls, DNS pinning, path confinement, command invocation, redaction, terminal safety, HTML encoding, and resource caps.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- 127.0.0.1 and ::1 pass while RFC1918 and public addresses fail by default.
- An unlisted private address fails even though its address class is otherwise private.
- Omitting any one gate prevents DNS resolution and delivery.
- A replayed, missing, wrong-host, or expired challenge fails closed.
- A table-driven IPv4/IPv6 corpus rejects all special blocked ranges with no override path.
- A mixed safe/unsafe DNS answer fails rather than selecting only the safe address.
- A DNS answer changed after authorization cannot alter the connected peer.
- A transport returning a different peer aborts before body transmission.
- 301 through 308 responses create no follow-up request.
- Proxy environment variables do not receive any test request.
- verify=false is absent from the configuration schema.
- Traversal, directory, device, and symlink-escape paths fail validation.
- Canary secrets are absent from a byte scan of the complete run directory.
- POSIX tests observe mode 0600 for files and 0700 for run directories subject to umask tightening.
- Absolute escape, .. traversal, alternate separators, and Windows drive/UNC escape cases are rejected.
- A race-resistant symlink test cannot read or overwrite an external canary file.
- Static analysis and tests find no shell=True or command-string execution path.
- PATH search is disabled unless a specific allowlisted executable name policy is configured.
- Hanging and output-flooding children are terminated and classified.
- Malicious fixture and observer strings cannot change terminal title, color, cursor, or hyperlinks.
- Newlines and control characters cannot create forged log records.
- Template tests fail if an evidence value is marked safe.
- Each input class has a boundary test and a classified resource_limit diagnostic.
- Task creation never exceeds the configured cap under duplicate and retry scenarios.
- Installed packages cannot alter runtime behavior through plugin entry points.
- The action documentation and example workflow use contents: read and omit write scopes.
- Default action artifacts contain redacted reports and no blobs directory.
- Hypothesis profiles run deterministic CI settings and retain minimized reproducers as explicit bundles where relevant.
- The threat-to-test matrix has no unmapped high-risk row.
- Fuzz targets enforce size/time limits and preserve no-crash/no-leak invariants.

## Commands to run

```bash
uv run pytest -q tests/security/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- tests/security/**

## Completion evidence

- Passing evidence for VT-SEC-001
- Passing evidence for VT-SEC-002
- Passing evidence for VT-SEC-003
- Passing evidence for VT-SEC-004
- Passing evidence for VT-SEC-005
- Passing evidence for VT-SEC-006
- Passing evidence for VT-SEC-007
- Passing evidence for VT-SEC-008
- Passing evidence for VT-SEC-009
- Passing evidence for VT-SEC-010
- Passing evidence for VT-SEC-011
- Passing evidence for VT-SEC-012
- Passing evidence for VT-SEC-013
- Passing evidence for VT-SEC-015
- Passing evidence for VT-SEC-016
- Passing evidence for VT-SEC-017
- Passing evidence for VT-SEC-019
- Passing evidence for VT-SEC-020
- Passing evidence for VT-SEC-021
- Passing evidence for VT-SEC-022
- Passing evidence for VT-SEC-023
- Passing evidence for VT-SEC-024
- Passing evidence for VT-SEC-025
- Passing evidence for VT-SEC-026
- Passing evidence for VT-SEC-027
- Passing evidence for VT-SEC-028
- Passing evidence for VT-SEC-029
- Passing evidence for VT-TEST-003
- Passing evidence for VT-TEST-007
- Passing evidence for VT-TEST-008

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
