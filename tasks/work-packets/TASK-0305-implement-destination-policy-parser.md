# TASK-0305 — Implement destination-policy parser

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0104 |
| Blocks | TASK-0306, TASK-0307 |
| Parallel group | PG-03A |
| Requirements | HTTP-002, SEC-001, SEC-002, SEC-003, SEC-005 |
| Tests | VT-HTTP-002, VT-SEC-001, VT-SEC-002, VT-SEC-003, VT-SEC-005 |
| ADRs | ADR-014 |

## Objective

Validate schemes, ports, host allowlists, IP classes, public authorization, and test-target preflight configuration.

## Rationale

Implements HTTP-002, SEC-001, SEC-002, SEC-003, SEC-005 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/network/policy.py
- src/webhook_receiver_conformance/network/addresses.py

**Allowed files**

- src/webhook_receiver_conformance/network/policy.py
- src/webhook_receiver_conformance/network/addresses.py
- tests/unit/network/test_policy.py

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
- **Consumed:** ARC-SECRET, ARC-TARGET

## Implementation scope

Validate schemes, ports, host allowlists, IP classes, public authorization, and test-target preflight configuration.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Block unspecified, multicast, link-local, and metadata targets; reject userinfo and fragments.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- ftp, embedded credentials, and fragment-bearing URLs fail validation.
- 127.0.0.1 and ::1 pass while RFC1918 and public addresses fail by default.
- An unlisted private address fails even though its address class is otherwise private.
- Omitting any one gate prevents DNS resolution and delivery.
- A table-driven IPv4/IPv6 corpus rejects all special blocked ranges with no override path.

## Commands to run

```bash
uv run pytest -q tests/unit/network/test_policy.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/network/policy.py
- src/webhook_receiver_conformance/network/addresses.py
- tests/unit/network/test_policy.py

## Completion evidence

- Passing evidence for VT-HTTP-002
- Passing evidence for VT-SEC-001
- Passing evidence for VT-SEC-002
- Passing evidence for VT-SEC-003
- Passing evidence for VT-SEC-005

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
