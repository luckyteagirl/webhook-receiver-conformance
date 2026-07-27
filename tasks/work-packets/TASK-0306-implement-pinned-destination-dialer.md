# TASK-0306 — Implement pinned destination dialer

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0305 |
| Blocks | TASK-0307, TASK-0308 |
| Parallel group | None |
| Requirements | HTTP-022, HTTP-023, OBS-011, SEC-006, SEC-007, SEC-008 |
| Tests | VT-HTTP-022, VT-HTTP-023, VT-OBS-011, VT-SEC-006, VT-SEC-007, VT-SEC-008 |
| ADRs | ADR-003 |

## Objective

Resolve, authorize, pin, and connect to a selected IPv4 or IPv6 address while preserving Host and TLS server-name semantics.

## Rationale

Implements HTTP-022, HTTP-023, OBS-011, SEC-006, SEC-007, SEC-008 at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/network/dialer.py
- src/webhook_receiver_conformance/network/transport.py

**Allowed files**

- src/webhook_receiver_conformance/network/dialer.py
- src/webhook_receiver_conformance/network/transport.py
- tests/unit/network/test_dialer.py

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
- **Consumed:** ARC-HTTP, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-SECRET, ARC-TARGET

## Implementation scope

Resolve, authorize, pin, and connect to a selected IPv4 or IPv6 address while preserving Host and TLS server-name semantics.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Prevent time-of-check/time-of-use DNS rebinding and validate the connected peer address.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- IPv4 and IPv6 tests show matching authorized and peer addresses.
- A DNS-rebinding test cannot redirect a request to a newly returned disallowed address.
- Observer URLs cannot bypass blocked address classes or redirects.
- A mixed safe/unsafe DNS answer fails rather than selecting only the safe address.
- A DNS answer changed after authorization cannot alter the connected peer.
- A transport returning a different peer aborts before body transmission.

## Commands to run

```bash
uv run pytest -q tests/unit/network/test_dialer.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/network/dialer.py
- src/webhook_receiver_conformance/network/transport.py
- tests/unit/network/test_dialer.py

## Completion evidence

- Passing evidence for VT-HTTP-022
- Passing evidence for VT-HTTP-023
- Passing evidence for VT-OBS-011
- Passing evidence for VT-SEC-006
- Passing evidence for VT-SEC-007
- Passing evidence for VT-SEC-008

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
