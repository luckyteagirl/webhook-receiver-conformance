# TASK-0308 — Implement bounded HTTP attempt executor

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-03-scheduler-and-executor |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0306, TASK-0301 |
| Blocks | TASK-0309, TASK-0503 |
| Parallel group | None |
| Requirements | ASSERT-003, HTTP-001, HTTP-003, HTTP-004, HTTP-005, HTTP-006, HTTP-007, HTTP-008, HTTP-009, HTTP-010, HTTP-011, HTTP-012, HTTP-013, HTTP-014, HTTP-015, HTTP-016, HTTP-018, HTTP-019, HTTP-020, HTTP-022, HTTP-025, HTTP-026, PRIV-001, PRIV-002, PRIV-003, REL-003, SCHED-007, SCHED-016, SEC-009, SEC-010, SEC-011, SEC-012, SEC-025 |
| Tests | VT-ASSERT-003, VT-HTTP-001, VT-HTTP-003, VT-HTTP-004, VT-HTTP-005, VT-HTTP-006, VT-HTTP-007, VT-HTTP-008, VT-HTTP-009, VT-HTTP-010, VT-HTTP-011, VT-HTTP-012, VT-HTTP-013, VT-HTTP-014, VT-HTTP-015, VT-HTTP-016, VT-HTTP-018, VT-HTTP-019, VT-HTTP-020, VT-HTTP-022, VT-HTTP-025, VT-HTTP-026, VT-PRIV-001, VT-PRIV-002, VT-PRIV-003, VT-REL-003, VT-SCHED-007, VT-SCHED-016, VT-SEC-009, VT-SEC-010, VT-SEC-011, VT-SEC-012, VT-SEC-025 |
| ADRs | ADR-006, ADR-009, ADR-014, ADR-023 |

## Objective

Send exact request bytes with granular timeouts, explicit limits, no redirects, no proxy environment, and bounded response capture.

## Rationale

Implements ASSERT-003, HTTP-001, HTTP-003, HTTP-004, HTTP-005, HTTP-006, HTTP-007, HTTP-008 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/http/executor.py
- src/webhook_receiver_conformance/http/evidence.py

**Allowed files**

- src/webhook_receiver_conformance/http/executor.py
- src/webhook_receiver_conformance/http/evidence.py
- tests/unit/http/**

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

- **Owned:** ARC-HTTP, ARC-OBS-HTTP
- **Consumed:** ARC-ASSERT, ARC-CLOCK, ARC-HTTP, ARC-JOURNAL, ARC-RECOVERY, ARC-REPORT-HTML, ARC-SCHED, ARC-SECRET, ARC-TARGET

## Implementation scope

Send exact request bytes with granular timeouts, explicit limits, no redirects, no proxy environment, and bounded response capture.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Use TLS verification by default, reject forbidden framing headers, and cap request/response resources.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Changing the schedule scale does not change a configured 2-second HTTP timeout.
- HTTP transport retries are disabled and every second attempt has a journaled retry decision.
- Project configuration rejects other methods in v0.1.
- A capture receiver computes the same SHA-256 digest as the manifest blob reference.
- Mixed-case variants produce identical policy and assertion behavior.
- Evidence distinguishes user, signer, and HTTP-client-generated headers.
- Each forbidden header fails before manifest creation.
- The delivered body equals the fixture/mutation bytes and Content-Encoding is absent unless explicitly represented by a raw fixture case.
- Accept-Encoding is identity unless an explicit future-compatible option is enabled.
- A 302 response is recorded as the attempt response and no second destination is contacted.
- HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY, SSL_CERT_FILE, and .netrc do not alter a default run.
- A self-signed certificate fails unless an explicit test CA file is configured.
- Attempt evidence reports HTTP/1.1 in the reference corpus.
- Each timeout type has an isolated fault test and distinct error classification.
- A slow multi-phase response cannot exceed the total deadline by more than the documented cancellation tolerance.
- A refused connection produces one physical attempt and any later attempt is scheduler-created.
- A 1 MiB body passes and a body one byte larger fails under default configuration.
- A larger response stores the first 65536 bytes after redaction plus total byte count and truncation=true.
- An unbounded response stream is closed at the hard cap and classified without exhausting disk or memory.
- DNS failure and connection refusal yield not_sent with no unknown_outcome.
- IPv4 and IPv6 tests show matching authorized and peer addresses.
- Pool instrumentation never exceeds configured limits under concurrent duplicates.
- Resource-leak tests show no open pooled response after each terminal path.
- A delayed-body response with prompt headers passes while delayed headers fail.
- 301 through 308 responses create no follow-up request.
- Proxy environment variables do not receive any test request.
- verify=false is absent from the configuration schema.
- Traversal, directory, device, and symlink-escape paths fail validation.
- Each input class has a boundary test and a classified resource_limit diagnostic.
- A body canary is absent from text and structured logs.
- A response canary is absent from logs.
- Default evidence renders a stable redacted marker for each header.
- Resolver rejection and connection refusal are eligible for configured retry without ambiguity.

## Commands to run

```bash
uv run pytest -q tests/unit/http/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/http/executor.py
- src/webhook_receiver_conformance/http/evidence.py
- tests/unit/http/**

## Completion evidence

- Passing evidence for VT-ASSERT-003
- Passing evidence for VT-HTTP-001
- Passing evidence for VT-HTTP-003
- Passing evidence for VT-HTTP-004
- Passing evidence for VT-HTTP-005
- Passing evidence for VT-HTTP-006
- Passing evidence for VT-HTTP-007
- Passing evidence for VT-HTTP-008
- Passing evidence for VT-HTTP-009
- Passing evidence for VT-HTTP-010
- Passing evidence for VT-HTTP-011
- Passing evidence for VT-HTTP-012
- Passing evidence for VT-HTTP-013
- Passing evidence for VT-HTTP-014
- Passing evidence for VT-HTTP-015
- Passing evidence for VT-HTTP-016
- Passing evidence for VT-HTTP-018
- Passing evidence for VT-HTTP-019
- Passing evidence for VT-HTTP-020
- Passing evidence for VT-HTTP-022
- Passing evidence for VT-HTTP-025
- Passing evidence for VT-HTTP-026
- Passing evidence for VT-PRIV-001
- Passing evidence for VT-PRIV-002
- Passing evidence for VT-PRIV-003
- Passing evidence for VT-REL-003
- Passing evidence for VT-SCHED-007
- Passing evidence for VT-SCHED-016
- Passing evidence for VT-SEC-009
- Passing evidence for VT-SEC-010
- Passing evidence for VT-SEC-011
- Passing evidence for VT-SEC-012
- Passing evidence for VT-SEC-025

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
