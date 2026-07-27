# Architecture Decision Records

## Index

| ID | Decision | Status | Affected requirements |
| --- | --- | --- | --- |
| ADR-001 | Use a Python modular monolith | accepted | FR-001, FR-007, COMPAT-001 |
| ADR-002 | Support CPython 3.12 through 3.14 | accepted | COMPAT-001, OPS-001 |
| ADR-003 | Use AnyIO with the asyncio backend in v0.1 | accepted | SCHED-012, STATE-007, OBS-011 |
| ADR-004 | Use a single-writer SQLite rollback journal | accepted | DATA-001, DATA-002, DATA-003, REL-001, REL-004 |
| ADR-005 | Use HMAC-SHA256 counter generation and RFC 8785 manifests | accepted | SCHED-001, SCHED-004, SCHED-005 |
| ADR-006 | Use integer microsecond logical time with real and scaled modes | superseded by ADR-023 | SCHED-006, SCHED-007, SCHED-008, SCHED-009 |
| ADR-007 | Use SQLite WAL, synchronous FULL, and one writer | superseded by ADR-004 | DATA-001, DATA-002, DATA-003, REL-010 |
| ADR-008 | Separate manifest, run, event, delivery, attempt, observation, and assertion identities | accepted | FR-004, DATA-006, DATA-007, REL-007 |
| ADR-009 | Preserve unknown network outcomes | accepted | STATE-008, REL-002, REL-003, REL-006 |
| ADR-010 | Use command and HTTP observers as v0.1 extension boundaries | accepted | OBS-001, OBS-002, OBS-004, ASSERT-009 |
| ADR-011 | Keep provider behavior in versioned signing and fixture adapters | accepted | SIG-001, SIG-008, SIG-009, SIG-010 |
| ADR-012 | Use staged typed mutations | accepted | MUT-001, MUT-002, MUT-003, MUT-004 |
| ADR-013 | Do not publish an in-process plugin API in v0.1 | accepted | API-002, API-003, API-004 |
| ADR-014 | Use allowlisted destination security with permanent metadata blocks | accepted | SEC-001, SEC-002, SEC-003, SEC-004, HTTP-003, HTTP-004 |
| ADR-015 | Use JSONL, summary JSON, JUnit, and static HTML; reject runtime SARIF | accepted | REPORT-003, REPORT-004, REPORT-005, REPORT-007 |
| ADR-016 | Use wrch as the neutral technical CLI name | accepted | CLI-001 |
| ADR-017 | Package as wheel, container, and GitHub Action | accepted | OPS-001, OPS-003, OPS-004, OPS-005 |
| ADR-018 | Use an orders-and-payments reference domain | accepted | FR-005, TEST-007 |
| ADR-019 | Import standards only as deferred adapters | accepted | CFG-001, API-002 |
| ADR-020 | Use bounded conformance performance budgets | accepted | PERF-001, PERF-002, PERF-003, PERF-008 |
| ADR-021 | Use context-derived HMAC-SHA256 deterministic generation | accepted | SCHED-001, SCHED-002, SCHED-003, DATA-008 |
| ADR-022 | Defer a public third-party plugin API | accepted | API-004, COMPAT-008, OPS-007 |
| ADR-023 | Support real and scaled clocks; limit virtual time to in-process tests | accepted | SCHED-007, SCHED-008, SCHED-009, SCHED-010 |
| ADR-024 | Ship three built-in HMAC signature profiles in v0.1 | accepted | SIG-001, SIG-006, SIG-009, SIG-015 |
| ADR-025 | Use JUnit, structured JSON Lines, and static HTML; reject runtime SARIF | accepted | REPORT-001, REPORT-006, REPORT-011, REPORT-015 |

## ADR-001 — Use a Python modular monolith

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | FR-001, FR-007, COMPAT-001 |
| Risks | RISK-001 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-077, SRC-080, SRC-046 |
| Related/superseded |  |

**Context and forces**

Use a Python modular monolith

**Options considered**

- Python modular monolith
- Go single binary
- Rust single binary
- Distributed services

**Decision**

Implement v0.1 as one Python package and process with explicit internal component boundaries.

**Positive consequences**

- Matches maintainer skills and preferred stack.
- Minimizes operational dependencies.
- Supports rapid property and integration testing.

**Negative consequences**

- Python packaging is less self-contained than a native binary.
- CPU-bound scale is not a design goal.

**Rejected alternatives**

- Python modular monolith
- Go single binary
- Rust single binary
- Distributed services

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- Measured install friction prevents adoption.
- A P0 workload cannot meet documented budgets.
## ADR-002 — Support CPython 3.12 through 3.14

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | COMPAT-001, OPS-001 |
| Risks | RISK-002 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-077, SRC-078, SRC-079, SRC-080 |
| Related/superseded |  |

**Context and forces**

Support CPython 3.12 through 3.14

**Options considered**

- 3.11-3.14
- 3.12-3.14
- 3.13-3.14
- Latest minor only

**Decision**

Set requires-python >=3.12,<3.15 for v0.1 and test every supported minor.

**Positive consequences**

- Balances modern typing/runtime features with broad current availability.
- All selected dependencies support the range.

**Negative consequences**

- Three-version CI matrix increases test cost.

**Rejected alternatives**

- 3.11-3.14
- 3.12-3.14
- 3.13-3.14
- Latest minor only

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- A core dependency drops a supported minor.
- CI duration exceeds budget.
## ADR-003 — Use AnyIO with the asyncio backend in v0.1

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | SCHED-012, STATE-007, OBS-011 |
| Risks | RISK-003 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-022, SRC-019 |
| Related/superseded |  |

**Context and forces**

Use AnyIO with the asyncio backend in v0.1

**Options considered**

- Raw asyncio
- AnyIO with asyncio backend
- AnyIO with asyncio and Trio parity
- Trio only

**Decision**

Use AnyIO task groups, cancellation scopes, subprocess APIs, and synchronization while running only the asyncio backend in required tests.

**Positive consequences**

- Structured concurrency and bounded cancellation.
- Preserves a future backend seam without promising parity.

**Negative consequences**

- Adds an abstraction dependency.
- Trio compatibility is not guaranteed.

**Rejected alternatives**

- Raw asyncio
- AnyIO with asyncio backend
- AnyIO with asyncio and Trio parity
- Trio only

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- AnyIO abstractions block required HTTPX or subprocess behavior.
## ADR-004 — Use a single-writer SQLite rollback journal

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | DATA-001, DATA-002, DATA-003, REL-001, REL-004 |
| Risks | RISK-006, RISK-007 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-084, SRC-085, SRC-086, SRC-087, SRC-088 |
| Related/superseded | supersedes ADR-007 |

**Context and forces**

The v0.1 core needs durable local state, crash recovery, simple packaging, and one active writer per run; it does not need concurrent distributed writers.

**Options considered**

- SQLite rollback journal DELETE + synchronous EXTRA
- SQLite WAL + synchronous FULL
- Append-only files only
- PostgreSQL

**Decision**

Use one local SQLite database per run bundle with journal_mode=DELETE, synchronous=EXTRA, foreign_keys=ON, trusted_schema=OFF, explicit BEGIN IMMEDIATE write transactions, and one owning process.

**Positive consequences**

- Hot-journal recovery is built into SQLite.
- No checkpoint subsystem or WAL sidecars are required.
- The design matches the single-writer product boundary.
- Current WAL-specific recovery risk is avoided.

**Negative consequences**

- Readers block briefly during commits.
- The database must remain on a local filesystem.
- Parallel processes cannot write one run.

**Rejected alternatives**

- WAL adds checkpoint and sidecar complexity without a measured reader-concurrency need.
- Append-only files alone make relational integrity and recovery scans harder.
- PostgreSQL violates local-first zero-service operation.

**Implementation constraints**

- One process owns a run directory.
- All state transitions occur through the journal service.
- Database files on network filesystems are unsupported.
- Migrations are transactional and append-only.

**Verification implications**

- Crash every transaction boundary.
- Verify hot-journal recovery and foreign-key integrity.
- Reject concurrent ownership.

**Revisit triggers**

- Measured report readers require concurrent reads during long writes.
- A distributed execution requirement is accepted.
## ADR-005 — Use HMAC-SHA256 counter generation and RFC 8785 manifests

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | SCHED-001, SCHED-004, SCHED-005 |
| Risks | RISK-005 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-018, SRC-030, SRC-031, SRC-033 |
| Related/superseded |  |

**Context and forces**

Use HMAC-SHA256 counter generation and RFC 8785 manifests

**Options considered**

- Python random seed
- PCG implementation
- HMAC-SHA256 counter generator plus realized manifest
- UUID-only random generation

**Decision**

Define wrch-hmac-drbg-v1 for deterministic choices and RFC 8785 canonical JSON for content hashes; record all realized values so replay never depends on generator stability.

**Positive consequences**

- Simple, portable test vectors.
- Algorithm changes cannot affect existing manifests.
- Cryptographic primitive is widely available.

**Negative consequences**

- Requires a small specified sampler and JCS implementation dependency.
- JCS constrains numeric representation.

**Rejected alternatives**

- Python random seed
- PCG implementation
- HMAC-SHA256 counter generator plus realized manifest
- UUID-only random generation

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- Canonicalization library becomes unmaintained.
- Interoperability vectors fail across runtimes.
## ADR-006 — Use integer microsecond logical time with real and scaled modes

This historical decision is superseded by ADR-023. Current implementations use signed integer logical nanoseconds.

| Field | Value |
| --- | --- |
| Status / date | superseded / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | SCHED-006, SCHED-007, SCHED-008, SCHED-009 |
| Risks | RISK-006 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-032, SRC-033, SRC-019 |
| Related/superseded | ADR-023 |

**Context and forces**

Use integer microsecond logical time with real and scaled modes

**Options considered**

- Floating seconds
- Integer nanoseconds
- Integer microseconds real/scaled
- Full virtual clock

**Decision**

Represent logical time as integer microseconds; use monotonic real deadlines; support real and rationally scaled delays in v0.1; defer external virtual time.

**Positive consequences**

- Avoids floating drift.
- Readable and sufficient precision for webhook conformance.
- Does not overclaim control of external systems.

**Negative consequences**

- Sub-microsecond scheduling is unsupported.
- Scaled time cannot prove receiver wall-clock behavior.

**Rejected alternatives**

- Floating seconds
- Integer nanoseconds
- Integer microseconds real/scaled
- Full virtual clock

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- A validated use case requires coordinated receiver test clocks.
## ADR-007 — Use SQLite WAL, synchronous FULL, and one writer

This historical decision is superseded by ADR-004. Current implementations use rollback-journal `DELETE` with `synchronous=EXTRA`.

| Field | Value |
| --- | --- |
| Status / date | superseded / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | DATA-001, DATA-002, DATA-003, REL-010 |
| Risks | RISK-007 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-026, SRC-027, SRC-028, SRC-029 |
| Related/superseded | ADR-004 |

**Context and forces**

Use SQLite WAL, synchronous FULL, and one writer

**Options considered**

- SQLite rollback journal
- SQLite WAL NORMAL
- SQLite WAL FULL single writer
- PostgreSQL

**Decision**

Store mutable execution state in SQLite with WAL, synchronous=FULL, foreign keys, one writer connection, and append-oriented evidence.

**Positive consequences**

- Local and CI portability.
- Strong transaction semantics and crash tests.
- No service dependency.

**Negative consequences**

- Power-loss durability has filesystem limits.
- One writer limits mutation throughput, which is acceptable.

**Rejected alternatives**

- SQLite rollback journal
- SQLite WAL NORMAL
- SQLite WAL FULL single writer
- PostgreSQL

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- A hosted multi-worker product becomes a committed scope.
- Measured writer contention violates budgets.
## ADR-008 — Separate manifest, run, event, delivery, attempt, observation, and assertion identities

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | FR-004, DATA-006, DATA-007, REL-007 |
| Risks | RISK-008 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-007, SRC-013, SRC-064 |
| Related/superseded |  |

**Context and forces**

Separate manifest, run, event, delivery, attempt, observation, and assertion identities

**Options considered**

- One event ID everywhere
- Run-scoped integer IDs only
- Layered typed identities

**Decision**

Use content-derived manifest and planned entity IDs, plus a unique execution run_id and separately generated physical attempt/sample/evaluation IDs.

**Positive consequences**

- Prevents conflating provider event identity with network attempts.
- Supports replay and ambiguity evidence.

**Negative consequences**

- More identifiers appear in user reports.

**Rejected alternatives**

- One event ID everywhere
- Run-scoped integer IDs only
- Layered typed identities

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- User testing shows identifiers are not navigable despite report design.
## ADR-009 — Preserve unknown network outcomes

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | STATE-008, REL-002, REL-003, REL-006 |
| Risks | RISK-009 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-064, SRC-065, SRC-075 |
| Related/superseded |  |

**Context and forces**

Preserve unknown network outcomes

**Options considered**

- Assume failure and retry
- Assume success
- Infer from socket state
- Explicit unknown_outcome

**Decision**

When request bytes may have left but terminal evidence is not durably committed, preserve unknown_outcome and require explicit reconciliation or redelivery policy.

**Positive consequences**

- Honest distributed-systems semantics.
- Makes duplicate physical delivery risk visible.

**Negative consequences**

- Some runs require operator or observer action.
- Cannot guarantee no duplicate physical send.

**Rejected alternatives**

- Assume failure and retry
- Assume success
- Infer from socket state
- Explicit unknown_outcome

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- A transport API provides a durable sender transaction boundary.
## ADR-010 — Use command and HTTP observers as v0.1 extension boundaries

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | OBS-001, OBS-002, OBS-004, ASSERT-009 |
| Risks | RISK-010 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-046, SRC-064, SRC-036 |
| Related/superseded |  |

**Context and forces**

Use command and HTTP observers as v0.1 extension boundaries

**Options considered**

- HTTP only
- Command only
- Command + HTTP
- General in-process plugin API

**Decision**

Provide schema-versioned command/stdin-stdout and authenticated HTTP observer contracts; defer direct SQL, telemetry, queue, and in-process custom plugins.

**Positive consequences**

- Language-independent application integration.
- Security boundaries are explicit and testable.

**Negative consequences**

- Requires receiver-side setup.
- Process and HTTP errors need careful classification.

**Rejected alternatives**

- HTTP only
- Command only
- Command + HTTP
- General in-process plugin API

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- Pilots reject both observer forms.
- Two proven adapters require a public API.
## ADR-011 — Keep provider behavior in versioned signing and fixture adapters

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | SIG-001, SIG-008, SIG-009, SIG-010 |
| Risks | RISK-011 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-003, SRC-006, SRC-009, SRC-012, SRC-013 |
| Related/superseded |  |

**Context and forces**

Keep provider behavior in versioned signing and fixture adapters

**Options considered**

- Generic HMAC only
- Many provider emulators
- Generic + Stripe + Standard Webhooks HMAC
- Generic + all asymmetric formats

**Decision**

Ship generic HMAC-SHA256, Stripe HMAC, and Standard Webhooks HMAC adapters; record versions; defer Ed25519 and broad provider emulation.

**Positive consequences**

- Covers core raw-byte and timestamp semantics.
- Demonstrates provider seam without broad scope.

**Negative consequences**

- Discord and other asymmetric providers are deferred.

**Rejected alternatives**

- Generic HMAC only
- Many provider emulators
- Generic + Stripe + Standard Webhooks HMAC
- Generic + all asymmetric formats

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- User demand clusters around an unsupported provider.
## ADR-012 — Use staged typed mutations

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | MUT-001, MUT-002, MUT-003, MUT-004 |
| Risks | RISK-012 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-066, SRC-067, SRC-046 |
| Related/superseded |  |

**Context and forces**

Use staged typed mutations

**Options considered**

- Boolean corruption flags
- Arbitrary scripts
- Versioned staged operators

**Decision**

Define structured, serialization, raw-byte, signing, and post-signing mutation stages with versioned operators and golden vectors.

**Positive consequences**

- Deterministic and diagnosable failures.
- Signing order remains explicit.

**Negative consequences**

- Operator catalog requires maintenance.

**Rejected alternatives**

- Boolean corruption flags
- Arbitrary scripts
- Versioned staged operators

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- Operator count creates support burden without use.
## ADR-013 — Do not publish an in-process plugin API in v0.1

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | API-002, API-003, API-004 |
| Risks | RISK-013 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-036, SRC-050 |
| Related/superseded |  |

**Context and forces**

Do not publish an in-process plugin API in v0.1

**Options considered**

- Entry-point plugins in v0.1
- No abstractions
- Internal protocols without public ABI

**Decision**

Keep internal protocols typed but unstable; use static first-party registry and process/HTTP extension boundaries.

**Positive consequences**

- Avoids premature compatibility commitments and arbitrary code loading.
- Still permits later extraction from concrete adapters.

**Negative consequences**

- Third-party provider packages cannot integrate in-process initially.

**Rejected alternatives**

- Entry-point plugins in v0.1
- No abstractions
- Internal protocols without public ABI

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- At least two external implementations prove a stable abstraction.
## ADR-014 — Use allowlisted destination security with permanent metadata blocks

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | SEC-001, SEC-002, SEC-003, SEC-004, HTTP-003, HTTP-004 |
| Risks | RISK-014 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-041, SRC-019, SRC-021 |
| Related/superseded |  |

**Context and forces**

Use allowlisted destination security with permanent metadata blocks

**Options considered**

- Allow any URL
- Block all public URLs permanently
- Dual authorization with address validation

**Decision**

Allow loopback and explicitly named local hosts by default; require configuration plus CLI confirmation for public targets; disable redirects and environment proxies; validate every resolved address.

**Positive consequences**

- Reduces accidental production traffic and SSRF paths.
- Retains legitimate staging tests through explicit consent.

**Negative consequences**

- Local DNS and container networking require clear diagnostics.
- Not equivalent to a multi-tenant network sandbox.

**Rejected alternatives**

- Allow any URL
- Block all public URLs permanently
- Dual authorization with address validation

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- A hosted mode is approved.
- DNS pinning is required by a demonstrated threat model.
## ADR-015 — Use JSONL, summary JSON, JUnit, and static HTML; reject runtime SARIF

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | REPORT-003, REPORT-004, REPORT-005, REPORT-007 |
| Risks | RISK-015 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-035, SRC-046, SRC-083 |
| Related/superseded |  |

**Context and forces**

Use JSONL, summary JSON, JUnit, and static HTML; reject runtime SARIF

**Options considered**

- JSON only
- JUnit only
- JSONL + summary + JUnit + HTML
- Add SARIF

**Decision**

Emit versioned JSONL evidence, result-summary JSON, JUnit XML, and no-script static HTML; do not emit SARIF for runtime conformance in v0.1.

**Positive consequences**

- Supports automation, CI, and human diagnosis.
- Keeps authoritative data separate from presentation.

**Negative consequences**

- Four artifact forms require consistency tests.

**Rejected alternatives**

- JSON only
- JUnit only
- JSONL + summary + JUnit + HTML
- Add SARIF

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- A concrete static-analysis result class is added.
## ADR-016 — Use wrch as the neutral technical CLI name

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | CLI-001 |
| Risks | RISK-016 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-050 |
| Related/superseded |  |

**Context and forces**

Use wrch as the neutral technical CLI name

**Options considered**

- HookLab
- EventGauntlet
- wrch technical identifier

**Decision**

Publish the technical executable wrch and repository identifier webhook-receiver-conformance-harness while leaving marketing branding outside architecture contracts.

**Positive consequences**

- Avoids known naming collisions.
- Schemas and scripts remain brand-neutral.

**Negative consequences**

- Acronym requires explanation in user-facing material.

**Rejected alternatives**

- HookLab
- EventGauntlet
- wrch technical identifier

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- A cleared final brand is selected before package publication.
## ADR-017 — Package as wheel, container, and GitHub Action

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | OPS-001, OPS-003, OPS-004, OPS-005 |
| Risks | RISK-017 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-037, SRC-038, SRC-039, SRC-040 |
| Related/superseded |  |

**Context and forces**

Package as wheel, container, and GitHub Action

**Options considered**

- Wheel only
- Standalone native executable
- Wheel + container + GitHub Action

**Decision**

Make the wheel authoritative, installable through pipx/uvx; build a thin nonroot container and action wrapper from released artifacts.

**Positive consequences**

- Meets local and CI adoption paths.
- Avoids separate runtime implementations.

**Negative consequences**

- Three distribution surfaces need smoke tests.

**Rejected alternatives**

- Wheel only
- Standalone native executable
- Wheel + container + GitHub Action

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- Installation measurements show a standalone binary is required.
## ADR-018 — Use an orders-and-payments reference domain

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | FR-005, TEST-007 |
| Risks | RISK-018 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-001, SRC-061, SRC-064 |
| Related/superseded |  |

**Context and forces**

Use an orders-and-payments reference domain

**Options considered**

- Generic counter receiver
- Orders and payments domain
- Full Stripe clone

**Decision**

Model order.created, payment.authorized, payment.captured, and order.cancelled with transactional side-effect and idempotency tables, plus isolated flawed variants.

**Positive consequences**

- Makes duplicate, ordering, partial processing, and signature defects understandable.
- Avoids implementing an entire provider.

**Negative consequences**

- Domain examples may appear payment-centric.

**Rejected alternatives**

- Generic counter receiver
- Orders and payments domain
- Full Stripe clone

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- Users consistently misunderstand provider independence.
## ADR-019 — Import standards only as deferred adapters

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | CFG-001, API-002 |
| Risks | RISK-019 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-014, SRC-015, SRC-016, SRC-017 |
| Related/superseded |  |

**Context and forces**

Import standards only as deferred adapters

**Options considered**

- All standards in v0.1
- Raw fixtures only forever
- Raw fixtures now, versioned import adapters later

**Decision**

Accept raw byte and JSON fixtures in v0.1; defer OpenAPI, AsyncAPI, CloudEvents, and broad schema import to roadmap adapters.

**Positive consequences**

- Keeps MVP focused while preserving evidence-backed extension direction.

**Negative consequences**

- Users must author initial fixture metadata manually.

**Rejected alternatives**

- All standards in v0.1
- Raw fixtures only forever
- Raw fixtures now, versioned import adapters later

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- Pilots identify fixture authoring as the dominant adoption blocker.
## ADR-020 — Use bounded conformance performance budgets

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, future maintainer |
| Requirements | PERF-001, PERF-002, PERF-003, PERF-008 |
| Risks | RISK-020 |
| Criteria | correctness, testability, security, local-first operation, solo-maintainer complexity, cross-platform behavior |
| Sources | SRC-019, SRC-022, SRC-046 |
| Related/superseded |  |

**Context and forces**

Use bounded conformance performance budgets

**Options considered**

- No budgets
- Enterprise-scale targets
- MVP conformance budgets

**Decision**

Set explicit local planning, throughput, memory, disk, payload, concurrency, startup, and CI budgets without treating the tool as a load tester.

**Positive consequences**

- Makes regressions measurable.
- Prevents accidental scope expansion.

**Negative consequences**

- Reference hardware must be documented.

**Rejected alternatives**

- No budgets
- Enterprise-scale targets
- MVP conformance budgets

**Implementation constraints**

- Public behavior must remain traceable to normative requirements.
- Changes require ADR supersession and schema/traceability updates.

**Verification implications**

- Decision-specific contract and regression tests are required.

**Revisit triggers**

- Real user workloads consistently exceed hard caps.
## ADR-021 — Use context-derived HMAC-SHA256 deterministic generation

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, determinism maintainer |
| Requirements | SCHED-001, SCHED-002, SCHED-003, DATA-008 |
| Risks | RISK-009 |
| Criteria | cross-version stability, domain separation, random-access derivation, testability |
| Sources | SRC-113 |
| Related/superseded |  |

**Context and forces**

A seed must produce stable independent choices even when unrelated fields are added, while algorithm changes must not invalidate an already realized manifest.

**Options considered**

- Python random.Random
- PCG stream
- ChaCha stream
- context-derived HMAC-SHA256

**Decision**

Define generator hmac-sha256-context-v1: derive bytes as HMAC-SHA256(seed_key, domain_separator || length-prefixed context path || block_index); use rejection sampling for bounded integers. The manifest records every realized value and replays without invoking the generator.

**Positive consequences**

- Adding an unrelated draw does not shift existing choices.
- The primitive is ubiquitous and easy to vector-test.
- Manifest replay is independent of generator implementation.

**Negative consequences**

- The seed becomes sensitive if users expect generated values to remain private.
- The algorithm requires an explicit canonical context encoding.

**Rejected alternatives**

- random.Random is not a public cross-version contract.
- A sequential stream is fragile when the plan shape changes.
- ChaCha adds a dependency without improving the realized-manifest guarantee.

**Implementation constraints**

- Seed material is not a signing key.
- Contexts are UTF-8 length-prefixed components.
- Golden vectors are immutable per algorithm version.

**Verification implications**

- Golden vectors, prefix independence, rejection-sampling, and replay-without-generator tests.

**Revisit triggers**

- A standards-based deterministic generator materially improves interoperability.
## ADR-022 — Defer a public third-party plugin API

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, open-source maintainer |
| Requirements | API-004, COMPAT-008, OPS-007 |
| Risks | RISK-016 |
| Criteria | scope discipline, compatibility cost, two-implementation rule, security boundary |
| Sources | SRC-106, SRC-107 |
| Related/superseded |  |

**Context and forces**

Signer, mutation, observer, assertion, and reporter seams are needed internally, but a public plugin contract would create an early compatibility burden before external implementations prove the abstractions.

**Options considered**

- Public entry-point plugins in v0.1
- Internal protocols only
- No extension seams

**Decision**

Keep typed internal protocols and built-in registries in v0.1. Publish only the observer wire protocol. Revisit entry-point plugins after at least two external adapter contributions or concrete user demand.

**Positive consequences**

- Avoids freezing speculative APIs.
- Reduces arbitrary-code loading and supply-chain exposure.
- Keeps built-ins contract-testable.

**Negative consequences**

- Third parties must contribute built-ins or wrap the CLI.
- Provider expansion is initially maintainer-mediated.

**Rejected alternatives**

- A generic plugin framework has no validated external consumers.
- Removing all seams would couple core planning to providers.

**Implementation constraints**

- Internal protocols are not compatibility promises.
- No dynamic entry-point loading in v0.1.
- The plugin metadata schema is informational/experimental only.

**Verification implications**

- Built-in contract suites; negative test that installed entry points are not auto-loaded.

**Revisit triggers**

- Two independent external implementations need the same category.
- A v0.2 architecture review accepts a trust model.
## ADR-023 — Support real and scaled clocks; limit virtual time to in-process tests

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, scheduler maintainer |
| Requirements | SCHED-007, SCHED-008, SCHED-009, SCHED-010 |
| Risks | RISK-008 |
| Criteria | honest claims, CI duration, deterministic ordering, external compatibility |
| Sources | SRC-001, SRC-022, SRC-032 |
| Related/superseded | supersedes ADR-006 |

**Context and forces**

CI cannot wait through provider-scale backoff, but a local harness cannot virtualize an unmodified external receiver clock or network stack honestly.

**Options considered**

- Real time only
- Real + scaled
- Full external virtual time
- Sleep patching

**Decision**

Provide real and scaled execution modes for network runs. Use integer logical nanoseconds for plan ordering, monotonic time for elapsed deadlines, UTC wall time for audit evidence, and virtual time only for pure/in-process unit and model tests.

**Positive consequences**

- CI remains fast.
- The tool does not claim to control the receiver wall clock.
- Schedule order and external elapsed time remain distinct.

**Negative consequences**

- A scaled retry does not prove behavior after the equivalent real-world duration.
- Time-dependent receivers need their own test-clock hook.

**Rejected alternatives**

- Full external virtual time is impossible without receiver cooperation.
- Real-only mode makes backoff corpora impractical.

**Implementation constraints**

- Every report names clock mode and scale.
- Timeouts use real monotonic time.
- Minimum physical intervals prevent zero-duration busy loops.

**Verification implications**

- Clock-jump, scale-boundary, monotonic-deadline, and false-claim tests.

**Revisit triggers**

- A standardized receiver test-clock protocol emerges.
## ADR-024 — Ship three built-in HMAC signature profiles in v0.1

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, security maintainer |
| Requirements | SIG-001, SIG-006, SIG-009, SIG-015 |
| Risks | RISK-003, RISK-014 |
| Criteria | market relevance, raw-byte fidelity, key rotation coverage, implementation scope |
| Sources | SRC-001, SRC-003, SRC-013, SRC-113, SRC-114 |
| Related/superseded |  |

**Context and forces**

The MVP must prove exact-byte signing and replay-window behavior without becoming a provider emulator or cryptographic framework.

**Options considered**

- Generic HMAC only
- Generic HMAC + Stripe
- Generic HMAC + Stripe + Standard Webhooks HMAC
- Include Ed25519

**Decision**

Ship generic HMAC-SHA256, Stripe v1, and Standard Webhooks HMAC profiles. Defer Ed25519 and other provider profiles until the core contract is stable.

**Positive consequences**

- Covers raw body, timestamps, multiple signatures, and key rotation.
- Keeps cryptographic surface reviewable.
- Provides one generic and two concrete profiles.

**Negative consequences**

- Discord-style Ed25519 receivers need custom test code in v0.1.
- Provider behavior still requires maintenance.

**Rejected alternatives**

- Generic-only does not prove provider fidelity.
- Ed25519 expands key encoding and dependency scope without being required for the first vertical slice.

**Implementation constraints**

- Sign exact transmitted bytes.
- Use fixed official/golden vectors.
- Never serialize secret key material.

**Verification implications**

- Official/golden vectors, altered-body, stale timestamp, wrong-key, multiple-key, and malformed-header cases.

**Revisit triggers**

- Measured demand from an Ed25519 provider integration.
## ADR-025 — Use JUnit, structured JSON Lines, and static HTML; reject runtime SARIF

| Field | Value |
| --- | --- |
| Status / date | accepted / 2026-07-26 |
| Owners | principal architect, reporting maintainer |
| Requirements | REPORT-001, REPORT-006, REPORT-011, REPORT-015 |
| Risks | RISK-015 |
| Criteria | CI compatibility, lossless evidence, security, standards fit |
| Sources | SRC-118, SRC-119, SRC-102 |
| Related/superseded |  |

**Context and forces**

CI needs test-result ingestion, developers need complete causal evidence, and reports render untrusted fixture content.

**Options considered**

- JUnit only
- SARIF
- JSON/JSONL only
- JUnit + JSON/JSONL + static HTML

**Decision**

Emit an immutable manifest, append-oriented JSON Lines evidence, a machine summary, JUnit XML, and a no-script escaped HTML report. Do not emit SARIF for runtime outcomes.

**Positive consequences**

- CI systems receive conventional test cases.
- Lossless evidence remains schema-backed.
- Static HTML reduces injection surface.

**Negative consequences**

- Several synchronized renderers must agree.
- JUnit attachment behavior varies by CI provider.

**Rejected alternatives**

- SARIF models static-analysis findings rather than network attempt lifecycles.
- JUnit alone cannot preserve full causal evidence.

**Implementation constraints**

- The journal is the reporting authority.
- Renderers are pure/idempotent.
- HTML contains no active content.

**Verification implications**

- Cross-renderer verdict checks, XML parsing, schema validation, secret canaries, and XSS payload corpus.

**Revisit triggers**

- A specific CI integration requires another export format.
