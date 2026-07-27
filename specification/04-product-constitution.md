# Product Constitution

## Product statement

The webhook receiver conformance harness is a local-first CLI and CI tool that freezes exact webhook test inputs into an immutable run bundle, executes adverse delivery plans against an HTTP receiver, collects transport and optional receiver-state evidence, evaluates explicit invariants, and emits reproducible diagnostic artifacts.

## Job to be done

Before releasing a receiver change, prove that expected duplicate, concurrent, retried, reordered, delayed, malformed, interrupted, and signature-invalid deliveries do not create prohibited observable application state.

## Primary users

| Stakeholder | Need |
| --- | --- |
| STAKE-001 — Backend or integration engineer | Reproduce duplicate, retry, ordering, timeout, and signature defects locally. |
| STAKE-002 — QA or test-automation engineer | Gate changes with deterministic, diagnosable CI evidence. |
| STAKE-003 — Platform or developer-experience engineer | Reuse scenario and observer contracts across services without operating another platform. |
| STAKE-004 — Reliability engineer | Distinguish receiver defects, environmental failures, harness defects, and ambiguous outcomes. |
| STAKE-005 — Application-security reviewer | Control destinations, secrets, untrusted fixtures, command execution, and generated reports. |
| STAKE-006 — Open-source maintainer | Maintain a small architecture with stable schemas, migrations, and compatibility rules. |
| STAKE-007 — Autonomous coding agent | Implement tasks without inventing public interfaces or modifying unowned files. |

## Goals

| ID | Goal | Success measure |
| --- | --- | --- |
| GOAL-001 | Compile and replay adverse webhook delivery plans with stable identities and logical schedules. | The same run bundle yields byte-identical planned inputs and schedule records. |
| GOAL-002 | Evaluate transport evidence and receiver-side state evidence as separate domains. | Every receiver verdict cites one or more typed observations or explicitly states that only transport was verified. |
| GOAL-003 | Resume after interruption without silently losing planned work or converting ambiguity into a known outcome. | Every crash point has a specified persisted state and deterministic resume policy. |
| GOAL-004 | Prevent accidental unsafe targets, secret disclosure, report injection, and uncontrolled resource use. | All high-risk threats map to automated regression tests. |
| GOAL-005 | Emit deterministic machine-readable and human-readable artifacts with stable causal links. | JUnit, JSON, JSON Lines, and HTML agree on verdicts and identifiers. |
| GOAL-006 | Use a modular monolith, explicit contracts, bounded dependencies, and dependency-ordered work packets. | Every P0 task has owned files, prerequisites, tests, and completion evidence. |

## Product principles

1. **Effects, not acknowledgements.** HTTP evidence and business-state evidence are separate and neither substitutes for the other.
2. **Realized artifacts over promises.** A seed is an input; the immutable manifest is the replay authority.
3. **Ambiguity is data.** A send that may have left the process without a committed outcome is `unknown_outcome`.
4. **One owner, one journal.** v0.1 has one process owner and one local SQLite database per run.
5. **Exact bytes are protocol state.** Fixtures, mutations, signatures, hashes, and transmission operate on explicit byte sequences.
6. **Safe targets by default.** Loopback is the default; public traffic requires conspicuous independent authorization.
7. **Diagnosable faults.** One-fault baselines precede combined faults; every mutation and attempt is versioned and recorded.
8. **No hidden services.** The P0 path runs locally and in CI without a hosted dependency.
9. **Small public surface.** Do not freeze speculative extension APIs.
10. **Evidence closes work.** Requirements, implementation tasks, tests, and artifacts form one traceable chain.

## Locked constraints

- **CON-LOCK-001:** The core is local-first and runs without an external hosted service.
- **CON-LOCK-002:** The product is usable as a deterministic CI gate.
- **CON-LOCK-003:** Receiver-side invariant evaluation is a first-class capability.
- **CON-LOCK-004:** Realized manifests are the reproducibility authority.
- **CON-LOCK-005:** Ambiguous send outcomes are represented honestly.
- **CON-LOCK-006:** Logging, reports, and targets are secure by default.
- **CON-LOCK-007:** Correct and deliberately flawed reference receivers are included.
- **CON-LOCK-008:** The product never claims exactly-once network delivery.
- **CON-LOCK-009:** The first release is not a gateway, request bin, tunnel, provider emulator, or load tester.

## Strong preferences

- **CON-PREF-001:** Python is the preferred implementation language.
- **CON-PREF-002:** The core is a single-process modular monolith.
- **CON-PREF-003:** Typer, Pydantic, HTTPX, AnyIO, SQLite, pytest, and Hypothesis are preferred.
- **CON-PREF-004:** JSON Schema, JSON Lines, JUnit XML, and static HTML are preferred artifact formats.
- **CON-PREF-005:** Wheels, a non-root container, and a GitHub Action are preferred distribution surfaces.

## MVP scope

### Included

- Strict YAML configuration and a traffic-free validation/materialization command.
- Exact JSON or arbitrary byte fixtures, content-addressed snapshots, and optional JSON Schema validation.
- Immutable realized manifests with separate identities and logical schedules.
- Single, duplicate, concurrent duplicate, delayed, reordered, dependency-violating, retry, timeout, connection-failure, replay, and typed mutation scenarios.
- Real and scaled clock modes.
- Generic HMAC-SHA256, Stripe v1, and Standard Webhooks HMAC signing profiles.
- Command and authenticated HTTP observer adapters.
- Transport, count, existence, field, temporal, callback/journal, and partial-effect assertions.
- Single-writer SQLite rollback journal and explicit recovery/ambiguity policy.
- JSON, JSON Lines, JUnit XML, static HTML, stable exit codes, Docker, and GitHub Action surfaces.
- One correct and nine isolated flawed reference receivers.

### Deferred

- Ed25519/asymmetric profiles, OpenAPI/AsyncAPI/CloudEvents import, direct SQL/OpenTelemetry/queue observers, public dynamic plugins, generalized lifecycle controllers, automatic failure shrinking, native single binaries, and non-GitHub CI wrappers.

### Rejected for v0.1

- Hosted execution, browser UI, multi-tenant service, microservices, PostgreSQL, Kubernetes, request capture, public ingress/tunneling, production gateway operation, provider lifecycle emulation, arbitrary TCP fault proxying, load generation, and runtime SARIF.

## Compatibility promises

The v0.1 public compatibility surfaces are CLI command/exit semantics, configuration schema, manifest/evidence schemas, observer wire protocol, and documented package import points. Pre-1.0 incompatible changes require a minor version increase, migration note, schema version policy, and changelog entry. Internal adapter protocols are explicitly nonpublic.

## Complexity budget

- One process per run.
- One local database per run bundle.
- At most 1,000 logical events, 5,000 attempts, 128 configured concurrency, and 16 MiB hard request bytes.
- No mandatory daemon, external database, message broker, or cloud service.
- A component remains only if a P0 requirement fails when it is removed.

## Change control

A behavior change requires an owning normative requirement, an ADR when material, updated schema/interface/state documentation, tests, traceability, migration/compatibility analysis, and an audit pass. Examples cannot create behavior not present in authoritative artifacts.
