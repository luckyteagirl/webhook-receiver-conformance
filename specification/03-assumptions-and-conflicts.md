# Assumptions, Conflicts, and Open Questions

## Assumptions

| ID | Statement | Impact | Confidence | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| ASM-001 | The v0.1 operator controls the local workstation or CI job and is trusted to authorize the receiver target. | The core is single-tenant and does not provide hostile-user isolation. | high | Revisit before any hosted or shared-runner execution mode. | accepted |
| ASM-002 | A receiver that needs business-effect assertions can expose a test-only HTTP probe or command observer in its test environment. | Without cooperation, only transport and externally observable callback assertions are available. | medium | Validate through at least five external pilots. | accepted |
| ASM-003 | Local and CI conformance suites normally contain no more than 1,000 logical events and 5,000 physical attempts. | Performance, storage, and schema limits are optimized for diagnostic testing rather than load testing. | medium | Collect opt-in aggregate usage before raising limits. | accepted |
| ASM-004 | The receiver is reachable over HTTP or HTTPS from the local process, container network, or CI job. | The first release does not provide a tunnel or public ingress service. | high | Document local, Compose, and GitHub Actions deployment patterns. | accepted |
| ASM-005 | A single writer per run is sufficient for the initial product. | SQLite write serialization and one run owner simplify crash consistency. | high | Revisit only after measured need for distributed execution. | accepted |
| ASM-006 | Raw fixtures may contain secrets or personal data even in test environments. | Minimized retention and redaction are default security properties. | high | Continuously test with secret canaries. | accepted |
| ASM-007 | Provider-specific signing and header semantics change more often than core event, delivery, and assertion semantics. | Adapters are isolated and versioned independently from the scheduler and journal. | high | Track provider release notes and conformance vectors. | accepted |
| ASM-008 | Users value reproducible artifacts more than reproducing incidental wall-clock timing. | The realized manifest records deterministic inputs and logical schedule while external execution remains observational. | high | Validate report usefulness in pilot incident reproductions. | accepted |
| ASM-009 | Most users can install Python wheels, run uvx/pipx, or use an OCI image. | A native standalone binary is deferred. | medium | Measure installation abandonment and platform support requests. | accepted |
| ASM-010 | GitHub Actions is the first CI wrapper, while the CLI remains CI-provider-neutral. | Other CI providers use the CLI and JUnit artifacts rather than dedicated integrations in v0.1. | high | Revisit based on adoption. | accepted |
| ASM-011 | Scenario plans can use an integer logical-microsecond timeline without sub-microsecond requirements. | Ordering and persistence avoid floating-point time. | high | Review any provider adapter requiring finer precision. | accepted |
| ASM-012 | The initial reference domain of orders and payments is understandable to backend reviewers and exposes meaningful idempotency defects. | Reference examples are illustrative and do not make the core payment-specific. | high | Confirm framework examples remain domain-neutral at core boundaries. | accepted |

## Resolved evidence conflicts

| Conflict | Resolution |
| --- | --- |
| Earlier WAL preference versus current single-writer needs | Current SQLite documentation and the one-owner run model favor rollback journal DELETE with synchronous EXTRA. ADR-004 owns the resolution. |
| Seed reproducibility versus Python PRNG implementation stability | The generator is explicitly versioned and context-derived; the realized manifest, not the seed, is the replay authority. |
| Virtual time for CI versus an external receiver clock | Network runs support real/scaled time only. Virtual time is an in-process test facility, not a product claim. |
| Provider-independent core versus provider-specific fidelity | The core models generic identities and attempts; signing/header profiles are isolated built-ins. |
| Plugin extensibility versus v0.1 compatibility cost | Internal protocols remain nonpublic; only observer wire protocol is public. |

## Open questions

| ID | Question | Owner | Impact | Latest safe point | Default | Blocking | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OQ-001 | What public product name clears package, repository, domain, and trademark screening? | product maintainer | Branding only; technical identifier remains stable. | Before public repository launch | Use webhook-receiver-conformance-harness and wrch. | False | open |
| OQ-002 | Should a public third-party plugin API ship before v0.2? | architecture maintainer | Premature compatibility obligation. | After two external adapter contributions | No public plugin API in v0.1. | False | deferred |
| OQ-003 | Should Standard Webhooks Ed25519 become P1 after HMAC adapters stabilize? | security maintainer | Broader signature coverage and key-management complexity. | Before v0.2 planning | Defer; retain schema room for asymmetric metadata. | False | deferred |
| OQ-004 | Which, if any, of OpenAPI, AsyncAPI, and CloudEvents importers earns first-party support? | product maintainer | Additional parser and semantic-mapping surface. | After fixture-manifest adoption evidence | Document manual conversion; no importer in v0.1. | False | deferred |
| OQ-005 | Do users need first-party read-only SQL or OpenTelemetry observers? | developer-experience maintainer | Credential handling and backend-specific integrations. | After command/HTTP observer pilot results | Ship protocol examples only. | False | deferred |
| OQ-006 | Is a standalone native executable materially better than wheels and OCI images? | release maintainer | Build complexity and platform matrix. | After measuring installation failures | Use wheels, uvx/pipx, and OCI. | False | deferred |
| OQ-007 | Should deterministic external virtual-time integration be standardized? | scheduler maintainer | Receiver-specific hooks and risk of overstated guarantees. | After at least two receiver implementations need it | Real and scaled clocks only. | False | deferred |
| OQ-008 | Should Docker Compose lifecycle control become a first-party adapter? | integration maintainer | Cross-platform Docker dependency. | After argv lifecycle profile validation | Provide documented argv examples, not a core adapter. | False | deferred |
| OQ-009 | What telemetry, if any, can be collected without compromising local-first trust? | privacy maintainer | Adoption measurement versus privacy promise. | Before any telemetry code | No telemetry in v0.1. | False | deferred |
| OQ-010 | Is a hosted report-sharing service commercially useful? | product maintainer | Would introduce multitenancy, SSRF, retention, and compliance requirements. | After repeated local CI adoption | Out of scope. | False | deferred |

No open question blocks the v0.1 implementation graph.
