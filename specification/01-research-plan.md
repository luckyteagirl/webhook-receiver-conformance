# Research Plan and Decision Question Tree

## Scope

The research program validates the technical and implementation decisions required for a local-first webhook receiver conformance harness. It does not repeat broad market sizing. The inherited viability prompt required a concise plan, explicit assumptions, counterevidence, separate product modes, and authoritative source preference; those principles are preserved here.

## Workstreams and closure

| Workstream | Primary question | Evidence classes | Closure |
| --- | --- | --- | --- |
| A — Provider semantics | What delivery, retry, ordering, timeout, identity, and signature behaviors must the harness represent? | Official provider docs and test tools | Closed for v0.1 profiles; provider drift remains monitored. |
| B — Existing tools | Which features are differentiated versus commodity replay/fault tooling? | Official products, repositories, package docs | Closed: business-state evidence, ambiguity, and realized manifests are the wedge. |
| C — Distributed systems | Which claims are accurate for at-least-once delivery and idempotent effects? | Provider guidance, incidents, engineering literature | Closed: no exactly-once network claim. |
| D — Determinism | What can be reproduced when the receiver is external? | Runtime/library docs and experiments | Closed: inputs and logical schedule only; observations remain external. |
| E — Persistence | How is every crash boundary represented? | SQLite docs and process-kill experiments | Closed for one-owner rollback-journal model. |
| F — Signatures/schemas | Which profiles and standards belong in v0.1? | RFCs, standards, provider docs | Closed: generic HMAC, Stripe v1, Standard Webhooks HMAC. |
| G — Security | How are targets, secrets, fixtures, processes, and reports contained? | OWASP, NIST, runtime docs | Closed with residual platform-specific path/DNS limits. |
| H — Python/DX | Which runtime, dependencies, and distributions are supportable? | Official package/release docs | Closed for CPython 3.12–3.14 and locked uv workflow. |
| I — Test architecture | What evidence proves correct and flawed behavior? | pytest/Hypothesis docs and defect corpus | Closed with layered test architecture. |
| J — Agentic delivery | Can tasks be implemented without interface invention? | Spec Kit, NASA, C4, SEI, BCP 14 | Closed subject to sampled work-packet audit. |

## Risk-weighted decision questions

| Decision | Failure impact | Evidence needed | Result |
| --- | --- | --- | --- |
| DQ-001 Identity separation | Incorrect causal reports and impossible resume semantics | Provider IDs, state model, incidents | Separate run, scenario, event, delivery, attempt, observation, and assertion identities. |
| DQ-002 Reproducibility boundary | False deterministic claims | Clock/runtime constraints | Manifest-fixed inputs and logical schedule; external execution explicitly nondeterministic. |
| DQ-003 Send crash ambiguity | Silent duplicate effects or skipped work | Transaction/network boundary analysis | `unknown_outcome`; no default automatic resend. |
| DQ-004 Persistence mode | Corruption or unnecessary operational complexity | Current SQLite docs | Single-writer DELETE journal with synchronous EXTRA. |
| DQ-005 Receiver evidence | Status-code-only false confidence | Incidents and application-state needs | Public command/HTTP observer protocol. |
| DQ-006 Destination safety | SSRF or production damage | OWASP and HTTP client behavior | Loopback default, address validation/pinning, three-gate public authorization. |
| DQ-007 Plugin scope | Premature compatibility and code-loading risk | Concrete implementation count | No public dynamic plugins in v0.1. |
| DQ-008 Reports | Poor CI integration or injection risk | JUnit/SARIF/HTML standards | JUnit + JSON/JSONL + static HTML; no runtime SARIF. |

## Stop-condition evidence

Two focused search waves after architecture convergence produced refinements to SQLite mode, current OpenAPI version, and dependency versions but no new P0 component. Every critical decision has an accepted ADR, explicit assumption, or nonblocking open question. Current versions and access dates are recorded in `machine/source-ledger.json`.
