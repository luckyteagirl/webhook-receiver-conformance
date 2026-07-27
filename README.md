# Webhook Receiver Conformance Harness — Specification Pack

**Technical identifier:** `webhook-receiver-conformance-harness`  
**Specification version:** `1.0.0-draft.1`  
**Research verification date:** 2026-07-26  
**Implementation status:** Specification only; production application not implemented.

## Product definition

A local-first command-line and CI harness that compiles reproducible webhook delivery-failure scenarios, executes them against a receiver, and evaluates transport behavior separately from observable application-side effects.

The product is not a request bin, tunnel, production gateway, managed webhook sender, provider emulator, generic HTTP proxy, or load-testing platform. Its differentiator is the chain:

```text
logical event → planned delivery → physical attempt → transport evidence
                                              ↘ observer sample → assertion → verdict
```

It tests idempotent processing and at-most-one observable business side effect per logical event. It does not claim exactly-once network delivery.

## Authority and reading order

1. `specification/04-product-constitution.md`
2. `specification/05-product-requirements.md` and `machine/requirements.yaml`
3. `specification/08-glossary-and-domain-model.md`
4. `specification/09-state-machines.md`
5. `specification/10-architecture.md` through `specification/20-observability-and-reporting.md`
6. `specification/21-test-strategy.md`
7. `machine/decisions.yaml`
8. `machine/task-index.yaml` and `tasks/work-packets/`
9. `validation/final-scorecard.md`

When artifacts conflict, the precedence in `AGENTS.md` applies. Machine-readable schemas own serialized field contracts; normative requirements own behavior; ADRs own selected design rationale.

## Workspace index

| Artifact | Purpose |
| --- | --- |
| README.md | Entry point, reading order, implementation status |
| AGENTS.md | Binding instructions for coding agents |
| specification/04-product-constitution.md | Authoritative product scope and principles |
| specification/05-product-requirements.md | Authoritative normative requirements |
| specification/08-glossary-and-domain-model.md | Authoritative terminology and identity model |
| specification/09-state-machines.md | Authoritative lifecycle transitions |
| specification/10-architecture.md | Architecture views and component responsibilities |
| specification/11-data-and-persistence.md | SQLite schema, transactions, and migrations |
| specification/12-scheduler-and-determinism.md | Clock, generator, schedule, and replay contracts |
| specification/13-http-and-signatures.md | Transport and signing contracts |
| specification/15-observer-and-assertions.md | Public observer wire protocol and assertion semantics |
| specification/16-interfaces-and-contracts.md | All internal/external boundaries |
| specification/18-security-privacy-threat-model.md | Threats, controls, residual risk, and tests |
| specification/21-test-strategy.md | Verification architecture and evidence |
| specification/28-traceability-matrix.md | Requirement-to-task-to-test links |
| specification/29-agentic-implementation-plan.md | Dependency-ordered implementation plan |
| validation/final-scorecard.md | Readiness verdict and measured quality gates |

## How a coding agent begins

1. Read `AGENTS.md` in full.
2. Read the work packet for the first dependency-ready task.
3. Verify that no higher-precedence artifact conflicts with the packet.
4. Edit only the allowed files.
5. Run every listed command and retain objective evidence.
6. Stop at the task boundary and hand off the evidence.

## Current first task

`TASK-0001 — Create package and quality-tool foundation` is first because every executable, schema validator, test, package, and coding-agent command depends on a locked source layout and reproducible toolchain. It does not decide public behavior.

## Validation claim

The generated workspace is validated by `validation/schema-validation.md` and `validation/cross-artifact-analysis.md`. Mermaid files receive structural checks only unless a Mermaid CLI is available; that limitation is reported rather than hidden.
