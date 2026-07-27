# Artifact Index

**Specification:** 1.0.0-draft.1  
**Generated:** 2026-07-26

| Path | Authority | Validation |
| --- | --- | --- |
| README.md | Entry point, reading order, implementation status | Required |
| AGENTS.md | Binding instructions for coding agents | Required |
| specification/04-product-constitution.md | Authoritative product scope and principles | Required |
| specification/05-product-requirements.md | Authoritative normative requirements | Required |
| specification/08-glossary-and-domain-model.md | Authoritative terminology and identity model | Required |
| specification/09-state-machines.md | Authoritative lifecycle transitions | Required |
| specification/10-architecture.md | Architecture views and component responsibilities | Required |
| specification/11-data-and-persistence.md | SQLite schema, transactions, and migrations | Required |
| specification/12-scheduler-and-determinism.md | Clock, generator, schedule, and replay contracts | Required |
| specification/13-http-and-signatures.md | Transport and signing contracts | Required |
| specification/15-observer-and-assertions.md | Public observer wire protocol and assertion semantics | Required |
| specification/16-interfaces-and-contracts.md | All internal/external boundaries | Required |
| specification/18-security-privacy-threat-model.md | Threats, controls, residual risk, and tests | Required |
| specification/21-test-strategy.md | Verification architecture and evidence | Required |
| specification/28-traceability-matrix.md | Requirement-to-task-to-test links | Required |
| specification/29-agentic-implementation-plan.md | Dependency-ordered implementation plan | Required |
| validation/final-scorecard.md | Readiness verdict and measured quality gates | Required |

## Machine-readable authorities

| Path | Contents |
| --- | --- |
| machine/requirements.yaml | 355 normative requirements |
| machine/decisions.yaml | 25 architecture decisions |
| machine/traceability.csv / .json | 565 requirement-task-test links |
| machine/task-index.yaml | 75 implementation tasks |
| machine/risk-register.yaml | 20 risks and 10 open questions |
| machine/source-ledger.json | 120 source records |

## Status vocabulary

- **Authoritative:** owns a behavior or serialized contract.
- **Derived:** generated from an authoritative artifact and must be regenerated after changes.
- **Informational:** rationale or navigation; cannot override normative behavior.
- **Validated:** parsed and cross-referenced by the validation process.
