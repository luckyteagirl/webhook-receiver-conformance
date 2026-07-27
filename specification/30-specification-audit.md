# Specification Audit

## Review method

The pack was reviewed through ten lenses: staff architecture, distributed systems, application security, test architecture, Python maintenance, open-source adoption, agentic implementation, standards editing, privacy/secure logging, and overengineering. Findings were repaired at their owning artifact before downstream regeneration.

## Findings

| ID | Lens | Severity | Affected | Problem | Failure | Remediation | Owner | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FND-001 | distributed-systems reviewer | high | Earlier persistence decision / ADR-004 | WAL was selected despite one-writer workload and current WAL reset-race history. | Unnecessary checkpoint/recovery surface and version-sensitive risk. | Use rollback journal DELETE with synchronous EXTRA and one-owner run model. | ADR-004 and specification/11 | resolved | ADR-004, DATA/REL requirements, SQLite sources SRC-084..088. |
| FND-002 | standards editor | high | Determinism claims | Seed-only language could imply identical external execution. | False reproducibility claim. | Define realized manifest authority and explicit nondeterministic boundary. | specification/12 | resolved | ADR-021/023 and SCHED requirements. |
| FND-003 | application-security reviewer | high | Public destination support | Host allowlisting alone is insufficient for DNS rebinding and accidental production traffic. | SSRF or destructive test delivery. | Add all-address validation, pinned connection, exact runtime authorization, and receiver challenge. | specification/13 and 18 | resolved | SEC/HTTP requirements and target policy tests. |
| FND-004 | overengineering reviewer | high | Plugin model | A public generalized plugin API had no proven external implementations. | Premature compatibility, code-loading risk, and delayed completion. | Keep internal protocols; publish observer wire only. | ADR-022 | resolved | API/COMPAT requirements and v0.1 scope. |
| FND-005 | test architect | medium | Automated shrinking | General shrinking across external state and faults could produce invalid causal reductions. | A “minimal” reproduction no longer proves the same defect. | Defer general CLI shrinking; require proof rerun and parent/reduction log. | specification/14 and 20 | accepted | MVP scope and mutation minimization contract. |
| FND-006 | privacy reviewer | medium | Malformed payload redaction | JSON-pointer redaction cannot safely process invalid JSON. | Secret body content leaks into diagnostics. | Omit malformed raw content by default and persist digest/length only. | specification/18 | resolved | PRIV requirements and secret-canary corpus. |
| FND-007 | Python maintainer | medium | AnyIO backend promise | Claiming Trio parity would multiply test/compatibility surface without value. | Backend-specific defects and support burden. | Use AnyIO structured concurrency with required asyncio backend only. | ADR-003 | resolved | COMPAT and test matrix requirements. |
| FND-008 | open-source adopter | medium | Command tree | `plugins` and `clean` commands lacked a v0.1 user job. | Confusing UI and unsafe deletion semantics. | Omit both; expose version and manual contained deletion guidance. | specification/17 | resolved | CLI command acceptance tests. |

## Overengineering removals

- Replaced WAL/checkpoint subsystem with rollback-journal single-writer storage.
- Removed public dynamic plugin loading.
- Deferred asymmetric signatures, broad provider catalog, schema import, generic lifecycle orchestration, automatic shrinking, and native binary packaging.
- Removed runtime SARIF.
- Omitted browser UI, hosted services, PostgreSQL, message broker, Kubernetes, load testing, tunneling, request-bin capture, and gateway behavior.
- Limited virtual time to in-process tests.
- Kept FastAPI outside the core dependency graph.

## Work-packet simulation sample

Ten packets are sampled by the validation script across every phase. The audit verifies dependencies, file ownership, authoritative inputs, tests, commands, error cases, completion evidence, and bounded scope. Results are recorded in `validation/cross-artifact-analysis.md`.

## Residual findings

The public product name, external observer adoption friction, and exact future provider demand remain nonblocking product risks. Mermaid syntax receives structural validation unless a renderer is installed. These limitations cannot be honestly converted into closed implementation facts.

## Readiness rule

The final verdict is generated only after schema/example parsing, identifier/reference checks, task DAG validation, sampled packet audit, and finding severity checks. A failing gate produces `not ready` with exact remediation.


## Executed validation outcome

- Verdict: **READY FOR IMPLEMENTATION**
- Validation failures: 0
- Limited checks: 1
- Requirement records: 355
- Tasks / sampled packets: 75 / 10
- Traceability rows: 565

See `validation/schema-validation.md`, `validation/cross-artifact-analysis.md`, and `validation/final-scorecard.md`.
