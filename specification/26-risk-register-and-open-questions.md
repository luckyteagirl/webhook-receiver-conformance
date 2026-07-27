# Risk Register and Open Questions

## Risks

| ID | Risk | Probability | Impact | Trigger | Mitigation | Owner | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RISK-001 | Observer adoption friction | medium | high | Pilot users refuse to add a command or test-only HTTP observer. | Keep protocol minimal, provide framework examples, and preserve transport-only scenarios as a valid subset. | DX maintainer | open |
| RISK-002 | Transport features are commoditized | high | high | Users compare the tool only to request replay or existing payment simulators. | Center onboarding and reports on business-state evidence, ambiguity, and deterministic manifests. | product maintainer | open |
| RISK-003 | Provider behavior drift | high | medium | Provider documentation, headers, or retry semantics change. | Version adapters, use official vectors, schedule documentation reviews, and avoid hard-coding provider retry policy into core. | adapter maintainer | open |
| RISK-004 | Ambiguous outcome misunderstood | medium | high | Users interpret resume as proof that an attempt did or did not execute. | Use explicit terminal vocabulary, stop by default, and render causal evidence prominently. | reliability maintainer | open |
| RISK-005 | Receiver nondeterminism causes flaky tests | high | high | External queues, clocks, or eventual consistency exceed polling assumptions. | Use bounded eventual assertions, distinguish environment errors, retain timing evidence, and prohibit hidden retries. | test architect | open |
| RISK-006 | DNS rebinding or target-policy bypass | low | critical | Resolved destination changes or redirects/proxies route to protected networks. | Disable redirects and trust_env, resolve every connection, block protected ranges, allowlist names and resolved addresses, and test rebinding. | security maintainer | open |
| RISK-007 | Sensitive data leaks into artifacts | medium | high | Error paths, duplicate headers, malformed bytes, or observer output bypass redaction. | Centralize evidence sanitization, minimize retention, run canary tests, and exclude raw evidence from default CI upload. | privacy maintainer | open |
| RISK-008 | SQLite durability assumptions differ by filesystem | low | high | Network or unusual filesystems do not honor required locking or fsync semantics. | Support local filesystems only in v0.1, preflight filesystem behavior where feasible, and document unsupported locations. | persistence maintainer | open |
| RISK-009 | Single writer limits future parallelism | low | medium | Measured runs need more than one mutating process per journal. | Keep journal repository interfaces explicit and revisit only with workload evidence. | architecture maintainer | accepted |
| RISK-010 | YAML ambiguity and unsafe tags | medium | medium | Different parsers coerce scalars or instantiate custom objects. | Use safe parsing, JSON-compatible values, strict models, and unknown-field rejection. | configuration maintainer | open |
| RISK-011 | Mutation combinations become uninterpretable | medium | high | A scenario applies several mutations and a failure has no isolated cause. | Require one-fault baselines, stage-aware conflict validation, and minimized reproductions. | scenario maintainer | open |
| RISK-012 | Command observer expands attack surface | medium | high | Shell interpolation, inherited secrets, unbounded output, or unsafe working directory. | argv-only execution, minimal environment, path containment, timeout, output caps, and explicit profile enablement. | security maintainer | open |
| RISK-013 | HTML report injection | medium | high | Fixture or receiver content is rendered as markup, URL, or script. | No script, context-aware escaping, restrictive CSP, no active links from untrusted data, and security regression corpus. | reporting maintainer | open |
| RISK-014 | Dependency or release compromise | low | high | Malicious dependency, build environment, or package upload. | Minimize dependencies, lock CI, scan, generate SBOMs, use trusted publishing, attest builds, and publish response policy. | release maintainer | open |
| RISK-015 | Cross-platform process semantics diverge | medium | medium | Signals, file locks, subprocess termination, or path rules differ on Windows. | Define portable abstractions, test hosted runners, and avoid POSIX-only process groups in normative behavior. | platform maintainer | open |
| RISK-016 | Manifest canonicalization is implemented incorrectly | low | high | Equivalent manifests hash differently or non-I-JSON values enter canonicalization. | Use RFC 8785 library or verified implementation, publish vectors, reject non-I-JSON values, and hash without self-referential fields. | determinism maintainer | open |
| RISK-017 | JUnit semantics lose causal detail | medium | medium | CI displays only one test case or conflates infrastructure errors with assertion failures. | Map one scenario to one testcase, use failure versus error deliberately, attach artifact references, and keep JSON authoritative. | reporting maintainer | open |
| RISK-018 | Performance caps are mistaken for load testing | medium | medium | Users direct high-volume traffic or cite results as receiver capacity evidence. | Validate purpose and caps, document limitations in CLI/report, and reject excessive concurrency. | product maintainer | open |
| RISK-019 | Reference flawed receivers have overlapping defects | medium | high | A scenario fails for an unintended reason, weakening test evidence. | One primary defect per variant, negative-control tests, and matrix assertions for unaffected scenarios. | test architect | open |
| RISK-020 | Autonomous agents diverge from contracts | medium | high | Tasks edit shared schemas or invent interfaces. | Exclusive ownership, dependency graph, work packets, schema-first tasks, architecture checks, and integration gates. | principal maintainer | open |

## Open questions

| ID | Question | Owner | Impact | Latest safe decision | Proposed default | Blocking | Status |
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

## Risk acceptance rules

- Critical/high implementation findings block the owning task and release.
- Product/adoption risks may remain open when they do not make the specification technically indeterminate.
- A deferred open question must have a safe default and latest decision point.
- Risk closure requires objective evidence, not only updated prose.
- Any trigger that invalidates a locked constraint requires product-level review rather than an implementation workaround.
