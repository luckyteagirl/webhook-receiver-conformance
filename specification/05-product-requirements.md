# Normative Product Requirements

**Specification version:** 1.0.0-draft.1

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in normative statements are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in all capitals.

Implementation priority uses `P0` through `P3` and is independent of BCP 14 normative strength.

## Inventory

| Family | Total | P0 | MVP required |
| --- | --- | --- | --- |
| API | 5 | 4 | 4 |
| ASSERT | 17 | 16 | 16 |
| CFG | 14 | 14 | 14 |
| CLI | 17 | 17 | 17 |
| COMPAT | 9 | 8 | 8 |
| DATA | 21 | 20 | 20 |
| DX | 10 | 10 | 10 |
| FR | 12 | 12 | 12 |
| HTTP | 26 | 26 | 26 |
| MUT | 22 | 19 | 19 |
| OBS | 22 | 20 | 20 |
| OPS | 14 | 14 | 14 |
| PERF | 9 | 9 | 9 |
| PRIV | 12 | 12 | 12 |
| REL | 16 | 16 | 16 |
| REPORT | 23 | 23 | 23 |
| SCHED | 19 | 18 | 18 |
| SEC | 35 | 35 | 35 |
| SIG | 18 | 16 | 16 |
| STATE | 14 | 14 | 14 |
| TEST | 20 | 19 | 19 |

## Requirement records

### FR-001 — Local execution

**Normative statement:** The core harness MUST execute a complete P0 run without contacting a hosted control plane.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI, ARC-COMPILER |
| Tasks | TASK-0311, TASK-0711 |
| Tests | VT-FR-001 |
| Verification | test |

**Rationale**

Offline-capable local and CI execution is a locked product boundary.

**Acceptance criteria**

- An end-to-end reference run succeeds with outbound networking blocked except for the configured local receiver.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-002 — Transport and state evidence separation

**Normative statement:** The harness MUST represent transport evidence separately from receiver-state evidence.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | SRC-064, SRC-075 |
| Constraints | CON-LOCK-003 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-HTTP, ARC-ASSERT |
| Tasks | TASK-0102, TASK-0508 |
| Tests | VT-FR-002 |
| Verification | test |

**Rationale**

An HTTP response cannot establish whether a business side effect occurred exactly once.

**Acceptance criteria**

- The result schema stores attempt evidence and observation evidence in different typed collections linked by identifiers.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-003 — Correct receiver corpus

**Normative statement:** The supported scenario corpus MUST pass against the correct reference receiver.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-007 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0701, TASK-0711 |
| Tests | VT-FR-003 |
| Verification | test |

**Rationale**

This requirement makes correct receiver corpus explicit and independently verifiable.

**Acceptance criteria**

- The complete P0 corpus produces a pass verdict and exit code 0 against REF-CORRECT-001.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-004 — Flawed receiver corpus

**Normative statement:** Each deliberately flawed reference receiver MUST fail only the scenarios mapped to its intentional defect.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-007 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0711 |
| Tests | VT-FR-004 |
| Verification | test |

**Rationale**

This requirement makes flawed receiver corpus explicit and independently verifiable.

**Acceptance criteria**

- The reference-corpus matrix matches every expected pass and failure with no unexplained failure.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-005 — No exactly-once claim

**Normative statement:** User-facing documentation MUST NOT describe network delivery as exactly once.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | SRC-075, SRC-076 |
| Constraints | CON-LOCK-008 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI, ARC-COMPILER |
| Tasks | TASK-0809 |
| Tests | VT-FR-005 |
| Verification | test |

**Rationale**

The harness can test idempotent processing but cannot establish exactly-once external side effects.

**Acceptance criteria**

- A repository-wide terminology test finds no prohibited exactly-once delivery claim outside explanatory rejection text.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-006 — Outcome classification

**Normative statement:** Every completed run MUST classify its terminal result as pass, receiver_failure, environment_error, harness_error, ambiguous, invalid_input, unsupported, or cancelled.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT, ARC-REPORT-JSON |
| Tasks | TASK-0508, TASK-0602 |
| Tests | VT-FR-006 |
| Verification | test |

**Rationale**

This requirement makes outcome classification explicit and independently verifiable.

**Acceptance criteria**

- Exactly one terminal result enum is present in every result summary.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-007 — Causal trace

**Normative statement:** Every reported failure MUST link the scenario, logical event, planned delivery, physical attempt, relevant observation, assertion, and evidence records.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-REPORT-JSON |
| Tasks | TASK-0601, TASK-0606 |
| Tests | VT-FR-007 |
| Verification | test |

**Rationale**

This requirement makes causal trace explicit and independently verifiable.

**Acceptance criteria**

- The inspect command traverses all required identifiers from a failed assertion without heuristic matching.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-008 — One-fault baseline

**Normative statement:** A multi-fault scenario MUST reference a passing or failing one-fault baseline for every included fault class.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-COMPILER |
| Tasks | TASK-0108 |
| Tests | VT-FR-008 |
| Verification | test |

**Rationale**

Combined failures are useful only when the resulting defect remains diagnosable.

**Acceptance criteria**

- Semantic validation rejects a multi-fault scenario that lacks required baseline scenario IDs.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-009 — Non-load-testing boundary

**Normative statement:** The runner MUST reject a configured concurrency greater than the documented conformance-testing hard limit.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-009 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG, ARC-SCHED |
| Tasks | TASK-0104, TASK-0303 |
| Tests | VT-FR-009 |
| Verification | test |

**Rationale**

This requirement makes non-load-testing boundary explicit and independently verifiable.

**Acceptance criteria**

- A concurrency value of 51 is rejected when the v0.1 hard limit is 50.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-010 — Provider-independent core

**Normative statement:** The core scenario model MUST NOT require a provider-specific event type.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-COMPILER, ARC-SIGN |
| Tasks | TASK-0108, TASK-0401 |
| Tests | VT-FR-010 |
| Verification | test |

**Rationale**

Provider adapters should enrich a generic event/delivery model rather than define it.

**Acceptance criteria**

- A raw-byte fixture using the generic signer executes without importing a provider package.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-011 — No external service for reports

**Normative statement:** Report generation MUST operate solely from the local run bundle and journal.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0605 |
| Tests | VT-FR-011 |
| Verification | test |

**Rationale**

This requirement makes no external service for reports explicit and independently verifiable.

**Acceptance criteria**

- Report regeneration succeeds while all network access is denied.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### FR-012 — Deterministic plan authority

**Normative statement:** The realized run bundle MUST be the authoritative input for replay.

| Field | Value |
| --- | --- |
| Type | FR |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001, GOAL-002, GOAL-006 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-004 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MANIFEST |
| Tasks | TASK-0109, TASK-0110 |
| Tests | VT-FR-012 |
| Verification | test |

**Rationale**

A seed alone does not freeze fixture ordering, plugin versions, serializer choices, or realized mutations.

**Acceptance criteria**

- Replay ignores changed source fixture files and uses only verified bundle blobs.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CFG-001 — Configuration format

**Normative statement:** The default project configuration MUST use YAML with a top-level schema_version field equal to 1.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0104, TASK-0105 |
| Tests | VT-CFG-001 |
| Verification | test |

**Rationale**

This requirement makes configuration format explicit and independently verifiable.

**Acceptance criteria**

- The minimal example parses and validates with schema_version 1.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CFG-002 — Duplicate YAML keys

**Normative statement:** The YAML loader MUST reject duplicate mapping keys before Pydantic validation.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0105 |
| Tests | VT-CFG-002 |
| Verification | test |

**Rationale**

Duplicate keys have parser-dependent overwrite behavior and obscure effective policy.

**Acceptance criteria**

- A fixture containing two receiver keys fails with a line-and-column diagnostic.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents policy-shadowing and ambiguous secret or target settings.

---

### CFG-003 — Unknown fields

**Normative statement:** Configuration models MUST reject unknown fields by default.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | SRC-024, SRC-025 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0104 |
| Tests | VT-CFG-003 |
| Verification | test |

**Rationale**

This requirement makes unknown fields explicit and independently verifiable.

**Acceptance criteria**

- A misspelled timeout field fails validation instead of being ignored.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CFG-004 — Custom YAML tags

**Normative statement:** The YAML loader MUST reject custom application tags.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0105 |
| Tests | VT-CFG-004 |
| Verification | test |

**Rationale**

This requirement makes custom yaml tags explicit and independently verifiable.

**Acceptance criteria**

- A !!python/object or unknown custom tag is rejected without object construction.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents unsafe deserialization.

---

### CFG-005 — Configuration precedence

**Normative statement:** Effective configuration MUST apply precedence in the order defaults, project file, environment secret references, and documented CLI overrides.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0105 |
| Tests | VT-CFG-005 |
| Verification | test |

**Rationale**

This requirement makes configuration precedence explicit and independently verifiable.

**Acceptance criteria**

- A precedence table test demonstrates the effective value at each layer.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CFG-006 — CLI override boundary

**Normative statement:** CLI overrides MUST be limited to run-scoped operational values documented in the configuration contract.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0105, TASK-0801 |
| Tests | VT-CFG-006 |
| Verification | test |

**Rationale**

This requirement makes cli override boundary explicit and independently verifiable.

**Acceptance criteria**

- A CLI attempt to override an undeclared signer or target-policy field is rejected.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CFG-007 — Environment secret references

**Normative statement:** Secret values MUST be resolved through explicit env references rather than generic string interpolation.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET |
| Tasks | TASK-0106 |
| Tests | VT-CFG-007 |
| Verification | test |

**Rationale**

This requirement makes environment secret references explicit and independently verifiable.

**Acceptance criteria**

- ${NAME}-style free-form interpolation remains literal while {env: NAME} resolves through the secret resolver.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Avoids accidental interpolation and leaking mixed secret/non-secret strings.

---

### CFG-008 — File secret references

**Normative statement:** Secret-file references MUST resolve to regular files confined to the configured secret roots.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET |
| Tasks | TASK-0106 |
| Tests | VT-CFG-008 |
| Verification | test |

**Rationale**

This requirement makes file secret references explicit and independently verifiable.

**Acceptance criteria**

- A symlink or traversal path outside the secret root is rejected.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents secret path traversal and symlink substitution.

---

### CFG-009 — Inline secret rejection

**Normative statement:** Plaintext signing keys in the project configuration MUST be rejected by default.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET |
| Tasks | TASK-0106 |
| Tests | VT-CFG-009 |
| Verification | test |

**Rationale**

This requirement makes inline secret rejection explicit and independently verifiable.

**Acceptance criteria**

- A literal secret field produces a diagnostic directing the user to env, file, or generated references.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces accidental source-control disclosure.

---

### CFG-010 — Relative path base

**Normative statement:** Relative fixture, report, observer, and lifecycle paths MUST resolve from the configuration file directory.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0105 |
| Tests | VT-CFG-010 |
| Verification | test |

**Rationale**

This requirement makes relative path base explicit and independently verifiable.

**Acceptance criteria**

- The same configuration resolves identically when invoked from a different current working directory.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CFG-011 — No includes in v0.1

**Normative statement:** The v0.1 configuration loader MUST NOT process includes, inheritance, anchors that cross files, or remote references.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0105 |
| Tests | VT-CFG-011 |
| Verification | test |

**Rationale**

Composition mechanisms add policy ambiguity, recursion, and file-loading attack surface.

**Acceptance criteria**

- Include-like keys and remote paths are rejected as unknown.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CFG-012 — Validation without traffic

**Normative statement:** Configuration validation MUST NOT resolve receiver DNS, execute observers, or send HTTP traffic.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0105, TASK-0801 |
| Tests | VT-CFG-012 |
| Verification | test |

**Rationale**

This requirement makes validation without traffic explicit and independently verifiable.

**Acceptance criteria**

- The validate command succeeds with network syscalls denied and observer executables unavailable.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Makes validation safe in untrusted CI review contexts.

---

### CFG-013 — Materialized configuration

**Normative statement:** The plan command MUST emit a redacted effective-configuration snapshot in the run bundle.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG, ARC-MANIFEST |
| Tasks | TASK-0109 |
| Tests | VT-CFG-013 |
| Verification | test |

**Rationale**

This requirement makes materialized configuration explicit and independently verifiable.

**Acceptance criteria**

- The snapshot contains resolved non-secret defaults and secret fingerprints but no secret values.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Supports auditability without credential disclosure.

---

### CFG-014 — Configuration migration

**Normative statement:** An unsupported configuration schema version MUST fail with a deterministic migration or compatibility diagnostic.

| Field | Value |
| --- | --- |
| Type | CFG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-006 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-001, UC-002, UC-003 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CONFIG |
| Tasks | TASK-0104, TASK-0801 |
| Tests | VT-CFG-014 |
| Verification | test |

**Rationale**

This requirement makes configuration migration explicit and independently verifiable.

**Acceptance criteria**

- schema_version 2 fails with exit code 6 and identifies the supported version range.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-001 — Initialize command

**Normative statement:** The CLI MUST provide `init` to create a minimal project skeleton without overwriting existing files.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0801 |
| Tests | VT-CLI-001 |
| Verification | test |

**Rationale**

This requirement makes initialize command explicit and independently verifiable.

**Acceptance criteria**

- `webhook-conformance init --help` exits 0 and the command contract test demonstrates its stated job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-002 — Validate command

**Normative statement:** The CLI MUST provide `validate` to validate configuration, fixtures, and schemas without sending traffic.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0801 |
| Tests | VT-CLI-002 |
| Verification | test |

**Rationale**

This requirement makes validate command explicit and independently verifiable.

**Acceptance criteria**

- `webhook-conformance validate --help` exits 0 and the command contract test demonstrates its stated job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-003 — Plan command

**Normative statement:** The CLI MUST provide `plan` to create and validate an immutable realized run bundle without sending traffic.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0109, TASK-0801 |
| Tests | VT-CLI-003 |
| Verification | test |

**Rationale**

This requirement makes plan command explicit and independently verifiable.

**Acceptance criteria**

- `webhook-conformance plan --help` exits 0 and the command contract test demonstrates its stated job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-004 — Run command

**Normative statement:** The CLI MUST provide `run` to compile or load a bundle and execute its eligible work.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0311, TASK-0801 |
| Tests | VT-CLI-004 |
| Verification | test |

**Rationale**

This requirement makes run command explicit and independently verifiable.

**Acceptance criteria**

- `webhook-conformance run --help` exits 0 and the command contract test demonstrates its stated job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-005 — Resume command

**Normative statement:** The CLI MUST provide `resume` to resume a named interrupted run under an explicit ambiguity policy.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0207, TASK-0801 |
| Tests | VT-CLI-005 |
| Verification | test |

**Rationale**

This requirement makes resume command explicit and independently verifiable.

**Acceptance criteria**

- `webhook-conformance resume --help` exits 0 and the command contract test demonstrates its stated job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-006 — Replay command

**Normative statement:** The CLI MUST provide `replay` to execute a verified existing run bundle without random generation.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0110, TASK-0801 |
| Tests | VT-CLI-006 |
| Verification | test |

**Rationale**

This requirement makes replay command explicit and independently verifiable.

**Acceptance criteria**

- `webhook-conformance replay --help` exits 0 and the command contract test demonstrates its stated job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-007 — Inspect command

**Normative statement:** The CLI MUST provide `inspect` to query a run and print a causal evidence view without network access.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0606, TASK-0801 |
| Tests | VT-CLI-007 |
| Verification | test |

**Rationale**

This requirement makes inspect command explicit and independently verifiable.

**Acceptance criteria**

- `webhook-conformance inspect --help` exits 0 and the command contract test demonstrates its stated job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-008 — Report command

**Normative statement:** The CLI MUST provide `report` to regenerate selected report formats from the journal.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0606, TASK-0801 |
| Tests | VT-CLI-008 |
| Verification | test |

**Rationale**

This requirement makes report command explicit and independently verifiable.

**Acceptance criteria**

- `webhook-conformance report --help` exits 0 and the command contract test demonstrates its stated job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-009 — Version command

**Normative statement:** The CLI MUST provide `version` to print tool, schema, manifest, and embedded SQLite versions.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0801 |
| Tests | VT-CLI-009 |
| Verification | test |

**Rationale**

This requirement makes version command explicit and independently verifiable.

**Acceptance criteria**

- `webhook-conformance version --help` exits 0 and the command contract test demonstrates its stated job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-010 — Standard output

**Normative statement:** Machine-readable command results MUST be written to stdout only when explicitly selected.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0801 |
| Tests | VT-CLI-010 |
| Verification | test |

**Rationale**

This requirement makes standard output explicit and independently verifiable.

**Acceptance criteria**

- JSON mode emits one valid JSON document on stdout and sends progress and diagnostics to stderr.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-011 — Standard error

**Normative statement:** Human diagnostics and progress MUST be written to stderr.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0801 |
| Tests | VT-CLI-011 |
| Verification | test |

**Rationale**

This requirement makes standard error explicit and independently verifiable.

**Acceptance criteria**

- A failed validation leaves stdout empty in default mode and writes the diagnostic to stderr.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-012 — Non-interactive CI mode

**Normative statement:** The CLI MUST provide a non-interactive mode that never waits for terminal input.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0801 |
| Tests | VT-CLI-012 |
| Verification | test |

**Rationale**

This requirement makes non-interactive ci mode explicit and independently verifiable.

**Acceptance criteria**

- CI mode fails closed when a confirmation would otherwise be required.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-013 — Color policy

**Normative statement:** Color output MUST default to automatic TTY detection and honor NO_COLOR.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0801 |
| Tests | VT-CLI-013 |
| Verification | test |

**Rationale**

This requirement makes color policy explicit and independently verifiable.

**Acceptance criteria**

- Captured output and NO_COLOR output contain no ANSI escape sequences.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents terminal-control leakage into logs.

---

### CLI-014 — Traceback policy

**Normative statement:** Unhandled implementation tracebacks MUST be hidden by default and enabled only by an explicit diagnostic option.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0002, TASK-0801 |
| Tests | VT-CLI-014 |
| Verification | test |

**Rationale**

This requirement makes traceback policy explicit and independently verifiable.

**Acceptance criteria**

- A forced internal error prints an incident ID by default and a traceback only with --debug or the documented environment variable.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Avoids leaking paths, environment data, or fixture content.

---

### CLI-015 — Cancellation exit status

**Normative statement:** A user or CI cancellation MUST return process exit code 130 after bounded cleanup.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0310, TASK-0801 |
| Tests | VT-CLI-015 |
| Verification | test |

**Rationale**

This requirement makes cancellation exit status explicit and independently verifiable.

**Acceptance criteria**

- SIGINT during an active attempt exits 130 and leaves a resumable journal.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-016 — Stable exit codes

**Normative statement:** The CLI MUST implement the documented stable exit-code table without command-specific reinterpretation.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0602, TASK-0801 |
| Tests | VT-CLI-016 |
| Verification | test |

**Rationale**

This requirement makes stable exit codes explicit and independently verifiable.

**Acceptance criteria**

- Each terminal result category maps to exactly one documented exit code across run, resume, and replay.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### CLI-017 — Public target authorization

**Normative statement:** A public-target run MUST require the exact hostname to be repeated through a non-interactive authorization argument.

| Field | Value |
| --- | --- |
| Type | CLI |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-005, GOAL-006 |
| Use cases | UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-CLI |
| Tasks | TASK-0307, TASK-0801 |
| Tests | VT-CLI-017 |
| Verification | test |

**Rationale**

This requirement makes public target authorization explicit and independently verifiable.

**Acceptance criteria**

- A public target fails before preflight when the authorization argument is absent or does not match.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents accidental targeting of public or production systems.

---

### API-001 — Typed internal boundaries

**Normative statement:** Every cross-module service boundary MUST use typed request and result models rather than unstructured dictionaries.

| Field | Value |
| --- | --- |
| Type | API |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006, STAKE-007 |
| Goals | GOAL-006 |
| Use cases | UC-003, UC-004, UC-009, UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-COMPILER |
| Tasks | TASK-0002, TASK-0102 |
| Tests | VT-API-001 |
| Verification | test |

**Rationale**

This requirement makes typed internal boundaries explicit and independently verifiable.

**Acceptance criteria**

- Static type checking reports no untyped public service method and contract tests cover serialization boundaries.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### API-002 — Stable error categories

**Normative statement:** Internal exceptions crossing a module boundary MUST be translated into the documented error taxonomy.

| Field | Value |
| --- | --- |
| Type | API |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006, STAKE-007 |
| Goals | GOAL-006 |
| Use cases | UC-003, UC-004, UC-009, UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-COMPILER |
| Tasks | TASK-0002 |
| Tests | VT-API-002 |
| Verification | test |

**Rationale**

This requirement makes stable error categories explicit and independently verifiable.

**Acceptance criteria**

- Fault injection in each major component produces a documented error category at the runner boundary.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### API-003 — No public plugin API in v0.1

**Normative statement:** The v0.1 package MUST NOT expose third-party plugin discovery as a supported compatibility surface.

| Field | Value |
| --- | --- |
| Type | API |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006, STAKE-007 |
| Goals | GOAL-006 |
| Use cases | UC-003, UC-004, UC-009, UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-COMPILER |
| Tasks | TASK-0001 |
| Tests | VT-API-003 |
| Verification | test |

**Rationale**

Two concrete external implementations do not yet exist for each proposed extension category.

**Acceptance criteria**

- No entry-point group is loaded by the v0.1 runtime.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### API-004 — Internal strategy interfaces

**Normative statement:** Built-in signer and observer implementations MUST conform to internal Protocol interfaces covered by contract tests.

| Field | Value |
| --- | --- |
| Type | API |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006, STAKE-007 |
| Goals | GOAL-006 |
| Use cases | UC-003, UC-004, UC-009, UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN, ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0401, TASK-0501 |
| Tests | VT-API-004 |
| Verification | test |

**Rationale**

This requirement makes internal strategy interfaces explicit and independently verifiable.

**Acceptance criteria**

- Every built-in implementation passes the same protocol conformance suite.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### API-005 — Deferred plugin metadata

**Normative statement:** A future plugin metadata schema MUST remain marked experimental until a public plugin ADR is approved.

| Field | Value |
| --- | --- |
| Type | API |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-006, STAKE-007 |
| Goals | GOAL-006 |
| Use cases | UC-003, UC-004, UC-009, UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-COMPILER |
| Tasks | TASK-0810 |
| Tests | VT-API-005 |
| Verification | test |

**Rationale**

This requirement makes deferred plugin metadata explicit and independently verifiable.

**Acceptance criteria**

- plugin-metadata.schema.json contains an experimental stability enum and is unused by v0.1 runtime discovery.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-001 — Run directory

**Normative statement:** Each execution MUST store its mutable journal and generated artifacts in a unique run directory.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0201, TASK-0311 |
| Tests | VT-DATA-001 |
| Verification | test |

**Rationale**

This requirement makes run directory explicit and independently verifiable.

**Acceptance criteria**

- Two executions of one bundle create distinct run directories and never share a database file.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-002 — Run identifier

**Normative statement:** A run identifier MUST be a UUIDv4 generated independently for each execution.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MANIFEST, ARC-JOURNAL |
| Tasks | TASK-0101, TASK-0109 |
| Tests | VT-DATA-002 |
| Verification | test |

**Rationale**

This requirement makes run identifier explicit and independently verifiable.

**Acceptance criteria**

- Replay creates a new run_id while preserving the same manifest_id.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-003 — Content-addressed fixture blobs

**Normative statement:** Every planned request body MUST reference a SHA-256-addressed immutable blob in the run bundle.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-FIXTURE, ARC-MANIFEST |
| Tasks | TASK-0107, TASK-0109 |
| Tests | VT-DATA-003 |
| Verification | test |

**Rationale**

This requirement makes content-addressed fixture blobs explicit and independently verifiable.

**Acceptance criteria**

- Changing one byte changes the blob digest and causes bundle verification to fail until re-planned.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-004 — Manifest immutability

**Normative statement:** A realized manifest MUST NOT be modified after its manifest identifier is computed.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MANIFEST |
| Tasks | TASK-0109, TASK-0110 |
| Tests | VT-DATA-004 |
| Verification | test |

**Rationale**

This requirement makes manifest immutability explicit and independently verifiable.

**Acceptance criteria**

- The loader rejects a manifest whose canonical content no longer matches manifest_id.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-005 — Canonical manifest hash

**Normative statement:** The manifest identifier MUST be the lowercase hexadecimal SHA-256 digest of its RFC 8785 canonical form with manifest_id omitted.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | SRC-018 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MANIFEST |
| Tasks | TASK-0101, TASK-0109 |
| Tests | VT-DATA-005 |
| Verification | test |

**Rationale**

This requirement makes canonical manifest hash explicit and independently verifiable.

**Acceptance criteria**

- Cross-language golden vectors produce the documented digest.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-006 — Stable entity identifiers

**Normative statement:** Scenario, logical-event, planned-delivery, attempt-plan, observation-plan, and assertion identifiers MUST use the versioned domain-separated identifier algorithm.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PRNG, ARC-MANIFEST |
| Tasks | TASK-0101, TASK-0103 |
| Tests | VT-DATA-006 |
| Verification | test |

**Rationale**

This requirement makes stable entity identifiers explicit and independently verifiable.

**Acceptance criteria**

- Golden vectors remain stable across supported Python versions and insertion of unrelated entities.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-007 — Schema versions

**Normative statement:** Every persisted JSON or JSON Lines record MUST contain an explicit schema_version.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0003, TASK-0601 |
| Tests | VT-DATA-007 |
| Verification | test |

**Rationale**

This requirement makes schema versions explicit and independently verifiable.

**Acceptance criteria**

- Schema validation rejects a persisted record without schema_version.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-008 — Foreign keys

**Normative statement:** The SQLite journal MUST enforce foreign-key constraints on every connection.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | SRC-085 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0202 |
| Tests | VT-DATA-008 |
| Verification | test |

**Rationale**

This requirement makes foreign keys explicit and independently verifiable.

**Acceptance criteria**

- An orphan attempt insert fails and PRAGMA foreign_keys reports 1.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-009 — State projection constraints

**Normative statement:** Current-state projection tables MUST enforce valid state values and uniqueness scopes in SQL.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0201, TASK-0203 |
| Tests | VT-DATA-009 |
| Verification | test |

**Rationale**

This requirement makes state projection constraints explicit and independently verifiable.

**Acceptance criteria**

- Direct insertion of an invalid state or duplicate scoped identifier fails at the database boundary.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-010 — Append-oriented transition history

**Normative statement:** Every state change MUST append an immutable transition record.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0203 |
| Tests | VT-DATA-010 |
| Verification | test |

**Rationale**

This requirement makes append-oriented transition history explicit and independently verifiable.

**Acceptance criteria**

- A completed attempt has an ordered transition history that can reconstruct its current state.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-011 — Atomic transition projection

**Normative statement:** A transition append and its current-state projection update MUST commit in one SQLite transaction.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0203, TASK-0806 |
| Tests | VT-DATA-011 |
| Verification | test |

**Rationale**

This requirement makes atomic transition projection explicit and independently verifiable.

**Acceptance criteria**

- Crash injection cannot produce a transition without its projection or a projection without its transition.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-012 — Rollback journal mode

**Normative statement:** The journal connection MUST set and verify journal_mode=DELETE.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | SRC-084, SRC-085, SRC-086 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0202 |
| Tests | VT-DATA-012 |
| Verification | test |

**Rationale**

The workload is single-writer and values crash simplicity over WAL read concurrency.

**Acceptance criteria**

- Startup fails if SQLite does not report delete mode after configuration.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-013 — Extra synchronous durability

**Normative statement:** The journal connection MUST set and verify synchronous=EXTRA.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | SRC-085 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0202 |
| Tests | VT-DATA-013 |
| Verification | test |

**Rationale**

This requirement makes extra synchronous durability explicit and independently verifiable.

**Acceptance criteria**

- Connection initialization reads PRAGMA synchronous as 3.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-014 — Explicit write transactions

**Normative statement:** Every journal mutation batch MUST begin with BEGIN IMMEDIATE and end with explicit COMMIT or ROLLBACK.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | SRC-029, SRC-088 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0202, TASK-0203 |
| Tests | VT-DATA-014 |
| Verification | test |

**Rationale**

This requirement makes explicit write transactions explicit and independently verifiable.

**Acceptance criteria**

- A SQL trace test finds no implicit write transaction in the journal repository.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-015 — Single writer

**Normative statement:** All SQLite writes MUST pass through one in-process journal service.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0202 |
| Tests | VT-DATA-015 |
| Verification | test |

**Rationale**

One serialized writer matches SQLite semantics and removes lease/checkpoint complexity.

**Acceptance criteria**

- Concurrent callers are serialized and no second write connection is opened.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-016 — Local filesystem support

**Normative statement:** The journal MUST reject an explicitly configured network-filesystem path when the platform can identify it.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | SRC-084, SRC-087 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0204 |
| Tests | VT-DATA-016 |
| Verification | test |

**Rationale**

This requirement makes local filesystem support explicit and independently verifiable.

**Acceptance criteria**

- A detected network mount fails with unsupported status before database creation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces locking and durability failures on unsupported storage.

---

### DATA-017 — Forward-only migrations

**Normative statement:** Database migrations MUST be ordered, checksummed, transactional, and forward-only.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0201 |
| Tests | VT-DATA-017 |
| Verification | test |

**Rationale**

This requirement makes forward-only migrations explicit and independently verifiable.

**Acceptance criteria**

- A changed applied migration checksum aborts startup; a new migration applies once and records its checksum.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-018 — Resume integrity check

**Normative statement:** Resume MUST run PRAGMA quick_check and foreign_key_check before scheduling work.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0205, TASK-0207 |
| Tests | VT-DATA-018 |
| Verification | test |

**Rationale**

This requirement makes resume integrity check explicit and independently verifiable.

**Acceptance criteria**

- A deliberately corrupt or referentially invalid database fails with harness_error before delivery.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-019 — Artifact digest registry

**Normative statement:** Every generated artifact MUST be registered with relative path, media type, size, and SHA-256 digest.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0205, TASK-0605 |
| Tests | VT-DATA-019 |
| Verification | test |

**Rationale**

This requirement makes artifact digest registry explicit and independently verifiable.

**Acceptance criteria**

- Regeneration updates the registry transactionally and every registered digest matches the file.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-020 — Atomic artifact replacement

**Normative statement:** Generated artifacts MUST be written to a sibling temporary file and atomically replaced after flush and fsync where supported.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0605, TASK-0806 |
| Tests | VT-DATA-020 |
| Verification | test |

**Rationale**

This requirement makes atomic artifact replacement explicit and independently verifiable.

**Acceptance criteria**

- Report-generation termination leaves either the old valid artifact or the new valid artifact, never a partial target file.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DATA-021 — Retention command

**Normative statement:** A run-deletion operation MUST be bound to an explicit run identifier and remain confined to the resolved run root.

| Field | Value |
| --- | --- |
| Type | DATA |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-004, STAKE-006 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-004, UC-005, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL |
| Tasks | TASK-0801 |
| Tests | VT-DATA-021 |
| Verification | test |

**Rationale**

This requirement makes retention command explicit and independently verifiable.

**Acceptance criteria**

- A deletion test leaves external symlink targets unchanged.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents destructive path traversal.

---

### STATE-001 — Run states

**Normative statement:** A run MUST use only planned, running, paused, completed, cancelled, or failed as its current state.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0201, TASK-0203 |
| Tests | VT-STATE-001 |
| Verification | test |

**Rationale**

This requirement makes run states explicit and independently verifiable.

**Acceptance criteria**

- The run-state transition table rejects every undeclared state value.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-002 — Scenario states

**Normative statement:** A scenario MUST use only pending, eligible, running, passed, failed, error, skipped, ambiguous, or cancelled as its current state.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203 |
| Tests | VT-STATE-002 |
| Verification | test |

**Rationale**

This requirement makes scenario states explicit and independently verifiable.

**Acceptance criteria**

- Scenario projection tests cover every legal and illegal transition.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-003 — Planned delivery states

**Normative statement:** A planned delivery MUST use only pending, eligible, active, satisfied, exhausted, ambiguous, cancelled, or skipped as its current state.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203 |
| Tests | VT-STATE-003 |
| Verification | test |

**Rationale**

This requirement makes planned delivery states explicit and independently verifiable.

**Acceptance criteria**

- The delivery state machine cannot become satisfied without a qualifying terminal attempt or explicit assertion policy.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-004 — Attempt states

**Normative statement:** A physical attempt MUST use only scheduled, claimed, pre_send_committed, connecting, sending, awaiting_response, response_observed, not_sent, succeeded, rejected, transport_failed, unknown_outcome, or cancelled as its current state.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203, TASK-0309 |
| Tests | VT-STATE-004 |
| Verification | test |

**Rationale**

This requirement makes attempt states explicit and independently verifiable.

**Acceptance criteria**

- The attempt-state model and SQL checks contain the same state set.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-005 — Observation states

**Normative statement:** An observer sample MUST use only scheduled, running, ok, pending, unsupported, error, timed_out, or cancelled as its current state.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203, TASK-0504 |
| Tests | VT-STATE-005 |
| Verification | test |

**Rationale**

This requirement makes observation states explicit and independently verifiable.

**Acceptance criteria**

- Observer lifecycle tests cover every terminal classification.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-006 — Assertion states

**Normative statement:** An assertion evaluation MUST use only pending, running, passed, failed, error, unsupported, or cancelled as its current state.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203, TASK-0508 |
| Tests | VT-STATE-006 |
| Verification | test |

**Rationale**

This requirement makes assertion states explicit and independently verifiable.

**Acceptance criteria**

- Assertion lifecycle tests cover every terminal classification.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-007 — Illegal transition rejection

**Normative statement:** The journal MUST reject every state transition absent from the authoritative transition table.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203 |
| Tests | VT-STATE-007 |
| Verification | test |

**Rationale**

This requirement makes illegal transition rejection explicit and independently verifiable.

**Acceptance criteria**

- Property tests generate state pairs and confirm only declared edges commit.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-008 — Transition trigger evidence

**Normative statement:** Every transition record MUST store the trigger category and causal record identifier when one exists.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203 |
| Tests | VT-STATE-008 |
| Verification | test |

**Rationale**

This requirement makes transition trigger evidence explicit and independently verifiable.

**Acceptance criteria**

- A retry transition points to the predecessor attempt outcome that made it eligible.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-009 — Transition timestamps

**Normative statement:** Every transition MUST store a UTC wall timestamp and an execution-relative monotonic nanosecond value when produced during a live run.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203, TASK-0301 |
| Tests | VT-STATE-009 |
| Verification | test |

**Rationale**

This requirement makes transition timestamps explicit and independently verifiable.

**Acceptance criteria**

- Live transitions contain both fields while imported historical records explicitly mark unavailable monotonic values.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-010 — Terminal immutability

**Normative statement:** A terminal state MUST NOT transition to a nonterminal state.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203 |
| Tests | VT-STATE-010 |
| Verification | test |

**Rationale**

This requirement makes terminal immutability explicit and independently verifiable.

**Acceptance criteria**

- All terminal-to-nonterminal transition attempts fail atomically.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-011 — Ambiguous attempt terminality

**Normative statement:** unknown_outcome MUST be terminal for a physical attempt.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-005 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203, TASK-0206 |
| Tests | VT-STATE-011 |
| Verification | test |

**Rationale**

Any later redelivery is a new physical attempt, not a rewrite of uncertain history.

**Acceptance criteria**

- Resume never changes an unknown attempt to succeeded or failed.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-012 — No silent scheduled work loss

**Normative statement:** A run MUST NOT become completed while any required planned delivery is pending, eligible, active, or ambiguous.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203, TASK-0508 |
| Tests | VT-STATE-012 |
| Verification | test |

**Rationale**

This requirement makes no silent scheduled work loss explicit and independently verifiable.

**Acceptance criteria**

- Completion is rejected until every required delivery is terminal under policy.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-013 — Projection reconstruction

**Normative statement:** Current-state projections MUST be reproducible from ordered transition records.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0203, TASK-0806 |
| Tests | VT-STATE-013 |
| Verification | test |

**Rationale**

This requirement makes projection reconstruction explicit and independently verifiable.

**Acceptance criteria**

- A rebuild test deletes projections, replays transitions into a temporary database, and obtains identical rows.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### STATE-014 — State diagram parity

**Normative statement:** The executable transition tables MUST match the state diagrams and normative state requirements.

| Field | Value |
| --- | --- |
| Type | STATE |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-004, UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-JOURNAL, ARC-RECOVERY |
| Tasks | TASK-0003, TASK-0203 |
| Tests | VT-STATE-014 |
| Verification | test |

**Rationale**

This requirement makes state diagram parity explicit and independently verifiable.

**Acceptance criteria**

- A generated comparison test detects any diagram/table mismatch.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-001 — Wall clock

**Normative statement:** UTC wall time MUST be used only for human/audit timestamps and replay-window inputs explicitly defined by a signer.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK |
| Tasks | TASK-0301 |
| Tests | VT-SCHED-001 |
| Verification | test |

**Rationale**

This requirement makes wall clock explicit and independently verifiable.

**Acceptance criteria**

- Scheduler ordering remains unchanged when the system wall clock jumps.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-002 — Monotonic clock

**Normative statement:** Physical durations, timeouts, and polling deadlines MUST use a monotonic clock.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | SRC-020, SRC-022 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK |
| Tasks | TASK-0301 |
| Tests | VT-SCHED-002 |
| Verification | test |

**Rationale**

This requirement makes monotonic clock explicit and independently verifiable.

**Acceptance criteria**

- A simulated wall-clock jump does not change a timeout result.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-003 — Logical clock

**Normative statement:** Scenario schedule offsets MUST use signed 64-bit integer nanoseconds relative to logical time origin zero.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK |
| Tasks | TASK-0104, TASK-0301 |
| Tests | VT-SCHED-003 |
| Verification | test |

**Rationale**

This requirement makes logical clock explicit and independently verifiable.

**Acceptance criteria**

- Schema validation rejects overflow and fractional logical durations.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-004 — Real mode

**Normative statement:** Real clock mode MUST map one logical second to one physical second.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0301 |
| Tests | VT-SCHED-004 |
| Verification | test |

**Rationale**

This requirement makes real mode explicit and independently verifiable.

**Acceptance criteria**

- A 100-millisecond logical wait completes within the documented test tolerance in real mode.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-005 — Scaled mode

**Normative statement:** Scaled clock mode MUST multiply positive logical waits by a configured scale in the inclusive range 0.001 through 100.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0104, TASK-0301 |
| Tests | VT-SCHED-005 |
| Verification | test |

**Rationale**

This requirement makes scaled mode explicit and independently verifiable.

**Acceptance criteria**

- A scale outside the range fails validation and a scale of 0.01 maps 10 logical seconds to 100 physical milliseconds.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-006 — No virtual external network mode

**Normative statement:** The v0.1 runner MUST NOT claim virtual-time control over an external receiver.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0104, TASK-0301 |
| Tests | VT-SCHED-006 |
| Verification | test |

**Rationale**

An external process may use its own wall clock, timers, queues, and services.

**Acceptance criteria**

- Virtual mode is available only to unit-test clock implementations and is rejected in project configuration.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-007 — Physical timeout independence

**Normative statement:** HTTP and observer timeouts MUST remain physical monotonic durations in scaled mode.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0301, TASK-0308 |
| Tests | VT-SCHED-007 |
| Verification | test |

**Rationale**

This requirement makes physical timeout independence explicit and independently verifiable.

**Acceptance criteria**

- Changing the schedule scale does not change a configured 2-second HTTP timeout.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-008 — Generator algorithm

**Normative statement:** The deterministic generator MUST use HMAC-SHA256 with the algorithm identifier hmac-sha256-context-v1.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | SRC-113 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PRNG |
| Tasks | TASK-0103 |
| Tests | VT-SCHED-008 |
| Verification | test |

**Rationale**

This requirement makes generator algorithm explicit and independently verifiable.

**Acceptance criteria**

- Published golden vectors match on Python 3.12, 3.13, and 3.14.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-009 — Generator domain separation

**Normative statement:** Every deterministic draw MUST include a versioned context path unique to its semantic purpose.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PRNG |
| Tasks | TASK-0103 |
| Tests | VT-SCHED-009 |
| Verification | test |

**Rationale**

This requirement makes generator domain separation explicit and independently verifiable.

**Acceptance criteria**

- Adding an unrelated event does not change existing IDs, jitter, or mutation values.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-010 — Seed normalization

**Normative statement:** A textual seed MUST be UTF-8 encoded and SHA-256 hashed into the generator key.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PRNG |
| Tasks | TASK-0103 |
| Tests | VT-SCHED-010 |
| Verification | test |

**Rationale**

This requirement makes seed normalization explicit and independently verifiable.

**Acceptance criteria**

- Equivalent byte input through text and explicit seed-hash forms yields the documented normalized key.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-011 — Seed persistence

**Normative statement:** The normalized non-secret seed MUST be stored in the realized manifest.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MANIFEST |
| Tasks | TASK-0109 |
| Tests | VT-SCHED-011 |
| Verification | test |

**Rationale**

This requirement makes seed persistence explicit and independently verifiable.

**Acceptance criteria**

- Replay can verify all deterministic outputs without the original config file.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-012 — Unbiased bounded integers

**Normative statement:** Bounded random integer selection MUST use rejection sampling rather than modulo reduction.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PRNG |
| Tasks | TASK-0103 |
| Tests | VT-SCHED-012 |
| Verification | test |

**Rationale**

This requirement makes unbiased bounded integers explicit and independently verifiable.

**Acceptance criteria**

- Property tests confirm every value is in range and golden vectors define rejection behavior.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-013 — Deterministic jitter

**Normative statement:** Retry jitter MUST be derived from scenario ID, planned delivery ID, attempt ordinal, and jitter-policy version.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0103, TASK-0304 |
| Tests | VT-SCHED-013 |
| Verification | test |

**Rationale**

This requirement makes deterministic jitter explicit and independently verifiable.

**Acceptance criteria**

- The same bundle yields the same signed jitter value regardless of task execution order.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-014 — Stable tie breaking

**Normative statement:** Equal logical due times MUST be ordered by scenario ordinal, step ordinal, planned delivery ordinal, and attempt ordinal.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0302 |
| Tests | VT-SCHED-014 |
| Verification | test |

**Rationale**

This requirement makes stable tie breaking explicit and independently verifiable.

**Acceptance criteria**

- A golden schedule with equal due times remains byte-identical across supported platforms.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-015 — Concurrency group semantics

**Normative statement:** A concurrency group MUST mean eligible tasks are released from one barrier without asserting simultaneous arrival or completion.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0303 |
| Tests | VT-SCHED-015 |
| Verification | test |

**Rationale**

This requirement makes concurrency group semantics explicit and independently verifiable.

**Acceptance criteria**

- Reports label actual monotonic start times and never use the term simultaneous as a guarantee.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-016 — Retry ownership

**Normative statement:** The scheduler MUST be the sole component that creates retry attempts.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0304, TASK-0308 |
| Tests | VT-SCHED-016 |
| Verification | test |

**Rationale**

This requirement makes retry ownership explicit and independently verifiable.

**Acceptance criteria**

- HTTP transport retries are disabled and every second attempt has a journaled retry decision.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-017 — Conditional attempt plans

**Normative statement:** A realized manifest MUST store retry attempts as deterministic conditional templates with predecessor predicates and delays.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MANIFEST, ARC-SCHED |
| Tasks | TASK-0109, TASK-0304 |
| Tests | VT-SCHED-017 |
| Verification | test |

**Rationale**

This requirement makes conditional attempt plans explicit and independently verifiable.

**Acceptance criteria**

- Manifest replay makes the same next-attempt decision for the same predecessor result.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-018 — Pause persistence

**Normative statement:** A pause or process stop MUST leave every not-yet-started work item represented in persistent schedule state.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0302, TASK-0207 |
| Tests | VT-SCHED-018 |
| Verification | test |

**Rationale**

This requirement makes pause persistence explicit and independently verifiable.

**Acceptance criteria**

- Resume schedules every due item exactly once unless policy creates an explicit new physical attempt.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SCHED-019 — System clock change evidence

**Normative statement:** A detected wall-clock discontinuity greater than five seconds MUST be recorded as a run event.

| Field | Value |
| --- | --- |
| Type | SCHED |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-004 |
| Goals | GOAL-001, GOAL-003 |
| Use cases | UC-003, UC-004, UC-006 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLOCK, ARC-SCHED |
| Tasks | TASK-0301 |
| Tests | VT-SCHED-019 |
| Verification | test |

**Rationale**

This requirement makes system clock change evidence explicit and independently verifiable.

**Acceptance criteria**

- A clock-injection test records the discontinuity while monotonic scheduling continues.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-001 — Supported request method

**Normative statement:** The v0.1 executor MUST send webhook deliveries with HTTP POST.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0104, TASK-0308 |
| Tests | VT-HTTP-001 |
| Verification | test |

**Rationale**

This requirement makes supported request method explicit and independently verifiable.

**Acceptance criteria**

- Project configuration rejects other methods in v0.1.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-002 — URL scheme

**Normative statement:** A receiver URL MUST be an http or https URL without userinfo or a fragment.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET |
| Tasks | TASK-0305 |
| Tests | VT-HTTP-002 |
| Verification | test |

**Rationale**

This requirement makes url scheme explicit and independently verifiable.

**Acceptance criteria**

- ftp, embedded credentials, and fragment-bearing URLs fail validation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-003 — Exact request body

**Normative statement:** The executor MUST send the exact realized body bytes referenced by the attempt plan.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | SRC-001, SRC-003, SRC-006, SRC-013 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-003 |
| Verification | test |

**Rationale**

This requirement makes exact request body explicit and independently verifiable.

**Acceptance criteria**

- A capture receiver computes the same SHA-256 digest as the manifest blob reference.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-004 — Header semantics

**Normative statement:** Header matching and policy checks MUST treat field names case-insensitively.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | SRC-111 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-004 |
| Verification | test |

**Rationale**

This requirement makes header semantics explicit and independently verifiable.

**Acceptance criteria**

- Mixed-case variants produce identical policy and assertion behavior.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-005 — Header evidence

**Normative statement:** Attempt evidence MUST preserve configured header order and display spelling while treating generated transport headers separately.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-005 |
| Verification | test |

**Rationale**

This requirement makes header evidence explicit and independently verifiable.

**Acceptance criteria**

- Evidence distinguishes user, signer, and HTTP-client-generated headers.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-006 — Forbidden framing headers

**Normative statement:** Configuration MUST reject user-supplied Host, Content-Length, Transfer-Encoding, Connection, and Proxy-Authorization headers.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0104, TASK-0308 |
| Tests | VT-HTTP-006 |
| Verification | test |

**Rationale**

This requirement makes forbidden framing headers explicit and independently verifiable.

**Acceptance criteria**

- Each forbidden header fails before manifest creation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces request smuggling, routing confusion, and proxy credential exposure.

---

### HTTP-007 — Request compression

**Normative statement:** The v0.1 executor MUST NOT apply automatic request-body compression.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-007 |
| Verification | test |

**Rationale**

This requirement makes request compression explicit and independently verifiable.

**Acceptance criteria**

- The delivered body equals the fixture/mutation bytes and Content-Encoding is absent unless explicitly represented by a raw fixture case.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-008 — Response encoding

**Normative statement:** The executor MUST request identity response encoding by default.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-008 |
| Verification | test |

**Rationale**

This requirement makes response encoding explicit and independently verifiable.

**Acceptance criteria**

- Accept-Encoding is identity unless an explicit future-compatible option is enabled.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-009 — Redirect policy

**Normative statement:** The executor MUST NOT follow redirects.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | SRC-100 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-009 |
| Verification | test |

**Rationale**

This requirement makes redirect policy explicit and independently verifiable.

**Acceptance criteria**

- A 302 response is recorded as the attempt response and no second destination is contacted.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents target-policy bypass.

---

### HTTP-010 — Proxy environment

**Normative statement:** The executor MUST construct HTTPX clients with trust_env=False.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | SRC-021 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-010 |
| Verification | test |

**Rationale**

This requirement makes proxy environment explicit and independently verifiable.

**Acceptance criteria**

- HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY, SSL_CERT_FILE, and .netrc do not alter a default run.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents ambient proxy or credential behavior from bypassing target policy.

---

### HTTP-011 — TLS verification

**Normative statement:** HTTPS connections MUST verify the configured trust store and hostname by default.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-011 |
| Verification | test |

**Rationale**

This requirement makes tls verification explicit and independently verifiable.

**Acceptance criteria**

- A self-signed certificate fails unless an explicit test CA file is configured.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents transparent interception and wrong-host delivery.

---

### HTTP-012 — HTTP protocol default

**Normative statement:** The v0.1 executor MUST enable HTTP/1.1 and disable HTTP/2 by default.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | SRC-019 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-012 |
| Verification | test |

**Rationale**

Webhook semantics do not require HTTP/2 and one protocol reduces transport ambiguity in the first release.

**Acceptance criteria**

- Attempt evidence reports HTTP/1.1 in the reference corpus.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-013 — Granular timeouts

**Normative statement:** The executor MUST expose connect, write, read, pool, and total physical timeout values.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | SRC-020 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0104, TASK-0308 |
| Tests | VT-HTTP-013 |
| Verification | test |

**Rationale**

This requirement makes granular timeouts explicit and independently verifiable.

**Acceptance criteria**

- Each timeout type has an isolated fault test and distinct error classification.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-014 — Total timeout

**Normative statement:** The total timeout MUST bound an attempt from connection-pool acquisition through response-stream closure.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-014 |
| Verification | test |

**Rationale**

This requirement makes total timeout explicit and independently verifiable.

**Acceptance criteria**

- A slow multi-phase response cannot exceed the total deadline by more than the documented cancellation tolerance.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-015 — No implicit transport retry

**Normative statement:** The HTTP transport MUST set its implicit connection retry count to zero.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-015 |
| Verification | test |

**Rationale**

This requirement makes no implicit transport retry explicit and independently verifiable.

**Acceptance criteria**

- A refused connection produces one physical attempt and any later attempt is scheduler-created.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-016 — Default request limit

**Normative statement:** The default realized request-body limit MUST be 1 MiB.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0107, TASK-0308 |
| Tests | VT-HTTP-016 |
| Verification | test |

**Rationale**

This requirement makes default request limit explicit and independently verifiable.

**Acceptance criteria**

- A 1 MiB body passes and a body one byte larger fails under default configuration.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-017 — Hard request limit

**Normative statement:** The configurable request-body limit MUST NOT exceed 16 MiB in v0.1.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0104 |
| Tests | VT-HTTP-017 |
| Verification | test |

**Rationale**

This requirement makes hard request limit explicit and independently verifiable.

**Acceptance criteria**

- A configured limit greater than 16777216 bytes fails validation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-018 — Response retention limit

**Normative statement:** The default retained response-body prefix MUST be limited to 64 KiB.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-018 |
| Verification | test |

**Rationale**

This requirement makes response retention limit explicit and independently verifiable.

**Acceptance criteria**

- A larger response stores the first 65536 bytes after redaction plus total byte count and truncation=true.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-019 — Response drain limit

**Normative statement:** The executor MUST close a response after reading at most 1 MiB of body data.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-019 |
| Verification | test |

**Rationale**

This requirement makes response drain limit explicit and independently verifiable.

**Acceptance criteria**

- An unbounded response stream is closed at the hard cap and classified without exhausting disk or memory.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents response-body resource exhaustion.

---

### HTTP-020 — Connect failure classification

**Normative statement:** A failure proven to occur before a socket connection is established MUST be classified not_sent.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308, TASK-0309 |
| Tests | VT-HTTP-020 |
| Verification | test |

**Rationale**

This requirement makes connect failure classification explicit and independently verifiable.

**Acceptance criteria**

- DNS failure and connection refusal yield not_sent with no unknown_outcome.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-021 — Post-send ambiguity classification

**Normative statement:** A timeout, reset, cancellation, or crash after request transmission may have begun MUST be classified unknown_outcome unless a complete response was durably recorded.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-005 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0309, TASK-0806 |
| Tests | VT-HTTP-021 |
| Verification | test |

**Rationale**

This requirement makes post-send ambiguity classification explicit and independently verifiable.

**Acceptance criteria**

- Write/read timeout tests never claim the receiver did not process the request.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-022 — Peer address evidence

**Normative statement:** Every connected attempt MUST record the authorized and actual peer IP address and address family.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0306, TASK-0308 |
| Tests | VT-HTTP-022 |
| Verification | test |

**Rationale**

This requirement makes peer address evidence explicit and independently verifiable.

**Acceptance criteria**

- IPv4 and IPv6 tests show matching authorized and peer addresses.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-023 — Pinned destination

**Normative statement:** The network dialer MUST connect only to an address authorized for the attempt immediately before connection.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | SRC-100 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET |
| Tasks | TASK-0306 |
| Tests | VT-HTTP-023 |
| Verification | test |

**Rationale**

This requirement makes pinned destination explicit and independently verifiable.

**Acceptance criteria**

- A DNS-rebinding test cannot redirect a request to a newly returned disallowed address.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents DNS time-of-check/time-of-use SSRF.

---

### HTTP-024 — Public preflight

**Normative statement:** A public-target attempt MUST NOT send fixture bytes until the receiver preflight returns the configured one-time challenge value.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET |
| Tasks | TASK-0307 |
| Tests | VT-HTTP-024 |
| Verification | test |

**Rationale**

This requirement makes public preflight explicit and independently verifiable.

**Acceptance criteria**

- A missing, stale, redirected, or mismatched challenge aborts the run before fixture delivery.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Provides receiver cooperation and protection against accidental production targeting.

---

### HTTP-025 — Connection pool limit

**Normative statement:** The HTTP client MUST cap total connections at the configured concurrency limit and keep-alive connections at no more than that limit.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | SRC-094 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308 |
| Tests | VT-HTTP-025 |
| Verification | test |

**Rationale**

This requirement makes connection pool limit explicit and independently verifiable.

**Acceptance criteria**

- Pool instrumentation never exceeds configured limits under concurrent duplicates.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### HTTP-026 — Response stream closure

**Normative statement:** Every response stream MUST be closed on success, error, timeout, or cancellation.

| Field | Value |
| --- | --- |
| Type | HTTP |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-004 |
| Sources | SRC-095 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-HTTP |
| Tasks | TASK-0308, TASK-0310 |
| Tests | VT-HTTP-026 |
| Verification | test |

**Rationale**

This requirement makes response stream closure explicit and independently verifiable.

**Acceptance criteria**

- Resource-leak tests show no open pooled response after each terminal path.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-001 — Generic HMAC-SHA256 adapter

**Normative statement:** The core MUST provide a generic HMAC-SHA256 signer with a versioned signing-input template.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | SRC-113 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0401 |
| Tests | VT-SIG-001 |
| Verification | test |

**Rationale**

This requirement makes generic hmac-sha256 adapter explicit and independently verifiable.

**Acceptance criteria**

- Published generic HMAC test vectors match exactly.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-002 — Raw-byte signing input

**Normative statement:** A signer MUST receive immutable realized body bytes rather than a parsed JSON value.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | SRC-001, SRC-003, SRC-006, SRC-013 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0401 |
| Tests | VT-SIG-002 |
| Verification | test |

**Rationale**

This requirement makes raw-byte signing input explicit and independently verifiable.

**Acceptance criteria**

- Whitespace-only fixture changes alter the signature as defined by the adapter.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-003 — Signer header ownership

**Normative statement:** A signer MUST exclusively own its declared headers and treat any conflicting user-supplied value as invalid configuration.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0401, TASK-0108 |
| Tests | VT-SIG-003 |
| Verification | test |

**Rationale**

This requirement makes signer header ownership explicit and independently verifiable.

**Acceptance criteria**

- A user-supplied signature header fails planning instead of being silently overwritten.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-004 — Reference constant-time comparison

**Normative statement:** Reference receivers MUST compare message authentication codes with a constant-time comparison primitive.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | SRC-003, SRC-030 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0701 |
| Tests | VT-SIG-004 |
| Verification | test |

**Rationale**

This requirement makes reference constant-time comparison explicit and independently verifiable.

**Acceptance criteria**

- Static and unit tests confirm hmac.compare_digest or an equivalent constant-time primitive is used.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces timing side channels in reference verification logic.

---

### SIG-005 — Timestamp clock domain

**Normative statement:** Timestamped signatures MUST derive their timestamp from the realized logical signing time unless the adapter declares a different tested rule.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0401, TASK-0109 |
| Tests | VT-SIG-005 |
| Verification | test |

**Rationale**

This requirement makes timestamp clock domain explicit and independently verifiable.

**Acceptance criteria**

- Scaled replay produces the same signature timestamp and signature bytes as the source bundle.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-006 — Replay window fixture

**Normative statement:** Reference receivers MUST reject a timestamped signature outside the configured replay window.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | SRC-001, SRC-012, SRC-013 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0701, TASK-0705 |
| Tests | VT-SIG-006 |
| Verification | test |

**Rationale**

This requirement makes replay window fixture explicit and independently verifiable.

**Acceptance criteria**

- A stale timestamp fails transport rejection and produces no business-state evidence.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-007 — Missing signature case

**Normative statement:** Every timestamped signer MUST support a missing-signature mutation case.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0406 |
| Tests | VT-SIG-007 |
| Verification | test |

**Rationale**

This requirement makes missing signature case explicit and independently verifiable.

**Acceptance criteria**

- The resulting attempt contains no owned signature header and remains otherwise byte-identical.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-008 — Malformed signature case

**Normative statement:** Every built-in signer MUST support at least one syntactically malformed signature case.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0406 |
| Tests | VT-SIG-008 |
| Verification | test |

**Rationale**

This requirement makes malformed signature case explicit and independently verifiable.

**Acceptance criteria**

- Malformed output is deterministic and identified by mutation ID/version.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-009 — Wrong-key case

**Normative statement:** Every keyed built-in signer MUST support signing with a deterministic wrong test key.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0404, TASK-0406 |
| Tests | VT-SIG-009 |
| Verification | test |

**Rationale**

This requirement makes wrong-key case explicit and independently verifiable.

**Acceptance criteria**

- The wrong-key fingerprint differs from the valid key fingerprint and the reference receiver rejects it.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-010 — Altered-body case

**Normative statement:** The mutation pipeline MUST support altering body bytes after signature construction.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT, ARC-SIGN |
| Tasks | TASK-0404, TASK-0406 |
| Tests | VT-SIG-010 |
| Verification | test |

**Rationale**

This requirement makes altered-body case explicit and independently verifiable.

**Acceptance criteria**

- The signature header remains unchanged while the delivered body digest changes.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-011 — Secret references

**Normative statement:** Signing key material MUST enter the signer only through the secret resolver.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-SIGN |
| Tasks | TASK-0106, TASK-0401 |
| Tests | VT-SIG-011 |
| Verification | test |

**Rationale**

This requirement makes secret references explicit and independently verifiable.

**Acceptance criteria**

- Signer constructors accept secret handles and cannot serialize raw key bytes into models.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Centralizes secret lifecycle and redaction.

---

### SIG-012 — Secret fingerprint

**Normative statement:** Reports MUST identify signing keys only by an algorithm-qualified non-secret fingerprint.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0106, TASK-0601 |
| Tests | VT-SIG-012 |
| Verification | test |

**Rationale**

This requirement makes secret fingerprint explicit and independently verifiable.

**Acceptance criteria**

- No raw or base64 key material appears in any default artifact.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Supports key correlation without disclosure.

---

### SIG-013 — Multiple signatures

**Normative statement:** The Standard Webhooks signer MUST support multiple signatures over one message for key rotation tests.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | SRC-013 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0403 |
| Tests | VT-SIG-013 |
| Verification | test |

**Rationale**

This requirement makes multiple signatures explicit and independently verifiable.

**Acceptance criteria**

- A golden header contains two independently verifiable v1 signatures in deterministic order.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-014 — Stripe v1 adapter

**Normative statement:** The core MUST provide a Stripe v1-compatible timestamped HMAC-SHA256 signer.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | SRC-001 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0402 |
| Tests | VT-SIG-014 |
| Verification | test |

**Rationale**

This requirement makes stripe v1 adapter explicit and independently verifiable.

**Acceptance criteria**

- Golden vectors match the documented timestamp-dot-payload signing input and header form.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-015 — Standard Webhooks HMAC adapter

**Normative statement:** The core MUST provide a Standard Webhooks HMAC-SHA256-compatible signer.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | SRC-013 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0403 |
| Tests | VT-SIG-015 |
| Verification | test |

**Rationale**

This requirement makes standard webhooks hmac adapter explicit and independently verifiable.

**Acceptance criteria**

- Golden vectors match webhook-id, webhook-timestamp, and webhook-signature semantics.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-016 — Generated test keys

**Normative statement:** Generated HMAC test keys MUST contain at least 256 bits of operating-system randomness.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0106, TASK-0401 |
| Tests | VT-SIG-016 |
| Verification | test |

**Rationale**

This requirement makes generated test keys explicit and independently verifiable.

**Acceptance criteria**

- The generator requests 32 bytes from secrets.token_bytes and stores only the secret reference and fingerprint.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents predictable test keys where secrecy is expected.

---

### SIG-017 — Ed25519 deferral

**Normative statement:** Ed25519 signing MUST remain outside the v0.1 runtime compatibility promise.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | SRC-013, SRC-114 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SIGN |
| Tasks | TASK-0810 |
| Tests | VT-SIG-017 |
| Verification | test |

**Rationale**

This requirement makes ed25519 deferral explicit and independently verifiable.

**Acceptance criteria**

- The v0.1 config schema rejects ed25519 while the roadmap names the enabling ADR and tests.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SIG-018 — Key rotation acceptance policy

**Normative statement:** Reference receivers MUST accept every currently active configured key and reject every retired key outside its overlap window.

| Field | Value |
| --- | --- |
| Type | SIG |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-005 |
| Goals | GOAL-001, GOAL-004 |
| Use cases | UC-009 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0701 |
| Tests | VT-SIG-018 |
| Verification | test |

**Rationale**

This requirement makes key rotation acceptance policy explicit and independently verifiable.

**Acceptance criteria**

- Time-controlled rotation tests cover old-only, overlap, and new-only windows.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-001 — Mutation identity

**Normative statement:** Every mutation operator MUST have a stable identifier and integer version.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0404 |
| Tests | VT-MUT-001 |
| Verification | test |

**Rationale**

This requirement makes mutation identity explicit and independently verifiable.

**Acceptance criteria**

- Manifest schema rejects an operator without id or version.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-002 — Mutation realization

**Normative statement:** Every stochastic mutation parameter MUST be fully realized into the manifest during planning.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0109, TASK-0407 |
| Tests | VT-MUT-002 |
| Verification | test |

**Rationale**

This requirement makes mutation realization explicit and independently verifiable.

**Acceptance criteria**

- Replay invokes no random generator and produces the same mutated blob digest.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-003 — Mutation pipeline order

**Normative statement:** Mutations MUST execute in the order structural JSON, raw pre-sign, signing, then raw post-sign.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0404 |
| Tests | VT-MUT-003 |
| Verification | test |

**Rationale**

This requirement makes mutation pipeline order explicit and independently verifiable.

**Acceptance criteria**

- A golden pipeline test records each intermediate digest and matches the documented order.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-004 — Structural serializer

**Normative statement:** A structural JSON mutation MUST serialize with the versioned json-compact-utf8-v1 serializer.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | SRC-115 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0405 |
| Tests | VT-MUT-004 |
| Verification | test |

**Rationale**

This requirement makes structural serializer explicit and independently verifiable.

**Acceptance criteria**

- Golden vectors define UTF-8, separators, escaping, and key-order behavior.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-005 — Structural mutation applicability

**Normative statement:** A structural JSON mutation MUST reject a fixture that is not valid JSON before that mutation is applied.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0405 |
| Tests | VT-MUT-005 |
| Verification | test |

**Rationale**

This requirement makes structural mutation applicability explicit and independently verifiable.

**Acceptance criteria**

- A raw invalid-JSON fixture receives unsupported_input rather than an implicit replacement value.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-006 — Remove JSON Pointer

**Normative statement:** The mutation system MUST provide remove-json-pointer-v1.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0405 |
| Tests | VT-MUT-006 |
| Verification | test |

**Rationale**

This requirement makes remove json pointer explicit and independently verifiable.

**Acceptance criteria**

- Removing an existing pointer succeeds and a missing pointer follows the configured error policy.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-007 — Replace JSON value

**Normative statement:** The mutation system MUST provide replace-json-value-v1.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0405 |
| Tests | VT-MUT-007 |
| Verification | test |

**Rationale**

This requirement makes replace json value explicit and independently verifiable.

**Acceptance criteria**

- The manifest stores the pointer and exact replacement JSON value.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-008 — Replace JSON type

**Normative statement:** The mutation system MUST provide replace-json-type-v1 with explicit target type and deterministic value.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0405 |
| Tests | VT-MUT-008 |
| Verification | test |

**Rationale**

This requirement makes replace json type explicit and independently verifiable.

**Acceptance criteria**

- A number-to-string mutation produces the documented serialized value.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-009 — Add unknown JSON field

**Normative statement:** The mutation system MUST provide add-json-field-v1.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0405 |
| Tests | VT-MUT-009 |
| Verification | test |

**Rationale**

This requirement makes add unknown json field explicit and independently verifiable.

**Acceptance criteria**

- The operator rejects an existing target field unless overwrite=true is explicitly represented.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-010 — Change logical identifier field

**Normative statement:** The mutation system MUST provide change-event-id-field-v1 without changing the harness logical_event_id.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0405 |
| Tests | VT-MUT-010 |
| Verification | test |

**Rationale**

This requirement makes change logical identifier field explicit and independently verifiable.

**Acceptance criteria**

- Evidence shows different provider payload ID and stable harness logical event identity.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-011 — Change event type field

**Normative statement:** The mutation system MUST provide change-event-type-field-v1.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0405 |
| Tests | VT-MUT-011 |
| Verification | test |

**Rationale**

This requirement makes change event type field explicit and independently verifiable.

**Acceptance criteria**

- The configured JSON Pointer changes while all unrelated fields remain equal.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-012 — Truncate raw body

**Normative statement:** The mutation system MUST provide truncate-bytes-v1 with a retained byte count.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0406 |
| Tests | VT-MUT-012 |
| Verification | test |

**Rationale**

This requirement makes truncate raw body explicit and independently verifiable.

**Acceptance criteria**

- Retained count zero through body length is validated and output digest is deterministic.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-013 — Invalid JSON body

**Normative statement:** The mutation system MUST provide invalid-json-v1 using a finite catalog of versioned malformed byte sequences.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0406 |
| Tests | VT-MUT-013 |
| Verification | test |

**Rationale**

This requirement makes invalid json body explicit and independently verifiable.

**Acceptance criteria**

- Each catalog case is named and reproduced from the manifest.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-014 — Content-type mismatch

**Normative statement:** The mutation system MUST provide content-type-mismatch-v1 that changes only the declared media type.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0406 |
| Tests | VT-MUT-014 |
| Verification | test |

**Rationale**

This requirement makes content-type mismatch explicit and independently verifiable.

**Acceptance criteria**

- Body bytes remain equal while Content-Type changes to the realized value.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-015 — Post-sign alteration

**Normative statement:** The mutation system MUST provide alter-after-signing-v1.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0406 |
| Tests | VT-MUT-015 |
| Verification | test |

**Rationale**

This requirement makes post-sign alteration explicit and independently verifiable.

**Acceptance criteria**

- The pre-alter signed digest and delivered digest are both recorded.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-016 — Signature-state mutations

**Normative statement:** The mutation system MUST represent stale timestamp, wrong key, missing signature, and malformed signature as distinct operator IDs.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0406 |
| Tests | VT-MUT-016 |
| Verification | test |

**Rationale**

This requirement makes signature-state mutations explicit and independently verifiable.

**Acceptance criteria**

- Reports never collapse the four cases into a generic invalid_signature label.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-017 — Oversized body mutation

**Normative statement:** The mutation system MUST permit deterministic body expansion only up to the configured request hard limit.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0406 |
| Tests | VT-MUT-017 |
| Verification | test |

**Rationale**

This requirement makes oversized body mutation explicit and independently verifiable.

**Acceptance criteria**

- Expansion beyond the hard limit fails at planning rather than allocating the requested body.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents memory and disk exhaustion.

---

### MUT-018 — Mutation compatibility

**Normative statement:** Semantic validation MUST reject mutation combinations whose pipeline order or payload requirements are incompatible.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0108, TASK-0404 |
| Tests | VT-MUT-018 |
| Verification | test |

**Rationale**

This requirement makes mutation compatibility explicit and independently verifiable.

**Acceptance criteria**

- Structural JSON after invalid-json and two conflicting signature-removal operations fail with operator-specific diagnostics.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-019 — Mutation redaction

**Normative statement:** Mutation diagnostics MUST apply the same redaction policy as delivery evidence.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0404, TASK-0604 |
| Tests | VT-MUT-019 |
| Verification | test |

**Rationale**

This requirement makes mutation redaction explicit and independently verifiable.

**Acceptance criteria**

- A replaced sensitive value is absent from logs and HTML while its redacted marker remains.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents mutated secrets from bypassing report redaction.

---

### MUT-020 — Duplicate JSON key deferral

**Normative statement:** Duplicate-json-key mutation MUST remain deferred until parser and serializer semantics are explicitly versioned.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | SRC-115 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0810 |
| Tests | VT-MUT-020 |
| Verification | test |

**Rationale**

This requirement makes duplicate json key deferral explicit and independently verifiable.

**Acceptance criteria**

- The v0.1 schema rejects this operator with unsupported status.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-021 — Invalid UTF-8 deferral

**Normative statement:** Invalid-utf8 mutation MUST remain deferred until platform and framework behavior is covered by a dedicated compatibility corpus.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0810 |
| Tests | VT-MUT-021 |
| Verification | test |

**Rationale**

This requirement makes invalid utf-8 deferral explicit and independently verifiable.

**Acceptance criteria**

- The v0.1 schema rejects this operator with unsupported status.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### MUT-022 — Scenario reduction artifact

**Normative statement:** A reduced failing scenario MUST be emitted as a complete replayable run bundle rather than an internal property-testing database entry.

| Field | Value |
| --- | --- |
| Type | MUT |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-001 |
| Use cases | UC-003, UC-004, UC-011 |
| Sources | SRC-032 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-MUT |
| Tasks | TASK-0810 |
| Tests | VT-MUT-022 |
| Verification | test |

**Rationale**

This requirement makes scenario reduction artifact explicit and independently verifiable.

**Acceptance criteria**

- The reduced bundle replays independently after the Hypothesis example database is deleted.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-001 — Command observer capability operation

**Normative statement:** A command observer MUST implement a versioned capabilities operation.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0501, TASK-0502 |
| Tests | VT-OBS-001 |
| Verification | test |

**Rationale**

This requirement makes command observer capability operation explicit and independently verifiable.

**Acceptance criteria**

- The harness rejects an observer that does not return protocol version and supported evidence types.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-002 — Command observer invocation

**Normative statement:** A command observer MUST be invoked as an executable plus argv array with shell execution disabled.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | SRC-101 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0502 |
| Tests | VT-OBS-002 |
| Verification | test |

**Rationale**

This requirement makes command observer invocation explicit and independently verifiable.

**Acceptance criteria**

- Metacharacters in an argument reach the child literally and do not invoke another process.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents command injection.

---

### OBS-003 — Command observer input

**Normative statement:** A command observer MUST receive one schema-valid UTF-8 JSON request on stdin.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0502 |
| Tests | VT-OBS-003 |
| Verification | test |

**Rationale**

This requirement makes command observer input explicit and independently verifiable.

**Acceptance criteria**

- The child receives exactly one newline-terminated JSON object matching observer-request.schema.json.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-004 — Command observer output

**Normative statement:** A command observer MUST return exactly one schema-valid UTF-8 JSON response on stdout.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0502 |
| Tests | VT-OBS-004 |
| Verification | test |

**Rationale**

This requirement makes command observer output explicit and independently verifiable.

**Acceptance criteria**

- Leading prose, a second JSON object, or invalid UTF-8 produces observer error.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-005 — Command observer output limits

**Normative statement:** Command observer stdout and stderr MUST be bounded to 1 MiB and 64 KiB respectively.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0502 |
| Tests | VT-OBS-005 |
| Verification | test |

**Rationale**

This requirement makes command observer output limits explicit and independently verifiable.

**Acceptance criteria**

- A child exceeding either cap is terminated and classified observer_output_limit.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents memory and log exhaustion.

---

### OBS-006 — Command observer environment

**Normative statement:** A command observer MUST receive only the configured environment allowlist plus protocol correlation variables.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0502 |
| Tests | VT-OBS-006 |
| Verification | test |

**Rationale**

This requirement makes command observer environment explicit and independently verifiable.

**Acceptance criteria**

- An unrelated parent secret environment variable is absent in the child.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents ambient CI secret disclosure.

---

### OBS-007 — Command observer working directory

**Normative statement:** A command observer MUST run from the configured project-confined working directory.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0502 |
| Tests | VT-OBS-007 |
| Verification | test |

**Rationale**

This requirement makes command observer working directory explicit and independently verifiable.

**Acceptance criteria**

- A traversal or symlink escape working directory fails validation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Constrains file access and relative-path behavior.

---

### OBS-008 — Observer timeout

**Normative statement:** Every observer invocation MUST have a physical monotonic timeout.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0502, TASK-0503, TASK-0504 |
| Tests | VT-OBS-008 |
| Verification | test |

**Rationale**

This requirement makes observer timeout explicit and independently verifiable.

**Acceptance criteria**

- A hanging observer is terminated and persisted as timed_out.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-009 — HTTP capability endpoint

**Normative statement:** An HTTP observer MUST expose POST /capabilities and POST /observe relative to its configured base URL.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0501, TASK-0503 |
| Tests | VT-OBS-009 |
| Verification | test |

**Rationale**

This requirement makes http capability endpoint explicit and independently verifiable.

**Acceptance criteria**

- Contract tests validate methods, paths, request IDs, and schemas.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-010 — HTTP observer authentication

**Normative statement:** An HTTP observer MUST authenticate requests through an explicit secret reference.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0106, TASK-0503 |
| Tests | VT-OBS-010 |
| Verification | test |

**Rationale**

This requirement makes http observer authentication explicit and independently verifiable.

**Acceptance criteria**

- Missing or wrong credentials produce observer error without response-body leakage.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents unauthorized application-state inspection.

---

### OBS-011 — HTTP observer target policy

**Normative statement:** An HTTP observer request MUST use the same destination authorization and pinned-dialer controls as a receiver request.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0306, TASK-0503 |
| Tests | VT-OBS-011 |
| Verification | test |

**Rationale**

This requirement makes http observer target policy explicit and independently verifiable.

**Acceptance criteria**

- Observer URLs cannot bypass blocked address classes or redirects.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents observer-side SSRF.

---

### OBS-012 — Observer request idempotency

**Normative statement:** Every observe request MUST include a stable request_id that an observer can use for idempotent handling.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0501, TASK-0504 |
| Tests | VT-OBS-012 |
| Verification | test |

**Rationale**

This requirement makes observer request idempotency explicit and independently verifiable.

**Acceptance criteria**

- A retried observation uses the same logical request_id and a new sample_id.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-013 — Snapshot identity

**Normative statement:** Every successful observer response MUST include a nonempty snapshot_id unique within the observer scope.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0501, TASK-0701 |
| Tests | VT-OBS-013 |
| Verification | test |

**Rationale**

This requirement makes snapshot identity explicit and independently verifiable.

**Acceptance criteria**

- Two different state snapshots cannot share a snapshot_id in the reference observer.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-014 — Evidence typing

**Normative statement:** Observer evidence values MUST use the protocol types null, boolean, integer, decimal-string, string, bytes-digest, timestamp, array, or object.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0501 |
| Tests | VT-OBS-014 |
| Verification | test |

**Rationale**

This requirement makes evidence typing explicit and independently verifiable.

**Acceptance criteria**

- Binary bytes are represented by digest/metadata rather than embedded arbitrary bytes.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-015 — Observer status

**Normative statement:** An observer response MUST classify itself as ok, pending, unsupported, or error.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0501 |
| Tests | VT-OBS-015 |
| Verification | test |

**Rationale**

This requirement makes observer status explicit and independently verifiable.

**Acceptance criteria**

- Every response has exactly one status and the harness maps it deterministically.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-016 — Read-only observer contract

**Normative statement:** An observer MUST declare read_only=true to be eligible for automatic polling or resume reconciliation.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0501, TASK-0504, TASK-0509 |
| Tests | VT-OBS-016 |
| Verification | test |

**Rationale**

This requirement makes read-only observer contract explicit and independently verifiable.

**Acceptance criteria**

- A non-read-only observer is limited to one explicit invocation and cannot reconcile ambiguity.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Avoids repeated observer side effects.

---

### OBS-017 — Polling interval

**Normative statement:** Observer polling MUST use a configured physical interval not less than 10 milliseconds.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0104, TASK-0504 |
| Tests | VT-OBS-017 |
| Verification | test |

**Rationale**

This requirement makes polling interval explicit and independently verifiable.

**Acceptance criteria**

- A smaller value fails validation and no busy loop occurs.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-018 — Polling deadline

**Normative statement:** Observer polling MUST stop at the configured physical monotonic deadline.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0504 |
| Tests | VT-OBS-018 |
| Verification | test |

**Rationale**

This requirement makes polling deadline explicit and independently verifiable.

**Acceptance criteria**

- Pending responses become timed_out at the deadline and do not continue in the background.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-019 — Observer redaction

**Normative statement:** Observer requests, responses, stdout, and stderr MUST pass through configured redaction before logging or reporting.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0502, TASK-0503, TASK-0601 |
| Tests | VT-OBS-019 |
| Verification | test |

**Rationale**

This requirement makes observer redaction explicit and independently verifiable.

**Acceptance criteria**

- Sensitive evidence and child stderr values are absent from every default artifact.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Protects application-state and secret data.

---

### OBS-020 — Unsupported capability

**Normative statement:** A missing required observer capability MUST produce unsupported rather than receiver_failure.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0501, TASK-0508 |
| Tests | VT-OBS-020 |
| Verification | test |

**Rationale**

This requirement makes unsupported capability explicit and independently verifiable.

**Acceptance criteria**

- An unsupported processing_count assertion yields exit code 6 under fail-on-unsupported policy.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-021 — SQL observer deferral

**Normative statement:** A direct SQL observer MUST remain outside the v0.1 core.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0810 |
| Tests | VT-OBS-021 |
| Verification | test |

**Rationale**

This requirement makes sql observer deferral explicit and independently verifiable.

**Acceptance criteria**

- No database driver other than SQLite journal support is a core dependency.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OBS-022 — Telemetry observer deferral

**Normative statement:** OpenTelemetry and queue-inspection observers MUST remain outside the v0.1 core.

| Field | Value |
| --- | --- |
| Type | OBS |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-002 |
| Use cases | UC-010 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-OBS-CMD, ARC-OBS-HTTP |
| Tasks | TASK-0810 |
| Tests | VT-OBS-022 |
| Verification | test |

**Rationale**

This requirement makes telemetry observer deferral explicit and independently verifiable.

**Acceptance criteria**

- The roadmap records adapter prerequisites without runtime placeholders.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-001 — HTTP status assertion

**Normative statement:** The assertion engine MUST support exact and set-membership HTTP status assertions.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0505 |
| Tests | VT-ASSERT-001 |
| Verification | test |

**Rationale**

This requirement makes http status assertion explicit and independently verifiable.

**Acceptance criteria**

- 200 exact and [200,202] membership cases pass; a missing response produces error rather than fail.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-002 — Status class assertion

**Normative statement:** The assertion engine MUST support 2xx, 3xx, 4xx, and 5xx status-class assertions.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0505 |
| Tests | VT-ASSERT-002 |
| Verification | test |

**Rationale**

This requirement makes status class assertion explicit and independently verifiable.

**Acceptance criteria**

- Boundary status values 199, 200, 299, 300, 399, 400, 499, 500, and 599 are classified correctly.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-003 — Acknowledgment deadline assertion

**Normative statement:** The assertion engine MUST measure acknowledgment deadline from request-send start to complete response headers using monotonic time.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0308, TASK-0505 |
| Tests | VT-ASSERT-003 |
| Verification | test |

**Rationale**

This requirement makes acknowledgment deadline assertion explicit and independently verifiable.

**Acceptance criteria**

- A delayed-body response with prompt headers passes while delayed headers fail.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-004 — Processing count assertion

**Normative statement:** The assertion engine MUST support integer processing-count comparisons scoped by logical event and observer evidence name.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0506 |
| Tests | VT-ASSERT-004 |
| Verification | test |

**Rationale**

This requirement makes processing count assertion explicit and independently verifiable.

**Acceptance criteria**

- Duplicate delivery to the correct receiver yields count 1 and the no-idempotency receiver yields count 2.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-005 — Resource existence assertion

**Normative statement:** The assertion engine MUST support resource existence and absence assertions.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0506 |
| Tests | VT-ASSERT-005 |
| Verification | test |

**Rationale**

This requirement makes resource existence assertion explicit and independently verifiable.

**Acceptance criteria**

- Reference observer evidence produces deterministic pass/fail for both forms.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-006 — Typed field equality

**Normative statement:** Field equality MUST compare evidence values by declared protocol type without string coercion.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0506 |
| Tests | VT-ASSERT-006 |
| Verification | test |

**Rationale**

This requirement makes typed field equality explicit and independently verifiable.

**Acceptance criteria**

- Integer 1 does not equal string "1".

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-007 — Numeric comparison

**Normative statement:** Numeric assertions MUST compare integers exactly and decimal strings through Decimal semantics.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0506 |
| Tests | VT-ASSERT-007 |
| Verification | test |

**Rationale**

This requirement makes numeric comparison explicit and independently verifiable.

**Acceptance criteria**

- Decimal 0.10 equals 0.1 under numeric comparison while retaining source representation in evidence.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-008 — Callback count assertion

**Normative statement:** The assertion engine MUST support callback-count comparisons over named observer evidence.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0506 |
| Tests | VT-ASSERT-008 |
| Verification | test |

**Rationale**

This requirement makes callback count assertion explicit and independently verifiable.

**Acceptance criteria**

- The correct receiver outbox callback count remains one under duplicate delivery.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-009 — Journal count assertion

**Normative statement:** The assertion engine MUST support application-journal count comparisons over named observer evidence.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0506 |
| Tests | VT-ASSERT-009 |
| Verification | test |

**Rationale**

This requirement makes journal count assertion explicit and independently verifiable.

**Acceptance criteria**

- A reference inbox contains one logical event record after concurrent duplicates.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-010 — Ordered transition assertion

**Normative statement:** The assertion engine MUST verify an expected subsequence of typed application-state transitions.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0507 |
| Tests | VT-ASSERT-010 |
| Verification | test |

**Rationale**

This requirement makes ordered transition assertion explicit and independently verifiable.

**Acceptance criteria**

- Intermediate unrelated transitions are permitted only when the assertion configuration allows them.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-011 — No partial side-effect assertion

**Normative statement:** The assertion engine MUST support an all-or-none assertion over a named set of evidence predicates.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0507 |
| Tests | VT-ASSERT-011 |
| Verification | test |

**Rationale**

This requirement makes no partial side-effect assertion explicit and independently verifiable.

**Acceptance criteria**

- A receiver with an order update but missing outbox entry fails with both predicate values shown.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-012 — Eventual state assertion

**Normative statement:** The assertion engine MUST support polling until a typed predicate passes or a physical deadline expires.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0504, TASK-0507 |
| Tests | VT-ASSERT-012 |
| Verification | test |

**Rationale**

This requirement makes eventual state assertion explicit and independently verifiable.

**Acceptance criteria**

- The final report includes every sample ID and the terminal pass or timeout.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-013 — Assertion pass semantics

**Normative statement:** An assertion MUST pass only when all required evidence is present and its predicate evaluates true.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0508 |
| Tests | VT-ASSERT-013 |
| Verification | test |

**Rationale**

This requirement makes assertion pass semantics explicit and independently verifiable.

**Acceptance criteria**

- Missing optional diagnostic evidence does not affect pass; missing required evidence produces error.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-014 — Assertion fail semantics

**Normative statement:** An assertion MUST fail only when valid evidence shows the receiver violated the expected predicate.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0508 |
| Tests | VT-ASSERT-014 |
| Verification | test |

**Rationale**

This requirement makes assertion fail semantics explicit and independently verifiable.

**Acceptance criteria**

- A comparison mismatch produces receiver_failure and cites actual/expected values.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-015 — Assertion error semantics

**Normative statement:** An assertion MUST produce error when it cannot be evaluated because evidence is invalid, missing, timed out, or produced by a failed observer.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0508 |
| Tests | VT-ASSERT-015 |
| Verification | test |

**Rationale**

This requirement makes assertion error semantics explicit and independently verifiable.

**Acceptance criteria**

- Observer timeout never becomes a receiver assertion failure.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-016 — Assertion unsupported semantics

**Normative statement:** An assertion MUST produce unsupported when the selected observer does not advertise a required evidence capability.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0501, TASK-0508 |
| Tests | VT-ASSERT-016 |
| Verification | test |

**Rationale**

This requirement makes assertion unsupported semantics explicit and independently verifiable.

**Acceptance criteria**

- Capability mismatch is visible before observer polling begins.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### ASSERT-017 — Custom assertion deferral

**Normative statement:** Arbitrary executable custom assertions MUST remain outside the v0.1 compatibility surface.

| Field | Value |
| --- | --- |
| Type | ASSERT |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-002 |
| Goals | GOAL-002 |
| Use cases | UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-ASSERT |
| Tasks | TASK-0810 |
| Tests | VT-ASSERT-017 |
| Verification | test |

**Rationale**

This requirement makes custom assertion deferral explicit and independently verifiable.

**Acceptance criteria**

- v0.1 supports composition of built-in typed predicates but no eval or code expression field.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Avoids code-execution and compatibility risk.

---

### REPORT-001 — Run manifest artifact

**Normative statement:** Every planned run MUST emit run-manifest.json conforming to run-manifest.schema.json.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0109, TASK-0601 |
| Tests | VT-REPORT-001 |
| Verification | test |

**Rationale**

This requirement makes run manifest artifact explicit and independently verifiable.

**Acceptance criteria**

- The example and every generated manifest validate against the selected schema version.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-002 — Delivery JSON Lines

**Normative statement:** Every physical attempt MUST emit one terminal delivery record in deliveries.jsonl.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0601 |
| Tests | VT-REPORT-002 |
| Verification | test |

**Rationale**

This requirement makes delivery json lines explicit and independently verifiable.

**Acceptance criteria**

- The number of terminal attempt rows equals the number of terminal attempts in SQLite.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-003 — Observation JSON Lines

**Normative statement:** Every terminal observer sample MUST emit one record in observations.jsonl.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0601 |
| Tests | VT-REPORT-003 |
| Verification | test |

**Rationale**

This requirement makes observation json lines explicit and independently verifiable.

**Acceptance criteria**

- Every observation record validates and references an existing attempt, checkpoint, or assertion plan.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-004 — Assertion JSON Lines

**Normative statement:** Every terminal assertion evaluation MUST emit one record in assertions.jsonl.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0601 |
| Tests | VT-REPORT-004 |
| Verification | test |

**Rationale**

This requirement makes assertion json lines explicit and independently verifiable.

**Acceptance criteria**

- Every assertion record contains expected, actual/evidence references, and classification.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-005 — Result summary

**Normative statement:** Every terminal run MUST emit result-summary.json conforming to result-summary.schema.json.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0601, TASK-0602 |
| Tests | VT-REPORT-005 |
| Verification | test |

**Rationale**

This requirement makes result summary explicit and independently verifiable.

**Acceptance criteria**

- Summary counts reconcile exactly with JSON Lines records and the process exit code.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-006 — Stable artifact order

**Normative statement:** JSON Lines exports MUST use scenario ordinal, planned delivery ordinal, attempt ordinal, observation ordinal, and assertion ordinal as applicable.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0601 |
| Tests | VT-REPORT-006 |
| Verification | test |

**Rationale**

This requirement makes stable artifact order explicit and independently verifiable.

**Acceptance criteria**

- Regeneration on another supported platform yields byte-identical records except explicitly volatile wall timestamps.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-007 — Volatile field declaration

**Normative statement:** Every report schema MUST identify fields excluded from reproducibility comparison.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0003, TASK-0601 |
| Tests | VT-REPORT-007 |
| Verification | test |

**Rationale**

This requirement makes volatile field declaration explicit and independently verifiable.

**Acceptance criteria**

- The schema annotations and determinism document name run_id, wall timestamps, durations, and environment observations as volatile.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-008 — Failure causality

**Normative statement:** A failure record MUST name its immediate causal evidence IDs and the owning subsystem classification.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0601, TASK-0606 |
| Tests | VT-REPORT-008 |
| Verification | test |

**Rationale**

This requirement makes failure causality explicit and independently verifiable.

**Acceptance criteria**

- A signature rejection links mutation, delivery, attempt response, and no-processing observation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-009 — Ambiguity representation

**Normative statement:** Reports MUST represent unknown_outcome as ambiguity rather than transport failure or receiver success.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-005 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0601, TASK-0603, TASK-0604 |
| Tests | VT-REPORT-009 |
| Verification | test |

**Rationale**

This requirement makes ambiguity representation explicit and independently verifiable.

**Acceptance criteria**

- JUnit uses error and HTML uses an ambiguity section for an unknown attempt.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-010 — JUnit suite mapping

**Normative statement:** JUnit XML MUST map each scenario to one testsuite.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | SRC-119 |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0603 |
| Tests | VT-REPORT-010 |
| Verification | test |

**Rationale**

This requirement makes junit suite mapping explicit and independently verifiable.

**Acceptance criteria**

- A run with three scenarios contains three suites with stable names and IDs.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-011 — JUnit testcase mapping

**Normative statement:** JUnit XML MUST map each assertion to one testcase and each scenario-level environmental condition to a reserved infrastructure testcase.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0603 |
| Tests | VT-REPORT-011 |
| Verification | test |

**Rationale**

This requirement makes junit testcase mapping explicit and independently verifiable.

**Acceptance criteria**

- Assertion counts and infrastructure testcase counts reconcile with the result summary.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-012 — JUnit failure mapping

**Normative statement:** A receiver behavior violation MUST be encoded as a JUnit failure element.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0603 |
| Tests | VT-REPORT-012 |
| Verification | test |

**Rationale**

This requirement makes junit failure mapping explicit and independently verifiable.

**Acceptance criteria**

- A processing_count mismatch appears as failure and not error.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-013 — JUnit error mapping

**Normative statement:** A harness error, environment error, or unresolved ambiguity MUST be encoded as a JUnit error element.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0603 |
| Tests | VT-REPORT-013 |
| Verification | test |

**Rationale**

This requirement makes junit error mapping explicit and independently verifiable.

**Acceptance criteria**

- Observer timeout and unknown_outcome appear as errors with distinct type attributes.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-014 — JUnit skipped mapping

**Normative statement:** An explicitly unsupported or user-skipped assertion MUST be encoded as a JUnit skipped element.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0603 |
| Tests | VT-REPORT-014 |
| Verification | test |

**Rationale**

This requirement makes junit skipped mapping explicit and independently verifiable.

**Acceptance criteria**

- The skipped element includes a stable reason code.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-015 — JUnit duration

**Normative statement:** JUnit testcase time MUST report physical monotonic seconds with fractional precision.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0603 |
| Tests | VT-REPORT-015 |
| Verification | test |

**Rationale**

This requirement makes junit duration explicit and independently verifiable.

**Acceptance criteria**

- Logical scaled durations are not substituted for physical testcase time.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-016 — JUnit attachments

**Normative statement:** JUnit report attachments MUST be referenced by sanitized relative artifact paths rather than embedded raw bodies.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0603 |
| Tests | VT-REPORT-016 |
| Verification | test |

**Rationale**

This requirement makes junit attachments explicit and independently verifiable.

**Acceptance criteria**

- No fixture body or secret is embedded in system-out or system-err.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents sensitive CI report leakage.

---

### REPORT-017 — Static HTML

**Normative statement:** The HTML report MUST contain no executable JavaScript.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0604 |
| Tests | VT-REPORT-017 |
| Verification | test |

**Rationale**

This requirement makes static html explicit and independently verifiable.

**Acceptance criteria**

- HTML parsing finds no script elements, event-handler attributes, javascript URLs, or external resources.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces report XSS and offline supply-chain risk.

---

### REPORT-018 — HTML escaping

**Normative statement:** Every fixture-derived, receiver-derived, observer-derived, and command-derived value MUST be HTML-escaped for its output context.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | SRC-102 |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0604 |
| Tests | VT-REPORT-018 |
| Verification | test |

**Rationale**

This requirement makes html escaping explicit and independently verifiable.

**Acceptance criteria**

- A payload containing closing tags, event handlers, and entities renders as text only.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents stored XSS in generated reports.

---

### REPORT-019 — HTML CSP

**Normative statement:** The HTML report MUST include a restrictive Content-Security-Policy meta directive permitting only inline generated styles and data images.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0604 |
| Tests | VT-REPORT-019 |
| Verification | test |

**Rationale**

This requirement makes html csp explicit and independently verifiable.

**Acceptance criteria**

- The policy contains default-src none and script-src none.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Provides defense in depth against report injection.

---

### REPORT-020 — Raw body omission

**Normative statement:** Default reports MUST NOT embed unredacted request or response bodies.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0601, TASK-0604 |
| Tests | VT-REPORT-020 |
| Verification | test |

**Rationale**

This requirement makes raw body omission explicit and independently verifiable.

**Acceptance criteria**

- Only digests, sizes, content type, and redacted previews appear by default.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents sensitive payload disclosure.

---

### REPORT-021 — Idempotent regeneration

**Normative statement:** Regenerating reports from an unchanged journal MUST preserve semantic content and artifact ordering.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0605 |
| Tests | VT-REPORT-021 |
| Verification | test |

**Rationale**

This requirement makes idempotent regeneration explicit and independently verifiable.

**Acceptance criteria**

- A normalized digest comparison is equal across two regenerations.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-022 — Exit-code precedence

**Normative statement:** When multiple terminal categories exist, exit-code precedence MUST be harness_error, invalid_input, ambiguous, environment_error, unsupported, receiver_failure, cancelled, then pass with cancellation overriding only while the run is not already durably terminal.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0602 |
| Tests | VT-REPORT-022 |
| Verification | test |

**Rationale**

This requirement makes exit-code precedence explicit and independently verifiable.

**Acceptance criteria**

- A table-driven test covers every pairwise category combination.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REPORT-023 — SARIF exclusion

**Normative statement:** Runtime conformance results MUST NOT be emitted as SARIF in v0.1.

| Field | Value |
| --- | --- |
| Type | REPORT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-004 |
| Goals | GOAL-005 |
| Use cases | UC-007, UC-008, UC-012 |
| Sources | SRC-118 |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML |
| Tasks | TASK-0809 |
| Tests | VT-REPORT-023 |
| Verification | test |

**Rationale**

This requirement makes sarif exclusion explicit and independently verifiable.

**Acceptance criteria**

- No SARIF reporter is registered and documentation explains JUnit/JSON selection.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SEC-001 — Default loopback profile

**Normative statement:** The default receiver target profile MUST permit only loopback addresses.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-100 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0305, TASK-0805 |
| Tests | VT-SEC-001 |
| Verification | test |

**Rationale**

This requirement makes default loopback profile explicit and independently verifiable.

**Acceptance criteria**

- 127.0.0.1 and ::1 pass while RFC1918 and public addresses fail by default.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Minimizes accidental or malicious SSRF reach by default.

---

### SEC-002 — Private profile allowlist

**Normative statement:** The private target profile MUST require an exact hostname or literal-address allowlist.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0305, TASK-0805 |
| Tests | VT-SEC-002 |
| Verification | test |

**Rationale**

This requirement makes private profile allowlist explicit and independently verifiable.

**Acceptance criteria**

- An unlisted private address fails even though its address class is otherwise private.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Restricts lateral movement in local and CI networks.

---

### SEC-003 — Public profile gates

**Normative statement:** The public target profile MUST require configuration opt-in, exact host-and-port allowlisting, and matching runtime authorization.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0305, TASK-0307, TASK-0805 |
| Tests | VT-SEC-003 |
| Verification | test |

**Rationale**

This requirement makes public profile gates explicit and independently verifiable.

**Acceptance criteria**

- Omitting any one gate prevents DNS resolution and delivery.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents accidental public or production targeting.

---

### SEC-004 — Public receiver challenge

**Normative statement:** The public target profile MUST require a successful one-time test-target challenge before fixture delivery.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0307, TASK-0805 |
| Tests | VT-SEC-004 |
| Verification | test |

**Rationale**

This requirement makes public receiver challenge explicit and independently verifiable.

**Acceptance criteria**

- A replayed, missing, wrong-host, or expired challenge fails closed.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Requires receiver-side acknowledgement that the endpoint is safe for tests.

---

### SEC-005 — Permanently blocked addresses

**Normative statement:** Unspecified, multicast, IPv4/IPv6 link-local, and cloud metadata addresses MUST remain blocked in every v0.1 profile.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-100 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0305, TASK-0805 |
| Tests | VT-SEC-005 |
| Verification | test |

**Rationale**

This requirement makes permanently blocked addresses explicit and independently verifiable.

**Acceptance criteria**

- A table-driven IPv4/IPv6 corpus rejects all special blocked ranges with no override path.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Blocks metadata-service and special-address SSRF.

---

### SEC-006 — All-address DNS validation

**Normative statement:** A hostname MUST be rejected if any resolved A or AAAA address violates its target profile.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-100 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0306, TASK-0805 |
| Tests | VT-SEC-006 |
| Verification | test |

**Rationale**

This requirement makes all-address dns validation explicit and independently verifiable.

**Acceptance criteria**

- A mixed safe/unsafe DNS answer fails rather than selecting only the safe address.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents round-robin and rebinding policy bypass.

---

### SEC-007 — DNS result pinning

**Normative statement:** A delivery MUST use a specific authorized resolved address for the socket connection.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0306, TASK-0805 |
| Tests | VT-SEC-007 |
| Verification | test |

**Rationale**

This requirement makes dns result pinning explicit and independently verifiable.

**Acceptance criteria**

- A DNS answer changed after authorization cannot alter the connected peer.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents DNS rebinding TOCTOU.

---

### SEC-008 — Peer verification

**Normative statement:** The dialer MUST verify that the connected peer address equals the pinned authorized address before sending request bytes.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0306, TASK-0805 |
| Tests | VT-SEC-008 |
| Verification | test |

**Rationale**

This requirement makes peer verification explicit and independently verifiable.

**Acceptance criteria**

- A transport returning a different peer aborts before body transmission.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Detects resolver or transport redirection.

---

### SEC-009 — Redirect prohibition

**Normative statement:** Receiver, observer, and preflight clients MUST disable redirect following.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-100 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0308, TASK-0503, TASK-0805 |
| Tests | VT-SEC-009 |
| Verification | test |

**Rationale**

This requirement makes redirect prohibition explicit and independently verifiable.

**Acceptance criteria**

- 301 through 308 responses create no follow-up request.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents allowlist bypass.

---

### SEC-010 — Ambient proxy prohibition

**Normative statement:** Receiver, observer, and preflight clients MUST ignore ambient proxy configuration.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-021 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0308, TASK-0503, TASK-0805 |
| Tests | VT-SEC-010 |
| Verification | test |

**Rationale**

This requirement makes ambient proxy prohibition explicit and independently verifiable.

**Acceptance criteria**

- Proxy environment variables do not receive any test request.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents proxy-based destination bypass and credential leakage.

---

### SEC-011 — TLS default

**Normative statement:** TLS certificate and hostname verification MUST remain enabled unless a project-confined test CA is explicitly configured.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0308, TASK-0805 |
| Tests | VT-SEC-011 |
| Verification | test |

**Rationale**

This requirement makes tls default explicit and independently verifiable.

**Acceptance criteria**

- verify=false is absent from the configuration schema.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents insecure global TLS bypass.

---

### SEC-012 — Test CA confinement

**Normative statement:** A configured test CA path MUST resolve to a regular file within an approved project or secret root.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0105, TASK-0308, TASK-0805 |
| Tests | VT-SEC-012 |
| Verification | test |

**Rationale**

This requirement makes test ca confinement explicit and independently verifiable.

**Acceptance criteria**

- Traversal, directory, device, and symlink-escape paths fail validation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents arbitrary file access and trust-store substitution.

---

### SEC-013 — Secret serialization prohibition

**Normative statement:** Plaintext secret bytes MUST NOT be serialized to manifests, SQLite, JSON Lines, JUnit, HTML, or ordinary logs.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0106, TASK-0805 |
| Tests | VT-SEC-013 |
| Verification | test |

**Rationale**

This requirement makes secret serialization prohibition explicit and independently verifiable.

**Acceptance criteria**

- Canary secrets are absent from a byte scan of the complete run directory.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents credential disclosure.

---

### SEC-014 — Secret lifetime

**Normative statement:** Resolved secret byte buffers MUST exist only for the operation that needs them and remain absent from reportable models.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0106 |
| Tests | VT-SEC-014 |
| Verification | test |

**Rationale**

This requirement makes secret lifetime explicit and independently verifiable.

**Acceptance criteria**

- Secret handles expose use-with callback semantics and model dumps contain only references/fingerprints.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces accidental retention and serialization.

---

### SEC-015 — Temporary file permissions

**Normative statement:** New run, blob, database, and temporary artifact files MUST request owner-only permissions where the operating system supports them.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0107, TASK-0201, TASK-0605, TASK-0805 |
| Tests | VT-SEC-015 |
| Verification | test |

**Rationale**

This requirement makes temporary file permissions explicit and independently verifiable.

**Acceptance criteria**

- POSIX tests observe mode 0600 for files and 0700 for run directories subject to umask tightening.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Limits local data exposure.

---

### SEC-016 — Path root confinement

**Normative statement:** Every configuration-derived filesystem path MUST be normalized and confined to its declared root before use.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0105, TASK-0805 |
| Tests | VT-SEC-016 |
| Verification | test |

**Rationale**

This requirement makes path root confinement explicit and independently verifiable.

**Acceptance criteria**

- Absolute escape, .. traversal, alternate separators, and Windows drive/UNC escape cases are rejected.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents arbitrary file read/write.

---

### SEC-017 — Symlink escape rejection

**Normative statement:** The fixture, secret, observer working-directory, and report writers MUST reject symlink resolution outside their declared roots.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0106, TASK-0107, TASK-0502, TASK-0605, TASK-0805 |
| Tests | VT-SEC-017 |
| Verification | test |

**Rationale**

This requirement makes symlink escape rejection explicit and independently verifiable.

**Acceptance criteria**

- A race-resistant symlink test cannot read or overwrite an external canary file.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents symlink traversal.

---

### SEC-018 — No fixture archives

**Normative statement:** The v0.1 core MUST NOT extract user-supplied fixture archives.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0107 |
| Tests | VT-SEC-018 |
| Verification | test |

**Rationale**

This requirement makes no fixture archives explicit and independently verifiable.

**Acceptance criteria**

- Archive extensions are treated as raw fixtures and no extraction library is invoked.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Removes archive traversal and decompression-bomb attack surface.

---

### SEC-019 — Shell prohibition

**Normative statement:** Observer and lifecycle process adapters MUST invoke executables without a shell.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-101 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0502, TASK-0805 |
| Tests | VT-SEC-019 |
| Verification | test |

**Rationale**

This requirement makes shell prohibition explicit and independently verifiable.

**Acceptance criteria**

- Static analysis and tests find no shell=True or command-string execution path.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents command injection.

---

### SEC-020 — Executable allowlist

**Normative statement:** An observer or lifecycle executable MUST resolve to an explicitly configured project-confined path or approved absolute executable.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0502, TASK-0805 |
| Tests | VT-SEC-020 |
| Verification | test |

**Rationale**

This requirement makes executable allowlist explicit and independently verifiable.

**Acceptance criteria**

- PATH search is disabled unless a specific allowlisted executable name policy is configured.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents executable path hijacking.

---

### SEC-021 — Subprocess resource limits

**Normative statement:** Observer and lifecycle subprocesses MUST have configured timeout and output limits.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0502, TASK-0805 |
| Tests | VT-SEC-021 |
| Verification | test |

**Rationale**

This requirement makes subprocess resource limits explicit and independently verifiable.

**Acceptance criteria**

- Hanging and output-flooding children are terminated and classified.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents denial of service.

---

### SEC-022 — Terminal control sanitization

**Normative statement:** Human-readable terminal output MUST escape or replace C0 controls other than tab/newline and every ANSI escape byte from untrusted data.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0604, TASK-0801, TASK-0805 |
| Tests | VT-SEC-022 |
| Verification | test |

**Rationale**

This requirement makes terminal control sanitization explicit and independently verifiable.

**Acceptance criteria**

- Malicious fixture and observer strings cannot change terminal title, color, cursor, or hyperlinks.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents terminal escape injection.

---

### SEC-023 — Structured log sanitization

**Normative statement:** Structured logs MUST encode untrusted strings as JSON values and cap each field length.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0601, TASK-0805 |
| Tests | VT-SEC-023 |
| Verification | test |

**Rationale**

This requirement makes structured log sanitization explicit and independently verifiable.

**Acceptance criteria**

- Newlines and control characters cannot create forged log records.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents log injection and disk exhaustion.

---

### SEC-024 — HTML report safety

**Normative statement:** The HTML reporter MUST use a template engine with autoescaping enabled and no unsafe-markup escape hatch for evidence values.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-102 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0604, TASK-0805 |
| Tests | VT-SEC-024 |
| Verification | test |

**Rationale**

This requirement makes html report safety explicit and independently verifiable.

**Acceptance criteria**

- Template tests fail if an evidence value is marked safe.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents stored report XSS.

---

### SEC-025 — Input size validation

**Normative statement:** Configuration, fixtures, observer messages, responses, and report fields MUST be size-checked before unbounded parsing or retention.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0104, TASK-0107, TASK-0308, TASK-0502, TASK-0805 |
| Tests | VT-SEC-025 |
| Verification | test |

**Rationale**

This requirement makes input size validation explicit and independently verifiable.

**Acceptance criteria**

- Each input class has a boundary test and a classified resource_limit diagnostic.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents memory and disk exhaustion.

---

### SEC-026 — Concurrency cap

**Normative statement:** Runtime concurrency MUST be bounded by configuration and the v0.1 hard maximum.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0303, TASK-0805 |
| Tests | VT-SEC-026 |
| Verification | test |

**Rationale**

This requirement makes concurrency cap explicit and independently verifiable.

**Acceptance criteria**

- Task creation never exceeds the configured cap under duplicate and retry scenarios.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents socket and memory exhaustion.

---

### SEC-027 — Untrusted plugin prohibition

**Normative statement:** The v0.1 runtime MUST NOT load code from entry-point plugins or configuration paths.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0001, TASK-0805 |
| Tests | VT-SEC-027 |
| Verification | test |

**Rationale**

This requirement makes untrusted plugin prohibition explicit and independently verifiable.

**Acceptance criteria**

- Installed packages cannot alter runtime behavior through plugin entry points.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Removes an untrusted code-execution boundary.

---

### SEC-028 — Least-privilege GitHub Action

**Normative statement:** The GitHub Action MUST declare no write permission by default.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0803, TASK-0805 |
| Tests | VT-SEC-028 |
| Verification | test |

**Rationale**

This requirement makes least-privilege github action explicit and independently verifiable.

**Acceptance criteria**

- The action documentation and example workflow use contents: read and omit write scopes.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces CI token compromise impact.

---

### SEC-029 — Raw artifact upload opt-in

**Normative statement:** The GitHub Action MUST NOT upload raw run-bundle blobs unless the user explicitly enables that output.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0803, TASK-0805 |
| Tests | VT-SEC-029 |
| Verification | test |

**Rationale**

This requirement makes raw artifact upload opt-in explicit and independently verifiable.

**Acceptance criteria**

- Default action artifacts contain redacted reports and no blobs directory.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents sensitive fixture disclosure through CI artifacts.

---

### SEC-030 — Dependency vulnerability scanning

**Normative statement:** Release CI MUST fail on known high-severity vulnerabilities without an approved, expiring exception.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-104 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0808 |
| Tests | VT-SEC-030 |
| Verification | test |

**Rationale**

This requirement makes dependency vulnerability scanning explicit and independently verifiable.

**Acceptance criteria**

- The release gate consumes a machine-readable exception file with owner and expiry.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces vulnerable dependency release risk.

---

### SEC-031 — SBOM generation

**Normative statement:** Every release MUST include an SPDX or CycloneDX SBOM for wheels and the container image.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-099, SRC-104 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0808 |
| Tests | VT-SEC-031 |
| Verification | test |

**Rationale**

This requirement makes sbom generation explicit and independently verifiable.

**Acceptance criteria**

- Release validation verifies subject digests in the SBOM and attestation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Supports dependency inventory and response.

---

### SEC-032 — Trusted publishing

**Normative statement:** PyPI publication MUST use OIDC Trusted Publishing rather than a long-lived upload token.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-096, SRC-098 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0808 |
| Tests | VT-SEC-032 |
| Verification | test |

**Rationale**

This requirement makes trusted publishing explicit and independently verifiable.

**Acceptance criteria**

- The release workflow has id-token write, contains no PyPI secret reference, and publishes an attested artifact.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces package credential theft.

---

### SEC-033 — Artifact provenance

**Normative statement:** Release wheels and container images MUST receive build provenance attestations.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-099 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0808 |
| Tests | VT-SEC-033 |
| Verification | test |

**Rationale**

This requirement makes artifact provenance explicit and independently verifiable.

**Acceptance criteria**

- gh attestation verify succeeds for release subjects.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Makes release origin verifiable.

---

### SEC-034 — Vulnerability reporting

**Normative statement:** The repository MUST publish a private vulnerability-reporting path and supported-version policy.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-104 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0808 |
| Tests | VT-SEC-034 |
| Verification | test |

**Rationale**

This requirement makes vulnerability reporting explicit and independently verifiable.

**Acceptance criteria**

- SECURITY.md names contact/process, supported versions, response stages, and disclosure expectations.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### SEC-035 — ASVS and SSDF mapping

**Normative statement:** Security requirements MUST map to ASVS 5.0.0 and SSDF 1.1 only where the control semantics genuinely apply.

| Field | Value |
| --- | --- |
| Type | SEC |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-002, UC-004 |
| Sources | SRC-103, SRC-104, SRC-105 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-TARGET, ARC-SECRET |
| Tasks | TASK-0809 |
| Tests | VT-SEC-035 |
| Verification | test |

**Rationale**

This requirement makes asvs and ssdf mapping explicit and independently verifiable.

**Acceptance criteria**

- The threat model labels unmapped requirements rather than forcing an identifier.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PRIV-001 — Request body logging default

**Normative statement:** Ordinary logs MUST record request-body digest and size but not request-body content.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0308, TASK-0601 |
| Tests | VT-PRIV-001 |
| Verification | test |

**Rationale**

This requirement makes request body logging default explicit and independently verifiable.

**Acceptance criteria**

- A body canary is absent from text and structured logs.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PRIV-002 — Response body logging default

**Normative statement:** Ordinary logs MUST record response-body digest, size, and truncation state but not response-body content.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0308, TASK-0601 |
| Tests | VT-PRIV-002 |
| Verification | test |

**Rationale**

This requirement makes response body logging default explicit and independently verifiable.

**Acceptance criteria**

- A response canary is absent from logs.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PRIV-003 — Header redaction defaults

**Normative statement:** Authorization, Proxy-Authorization, Cookie, Set-Cookie, and signer-owned signature headers MUST be redacted by default.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0308, TASK-0601 |
| Tests | VT-PRIV-003 |
| Verification | test |

**Rationale**

This requirement makes header redaction defaults explicit and independently verifiable.

**Acceptance criteria**

- Default evidence renders a stable redacted marker for each header.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PRIV-004 — Configured JSON Pointer redaction

**Normative statement:** Redaction MUST support exact JSON Pointer paths over valid JSON previews.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0601 |
| Tests | VT-PRIV-004 |
| Verification | test |

**Rationale**

This requirement makes configured json pointer redaction explicit and independently verifiable.

**Acceptance criteria**

- Nested objects and arrays redact only configured paths while invalid JSON falls back to no-body preview.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PRIV-005 — Redaction before persistence

**Normative statement:** Sensitive body previews and header values MUST be redacted before insertion into SQLite.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0309, TASK-0504 |
| Tests | VT-PRIV-005 |
| Verification | test |

**Rationale**

This requirement makes redaction before persistence explicit and independently verifiable.

**Acceptance criteria**

- A byte scan of the journal finds no canary secret.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Prevents later reporters from recovering sensitive values.

---

### PRIV-006 — Redaction failure closed

**Normative statement:** A redaction-processing error MUST omit the affected preview rather than persist or display unredacted data.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0601 |
| Tests | VT-PRIV-006 |
| Verification | test |

**Rationale**

This requirement makes redaction failure closed explicit and independently verifiable.

**Acceptance criteria**

- Malformed JSON with configured pointer redaction yields preview_omitted and no body content.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Fails closed on privacy controls.

---

### PRIV-007 — Stable correlation hash

**Normative statement:** Optional value correlation MUST use an HMAC with an ephemeral run-specific redaction key rather than an unsalted hash.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0106, TASK-0601 |
| Tests | VT-PRIV-007 |
| Verification | test |

**Rationale**

This requirement makes stable correlation hash explicit and independently verifiable.

**Acceptance criteria**

- Equal values correlate within one run but not across runs and the key is not persisted.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Reduces dictionary attacks on redacted low-entropy values.

---

### PRIV-008 — Raw blob visibility

**Normative statement:** The CLI MUST label run-bundle blobs as potentially sensitive and exclude them from default inspect output.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0606, TASK-0801 |
| Tests | VT-PRIV-008 |
| Verification | test |

**Rationale**

This requirement makes raw blob visibility explicit and independently verifiable.

**Acceptance criteria**

- Inspect requires an explicit raw-artifact option and a TTY warning for blob paths.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PRIV-009 — Observer evidence minimization

**Normative statement:** Observer requests MUST name the required evidence fields instead of requesting an unrestricted state dump.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0501, TASK-0701 |
| Tests | VT-PRIV-009 |
| Verification | test |

**Rationale**

This requirement makes observer evidence minimization explicit and independently verifiable.

**Acceptance criteria**

- The reference observer returns only requested capabilities and evidence names.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

Minimizes application-state collection.

---

### PRIV-010 — Retention default

**Normative statement:** The core CLI MUST leave generated run data local and untouched by automatic upload or deletion behavior.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0311, TASK-0803 |
| Tests | VT-PRIV-010 |
| Verification | test |

**Rationale**

This requirement makes retention default explicit and independently verifiable.

**Acceptance criteria**

- A complete run performs no upload and no automatic retention deletion.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PRIV-011 — CI artifact warning

**Normative statement:** The GitHub Action MUST warn when configured artifacts include raw blobs or receiver snapshots.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0803 |
| Tests | VT-PRIV-011 |
| Verification | test |

**Rationale**

This requirement makes ci artifact warning explicit and independently verifiable.

**Acceptance criteria**

- The action summary names sensitive artifact classes before upload.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PRIV-012 — Crash diagnostic privacy

**Normative statement:** Crash and internal-error diagnostics MUST identify records by IDs and classifications without embedding raw payloads or secrets.

| Field | Value |
| --- | --- |
| Type | PRIV |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-005 |
| Goals | GOAL-004 |
| Use cases | UC-004, UC-007, UC-008 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SECRET, ARC-REPORT-HTML |
| Tasks | TASK-0002, TASK-0806 |
| Tests | VT-PRIV-012 |
| Verification | test |

**Rationale**

This requirement makes crash diagnostic privacy explicit and independently verifiable.

**Acceptance criteria**

- Forced crashes contain only IDs, hashes, safe exception type, and incident code.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-001 — Pre-send persistence

**Normative statement:** An attempt MUST enter pre_send_committed in SQLite before the executor may begin connection establishment.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0309, TASK-0806 |
| Tests | VT-REL-001 |
| Verification | test |

**Rationale**

This requirement makes pre-send persistence explicit and independently verifiable.

**Acceptance criteria**

- Crash before connection leaves a durable attempt requiring recovery classification.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-002 — Conservative interrupted-send state

**Normative statement:** An attempt found in connecting, sending, or awaiting_response after process restart MUST become unknown_outcome.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-005 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0206, TASK-0806 |
| Tests | VT-REL-002 |
| Verification | test |

**Rationale**

This requirement makes conservative interrupted-send state explicit and independently verifiable.

**Acceptance criteria**

- Crash tests at each phase produce unknown_outcome unless durable evidence proves no connection was established.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-003 — Known no-send exception

**Normative statement:** An in-process failure proven to occur before a socket connection is established MUST terminate the attempt as not_sent.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0308, TASK-0309 |
| Tests | VT-REL-003 |
| Verification | test |

**Rationale**

This requirement makes known no-send exception explicit and independently verifiable.

**Acceptance criteria**

- Resolver rejection and connection refusal are eligible for configured retry without ambiguity.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-004 — Default ambiguity policy

**Normative statement:** Resume MUST default to stopping before any planned delivery whose predecessor attempt is ambiguous.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0207, TASK-0801 |
| Tests | VT-REL-004 |
| Verification | test |

**Rationale**

This requirement makes default ambiguity policy explicit and independently verifiable.

**Acceptance criteria**

- resume without --on-ambiguous does not contact the receiver and exits 4.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-005 — Observe ambiguity policy

**Normative statement:** The observe ambiguity policy MUST reconcile only through a configured read-only observer and decisive assertion set.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0509 |
| Tests | VT-REL-005 |
| Verification | test |

**Rationale**

This requirement makes observe ambiguity policy explicit and independently verifiable.

**Acceptance criteria**

- Inconclusive, pending, unsupported, or contradictory evidence leaves the delivery ambiguous.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-006 — Redeliver ambiguity policy

**Normative statement:** The redeliver ambiguity policy MUST create a new physical attempt while preserving the logical event and planned delivery identity.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0207, TASK-0309 |
| Tests | VT-REL-006 |
| Verification | test |

**Rationale**

This requirement makes redeliver ambiguity policy explicit and independently verifiable.

**Acceptance criteria**

- The original unknown attempt remains immutable and the new attempt has the next ordinal and a distinct attempt_id.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-007 — Explicit redelivery consent

**Normative statement:** Redelivery after ambiguity MUST require a scenario policy and an explicit resume command option.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0207, TASK-0801 |
| Tests | VT-REL-007 |
| Verification | test |

**Rationale**

This requirement makes explicit redelivery consent explicit and independently verifiable.

**Acceptance criteria**

- Config-only or CLI-only consent is insufficient.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-008 — Outcome and retry atomicity

**Normative statement:** A terminal attempt outcome and any newly eligible retry schedule MUST commit in one transaction.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0203, TASK-0309, TASK-0806 |
| Tests | VT-REL-008 |
| Verification | test |

**Rationale**

This requirement makes outcome and retry atomicity explicit and independently verifiable.

**Acceptance criteria**

- Crash after outcome commit cannot omit or duplicate the derived retry schedule.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-009 — Observer rerun safety

**Normative statement:** Automatic observer retries MUST be limited to observers that declared read_only and idempotent capability.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0501, TASK-0504 |
| Tests | VT-REL-009 |
| Verification | test |

**Rationale**

This requirement makes observer rerun safety explicit and independently verifiable.

**Acceptance criteria**

- A non-idempotent observer error is terminal and not retried.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-010 — Report recovery

**Normative statement:** A crash during report generation MUST NOT change the run verdict or execution state.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0605, TASK-0806 |
| Tests | VT-REL-010 |
| Verification | test |

**Rationale**

This requirement makes report recovery explicit and independently verifiable.

**Acceptance criteria**

- Resume or report regenerates artifacts from the journal without sending traffic.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-011 — Cancellation persistence

**Normative statement:** Cancellation MUST persist every transition known before the cancellation deadline and mark unfinished nonterminal work resumable.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0310, TASK-0806 |
| Tests | VT-REL-011 |
| Verification | test |

**Rationale**

This requirement makes cancellation persistence explicit and independently verifiable.

**Acceptance criteria**

- A cancelled run contains no fabricated terminal receiver result.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-012 — Run lock takeover

**Normative statement:** A stale run lock MUST require explicit takeover after the tool verifies that the recorded local process is not alive.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0204 |
| Tests | VT-REL-012 |
| Verification | test |

**Rationale**

This requirement makes run lock takeover explicit and independently verifiable.

**Acceptance criteria**

- A live owner blocks takeover and a dead same-host owner can be taken over with an audit event.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-013 — Database corruption handling

**Normative statement:** A failed SQLite integrity check MUST stop execution and preserve the database for diagnosis.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0205, TASK-0207 |
| Tests | VT-REL-013 |
| Verification | test |

**Rationale**

This requirement makes database corruption handling explicit and independently verifiable.

**Acceptance criteria**

- No automatic repair or replacement occurs and exit classification is harness_error.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-014 — Artifact corruption handling

**Normative statement:** A run bundle with a missing or digest-mismatched blob MUST fail before execution.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0110 |
| Tests | VT-REL-014 |
| Verification | test |

**Rationale**

This requirement makes artifact corruption handling explicit and independently verifiable.

**Acceptance criteria**

- No receiver connection occurs after bundle verification failure.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-015 — Migration interruption

**Normative statement:** An interrupted migration MUST leave either the prior schema or the fully committed next schema.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0201, TASK-0806 |
| Tests | VT-REL-015 |
| Verification | test |

**Rationale**

This requirement makes migration interruption explicit and independently verifiable.

**Acceptance criteria**

- Crash-point tests around every migration statement preserve a valid migration ledger.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### REL-016 — Crash matrix coverage

**Normative statement:** The test suite MUST exercise every crash boundary named in the recovery specification.

| Field | Value |
| --- | --- |
| Type | REL |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-004 |
| Goals | GOAL-003 |
| Use cases | UC-005 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-RECOVERY, ARC-JOURNAL |
| Tasks | TASK-0806 |
| Tests | VT-REL-016 |
| Verification | test |

**Rationale**

This requirement makes crash matrix coverage explicit and independently verifiable.

**Acceptance criteria**

- A generated matrix report has no uncovered P0 crash point.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PERF-001 — Startup budget

**Normative statement:** The version and help commands MUST complete within 1.0 second at the 95th percentile on the reference CI runner after a warm filesystem cache.

| Field | Value |
| --- | --- |
| Type | PERF |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-004, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SCHED, ARC-HTTP |
| Tasks | TASK-0807 |
| Tests | VT-PERF-001 |
| Verification | test |

**Rationale**

This requirement makes startup budget explicit and independently verifiable.

**Acceptance criteria**

- Thirty measured invocations meet the percentile budget.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PERF-002 — Plan budget

**Normative statement:** Planning 100 logical events and at most 1000 attempt templates with 1 KiB fixtures MUST complete within 2.0 seconds at the 95th percentile on the reference CI runner.

| Field | Value |
| --- | --- |
| Type | PERF |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-004, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SCHED, ARC-HTTP |
| Tasks | TASK-0807 |
| Tests | VT-PERF-002 |
| Verification | test |

**Rationale**

This requirement makes plan budget explicit and independently verifiable.

**Acceptance criteria**

- The locked benchmark corpus meets the percentile budget without network access.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PERF-003 — Memory budget

**Normative statement:** A 1000-attempt reference run with 64 KiB retained-response caps MUST remain below 256 MiB peak resident memory on the reference Linux runner.

| Field | Value |
| --- | --- |
| Type | PERF |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-004, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SCHED, ARC-HTTP |
| Tasks | TASK-0807 |
| Tests | VT-PERF-003 |
| Verification | test |

**Rationale**

This requirement makes memory budget explicit and independently verifiable.

**Acceptance criteria**

- Peak RSS measurement remains within budget.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PERF-004 — Default concurrency

**Normative statement:** The default delivery concurrency MUST be 10.

| Field | Value |
| --- | --- |
| Type | PERF |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-004, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SCHED, ARC-HTTP |
| Tasks | TASK-0104, TASK-0303 |
| Tests | VT-PERF-004 |
| Verification | test |

**Rationale**

This requirement makes default concurrency explicit and independently verifiable.

**Acceptance criteria**

- Omitted configuration realizes concurrency 10 in the effective snapshot.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PERF-005 — Hard concurrency

**Normative statement:** The v0.1 hard delivery-concurrency limit MUST be 50.

| Field | Value |
| --- | --- |
| Type | PERF |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-004, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SCHED, ARC-HTTP |
| Tasks | TASK-0104, TASK-0303 |
| Tests | VT-PERF-005 |
| Verification | test |

**Rationale**

This requirement makes hard concurrency explicit and independently verifiable.

**Acceptance criteria**

- 50 validates and 51 fails before task creation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PERF-006 — Journal growth

**Normative statement:** Journal and structured evidence growth excluding raw blobs MUST remain below 32 KiB per terminal attempt for the reference corpus.

| Field | Value |
| --- | --- |
| Type | PERF |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-004, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SCHED, ARC-HTTP |
| Tasks | TASK-0807 |
| Tests | VT-PERF-006 |
| Verification | test |

**Rationale**

This requirement makes journal growth explicit and independently verifiable.

**Acceptance criteria**

- The benchmark reports per-attempt growth and remains within budget.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PERF-007 — Report regeneration budget

**Normative statement:** Regenerating all report formats for 1000 attempts MUST complete within 5.0 seconds at the 95th percentile on the reference CI runner.

| Field | Value |
| --- | --- |
| Type | PERF |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-004, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SCHED, ARC-HTTP |
| Tasks | TASK-0605, TASK-0807 |
| Tests | VT-PERF-007 |
| Verification | test |

**Rationale**

This requirement makes report regeneration budget explicit and independently verifiable.

**Acceptance criteria**

- The locked report corpus meets the percentile budget.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PERF-008 — Bounded cleanup

**Normative statement:** Cancellation cleanup MUST complete within 5.0 seconds after the final in-flight timeout cancellation is issued.

| Field | Value |
| --- | --- |
| Type | PERF |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-004, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SCHED, ARC-HTTP |
| Tasks | TASK-0310, TASK-0807 |
| Tests | VT-PERF-008 |
| Verification | test |

**Rationale**

This requirement makes bounded cleanup explicit and independently verifiable.

**Acceptance criteria**

- The cancellation benchmark exits within budget with response streams closed.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### PERF-009 — No load-test claim

**Normative statement:** Performance documentation MUST label throughput measurements as resource budgets rather than receiver load-test results.

| Field | Value |
| --- | --- |
| Type | PERF |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-004, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-009 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-SCHED, ARC-HTTP |
| Tasks | TASK-0809 |
| Tests | VT-PERF-009 |
| Verification | test |

**Rationale**

This requirement makes no load-test claim explicit and independently verifiable.

**Acceptance criteria**

- Documentation contains no RPS capacity claim for receivers.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### COMPAT-001 — Python support

**Normative statement:** The v0.1 package MUST support CPython 3.12, 3.13, and 3.14.

| Field | Value |
| --- | --- |
| Type | COMPAT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-012 |
| Sources | SRC-077, SRC-090, SRC-091, SRC-092, SRC-093 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE |
| Tasks | TASK-0004, TASK-0804 |
| Tests | VT-COMPAT-001 |
| Verification | test |

**Rationale**

This requirement makes python support explicit and independently verifiable.

**Acceptance criteria**

- CI and package-smoke tests pass on all three versions.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### COMPAT-002 — Python implementation

**Normative statement:** The v0.1 compatibility promise MUST be limited to CPython.

| Field | Value |
| --- | --- |
| Type | COMPAT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE |
| Tasks | TASK-0001, TASK-0809 |
| Tests | VT-COMPAT-002 |
| Verification | test |

**Rationale**

This requirement makes python implementation explicit and independently verifiable.

**Acceptance criteria**

- Package metadata and documentation do not claim PyPy or free-threaded support.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### COMPAT-003 — Operating systems

**Normative statement:** The CLI MUST support current GitHub-hosted Ubuntu, macOS, and Windows runners.

| Field | Value |
| --- | --- |
| Type | COMPAT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE |
| Tasks | TASK-0004, TASK-0804 |
| Tests | VT-COMPAT-003 |
| Verification | test |

**Rationale**

This requirement makes operating systems explicit and independently verifiable.

**Acceptance criteria**

- Locked end-to-end smoke tests pass on all three operating systems.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### COMPAT-004 — SQLite minimum

**Normative statement:** Runtime startup MUST require SQLite 3.40.0 or later.

| Field | Value |
| --- | --- |
| Type | COMPAT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE |
| Tasks | TASK-0202, TASK-0804 |
| Tests | VT-COMPAT-004 |
| Verification | test |

**Rationale**

The selected schema and defensive pragmas need a documented modern baseline without requiring WAL.

**Acceptance criteria**

- An injected older version produces unsupported before database creation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### COMPAT-005 — Local filesystem boundary

**Normative statement:** Run databases on network filesystems MUST be documented as unsupported.

| Field | Value |
| --- | --- |
| Type | COMPAT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-012 |
| Sources | SRC-084, SRC-087 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE |
| Tasks | TASK-0809 |
| Tests | VT-COMPAT-005 |
| Verification | test |

**Rationale**

This requirement makes local filesystem boundary explicit and independently verifiable.

**Acceptance criteria**

- Documentation and diagnostics state the boundary and its data-integrity rationale.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### COMPAT-006 — Schema compatibility

**Normative statement:** Artifact schema versions MUST use independent integer major versions and additive backward-compatible minor documentation.

| Field | Value |
| --- | --- |
| Type | COMPAT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE |
| Tasks | TASK-0003, TASK-0809 |
| Tests | VT-COMPAT-006 |
| Verification | test |

**Rationale**

This requirement makes schema compatibility explicit and independently verifiable.

**Acceptance criteria**

- A compatibility matrix defines reader behavior for same-major additions and unknown major versions.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### COMPAT-007 — Manifest reader compatibility

**Normative statement:** A v0.1 reader MUST reject an unknown manifest major version before blob access.

| Field | Value |
| --- | --- |
| Type | COMPAT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE |
| Tasks | TASK-0110 |
| Tests | VT-COMPAT-007 |
| Verification | test |

**Rationale**

This requirement makes manifest reader compatibility explicit and independently verifiable.

**Acceptance criteria**

- Unknown major produces unsupported with no fixture file reads beyond manifest verification.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### COMPAT-008 — Path serialization

**Normative statement:** Persisted artifact paths MUST use forward-slash relative form independent of host operating system.

| Field | Value |
| --- | --- |
| Type | COMPAT |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE |
| Tasks | TASK-0109, TASK-0804 |
| Tests | VT-COMPAT-008 |
| Verification | test |

**Rationale**

This requirement makes path serialization explicit and independently verifiable.

**Acceptance criteria**

- Windows and POSIX generate the same manifest path strings for the same project tree.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### COMPAT-009 — HTTP/2 deferral

**Normative statement:** HTTP/2 MUST remain opt-in experimental or absent from the v0.1 compatibility promise.

| Field | Value |
| --- | --- |
| Type | COMPAT |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-012 |
| Sources | SRC-019 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE |
| Tasks | TASK-0810 |
| Tests | VT-COMPAT-009 |
| Verification | test |

**Rationale**

This requirement makes http/2 deferral explicit and independently verifiable.

**Acceptance criteria**

- Default dependencies do not install h2 and reference tests use HTTP/1.1.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-001 — Five-minute example

**Normative statement:** The repository MUST include a local correct-receiver example that reaches a passing run within five minutes from a clean supported Python installation.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0809 |
| Tests | VT-DX-001 |
| Verification | test |

**Rationale**

This requirement makes five-minute example explicit and independently verifiable.

**Acceptance criteria**

- A scripted documentation test follows only published commands and completes under five minutes on the reference runner.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-002 — Actionable diagnostics

**Normative statement:** Every user-correctable error MUST include a stable diagnostic code, failing field or entity ID, and one corrective action.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0002, TASK-0801 |
| Tests | VT-DX-002 |
| Verification | test |

**Rationale**

This requirement makes actionable diagnostics explicit and independently verifiable.

**Acceptance criteria**

- Snapshot tests cover representative config, target, observer, assertion, and recovery diagnostics.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-003 — No raw stack by default

**Normative statement:** User-correctable failures MUST NOT display a Python traceback in default mode.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0002, TASK-0801 |
| Tests | VT-DX-003 |
| Verification | test |

**Rationale**

This requirement makes no raw stack by default explicit and independently verifiable.

**Acceptance criteria**

- CLI snapshots contain concise diagnostics only.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-004 — Plan preview

**Normative statement:** The plan command MUST summarize counts, target policy, signers, observers, fault operators, and logical duration before execution.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0109, TASK-0801 |
| Tests | VT-DX-004 |
| Verification | test |

**Rationale**

This requirement makes plan preview explicit and independently verifiable.

**Acceptance criteria**

- The preview is generated solely from the bundle and contains no secrets.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-005 — Causal inspect view

**Normative statement:** The inspect command MUST support filtering by scenario, event, delivery, attempt, observation, assertion, or diagnostic ID.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0606 |
| Tests | VT-DX-005 |
| Verification | test |

**Rationale**

This requirement makes causal inspect view explicit and independently verifiable.

**Acceptance criteria**

- Every identifier type returns the linked causal chain in human and JSON modes.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-006 — Configuration examples

**Normative statement:** The repository MUST include minimal and complete configuration examples that validate against the current schema.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0003, TASK-0809 |
| Tests | VT-DX-006 |
| Verification | test |

**Rationale**

This requirement makes configuration examples explicit and independently verifiable.

**Acceptance criteria**

- Schema validation runs on both examples in CI.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-007 — Observer examples

**Normative statement:** The repository MUST include command and HTTP observer examples with protocol contract tests.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0502, TASK-0503, TASK-0809 |
| Tests | VT-DX-007 |
| Verification | test |

**Rationale**

This requirement makes observer examples explicit and independently verifiable.

**Acceptance criteria**

- Both examples pass the same observer test kit.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-008 — Error classification visibility

**Normative statement:** Human reports MUST visibly distinguish receiver, environment, harness, unsupported, cancelled, and ambiguous outcomes.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0604 |
| Tests | VT-DX-008 |
| Verification | test |

**Rationale**

This requirement makes error classification visibility explicit and independently verifiable.

**Acceptance criteria**

- Each classification has a separate label and explanatory action in the golden HTML report.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-009 — No hidden network

**Normative statement:** Commands that perform network activity MUST state the authorized destination before the first connection in human mode.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0801 |
| Tests | VT-DX-009 |
| Verification | test |

**Rationale**

This requirement makes no hidden network explicit and independently verifiable.

**Acceptance criteria**

- run, resume, and replay print or record the destination; validate, plan, inspect, and report perform none.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### DX-010 — Documentation authority

**Normative statement:** Documentation MUST identify which specification, schema, or command help is authoritative when examples conflict.

| Field | Value |
| --- | --- |
| Type | DX |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-001, STAKE-003 |
| Goals | GOAL-006 |
| Use cases | UC-001, UC-011 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-CLI |
| Tasks | TASK-0809 |
| Tests | VT-DX-010 |
| Verification | test |

**Rationale**

This requirement makes documentation authority explicit and independently verifiable.

**Acceptance criteria**

- README and AGENTS.md define precedence and link every normative source artifact.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-001 — PEP 621 metadata

**Normative statement:** Package metadata MUST be declared in pyproject.toml using PEP 621 fields.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0001 |
| Tests | VT-OPS-001 |
| Verification | test |

**Rationale**

This requirement makes pep 621 metadata explicit and independently verifiable.

**Acceptance criteria**

- A build metadata inspection finds no setup.py metadata source.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-002 — Locked development environment

**Normative statement:** CI MUST use the committed uv lockfile with --locked or --frozen behavior.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | SRC-097 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0004 |
| Tests | VT-OPS-002 |
| Verification | test |

**Rationale**

This requirement makes locked development environment explicit and independently verifiable.

**Acceptance criteria**

- CI fails when pyproject dependencies and uv.lock diverge.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-003 — Wheel and sdist

**Normative statement:** Every release MUST build and smoke-test a universal wheel and source distribution.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | SRC-096 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0804, TASK-0802 |
| Tests | VT-OPS-003 |
| Verification | test |

**Rationale**

This requirement makes wheel and sdist explicit and independently verifiable.

**Acceptance criteria**

- Both artifacts install into clean environments and run version plus the minimal example.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-004 — pipx and uvx

**Normative statement:** Installation documentation MUST provide tested pipx and uvx invocation paths.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | SRC-096 |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0804, TASK-0809 |
| Tests | VT-OPS-004 |
| Verification | test |

**Rationale**

This requirement makes pipx and uvx explicit and independently verifiable.

**Acceptance criteria**

- Package smoke tests exercise both paths where the tool is available.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-005 — Non-root container

**Normative statement:** The container image MUST execute as a non-root user by default.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0802, TASK-0803 |
| Tests | VT-OPS-005 |
| Verification | test |

**Rationale**

This requirement makes non-root container explicit and independently verifiable.

**Acceptance criteria**

- Container inspection and runtime id show a nonzero UID.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-006 — Container immutability

**Normative statement:** The container image MUST write only to explicitly mounted run and cache paths.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0802 |
| Tests | VT-OPS-006 |
| Verification | test |

**Rationale**

This requirement makes container immutability explicit and independently verifiable.

**Acceptance criteria**

- A read-only root filesystem run succeeds with writable mounts.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-007 — GitHub Action inputs

**Normative statement:** The GitHub Action MUST expose configuration path, command, report formats, artifact retention, and public-target authorization as typed documented inputs.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0803 |
| Tests | VT-OPS-007 |
| Verification | test |

**Rationale**

This requirement makes github action inputs explicit and independently verifiable.

**Acceptance criteria**

- action.yml input definitions match action contract tests and documentation.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-008 — GitHub Action outputs

**Normative statement:** The GitHub Action MUST expose result category, exit code, run ID, manifest ID, and report directory as outputs.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0803 |
| Tests | VT-OPS-008 |
| Verification | test |

**Rationale**

This requirement makes github action outputs explicit and independently verifiable.

**Acceptance criteria**

- A workflow integration test consumes every output.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-009 — Semantic versioning

**Normative statement:** Package releases MUST use semantic versioning with pre-1.0 compatibility documented explicitly.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0808, TASK-0809 |
| Tests | VT-OPS-009 |
| Verification | test |

**Rationale**

This requirement makes semantic versioning explicit and independently verifiable.

**Acceptance criteria**

- Release policy defines breaking changes for CLI, config, manifest, observer protocol, and Python API.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-010 — Independent schema versions

**Normative statement:** Configuration, manifest, observer protocol, and report schemas MUST version independently from the package.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0002, TASK-0809 |
| Tests | VT-OPS-010 |
| Verification | test |

**Rationale**

This requirement makes independent schema versions explicit and independently verifiable.

**Acceptance criteria**

- Version command prints each version and compatibility documentation maps them.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-011 — Changelog

**Normative statement:** Every release MUST include a changelog entry naming compatibility, migration, security, and schema effects.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0808 |
| Tests | VT-OPS-011 |
| Verification | test |

**Rationale**

This requirement makes changelog explicit and independently verifiable.

**Acceptance criteria**

- Release CI fails when the target version lacks a changelog entry.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-012 — Dependency update policy

**Normative statement:** Dependency updates MUST run the full locked test matrix and require review for security-sensitive transport, parser, crypto, and template changes.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0004, TASK-0808 |
| Tests | VT-OPS-012 |
| Verification | test |

**Rationale**

This requirement makes dependency update policy explicit and independently verifiable.

**Acceptance criteria**

- Dependabot groups and CODEOWNERS/review guidance identify sensitive dependency classes.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-013 — Supported-version policy

**Normative statement:** The project MUST publish which package and schema versions receive security fixes.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0808 |
| Tests | VT-OPS-013 |
| Verification | test |

**Rationale**

This requirement makes supported-version policy explicit and independently verifiable.

**Acceptance criteria**

- SECURITY.md names the current supported release line and end-of-support rule.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### OPS-014 — Release gate

**Normative statement:** A release MUST NOT publish unless lint, typing, tests, schema validation, package smoke, security scan, SBOM, and provenance steps pass.

| Field | Value |
| --- | --- |
| Type | OPS |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-006 |
| Goals | GOAL-004, GOAL-006 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-PACKAGE, ARC-ACTION |
| Tasks | TASK-0808, TASK-0810 |
| Tests | VT-OPS-014 |
| Verification | test |

**Rationale**

This requirement makes release gate explicit and independently verifiable.

**Acceptance criteria**

- The release workflow has explicit dependencies on every required job.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-001 — Unit tests

**Normative statement:** Every pure domain, parser, serializer, policy, and state-transition component MUST have isolated unit tests.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0810 |
| Tests | VT-TEST-001 |
| Verification | test |

**Rationale**

This requirement makes unit tests explicit and independently verifiable.

**Acceptance criteria**

- Coverage inventory maps each listed component to one or more unit test modules.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-002 — Contract tests

**Normative statement:** Every signer, observer, assertion, and reporter implementation MUST pass its category contract suite.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0401, TASK-0501, TASK-0508, TASK-0605 |
| Tests | VT-TEST-002 |
| Verification | test |

**Rationale**

This requirement makes contract tests explicit and independently verifiable.

**Acceptance criteria**

- Adding a built-in implementation without registering the contract tests fails CI.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-003 — Property tests

**Normative statement:** Identifier, generator, scheduler, transition, redaction, and schema-boundary invariants MUST have property-based tests.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | SRC-032 |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0103, TASK-0203, TASK-0302, TASK-0805 |
| Tests | VT-TEST-003 |
| Verification | test |

**Rationale**

This requirement makes property tests explicit and independently verifiable.

**Acceptance criteria**

- Hypothesis profiles run deterministic CI settings and retain minimized reproducers as explicit bundles where relevant.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-004 — Stateful model tests

**Normative statement:** The journal and scheduler state machines MUST have model-based tests comparing executable behavior with a reference model.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | SRC-032 |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0203, TASK-0302 |
| Tests | VT-TEST-004 |
| Verification | test |

**Rationale**

This requirement makes stateful model tests explicit and independently verifiable.

**Acceptance criteria**

- Random action sequences preserve invariants and shrink to a replayable action list.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-005 — Golden manifest tests

**Normative statement:** The deterministic generator, identifiers, manifests, signatures, and reports MUST have versioned golden vectors.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0103, TASK-0109, TASK-0402, TASK-0403, TASK-0605 |
| Tests | VT-TEST-005 |
| Verification | test |

**Rationale**

This requirement makes golden manifest tests explicit and independently verifiable.

**Acceptance criteria**

- Golden updates require an explicit compatibility review marker.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-006 — Crash-point tests

**Normative statement:** Every persistence/network boundary in the crash matrix MUST have a deterministic process-termination test.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0806 |
| Tests | VT-TEST-006 |
| Verification | test |

**Rationale**

This requirement makes crash-point tests explicit and independently verifiable.

**Acceptance criteria**

- The generated crash coverage matrix reports 100 percent P0 boundary coverage.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-007 — Security regression tests

**Normative statement:** Every high-risk threat in the threat model MUST map to at least one automated negative test.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0805 |
| Tests | VT-TEST-007 |
| Verification | test |

**Rationale**

This requirement makes security regression tests explicit and independently verifiable.

**Acceptance criteria**

- The threat-to-test matrix has no unmapped high-risk row.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-008 — Fixture and protocol fuzzing

**Normative statement:** YAML, JSON, JSON Lines, observer protocol, and HTML-report inputs MUST receive bounded fuzz testing.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0003, TASK-0805 |
| Tests | VT-TEST-008 |
| Verification | test |

**Rationale**

This requirement makes fixture and protocol fuzzing explicit and independently verifiable.

**Acceptance criteria**

- Fuzz targets enforce size/time limits and preserve no-crash/no-leak invariants.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-009 — Mutation testing

**Normative statement:** Critical state, security, signature, and redaction modules MUST undergo mutation testing before a stable 1.0 release.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P1 |
| MVP | deferred |
| Status | deferred |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0810 |
| Tests | VT-TEST-009 |
| Verification | test |

**Rationale**

This requirement makes mutation testing explicit and independently verifiable.

**Acceptance criteria**

- The release-readiness checklist defines the mutation score floor and surviving-mutant review.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-010 — Cross-platform tests

**Normative statement:** CLI, paths, run locks, SQLite, subprocess observers, and packaging MUST run on Linux, macOS, and Windows CI.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0004, TASK-0804 |
| Tests | VT-TEST-010 |
| Verification | test |

**Rationale**

This requirement makes cross-platform tests explicit and independently verifiable.

**Acceptance criteria**

- No supported-platform job is allowed to be continue-on-error.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-011 — Offline end-to-end tests

**Normative statement:** The complete P0 reference corpus MUST run with external internet access disabled.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-001 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0711 |
| Tests | VT-TEST-011 |
| Verification | test |

**Rationale**

This requirement makes offline end-to-end tests explicit and independently verifiable.

**Acceptance criteria**

- The e2e job can reach only loopback or its isolated container network.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-012 — Correct receiver tests

**Normative statement:** The correct reference receiver MUST pass every scenario it claims to support.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0701, TASK-0711 |
| Tests | VT-TEST-012 |
| Verification | test |

**Rationale**

This requirement makes correct receiver tests explicit and independently verifiable.

**Acceptance criteria**

- The corpus matrix has no unexpected fail, error, unsupported, or ambiguous result.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-013 — Flawed receiver isolation tests

**Normative statement:** Each flawed receiver MUST pass unrelated scenarios and fail its mapped defect scenarios with expected evidence.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0711 |
| Tests | VT-TEST-013 |
| Verification | test |

**Rationale**

This requirement makes flawed receiver isolation tests explicit and independently verifiable.

**Acceptance criteria**

- Every flawed receiver row in the corpus matrix has one primary violated requirement set.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-014 — Determinism tests

**Normative statement:** Replanning from identical inputs and replaying an unchanged bundle MUST preserve every guaranteed deterministic field.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0109, TASK-0110, TASK-0804 |
| Tests | VT-TEST-014 |
| Verification | test |

**Rationale**

This requirement makes determinism tests explicit and independently verifiable.

**Acceptance criteria**

- A normalized cross-version digest matches the golden digest.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-015 — Migration tests

**Normative statement:** Every supported database migration path MUST be tested from a golden prior-version database.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0201 |
| Tests | VT-TEST-015 |
| Verification | test |

**Rationale**

This requirement makes migration tests explicit and independently verifiable.

**Acceptance criteria**

- Migration output passes integrity, foreign-key, and projection-rebuild checks.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-016 — Package installation tests

**Normative statement:** Wheel, sdist, container, pipx, uvx, and GitHub Action distributions MUST each execute the minimal example.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0802, TASK-0803, TASK-0804 |
| Tests | VT-TEST-016 |
| Verification | test |

**Rationale**

This requirement makes package installation tests explicit and independently verifiable.

**Acceptance criteria**

- Release validation records the command and artifact digest for every distribution surface.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-017 — Performance budget tests

**Normative statement:** Every P0 performance and resource budget MUST have a reproducible benchmark or boundary test.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0807 |
| Tests | VT-TEST-017 |
| Verification | test |

**Rationale**

This requirement makes performance budget tests explicit and independently verifiable.

**Acceptance criteria**

- The final scorecard links each PERF requirement to measured evidence.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-018 — Flake policy

**Normative statement:** A failing test MUST NOT be retried automatically unless it is explicitly classified as an external-environment diagnostic job outside release gates.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0004 |
| Tests | VT-TEST-018 |
| Verification | test |

**Rationale**

This requirement makes flake policy explicit and independently verifiable.

**Acceptance criteria**

- Core CI contains no automatic test retry plugin or retry loop.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-019 — Test cleanup

**Normative statement:** Every integration and end-to-end test MUST clean up processes, sockets, temporary directories, and databases even after failure.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | Locked constraint / design decision |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0711, TASK-0810 |
| Tests | VT-TEST-019 |
| Verification | test |

**Rationale**

This requirement makes test cleanup explicit and independently verifiable.

**Acceptance criteria**

- Leak checks find no child process or listening socket after the suite.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.

---

### TEST-020 — Objective completion evidence

**Normative statement:** Every implementation task MUST name the commands and artifacts that prove completion.

| Field | Value |
| --- | --- |
| Type | TEST |
| Priority | P0 |
| MVP | required |
| Status | approved-for-implementation |
| Confidence | high |
| Stakeholders | STAKE-002, STAKE-007 |
| Goals | GOAL-001, GOAL-002, GOAL-003, GOAL-004, GOAL-005 |
| Use cases | UC-012 |
| Sources | SRC-083 |
| Constraints | CON-LOCK-002 |
| Dependencies | None |
| Conflicts | None |
| Architecture | ARC-REF |
| Tasks | TASK-0003, TASK-0810, TASK-0702, TASK-0703, TASK-0704, TASK-0706, TASK-0707, TASK-0708, TASK-0709, TASK-0710 |
| Tests | VT-TEST-020 |
| Verification | test |

**Rationale**

This requirement makes objective completion evidence explicit and independently verifiable.

**Acceptance criteria**

- task-index validation rejects a task with empty commands_to_run or completion_evidence.

**Failure behavior**

The command returns a classified nonzero result and preserves diagnostic evidence.

**Security or privacy impact**

No additional security or privacy impact beyond the referenced subsystem.
