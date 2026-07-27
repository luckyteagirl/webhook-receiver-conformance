# Interfaces and Contracts

## Interface principles

- Inputs are validated at one boundary and represented internally by typed values.
- Errors have stable categories, safe human messages, optional cause chains for debug mode, and an exit-category mapping.
- No public consumer branches on exception class names from third-party libraries.
- Timeouts are explicit real monotonic durations at external boundaries.
- An interface is idempotent only where stated; retries never occur implicitly.
- Schema/wire versions and package versions are independent.
- Security policy is evaluated before side effects.

## Artifact schema compatibility behavior

Artifact schema majors are independent. A same-major additive field is accepted only when a registered same-major schema revision declares it optional; arbitrary unknown properties remain invalid at a strict current-schema boundary.

| Version relation | Change kind | Reader behavior |
| --- | --- | --- |
| `same-major` | `exact` | `accept` |
| `same-major` | `additive-optional` | `accept` |
| `same-major` | `breaking` | `reject` |
| `unknown-major` | `any` | `reject` |

A breaking change includes removing or renaming a field, adding a required field, changing a field type or meaning, or adding a value that the reader must interpret. It requires a new integer major. An unknown major is rejected before blob access, observer invocation, network activity, or other side effects.

## Identity encoding at serialized boundaries

- `run_id` is a canonical lowercase, hyphenated UUIDv4 and is newly generated for every execution, including replay. It belongs to the execution journal, evidence, and results; it is not serialized in the immutable manifest.
- `manifest_id` is the raw 64-character lowercase hexadecimal SHA-256 digest of the RFC 8785 canonical manifest with `manifest_id` omitted. It does not use the `sha256:` prefix, and no execution-specific `run_id` participates in the manifest.
- Blob, request-body, response-body, header, dependency, and fingerprint digests keep the `sha256:<64 lowercase hexadecimal>` encoding.
- Type-prefixed deterministic IDs are reserved for manifest-planned/domain entities. Physical attempt, observer sample, evaluation, and evidence-record IDs are separately generated and are not replay-stable.
- Canonical manifests admit only JSON integers in the inclusive range `-9007199254740991` through `9007199254740991`. Floating-point values and integers outside this I-JSON interoperable range are rejected. Internal logical time remains signed 64-bit nanoseconds, but the compiler rejects an out-of-profile value before manifest serialization.

## Error envelope

Internal application errors normalize to:

```json
{
  "category": "configuration_error",
  "code": "CFG_UNKNOWN_FIELD",
  "message": "Unknown field at scenarios[0].deliver.retryy",
  "location": {"path": "project.yaml", "line": 42, "column": 9},
  "retryable": false,
  "safe_details": {},
  "cause_category": null
}
```

Human text is not a compatibility surface. Category, code, location shape, retryable flag, and exit mapping are.

## IF-CONFIG — Project configuration loader

| Field | Contract |
| --- | --- |
| Owner | configuration |
| Consumer | CLI and planner |
| Inputs | YAML 1.2 JSON-compatible document plus explicit CLI overrides |
| Outputs | Validated immutable ProjectConfig model |
| Preconditions | Readable path; supported schema_version |
| Postconditions | No secret values rendered; all relative paths normalized |
| Errors | configuration_error, unsupported_schema, secret_reference_error |
| Timeout | none |
| Idempotency | Pure for fixed files, environment, and overrides |
| Versioning | schema_version major/minor |
| Security | Safe parser, unknown-field rejection, path containment |
| Verification | VT-CFG-001, VT-CFG-007 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-PLAN — Manifest compiler

| Field | Contract |
| --- | --- |
| Owner | planning |
| Consumer | CLI run/replay and journal |
| Inputs | Validated ProjectConfig, fixture bytes, seed, adapter metadata |
| Outputs | Immutable execution-agnostic RunManifest and canonical digest |
| Preconditions | No unresolved configuration error |
| Postconditions | All randomness realized; no network activity; no `run_id` embedded in the manifest |
| Errors | planning_error, fixture_error, unsupported_capability |
| Timeout | planning budget |
| Idempotency | Same normalized inputs and algorithm version yield the same manifest bytes |
| Versioning | run manifest schema plus generator_algorithm |
| Security | Digests not raw secrets; target policy snapshot |
| Verification | VT-FR-006, VT-SCHED-001, VT-SCHED-003 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-JOURNAL — Run journal repository

| Field | Contract |
| --- | --- |
| Owner | persistence |
| Consumer | runner, scheduler, recovery, reporting |
| Inputs | Typed commands with expected prior state |
| Outputs | Committed entities and append-only transition/evidence records |
| Preconditions | Run ownership and valid transition guard |
| Postconditions | Transaction is durable under configured policy or no state is exposed |
| Errors | journal_busy, illegal_transition, integrity_error, migration_error |
| Timeout | busy_timeout 5 seconds by default |
| Idempotency | Command idempotency keys prevent duplicate state transitions |
| Versioning | SQLite user_version and migration IDs |
| Security | Contained local path; no secret body storage by default |
| Verification | VT-DATA-001, VT-STATE-007, VT-REL-010 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-SCHED — Logical scheduler

| Field | Contract |
| --- | --- |
| Owner | scheduler |
| Consumer | scenario runner |
| Inputs | Manifest actions and persisted terminal/nonterminal state |
| Outputs | Ordered executable work leases and barrier releases |
| Preconditions | Manifest validated and run active |
| Postconditions | Equal-time actions use stable order keys |
| Errors | schedule_error, deadlock, cancelled |
| Timeout | logical and monotonic deadlines |
| Idempotency | Reconstruction from journal yields the same pending set |
| Versioning | scheduler semantics version in manifest |
| Security | Enforces concurrency/resource caps |
| Verification | VT-SCHED-004, VT-SCHED-007, VT-REL-004 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-HTTP — HTTP attempt executor

| Field | Contract |
| --- | --- |
| Owner | http |
| Consumer | runner |
| Inputs | Exact bytes, ordered headers, target decision, timeout budget |
| Outputs | AttemptResult with classified transport evidence |
| Preconditions | Persisted sending intent and approved resolved target |
| Postconditions | Bounded retained response; no automatic redirect or proxy use |
| Errors | connect_timeout, read_timeout, write_timeout, pool_timeout, tls_error, connection_error, protocol_error, response_too_large, cancelled |
| Timeout | granular plus total monotonic deadline |
| Idempotency | No inherent idempotency; one call is one physical attempt |
| Versioning | internal typed protocol |
| Security | TLS verify, trust_env false, DNS/IP policy, size caps |
| Verification | VT-HTTP-003, VT-HTTP-006, VT-SEC-001 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-SIGNER — Signature adapter

| Field | Contract |
| --- | --- |
| Owner | signatures |
| Consumer | manifest compiler and attempt builder |
| Inputs | Exact body bytes, logical timestamp, typed secret/key reference, adapter config |
| Outputs | Ordered signature headers and public metadata/fingerprints |
| Preconditions | Secret material resolved only at execution boundary |
| Postconditions | Secret value not persisted; covered-byte digest recorded |
| Errors | key_unavailable, unsupported_algorithm, signing_error |
| Timeout | none |
| Idempotency | Deterministic for fixed bytes, key, timestamp, and adapter version |
| Versioning | adapter_id and adapter_version |
| Security | HMAC-SHA256, safe fingerprint, no secret logging |
| Verification | VT-SIG-001, VT-SIG-002, VT-SIG-009 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-MUTATION — Mutation operator

| Field | Contract |
| --- | --- |
| Owner | mutations |
| Consumer | manifest compiler and request builder |
| Inputs | Typed stage input and realized parameters |
| Outputs | Mutated structure or bytes plus evidence |
| Preconditions | Operator compatible with stage and media type |
| Postconditions | Original and resulting digests recorded when bytes exist |
| Errors | mutation_not_applicable, conflicting_mutation, invalid_parameter |
| Timeout | none |
| Idempotency | Manifest-realized operator is deterministic |
| Versioning | operator_id and operator_version |
| Security | Redacted evidence; size caps remain enforced |
| Verification | VT-MUT-001, VT-MUT-009 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-OBSERVER-CMD — Command observer protocol

| Field | Contract |
| --- | --- |
| Owner | observers |
| Consumer | runner and recovery |
| Inputs | ObserverRequest JSON on stdin and argv profile |
| Outputs | One ObserverResponse JSON on stdout |
| Preconditions | Explicit profile enabled; executable and working directory allowed |
| Postconditions | Bounded stderr captured separately; no shell |
| Errors | observer_timeout, observer_protocol_error, observer_process_error, unsupported_capability |
| Timeout | configured monotonic observer timeout |
| Idempotency | Automatic reinvocation requires declared `read_only=true` and `idempotent=true`; retries preserve `request_id` and use a fresh `sample_id` |
| Versioning | protocol_version and capabilities |
| Security | Minimal env, argv-only, path containment, output cap |
| Verification | VT-OBS-001, VT-SEC-006 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-OBSERVER-HTTP — HTTP observer protocol

| Field | Contract |
| --- | --- |
| Owner | observers |
| Consumer | runner and recovery |
| Inputs | Authenticated ObserverRequest JSON |
| Outputs | ObserverResponse JSON |
| Preconditions | Observer target separately approved; `POST /capabilities` handshake succeeds |
| Postconditions | Evidence sanitized before persistence |
| Errors | observer_http_error, observer_auth_error, observer_protocol_error, unsupported_capability |
| Timeout | configured connect/read/total timeout |
| Idempotency | An observe retry preserves logical `request_id`, uses a fresh `sample_id`, and is automatic only when capabilities declare `read_only=true` and `idempotent=true` |
| Versioning | protocol_version and media type |
| Security | Dedicated token reference, TLS/target policy, no credential persistence |
| Verification | VT-OBS-002, VT-OBS-003 |

### Example interaction

The HTTP adapter sends capability requests to `POST /capabilities` and observation requests to `POST /observe`, both relative to the configured base URL. The request body uses `observer-request.schema.json`; an `observe` operation requires `sample_id`, UUIDv4 `run_id`, and at least one query. The response body uses `observer-response.schema.json`. Its capability object declares supported evidence keys, the exact OBS-014 evidence types, `read_only`, and `idempotent`. Every `status=ok` response contains a nonempty `snapshot_id`.

The shared `observer-evidence.schema.json` owns the wire and persisted evidence-type enum: `null`, `boolean`, `integer`, `decimal-string`, `string`, `bytes-digest`, `timestamp`, `array`, and `object`. Binary evidence is digest/metadata, never arbitrary embedded bytes.

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-ASSERT — Assertion evaluator

| Field | Contract |
| --- | --- |
| Owner | assertions |
| Consumer | runner and reporter |
| Inputs | Assertion specification plus normalized transport/observation evidence |
| Outputs | AssertionRecord pass, fail, error, or skipped |
| Preconditions | Required evidence exists or missing-evidence rule applies |
| Postconditions | Comparison is deterministic for normalized evidence |
| Errors | assertion_error, evidence_missing, unsupported_assertion |
| Timeout | eventual assertions use explicit monotonic deadline |
| Idempotency | Pure for fixed normalized evidence |
| Versioning | assertion_type and semantics_version |
| Security | Diagnostic values pass through redaction |
| Verification | VT-ASSERT-001, VT-ASSERT-009 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-REPORT — Report renderer

| Field | Contract |
| --- | --- |
| Owner | reporting |
| Consumer | CLI and CI |
| Inputs | Read-only journal, manifest, and sanitized evidence |
| Outputs | JSONL, summary JSON, JUnit XML, static HTML |
| Preconditions | Authoritative files pass integrity checks |
| Postconditions | Stable ordering; atomic final-file replacement |
| Errors | report_error, artifact_integrity_error, output_limit |
| Timeout | reporting budget |
| Idempotency | Regeneration yields byte-stable outputs except declared generated_at fields |
| Versioning | per-artifact schema version |
| Security | No script, context escaping, CSP, safe paths |
| Verification | VT-REPORT-001, VT-REPORT-005, VT-SEC-010 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-LIFECYCLE — Receiver lifecycle profile

| Field | Contract |
| --- | --- |
| Owner | lifecycle |
| Consumer | scenario runner |
| Inputs | Named argv action and bounded environment |
| Outputs | Lifecycle result plus health-check evidence |
| Preconditions | Profile explicitly enabled and paths allowed |
| Postconditions | No shell; process result persisted |
| Errors | lifecycle_disabled, process_error, readiness_timeout |
| Timeout | per-action monotonic deadline |
| Idempotency | Profile declares whether action is safe to retry |
| Versioning | configuration schema |
| Security | argv-only, minimal env, no arbitrary scenario command |
| Verification | VT-SEC-007, VT-STATE-008 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-CLI — Command-line interface

| Field | Contract |
| --- | --- |
| Owner | CLI |
| Consumer | developer and CI |
| Inputs | argv, stdin where documented, environment references |
| Outputs | stdout result, stderr diagnostic, process exit code |
| Preconditions | Installed supported build |
| Postconditions | Noninteractive mode never prompts |
| Errors | exit codes 0,2,3,4,5,6,7,130 |
| Timeout | command-specific |
| Idempotency | validate/inspect/report are nonmutating or idempotent as specified |
| Versioning | semantic CLI version; deprecation policy |
| Security | Safe terminal rendering and secret-safe diagnostics |
| Verification | VT-CLI-001, VT-CLI-009 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-ACTION — GitHub Action wrapper

| Field | Contract |
| --- | --- |
| Owner | release |
| Consumer | GitHub Actions workflow |
| Inputs | Configuration path, command mode, artifact policy, optional secret references |
| Outputs | CLI exit status, job summary, sanitized artifacts |
| Preconditions | Supported runner and checked-out repository |
| Postconditions | No raw evidence uploaded unless explicitly enabled |
| Errors | Action failure mirrors CLI classification while setup errors are distinct |
| Timeout | workflow-configured |
| Idempotency | One invocation creates one run unless report-only mode |
| Versioning | action major tag and exact release SHA |
| Security | Least-privilege permissions and masked inputs |
| Verification | VT-OPS-007, VT-PRIV-008 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.
## IF-SCHEMA — Machine-readable contract schemas

| Field | Contract |
| --- | --- |
| Owner | contracts |
| Consumer | core, tools, agents, integrations |
| Inputs | JSON-compatible instances |
| Outputs | validation result with instance and schema paths |
| Preconditions | Known $id and schema version |
| Postconditions | No unevaluated properties unless extension point explicitly permits |
| Errors | schema_validation_error |
| Timeout | bounded by input limits |
| Idempotency | Pure |
| Versioning | stable $id plus semantic schema_version |
| Security | Input depth/size limits applied by caller |
| Verification | VT-API-002, VT-CFG-003 |

### Example interaction

The owning task MUST provide a contract test using the corresponding schema or typed model. The consumer MUST handle every documented error category without parsing human message text.

## Additional internal boundaries

| Architecture ID | Owner | Input | Output | Failure boundary |
| --- | --- | --- | --- | --- |
| ARC-PRNG | Determinism | Seed bytes, versioned context, requested shape | Deterministic bytes/integers | Generator contract violation = harness failure |
| ARC-TARGET | Network policy | Parsed URL, target profile, runtime authorization | Pinned authorized destination or rejection | Policy rejection = invalid input; resolver outage = environment failure |
| ARC-HTTP | Transport | Attempt command with exact bytes/headers and pinned target | Sanitized transport evidence | Phase-aware environment/ambiguous/protocol result |
| ARC-RECOVERY | Recovery | Journal, manifest, owner epoch, resume policy | Recovery plan and appended decisions | Integrity mismatch = harness failure; unresolved send = ambiguity |
| ARC-ASSERT | Assertions | Typed evidence and assertion definition | Immutable evaluation | Mismatch = receiver failure; missing required evidence = error/unsupported |

## Public Python API

v0.1 exposes only version metadata, validated model types needed by integrations, observer protocol models, and a `run_cli()` entry point. Internal scheduler/journal/adapter classes are not a semver compatibility promise before 1.0. Direct library orchestration is deferred until real consumers establish a stable use case.
