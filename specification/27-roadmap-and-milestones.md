# Roadmap and Milestones

## v0.1 implementation roadmap

| Phase | Name | Scope | Exit demonstration |
| --- | --- | --- | --- |
| Phase 00 | Foundation | Locked package/tooling layout, validation harness, CI baseline | A clean clone runs lint/type/unit/schema checks. |
| Phase 01 | Domain and schemas | IDs, values, deterministic generator, strict config, fixtures, manifest | Minimal config plans a byte-stable bundle offline. |
| Phase 02 | Journal and state | Migrations, repository, transitions, ownership, recovery scan | Process restart reconstructs a no-network synthetic run. |
| Phase 03 | Scheduler and executor | Clocks, persistent schedule, target policy, HTTP, cancellation | One valid local delivery produces durable attempt evidence. |
| Phase 04 | Signers and mutations | Three profiles and typed mutation pipeline | Golden vectors and altered-body cases pass. |
| Phase 05 | Observers and assertions | Public protocol, command/HTTP adapters, polling, verdicts | One duplicate scenario proves a single observable effect. |
| Phase 06 | Reporting | JSON/JSONL/JUnit/static HTML/exit reduction | All projections agree and contain no canary. |
| Phase 07 | Reference corpus | Correct receiver and isolated flawed receivers | Expected pass/fail matrix is exact offline. |
| Phase 08 | Packaging, security, release | CLI completion, Docker, Action, cross-platform, crash/security/budgets, docs | All readiness gates pass. |

## First vertical slices

1. **Plan-only slice:** strict config → exact fixture snapshot → deterministic ID/schedule → immutable manifest.
2. **Single-delivery slice:** manifest → journal → authorized loopback POST → terminal attempt → JSON summary.
3. **Conformance slice:** duplicate attempts → command observer → processing-count assertion → JUnit/HTML.
4. **Recovery slice:** failpoint after possible send → fresh-process resume → `unknown_outcome` → observer reconciliation.
5. **Security slice:** mixed DNS/public target rejection, secret canary, malicious report content, command argv safety.

The first slices prove the highest-risk boundaries before implementing broad scenario breadth.

## Post-v0.1 gates

- **v0.2 candidate:** two external adapter needs, Ed25519 demand, proven lifecycle profile use, automatic reduction pilot.
- **v0.3 candidate:** schema import only if OpenAPI/AsyncAPI/CloudEvents examples reduce setup materially.
- **1.0 candidate:** stable public surfaces, mutation-test gate, upgrade guarantees, at least three external CI adopters, no unresolved high security/recovery findings.

## Deferred capability prerequisites

- **Ed25519 signing:** a superseding ADR to ADR-024 is the enabling ADR. It must define
  key encodings, secret handling, exact signed bytes, dependency and compatibility scope,
  and provider-specific semantics. Required future tests include official and golden
  vectors, malformed and wrong-key cases, altered-body rejection, key-encoding boundaries,
  secret-canary regressions, and schema/CLI compatibility tests that replace the v0.1
  rejection contract.
- **Direct SQL observer:** a superseding ADR to ADR-010 must identify a concrete receiver
  need, a read-only least-privilege authentication model, versioned query and normalization
  semantics, bounded timeouts and cancellation, and an optional driver boundary isolated
  from core dependencies. Required future tests include adapter contracts, malformed data,
  timeout and cancellation, credential redaction, driver-absence, and supported-database
  compatibility cases.
- **OpenTelemetry and queue-inspection observers:** a superseding ADR to ADR-010 must
  identify a concrete receiver need, read-only APIs, schema-versioned evidence
  normalization, bounded polling and output, an optional client-library boundary isolated
  from core dependencies, and a threat-model review. Required future tests include adapter
  contracts, malformed protocol data, timeout and cancellation, authentication redaction,
  client-library absence, and compatibility cases for each accepted backend.

These prerequisites do not authorize placeholder adapters, external driver dependencies,
entry-point discovery, or other runtime discovery in v0.1.

## Explicitly noncommitted future ideas

Hosted reports, team collaboration, enterprise policy packs, direct database observers, OpenTelemetry, Kubernetes, and additional CI wrappers remain product hypotheses. They do not influence v0.1 component boundaries beyond stable artifact files and process exit behavior.
