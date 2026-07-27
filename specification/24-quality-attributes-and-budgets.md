# Quality Attributes and Budgets

## Priority order

Correctness and evidence integrity > security/privacy > recovery honesty > deterministic planning > diagnosability > portability > performance > extensibility. Throughput targets are diagnostic and explicitly not load-testing claims.

## Budgets

| Attribute | Budget | Measurement | Requirement |
| --- | --- | --- | --- |
| Startup | <= 750 ms p95 | `webhook-conformance version` on supported CI baseline after warm filesystem cache | PERF-001 |
| Minimal validation | <= 1.5 s p95 | One 4 KiB fixture, no network | PERF-002 |
| Plan 1,000 events / 5,000 attempts | <= 10 s p95 | Reference workstation, blobs already local | PERF-003 |
| Execution overhead | <= 5 ms p50 / 20 ms p95 per attempt excluding network/wait | Loopback no-op receiver, concurrency 8 | PERF-004 |
| Memory | <= 256 MiB RSS at max supported planning corpus | 1,000 events, 5,000 attempts, 1 MiB average not all resident | PERF-005 |
| Disk metadata | <= 4 KiB journal growth per ordinary attempt excluding retained bodies | One response metadata/evidence set | PERF-006 |
| Report generation | <= 5 s for 5,000 attempts and <= 128 MiB RSS incremental | Static report, no raw bodies | PERF-007 |
| Request limits | 1 MiB default; 16 MiB hard | Before allocation/send | PERF-008 |
| Response capture | 64 KiB default; 1 MiB hard capture; 1 MiB drain | Streaming bounded client | PERF-009 |
| Core CI | <= 15 minutes per supported platform job | Excludes nightly fuzz/mutation exhaustive jobs | TEST/OPS |
| Crash recovery | No planned entity silently omitted; preview <= 5 s for max corpus | Healthy local database | REL |
| Determinism | 100% equality for guaranteed normalized fields | Same bundle/tool-compatible schema | SCHED |
| Installation | Wheel/sdist compressed <= 10 MiB excluding optional reference extras | Release artifact | OPS |

## Reliability

- No committed manifest or blob changes after planning.
- No silent loss of scheduled work after any crash matrix point.
- Every possible-send/no-outcome case remains ambiguous until explicit evidence/policy.
- Report regeneration is idempotent from committed state.
- Illegal transitions stop the run rather than being coerced.

## Security/privacy

- Zero known secret-canary occurrences in default artifacts.
- Zero allowed connection to unconditionally forbidden address classes.
- Zero active-script execution in report corpus under supported browsers/static inspection.
- Zero shell interpolation paths.
- High-risk threat matrix 100% automated-test mapped.

## Compatibility

- Linux, macOS, Windows; CPython 3.12–3.14.
- Public schemas reject unknown major versions and unknown fields by default.
- A reader may ignore only extension fields in an explicitly declared extension map; v0.1 base schemas use closed objects.
- Migration tests cover every supported database/config path.

## Maintainability

- Module dependency graph remains acyclic.
- No public plugin API before two concrete external implementations.
- Every public behavior maps to requirement, test, and task.
- Cyclomatic/complexity lint thresholds are implementation settings, but security/state transition functions require direct review and focused tests.

## Observability/usability

- Every failure traces to stable identities and evidence.
- A minimal first run target is 15 minutes from install.
- Validation accumulates path-qualified diagnostics up to a bounded maximum.
- Human and machine outputs remain separated and stable.

## Budget change rule

A budget may change only with benchmark evidence, an ADR or requirement revision, compatibility analysis, and updated tests. A failing budget is not solved by deleting the test or relabeling the product as load testing.
