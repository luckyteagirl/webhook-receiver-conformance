# Agentic Implementation Plan

## Operating model

One integration owner controls public schemas, error enums, migrations, and command registries. Read-heavy research/review and disjoint implementation packets may run in parallel. Parallel groups are advisory only when exclusive file globs are disjoint and all prerequisites pass.

## Task DAG

| Task | Phase | Title | Dependencies | Parallel group | Exclusive ownership | Complexity |
| --- | --- | --- | --- | --- | --- | --- |
| TASK-0001 | phase-00-foundation | Create package and quality-tool foundation | None | Serial | pyproject.toml, uv.lock, src/webhook_receiver_conformance/**, .python-version | medium |
| TASK-0002 | phase-00-foundation | Define error taxonomy and common primitives | TASK-0001 | PG-00A | src/webhook_receiver_conformance/errors.py, src/webhook_receiver_conformance/types.py, src/webhook_receiver_conformance/version.py | medium |
| TASK-0003 | phase-00-foundation | Install schema and cross-reference validation harness | TASK-0001 | PG-00A | scripts/validate_artifacts.py | medium |
| TASK-0004 | phase-00-foundation | Create baseline CI workflow | TASK-0001 | PG-00A | .github/workflows/ci.yml, .github/dependabot.yml | medium |
| TASK-0101 | phase-01-domain-and-schemas | Implement identifiers and canonical hashing | TASK-0002 | PG-01A | src/webhook_receiver_conformance/domain/identifiers.py, src/webhook_receiver_conformance/domain/hashing.py | medium |
| TASK-0102 | phase-01-domain-and-schemas | Implement domain value objects | TASK-0002 | PG-01A | src/webhook_receiver_conformance/domain/models.py, src/webhook_receiver_conformance/domain/enums.py | medium |
| TASK-0103 | phase-01-domain-and-schemas | Implement deterministic byte generator | TASK-0002 | PG-01A | src/webhook_receiver_conformance/determinism/generator.py | medium |
| TASK-0104 | phase-01-domain-and-schemas | Implement strict project configuration models | TASK-0102, TASK-0003 | PG-01B | src/webhook_receiver_conformance/config/models.py, src/webhook_receiver_conformance/config/schema.py | medium |
| TASK-0105 | phase-01-domain-and-schemas | Implement YAML loader and precedence | TASK-0104 | PG-01C | src/webhook_receiver_conformance/config/loader.py, src/webhook_receiver_conformance/config/diagnostics.py | medium |
| TASK-0106 | phase-01-domain-and-schemas | Implement secret references and fingerprints | TASK-0104 | PG-01C | src/webhook_receiver_conformance/secrets.py | medium |
| TASK-0107 | phase-01-domain-and-schemas | Implement fixture loader and blob snapshotter | TASK-0101, TASK-0104 | PG-01C | src/webhook_receiver_conformance/fixtures/loader.py, src/webhook_receiver_conformance/fixtures/blobs.py | medium |
| TASK-0108 | phase-01-domain-and-schemas | Implement scenario grammar and semantic validation | TASK-0102, TASK-0104 | PG-01B | src/webhook_receiver_conformance/scenario/models.py, src/webhook_receiver_conformance/scenario/validate.py | medium |
| TASK-0109 | phase-01-domain-and-schemas | Implement realized run-bundle compiler | TASK-0101, TASK-0103, TASK-0105, TASK-0106, TASK-0107, TASK-0108 | Serial | src/webhook_receiver_conformance/manifest/compiler.py, src/webhook_receiver_conformance/manifest/models.py | large |
| TASK-0110 | phase-01-domain-and-schemas | Implement run-bundle replay loader | TASK-0109 | Serial | src/webhook_receiver_conformance/manifest/loader.py | medium |
| TASK-0201 | phase-02-journal-and-state | Implement migration framework and initial SQLite schema | TASK-0102 | PG-02A | src/webhook_receiver_conformance/journal/migrations/**, src/webhook_receiver_conformance/journal/schema.py | large |
| TASK-0202 | phase-02-journal-and-state | Implement single-writer journal service | TASK-0201 | PG-02B | src/webhook_receiver_conformance/journal/service.py, src/webhook_receiver_conformance/journal/connection.py | medium |
| TASK-0203 | phase-02-journal-and-state | Implement transition guards and projections | TASK-0202 | Serial | src/webhook_receiver_conformance/journal/transitions.py, src/webhook_receiver_conformance/journal/repositories.py | large |
| TASK-0204 | phase-02-journal-and-state | Implement run-directory ownership lock | TASK-0201 | PG-02B | src/webhook_receiver_conformance/journal/run_lock.py | medium |
| TASK-0205 | phase-02-journal-and-state | Implement journal integrity and artifact registry | TASK-0202 | PG-02C | src/webhook_receiver_conformance/journal/integrity.py, src/webhook_receiver_conformance/journal/artifacts.py | medium |
| TASK-0206 | phase-02-journal-and-state | Implement recovery scanner and ambiguity model | TASK-0203 | Serial | src/webhook_receiver_conformance/recovery/scanner.py, src/webhook_receiver_conformance/recovery/models.py | large |
| TASK-0207 | phase-02-journal-and-state | Implement resume policy engine | TASK-0206 | Serial | src/webhook_receiver_conformance/recovery/policy.py | medium |
| TASK-0301 | phase-03-scheduler-and-executor | Implement clock domains and scaled time | TASK-0102 | PG-03A | src/webhook_receiver_conformance/scheduler/clocks.py | medium |
| TASK-0302 | phase-03-scheduler-and-executor | Implement persistent priority scheduler | TASK-0203, TASK-0301 | Serial | src/webhook_receiver_conformance/scheduler/queue.py, src/webhook_receiver_conformance/scheduler/engine.py | large |
| TASK-0303 | phase-03-scheduler-and-executor | Implement barriers and concurrency groups | TASK-0302 | PG-03B | src/webhook_receiver_conformance/scheduler/barriers.py | medium |
| TASK-0304 | phase-03-scheduler-and-executor | Implement retry and deterministic jitter policies | TASK-0103, TASK-0302 | PG-03B | src/webhook_receiver_conformance/scheduler/retries.py | medium |
| TASK-0305 | phase-03-scheduler-and-executor | Implement destination-policy parser | TASK-0104 | PG-03A | src/webhook_receiver_conformance/network/policy.py, src/webhook_receiver_conformance/network/addresses.py | medium |
| TASK-0306 | phase-03-scheduler-and-executor | Implement pinned destination dialer | TASK-0305 | Serial | src/webhook_receiver_conformance/network/dialer.py, src/webhook_receiver_conformance/network/transport.py | large |
| TASK-0307 | phase-03-scheduler-and-executor | Implement public-target preflight | TASK-0305, TASK-0306 | Serial | src/webhook_receiver_conformance/network/preflight.py | medium |
| TASK-0308 | phase-03-scheduler-and-executor | Implement bounded HTTP attempt executor | TASK-0306, TASK-0301 | Serial | src/webhook_receiver_conformance/http/executor.py, src/webhook_receiver_conformance/http/evidence.py | large |
| TASK-0309 | phase-03-scheduler-and-executor | Integrate attempt lifecycle with journal | TASK-0203, TASK-0304, TASK-0308 | Serial | src/webhook_receiver_conformance/runtime/attempts.py | large |
| TASK-0310 | phase-03-scheduler-and-executor | Implement cancellation and interruption handling | TASK-0309 | Serial | src/webhook_receiver_conformance/runtime/cancellation.py | medium |
| TASK-0311 | phase-03-scheduler-and-executor | Assemble first run vertical slice | TASK-0110, TASK-0204, TASK-0205, TASK-0302, TASK-0309, TASK-0310 | Serial | src/webhook_receiver_conformance/runtime/runner.py, src/webhook_receiver_conformance/cli/run.py | large |
| TASK-0401 | phase-04-signers-and-mutations | Implement signer contract and generic HMAC-SHA256 | TASK-0106, TASK-0107 | PG-04A | src/webhook_receiver_conformance/signatures/base.py, src/webhook_receiver_conformance/signatures/hmac_generic.py | medium |
| TASK-0402 | phase-04-signers-and-mutations | Implement Stripe v1 signer | TASK-0401 | PG-04B | src/webhook_receiver_conformance/signatures/stripe.py | medium |
| TASK-0403 | phase-04-signers-and-mutations | Implement Standard Webhooks HMAC signer | TASK-0401 | PG-04B | src/webhook_receiver_conformance/signatures/standard_webhooks.py | medium |
| TASK-0404 | phase-04-signers-and-mutations | Implement mutation contract and pipeline | TASK-0107, TASK-0401 | PG-04A | src/webhook_receiver_conformance/mutations/base.py, src/webhook_receiver_conformance/mutations/pipeline.py | medium |
| TASK-0405 | phase-04-signers-and-mutations | Implement structural JSON mutations | TASK-0404 | PG-04C | src/webhook_receiver_conformance/mutations/json_ops.py | medium |
| TASK-0406 | phase-04-signers-and-mutations | Implement raw-body and signature mutations | TASK-0402, TASK-0403, TASK-0404 | PG-04C | src/webhook_receiver_conformance/mutations/raw_ops.py, src/webhook_receiver_conformance/mutations/signature_ops.py | medium |
| TASK-0407 | phase-04-signers-and-mutations | Integrate signers and mutations into manifest and executor | TASK-0405, TASK-0406, TASK-0309 | Serial | src/webhook_receiver_conformance/manifest/compiler.py, src/webhook_receiver_conformance/runtime/attempts.py | large |
| TASK-0501 | phase-05-observers-and-assertions | Implement observer protocol models and capability negotiation | TASK-0102, TASK-0003 | PG-05A | src/webhook_receiver_conformance/observers/protocol.py, schemas/observer-evidence.schema.json, schemas/observer-request.schema.json, schemas/observer-response.schema.json, schemas/observation-record.schema.json | medium |
| TASK-0502 | phase-05-observers-and-assertions | Implement command observer | TASK-0501 | PG-05B | src/webhook_receiver_conformance/observers/command.py | medium |
| TASK-0503 | phase-05-observers-and-assertions | Implement HTTP probe observer | TASK-0501, TASK-0308 | PG-05B | src/webhook_receiver_conformance/observers/http_probe.py | medium |
| TASK-0504 | phase-05-observers-and-assertions | Implement observation polling and journaling | TASK-0502, TASK-0503, TASK-0203 | Serial | src/webhook_receiver_conformance/observers/polling.py, src/webhook_receiver_conformance/runtime/observations.py | large |
| TASK-0505 | phase-05-observers-and-assertions | Implement transport assertions | TASK-0309 | PG-05C | src/webhook_receiver_conformance/assertions/transport.py | medium |
| TASK-0506 | phase-05-observers-and-assertions | Implement receiver-state assertions | TASK-0501 | PG-05C | src/webhook_receiver_conformance/assertions/state.py | medium |
| TASK-0507 | phase-05-observers-and-assertions | Implement temporal and composite assertions | TASK-0504, TASK-0506 | PG-05D | src/webhook_receiver_conformance/assertions/temporal.py, src/webhook_receiver_conformance/assertions/composite.py | medium |
| TASK-0508 | phase-05-observers-and-assertions | Integrate assertion lifecycle and verdict classification | TASK-0505, TASK-0507, TASK-0203 | Serial | src/webhook_receiver_conformance/runtime/assertions.py, src/webhook_receiver_conformance/runtime/verdicts.py | large |
| TASK-0509 | phase-05-observers-and-assertions | Implement observer-assisted ambiguity reconciliation | TASK-0207, TASK-0504, TASK-0508 | Serial | src/webhook_receiver_conformance/recovery/reconcile.py | medium |
| TASK-0601 | phase-06-reporting | Implement stable JSON and JSON Lines exports | TASK-0205, TASK-0508 | PG-06A | src/webhook_receiver_conformance/reporting/json_reports.py | medium |
| TASK-0602 | phase-06-reporting | Implement result summary and exit-code precedence | TASK-0508 | PG-06A | src/webhook_receiver_conformance/reporting/summary.py, src/webhook_receiver_conformance/cli/exit_codes.py | medium |
| TASK-0603 | phase-06-reporting | Implement JUnit XML renderer | TASK-0602 | PG-06B | src/webhook_receiver_conformance/reporting/junit.py | medium |
| TASK-0604 | phase-06-reporting | Implement static HTML renderer | TASK-0601, TASK-0602 | PG-06B | src/webhook_receiver_conformance/reporting/html.py, src/webhook_receiver_conformance/reporting/templates/** | medium |
| TASK-0605 | phase-06-reporting | Implement atomic report generation and regeneration | TASK-0205, TASK-0601, TASK-0603, TASK-0604 | Serial | src/webhook_receiver_conformance/reporting/writer.py | medium |
| TASK-0606 | phase-06-reporting | Implement inspect and report commands | TASK-0605 | Serial | src/webhook_receiver_conformance/cli/inspect.py, src/webhook_receiver_conformance/cli/report.py | medium |
| TASK-0701 | phase-07-reference-receivers | Implement correct reference receiver | TASK-0407, TASK-0508 | Serial | reference_receivers/correct/** | large |
| TASK-0702 | phase-07-reference-receivers | No idempotency record receiver | TASK-0701 | PG-07A | reference_receivers/flawed/no-idempotency-record-receiver/** | small |
| TASK-0703 | phase-07-reference-receivers | Check-then-insert race receiver | TASK-0701 | PG-07A | reference_receivers/flawed/check-then-insert-race-receiver/** | small |
| TASK-0704 | phase-07-reference-receivers | Signature-after-parse receiver | TASK-0701 | PG-07A | reference_receivers/flawed/signature-after-parse-receiver/** | small |
| TASK-0705 | phase-07-reference-receivers | Stale-signature-accepting receiver | TASK-0701 | PG-07A | reference_receivers/flawed/stale-signature-accepting-receiver/** | small |
| TASK-0706 | phase-07-reference-receivers | Acknowledge-before-commit receiver | TASK-0701 | PG-07A | reference_receivers/flawed/acknowledge-before-commit-receiver/** | small |
| TASK-0707 | phase-07-reference-receivers | Side-effect-before-deduplication receiver | TASK-0701 | PG-07A | reference_receivers/flawed/side-effect-before-deduplication-receiver/** | small |
| TASK-0708 | phase-07-reference-receivers | Order-assuming receiver | TASK-0701 | PG-07A | reference_receivers/flawed/order-assuming-receiver/** | small |
| TASK-0709 | phase-07-reference-receivers | Sensitive-logging receiver | TASK-0701 | PG-07A | reference_receivers/flawed/sensitive-logging-receiver/** | small |
| TASK-0710 | phase-07-reference-receivers | Crash-after-effect-before-ack receiver | TASK-0701 | PG-07A | reference_receivers/flawed/crash-after-effect-before-ack-receiver/** | small |
| TASK-0711 | phase-07-reference-receivers | Implement reference scenario corpus | TASK-0702, TASK-0703, TASK-0704, TASK-0705, TASK-0706, TASK-0707, TASK-0708, TASK-0709, TASK-0710, TASK-0605 | Serial | examples/scenarios/** | large |
| TASK-0801 | phase-08-packaging-security-and-ci | Complete CLI command tree and help contracts | TASK-0311, TASK-0509, TASK-0606 | Serial | src/webhook_receiver_conformance/cli/** | large |
| TASK-0802 | phase-08-packaging-security-and-ci | Create non-root Docker distribution | TASK-0801 | PG-08A | Dockerfile, .dockerignore | medium |
| TASK-0803 | phase-08-packaging-security-and-ci | Create GitHub Action wrapper | TASK-0801 | PG-08A | action.yml, .github/actions/** | medium |
| TASK-0804 | phase-08-packaging-security-and-ci | Implement cross-platform installation tests | TASK-0801 | PG-08A | .github/workflows/package-test.yml, scripts/package_smoke.py | medium |
| TASK-0805 | phase-08-packaging-security-and-ci | Implement security regression suite | TASK-0307, TASK-0407, TASK-0503, TASK-0604 | PG-08B | tests/security/** | large |
| TASK-0806 | phase-08-packaging-security-and-ci | Implement crash-point matrix suite | TASK-0207, TASK-0309, TASK-0504, TASK-0605 | PG-08B | scripts/crash_harness.py | large |
| TASK-0807 | phase-08-packaging-security-and-ci | Implement quality-attribute budget tests | TASK-0711 | PG-08B | scripts/benchmark.py | medium |
| TASK-0808 | phase-08-packaging-security-and-ci | Implement release security and provenance | TASK-0802, TASK-0804 | Serial | .github/workflows/release.yml, SECURITY.md, scripts/release_check.py | medium |
| TASK-0809 | phase-08-packaging-security-and-ci | Complete documentation and examples | TASK-0711, TASK-0801 | PG-08C | README.md, examples/** | large |
| TASK-0810 | phase-08-packaging-security-and-ci | Run final convergence and release-readiness gate | TASK-0803, TASK-0805, TASK-0806, TASK-0807, TASK-0808, TASK-0809 | Serial | CHANGELOG.md | large |

## Integration checkpoints

- **IC-00:** Package imports and CI quality gates pass.
- **IC-01:** Config/schema/examples and manifest golden vectors agree.
- **IC-02:** Journal model, migrations, transitions, ownership, and recovery audit pass.
- **IC-03:** Single valid loopback delivery completes with no observer.
- **IC-04:** Signer/mutation profiles pass golden and transport integration tests.
- **IC-05:** Observer/assertion duplicate vertical slice passes.
- **IC-06:** Report renderers and exit-code reducer agree.
- **IC-07:** Correct/flawed corpus matrix passes offline.
- **IC-08:** Cross-platform package, security, crash, budgets, provenance, and documentation converge.

## Safe parallelism

A task may start in parallel only when every dependency is complete, its `parallel_group` matches the intended group, and no allowed/exclusive pattern overlaps another active task. Tests that exercise a shared public interface do not grant ownership of that interface. The integration owner resolves generated files after the group.

## Task packet protocol

1. Read packet and every cited requirement/ADR/interface.
2. Confirm allowed and forbidden files.
3. Run baseline commands.
4. Implement only the objective and explicit acceptance criteria.
5. Add/modify mapped tests.
6. Run packet commands and cross-artifact validation.
7. Return completion evidence and stop.

## First task

`TASK-0001` creates the reproducible package/tool foundation and has no implementation dependencies. It intentionally does not define domain contracts; those are already fixed in this specification and begin in parallel only after the foundation exists.

## Large-task policy

A task marked `large` is still one focused agent run because it owns one coherent boundary. If implementation reveals unrelated decisions or more than one public interface, stop and split the task through a specification change; do not improvise a broader packet.
