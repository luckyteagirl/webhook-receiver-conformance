# Architecture

## Architecture drivers

1. Exact-byte, manifest-fixed planning.
2. Honest recovery around an irreversible network-send boundary.
3. Separate transport and application-state evidence.
4. Secure target and untrusted-input handling.
5. Deterministic local/CI operation without a service dependency.
6. A source layout that agents can implement in dependency order.
7. A public surface small enough to maintain before 1.0.

## Style

A **single-process modular monolith** with ports around clocks, deterministic generation, HTTP transport, persistence, observers, process execution, and report sinks. Each run has one owner process and one local SQLite journal. AnyIO provides structured concurrency over the asyncio backend. HTTPX is used through a guarded transport boundary rather than throughout domain code.

## Modules

| Element | Responsibility | Why it exists | Removal consequence |
| --- | --- | --- | --- |
| ARC-CLI | Typer CLI adapter and exit-code mapper | Typer CLI adapter. | A mapped P0 requirement loses an implementation owner. |
| ARC-CONFIG | Strict YAML loader, Pydantic models, and configuration materializer | Strict YAML loader, Pydantic models,. | A mapped P0 requirement loses an implementation owner. |
| ARC-SECRET | Secret-reference resolver and fingerprint service | Secret-reference resolver. | A mapped P0 requirement loses an implementation owner. |
| ARC-FIXTURE | Byte-preserving fixture loader and content-addressed blob store | Byte-preserving fixture loader. | A mapped P0 requirement loses an implementation owner. |
| ARC-COMPILER | Scenario compiler and semantic validator | Scenario compiler. | A mapped P0 requirement loses an implementation owner. |
| ARC-PRNG | Versioned context-derived deterministic byte generator | Versioned context-derived deterministic byte generator. | A mapped P0 requirement loses an implementation owner. |
| ARC-MANIFEST | Immutable realized run-bundle writer and reader | Immutable realized run-bundle writer. | A mapped P0 requirement loses an implementation owner. |
| ARC-CLOCK | Wall, monotonic, and logical clock abstraction | Wall, monotonic,. | A mapped P0 requirement loses an implementation owner. |
| ARC-SCHED | Persistent logical scheduler, retry planner, and barrier coordinator | Persistent logical scheduler, retry planner,. | A mapped P0 requirement loses an implementation owner. |
| ARC-TARGET | Destination policy, resolution, preflight, and pinned dialer | Destination policy, resolution, preflight,. | A mapped P0 requirement loses an implementation owner. |
| ARC-HTTP | HTTP/1.1 attempt executor and transport evidence collector | HTTP/1.1 attempt executor. | A mapped P0 requirement loses an implementation owner. |
| ARC-JOURNAL | Single-writer SQLite journal, migrations, transitions, and projections | Single-writer SQLite journal, migrations, transitions,. | A mapped P0 requirement loses an implementation owner. |
| ARC-LOCK | Run-directory ownership lock and stale-lock takeover protocol | Run-directory ownership lock. | A mapped P0 requirement loses an implementation owner. |
| ARC-RECOVERY | Crash scanner, ambiguity classifier, and resume policy engine | Crash scanner, ambiguity classifier,. | A mapped P0 requirement loses an implementation owner. |
| ARC-SIGN | Built-in signature adapters and test-key material handling | Built-in signature adapters. | A mapped P0 requirement loses an implementation owner. |
| ARC-MUT | Versioned typed mutation pipeline | Versioned typed mutation pipeline. | A mapped P0 requirement loses an implementation owner. |
| ARC-OBS-CMD | Command observer adapter | Command observer adapter. | A mapped P0 requirement loses an implementation owner. |
| ARC-OBS-HTTP | HTTP probe observer adapter | HTTP probe observer adapter. | A mapped P0 requirement loses an implementation owner. |
| ARC-ASSERT | Typed assertion and eventual-poll evaluator | Typed assertion. | A mapped P0 requirement loses an implementation owner. |
| ARC-REPORT-JSON | Stable JSON and JSON Lines report renderer | Stable JSON. | A mapped P0 requirement loses an implementation owner. |
| ARC-REPORT-JUNIT | JUnit XML renderer | JUnit XML renderer. | A mapped P0 requirement loses an implementation owner. |
| ARC-REPORT-HTML | Static escaped HTML renderer | Static escaped HTML renderer. | A mapped P0 requirement loses an implementation owner. |
| ARC-REF | Correct and isolated flawed reference receivers | Correct. | A mapped P0 requirement loses an implementation owner. |
| ARC-PACKAGE | Python package, wheel, sdist, and container build | Python package, wheel, sdist,. | A mapped P0 requirement loses an implementation owner. |
| ARC-ACTION | GitHub Action wrapper and artifact publisher | GitHub Action wrapper. | A mapped P0 requirement loses an implementation owner. |

## Dependency direction

```text
CLI / GitHub Action
        ↓
Application services: validate, plan, run, resume, replay, report
        ↓
Domain + policy + state machines + public protocol models
        ↓
Ports: journal, clock, generator, transport, observer, process, report sink
        ↓
Adapters: SQLite, HTTPX, command/HTTP observer, filesystem, renderers
```

Domain modules must not import Typer, HTTPX, FastAPI, HTML rendering, or distribution wrappers. FastAPI appears only in reference receivers.

## Execution flow

1. CLI resolves explicit paths and overrides.
2. Configuration loader parses duplicate-key-free safe YAML into strict Pydantic models.
3. Validator resolves secret *references* without rendering values, loads exact fixture bytes, checks scenario semantics, and evaluates target policy without sending fixture traffic.
4. Planner snapshots fixtures/blobs, derives deterministic values, resolves typed mutations, builds conditional attempt plans, and writes a canonical immutable manifest.
5. Run service creates the SQLite journal, imports manifest entities, acquires run ownership, and schedules ready deliveries by `(logical_time_ns, scenario_ordinal, delivery_ordinal, attempt_ordinal, ID)`.
6. Executor commits `sending` intent, performs guarded HTTP, and appends the best-known terminal evidence.
7. Observer service invokes declared checkpoints and appends typed samples.
8. Assertion engine evaluates normalized evidence and appends immutable results.
9. Verdict service reduces scenario/run classifications by documented precedence.
10. Pure report projectors regenerate JSON/JSONL/JUnit/HTML from the journal and manifest.

## Concurrency boundaries

- One scheduler coordinator owns readiness and journal writes.
- An AnyIO task group runs bounded attempt workers.
- A capacity limiter enforces configured concurrency.
- Every worker requests durable state transitions through the journal service; workers do not write SQLite directly.
- Barrier membership and deterministic release keys are manifest state. OS task execution order after release is observed, not guaranteed.
- Observers use a separate bounded limiter so a slow probe cannot exhaust delivery capacity.

## Deployment views

### Local process

The CLI, journal, run bundle, receiver, and optional command observer run on one workstation. Only the receiver/HTTP observer sockets cross process boundaries.

### Docker Compose

The harness container receives a read-only project mount and writable artifact mount. Receiver and observer services are addressed on an explicit Compose network and must satisfy private allowlisting. The harness runs as non-root with a read-only root filesystem.

### GitHub Actions

The action installs or invokes the locked CLI, starts user-supplied receiver services, executes the run, preserves the original exit category, and uploads sanitized artifacts. No artifact upload occurs before redaction validation.

## Trust boundaries

1. Project files and fixtures are untrusted structured/binary input.
2. Secret sources are high-sensitivity local/CI inputs.
3. Destination URLs and DNS are untrusted network configuration.
4. Receiver responses are untrusted and bounded.
5. Observer processes/endpoints are configured code/services and remain untrusted output sources.
6. SQLite and run artifacts are integrity-sensitive local state.
7. HTML/JUnit viewers are downstream parsers and must not receive active content or secrets.
8. Built-in adapters are trusted package code; dynamic third-party code is not loaded in v0.1.

## View mapping

| View | Source | Owning details |
| --- | --- | --- |
| Context | diagrams/system-context.mmd | Users, receiver, observer, CI, filesystem boundaries |
| Modules | diagrams/modules.mmd | Internal dependency direction |
| Components | diagrams/component-*.mmd | Planning, execution, observation, reporting |
| Deployment | diagrams/deployment-*.mmd | Local, Compose, CI processes and data paths |
| Data | diagrams/data-model.mmd | Relational identities and evidence links |
| State | diagrams/state-*.mmd | Allowed lifecycle transitions |
| Dynamic | diagrams/sequences/*.mmd | Nominal, retry, duplicate, restart, crash, reconciliation |
| Trust | diagrams/trust-boundaries.mmd | Untrusted inputs and security controls |

## Known limitations

- The harness cannot know whether an external receiver completed work when transport outcome and observer evidence are both unavailable.
- Scaled delays preserve logical order and ratios, not receiver wall-clock equivalence.
- A command observer executes trusted project code under the operator identity; v0.1 is not a sandbox.
- The target dialer can reduce DNS rebinding risk, but platform resolver/TLS behavior must be verified per supported OS.
- SQLite run directories on network filesystems are unsupported.
