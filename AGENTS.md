# AGENTS.md

## Mission

Implement the local-first webhook receiver conformance harness exactly as specified. Preserve deterministic planning, explicit ambiguity, receiver-state evidence, secure target policy, and offline CI operation.

## Non-goals

Do not add a hosted control plane, request bin, tunnel, gateway, browser UI, distributed queue, PostgreSQL service, Kubernetes controller, generalized workflow engine, load-testing mode, or public third-party plugin loader unless a superseding approved requirement and ADR explicitly add it.

## Authority and conflict precedence

1. Normative statements in `specification/05-product-requirements.md` and `machine/requirements.yaml`.
2. JSON Schemas under `schemas/` for serialized data.
3. State machines and interface contracts in `specification/09-state-machines.md` and `specification/16-interfaces-and-contracts.md`.
4. Accepted ADRs in `machine/decisions.yaml`.
5. The assigned task packet.
6. Examples and explanatory prose.

Stop and report a conflict rather than selecting a lower-precedence interpretation.

## Repository layout

- `src/webhook_receiver_conformance/`: production package.
- `tests/`: unit, contract, integration, end-to-end, crash, security, package, and performance tests.
- `schemas/`: authoritative JSON Schemas copied from this specification pack.
- `examples/`: validated examples and reference configurations.
- `reference_receivers/`: correct and deliberately flawed receivers.
- `scripts/`: deterministic validation and release tools.
- `.github/`: CI, release, and GitHub Action wrapper.

## Supported commands

Use the locked environment:

```bash
uv sync --locked --all-groups
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -q
uv run python scripts/validate_artifacts.py
uv build
```

Do not silently substitute unlocked dependencies or skip a failing gate.

## Coding and typing standards

- CPython 3.12 through 3.14.
- Complete type annotations for public and internal boundaries.
- Pydantic models are strict and reject unknown fields unless a documented extension point allows them.
- Use immutable domain value objects where state mutation is not the contract.
- Use AnyIO structured concurrency with the asyncio backend; do not create unmanaged background tasks.
- Inject clocks, deterministic generation, transport, persistence, and process execution at testable boundaries.
- Avoid global mutable state.

## Architectural dependency rules

Adapters may depend inward on domain protocols. Domain, state, determinism, and policy modules must not import CLI, report rendering, FastAPI, or reference receiver modules. The SQLite repository owns persistence SQL. The scheduler does not perform implicit HTTP retries. Reporters read normalized projections and never mutate run state.

## Interface and schema rules

- Do not invent or rename serialized fields.
- Update schema, example, compatibility note, migration, tests, and traceability in one change when an approved task changes a contract.
- Preserve exact request-body bytes through mutation, signing, snapshotting, and transmission.
- Public compatibility promises in v0.1 are the CLI, configuration schema, run/evidence schemas, exit codes, and observer wire protocol. Internal adapter protocols are not public plugins.

## Database and migration rules

- One process owns a run directory.
- Use SQLite rollback journal `DELETE`, `synchronous=EXTRA`, `foreign_keys=ON`, `trusted_schema=OFF`, and explicit `BEGIN IMMEDIATE` write transactions.
- Do not put run databases on network filesystems.
- Never edit an applied migration; append a new transactional migration.
- Persist pre-send intent before allowing request bytes to leave the process.
- A recovered `sending` attempt without a terminal outcome becomes `unknown_outcome`; never infer success or failure.

## Security invariants

- Default target scope is loopback.
- Public targets require configuration authorization, an exact runtime authorization flag, and a matching test-receiver challenge.
- Disable redirects and proxy environment inheritance.
- Validate every resolved IPv4 and IPv6 address and pin the authorized destination through connection establishment.
- Block metadata, link-local, multicast, unspecified, and otherwise disallowed ranges regardless of operator flags.
- Never invoke command/lifecycle observers through a shell.
- Bound all request, response, subprocess, concurrency, disk, and report resources.

## Logging and redaction

- Never log signing secrets, observer tokens, authorization values, raw secret-reference contents, or configured sensitive fixture paths.
- Redact before persistence and before rendering.
- Escape terminal controls and all HTML contexts.
- Raw payload retention is opt-in and is never embedded in JUnit or HTML by default.
- Secret-canary regression tests are mandatory.

## Test expectations

Every changed behavior requires nominal, malformed, boundary, timeout, cancellation, and relevant crash/security tests. Contract implementations run the category contract suite. No core test is automatically retried. A flaky test is a defect, not a reason to weaken a gate.

## Task-selection protocol

Select only a task whose dependencies are complete. Confirm file ownership is unclaimed. Read all cited requirements, tests, ADRs, and interfaces. Implement only the packet scope. Do not absorb adjacent backlog work.

## Safe parallelism and file ownership

Parallel tasks are safe only when they share a non-null parallel group and have disjoint exclusive ownership. Schema files, migrations, CLI command registries, error enums, and public protocol models are exclusive integration points even when glob patterns appear disjoint. One integration agent resolves those points after a parallel group.

## Definition of done

- All acceptance criteria pass.
- Every packet command has been run in the locked environment.
- Objective evidence is retained.
- No unowned file changed.
- Public behavior and documentation agree.
- No new high-risk threat or unresolved interface ambiguity was introduced.
- Handoff notes list changed files, commands, results, risks, and follow-up dependencies.

## Prohibited shortcuts

Do not mock away the core behavior being verified, skip persistence around network sends, conflate event IDs with attempt IDs, use wall-clock time for elapsed deadlines, retry HTTP implicitly, trust proxy environment variables, disable TLS verification by default, serialize secrets, insert active JavaScript into reports, use shell interpolation, claim exactly-once delivery, or mark a task complete without evidence.
