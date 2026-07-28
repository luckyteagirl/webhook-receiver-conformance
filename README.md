# Webhook Receiver Conformance

`webhook-conformance` is a local-first command-line harness for compiling reproducible
webhook failure scenarios, sending their exact request bytes to a test receiver, and
retaining sanitized evidence. Version 0.1.0 is pre-alpha.

The harness is not a request bin, tunnel, production gateway, provider emulator,
general workflow engine, or receiver load-testing tool. It can test duplicate-safe
processing and observable business effects. It explicitly rejects an exactly-once
network-delivery claim because an unresolved send cannot prove whether the receiver
committed an external effect.

## Five-minute local path

Prerequisites are Git, [uv](https://docs.astral.sh/uv/), and a supported CPython.
All traffic in this path stays on `127.0.0.1`.

From a clean checkout:

```text
uv sync --locked --all-groups
uv run webhook-conformance version
uv run webhook-conformance validate --config examples/project-config.quickstart.yaml
```

Start the correct SQLite-backed reference receiver in one terminal.

PowerShell:

```powershell
$env:WEBHOOK_TEST_SECRET = "local-test-secret-32-bytes-long"
$env:WEBHOOK_OBSERVER_TOKEN = "local-observer-token-32-bytes"
uv run python examples/reference_receiver.py
```

POSIX shell:

```sh
export WEBHOOK_TEST_SECRET='local-test-secret-32-bytes-long'
export WEBHOOK_OBSERVER_TOKEN='local-observer-token-32-bytes'
uv run python examples/reference_receiver.py
```

In a second terminal, set `WEBHOOK_TEST_SECRET` to the same local test value and run:

```text
uv run webhook-conformance run --config examples/project-config.quickstart.yaml
```

A successful command prints `pass` and the local run directory. Stop the receiver with
Ctrl+C. The example secret and observer token are disposable test values; do not reuse
production credentials.

The path is intentionally loopback-only. It does not require Docker, a hosted service,
a tunnel, or public-target authorization. See
[Configuration and schemas](docs/configuration-and-schemas.md) for planning and the
complete example, and [Failure diagnosis and reporting](docs/failure-diagnosis-and-reporting.md)
for the generated artifacts.

## Mental model

```text
logical event -> planned delivery -> physical attempt -> transport evidence
                                             \-> observer sample -> assertion -> verdict
```

- A logical event is receiver-domain input such as the included payment event.
- A delivery is a manifest-planned presentation of an event.
- An attempt is one physical HTTP send. The scheduler performs no implicit HTTP retry;
  configured retry policy creates explicit planned attempts.
- Transport evidence answers whether bytes were sent and what response was observed.
- Observer evidence is a separate, read-only view of receiver state. It is what lets a
  conformance assertion distinguish an HTTP acknowledgement from a durable business
  effect.
- A timeout after bytes may have left the process is ambiguous, not proof of failure or
  success. Recovery never silently converts that uncertainty into a receiver verdict.

`run_id` identifies one execution. `manifest_id` identifies the canonical, immutable,
execution-independent plan. Event, delivery, attempt, observation, and assertion
identities are not interchangeable.

The reference receiver is intentionally small and payment-oriented. It uses a durable
inbox plus business-effect and outbox tables so duplicate, ordering, signature, and
partial-processing defects are visible without pretending to be a full payment
provider. The decision rationale is [ADR-018](specification/25-architecture-decisions.md#adr-018--use-an-orders-and-payments-reference-domain).

## Current executable behavior

The installed command tree is:

```text
version  init  validate  plan  run  resume  replay  inspect  report
```

`validate` and `plan` do not contact the receiver. `run` executes every realized
delivery through the durable scheduler, including configured waits, concurrency,
conditional retries, transport assertions, and all built-in observer-backed assertion
families. Attempts, observations, and assertions commit to the SQLite journal before
the final JSON/JSON Lines, JUnit, and HTML projections are generated. See
[Observer integration](docs/observers.md).

`run --manifest BUNDLE --config CONFIG` verifies and loads an existing immutable
bundle instead of planning from fixture sources. The fresh configuration must supply
matching target policy and secret fingerprints; source fixtures are not rediscovered.
Before any public-target nonce challenge, the command freezes a private verified
bundle snapshot and anonymous request-body spool. Execution consumes that snapshot
once, so later changes to the selected bundle cannot change transmitted fixture bytes.

`resume` verifies the existing bundle and journal, advances the owner epoch, and
continues only unconsumed schedules and pending assertions in the same run. Continued
execution requires fresh `--config` secret references whose fingerprints and target
match the bundle. An ambiguous possible send remains read-only by default. Redelivery
requires both a manifest-fixed `timed_out` retry node and the explicit
`--on-ambiguous redeliver` option; the original unknown attempt remains immutable.

`replay` verifies an immutable bundle, requires fresh configuration and secret
references that match its digest-bound target and fingerprints, and executes a new
self-contained run without fixture discovery or random generation. `inspect` verifies
the bundle, journal, artifact registry, and exact causal links without network access.
`report` regenerates the complete report set from journal truth and returns the
normalized digest for the selected formats.

## Documentation map

- [Configuration and schemas](docs/configuration-and-schemas.md): strict YAML, the two
  runnable examples, planning, manifests, and schema-reader behavior.
- [Observer integration](docs/observers.md): command/HTTP protocol, authentication,
  shared test kit, and extension boundary.
- [Failure diagnosis and reporting](docs/failure-diagnosis-and-reporting.md): exit
  codes, ambiguity, inspection, and JSON/JUnit/HTML selection.
- [Security boundaries](docs/security-boundaries.md): local storage, target policy,
  secret handling, and threat-model mappings.
- [Compatibility and releases](docs/compatibility-and-releases.md): CPython/platform
  matrix, independent versions, SemVer, and breaking-change policy.

## Installation surfaces

The wheel is authoritative. A local build can be exercised through the two ephemeral
runner paths without contacting a package registry:

```text
uv build --no-sources
uvx --from dist/webhook_receiver_conformance-0.1.0-py3-none-any.whl webhook-conformance version
pipx run --spec dist/webhook_receiver_conformance-0.1.0-py3-none-any.whl webhook-conformance version
```

The thin OCI image and GitHub Action wrapper invoke the same CLI behavior. Distribution
surfaces do not define separate runtime semantics. Package smoke tests run wheel and
source-distribution installs and exercise `uvx` and `pipx` where those tools are
available.

Supported runtime combinations are CPython 3.12, 3.13, and 3.14 on the current
GitHub-hosted Ubuntu, macOS, and Windows runner families. See the exact tested matrix in
[Compatibility and releases](docs/compatibility-and-releases.md).

## Authority and conflict precedence

When documentation or examples disagree, use this order and stop rather than choosing
a lower-precedence interpretation:

1. Normative behavior in
   [`specification/05-product-requirements.md`](specification/05-product-requirements.md)
   and [`machine/requirements.yaml`](machine/requirements.yaml).
2. Serialized field contracts in [`schemas/`](schemas/).
3. Lifecycle and interface contracts in
   [`specification/09-state-machines.md`](specification/09-state-machines.md) and
   [`specification/16-interfaces-and-contracts.md`](specification/16-interfaces-and-contracts.md).
4. Accepted design decisions in [`machine/decisions.yaml`](machine/decisions.yaml).
5. The assigned packet in [`tasks/work-packets/`](tasks/work-packets/).
6. Examples and explanatory prose, including this README and `docs/`.

[`AGENTS.md`](AGENTS.md) is the binding repository work policy and defines the same
precedence. Command help is authoritative for the options implemented by the installed
version; schemas remain authoritative for serialized fields even when an example is
older.

The broader specification index remains available in [`specification/`](specification/),
but it cannot override the sources above.
