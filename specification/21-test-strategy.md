# Test Strategy

## Principle

Verification distinguishes receiver-under-test failure, harness failure, invalid input, environment failure, unsupported capability, ambiguity, and cancellation. Tests assert both category and evidence; exception presence alone is insufficient.

## Layers

| Layer | Scope | CI placement |
| --- | --- | --- |
| Unit | Pure parsers, value objects, generator, comparators, policy, redaction, transition functions | Every commit |
| Contract | Signer, observer, assertion, reporter, clock, transport, journal ports | Every commit |
| Property-based | IDs, HMAC-derived generation, schedule ordering, mutation boundaries, schemas, redaction | Every commit with deterministic CI profile |
| Stateful model | Journal and scheduler command sequences versus reference models | Every commit / extended nightly |
| Integration | SQLite, HTTPX transport, subprocess/HTTP observers, renderer pipelines | Every commit |
| End-to-end | Correct/flawed reference receiver corpus | Every commit on Linux; matrix on merge/release |
| Crash | Process kill at every crash matrix failpoint and resume in a fresh process | Merge/release; representative subset per commit |
| Security | SSRF, DNS, paths, shell, limits, redaction, terminal/HTML/XML injection, CI policy | Every commit for core; extended nightly |
| Fuzz | YAML/JSON/JSONL/protocol/report parsers under bounded resources | Nightly and before release |
| Mutation testing | State, target policy, signature verification helpers, redaction | Before 1.0 and scheduled |
| Packaging | Wheel, sdist, pipx, uvx, container, GitHub Action on clean platforms | Release candidate |
| Performance | Startup, planning, attempts, memory, disk, report generation budgets | Release candidate and regression trend |

## Test ID contract

Each normative requirement owns one primary `VT-<FAMILY>-###` ID. One test implementation may verify several IDs, but the result metadata names each ID. `machine/requirements.yaml` and `machine/traceability.json` are the authoritative mapping.

## Profiles

- `unit`: no sockets/processes/filesystem except temporary in-memory equivalents.
- `integration`: local temporary directories, loopback sockets, subprocesses; no internet.
- `e2e`: reference receiver/observer on loopback or isolated Compose network.
- `crash`: process failpoints and fresh-process resume.
- `security`: hostile corpus and network/path controls.
- `package`: clean environments and built artifacts.
- `slow`: fuzz, mutation, performance, exhaustive stateful sequences.

## Determinism

Hypothesis CI profile uses a fixed database artifact policy and reports/shrinks failures. Property-test examples are not treated as stable product replays until exported to a realized manifest/action sequence. Golden fixtures include generator vectors, IDs, manifests, signature headers, SQLite prior-version databases, JSONL ordering, JUnit, and HTML semantic snapshots.

## Flake policy

Core tests have no automatic retry. A failure is reproducible locally from captured seed/example/manifest or is quarantined only by disabling the affected release gate with an approved high-severity finding; arbitrary rerun-until-pass is prohibited. Timing tests use synchronization barriers and generous bounded deadlines rather than sleeps.

## Crash harness

A failpoint controller identifies durable boundaries by stable names, signals readiness to the parent, and terminates with `os._exit`/platform equivalent. The parent never shares the child SQLite connection. After each kill, a fresh process runs integrity checks, recovery preview, policy application, and model comparison. Each crash test also verifies leaked processes/sockets and secret canaries.

## Security corpus

Includes mixed IPv4/IPv6 answers, mapped addresses, metadata aliases, DNS answer changes, redirects, proxy environment, CRLF/header controls, ANSI/bidi strings, malicious HTML/XML, duplicate YAML/JSON keys, deep documents, large bodies, symlinks, path traversal, executable argv metacharacters, oversized observer output, malformed signatures, stale timestamps, and report artifact attacks.

## Reference corpus expectations

`correct` must pass every supported P0 scenario. Each flawed receiver has one intentional defect, must fail mapped scenarios with exact assertion/evidence, and must pass unrelated controls. The matrix itself is versioned and machine checked; an unexplained extra failure invalidates the flaw fixture.

## Cleanup and isolation

Every integration test owns a temporary root, unique loopback port, unique database, bounded process group, and explicit cleanup finalizer. Tests never use developer home configuration, proxy environment, or production secrets. Network namespaces/containers may strengthen isolation but are not required for the base suite.

## Objective evidence

A passing task records command, commit, environment versions, test IDs, result, duration, artifact digests, and any skipped optional platform capability. Release evidence is retained with the release and tied to provenance.

## Coverage goals

Coverage percentage is secondary to requirement/transition/threat coverage. Required gates are 100% P0 requirement mapping, 100% legal and illegal state transitions, every crash boundary, every high-risk threat, and every public schema example. Line/branch targets may be set during implementation but cannot replace these matrices.
