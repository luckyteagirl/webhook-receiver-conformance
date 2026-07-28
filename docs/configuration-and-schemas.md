# Configuration and schemas

## The two runnable examples

[`examples/project-config.quickstart.yaml`](../examples/project-config.quickstart.yaml)
is the five-minute delivery path. It contains one fixture, one generic HMAC test signer,
one delivery, one HTTP-status assertion declaration, and all four report-format
declarations.

[`examples/project-config.complete.yaml`](../examples/project-config.complete.yaml)
adds an explicit seed, fixture pointers, command and HTTP observers, duplicate delivery,
receiver-state assertion declarations, failure policy, and complete resource limits.
Both runnable files validate against
[`schemas/project-config.schema.json`](../schemas/project-config.schema.json) and the
stricter typed loader.

[`examples/project-config.minimal.yaml`](../examples/project-config.minimal.yaml) is an
additional schema-minimal contract fixture. It deliberately omits `project.seed` so the
loader test suite can prove default and override behavior; validate it, but use the
quickstart file for `plan` or `run`, because the current planner requires an explicit
normalized seed.

Validate both without network access:

```text
uv run webhook-conformance validate --config examples/project-config.quickstart.yaml
uv run webhook-conformance validate --config examples/project-config.complete.yaml
uv run webhook-conformance validate --config examples/project-config.minimal.yaml
uv run python scripts/validate_artifacts.py
```

To run the complete delivery plan, start
[`examples/reference_receiver.py`](../examples/reference_receiver.py) as shown in the
README and set both environment references:

PowerShell:

```powershell
$env:WEBHOOK_TEST_SECRET = "local-test-secret-32-bytes-long"
$env:WEBHOOK_OBSERVER_TOKEN = "local-observer-token-32-bytes"
uv run webhook-conformance run --config examples/project-config.complete.yaml
```

POSIX shell:

```sh
export WEBHOOK_TEST_SECRET='local-test-secret-32-bytes-long'
export WEBHOOK_OBSERVER_TOKEN='local-observer-token-32-bytes'
uv run webhook-conformance run --config examples/project-config.complete.yaml
```

The CLI's present observer-orchestration limit is documented in the README. Use the
observer test kit for the command and HTTP observer paths.

## Strict configuration boundary

Configuration is YAML restricted to the JSON data model. Unknown fields, duplicate
keys, non-string keys, custom tags, merge keys, non-finite or floating-point lexical
values, unsupported schema majors, and resource-limit overruns fail closed. Relative
paths resolve from the configuration file's directory and must stay within the
applicable project boundary.

The main sections are:

| Section | Purpose |
| --- | --- |
| `project` | Name, local artifact directory, deterministic seed, secret roots |
| `receiver` | URL, target profile/allowlists, public challenge path, timeouts |
| `fixtures` | Exact body source and event identity/type pointers |
| `signers` | Built-in signature profile and secret reference |
| `observers` | Command argv or HTTP base URL/token and physical timeouts |
| `lifecycles` | Named, disabled-by-default local process controls |
| `clock` | Real or exact scaled schedule clock |
| `limits` | Event, attempt, concurrency, request, and response-capture bounds |
| `scenarios` | Events, ordered steps, explicit retry/mutation policy, assertions |
| `reports` | Closed output-format list and redaction policy |

Secret values use references:

```yaml
secret: {env: WEBHOOK_TEST_SECRET}
secret: {file: .secrets/local-test-key}
secret: {generated: hmac-256}
```

Plaintext secret content is not a serialized configuration field. A generated secret is
for a self-contained test context; an external receiver that must verify the signature
needs a separately coordinated test key.

## Validate, plan, and run

```text
uv run webhook-conformance validate --config examples/project-config.quickstart.yaml
uv run webhook-conformance validate --config examples/project-config.quickstart.yaml --print-materialized
uv run webhook-conformance plan --config examples/project-config.quickstart.yaml --out .webhook-conformance/example-plan
uv run webhook-conformance run --config examples/project-config.quickstart.yaml
uv run webhook-conformance run --manifest .webhook-conformance/plan \
  --config examples/project-config.quickstart.yaml
```

`validate` materializes typed configuration and performs no network I/O. `plan` resolves
the fixture and secret fingerprint and writes an immutable bundle without sending
traffic. `run` either plans from configuration or verifies and loads the bundle selected
by `--manifest`, then sends to the authorized target. Bundle execution still requires
fresh configuration with matching target policy and secret fingerprints, but does not
rediscover fixture sources. Loaded execution is fully materialized into a private
verified snapshot and anonymous request-body spool before a public-target nonce
challenge; the resulting runner-bound capability is consumed once and cleaned up after
execution. Mutating the original manifest, effective configuration, blobs, or fixture
source after that preparation cannot affect the request bytes. The last two commands
therefore need the referenced signer secret.

The plan separates reproducible choices from execution-specific facts. It realizes
mutation parameters, retry recipes, logical times, identifiers, exact blob digests, and
algorithm versions. It does not contain a `run_id` or plaintext secret. A new execution
gets a new `run_id` even when its plan has the same `manifest_id`.

## Schema inventory and version encoding

The JSON Schemas under [`schemas/`](../schemas/) own serialized field names, required
fields, types, closed enums, identifier encodings, and unknown-field policy.

Important v0.1 contracts include:

| Artifact | Schema | Serialized version |
| --- | --- | --- |
| Project YAML | `project-config.schema.json` | integer `schema_version: 1` |
| Immutable plan | `run-manifest.schema.json` | string `"1.0"` |
| Observer request/response/evidence | `observer-*.schema.json` | string `"1.0"` where present |
| Delivery/observation/assertion records | matching record schemas | string `"1.0"` |
| Result summary | `result-summary.schema.json` | string `"1.0"` |
| Fixture inventory | `fixture-manifest.schema.json` | string `"1.0"` |

The project configuration uses integer major `1`; its documented compatibility revision
is reported as `1.0`. Do not rewrite a serialized field merely to make every artifact's
version lexical form identical.

## Reader compatibility

Artifact schema majors are independent of the package and of one another.

| Version relation | Change kind | Reader behavior |
| --- | --- | --- |
| Same major | Exact known revision | Accept |
| Same major | Optional additive field declared by a registered schema revision | Accept |
| Same major | Breaking change | Reject |
| Unknown major | Any change | Reject before side effects |

Current strict schema boundaries still reject arbitrary unknown properties. “Optional
additive” means a known same-major schema revision has explicitly declared the field;
it is not permission to ignore undeclared input.

A breaking schema change includes removing or renaming a field, adding a required field,
changing a type or meaning, or adding a value that a reader must interpret. It requires
a new integer major and migration/compatibility notes. Unknown majors are rejected
before blob access, observer invocation, receiver traffic, or other side effects.

## Manifest compatibility and reproducibility

Manifest IDs are raw 64-character lowercase SHA-256 digests of the canonical manifest
with `manifest_id` omitted. Blob and evidence digests use the
`sha256:<64 lowercase hexadecimal>` form. Canonical manifest numbers are integers in the
I-JSON interoperable range; floating-point values are not admitted.

Reproducibility comparisons exclude only declared volatile categories such as execution
identity, wall timestamps, measured durations, and environment observations. They do
not erase semantic differences.
