# CLI, Configuration, and Developer Experience

## Executable

Canonical executable: `webhook-conformance`. The neutral Python package is `webhook_receiver_conformance`. Branding aliases are not introduced until naming clearance.

## Command tree

| Command | User job and contract |
| --- | --- |
| init [PATH] | Create minimal directories, config, fixture, observer stub, `.gitignore`, and README; never overwrite without `--force` and preview. |
| validate -c PATH | Parse, validate, materialize defaults, resolve nonsecret metadata, inspect target policy, and emit diagnostics without network traffic. |
| plan -c PATH --out DIR | Create immutable run bundle and manifest without sending traffic. |
| run -c PATH \| --manifest PATH | Plan if needed, acquire run ownership, execute, observe, assert, report, and exit by final category. |
| resume RUN_DIR | Verify integrity, preview recovery, apply explicit ambiguity policy, and continue the same run. |
| replay MANIFEST | Create a new run from one immutable manifest without random generation or fixture discovery. |
| inspect RUN_DIR [--id ID] | Print sanitized causal state and integrity information without mutation. |
| report RUN_DIR [--format ...] | Regenerate projections from committed state without running deliveries. |
| version [--json] | Print package, schema, observer protocol, generator, and built-in adapter versions. |

A command is omitted when it does not own a distinct user job. `plugins` is omitted because v0.1 has no public dynamic plugins. There is no `clean` command because safe deletion semantics are not required for core conformance.

## Global options

- `--config PATH`: explicit configuration path; default `webhook-conformance.yaml` then `.webhook-conformance.yaml` in current directory, no parent-directory search.
- `--project-root PATH`: base for relative paths; defaults to config directory.
- `--log-format text|json`.
- `--color auto|always|never`; `NO_COLOR` is honored only when `--color` is absent.
- `--verbosity quiet|normal|verbose|debug`; debug still redacts secrets.
- `--non-interactive`: required automatically when stdin is not a TTY or `CI` is truthy.
- `--authorize-public-target HOST:PORT`: exact runtime authorization; no environment-variable equivalent.
- `--output DIR`: report/bundle destination where command-specific.

## Configuration format and precedence

YAML is restricted to the JSON data model. Duplicate keys, aliases that exceed expansion limits, custom tags, merge keys, non-string mapping keys, timestamps, binary tags, NaN/Infinity, and unknown fields are rejected. Paths resolve relative to the configuration file after normalization and containment policy.

Precedence, highest first:

1. Explicit CLI option for fields documented as overrideable.
2. Environment variables for documented secret references and process-level presentation (`NO_COLOR`, `CI`).
3. Project YAML.
4. Versioned defaults materialized by `validate --print-materialized`.

Arbitrary environment-to-field mapping is prohibited. Includes and inheritance are not supported in v0.1; duplication is preferable to hidden merge semantics.

## Secret references

```yaml
secret: {env: STRIPE_WEBHOOK_TEST_SECRET}
secret: {file: .secrets/stripe-test-secret}
secret: {generated: hmac-256}
```

A file reference is opened from a contained normalized path without following a final symlink. `validate` checks presence/metadata but does not print content. `plan` resolves and fingerprints the key needed to realize signatures but does not persist plaintext.

## stdout, stderr, and logging

- stdout: requested machine output or concise terminal summary.
- stderr: diagnostics and progress.
- `--log-format json` emits one JSON object per line on stderr; stdout remains command result data.
- Non-TTY mode has no spinners, cursor movement, or ANSI unless forced.
- Progress is event-based, not periodic noisy polling.
- All user/provider content is control-character escaped before terminal rendering.

## Exit codes and precedence

| Code | Category | Meaning |
| --- | --- | --- |
| 0 | pass | All required scenarios/assertions passed. |
| 1 | receiver_failure | One or more comparable assertions failed. |
| 2 | invalid_input | Configuration, fixture, manifest, policy, or schema invalid before/without execution. |
| 3 | environment_failure | Receiver/observer/dependency unavailable with no stronger receiver verdict. |
| 4 | ambiguous | One or more send outcomes remain unresolved. |
| 5 | harness_failure | Internal invariant, integrity, migration, or unsupported valid-state defect. |
| 6 | unsupported | Required declared capability is unsupported and no execution defect occurred. |
| 130 | cancelled | Operator/CI interruption completed before a stronger committed terminal category. |

Reduction precedence after recovery is: harness integrity failure (5) > unresolved ambiguity (4) > receiver failure (1) > invalid input discovered in a later artifact operation (2) > environment failure (3) > unsupported (6) > cancelled (130) > pass (0). Cancellation returns 130 only when no stronger category was already durably established. Reports preserve all categories even when one exit code wins.

## Cancellation

First SIGINT/SIGTERM requests graceful stop: stop claiming work, cancel observers/workers, classify attempts by transport phase, commit evidence, render a minimal summary, and return 130 or stronger category. A second interrupt may terminate immediately; the next resume must recover from persisted state. Windows console events receive equivalent best-effort behavior.

## Diagnostic obligations

Every validation error contains stable code, path, line/column where available, violated rule, and one safe remediation. Related errors are accumulated up to a bounded maximum rather than failing only on the first field. Network errors name phase, authorized host/port, selected address class, timeout, and sanitized library cause category.

## Onboarding target

A developer with Python/uv or Docker, one fixture, one local receiver URL, and an HMAC secret should reach a passing baseline run in 15 minutes without reading architecture documents. The minimal example is the acceptance path for this goal.
