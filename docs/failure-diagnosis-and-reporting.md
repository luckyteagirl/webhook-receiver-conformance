# Failure diagnosis and reporting

## Exit categories

| Code | CLI category | Persisted result | Meaning |
| --- | --- | --- | --- |
| 0 | `pass` | `pass` | All evidence evaluated by the current command path passed |
| 1 | `receiver_failure` | `receiver_failure` | Comparable receiver behavior failed |
| 2 | `invalid_input` | `invalid_input` | Config, fixture, manifest, policy, or schema was invalid |
| 3 | `environment_failure` | `environment_error` | Receiver/observer/dependency was unavailable |
| 4 | `ambiguous` | `ambiguous` | A send may have occurred but lacks a trusted terminal outcome |
| 5 | `harness_failure` | `harness_error` | Internal invariant, integrity, or persistence failure |
| 6 | `unsupported` | `unsupported` | A required valid capability/path is not implemented |
| 130 | `cancelled` | `cancelled` | Operator or CI interruption |

Human wording is not a compatibility surface. Stable diagnostic category/code, safe
location, retryability, result category, and exit mapping are. Add global `--json` for
one machine-readable result document. Add `--debug` only when needed; it still redacts
exception messages and secrets from unexpected-error output.

## A practical diagnosis order

1. Run `validate` again. It is network-free and isolates configuration, fixture,
   secret-reference metadata, schema version, and target policy problems.
2. Run `plan` into a new local directory. A plan failure isolates fixture loading,
   deterministic compilation, or secret resolution before traffic.
3. Read the command's stable diagnostic code and exit category. Do not branch automation
   on prose.
4. For a created run, inspect `run-state.json`, `result-summary.json`, and sanitized
   `deliveries.jsonl`. Keep event IDs, delivery IDs, and attempt IDs distinct.
5. Use `inspect RUN_DIR` for the verified sanitized summary or supply both
   `--kind KIND --identifier ID` for an exact scenario, event, delivery, attempt,
   observation, assertion, or diagnostic causal chain.
6. Request `--raw-artifacts` only when the sanitized evidence is insufficient. It emits
   an explicit sensitivity warning and lists paths; raw retention is not a normal
   reporting default.

Example:

```text
uv run webhook-conformance inspect RUN_DIR
uv run webhook-conformance --json inspect RUN_DIR \
  --kind attempt --identifier ATTEMPT_OR_RECORD_ID
```

Replace `RUN_DIR` with the path printed by `run`.

## Ambiguity and recovery

Connection failure before a send and an unknown outcome after a possible send are
different. The latter remains `ambiguous`; blindly redelivering could duplicate a
business effect.

```text
uv run webhook-conformance resume RUN_DIR
uv run webhook-conformance resume RUN_DIR --on-ambiguous stop
uv run webhook-conformance resume RUN_DIR \
  --config webhook-conformance.yaml \
  --on-ambiguous redeliver
```

Without `--on-ambiguous`, resume performs a read-only integrity preview and exits 4
before receiver or observer contact when an unknown send is present. With no unresolved
send, it advances the owner epoch and executes only unconsumed schedules and pending
assertions in the same run. Continued execution reloads fresh configuration and secret
references, verifies their fingerprints and target against the bundle, preserves all
prior evidence, then regenerates the complete report set.

The explicit closed policies are `stop`, `observe`, and `redeliver`. Redelivery
requires two independent consents: an immediate unused manifest attempt whose scenario
retry predicate includes `timed_out`, plus `--on-ambiguous redeliver`. It creates a new
physical attempt while leaving the unknown predecessor immutable. The v1 configuration
and manifest formats do not declare a delivery-scoped decisive reconciliation rule, so
`observe` currently fails closed and leaves the run ambiguous instead of inferring
authority from ordinary observer assertions.

`replay` verifies bundle integrity, requires fresh configuration and secret references
whose safe fingerprints match the bundle, and executes into a new self-contained run.
The source fixtures are not read:

```text
uv run webhook-conformance replay \
  .webhook-conformance/example-plan/run-manifest.json \
  --config webhook-conformance.yaml
```

## Report selection

Configuration accepts the closed set `json`, `jsonl`, `junit`, and `html`.

| Need | Select | Notes |
| --- | --- | --- |
| Automation, detailed evidence, archival | JSON + JSON Lines | Typed summary plus ordered record streams |
| CI test annotations | JUnit | Compact assertion/test projection; no raw payload embedding by default |
| Local human review | HTML | Static document with contextual escaping and no active script |

The offline `report` command accepts `json`, `junit`, and `html`. Selecting `json`
verifies the manifest, summary, and JSON Lines record artifacts as one machine-readable
group:

```text
uv run webhook-conformance report RUN_DIR --format json
uv run webhook-conformance report RUN_DIR --format junit --format html
```

With no `--format`, it selects all three groups. The command verifies the bundle and
journal, regenerates the complete seven-file projection and artifact registry, and
returns the selected records plus a normalized digest. It does not contact the receiver
or alter authoritative journal state.

Version 0.1 has no SARIF runtime reporter. Use JUnit for CI test presentation and JSON
or JSON Lines when downstream tools need structured conformance evidence.

Headers and JSON pointers listed under `reports.redaction` are redacted before ordinary
rendering. Raw payload retention is opt-in and raw payloads are not embedded into JUnit
or HTML by default.
