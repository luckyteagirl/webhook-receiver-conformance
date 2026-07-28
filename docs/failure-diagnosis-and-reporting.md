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
5. Use `inspect RUN_DIR` for the sanitized summary or
   `inspect RUN_DIR --identifier ID` for an exact scenario/event/delivery filter.
6. Request `--raw-artifacts` only when the sanitized evidence is insufficient. It emits
   an explicit sensitivity warning and lists paths; raw retention is not a normal
   reporting default.

Example:

```text
uv run webhook-conformance inspect RUN_DIR
uv run webhook-conformance --json inspect RUN_DIR --identifier EVENT_OR_DELIVERY_ID
```

Replace `RUN_DIR` with the path printed by `run`.

## Ambiguity and recovery

Connection failure before a send and an unknown outcome after a possible send are
different. The latter remains `ambiguous`; blindly redelivering could duplicate a
business effect.

```text
uv run webhook-conformance resume RUN_DIR
uv run webhook-conformance resume RUN_DIR --on-ambiguous stop
```

The 0.1.0 resume command requires one of `stop`, `observe`, `redeliver`,
`assume-processed`, or `assume-not-processed` when state is ambiguous. Its current
implementation reports the existing state and does not perform the named recovery
action, so do not treat the option as evidence that receiver state changed.

`replay` verifies bundle integrity and copies immutable files to a new execution
directory, then returns exit 6 because the bundle contains no fresh signing-secret
context:

```text
uv run webhook-conformance replay .webhook-conformance/example-plan/run-manifest.json
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

With no `--format`, it verifies all three groups. It reads existing local files, computes
their hashes and a normalized digest, and does not contact the receiver or mutate run
state.

Version 0.1 has no SARIF runtime reporter. Use JUnit for CI test presentation and JSON
or JSON Lines when downstream tools need structured conformance evidence.

Headers and JSON pointers listed under `reports.redaction` are redacted before ordinary
rendering. Raw payload retention is opt-in and raw payloads are not embedded into JUnit
or HTML by default.
