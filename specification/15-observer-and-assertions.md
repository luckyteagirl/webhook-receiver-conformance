# Observer and Assertions

## Public observer protocol

The observer wire protocol is the only v0.1 extension compatibility promise. It is JSON over stdin/stdout for a command observer or HTTPS/HTTP for an authorized probe. It is read-only from the harness perspective.

### Capability negotiation

Before the first required observation, the harness sends `operation=capabilities`. The response names protocol version, supported evidence keys/query types, maximum query count, whether snapshot IDs are stable, whether `pending` is supported, and any authentication requirements already satisfied by the transport. A required assertion whose capability is absent fails as `unsupported` unless the assertion explicitly allows skip.

### Observe request

A request contains request/run/scenario/event IDs, checkpoint, ordered typed queries, and an optional prior snapshot ID. It contains no signing secret or raw fixture by default. Query parameters are bounded JSON values.

### Response

- `ok`: complete typed evidence for all successful queries.
- `pending`: valid only for declared eventual capabilities; may include retry-after duration.
- `unsupported`: named capability is unavailable.
- `error`: observer executed but could not produce evidence; includes stable error category and retryable flag.

Evidence values are tagged as null, boolean, integer, number, string, array, or object. No implicit string-to-number conversion occurs. `sensitive=true` forces redaction from ordinary reports; assertions may compare an in-memory value before redaction and persist only a keyed digest where configured.

## Command observer

- Configuration is an argv array; no shell string is accepted.
- Request is one bounded JSON object on stdin; response is one bounded JSON object on stdout.
- stderr is captured, control-sanitized, capped, and treated as diagnostic only.
- Environment is an explicit allowlist plus protocol variables; the parent environment is not inherited wholesale.
- Working directory is an explicitly contained path.
- Hard real monotonic timeout; process group/Job Object cleanup on cancellation.
- Exit 0 with valid JSON is protocol processing; nonzero is observer environment error; malformed/oversized output is protocol error.
- The command is trusted project code, not a sandboxed plugin.

## HTTP probe observer

- Endpoints: `GET /.well-known/webhook-conformance/capabilities`, `POST /v1/observe`, optional `GET /health`.
- Bearer test token through a secret reference; token never appears in URL/log/report.
- The URL passes the same destination policy and pinned transport as the receiver.
- No redirects or proxy environment.
- Content type must be `application/json`; request/response limits apply.
- Public probe endpoints require HTTPS and the same public target authorization.

## Polling

An eventual assertion defines real monotonic `within` and `poll_interval` bounds. Each poll creates a sample. The final result is:

- `pass` when a valid sample meets the comparison before the deadline.
- `fail` when valid evidence remains contrary at the deadline.
- `error` when required evidence is unavailable due to observer/protocol failure under policy.
- `skipped` only for explicitly optional unsupported capability.

The poller applies no hidden exponential backoff; intervals are manifest/config state. Observer retry does not change delivery attempt state.

## Assertion types

| Type | Inputs | Evidence | Pass/fail/error semantics |
|---|---|---|---|
| `http-status` | Attempt selector, allowed exact codes/classes | Terminal attempt record | Pass on match; fail on contrary receiver response; error when no comparable terminal response |
| `acknowledgement-deadline` | Attempt, max real duration | Sending/response monotonic timestamps | Pass within limit; fail for late response; error/ambiguous for no trusted response depending transport phase |
| `processing-count` | Observer, event scope, integer comparator | Typed integer sample | Pass comparator; fail valid mismatch; error noninteger/missing/observer failure |
| `resource-exists` / `resource-absent` | Observer query and resource key | Boolean or object evidence | Strict typed existence comparison |
| `resource-field` | Evidence key/JSON Pointer, operator, expected typed value | Object evidence | No coercion; missing pointer is fail or error as declared |
| `ordered-transition` | Ordered state values and optional timestamps | Sequence evidence | Pass when observed order satisfies relation; fail prohibited order; error incomplete malformed evidence |
| `callback-count` / `journal-count` | Typed counter scope | Integer evidence | Same strict comparator rules as processing count |
| `no-partial-side-effect` | Named all-or-none fields/resources | One snapshot or transaction marker | Pass only when allowed complete/absent state; fail mixed state; error insufficient evidence |
| `eventual-state` | Observer query, expected value, within/interval | Poll sample series | Temporal semantics above |
| `custom` | Registered built-in evaluator and schema | Declared evidence | Internal only in v0.1; unknown custom type unsupported |

## Comparison rules

- Equality is type-strict. JSON integer 1 is not string `"1"`; booleans are not integers.
- Numbers use exact integer comparison or Decimal created from JSON lexical form. Binary floating-point tolerances are not implicit.
- String comparison is Unicode code-point exact unless a named normalization comparator is selected.
- Arrays preserve order by default; set semantics require an explicit comparator and canonical element key.
- Objects compare declared pointers or deep exact values after deterministic key ordering; undeclared extra fields do not affect pointer assertions.
- Secret values may be compared by keyed digest and persisted only as digest metadata.

## Snapshot identity

A snapshot ID identifies one logically consistent application view as defined by the observer. Multiple values needed for an all-or-none assertion must come from one snapshot response. An observer that cannot provide consistency must declare that limitation; the corresponding composite assertion is unsupported rather than falsely evaluated.

## Authentication and isolation

Observer authentication is independent from webhook signing. Test-only probe routes must be disabled outside the receiver test profile. The correct reference receiver uses a dedicated token, binds to an explicit test address, exposes read-only normalized evidence, and never returns raw secrets or customer data.
