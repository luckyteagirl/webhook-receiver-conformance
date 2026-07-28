# Observer integration

An HTTP acknowledgement alone cannot show whether the receiver committed its durable
business effect. Observers provide a separate, read-only and normalized receiver-state
view. Webhook signing credentials and observer authentication are independent.

The public v0.1 extension contract is the observer wire protocol. Internal signer,
mutation, scheduler, journal, report, and transport adapters are built-in implementation
details, not third-party plugin APIs.

## Shared protocol

Both observer transports use
[`observer-request.schema.json`](../schemas/observer-request.schema.json),
[`observer-response.schema.json`](../schemas/observer-response.schema.json), and
[`observer-evidence.schema.json`](../schemas/observer-evidence.schema.json).

Before an observation, the caller requests `operation=capabilities`. Capabilities name
the exact evidence keys/types, query limit, pending/snapshot support, and the mandatory
`read_only` and `idempotent` declarations. Automatic reinvocation is allowed only when
both declarations are true.

An `observe` request has a logical `request_id`, a fresh `sample_id`, UUIDv4 `run_id`,
optional scenario/event/checkpoint scope, and one or more typed queries. A retry keeps
`request_id` and changes `sample_id`. Every successful response has a nonempty
`snapshot_id`.

Evidence tags are closed: `null`, `boolean`, `integer`, `decimal-string`, `string`,
`bytes-digest`, `timestamp`, `array`, and `object`. There is no implicit string/number
coercion. Binary evidence is digest metadata, not embedded arbitrary bytes.

## Command observer

[`examples/observers/command_observer.py`](../examples/observers/command_observer.py)
reads one bounded JSON request from stdin and writes one JSON response to stdout. The
configuration is an argv array; the harness never runs it through a shell. Its working
directory is project-contained, the environment is allowlisted, stderr is diagnostic,
and execution/output are bounded.

The complete configuration declares:

```yaml
observers:
  receiver_state_command:
    type: command
    argv: [python, observers/command_observer.py]
    timeout: 2s
    working_directory: .
    environment_allowlist:
    - WEBHOOK_OBSERVER_TOKEN
    - WEBHOOK_RECEIVER_DB
```

Set `WEBHOOK_RECEIVER_DB` to the local reference database when invoking this example
outside the harness:

```text
.webhook-conformance/reference-receiver.sqlite3
```

The observer opens the database read-only and enables SQLite query-only mode.

## HTTP observer

[`examples/observers/http_observer.py`](../examples/observers/http_observer.py) binds
only to `127.0.0.1` and exposes:

```text
POST /capabilities
POST /observe
```

It requires `Content-Type: application/json` and a dedicated bearer test token. Start it
after the reference receiver has created its database:

PowerShell:

```powershell
$env:WEBHOOK_OBSERVER_TOKEN = "local-observer-token-32-bytes"
uv run python examples/observers/http_observer.py --database .webhook-conformance/reference-receiver.sqlite3
```

POSIX shell:

```sh
export WEBHOOK_OBSERVER_TOKEN='local-observer-token-32-bytes'
uv run python examples/observers/http_observer.py --database .webhook-conformance/reference-receiver.sqlite3
```

The harness's HTTP observer adapter applies the same destination-policy, address pinning,
redirect, proxy, TLS, and size-limit boundaries as receiver transport. Public observers
also require the public-target gates; this example deliberately avoids that boundary.

## One test kit for both transports

Run:

```text
uv run python examples/observers/observer_test_kit.py
```

The kit sends the same capability and observe request corpus through the command process
and loopback HTTP server, validates every request and response with the same current
schemas, checks `request_id` preservation, and verifies typed `processing_count`
evidence. It creates a temporary local database and contacts no external service.

The example JSON documents
[`observer-request.example.json`](../examples/observer-request.example.json) and
[`observer-response.example.json`](../examples/observer-response.example.json) are also
validated by `scripts/validate_artifacts.py`.

## Extension boundary

There is no public dynamic plugin loader in v0.1. Do not load arbitrary signer, mutation,
observer, assertion, reporter, lifecycle, or transport code from configuration. The existing
[`plugin-metadata.example.json`](../examples/plugin-metadata.example.json) is explicitly
marked with `stability: experimental`, is built-in-only metadata, and has
`public_compatibility_promise: false`; it does not make internal adapters public plugins.

Use the versioned observer protocol for receiver-specific state integration. A new
built-in adapter requires source changes, a closed registration, schemas where
applicable, and the category contract suite. Unknown configuration fields remain
invalid.
