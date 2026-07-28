# Compatibility and releases

## Supported runtime matrix

Version 0.1 supports CPython only:

| Platform runner family | CPython 3.12 | CPython 3.13 | CPython 3.14 |
| --- | --- | --- | --- |
| Ubuntu (`ubuntu-24.04`) | Supported | Supported | Supported |
| macOS (`macos-14`) | Supported | Supported | Supported |
| Windows (`windows-2025`) | Supported | Supported | Supported |

The package metadata enforces `>=3.12,<3.15`, and
`.github/workflows/package-test.yml` runs the exact matrix above. The compatibility
promise does not extend to alternative Python implementations or experimental runtime
modes. AnyIO uses its asyncio backend; Trio parity is not promised.

“Supported” describes the release contract and mandatory CI matrix; it is not a claim
that a workflow file executed. The command transcripts and unavailable runners for a
particular local release candidate are recorded in `validation/final-scorecard.md`.

The universal Python wheel is authoritative. The source distribution, non-root OCI
image, and GitHub Action wrapper must preserve the same CLI and schema behavior. A
Windows container is not required.

## Version command

```text
uv run webhook-conformance version
uv run webhook-conformance --json version
```

Version 0.1.0 currently reports:

```text
webhook-conformance 0.1.0
configuration schema 1.0
manifest schema 1.0
observer protocol 1.0
report schema 1.0
generator hmac-sha256-context-v1
sqlite user_version 4
```

The JSON form additionally exposes `task_index_schema`.

| Version field | Compatibility scope |
| --- | --- |
| `package` | Distribution, CLI and documented public Python surface |
| `configuration_schema` | Project configuration reader |
| `manifest_schema` | Immutable execution-plan reader |
| `observer_protocol` | Command and HTTP observer wire messages |
| `report_schema` | Result summary and evidence record projections |
| `task_index_schema` | Repository implementation-planning artifact |
| `generator_algorithm` | Deterministic context/ID generation |
| `sqlite_user_version` | Ordered local journal migrations |

These values are independent. A package patch may leave every schema unchanged; a new
schema major need not numerically match the package major.

## SemVer before 1.0

Package releases use Semantic Versioning. Before 1.0:

- a patch release fixes behavior without intentionally breaking a documented public
  contract;
- a minor release may contain a breaking change only when the changelog calls it out
  and supplies an explicit migration/compatibility note;
- no release silently reinterprets persisted data or wire messages;
- deprecations identify the replacement and removal release where feasible.

“Pre-1.0” is not permission to make unannounced compatibility breaks.

## What counts as breaking

| Surface | Breaking examples |
| --- | --- |
| CLI | Removing/renaming a command or option; changing option meaning, machine-output shape, diagnostic category/code contract, or exit mapping |
| Configuration | Removing/renaming a field; adding a required field; changing type, default meaning, enum interpretation, path/security semantics, or secret reference behavior |
| Manifest | Removing/renaming a field; adding required data; changing identity/digest/canonicalization meaning; changing a type or interpreted enum |
| Observer protocol | Changing routes/method, ID retry semantics, authentication placement, capability meaning, evidence tags, required fields, or response status semantics |
| Report/evidence | Changing required fields, identity linkage, redaction guarantees, result meaning, or a consumer-interpreted enum |
| Public Python API | Removing/renaming documented imports, changing call signatures/return types, or changing validated model semantics |

Breaking serialized changes require a new schema/protocol major. Same-major additive
fields are compatible only after a registered revision declares them optional. Unknown
majors are rejected before side effects.

## Public Python and extension scope

The v0.1 public Python scope is intentionally narrow: version metadata, validated model
types needed by integrations, observer protocol models, and
`webhook_receiver_conformance.cli.run_cli()`. Direct orchestration through scheduler,
journal, network, signer, mutation, assertion, or reporter classes is not a pre-1.0
compatibility promise.

There is no public third-party plugin API. Receiver-specific integrations should use
the independently versioned observer wire protocol described in
[Observer integration](observers.md).

## Release evidence

A release requires a clean locked build, schema/example validation, lint/type/test
gates, package install smoke tests, cross-platform matrix results, changelog and
compatibility review, and verified distribution artifacts. Resource measurements are
quality budgets for the harness, not receiver load results.
