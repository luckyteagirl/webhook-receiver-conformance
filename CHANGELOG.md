# Changelog

All notable changes to this project are documented here.

## 0.1.0 - 2026-07-27

Initial local-first release of the webhook receiver conformance harness.

### Added

- Durable scenario execution with bounded concurrency, retries, deterministic waits,
  journaled evidence, observer assertions, and generated reports.
- Self-contained replay bundles, offline inspection, report regeneration, minimized
  replay export, and interrupted-run recovery.
- A real `webhook-conformance` command with `run`, `replay`, `inspect`, `report`, and
  `resume` workflows.

### Compatibility

The supported runtime range is CPython 3.12 through 3.14. The public configuration,
bundle, observer, and report contracts use their documented 1.0 schema versions.

### Migration

This is the first packaged release, so there is no earlier production data migration.
Pre-release bundles should be regenerated with 0.1.0 before relying on replay.
Existing pre-release journals migrate transactionally through SQLite schema version 4.
Version 4 adds sanitized response staging so a crash after a durable HTTP response can
recover its exact terminal classification without resending the request. Legacy
`response_observed` rows that predate this evidence fail closed during resume.

### Security

Receiver secrets remain external to replay bundles, path traversal is rejected, bundle
digests are verified before use, subprocess assertions use explicit safe aliases, and
network targets are re-authorized for each invocation.

### Schema

Configuration, bundle manifest, observer, evidence, and report schemas are versioned.
SQLite journal schema version 4 is migrated transactionally by the runtime.
