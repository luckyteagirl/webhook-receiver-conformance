# Data and Persistence

## Storage boundary

Each run bundle owns:

```text
<artifact-dir>/<run_id>/
├── manifest.json              # immutable canonical JSON
├── manifest.sha256
├── journal.sqlite3            # mutable durable execution state
├── blobs/sha256/ab/<digest>   # immutable exact bytes, permissions 0600 where supported
├── reports/                   # regenerated projections
└── run.lock                   # ownership metadata; never the sole state authority
```

The directory must be local. Network and virtual filesystems without SQLite locking/sync guarantees are rejected or reported unsupported.

## SQLite settings

At every connection:

```sql
PRAGMA foreign_keys = ON;
PRAGMA trusted_schema = OFF;
PRAGMA busy_timeout = 5000;
PRAGMA journal_mode = DELETE;
PRAGMA synchronous = EXTRA;
```

Writes use explicit `BEGIN IMMEDIATE`. The journal service is the only writer. Long network or observer operations never occur inside a database transaction.

## Core schema

| Table | Primary key | Essential fields / constraints |
|---|---|---|
| `schema_migrations` | `migration_id` | checksum, applied_at; applied migrations immutable |
| `runs` | `run_id` | manifest_id UNIQUE, state, owner_epoch, created_at, terminal_category |
| `scenarios` | `scenario_id` | run_id FK, ordinal UNIQUE per run, state |
| `events` | `event_id` | scenario_id FK, event_type, fixture_blob_hash |
| `event_dependencies` | `(event_id, dependency_event_id)` | same scenario; no self-edge; DAG validated before insert |
| `deliveries` | `delivery_id` | event_id FK, ordinal UNIQUE per scenario, logical_time_ns, state |
| `attempts` | `attempt_id` | delivery_id FK, ordinal UNIQUE per delivery, state, phase, request hash, outcome category |
| `schedule_entries` | `schedule_entry_id` | entity type/id, logical time, deterministic tie key, condition, consumed_at |
| `observer_series` | `observation_id` | scenario/event/checkpoint/observer identity |
| `observation_samples` | `sample_id` | observation_id FK, sample_sequence UNIQUE, status, evidence blob |
| `assertions` | `assertion_id` | scenario_id FK, type, policy, state |
| `assertion_evaluations` | `evaluation_id` | assertion_id FK, sequence UNIQUE, result, expected/actual blobs |
| `evidence_links` | composite | assertion evaluation to attempt/observation/record IDs |
| `transitions` | `transition_id` | entity type/id, from/to, trigger, wall/monotonic/logical times, owner epoch |
| `recovery_decisions` | `decision_id` | attempt/scenario, policy, evidence refs, operator input digest |
| `redaction_events` | `redaction_id` | source type/id, rule ID, replacement type; never original secret |

Every foreign key is immediate unless a migration has a documented need for deferral. User strings are stored only after length/control-character handling. Raw payloads are content-addressed blobs, not repeated in rows.

## Append-oriented versus mutable state

- Manifests, blobs, transitions, attempt terminal outcomes, observation samples, assertion evaluations, and recovery decisions are append-only.
- Current entity state columns are mutable projections updated in the same transaction as their transition record.
- Report files are disposable projections.
- A current-state row can be rebuilt from append records and is integrity-checked in tests.

## Transaction boundaries

1. **Plan import:** run + all manifest entities in one transaction or none.
2. **Claim:** schedule entry consumption, lease/owner epoch, and entity transition in one transaction.
3. **Before send:** attempt row and `sending` transition commit before the executor may release request bytes.
4. **After transport:** one terminal attempt transition and sanitized evidence append in one transaction.
5. **Retry scheduling:** terminal result and conditional next schedule entry in one transaction.
6. **Observation:** one sample and state transition in one transaction.
7. **Assertion:** evaluation, evidence links, and assertion state in one transaction.
8. **Run terminal:** scenario reductions, run category, and report-generation checkpoint in one transaction.

## Ownership and work claiming

`run.lock` contains run ID, PID, process start fingerprint, hostname, owner epoch, and wall timestamp. The database `runs.owner_epoch` is authoritative. A new process may take ownership only when the prior process is proven absent on the same host or the operator supplies `--take-over` after a recovery preview. Takeover increments the epoch; stale workers cannot commit transitions with an old epoch.

## Integrity checks

On open/resume:

1. Verify manifest digest and all referenced blob digests.
2. Run `PRAGMA quick_check` by default; `integrity_check` for explicit inspect/repair.
3. Run `PRAGMA foreign_key_check`.
4. Verify schema migration checksums and supported `user_version`.
5. Recompute current-state projections from append records in audit mode.
6. Reject a journal whose run ID or manifest ID differs from the bundle.

## Migrations

- Ordered immutable Python/SQL migrations with ID and checksum.
- Backup or copy the database before a migration unless `--no-backup` is explicitly used for a disposable run.
- Run migrations under an exclusive owner and transaction where SQLite permits.
- A failed migration leaves the prior version usable or restores the backup.
- Downgrade is not automatic; export/recreate is the safe path before 1.0.

## Retention and deletion

Default retention is operator-controlled project files. `clean` is not a v0.1 CLI command; deletion is explicit filesystem removal after the run is closed. A future deletion command must refuse active runs, list files, require confirmation outside CI, and securely avoid following symlinks. Secret-bearing raw retention is off by default.

## Idempotent reporting

A report has an input watermark consisting of manifest digest, latest committed transition/evidence sequence, schema versions, renderer version, and redaction-policy digest. Regeneration to a temporary directory followed by atomic rename yields identical semantic content; generated-at fields use the committed run terminal time, not regeneration time.
