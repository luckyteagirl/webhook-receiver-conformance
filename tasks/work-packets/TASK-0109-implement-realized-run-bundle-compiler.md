# TASK-0109 — Implement realized run-bundle compiler

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | large |
| Dependencies | TASK-0101, TASK-0103, TASK-0105, TASK-0106, TASK-0107, TASK-0108 |
| Blocks | TASK-0110 |
| Parallel group | None |
| Requirements | CFG-013, CLI-003, COMPAT-008, DATA-002, DATA-003, DATA-004, DATA-005, DX-004, FR-012, MUT-002, REPORT-001, SCHED-011, SCHED-017, SIG-005, TEST-005, TEST-014 |
| Tests | VT-CFG-013, VT-CLI-003, VT-COMPAT-008, VT-DATA-002, VT-DATA-003, VT-DATA-004, VT-DATA-005, VT-DX-004, VT-FR-012, VT-MUT-002, VT-REPORT-001, VT-SCHED-011, VT-SCHED-017, VT-SIG-005, VT-TEST-005, VT-TEST-014 |
| ADRs | ADR-004, ADR-012, ADR-022, ADR-025 |

## Objective

Freeze configuration, fixture blobs, planned IDs, mutations, conditional attempts, versions, and logical schedules into an immutable run-agnostic bundle; bind a fresh run ID only in execution artifacts.

## Rationale

Implements CFG-013, CLI-003, COMPAT-008, DATA-002, DATA-003, DATA-004, DATA-005, DX-004 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/manifest/compiler.py
- src/webhook_receiver_conformance/manifest/models.py

**Allowed files**

- src/webhook_receiver_conformance/manifest/compiler.py
- src/webhook_receiver_conformance/manifest/models.py
- tests/unit/manifest/test_compiler.py
- tests/golden/manifests/**

**Forbidden files**

- schemas/** unless explicitly listed
- machine/**
- specification/**
- unowned migrations
- public interfaces owned by another task

## Authoritative inputs

- machine/requirements.yaml
- machine/decisions.yaml
- machine/task-index.yaml
- specification/16-interfaces-and-contracts.md

## Interfaces

- **Owned:** ARC-COMPILER, ARC-MANIFEST
- **Consumed:** ARC-CLI, ARC-CONFIG, ARC-FIXTURE, ARC-JOURNAL, ARC-MANIFEST, ARC-MUT, ARC-PACKAGE, ARC-REF, ARC-REPORT-HTML, ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-SCHED, ARC-SIGN

## Implementation scope

Freeze configuration, fixture blobs, planned IDs, mutations, conditional attempts, versions, and logical schedules into an immutable run-agnostic bundle; bind a fresh `run_id` only in execution artifacts.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- Replay ignores changed source fixture files and uses only verified bundle blobs.
- The snapshot contains resolved non-secret defaults and secret fingerprints but no secret values.
- `webhook-conformance plan --help` exits 0 and the command contract test demonstrates its stated job.
- Replay creates a new run_id while preserving the same manifest_id.
- The manifest contains no `run_id` and hashing its canonical form omits only `manifest_id`.
- Planning rejects every floating-point manifest value and integer outside the inclusive I-JSON-safe range `-(2^53-1)` through `2^53-1`.
- Changing one byte changes the blob digest and causes bundle verification to fail until re-planned.
- The loader rejects a manifest whose canonical content no longer matches manifest_id.
- Cross-language golden vectors produce the documented digest.
- Replay can verify all deterministic outputs without the original config file.
- Manifest replay makes the same next-attempt decision for the same predecessor result.
- Scaled replay produces the same signature timestamp and signature bytes as the source bundle.
- Replay invokes no random generator and produces the same mutated blob digest.
- The example and every generated manifest validate against the selected schema version.
- Windows and POSIX generate the same manifest path strings for the same project tree.
- The preview is generated solely from the bundle and contains no secrets.
- Golden updates require an explicit compatibility review marker.
- A normalized cross-version digest matches the golden digest.

## Commands to run

```bash
uv run pytest -q tests/unit/manifest/test_compiler.py tests/golden/manifests/**
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/manifest/compiler.py
- src/webhook_receiver_conformance/manifest/models.py
- tests/unit/manifest/test_compiler.py
- tests/golden/manifests/**

## Completion evidence

- Passing evidence for VT-CFG-013
- Passing evidence for VT-CLI-003
- Passing evidence for VT-COMPAT-008
- Passing evidence for VT-DATA-002
- Passing evidence for VT-DATA-003
- Passing evidence for VT-DATA-004
- Passing evidence for VT-DATA-005
- Passing evidence for VT-DX-004
- Passing evidence for VT-FR-012
- Passing evidence for VT-MUT-002
- Passing evidence for VT-REPORT-001
- Passing evidence for VT-SCHED-011
- Passing evidence for VT-SCHED-017
- Passing evidence for VT-SIG-005
- Passing evidence for VT-TEST-005
- Passing evidence for VT-TEST-014

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
