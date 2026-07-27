# TASK-0601 — Implement stable JSON and JSON Lines exports

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-06-reporting |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0205, TASK-0508 |
| Blocks | TASK-0604, TASK-0605 |
| Parallel group | PG-06A |
| Requirements | DATA-007, FR-007, OBS-019, PRIV-001, PRIV-002, PRIV-003, PRIV-004, PRIV-006, PRIV-007, REPORT-001, REPORT-002, REPORT-003, REPORT-004, REPORT-005, REPORT-006, REPORT-007, REPORT-008, REPORT-009, REPORT-020, SEC-023, SIG-012 |
| Tests | VT-DATA-007, VT-FR-007, VT-OBS-019, VT-PRIV-001, VT-PRIV-002, VT-PRIV-003, VT-PRIV-004, VT-PRIV-006, VT-PRIV-007, VT-REPORT-001, VT-REPORT-002, VT-REPORT-003, VT-REPORT-004, VT-REPORT-005, VT-REPORT-006, VT-REPORT-007, VT-REPORT-008, VT-REPORT-009, VT-REPORT-020, VT-SEC-023, VT-SIG-012 |
| ADRs | ADR-001, ADR-008, ADR-015, ADR-025 |

## Objective

Export run, delivery, observation, assertion, and result records in schema-valid stable order.

## Rationale

Implements DATA-007, FR-007, OBS-019, PRIV-001, PRIV-002, PRIV-003, PRIV-004, PRIV-006 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/reporting/json_reports.py

**Allowed files**

- src/webhook_receiver_conformance/reporting/json_reports.py
- tests/unit/reporting/test_json_reports.py

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

- **Owned:** ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-REPORT-HTML
- **Consumed:** ARC-JOURNAL, ARC-OBS-CMD, ARC-OBS-HTTP, ARC-REPORT-HTML, ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-SECRET, ARC-SIGN, ARC-TARGET

## Implementation scope

Export run, delivery, observation, assertion, and result records in schema-valid stable order.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Preserve all project security invariants.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The inspect command traverses all required identifiers from a failed assertion without heuristic matching.
- Schema validation rejects a persisted record without schema_version.
- No raw or base64 key material appears in any default artifact.
- Sensitive evidence and child stderr values are absent from every default artifact.
- The example and every generated manifest validate against the selected schema version.
- The number of terminal attempt rows equals the number of terminal attempts in SQLite.
- Every observation record validates and references an existing attempt, checkpoint, or assertion plan.
- Every assertion record contains expected, actual/evidence references, and classification.
- Summary counts reconcile exactly with JSON Lines records and the process exit code.
- Regeneration on another supported platform yields byte-identical records except explicitly volatile wall timestamps.
- The schema annotations and determinism document name run_id, wall timestamps, durations, and environment observations as volatile.
- A signature rejection links mutation, delivery, attempt response, and no-processing observation.
- JUnit uses error and HTML uses an ambiguity section for an unknown attempt.
- Only digests, sizes, content type, and redacted previews appear by default.
- Newlines and control characters cannot create forged log records.
- A body canary is absent from text and structured logs.
- A response canary is absent from logs.
- Default evidence renders a stable redacted marker for each header.
- Nested objects and arrays redact only configured paths while invalid JSON falls back to no-body preview.
- Malformed JSON with configured pointer redaction yields preview_omitted and no body content.
- Equal values correlate within one run but not across runs and the key is not persisted.

## Commands to run

```bash
uv run pytest -q tests/unit/reporting/test_json_reports.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/reporting/json_reports.py
- tests/unit/reporting/test_json_reports.py

## Completion evidence

- Passing evidence for VT-DATA-007
- Passing evidence for VT-FR-007
- Passing evidence for VT-OBS-019
- Passing evidence for VT-PRIV-001
- Passing evidence for VT-PRIV-002
- Passing evidence for VT-PRIV-003
- Passing evidence for VT-PRIV-004
- Passing evidence for VT-PRIV-006
- Passing evidence for VT-PRIV-007
- Passing evidence for VT-REPORT-001
- Passing evidence for VT-REPORT-002
- Passing evidence for VT-REPORT-003
- Passing evidence for VT-REPORT-004
- Passing evidence for VT-REPORT-005
- Passing evidence for VT-REPORT-006
- Passing evidence for VT-REPORT-007
- Passing evidence for VT-REPORT-008
- Passing evidence for VT-REPORT-009
- Passing evidence for VT-REPORT-020
- Passing evidence for VT-SEC-023
- Passing evidence for VT-SIG-012

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
