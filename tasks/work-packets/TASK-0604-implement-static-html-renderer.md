# TASK-0604 — Implement static HTML renderer

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-06-reporting |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0601, TASK-0602 |
| Blocks | TASK-0605, TASK-0805 |
| Parallel group | PG-06B |
| Requirements | DX-008, MUT-019, REPORT-009, REPORT-017, REPORT-018, REPORT-019, REPORT-020, SEC-022, SEC-024 |
| Tests | VT-DX-008, VT-MUT-019, VT-REPORT-009, VT-REPORT-017, VT-REPORT-018, VT-REPORT-019, VT-REPORT-020, VT-SEC-022, VT-SEC-024 |
| ADRs | None |

## Objective

Render a no-script, escaped, CSP-constrained report that traces causal evidence without exposing raw secrets.

## Rationale

Implements DX-008, MUT-019, REPORT-009, REPORT-017, REPORT-018, REPORT-019, REPORT-020, SEC-022 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/reporting/html.py
- src/webhook_receiver_conformance/reporting/templates/**

**Allowed files**

- src/webhook_receiver_conformance/reporting/html.py
- src/webhook_receiver_conformance/reporting/templates/**
- tests/unit/reporting/test_html.py

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
- **Consumed:** ARC-CLI, ARC-MUT, ARC-REPORT-HTML, ARC-REPORT-JSON, ARC-REPORT-JUNIT, ARC-SECRET, ARC-TARGET

## Implementation scope

Render a no-script, escaped, CSP-constrained report that traces causal evidence without exposing raw secrets.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Escape every fixture-derived value, emit a restrictive CSP, and never render raw HTML from evidence.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- A replaced sensitive value is absent from logs and HTML while its redacted marker remains.
- JUnit uses error and HTML uses an ambiguity section for an unknown attempt.
- HTML parsing finds no script elements, event-handler attributes, javascript URLs, or external resources.
- A payload containing closing tags, event handlers, and entities renders as text only.
- The policy contains default-src none and script-src none.
- Only digests, sizes, content type, and redacted previews appear by default.
- Malicious fixture and observer strings cannot change terminal title, color, cursor, or hyperlinks.
- Template tests fail if an evidence value is marked safe.
- Each classification has a separate label and explanatory action in the golden HTML report.

## Commands to run

```bash
uv run pytest -q tests/unit/reporting/test_html.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/reporting/html.py
- src/webhook_receiver_conformance/reporting/templates/**
- tests/unit/reporting/test_html.py

## Completion evidence

- Passing evidence for VT-DX-008
- Passing evidence for VT-MUT-019
- Passing evidence for VT-REPORT-009
- Passing evidence for VT-REPORT-017
- Passing evidence for VT-REPORT-018
- Passing evidence for VT-REPORT-019
- Passing evidence for VT-REPORT-020
- Passing evidence for VT-SEC-022
- Passing evidence for VT-SEC-024

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
