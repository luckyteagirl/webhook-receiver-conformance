# TASK-0105 — Implement YAML loader and precedence

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0104 |
| Blocks | TASK-0109 |
| Parallel group | PG-01C |
| Requirements | CFG-001, CFG-002, CFG-004, CFG-005, CFG-006, CFG-010, CFG-011, CFG-012, SEC-012, SEC-016 |
| Tests | VT-CFG-001, VT-CFG-002, VT-CFG-004, VT-CFG-005, VT-CFG-006, VT-CFG-010, VT-CFG-011, VT-CFG-012, VT-SEC-012, VT-SEC-016 |
| ADRs | ADR-019 |

## Objective

Parse duplicate-key-free YAML, resolve paths, apply documented CLI overrides, and return structured diagnostics.

## Rationale

Implements CFG-001, CFG-002, CFG-004, CFG-005, CFG-006, CFG-010, CFG-011, CFG-012 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/config/loader.py
- src/webhook_receiver_conformance/config/diagnostics.py

**Allowed files**

- src/webhook_receiver_conformance/config/loader.py
- src/webhook_receiver_conformance/config/diagnostics.py
- tests/unit/config/test_loader.py

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

- **Owned:** ARC-CONFIG
- **Consumed:** ARC-CONFIG, ARC-SECRET, ARC-TARGET

## Implementation scope

Parse duplicate-key-free YAML, resolve paths, apply documented CLI overrides, and return structured diagnostics.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Use safe YAML construction, reject custom tags, and never interpolate arbitrary expressions.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The minimal example parses and validates with schema_version 1.
- A fixture containing two receiver keys fails with a line-and-column diagnostic.
- A !!python/object or unknown custom tag is rejected without object construction.
- A precedence table test demonstrates the effective value at each layer.
- A CLI attempt to override an undeclared signer or target-policy field is rejected.
- The same configuration resolves identically when invoked from a different current working directory.
- Include-like keys and remote paths are rejected as unknown.
- The validate command succeeds with network syscalls denied and observer executables unavailable.
- Traversal, directory, device, and symlink-escape paths fail validation.
- Absolute escape, .. traversal, alternate separators, and Windows drive/UNC escape cases are rejected.

## Commands to run

```bash
uv run pytest -q tests/unit/config/test_loader.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/config/loader.py
- src/webhook_receiver_conformance/config/diagnostics.py
- tests/unit/config/test_loader.py

## Completion evidence

- Passing evidence for VT-CFG-001
- Passing evidence for VT-CFG-002
- Passing evidence for VT-CFG-004
- Passing evidence for VT-CFG-005
- Passing evidence for VT-CFG-006
- Passing evidence for VT-CFG-010
- Passing evidence for VT-CFG-011
- Passing evidence for VT-CFG-012
- Passing evidence for VT-SEC-012
- Passing evidence for VT-SEC-016

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
