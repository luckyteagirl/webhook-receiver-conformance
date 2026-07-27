# TASK-0106 — Implement secret references and fingerprints

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-01-domain-and-schemas |
| Priority | P0 |
| Complexity | medium |
| Dependencies | TASK-0104 |
| Blocks | TASK-0109, TASK-0401 |
| Parallel group | PG-01C |
| Requirements | CFG-007, CFG-008, CFG-009, OBS-010, PRIV-007, SEC-013, SEC-014, SEC-017, SIG-011, SIG-012, SIG-016 |
| Tests | VT-CFG-007, VT-CFG-008, VT-CFG-009, VT-OBS-010, VT-PRIV-007, VT-SEC-013, VT-SEC-014, VT-SEC-017, VT-SIG-011, VT-SIG-012, VT-SIG-016 |
| ADRs | None |

## Objective

Resolve environment, file, and generated test-key references without serializing plaintext secrets.

## Rationale

Implements CFG-007, CFG-008, CFG-009, OBS-010, PRIV-007, SEC-013, SEC-014, SEC-017 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- src/webhook_receiver_conformance/secrets.py

**Allowed files**

- src/webhook_receiver_conformance/secrets.py
- tests/unit/test_secrets.py

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

- **Owned:** ARC-SECRET
- **Consumed:** ARC-OBS-CMD, ARC-OBS-HTTP, ARC-REPORT-HTML, ARC-SECRET, ARC-SIGN, ARC-TARGET

## Implementation scope

Resolve environment, file, and generated test-key references without serializing plaintext secrets.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Do not log secret values; validate file ownership/permissions where supported; use SHA-256 fingerprints over public or derived non-secret material.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- ${NAME}-style free-form interpolation remains literal while {env: NAME} resolves through the secret resolver.
- A symlink or traversal path outside the secret root is rejected.
- A literal secret field produces a diagnostic directing the user to env, file, or generated references.
- Signer constructors accept secret handles and cannot serialize raw key bytes into models.
- No raw or base64 key material appears in any default artifact.
- The generator requests 32 bytes from secrets.token_bytes and stores only the secret reference and fingerprint.
- Missing or wrong credentials produce observer error without response-body leakage.
- Canary secrets are absent from a byte scan of the complete run directory.
- Secret handles expose use-with callback semantics and model dumps contain only references/fingerprints.
- A race-resistant symlink test cannot read or overwrite an external canary file.
- Equal values correlate within one run but not across runs and the key is not persisted.

## Commands to run

```bash
uv run pytest -q tests/unit/test_secrets.py
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- src/webhook_receiver_conformance/secrets.py
- tests/unit/test_secrets.py

## Completion evidence

- Passing evidence for VT-CFG-007
- Passing evidence for VT-CFG-008
- Passing evidence for VT-CFG-009
- Passing evidence for VT-OBS-010
- Passing evidence for VT-PRIV-007
- Passing evidence for VT-SEC-013
- Passing evidence for VT-SEC-014
- Passing evidence for VT-SEC-017
- Passing evidence for VT-SIG-011
- Passing evidence for VT-SIG-012
- Passing evidence for VT-SIG-016

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
