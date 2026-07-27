# TASK-0808 — Implement release security and provenance

## Metadata

| Field | Value |
| --- | --- |
| Phase | phase-08-packaging-security-and-ci |
| Priority | P1 |
| Complexity | medium |
| Dependencies | TASK-0802, TASK-0804 |
| Blocks | TASK-0810 |
| Parallel group | None |
| Requirements | OPS-009, OPS-011, OPS-012, OPS-013, OPS-014, SEC-030, SEC-031, SEC-032, SEC-033, SEC-034 |
| Tests | VT-OPS-009, VT-OPS-011, VT-OPS-012, VT-OPS-013, VT-OPS-014, VT-SEC-030, VT-SEC-031, VT-SEC-032, VT-SEC-033, VT-SEC-034 |
| ADRs | None |

## Objective

Generate SBOMs, scan dependencies, publish through Trusted Publishing, and attest wheels and images.

## Rationale

Implements OPS-009, OPS-011, OPS-012, OPS-013, OPS-014, SEC-030, SEC-031, SEC-032 and related requirements at the earliest dependency-safe point.

## Preconditions

- Every dependency task is complete and its verification commands pass.
- No unresolved high-severity finding affects an owned interface.

## File ownership

**Exclusive ownership**

- .github/workflows/release.yml
- SECURITY.md
- scripts/release_check.py

**Allowed files**

- .github/workflows/release.yml
- SECURITY.md
- scripts/release_check.py

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

- **Owned:** No public interface; task owns only listed implementation files.
- **Consumed:** ARC-ACTION, ARC-PACKAGE, ARC-SECRET, ARC-TARGET

## Implementation scope

Generate SBOMs, scan dependencies, publish through Trusted Publishing, and attest wheels and images.

## Explicit non-goals

- Do not implement adjacent tasks or redesign public contracts.

## Security constraints

Use OIDC Trusted Publishing; prohibit long-lived PyPI or registry tokens.

## Error and edge cases

- The command returns a classified nonzero result and preserves diagnostic evidence.

## Acceptance criteria

- The release gate consumes a machine-readable exception file with owner and expiry.
- Release validation verifies subject digests in the SBOM and attestation.
- The release workflow has id-token write, contains no PyPI secret reference, and publishes an attested artifact.
- gh attestation verify succeeds for release subjects.
- SECURITY.md names contact/process, supported versions, response stages, and disclosure expectations.
- Release policy defines breaking changes for CLI, config, manifest, observer protocol, and Python API.
- Release CI fails when the target version lacks a changelog entry.
- Dependabot groups and CODEOWNERS/review guidance identify sensitive dependency classes.
- SECURITY.md names the current supported release line and end-of-support rule.
- The release workflow has explicit dependencies on every required job.

## Commands to run

```bash
uv run pytest -q tests
uv run python scripts/validate_artifacts.py
uv run ruff check .
uv run pyright
```

## Expected outputs

- .github/workflows/release.yml
- SECURITY.md
- scripts/release_check.py

## Completion evidence

- Passing evidence for VT-OPS-009
- Passing evidence for VT-OPS-011
- Passing evidence for VT-OPS-012
- Passing evidence for VT-OPS-013
- Passing evidence for VT-OPS-014
- Passing evidence for VT-SEC-030
- Passing evidence for VT-SEC-031
- Passing evidence for VT-SEC-032
- Passing evidence for VT-SEC-033
- Passing evidence for VT-SEC-034

## Rollback or recovery

Revert only files owned by this task; preserve schema and migration history; document any partially generated artifact before handoff.

## Documentation changes

- Update public behavior documentation when the task changes a command, schema, interface, error, security control, or compatibility promise.

## Handoff

Report changed files, commands run, test evidence, remaining risks, and any interface assumption. Do not broaden scope.
