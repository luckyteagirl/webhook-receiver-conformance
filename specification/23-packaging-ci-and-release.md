# Packaging, CI, and Release Engineering

## Runtime support

- CPython >=3.12,<3.15 on Linux, macOS, and Windows.
- Required CI tests every supported minor and platform for path/process/SQLite/CLI-critical behavior.
- AnyIO runs the asyncio backend in v0.1. Trio parity is not promised.

## Dependency management

PEP 621 metadata in `pyproject.toml`; uv lockfile committed. Runtime dependencies are minimized to Typer, Pydantic, HTTPX, AnyIO, safe YAML parsing, JSON Schema validation, and small direct necessities. FastAPI is an optional development/reference extra. CI uses `uv sync --locked`; release builds use a clean locked environment.

## Python distributions

Build wheel and sdist with `uv build`. Test metadata, import, CLI version, minimal offline run, included schemas/templates, and reproducibility-relevant contents in fresh environments. Publish through PyPI Trusted Publishing; no long-lived upload token.

## pipx and uvx

Document and test:

```bash
pipx run webhook-receiver-conformance --version
uvx webhook-receiver-conformance --version
```

The package command remains `webhook-conformance` after install.

## OCI image

- Multi-stage build from a pinned digest.
- Non-root numeric UID/GID.
- Read-only root filesystem compatible.
- Only project input and artifact output mounts required.
- No shell required at runtime where practical.
- OCI labels contain source, revision, version, license, created timestamp.
- Image and SBOM are attested and scanned.
- Multi-architecture amd64/arm64 after package convergence; Windows container is not required.

## GitHub Action

A composite or JavaScript wrapper may invoke the version-pinned container/CLI. Inputs: version/image digest, config or manifest, command, artifact directory, formats, retention days, noninteractive mode, and explicit public-target authorization. Outputs: run ID, manifest ID, result category, exit code, report directory. The wrapper preserves the CLI exit category after uploading sanitized artifacts.

## CI jobs

1. Formatting/lint.
2. Static typing.
3. Unit/property/contract.
4. Schema/example/cross-reference.
5. Integration/e2e on supported OS/Python matrix.
6. Security regression.
7. Crash subset; exhaustive on nightly/release.
8. Package build/install smoke.
9. Dependency, secret, license, and static security scans.
10. Release-only SBOM, provenance, image, signature/attestation verification.

Fork pull requests run without secrets, public targets, publish permissions, or untrusted action execution from privileged contexts.

## Versioning

- Package: SemVer; pre-1.0 minor may break with explicit migration, never silently.
- Configuration, manifest, observer, evidence, and task schemas version independently.
- Generator/signature/mutation IDs include algorithm/profile versions.
- Database uses ordered migration IDs and `user_version`.
- Built-in provider profiles include behavior/version metadata.

## Release process

1. Changelog and compatibility review.
2. All release gates pass from clean locked checkout.
3. Build wheel/sdist/image once.
4. Generate SPDX or CycloneDX SBOMs.
5. Produce artifact attestations/provenance.
6. Verify artifacts before publishing.
7. Publish through trusted identity.
8. Verify installed artifacts and attestations from public registries.
9. Attach evidence and support statement to release.

## Vulnerability response

`SECURITY.md` names supported release line, private reporting route, acknowledgement target, triage/severity process, embargo coordination, patch branch, advisory/CVE decision, release verification, and postmortem trigger. Security fixes that alter schemas or defaults include migration/compatibility notes.
