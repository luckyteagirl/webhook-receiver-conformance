# Unresolved Findings

## Blocking local completion

None.

## Public-release prerequisites

- The hosted Windows, Ubuntu 24.04, and macOS matrix for CPython 3.12, 3.13,
  and 3.14 was not run. Local evidence covers full suites on Windows and native
  WSL Linux with CPython 3.12, plus installed-artifact smoke tests on all three
  supported Python versions.
- The Linux full suite ran on Ubuntu 26.04 under WSL2 rather than the release
  workflow's exact Ubuntu 24.04 hosted runner.
- Trivy was unavailable locally, so neither the filesystem nor OCI image has a
  final Trivy report. The locked Python dependency audit reports no
  vulnerabilities and the release policy reports zero high-severity findings.
- Local SPDX documents and digest statements were generated and verified, but
  they are not signed hosted provenance. GitHub attestations, OIDC publication,
  registry digest verification, and release upload were intentionally not run.
- The v0.1 stable-release mutation-score gate remains deferred by the accepted
  release policy and its contract test.

## Accepted local limitations

- `mmdc` is not installed; Mermaid artifacts received structural validation
  rather than rendered-image validation.
- The secondary, non-gating quality table in
  `specification/24-quality-attributes-and-budgets.md` sets a 1,500 ms minimal
  validation target; the local measurement was 1,986.636 ms. All authoritative
  P0 budgets in `specification/05-product-requirements.md` and
  `machine/requirements.yaml` pass.
- A file- or environment-backed signing secret changed by another local actor
  after successful resolution can cause a post-challenge failure. Digest-bound
  fixture bytes remain frozen and cannot be replaced or sent tampered; the CLI's
  required challenge-before-fixture-delivery invariant remains satisfied.
- Observer adoption and demand still require external pilots; this does not
  block the local technical implementation.
