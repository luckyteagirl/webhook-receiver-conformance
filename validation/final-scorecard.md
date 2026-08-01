# Final scorecard

## Verdict

**GITHUB REPOSITORY READY. PUBLIC PACKAGE RELEASE BLOCKED.**

The release candidate passes local and hosted repository gates. PyPI trusted-publisher configuration blocks the first public package release.

No release tag, PyPI distribution, or GHCR image exists.

## Candidate identity

| Subject | Value |
| --- | --- |
| Repository | `luckyteagirl/webhook-receiver-conformance` |
| Implementation commit | `924ef205ff57fac5973713944b2f2783770ba42e` |
| Package version | `0.1.0` |
| Python versions | CPython 3.12, 3.13, and 3.14 |

## Verification gates

| Gate | Result | Evidence |
| --- | --- | --- |
| Locked local suite | PASS | 3,233 passed, 26 skipped, 0 failed |
| Static analysis | PASS | Ruff check, Ruff format, and Pyright report no error |
| Artifact validation | PASS | `scripts/validate_artifacts.py` |
| Package build | PASS | `uv build` creates the wheel and source distribution |
| Hosted CI | PASS | [CI run 30696252141](https://github.com/luckyteagirl/webhook-receiver-conformance/actions/runs/30696252141) |
| Hosted package matrix | PASS | [Package run 30696252128](https://github.com/luckyteagirl/webhook-receiver-conformance/actions/runs/30696252128) |
| Hosted release dry run | PASS | [Release run 30696255381](https://github.com/luckyteagirl/webhook-receiver-conformance/actions/runs/30696255381) |
| Vulnerability policy | PASS | Trivy reports no unapproved high or critical finding |
| Secret scan | PASS | Gitleaks 8.30.1 covers `c6a8629`, and required CI scans later changes |
| Repository controls | PASS | GitHub security controls operate, and the default-branch ruleset exists |

## Installable artifacts

| Subject | Digest | Result |
| --- | --- | --- |
| Wheel | `sha256:d8fb2805d580bd78d5d37762f85827c28badfe906b21cd42373db69905662f74` | Release dry-run build and package checks pass |
| Source distribution | `sha256:ec93308527361a3ba090e1b97f21e566b3af78006176a516931fd9fd4215f447` | Release dry-run build and package checks pass |
| Container archive | `sha256:e44e36d53e0cc20fe27cb6fc17a0f8f209ec72e4a7f5225b487cbfd09ef5e3ba` | Container contract, Trivy, SBOM, and digest checks pass |
| Normalized manifest | `sha256:178dc7ee90d54e25ff4e8bd498126a95e7694e2f52644875dc3af9d313d35099` | Installed-artifact checks agree |

## GitHub controls

The repository enables private vulnerability reports, secret scanning, push protection, and Dependabot security updates.

The default-branch ruleset requires pull requests, resolved conversations, linear history, and 20 CI checks.

GitHub Actions use read-only default permissions. Workflows cannot approve pull requests.

## Publication boundary

Configure this pending publisher in the PyPI project settings:

- Owner: `luckyteagirl`
- Repository: `webhook-receiver-conformance`
- Workflow: `release.yml`
- Environment: `pypi`

After this configuration, create the `v0.1.0` GitHub release. The release workflow will publish and verify PyPI, GHCR, SBOM, and provenance subjects.
