# Final Scorecard

## Verdict

**LOCAL IMPLEMENTATION COMPLETE; PUBLIC RELEASE NOT CERTIFIED**

The complete local harness is implemented at commit
`58fc1342ded1e2a568d96aca756333f14f2a87f3`. Its locked tests, crash matrix,
security policy, package installation matrix, container contract, and local
execution gates pass. No repository was published, no artifact was uploaded,
and no public webhook target was contacted.

## Implementation gates

| Gate | Result | Evidence |
| --- | --- | --- |
| Windows full suite | PASS | CPython 3.12.13: 3,226 passed, 21 skipped, 0 failed in 536.96 s |
| Native Linux full suite | PASS | Ubuntu 26.04 WSL2, CPython 3.12.13: 3,212 passed, 35 skipped, 0 failed in 333.49 s |
| Static analysis | PASS | Ruff check, Ruff format, and Pyright (0 errors) |
| Artifact validation | PASS | `scripts/validate_artifacts.py` |
| Crash consistency | PASS | 16/16 P0 boundaries, 20 evidence nodes, schema migrations 1-4 |
| Security policy | PASS | 0 approved exceptions; 0 high-severity findings |
| Dependency licenses | PASS | 38 locked packages allowed; unknown licenses denied |
| Performance | PASS | All six authoritative P0 budgets and 13 performance tests |
| TASK-0810 convergence | PASS | All 14 exact VT records generated and validated against the implementation commit |

## Installable artifacts

| Subject | Digest | Result |
| --- | --- | --- |
| Wheel | `sha256:384d9bd9816f6a03b7115a7eb45a366da03cd61486d39aab75d4657a1f4f89dd` | SBOM, local digest statement, and verification pass |
| Source distribution | `sha256:64fd9a5c3851ae1e4a01f15977afd387536aadbc498d4dde93ea62597f65deff` | SBOM, local digest statement, and verification pass |
| OCI image manifest | `sha256:e74e6b9a466c293222deae4214e9ca04a35b010fc7b55f4d8d9ef1e2001bcbc5` | Non-root/read-only execution, SBOM, local digest statement, and verification pass |

Fresh wheel and source-distribution installations passed on CPython 3.12.13,
3.13.9, and 3.14.6. Every installation executed the installed console script
against a loopback receiver, returned a `pass` verdict, rejected an unsupported
schema with exit code 6, and produced the same normalized manifest digest:
`sha256:66c361e5c82d111575e14811d86e3ed7f03eb3a13018aa4d5d5c30ac26681e35`.
Both `uvx` and `pipx` reported package version 0.1.0.

## Quality-attribute measurements

| Metric | Observed | Authoritative budget | Result |
| --- | ---: | ---: | --- |
| Warm startup p95 | 247.3161 ms | 1,000 ms | PASS |
| Plan 100 events / 1,000 attempts p95 | 811.5099 ms | 2,000 ms | PASS |
| Peak planning RSS | 98.503906 MiB | 256 MiB | PASS |
| Journal growth per terminal attempt | 784 bytes | 32,768 bytes | PASS |
| All-format report regeneration p95 | 111.4152 ms | 5,000 ms | PASS |
| Cancellation cleanup | 0.5576 ms | 5,000 ms | PASS |

## Release boundary

This scorecard certifies the local implementation and artifacts only. Hosted
multi-OS CI, public registry scans, signed hosted attestations, OIDC publication,
GitHub release verification, and public upload steps were intentionally not run.
Those external gates remain prerequisites for any public release claim.
