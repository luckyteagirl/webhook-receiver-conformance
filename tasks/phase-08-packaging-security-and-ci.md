# phase-08-packaging-security-and-ci

## Objective

Complete the phase as a demonstrable vertical increment without violating later public contracts.

## Entry criteria

All dependencies outside this phase are complete and their integration checkpoint passes.

## Tasks

| ID | Title | Dependencies | Parallel | Owned files | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| TASK-0801 | Complete CLI command tree and help contracts | TASK-0311, TASK-0509, TASK-0606 | Serial | src/webhook_receiver_conformance/cli/** | Passing evidence for VT-CFG-006; Passing evidence for VT-CFG-012; Passing evidence for VT-CFG-014 |
| TASK-0802 | Create non-root Docker distribution | TASK-0801 | PG-08A | Dockerfile, .dockerignore | Passing evidence for VT-OPS-003; Passing evidence for VT-OPS-005; Passing evidence for VT-OPS-006 |
| TASK-0803 | Create GitHub Action wrapper | TASK-0801 | PG-08A | action.yml, .github/actions/** | Passing evidence for VT-OPS-005; Passing evidence for VT-OPS-007; Passing evidence for VT-OPS-008 |
| TASK-0804 | Implement cross-platform installation tests | TASK-0801 | PG-08A | .github/workflows/package-test.yml, scripts/package_smoke.py | Passing evidence for VT-COMPAT-001; Passing evidence for VT-COMPAT-003; Passing evidence for VT-COMPAT-004 |
| TASK-0805 | Implement security regression suite | TASK-0307, TASK-0407, TASK-0503, TASK-0604 | PG-08B | tests/security/** | Passing evidence for VT-SEC-001; Passing evidence for VT-SEC-002; Passing evidence for VT-SEC-003 |
| TASK-0806 | Implement crash-point matrix suite | TASK-0207, TASK-0309, TASK-0504, TASK-0605 | PG-08B | scripts/crash_harness.py | Passing evidence for VT-DATA-011; Passing evidence for VT-DATA-020; Passing evidence for VT-HTTP-021 |
| TASK-0807 | Implement quality-attribute budget tests | TASK-0711 | PG-08B | scripts/benchmark.py | Passing evidence for VT-PERF-001; Passing evidence for VT-PERF-002; Passing evidence for VT-PERF-003 |
| TASK-0808 | Implement release security and provenance | TASK-0802, TASK-0804 | Serial | .github/workflows/release.yml, SECURITY.md, scripts/release_check.py | Passing evidence for VT-OPS-009; Passing evidence for VT-OPS-011; Passing evidence for VT-OPS-012 |
| TASK-0809 | Complete documentation and examples | TASK-0711, TASK-0801 | PG-08C | README.md, examples/** | Passing evidence for VT-COMPAT-002; Passing evidence for VT-COMPAT-005; Passing evidence for VT-COMPAT-006 |
| TASK-0810 | Run final convergence and release-readiness gate | TASK-0803, TASK-0805, TASK-0806, TASK-0807, TASK-0808, TASK-0809 | Serial | CHANGELOG.md | Passing evidence for VT-API-005; Passing evidence for VT-ASSERT-017; Passing evidence for VT-COMPAT-009 |

## Phase exit

Every task acceptance criterion passes, the baseline cross-artifact validator remains green, and the next integration checkpoint described in `specification/29-agentic-implementation-plan.md` is demonstrated.
