# phase-00-foundation

## Objective

Complete the phase as a demonstrable vertical increment without violating later public contracts.

## Entry criteria

All dependencies outside this phase are complete and their integration checkpoint passes.

## Tasks

| ID | Title | Dependencies | Parallel | Owned files | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| TASK-0001 | Create package and quality-tool foundation | None | Serial | pyproject.toml, uv.lock, src/webhook_receiver_conformance/**, .python-version | Passing evidence for VT-API-003; Passing evidence for VT-COMPAT-002; Passing evidence for VT-OPS-001 |
| TASK-0002 | Define error taxonomy and common primitives | TASK-0001 | PG-00A | src/webhook_receiver_conformance/errors.py, src/webhook_receiver_conformance/types.py, src/webhook_receiver_conformance/version.py | Passing evidence for VT-API-001; Passing evidence for VT-API-002; Passing evidence for VT-CLI-014 |
| TASK-0003 | Install schema and cross-reference validation harness | TASK-0001 | PG-00A | scripts/validate_artifacts.py | Passing evidence for VT-COMPAT-006; Passing evidence for VT-DATA-007; Passing evidence for VT-DX-006 |
| TASK-0004 | Create baseline CI workflow | TASK-0001 | PG-00A | .github/workflows/ci.yml, .github/dependabot.yml | Passing evidence for VT-COMPAT-001; Passing evidence for VT-COMPAT-003; Passing evidence for VT-OPS-002 |

## Phase exit

Every task acceptance criterion passes, the baseline cross-artifact validator remains green, and the next integration checkpoint described in `specification/29-agentic-implementation-plan.md` is demonstrated.
