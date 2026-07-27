# phase-06-reporting

## Objective

Complete the phase as a demonstrable vertical increment without violating later public contracts.

## Entry criteria

All dependencies outside this phase are complete and their integration checkpoint passes.

## Tasks

| ID | Title | Dependencies | Parallel | Owned files | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| TASK-0601 | Implement stable JSON and JSON Lines exports | TASK-0205, TASK-0508 | PG-06A | src/webhook_receiver_conformance/reporting/json_reports.py | Passing evidence for VT-DATA-007; Passing evidence for VT-FR-007; Passing evidence for VT-OBS-019 |
| TASK-0602 | Implement result summary and exit-code precedence | TASK-0508 | PG-06A | src/webhook_receiver_conformance/reporting/summary.py, src/webhook_receiver_conformance/cli/exit_codes.py | Passing evidence for VT-CLI-016; Passing evidence for VT-FR-006; Passing evidence for VT-REPORT-005 |
| TASK-0603 | Implement JUnit XML renderer | TASK-0602 | PG-06B | src/webhook_receiver_conformance/reporting/junit.py | Passing evidence for VT-REPORT-009; Passing evidence for VT-REPORT-010; Passing evidence for VT-REPORT-011 |
| TASK-0604 | Implement static HTML renderer | TASK-0601, TASK-0602 | PG-06B | src/webhook_receiver_conformance/reporting/html.py, src/webhook_receiver_conformance/reporting/templates/** | Passing evidence for VT-DX-008; Passing evidence for VT-MUT-019; Passing evidence for VT-REPORT-009 |
| TASK-0605 | Implement atomic report generation and regeneration | TASK-0205, TASK-0601, TASK-0603, TASK-0604 | Serial | src/webhook_receiver_conformance/reporting/writer.py | Passing evidence for VT-DATA-019; Passing evidence for VT-DATA-020; Passing evidence for VT-FR-011 |
| TASK-0606 | Implement inspect and report commands | TASK-0605 | Serial | src/webhook_receiver_conformance/cli/inspect.py, src/webhook_receiver_conformance/cli/report.py | Passing evidence for VT-CLI-007; Passing evidence for VT-CLI-008; Passing evidence for VT-DX-005 |

## Phase exit

Every task acceptance criterion passes, the baseline cross-artifact validator remains green, and the next integration checkpoint described in `specification/29-agentic-implementation-plan.md` is demonstrated.
