# phase-02-journal-and-state

## Objective

Complete the phase as a demonstrable vertical increment without violating later public contracts.

## Entry criteria

All dependencies outside this phase are complete and their integration checkpoint passes.

## Tasks

| ID | Title | Dependencies | Parallel | Owned files | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| TASK-0201 | Implement migration framework and initial SQLite schema | TASK-0102 | PG-02A | src/webhook_receiver_conformance/journal/migrations/**, src/webhook_receiver_conformance/journal/schema.py | Passing evidence for VT-DATA-001; Passing evidence for VT-DATA-009; Passing evidence for VT-DATA-017 |
| TASK-0202 | Implement single-writer journal service | TASK-0201 | PG-02B | src/webhook_receiver_conformance/journal/service.py, src/webhook_receiver_conformance/journal/connection.py | Passing evidence for VT-COMPAT-004; Passing evidence for VT-DATA-008; Passing evidence for VT-DATA-012 |
| TASK-0203 | Implement transition guards and projections | TASK-0202 | Serial | src/webhook_receiver_conformance/journal/transitions.py, src/webhook_receiver_conformance/journal/repositories.py | Passing evidence for VT-DATA-009; Passing evidence for VT-DATA-010; Passing evidence for VT-DATA-011 |
| TASK-0204 | Implement run-directory ownership lock | TASK-0201 | PG-02B | src/webhook_receiver_conformance/journal/run_lock.py | Passing evidence for VT-DATA-016; Passing evidence for VT-REL-012 |
| TASK-0205 | Implement journal integrity and artifact registry | TASK-0202 | PG-02C | src/webhook_receiver_conformance/journal/integrity.py, src/webhook_receiver_conformance/journal/artifacts.py | Passing evidence for VT-DATA-018; Passing evidence for VT-DATA-019; Passing evidence for VT-REL-013 |
| TASK-0206 | Implement recovery scanner and ambiguity model | TASK-0203 | Serial | src/webhook_receiver_conformance/recovery/scanner.py, src/webhook_receiver_conformance/recovery/models.py | Passing evidence for VT-REL-002; Passing evidence for VT-STATE-011 |
| TASK-0207 | Implement resume policy engine | TASK-0206 | Serial | src/webhook_receiver_conformance/recovery/policy.py | Passing evidence for VT-CLI-005; Passing evidence for VT-DATA-018; Passing evidence for VT-REL-004 |

## Phase exit

Every task acceptance criterion passes, the baseline cross-artifact validator remains green, and the next integration checkpoint described in `specification/29-agentic-implementation-plan.md` is demonstrated.
