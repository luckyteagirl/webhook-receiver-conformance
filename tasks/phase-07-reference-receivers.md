# phase-07-reference-receivers

## Objective

Complete the phase as a demonstrable vertical increment without violating later public contracts.

## Entry criteria

All dependencies outside this phase are complete and their integration checkpoint passes.

## Tasks

| ID | Title | Dependencies | Parallel | Owned files | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| TASK-0701 | Implement correct reference receiver | TASK-0407, TASK-0508 | Serial | reference_receivers/correct/** | Passing evidence for VT-FR-003; Passing evidence for VT-OBS-013; Passing evidence for VT-PRIV-009 |
| TASK-0702 | No idempotency record receiver | TASK-0701 | PG-07A | reference_receivers/flawed/no-idempotency-record-receiver/** | Passing evidence for VT-TEST-020 |
| TASK-0703 | Check-then-insert race receiver | TASK-0701 | PG-07A | reference_receivers/flawed/check-then-insert-race-receiver/** | Passing evidence for VT-TEST-020 |
| TASK-0704 | Signature-after-parse receiver | TASK-0701 | PG-07A | reference_receivers/flawed/signature-after-parse-receiver/** | Passing evidence for VT-TEST-020 |
| TASK-0705 | Stale-signature-accepting receiver | TASK-0701 | PG-07A | reference_receivers/flawed/stale-signature-accepting-receiver/** | Passing evidence for VT-SIG-006 |
| TASK-0706 | Acknowledge-before-commit receiver | TASK-0701 | PG-07A | reference_receivers/flawed/acknowledge-before-commit-receiver/** | Passing evidence for VT-TEST-020 |
| TASK-0707 | Side-effect-before-deduplication receiver | TASK-0701 | PG-07A | reference_receivers/flawed/side-effect-before-deduplication-receiver/** | Passing evidence for VT-TEST-020 |
| TASK-0708 | Order-assuming receiver | TASK-0701 | PG-07A | reference_receivers/flawed/order-assuming-receiver/** | Passing evidence for VT-TEST-020 |
| TASK-0709 | Sensitive-logging receiver | TASK-0701 | PG-07A | reference_receivers/flawed/sensitive-logging-receiver/** | Passing evidence for VT-TEST-020 |
| TASK-0710 | Crash-after-effect-before-ack receiver | TASK-0701 | PG-07A | reference_receivers/flawed/crash-after-effect-before-ack-receiver/** | Passing evidence for VT-TEST-020 |
| TASK-0711 | Implement reference scenario corpus | TASK-0702, TASK-0703, TASK-0704, TASK-0705, TASK-0706, TASK-0707, TASK-0708, TASK-0709, TASK-0710, TASK-0605 | Serial | examples/scenarios/** | Passing evidence for VT-FR-001; Passing evidence for VT-FR-003; Passing evidence for VT-FR-004 |

## Phase exit

Every task acceptance criterion passes, the baseline cross-artifact validator remains green, and the next integration checkpoint described in `specification/29-agentic-implementation-plan.md` is demonstrated.
