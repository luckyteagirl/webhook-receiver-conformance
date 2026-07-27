# phase-05-observers-and-assertions

## Objective

Complete the phase as a demonstrable vertical increment without violating later public contracts.

## Entry criteria

All dependencies outside this phase are complete and their integration checkpoint passes.

## Tasks

| ID | Title | Dependencies | Parallel | Owned files | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| TASK-0501 | Implement observer protocol models and capability negotiation | TASK-0102, TASK-0003 | PG-05A | src/webhook_receiver_conformance/observers/protocol.py | Passing evidence for VT-API-004; Passing evidence for VT-ASSERT-016; Passing evidence for VT-OBS-001 |
| TASK-0502 | Implement command observer | TASK-0501 | PG-05B | src/webhook_receiver_conformance/observers/command.py | Passing evidence for VT-DX-007; Passing evidence for VT-OBS-001; Passing evidence for VT-OBS-002 |
| TASK-0503 | Implement HTTP probe observer | TASK-0501, TASK-0308 | PG-05B | src/webhook_receiver_conformance/observers/http_probe.py | Passing evidence for VT-DX-007; Passing evidence for VT-OBS-008; Passing evidence for VT-OBS-009 |
| TASK-0504 | Implement observation polling and journaling | TASK-0502, TASK-0503, TASK-0203 | Serial | src/webhook_receiver_conformance/observers/polling.py, src/webhook_receiver_conformance/runtime/observations.py | Passing evidence for VT-ASSERT-012; Passing evidence for VT-OBS-008; Passing evidence for VT-OBS-012 |
| TASK-0505 | Implement transport assertions | TASK-0309 | PG-05C | src/webhook_receiver_conformance/assertions/transport.py | Passing evidence for VT-ASSERT-001; Passing evidence for VT-ASSERT-002; Passing evidence for VT-ASSERT-003 |
| TASK-0506 | Implement receiver-state assertions | TASK-0501 | PG-05C | src/webhook_receiver_conformance/assertions/state.py | Passing evidence for VT-ASSERT-004; Passing evidence for VT-ASSERT-005; Passing evidence for VT-ASSERT-006 |
| TASK-0507 | Implement temporal and composite assertions | TASK-0504, TASK-0506 | PG-05D | src/webhook_receiver_conformance/assertions/temporal.py, src/webhook_receiver_conformance/assertions/composite.py | Passing evidence for VT-ASSERT-010; Passing evidence for VT-ASSERT-011; Passing evidence for VT-ASSERT-012 |
| TASK-0508 | Integrate assertion lifecycle and verdict classification | TASK-0505, TASK-0507, TASK-0203 | Serial | src/webhook_receiver_conformance/runtime/assertions.py, src/webhook_receiver_conformance/runtime/verdicts.py | Passing evidence for VT-ASSERT-013; Passing evidence for VT-ASSERT-014; Passing evidence for VT-ASSERT-015 |
| TASK-0509 | Implement observer-assisted ambiguity reconciliation | TASK-0207, TASK-0504, TASK-0508 | Serial | src/webhook_receiver_conformance/recovery/reconcile.py | Passing evidence for VT-OBS-016; Passing evidence for VT-REL-005 |

## Phase exit

Every task acceptance criterion passes, the baseline cross-artifact validator remains green, and the next integration checkpoint described in `specification/29-agentic-implementation-plan.md` is demonstrated.
