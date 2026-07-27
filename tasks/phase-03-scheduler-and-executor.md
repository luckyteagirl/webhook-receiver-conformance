# phase-03-scheduler-and-executor

## Objective

Complete the phase as a demonstrable vertical increment without violating later public contracts.

## Entry criteria

All dependencies outside this phase are complete and their integration checkpoint passes.

## Tasks

| ID | Title | Dependencies | Parallel | Owned files | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| TASK-0301 | Implement clock domains and scaled time | TASK-0102 | PG-03A | src/webhook_receiver_conformance/scheduler/clocks.py | Passing evidence for VT-SCHED-001; Passing evidence for VT-SCHED-002; Passing evidence for VT-SCHED-003 |
| TASK-0302 | Implement persistent priority scheduler | TASK-0203, TASK-0301 | Serial | src/webhook_receiver_conformance/scheduler/queue.py, src/webhook_receiver_conformance/scheduler/engine.py | Passing evidence for VT-SCHED-014; Passing evidence for VT-SCHED-018; Passing evidence for VT-TEST-003 |
| TASK-0303 | Implement barriers and concurrency groups | TASK-0302 | PG-03B | src/webhook_receiver_conformance/scheduler/barriers.py | Passing evidence for VT-FR-009; Passing evidence for VT-PERF-004; Passing evidence for VT-PERF-005 |
| TASK-0304 | Implement retry and deterministic jitter policies | TASK-0103, TASK-0302 | PG-03B | src/webhook_receiver_conformance/scheduler/retries.py | Passing evidence for VT-SCHED-013; Passing evidence for VT-SCHED-016; Passing evidence for VT-SCHED-017 |
| TASK-0305 | Implement destination-policy parser | TASK-0104 | PG-03A | src/webhook_receiver_conformance/network/policy.py, src/webhook_receiver_conformance/network/addresses.py | Passing evidence for VT-HTTP-002; Passing evidence for VT-SEC-001; Passing evidence for VT-SEC-002 |
| TASK-0306 | Implement pinned destination dialer | TASK-0305 | Serial | src/webhook_receiver_conformance/network/dialer.py, src/webhook_receiver_conformance/network/transport.py | Passing evidence for VT-HTTP-022; Passing evidence for VT-HTTP-023; Passing evidence for VT-OBS-011 |
| TASK-0307 | Implement public-target preflight | TASK-0305, TASK-0306 | Serial | src/webhook_receiver_conformance/network/preflight.py | Passing evidence for VT-CLI-017; Passing evidence for VT-HTTP-024; Passing evidence for VT-SEC-003 |
| TASK-0308 | Implement bounded HTTP attempt executor | TASK-0306, TASK-0301 | Serial | src/webhook_receiver_conformance/http/executor.py, src/webhook_receiver_conformance/http/evidence.py | Passing evidence for VT-ASSERT-003; Passing evidence for VT-HTTP-001; Passing evidence for VT-HTTP-003 |
| TASK-0309 | Integrate attempt lifecycle with journal | TASK-0203, TASK-0304, TASK-0308 | Serial | src/webhook_receiver_conformance/runtime/attempts.py | Passing evidence for VT-HTTP-020; Passing evidence for VT-HTTP-021; Passing evidence for VT-PRIV-005 |
| TASK-0310 | Implement cancellation and interruption handling | TASK-0309 | Serial | src/webhook_receiver_conformance/runtime/cancellation.py | Passing evidence for VT-CLI-015; Passing evidence for VT-HTTP-026; Passing evidence for VT-PERF-008 |
| TASK-0311 | Assemble first run vertical slice | TASK-0110, TASK-0204, TASK-0205, TASK-0302, TASK-0309, TASK-0310 | Serial | src/webhook_receiver_conformance/runtime/runner.py, src/webhook_receiver_conformance/cli/run.py | Passing evidence for VT-CLI-004; Passing evidence for VT-DATA-001; Passing evidence for VT-FR-001 |

## Phase exit

Every task acceptance criterion passes, the baseline cross-artifact validator remains green, and the next integration checkpoint described in `specification/29-agentic-implementation-plan.md` is demonstrated.
