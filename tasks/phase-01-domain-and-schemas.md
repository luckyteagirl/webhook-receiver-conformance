# phase-01-domain-and-schemas

## Objective

Complete the phase as a demonstrable vertical increment without violating later public contracts.

## Entry criteria

All dependencies outside this phase are complete and their integration checkpoint passes.

## Tasks

| ID | Title | Dependencies | Parallel | Owned files | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| TASK-0101 | Implement identifiers and canonical hashing | TASK-0002 | PG-01A | src/webhook_receiver_conformance/domain/identifiers.py, src/webhook_receiver_conformance/domain/hashing.py | Passing evidence for VT-DATA-002; Passing evidence for VT-DATA-005; Passing evidence for VT-DATA-006 |
| TASK-0102 | Implement domain value objects | TASK-0002 | PG-01A | src/webhook_receiver_conformance/domain/models.py, src/webhook_receiver_conformance/domain/enums.py | Passing evidence for VT-API-001; Passing evidence for VT-FR-002 |
| TASK-0103 | Implement deterministic byte generator | TASK-0002 | PG-01A | src/webhook_receiver_conformance/determinism/generator.py | Passing evidence for VT-DATA-006; Passing evidence for VT-SCHED-008; Passing evidence for VT-SCHED-009 |
| TASK-0104 | Implement strict project configuration models | TASK-0102, TASK-0003 | PG-01B | src/webhook_receiver_conformance/config/models.py, src/webhook_receiver_conformance/config/schema.py | Passing evidence for VT-CFG-001; Passing evidence for VT-CFG-003; Passing evidence for VT-CFG-014 |
| TASK-0105 | Implement YAML loader and precedence | TASK-0104 | PG-01C | src/webhook_receiver_conformance/config/loader.py, src/webhook_receiver_conformance/config/diagnostics.py | Passing evidence for VT-CFG-001; Passing evidence for VT-CFG-002; Passing evidence for VT-CFG-004 |
| TASK-0106 | Implement secret references and fingerprints | TASK-0104 | PG-01C | src/webhook_receiver_conformance/secrets.py | Passing evidence for VT-CFG-007; Passing evidence for VT-CFG-008; Passing evidence for VT-CFG-009 |
| TASK-0107 | Implement fixture loader and blob snapshotter | TASK-0101, TASK-0104 | PG-01C | src/webhook_receiver_conformance/fixtures/loader.py, src/webhook_receiver_conformance/fixtures/blobs.py | Passing evidence for VT-DATA-003; Passing evidence for VT-HTTP-016; Passing evidence for VT-SEC-015 |
| TASK-0108 | Implement scenario grammar and semantic validation | TASK-0102, TASK-0104 | PG-01B | src/webhook_receiver_conformance/scenario/models.py, src/webhook_receiver_conformance/scenario/validate.py | Passing evidence for VT-FR-008; Passing evidence for VT-FR-010; Passing evidence for VT-MUT-018 |
| TASK-0109 | Implement realized run-bundle compiler | TASK-0101, TASK-0103, TASK-0105, TASK-0106, TASK-0107, TASK-0108 | Serial | src/webhook_receiver_conformance/manifest/compiler.py, src/webhook_receiver_conformance/manifest/models.py | Passing evidence for VT-CFG-013; Passing evidence for VT-CLI-003; Passing evidence for VT-COMPAT-008 |
| TASK-0110 | Implement run-bundle replay loader | TASK-0109 | Serial | src/webhook_receiver_conformance/manifest/loader.py | Passing evidence for VT-CLI-006; Passing evidence for VT-COMPAT-007; Passing evidence for VT-DATA-004 |

## Phase exit

Every task acceptance criterion passes, the baseline cross-artifact validator remains green, and the next integration checkpoint described in `specification/29-agentic-implementation-plan.md` is demonstrated.
