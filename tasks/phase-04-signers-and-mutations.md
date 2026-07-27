# phase-04-signers-and-mutations

## Objective

Complete the phase as a demonstrable vertical increment without violating later public contracts.

## Entry criteria

All dependencies outside this phase are complete and their integration checkpoint passes.

## Tasks

| ID | Title | Dependencies | Parallel | Owned files | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| TASK-0401 | Implement signer contract and generic HMAC-SHA256 | TASK-0106, TASK-0107 | PG-04A | src/webhook_receiver_conformance/signatures/base.py, src/webhook_receiver_conformance/signatures/hmac_generic.py | Passing evidence for VT-API-004; Passing evidence for VT-FR-010; Passing evidence for VT-SIG-001 |
| TASK-0402 | Implement Stripe v1 signer | TASK-0401 | PG-04B | src/webhook_receiver_conformance/signatures/stripe.py | Passing evidence for VT-SIG-014; Passing evidence for VT-TEST-005 |
| TASK-0403 | Implement Standard Webhooks HMAC signer | TASK-0401 | PG-04B | src/webhook_receiver_conformance/signatures/standard_webhooks.py | Passing evidence for VT-SIG-013; Passing evidence for VT-SIG-015; Passing evidence for VT-TEST-005 |
| TASK-0404 | Implement mutation contract and pipeline | TASK-0107, TASK-0401 | PG-04A | src/webhook_receiver_conformance/mutations/base.py, src/webhook_receiver_conformance/mutations/pipeline.py | Passing evidence for VT-MUT-001; Passing evidence for VT-MUT-003; Passing evidence for VT-MUT-018 |
| TASK-0405 | Implement structural JSON mutations | TASK-0404 | PG-04C | src/webhook_receiver_conformance/mutations/json_ops.py | Passing evidence for VT-MUT-004; Passing evidence for VT-MUT-005; Passing evidence for VT-MUT-006 |
| TASK-0406 | Implement raw-body and signature mutations | TASK-0402, TASK-0403, TASK-0404 | PG-04C | src/webhook_receiver_conformance/mutations/raw_ops.py, src/webhook_receiver_conformance/mutations/signature_ops.py | Passing evidence for VT-MUT-012; Passing evidence for VT-MUT-013; Passing evidence for VT-MUT-014 |
| TASK-0407 | Integrate signers and mutations into manifest and executor | TASK-0405, TASK-0406, TASK-0309 | Serial | src/webhook_receiver_conformance/manifest/compiler.py, src/webhook_receiver_conformance/runtime/attempts.py | Passing evidence for VT-MUT-002 |

## Phase exit

Every task acceptance criterion passes, the baseline cross-artifact validator remains green, and the next integration checkpoint described in `specification/29-agentic-implementation-plan.md` is demonstrated.
