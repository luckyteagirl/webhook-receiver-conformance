# Reference Receivers

## Reference domain

A minimal order/payment service receives `payment.succeeded` and `payment.refunded`. Tables: `webhook_inbox`, `orders`, `payment_effects`, and `outbox`. The logical event ID is scoped by provider profile and account. The observer exposes normalized counts/state keyed by event/order IDs, not raw customer fields.

## Correct transaction

```text
verify exact raw-body signature and timestamp
begin transaction
insert webhook_inbox scoped unique key
if conflict: verify compatible prior event and return idempotent success
validate dependency / stage event if prerequisite absent
apply order/payment state with legal transition guard
insert payment_effect and outbox row with unique event correlation
commit
return 204
```

Acknowledgement occurs only after durable commit. A post-commit response loss is safe because a retry hits the unique inbox key and returns success without repeating effects. Outbox dispatch is modeled as a durable row, not an external irreversible message in the reference P0 proof.

## Test-only hooks

Fault hooks are enabled only under an explicit test profile and token, bound to test addresses, and excluded from production configuration. Named hooks pause/crash at transaction boundaries and expose readiness barriers. They cannot execute arbitrary code or SQL.

## Corpus

| ID | Receiver | Intentional behavior | Expected evidence |
| --- | --- | --- | --- |
| REF-CORRECT-001 | Correct receiver | Atomic transaction inserts inbox/idempotency record, applies business state, appends outbox effect, then acknowledges; verifies raw signature/replay window first. | All supported scenarios pass. |
| FLAW-001 | No idempotency record | Processes every valid delivery. | Sequential duplicate and replay scenarios fail processing/resource count. |
| FLAW-002 | Check-then-insert race | Checks for event outside/without unique transaction then concurrently inserts. | Concurrent duplicate creates two effects. |
| FLAW-003 | Idempotency marked before effect completion | Commits processed marker before business effect; injected crash occurs between. | Retry is suppressed while effect is absent/partial. |
| FLAW-004 | Acknowledges before durable work | Returns success before queued/background work commits. | Acknowledgement-deadline passes but eventual/partial-effect assertion fails under restart. |
| FLAW-005 | Signature verification after body transformation | Parses and reserializes JSON before verification. | Whitespace/duplicate-key/raw-byte signature vectors expose wrong behavior. |
| FLAW-006 | Accepts invalid or stale signatures | Weak parsing, wrong-key fallback, or no replay-window enforcement. | Missing/malformed/wrong-key/stale cases process when count must be zero. |
| FLAW-007 | Side effect before deduplication | Commits business effect before processed-event unique row. | Crash/retry creates duplicate effect. |
| FLAW-008 | Assumes event order | Requires prerequisite row synchronously and drops/deforms dependent event. | Dependency-violating order fails eventual correct state. |
| FLAW-009 | Logs sensitive content | Writes signature and customer fixture fields to logs. | Secret-canary privacy test fails while functional controls otherwise pass. |
| FLAW-010 | Crash after effect before acknowledgement | Commits effect, crashes before response and without atomic idempotency correlation. | Timeout/ambiguity redelivery exposes duplicate or irreconcilable effect. |

## Isolation rules

- One primary defect per flawed receiver.
- Shared correct infrastructure is used unless that would mask the defect.
- Each flaw has a compile/runtime marker visible to tests but not relied on for verdicts.
- Unrelated scenario expectations are explicit and must pass.
- Functional and privacy defects are not combined.
- A flaw that creates unexpected extra failures is rejected and redesigned.

## Framework scope

FastAPI is used for the Python reference implementation because it provides a concise ASGI example; the core package does not import it. A TypeScript example is P1 documentation after v0.1 core convergence and is not required to prove Python implementation correctness.
