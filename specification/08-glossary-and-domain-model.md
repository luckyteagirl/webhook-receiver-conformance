# Glossary and Domain Model

## Terms

| Term | Definition |
| --- | --- |
| Run | One invocation bound to one immutable manifest and one durable journal. A resumed process continues the same run ID. |
| Scenario | A named set of logical events, dependencies, planned deliveries, lifecycle actions, observations, assertions, and terminal policy. |
| Logical event | The semantic provider event whose identity is stable across duplicates, retries, and replays intended to test idempotency. |
| Event type | A provider or user-defined semantic label such as `payment.succeeded`; it is not an identity. |
| Event dependency | A directed prerequisite relation between logical events; the graph must be acyclic. |
| Planned delivery | A manifest-fixed instruction to deliver one logical event at a logical time under one policy. A duplicate has a distinct delivery ID. |
| Physical attempt | One network transmission attempt for a planned delivery. Retries always receive new attempt IDs. |
| Retry | A policy-created later attempt for the same planned delivery after a retry-eligible attempt classification. |
| Replay | Execution of an already realized manifest or deliberate reuse of a logical event/payload; it is not synonymous with retry. |
| Duplicate | Two or more planned deliveries sharing one logical event ID. |
| Concurrent duplicate | Duplicate deliveries released through one barrier; exact CPU/network interleaving is external. |
| Observer sample | One immutable result from an observer invocation at a checkpoint. |
| Assertion evaluation | One typed comparison over transport and/or observation evidence. |
| Side effect | An externally observable application-state change caused by receiver processing. |
| Idempotency key | The application key used to make repeat processing converge; often the logical event ID, scoped by provider/tenant/receiver contract. |
| Deduplication scope | The namespace in which an idempotency key is unique, such as provider + account + endpoint. |
| Deduplication window | The period for which an application retains deduplication state; a finite window permits later reprocessing. |
| Acknowledgement | The receiver HTTP response. It proves only transport-level response behavior. |
| Environmental failure | Target unavailability, DNS/TLS/connectivity, observer process failure, or unavailable dependency outside a demonstrated receiver invariant. |
| Receiver defect | A valid scenario produces an assertion failure attributable to receiver behavior. |
| Harness defect | The tool violates its own contract, corrupts evidence, encounters an invariant failure, or cannot execute a valid supported plan. |
| Ambiguous outcome | Request bytes may have left the process but no trustworthy terminal transport outcome was durably recorded. |
| Terminal result | The highest-precedence run category used for exit status and reports after all allowed recovery/reconciliation. |

## Identity contract

| Identifier | Serialization | Uniqueness scope | Correlation / ordering |
| --- | --- | --- | --- |
| run_id | run_<ULID> | Workspace | One immutable manifest/journal relationship |
| scenario_id | scenario_<ULID> | Run | Manifest order key then ID |
| event_id | event_<ULID> | Scenario | Stable across intended duplicate/retry deliveries |
| delivery_id | delivery_<ULID> | Scenario | One plan entry; stable on replay |
| attempt_id | attempt_<ULID> | Delivery | New for every physical transmission |
| observation_id | observation_<ULID> | Scenario/checkpoint | One observer polling series |
| assertion_id | assertion_<ULID> | Scenario | One declared invariant |
| record_id | record_<ULID> | Run journal | One append-oriented evidence record |

Identifiers are lowercase type-prefixed ULIDs generated from manifest-fixed logical timestamps and context-derived deterministic entropy. The prefix prevents accidental interchange. A collision in the relevant scope is a harness error; IDs are never silently regenerated during replay.

## Core invariants

- One manifest ID identifies exactly one canonical manifest byte sequence.
- A run references one manifest; resume never changes it.
- An event belongs to one scenario and may have many planned deliveries.
- A delivery belongs to one event and may have one or more physical attempts.
- An attempt belongs to one delivery and has one terminal attempt classification at most.
- An `unknown_outcome` attempt remains unknown even if application evidence later reconciles the scenario.
- Observations are immutable samples. Polling creates new samples rather than overwriting evidence.
- Assertion evaluations cite immutable evidence IDs.
- A report is a projection; it cannot create or alter run truth.
- Database row IDs and artifact IDs use the same serialized identifiers.

## Deduplication semantics

The reference receiver defines its idempotency key as `(provider_profile, receiver_account, logical_event_id)` and retains it for the full test database lifetime. The harness does not prescribe a production retention window; it tests the configured application contract. “Processed once” means one committed observable business effect under the assertion’s declared scope, not one received HTTP request.

## Relationship model

```text
Run 1 ── 1 Manifest
Run 1 ── * Scenario
Scenario 1 ── * LogicalEvent
LogicalEvent 1 ── * PlannedDelivery
PlannedDelivery 1 ── * PhysicalAttempt
Scenario 1 ── * ObserverSample
Scenario 1 ── * AssertionEvaluation
AssertionEvaluation * ── * EvidenceRecord
```
