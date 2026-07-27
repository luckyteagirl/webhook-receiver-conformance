# State Machines

The Mermaid sources under `diagrams/` are normative for allowed high-level transitions. The tables below define the same edges and own transaction and recovery semantics. Lifecycle state names come exclusively from STATE-001 through STATE-006; serialized evidence outcome vocabularies are separate contracts and are not lifecycle aliases.

## Run states

| State | Legal exits | Terminal | Entry / recovery rule |
| --- | --- | --- | --- |
| `planned` | `running`, `cancelled`, `failed` | no | Manifest and initial run projection are durable; network activity is prohibited until `running`. |
| `running` | `paused`, `completed`, `cancelled`, `failed` | no | One owner epoch is active and eligible work may be claimed. |
| `paused` | `running`, `cancelled`, `failed` | no | No new work is claimed; resume first performs integrity and recovery checks. |
| `completed` | none | yes | Every required planned delivery is terminal under policy and none is ambiguous. |
| `cancelled` | none | yes | Cancellation evidence is durable and unfinished work is explicitly classified. |
| `failed` | none | yes | A harness/integrity failure stopped this run; inspect the preserved bundle. |

## Scenario states

| State | Legal exits | Terminal | Entry / recovery rule |
| --- | --- | --- | --- |
| `pending` | `eligible`, `skipped`, `error`, `cancelled` | no | Dependencies or preconditions are not yet satisfied. |
| `eligible` | `running`, `skipped`, `error`, `cancelled` | no | Preconditions and required capabilities are satisfied. |
| `running` | `passed`, `failed`, `error`, `skipped`, `ambiguous`, `cancelled` | no | At least one scenario action has been claimed. |
| `passed` | none | yes | Every required assertion passed. |
| `failed` | none | yes | Comparable evidence violated a receiver assertion. |
| `error` | none | yes | Required execution/evidence failed outside a comparable receiver assertion. |
| `skipped` | none | yes | Policy explicitly allows the scenario to be skipped. |
| `ambiguous` | none | yes | Possible receiver effect remains unresolved. |
| `cancelled` | none | yes | Cancellation prevented completion. |

A scenario cannot become `passed` while any required assertion is pending, running, failed, errored, unsupported under error policy, or cancelled.

## Planned delivery states

| State | Legal exits | Terminal | Entry / recovery rule |
| --- | --- | --- | --- |
| `pending` | `eligible`, `skipped`, `cancelled` | no | Dependencies or logical due time are not yet satisfied. |
| `eligible` | `active`, `skipped`, `cancelled` | no | The scheduler may claim the next conditional attempt. |
| `active` | `eligible`, `satisfied`, `exhausted`, `ambiguous`, `cancelled` | no | A physical attempt is active or its durable outcome is being reduced. |
| `satisfied` | none | yes | A qualifying terminal attempt or explicit assertion policy satisfied the delivery. |
| `exhausted` | none | yes | No eligible attempt template remains and policy did not satisfy the delivery. |
| `ambiguous` | none | yes | A possible send has no decisive terminal evidence. |
| `cancelled` | none | yes | Cancellation prevented completion. |
| `skipped` | none | yes | A manifest-fixed condition or explicit policy skipped the delivery. |

Retry wait is represented by a persistent schedule entry. It is not a delivery lifecycle state and never occupies a sleeping worker.

## Physical attempt states and transaction boundaries

| State | Legal exits | Terminal | Durable / recovery rule |
| --- | --- | --- | --- |
| `scheduled` | `claimed`, `cancelled` | no | The attempt exists durably but has no owner claim. |
| `claimed` | `pre_send_committed`, `not_sent`, `cancelled` | no | The claim is committed; an expired claim is recoverable before send intent. |
| `pre_send_committed` | `connecting`, `not_sent`, `cancelled` | no | Pre-send intent is durable before connection establishment may begin. |
| `connecting` | `sending`, `not_sent`, `transport_failed`, `unknown_outcome`, `cancelled` | no | DNS/connect/TLS evidence decides whether no send is provable; restart recovery is conservative. |
| `sending` | `awaiting_response`, `transport_failed`, `unknown_outcome` | no | Request transmission may have begun; cancellation/crash without decisive evidence becomes `unknown_outcome`. |
| `awaiting_response` | `response_observed`, `transport_failed`, `unknown_outcome` | no | Request bytes may have left; a lost response is ambiguous. |
| `response_observed` | `succeeded`, `rejected`, `transport_failed` | no | Bounded response evidence is durable before terminal classification. |
| `not_sent` | none | yes | Durable phase evidence proves no application request bytes left. |
| `succeeded` | none | yes | A qualifying receiver response was recorded. |
| `rejected` | none | yes | A receiver rejection response was recorded. |
| `transport_failed` | none | yes | A decisive transport/protocol failure was recorded without claiming receiver success. |
| `unknown_outcome` | none | yes | Request bytes may have left and no decisive terminal response is durable. |
| `cancelled` | none | yes | Cancellation occurred while no send remained possible. |

The serialized delivery evidence schema may use evidence-oriented outcome labels such as `acknowledged` or `timed_out`; those labels do not expand or rename the STATE-004 lifecycle set.

## Observation states

| State | Legal exits | Terminal | Entry / recovery rule |
| --- | --- | --- | --- |
| `scheduled` | `running`, `cancelled` | no | One immutable sample invocation is planned. |
| `running` | `ok`, `pending`, `unsupported`, `error`, `timed_out`, `cancelled` | no | The bounded observer invocation is active. |
| `ok` | none | yes | Complete typed evidence and a nonempty snapshot ID were returned. |
| `pending` | none | yes | This sample is complete but evidence is not ready; a later poll creates a new sample ID. |
| `unsupported` | none | yes | A required evidence capability is not declared. |
| `error` | none | yes | The observer returned or caused a classified error. |
| `timed_out` | none | yes | The physical monotonic observer deadline elapsed. |
| `cancelled` | none | yes | Cancellation terminated this sample. |

## Assertion states

| State | Legal exits | Terminal | Entry / recovery rule |
| --- | --- | --- | --- |
| `pending` | `running`, `cancelled` | no | Required evidence is not yet selected. |
| `running` | `passed`, `failed`, `error`, `unsupported`, `cancelled` | no | A typed evaluation is in progress. |
| `passed` | none | yes | Comparable evidence satisfied the invariant. |
| `failed` | none | yes | Comparable evidence violated the invariant. |
| `error` | none | yes | Evidence or evaluation failed without a valid comparison. |
| `unsupported` | none | yes | The required capability/evaluator is unavailable; higher policy decides error versus skip. |
| `cancelled` | none | yes | Cancellation prevented evaluation. |

## Illegal transitions

The journal rejects transitions absent from these tables, transitions whose expected prior state differs, terminal-to-nonterminal transitions, a second terminal attempt result, and evidence referencing another run. A rejected transition is a harness integrity error and stops the run.

## Crash boundary authority

`specification/19-reliability-and-recovery.md` contains the complete crash matrix. State diagrams show lifecycle shape; the crash matrix owns persisted-state interpretation. Executable transition tables, these tables, and the six Mermaid diagrams must remain byte-for-value equivalent at their state/edge boundary.
