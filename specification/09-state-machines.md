# State Machines

The Mermaid sources under `diagrams/` are normative for allowed states and high-level transitions. The tables below own transaction and recovery semantics.

## Run states

| State | Entry | Exit | Illegal behavior | Recovery |
|---|---|---|---|---|
| `created` | Run row and immutable manifest digest committed | `validated` or `invalid` | Network activity | Revalidate safely |
| `validated` | All static and semantic checks pass | `running` | Manifest mutation | Start owner lease |
| `running` | Run ownership acquired | `paused`, `completed`, `cancelled`, `failed` | Second owner | Expired owner invokes recovery scan |
| `paused` | Explicit pause/interruption with state committed | `running`, `cancelled` | Scheduling new work | Resume against same manifest |
| `completed` | All scenarios terminal and reports projectable | none | New attempt under same run | Create a new run/replay |
| `cancelled` | Cancellation policy completes | none | Hidden pending work | Pending items remain classified/cancelled |
| `failed` | Harness integrity failure | none | Continue execution | Inspect/recover database, then new run |

## Scenario states

`planned → ready → running → passed | receiver_failed | environment_failed | ambiguous | unsupported | cancelled | harness_failed`. A scenario cannot be `passed` while any required assertion is pending, failed, errored, or skipped under an error-on-unsupported policy.

## Delivery states

`planned → ready → in_progress → succeeded | rejected | failed | ambiguous | cancelled`. Retry wait is persisted as a schedule entry, not a sleep-held worker. An ambiguous delivery can become `reconciled` at scenario level, but the physical attempt remains `unknown_outcome`.

## Attempt states and transaction boundaries

| From | Trigger | Guard | Durable transaction before side effect | Terminal / recovery |
|---|---|---|---|---|
| `scheduled` | Claim | Owner valid; dependencies ready | Lease/claim row committed | Expired claim can be reclaimed before send |
| `leased` | Begin send | Authorized pinned target | `sending` intent committed | Crash before bytes: recovery may prove no send and reclaim |
| `sending` | Response | Response parsed within limits | Terminal outcome appended | `acknowledged` or `rejected` |
| `sending` | Known connect/TLS failure before bytes | Transport phase proves no application bytes | Failure appended | Retry policy may schedule a new attempt |
| `sending` | Timeout/reset/termination after bytes may leave | Cannot prove non-delivery | None possible after process loss | `unknown_outcome`; default no automatic resend |
| `sending` | Cancellation | Phase-specific certainty | Best-known phase appended | `cancelled` only if no bytes; otherwise ambiguity |

## Observation states

`requested → running → ok | pending | unsupported | error | timeout`. Every poll is a new immutable sample. `pending` is valid only when the observer capability declares eventual evidence and a deadline remains.

## Assertion states

`pending → polling → pass | fail | error | skipped`. `skipped` is legal only when the assertion explicitly configures `on_unsupported: skip`; a P0 receiver-state assertion defaults to error.

## Illegal transitions

The journal rejects transitions not present in the transition registry, transitions whose expected prior state differs, terminal-to-nonterminal transitions, a second terminal attempt result, and evidence referencing another run. An illegal transition is a harness integrity error and stops the run.

## Crash boundary authority

`specification/19-reliability-and-recovery.md` contains the complete crash matrix. State diagrams show lifecycle shape; the crash matrix owns persisted-state interpretation.
