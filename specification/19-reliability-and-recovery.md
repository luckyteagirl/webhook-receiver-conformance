# Reliability and Recovery

## Reliability model

The tool guarantees durable accounting of planned work and explicit uncertainty. It cannot guarantee that an external receiver, database, queue, or downstream service is available or deterministic. Recovery never upgrades incomplete evidence into certainty.

## Crash-consistency matrix

| Crash/cancel point | Persisted state | Possible external effect | Resume behavior | Ambiguity |
| --- | --- | --- | --- | --- |
| Before owner/claim acquisition | `scheduled` | No network side effect | Claim normally | None |
| After claim, before pre-send commit | `claimed` | Executor contract forbids connection establishment | Expire/reclaim claim | None |
| After pre-send commit, before transport call | `pre_send_committed` | No bytes by construction if injected at the exact test point | Crash test may prove `not_sent`; production recovery remains conservative without durable phase proof | None at the controlled point; otherwise phase-dependent |
| During DNS/connect/TLS before application bytes | `connecting` | Transport may prove that no application bytes left | `not_sent` or `transport_failed` with decisive proof; otherwise `unknown_outcome` | Phase-dependent |
| After headers/body bytes may leave, before response | `sending` or `awaiting_response` | Receiver may process | Mark `unknown_outcome`; default stop/reconcile | Yes |
| After a bounded response is durable, before terminal classification | `response_observed` | Receiver processed/answered | Rebuild the deterministic terminal classification from durable response evidence | No |
| After terminal attempt commit, before retry schedule commit | Terminal attempt, no retry entry | Known outcome | Atomic transaction requirement prevents split; integrity error if detected | No if implementation conforms |
| After retry schedule commit | Terminal + schedule entry | Known outcome | Resume claims schedule once | No |
| During observer invocation | Observation `scheduled` or `running` | Delivery state unchanged | Append `timed_out`, `error`, or `cancelled`; retry only when capabilities permit | Observer evidence only |
| After observer response, before sample commit | No terminal sample | Receiver state may have changed | Re-query with the same logical request ID and a fresh sample ID | Not a network-send ambiguity |
| After sample commit, before assertion commit | Sample durable, assertion pending | Evidence known | Reevaluate idempotently | No |
| During report generation | Run truth durable; temporary projection | No receiver effect | Delete temp and regenerate | No |

## `unknown_outcome`

An attempt becomes `unknown_outcome` when request bytes may have left the harness but no trustworthy terminal transport result was committed. It is terminal and immutable for that physical attempt. It contributes an ambiguous delivery/scenario/run category until one of these explicit policies is applied:

1. `stop` (default): preserve ambiguity and do not resend.
2. `observe`: query declared observer evidence; reconcile only when the configured assertions uniquely establish an acceptable result.
3. `redeliver`: create a new linked physical attempt for the same logical event, acknowledging that this may create duplicate physical delivery and must rely on receiver idempotency.
4. `operator-decision`: record a typed decision, reason, operator identity fingerprint, and evidence references; disabled in noninteractive CI unless supplied as a signed policy file.

Reconciliation changes the scenario decision, not the historical attempt state.

## Observer-assisted reconciliation

A reconciliation rule declares the exact assertions that prove one of: safely processed, safely not processed, or still unknown. “Resource exists” alone is insufficient when the resource may predate the event; evidence must correlate the logical event ID or another manifest-fixed causation key. A contrary or incomplete sample preserves ambiguity.

## Resume algorithm

1. Verify bundle paths, manifest/blob hashes, database quick/foreign-key checks, versions, and owner status.
2. Preview every nonterminal entity and expired owner/claim.
3. Convert in-flight attempts conservatively using durable phase evidence.
4. Rebuild mutable projections/audit them against append records.
5. Resolve or block ambiguous deliveries per policy.
6. Reconstruct ready schedule entries with stable ordering.
7. Acquire a new owner epoch and continue.
8. Regenerate reports from the committed watermark.

## Retry semantics

A retry is a new physical attempt, never mutation of an earlier attempt. It preserves logical event and delivery identity, gets a new attempt ID, and follows a manifest-fixed conditional node. The scheduler owns retry policy; HTTPX retries are disabled. `Retry-After` or provider response data influences retries only if an explicit scenario policy supports and realizes that branch.

## Receiver restart

v0.1 supports controlled restart only through a named argv lifecycle profile and the reference receiver corpus. A profile declares stop/start/restart argv, working directory, environment allowlist, timeout, and readiness observer. Shell interpolation is prohibited. Restart evidence is persisted. Docker Compose and Kubernetes controllers are deferred; documented argv wrappers may invoke user-controlled tools.

## Partial-processing failures

A generic harness cannot inject a crash at an arbitrary receiver transaction line. P0 partial-processing scenarios run against reference receivers or a cooperating receiver fault hook whose capability is explicit. The report identifies this as receiver-cooperative injection, not a network property.

## Error classification

- **Invalid input:** no supported run should begin with the supplied contract.
- **Environment failure:** valid plan could not reach target/observer/dependency and no receiver invariant was comparably evaluated.
- **Receiver failure:** valid comparable evidence violates a receiver assertion.
- **Harness failure:** internal invariant, journal integrity, schema mismatch, or valid supported state cannot be handled.
- **Unsupported:** requested optional capability lacks an implementation.
- **Ambiguous:** effect cannot be established after a possible send.
- **Cancelled:** operator/CI stop without a stronger established category.

## Corruption and incomplete artifacts

Manifest/blob corruption stops execution. Database integrity failure copies the bundle for diagnosis and returns harness failure; automatic repair is prohibited. A missing derived report is regenerated. A truncated JSON Lines report is replaced from the journal. An orphan temporary report directory is safe to delete after verifying it is contained and not symlinked.

## Reliability tests

Crash tests run the process under a deterministic failpoint controller at every matrix row. Each test restarts a fresh process, verifies journal integrity, checks no planned work is silently skipped, and compares the recovered state/evidence with the expected model. Power-loss durability is limited to SQLite/filesystem guarantees under the documented local filesystem and sync settings.
