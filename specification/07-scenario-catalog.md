# Scenario Catalog

## Composition rules

1. A one-fault baseline MUST exist before a multi-fault scenario is accepted.
2. Structural JSON mutations occur before serialization; raw-byte mutations occur after serialization; signatures are created after pre-sign mutations; post-sign mutations occur last.
3. A combination is invalid when two operators target the same path/byte range without an explicit ordered override, when a mutation destroys data needed by a later operator, or when the expected defect cannot be attributed.
4. Concurrency groups fix membership, logical release, and deterministic order keys; operating-system scheduling is evidence rather than a reproducibility guarantee.
5. A timeout is an attempt observation, not proof that the receiver did not process the request.
6. Restart and partial-processing cases require an enabled lifecycle profile or the controlled reference receiver.

## Inventory

| ID | Name | Motivation | Requirements | Correct result |
| --- | --- | --- | --- | --- |
| SCN-001 | single-valid-delivery | Establish the one-fault baseline and expected correct processing. | FR-002, HTTP-001, SIG-001, ASSERT-001 | pass |
| SCN-002 | sequential-duplicate | Detect missing idempotency or incorrect deduplication scope. | STATE-004, ASSERT-004, REL-007 | pass |
| SCN-003 | concurrent-duplicate | Expose non-atomic check-then-act races. | SCHED-012, ASSERT-004, REL-007 | pass |
| SCN-004 | dependency-order-reversal | Detect receivers that assume provider order. | STATE-005, SCHED-007, ASSERT-005 | pass |
| SCN-005 | timeout-then-retry | Model timeout ambiguity followed by provider retry. | HTTP-006, REL-002, REL-007, ASSERT-004 | pass |
| SCN-006 | connection-failure-then-retry | Verify retry eligibility and environmental classification. | HTTP-007, REPORT-006 | pass with classified first failure |
| SCN-007 | missing-signature | Verify fail-closed authentication. | SIG-006, ASSERT-003 | pass |
| SCN-008 | malformed-signature | Verify malformed input is rejected and classified without server error. | SIG-006, REPORT-006 | pass |
| SCN-009 | wrong-key-signature | Verify key identity and active-key set. | SIG-004, SIG-006 | pass |
| SCN-010 | stale-timestamp | Verify replay-window enforcement. | SIG-003, SIG-006 | pass |
| SCN-011 | alter-after-signing | Verify signature covers exact transmitted bytes. | MUT-006, SIG-002 | pass |
| SCN-012 | malformed-body-and-content-type | Verify parser and error classification boundaries. | MUT-005, HTTP-002, REPORT-006 | pass |
| SCN-013 | receiver-restart-between-attempts | Verify retry and persisted receiver idempotency across process lifecycle. | STATE-008, REL-007 | pass |
| SCN-014 | harness-crash-after-send | Prove honest ambiguity and resumability. | REL-002, REL-003, REL-006 | pass harness behavior |
| SCN-015 | partial-processing-reference-hook | Expose side-effect and deduplication transaction ordering. | ASSERT-006, TEST-007 | pass |
| SCN-016 | redaction-canary | Prove sensitive fixture values do not enter default artifacts. | PRIV-001, PRIV-002, PRIV-003, SEC-011 | pass |

## SCN-001 — single-valid-delivery

| Field | Definition |
| --- | --- |
| Motivation | Establish the one-fault baseline and expected correct processing. |
| Requirements | FR-002, HTTP-001, SIG-001, ASSERT-001 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one |
| Timing | logical t=0 |
| Mutations | None |
| Signing | valid configured adapter |
| Observer checkpoints | before, after acknowledged delivery |
| Assertions | HTTP success class, processing count equals 1, resource state equals expected |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | All request bytes, headers, IDs, and logical time are manifest-fixed. |
| Combinability | Baseline only. |
| Minimization | Already minimal. |
| Correct receiver | pass |
| Flawed receiver mapping | {'all': 'control result unless defect affects baseline'} |
## SCN-002 — sequential-duplicate

| Field | Definition |
| --- | --- |
| Motivation | Detect missing idempotency or incorrect deduplication scope. |
| Requirements | STATE-004, ASSERT-004, REL-007 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | two deliveries with the same logical event ID and distinct delivery/attempt IDs |
| Timing | t=0 and t=1 logical second |
| Mutations | None |
| Signing | valid |
| Observer checkpoints | after each delivery |
| Assertions | processing count equals 1, resource count equals 1 |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Delivery order and IDs are manifest-fixed. |
| Combinability | May combine with delay only after baseline passes. |
| Minimization | Remove second attempt only if failure persists, which reclassifies defect. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-001': 'fail duplicate side effect'} |
## SCN-003 — concurrent-duplicate

| Field | Definition |
| --- | --- |
| Motivation | Expose non-atomic check-then-act races. |
| Requirements | SCHED-012, ASSERT-004, REL-007 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | two attempts released through one deterministic barrier |
| Timing | same logical release time; observed start order is evidence, not guaranteed |
| Mutations | None |
| Signing | valid |
| Observer checkpoints | before barrier, after both terminal |
| Assertions | processing count equals 1, one durable resource |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Barrier membership and release order key are fixed; OS scheduling remains external. |
| Combinability | No other fault in baseline. |
| Minimization | Keep two attempts and one barrier. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-002': 'fail race with duplicate resources'} |
## SCN-004 — dependency-order-reversal

| Field | Definition |
| --- | --- |
| Motivation | Detect receivers that assume provider order. |
| Requirements | STATE-005, SCHED-007, ASSERT-005 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 2 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | dependent event before prerequisite event |
| Timing | dependent t=0; prerequisite t=1s |
| Mutations | None |
| Signing | valid |
| Observer checkpoints | after each event, eventual terminal checkpoint |
| Assertions | no corrupt intermediate state, eventual ordered domain state |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Dependency graph and reversed delivery plan are fixed. |
| Combinability | May combine with duplicate only in an explicit advanced scenario. |
| Minimization | Two events are minimal. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-006': 'fail missing prerequisite or corrupt transition'} |
## SCN-005 — timeout-then-retry

| Field | Definition |
| --- | --- |
| Motivation | Model timeout ambiguity followed by provider retry. |
| Requirements | HTTP-006, REL-002, REL-007, ASSERT-004 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | first attempt uses short read timeout; second delivery reuses logical event ID |
| Timing | retry after scaled 2s logical delay |
| Mutations | None |
| Signing | valid |
| Observer checkpoints | after first timeout, after retry |
| Assertions | at-most-one business effect, eventual success |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Timeout budget and retry plan are fixed; receiver completion relative to timeout is observed. |
| Combinability | No restart in baseline. |
| Minimization | Two attempts are minimal. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-001': 'fail duplicate effect', 'FLAW-003': 'may expose early acknowledgment defect'} |
## SCN-006 — connection-failure-then-retry

| Field | Definition |
| --- | --- |
| Motivation | Verify retry eligibility and environmental classification. |
| Requirements | HTTP-007, REPORT-006 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | first target endpoint deliberately refuses connection; second uses receiver endpoint |
| Timing | fixed retry schedule |
| Mutations | None |
| Signing | valid |
| Observer checkpoints | after successful retry |
| Assertions | one business effect, first classified environment failure |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Endpoint plan and schedule fixed. |
| Combinability | Transport-only baseline. |
| Minimization | Two attempts. |
| Correct receiver | pass with classified first failure |
| Flawed receiver mapping | {} |
## SCN-007 — missing-signature

| Field | Definition |
| --- | --- |
| Motivation | Verify fail-closed authentication. |
| Requirements | SIG-006, ASSERT-003 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one |
| Timing | t=0 |
| Mutations | missing_signature |
| Signing | none |
| Observer checkpoints | after rejection |
| Assertions | HTTP rejection, processing count equals 0 |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Headers and body fixed. |
| Combinability | No other mutation. |
| Minimization | Single attempt. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-004': 'fail accepted unsigned event'} |
## SCN-008 — malformed-signature

| Field | Definition |
| --- | --- |
| Motivation | Verify malformed input is rejected and classified without server error. |
| Requirements | SIG-006, REPORT-006 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one |
| Timing | t=0 |
| Mutations | malformed_signature |
| Signing | malformed encoding |
| Observer checkpoints | after rejection |
| Assertions | HTTP 4xx, processing count 0, no harness internal error |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Malformed value fixed. |
| Combinability | No body mutation. |
| Minimization | Single attempt. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-004': 'fail acceptance or 5xx misclassification'} |
## SCN-009 — wrong-key-signature

| Field | Definition |
| --- | --- |
| Motivation | Verify key identity and active-key set. |
| Requirements | SIG-004, SIG-006 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one |
| Timing | t=0 |
| Mutations | wrong_key |
| Signing | valid format with unauthorized key |
| Observer checkpoints | after rejection |
| Assertions | HTTP rejection, processing count 0 |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Test-key fingerprint fixed; secret excluded. |
| Combinability | No body mutation. |
| Minimization | Single attempt. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-004': 'fail accepted wrong key'} |
## SCN-010 — stale-timestamp

| Field | Definition |
| --- | --- |
| Motivation | Verify replay-window enforcement. |
| Requirements | SIG-003, SIG-006 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one |
| Timing | signature timestamp is logical origin minus configured window plus one microsecond |
| Mutations | stale_timestamp |
| Signing | cryptographically valid but stale |
| Observer checkpoints | after rejection |
| Assertions | HTTP rejection, processing count 0 |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Logical timestamp fixed. |
| Combinability | No clock skew mutation in baseline. |
| Minimization | Boundary vector plus one inside-window control. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-005': 'fail accepts stale signature'} |
## SCN-011 — alter-after-signing

| Field | Definition |
| --- | --- |
| Motivation | Verify signature covers exact transmitted bytes. |
| Requirements | MUT-006, SIG-002 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one |
| Timing | t=0 |
| Mutations | replace_value at decoded stage, alter_after_signing at post-sign stage |
| Signing | signature over pre-alteration bytes |
| Observer checkpoints | after rejection |
| Assertions | HTTP rejection, processing count 0 |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Both byte sequences and digest recorded. |
| Combinability | This intentional two-stage scenario is justified because it tests signature coverage. |
| Minimization | One-byte post-sign change. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-004': 'fail if verification occurs after transformed parsing'} |
## SCN-012 — malformed-body-and-content-type

| Field | Definition |
| --- | --- |
| Motivation | Verify parser and error classification boundaries. |
| Requirements | MUT-005, HTTP-002, REPORT-006 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one attempt per isolated mutation vector |
| Timing | sequential isolated cases |
| Mutations | invalid_json OR truncate_bytes OR content_type_mismatch |
| Signing | valid over exact malformed bytes when applicable |
| Observer checkpoints | after each isolated attempt |
| Assertions | documented 4xx, no side effect, no unhandled exception |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Each vector has a separate manifest case. |
| Combinability | Mutations MUST NOT be combined in baseline. |
| Minimization | Byte-level shrinking supported. |
| Correct receiver | pass |
| Flawed receiver mapping | {} |
## SCN-013 — receiver-restart-between-attempts

| Field | Definition |
| --- | --- |
| Motivation | Verify retry and persisted receiver idempotency across process lifecycle. |
| Requirements | STATE-008, REL-007 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | valid delivery, named restart action, duplicate delivery |
| Timing | restart barrier between attempts |
| Mutations | None |
| Signing | valid |
| Observer checkpoints | before restart, after health recovery, after duplicate |
| Assertions | processing count equals 1, receiver readiness restored |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Action order fixed; restart duration observed. |
| Combinability | Reference/lifecycle-enabled environments only. |
| Minimization | One event, two deliveries, one restart. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-001': 'fail if deduplication is memory-only'} |
## SCN-014 — harness-crash-after-send

| Field | Definition |
| --- | --- |
| Motivation | Prove honest ambiguity and resumability. |
| Requirements | REL-002, REL-003, REL-006 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one attempt with injected harness crash after request write and before outcome commit |
| Timing | crash point controlled by test harness |
| Mutations | None |
| Signing | valid |
| Observer checkpoints | optional reconciliation sample after restart |
| Assertions | attempt remains unknown_outcome, no automatic resend, reconciliation cites evidence |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Crash injection point and resume policy fixed; receiver effect observed. |
| Combinability | System verification scenario, not ordinary user corpus. |
| Minimization | Single attempt. |
| Correct receiver | pass harness behavior |
| Flawed receiver mapping | {} |
## SCN-015 — partial-processing-reference-hook

| Field | Definition |
| --- | --- |
| Motivation | Expose side-effect and deduplication transaction ordering. |
| Requirements | ASSERT-006, TEST-007 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one attempt triggers a named test-only crash point, then one duplicate delivery |
| Timing | duplicate after receiver recovery |
| Mutations | None |
| Signing | valid |
| Observer checkpoints | database state after crash, after retry |
| Assertions | no forbidden partial state, eventual single completed effect |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Reference fault hook and plan fixed. |
| Combinability | Reference receiver or explicit cooperative receiver only. |
| Minimization | One event and one injected crash. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-003': 'fail partial or duplicate side effect'} |
## SCN-016 — redaction-canary

| Field | Definition |
| --- | --- |
| Motivation | Prove sensitive fixture values do not enter default artifacts. |
| Requirements | PRIV-001, PRIV-002, PRIV-003, SEC-011 |
| Preconditions | A validated immutable run bundle, an authorized target, and all declared capabilities. |
| Fixtures / logical events | 1 logical event(s); fixture bytes are manifest-pinned. |
| Delivery plan | one valid delivery containing canaries in body, headers, observer output, and error text |
| Timing | t=0 |
| Mutations | None |
| Signing | valid |
| Observer checkpoints | observer returns canary in configured sensitive field |
| Assertions | business baseline passes, artifact scan finds zero plaintext canaries |
| Failure classification | Assertion mismatch = receiver failure; transport setup = environment failure; invalid plan = input failure; uncertain sent request = ambiguous. |
| Determinism | Canary values derived per test and searched exactly. |
| Combinability | Security regression only. |
| Minimization | One value per channel. |
| Correct receiver | pass |
| Flawed receiver mapping | {'FLAW-007': 'fail unsafe logging'} |
