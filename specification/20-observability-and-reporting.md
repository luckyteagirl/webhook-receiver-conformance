# Observability and Reporting

## Evidence authority

The immutable manifest and SQLite journal are authoritative. JSON Lines, summary JSON, JUnit XML, HTML, and console output are projections. A renderer cannot infer missing evidence or change classifications.

## Artifact set

| Artifact | Content | Ordering | Sanitization |
|---|---|---|---|
| `run-manifest.json` | Exact planned identities, bytes/hashes, schedule, policies, versions | Canonical JSON | No plaintext secrets; target and fixture metadata minimized |
| `deliveries.jsonl` | Attempt transitions and bounded transport evidence | Journal sequence | Header values/body snippets redacted before persistence |
| `observations.jsonl` | Observer samples and evidence | Journal sequence, sample sequence | Sensitive evidence omitted/digested |
| `assertions.jsonl` | Expected/actual comparison and evidence refs | Scenario ordinal, assertion ordinal, evaluation sequence | Safe messages and redacted values |
| `result-summary.json` | Final category, counts, failure refs, artifact paths | Fixed field order/canonical semantic model | No raw content |
| `junit.xml` | CI scenario/assertion test cases | Scenario then assertion order | No raw payload/header/secret; bounded escaped text |
| `results.html` | Static navigable causal report | Same normalized ordering | Escaped, no active content |
| `receiver-state.json` | Optional sanitized snapshot/evidence bundle | Observer/sample order | Only explicitly retainable evidence |

## Failure causality

Every failure page/record includes:

```text
run_id
  scenario_id
    event_id
      delivery_id
        attempt_id(s) and transport phase/outcome
    observation_id / sample_id(s)
    assertion_id / evaluation_id
    exact evidence references
    classification and next safe action
```

A receiver failure cannot cite only a human string; it cites a typed assertion and immutable evidence. An environment failure names the failed phase. Ambiguity names the last durable phase and available reconciliation actions.

## Stable ordering

Records use journal sequence as primary append order. Summary views use manifest scenario/delivery/assertion ordinals and IDs as deterministic ties. Regeneration does not reorder based on wall timestamps or filesystem order.

## JUnit mapping

- One top-level `<testsuites>` per run.
- One `<testsuite>` per scenario.
- One `<testcase>` per required assertion; transport setup can produce a synthetic scenario-environment testcase only when no assertion is comparable.
- Assertion `fail` → `<failure type="receiver_failure">`.
- Observer/environment/harness error → `<error type="...">`.
- Optional unsupported assertion → `<skipped message="unsupported capability">`.
- Ambiguous required assertion → `<error type="ambiguous_outcome">`.
- Durations are measured real monotonic seconds and do not affect deterministic digest.
- Properties include run/manifest/scenario IDs and relative artifact paths.
- stdout/stderr elements contain only bounded sanitized summaries.
- CI job success remains the process exit code; JUnit does not override it.

## HTML structure

- Run summary and final category.
- Scenario matrix.
- Causal timeline with logical and measured real time separated.
- Event/delivery/attempt tree.
- Observation and assertion evidence.
- Ambiguity/recovery decisions.
- Environment/tool/schema versions.
- Redaction and truncation notices.
- Artifact hashes.

The report is a self-contained static directory. No remote fonts, scripts, analytics, or network calls.

## Logging

Internal logs are structured events with event code, severity, run/scenario/entity IDs, safe fields, and exception category. They are not the evidence journal. Debug logs may include stack traces from harness code but still redact external data and secrets.

## Exit-code mapping

The final summary stores all encountered categories and the winning exit category. Precedence is defined in the CLI specification. Reports distinguish “receiver assertion failed after successful transport” from “assertion not comparable because the target was unavailable.”

## Minimized reproductions

When reduction is supported, the output is a new immutable bundle containing parent manifest digest, ordered reduction steps, preserved failure assertion/evidence signature, and a proof rerun. A reduced bundle that no longer reproduces is not published.
