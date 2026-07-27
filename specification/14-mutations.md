# Mutation System

## Contract

Every mutation has a stable ID/version, applicable input kinds, strict parameter schema, deterministic realization context, pipeline stage, conflict rules, redaction behavior, and optional shrinker. The manifest records the operator ID, version, resolved parameters, input hash, output hash, and stage. Unknown operators are unsupported input, not ignored.

## Operators

| ID | Input | Parameters | Stage | Semantics | Shrinking |
| --- | --- | --- | --- | --- | --- |
| MUT-remove-json-pointer-v1 | JSON object/array | pointer | Structural pre-sign | Remove exact JSON Pointer; missing path is error unless `if_missing=ignore` | Drop operation or simplify pointer |
| MUT-replace-json-value-v1 | JSON | pointer,value | Structural pre-sign | Replace existing value | Shrink replacement recursively |
| MUT-replace-json-type-v1 | JSON | pointer,target_type | Structural pre-sign | Replace with deterministic representative of another type | Use null/false/0/empty string first |
| MUT-add-json-field-v1 | JSON object | pointer,name,value | Structural pre-sign | Add unknown field; collision is validation error | Shrink value |
| MUT-change-event-id-v1 | JSON with configured ID pointer | value or generated context | Structural pre-sign | Create replay/new-ID distinction | Fixed minimal ID |
| MUT-change-event-type-v1 | JSON with type pointer | value | Structural pre-sign | Change semantic event type | Shortest valid type |
| MUT-truncate-bytes-v1 | Bytes | length | Raw pre-sign | Keep first N bytes | Binary search N |
| MUT-invalid-json-v1 | JSON bytes | strategy | Raw pre-sign | Deterministic syntax defect | Smallest invalid token |
| MUT-invalid-utf8-v1 | Declared UTF-8 body | offset,octets | Raw pre-sign | Insert selected invalid sequence | One invalid byte where meaningful |
| MUT-duplicate-json-key-v1 | JSON object bytes | key,values | Raw pre-sign | Construct exact duplicate-name bytes without dict round-trip | One duplicated key |
| MUT-content-type-mismatch-v1 | Any | media_type | Header pre-sign | Set mismatched declared type | Fixed minimal mismatch |
| MUT-alter-after-signing-v1 | Bytes | offset,xor | Post-sign | Change body without recomputing signature | One-bit change |
| MUT-stale-signature-timestamp-v1 | Timestamped signer | age | Signer case | Use manifest timestamp outside replay window | Smallest failing age |
| MUT-wrong-signing-key-v1 | Signer | derived key context | Signer case | Sign exact bytes with a distinct key | Fixed derived key |
| MUT-missing-signature-v1 | Signer | header selector | Post-sign header | Remove required signature header | Already minimal |
| MUT-malformed-signature-v1 | Signer | case | Post-sign header | Invalid encoding, component, delimiter, or duplicate | Shortest malformed form |
| MUT-oversized-body-v1 | Bytes | target length,fill strategy | Raw pre-sign | Construct body within harness hard cap but above receiver contract | Boundary search |

## JSON fidelity

Structural operators parse JSON with duplicate-key rejection and explicit numeric constraints, then serialize using the harness deterministic JSON serializer. They intentionally change original formatting and therefore are unsuitable when whitespace is part of the test; raw-byte operators must be used instead. Duplicate-key and invalid-UTF-8 cases are constructed at the byte layer because ordinary JSON object models cannot preserve them reliably.

## Conflict validation

- Two structural writes to the same pointer conflict unless explicitly ordered and the second declares `accept_prior_mutation`.
- Truncation conflicts with any later pre-sign operator that needs bytes beyond the retained range.
- `invalid-json` conflicts with later structural JSON operators.
- `missing-signature` conflicts with `malformed-signature` for the same header.
- `wrong-signing-key` and `alter-after-signing` may combine only when a one-fault baseline for each exists and the scenario names the diagnostic purpose.
- An oversized body cannot exceed the harness hard request cap.
- A post-sign body mutation always records both signed-body and transmitted-body hashes.

## Redaction

Mutation parameters and diagnostic diffs pass through the same header/JSON-pointer/byte-range redaction policy as fixtures. A shrinker cannot reintroduce a value removed by redaction and never writes a raw secret to the reduced manifest.

## Minimization boundary

v0.1 provides deterministic manual reducers for sequence deletion and operator-specific parameter reduction as a library/test facility. Automatic general shrinking in the CLI is P1. Any minimized bundle is a new manifest that cites its parent manifest and reduction log.
