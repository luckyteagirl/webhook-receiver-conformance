# HTTP and Signatures

## Request contract

- v0.1 sends `POST` only.
- The body is the exact manifest-referenced byte blob after the ordered mutation/signing pipeline.
- Header names are compared case-insensitively; reports render a normalized lowercase name while preserving no secret value.
- The harness sets `Host`, `Content-Length`, `Content-Type` when declared, `User-Agent`, correlation headers, and signer headers. User configuration cannot set hop-by-hop/framing headers including `Connection`, `Transfer-Encoding`, `Content-Length`, `TE`, `Trailer`, `Upgrade`, or proxy authorization.
- Compression is not implicit. A compressed fixture is an exact raw byte fixture with an explicit `Content-Encoding`; v0.1 does not transparently compress/decompress payloads.
- Redirects are disabled and any 3xx is receiver evidence, not followed traffic.
- `trust_env=False`; proxy and CA environment variables do not alter the transport. Explicit custom CA support is a path option, not environment inheritance.
- TLS verification and hostname verification are on. Disabling TLS verification is not supported for public targets; loopback/private test profiles may use an explicit test CA, not `verify=False`.
- HTTP/1.1 is the required transport. HTTP/2 is deferred because provider delivery semantics do not require it and connection pinning/diagnostics are simpler under HTTP/1.1.

## Destination resolution and pinning

1. Parse URL; reject userinfo, fragments, unsupported schemes, invalid/implicit forbidden ports, and non-ASCII ambiguity after IDNA normalization.
2. Resolve all A and AAAA answers.
3. Reject the hostname if any candidate answer falls outside the configured profile; metadata/link-local/multicast/unspecified ranges remain unconditionally blocked.
4. Deterministically select an authorized address, record the complete answer set, connect to the selected address, and preserve original hostname for `Host` and TLS SNI/certificate verification.
5. Validate the connected peer address.
6. Re-resolve before each new connection rather than trusting an unbounded cache.

Public targets additionally require config profile, exact host/port allowlist, `--authorize-public-target <host>:<port>`, and a nonce challenge response from the configured test endpoint. The challenge sends no fixture or secret.

## Timeouts

| Timeout | Meaning | Classification |
|---|---|---|
| Connect | TCP/TLS connection cannot complete before real monotonic deadline | Known non-send only when no application bytes could leave |
| Pool | No connection slot before deadline | Environment failure; no send |
| Write | Body cannot be fully written before deadline | Ambiguous when any body bytes may have left |
| Read | No response bytes/progress before deadline after request write | Ambiguous with respect to receiver processing |
| Total | Outer monotonic budget around the attempt | Classified using the furthest known transport phase |

Defaults are explicit in materialized configuration. `None`/unbounded timeouts are rejected in CI mode.

## Response handling

- Accept status 100–599; malformed status/headers are protocol failures.
- Retain at most 64 KiB by default and 1 MiB hard cap; hash streamed bytes up to the configured drain limit.
- Close the stream once the drain limit is exceeded; record truncation and counts.
- Sanitize header values and response snippets before persistence.
- Status retry eligibility comes only from scenario policy; no universal “5xx retries” rule is assumed.

## Signature pipeline

```text
fixture bytes
→ structural JSON mutations (parse/serialize only when requested)
→ raw pre-sign mutations
→ exact body snapshot
→ signer canonical input over exact body and manifest timestamp/ID
→ signature headers
→ post-sign mutations
→ transmitted request snapshot
```

### Generic HMAC-SHA256

Configuration defines header name, optional prefix, message template tokens (`timestamp`, `event_id`, `body`), timestamp encoding, and output encoding (`hex` or base64). The default message is exact body bytes with no implicit newline or JSON transformation. The profile is versioned in the manifest.

### Stripe v1

The signed payload is ASCII decimal timestamp, one dot byte, then exact body bytes. Header values support one `t=` and one or more `v1=` entries for rotation tests. Valid, wrong-key, missing, malformed, stale, altered-body, and multiple-secret cases are supported. The reference verifier parses before comparing but verifies against raw bytes and uses constant-time digest comparison.

### Standard Webhooks HMAC

The signed content follows the current Standard Webhooks HMAC profile over webhook ID, timestamp, and exact body. Secret decoding, signature prefix/encoding, multiple signature values, timestamp tolerance, and key rotation follow the profile version recorded in the manifest.

### Asymmetric signatures

Ed25519 metadata is schema-reserved but implementation is deferred. Adding it requires an ADR covering key encoding, library choice, official vectors, multiple signatures, and dependency/supply-chain impact.

## Test key handling

- Secrets come from environment, permission-checked file, or generated ephemeral test key.
- Generated HMAC keys use a CSPRNG and are stored only in memory unless the user explicitly writes a protected test-secret file.
- Reports store profile, key ID, and a domain-separated SHA-256 fingerprint, never key bytes.
- Reference receivers use `hmac.compare_digest` or equivalent constant-time comparison after strict length/encoding validation.
