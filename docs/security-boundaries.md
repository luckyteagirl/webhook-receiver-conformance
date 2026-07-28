# Security boundaries

## Target policy

The default and recommended receiver scope is loopback. The five-minute and complete
examples name `127.0.0.1`, port 8000, and `target_profile: loopback`.

The transport policy:

- disables redirects and proxy-environment inheritance;
- validates every resolved IPv4 and IPv6 address;
- pins the authorized destination through connection establishment;
- keeps TLS verification enabled;
- blocks metadata, link-local, multicast, unspecified, and other disallowed ranges
  regardless of operator flags;
- applies explicit connect/write/read/pool/total timeouts and byte limits.

Private targets require a configured allowlist. Public targets are exceptional: the
configuration must select `public-authorized`, the URL must be HTTPS and allowlisted,
the runtime must repeat the exact `HOST:PORT` through
`--authorize-public-target`, and the test receiver must satisfy the configured challenge
contract. The challenge is evidence of operator control of a test receiver, not a way
to make disallowed IP ranges safe.

The repository examples deliberately do not exercise public-target execution. Never
point them at production or a third party.

These gates prevent configuration alone, ambient DNS/proxy state, or a redirect from
turning a local conformance run into SSRF or unauthorized traffic.

## Local filesystem boundary

Run directories and SQLite journals must be on a local filesystem. UNC paths and
identified network filesystems are unsupported; the journal and run-lock boundaries
emit diagnostics stating that restriction.

The data-integrity reason is concrete: the persistence contract depends on SQLite
locking, rollback-journal behavior, `synchronous=EXTRA`, explicit write transactions,
and filesystem durability semantics. NFS, SMB, synchronized folders, or unusual remote
mounts may not preserve those assumptions during concurrent access or crashes. Put
`.webhook-conformance` on a local disk, then copy sanitized finalized reports elsewhere
after the run if needed.

One process owns a run directory. A recovered attempt that was persisted as `sending`
without a trusted terminal result becomes `unknown_outcome`; storage recovery does not
invent a receiver response.

## Secrets and sensitive evidence

- Signer keys and HTTP observer tokens are references, not plaintext serialized values.
- Webhook signing and observer authentication use independent credentials.
- Redirects and proxy inheritance are disabled so credentials are not forwarded through
  ambient network configuration.
- Command observers and lifecycle commands use argv arrays without a shell and receive
  an allowlisted environment.
- Diagnostics, persistence, and reports redact authorization/signature headers and
  configured sensitive JSON pointers.
- Raw payload retention is opt-in. Ordinary JUnit and HTML do not embed raw payloads.
- Terminal controls and HTML contexts are escaped.

CPython cannot guarantee in-process memory zeroization. Core dumps and a hostile local
administrator are outside the v0.1 protection boundary.

## Resource boundaries

Configuration, request/response bodies, observer messages, subprocess output/runtime,
event/attempt/concurrency counts, disk artifacts, and report output are bounded. Those
limits are safety budgets for the harness on its reference runner. They are not receiver
throughput or capacity measurements.

This project is not a load-testing tool and makes no requests-per-second claim about a
receiver.

## ASVS and SSDF mapping

[`specification/18-security-privacy-threat-model.md`](../specification/18-security-privacy-threat-model.md)
maps requirements to OWASP ASVS 5.0.0 and NIST SSDF 1.1 only where control semantics
genuinely apply. Requirements without a verified semantic match remain explicitly
unmapped; the project does not force an identifier to create superficial coverage.
High-level mappings cover safe input/encoding, authentication/cryptography,
communications, files/resources, secure development preparation/protection/production,
and vulnerability response.
