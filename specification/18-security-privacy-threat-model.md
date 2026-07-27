# Security and Privacy Threat Model

## Scope and trust model

The v0.1 operator is trusted to choose local project code and explicitly authorize targets. Fixtures, configuration content, paths, URLs, DNS, receiver responses, observer output, subprocess stderr, report viewers, and package dependencies are untrusted. The tool is not a sandbox and is not safe for mutually hostile users sharing one process or artifact directory.

## Assets

- Receiver systems and protected network services.
- Webhook fixtures, credentials, signing keys, observer tokens, and generated test keys.
- Integrity of manifests, journals, evidence, reports, and release artifacts.
- CI tokens, workspace files, logs, and uploaded artifacts.
- Operator terminal/browser and downstream XML/JSON consumers.

## Trust boundaries

See `diagrams/trust-boundaries.mmd`. Security checks occur before crossing a boundary, and sanitized evidence is the only data allowed to cross from raw execution into ordinary reports.

## Threat register

| ID | Threat | Asset | Entry | Abuse case | Mitigations | Tests | Residual risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| THR-001 | SSRF to protected network | Local network and cloud credentials | receiver or HTTP observer URL | Attacker-controlled configuration targets metadata, loopback service, or private address. | SEC-001, SEC-002, SEC-003, SEC-004 | VT-SEC-001, VT-SEC-002, VT-SEC-003, VT-SEC-004 | Operator can explicitly authorize public targets but never metadata ranges. |
| THR-002 | DNS rebinding | Protected services | hostname resolution | Allowed hostname changes to a protected address between validation and connection. | SEC-002, SEC-003 | VT-SEC-002, VT-SEC-003 | Platform resolver limitations require validation at every connection. |
| THR-003 | Proxy environment exfiltration | Fixtures and signatures | HTTP client environment | HTTP(S)_PROXY silently routes traffic through an untrusted proxy. | HTTP-004, SEC-004 | VT-HTTP-004, VT-SEC-004 | Explicit future proxy support requires a new threat review. |
| THR-004 | TLS interception or downgrade | Payload confidentiality and receiver identity | HTTPS connection | Disabled verification or custom CA silently accepts an attacker. | HTTP-005 | VT-HTTP-005 | User-authorized CA files remain trusted by design. |
| THR-005 | Secret disclosure in configuration | Signing and observer secrets | project YAML and CLI diagnostics | Plaintext secret is committed or printed. | CFG-004, PRIV-006 | VT-CFG-004, VT-PRIV-006 | Environment and file secret stores remain operator responsibilities. |
| THR-006 | Sensitive payload persistence | Personal and confidential fixture data | logs and reports | Raw payload or response appears in default artifact. | PRIV-001, PRIV-002, PRIV-003, PRIV-004 | VT-PRIV-001, VT-PRIV-002, VT-PRIV-003, VT-PRIV-004 | Explicit raw retention carries a visible warning and access-control responsibility. |
| THR-007 | Terminal escape injection | Operator terminal integrity | fixture labels, headers, receiver errors | Control sequences alter display or hide diagnostics. | SEC-011 | VT-SEC-011 | Copying raw optional evidence remains user-controlled. |
| THR-008 | HTML report XSS | Report viewer browser | untrusted evidence rendered in HTML | Payload executes script or injects active markup. | REPORT-005, SEC-010 | VT-REPORT-005, VT-SEC-010 | Opening optional raw files outside the report is not covered. |
| THR-009 | Path traversal | Local filesystem | fixture, artifact, secret, and working-directory paths | Relative or absolute path escapes declared roots. | SEC-008 | VT-SEC-008 | Explicit external-path authorization is a privileged operator action. |
| THR-010 | Symlink race | Local files | path opened after validation | Path is swapped to a sensitive target between validation and use. | SEC-008 | VT-SEC-008 | Complete race elimination is platform-dependent; use no-follow/open-at patterns where available. |
| THR-011 | Command injection | Host process and credentials | observer or lifecycle profile | Scenario data reaches a shell or executable path. | SEC-006, SEC-007 | VT-SEC-006, VT-SEC-007 | Authorized executable itself is trusted code. |
| THR-012 | Inherited environment secret leakage | CI and developer credentials | subprocess environment | Observer reads unrelated tokens. | SEC-006 | VT-SEC-006 | Explicitly passed variables are intentionally disclosed. |
| THR-013 | Resource exhaustion | CPU, memory, disk, receiver availability | large fixtures, responses, scenario counts, concurrency | Configuration or receiver causes local denial of service. | PERF-004, PERF-005, SEC-010 | VT-PERF-004, VT-PERF-005, VT-SEC-010 | Limits can be raised by a trusted operator within hard maxima. |
| THR-014 | CI artifact exposure | Fixtures and state evidence | artifact upload | Raw evidence is retained in a broadly readable CI artifact. | PRIV-008 | VT-PRIV-008 | Repository access policy is outside the harness. |
| THR-015 | Malicious third-party plugin | Host and secrets | in-process extension loading | Plugin executes arbitrary code. | API-003 | VT-API-003 | v0.1 rejects unregistered third-party in-process plugins. |
| THR-016 | Dependency compromise | Release and developer environments | package resolver and build | Compromised dependency executes during install or runtime. | OPS-006, SEC-012, SEC-013 | VT-OPS-006, VT-SEC-012, VT-SEC-013 | No supply-chain control eliminates all upstream compromise. |
| THR-017 | Manifest tampering | Reproducibility and evidence integrity | run-manifest file | Plan is modified before replay. | REPORT-008, SCHED-003 | VT-REPORT-008, VT-SCHED-003 | Unsigned local artifacts do not prove external authorship. |
| THR-018 | Journal tampering or corruption | Recovery correctness | SQLite file | State is edited or corrupted and resume proceeds. | DATA-008, REL-009 | VT-DATA-008, VT-REL-009 | Local administrator can modify files; detection, not hostile-host protection, is provided. |
| THR-019 | Production-target accident | Production receiver data and availability | receiver URL and CLI run | Developer runs destructive fault corpus against production. | SEC-001, SEC-005 | VT-SEC-001, VT-SEC-005 | A trusted operator can deliberately override after explicit authorization. |
| THR-020 | Signature oracle or key exposure | Test signing key | signing adapter and error output | Secret appears in persisted metadata or arbitrary signing is exposed remotely. | CFG-004, SIG-008, SIG-009 | VT-CFG-004, VT-SIG-008, VT-SIG-009 | Local process memory contains resolved key material during signing. |

## Destination policy

### Profiles

- `loopback`: only `127.0.0.0/8` and `::1`, exact configured ports.
- `private-allowlist`: exact normalized hostnames and ports whose every resolved address is an allowed RFC1918/ULA address; loopback must be separately allowed.
- `public-authorized`: exact hostname/port, runtime authorization, challenge proof, HTTPS, and allowed public unicast addresses.

Unconditionally forbidden: IPv4/IPv6 unspecified, multicast, link-local, benchmark/documentation ranges when unsafe, cloud metadata aliases and addresses, IPv4-mapped bypass forms, zone-index ambiguity, and alternate textual encodings that evade canonical parsing. Redirects and proxy environment are disabled.

## Path and file policy

- Resolve project-relative paths under the configured root.
- Reject `..` escape after normalization.
- Use `lstat`/no-follow or platform-equivalent safe open where available.
- Reject a symlink as the final component for secrets, fixtures, database, manifests, and output files.
- Create run directories with restrictive permissions and atomic exclusive creation.
- Do not extract archives in v0.1. Future archive support requires traversal, symlink, device-file, decompression-bomb, and quota controls.
- Report generation writes to a fresh temporary sibling and atomically renames; it never follows an existing report symlink.

## Process execution

Command observer and lifecycle profiles accept an argv array only. `shell=False`; executable resolution is explicit or constrained to project/tool paths. Environment inheritance is allowlisted. stdin/stdout/stderr and runtime are bounded. On cancellation the whole process group or Windows Job Object is terminated. Lifecycle profiles are named, disabled by default, and cannot interpolate fixture values into argv.

## Secret lifecycle

1. Parse a reference, not a value.
2. Resolve as late as required.
3. Store in a mutable buffer where practical and avoid copies.
4. Use only for signing/authentication.
5. Persist key ID/fingerprint and algorithm, never plaintext.
6. Redact before logs, journal, exceptions, reports, JUnit, and CI annotations.
7. Generated keys are ephemeral unless explicitly written to a protected file.

The tool cannot guarantee memory zeroization under CPython; this residual limitation is documented. Core dumps and hostile local administrators are outside the v0.1 protection boundary.

## Redaction model

Rules are case-insensitive header names, JSON Pointers, exact byte-range labels from fixture metadata, and always-sensitive built-ins. Replacement is `[REDACTED:<rule-id>:<sha256-prefix>]` where the digest is domain-separated and does not permit cross-project correlation. Redaction runs on structured data before formatting. If a payload is malformed and structured redaction cannot safely apply, the default is to omit body content and retain only digest/length.

A secret-canary suite places known values in headers, JSON strings, nested arrays, invalid JSON, response bodies, errors, subprocess output, SQLite fields, report metadata, JUnit, and HTML. No canary may appear in default artifacts.

## Terminal and log injection

Control characters, ESC, bidi controls, CR/LF header injection, and invalid Unicode are escaped or rendered as bounded hexadecimal. JSON logging uses a standards-compliant encoder and one record per line. Human diagnostics never concatenate raw header names/values into terminal control sequences.

## HTML report safety

- Static HTML only; no JavaScript, inline event handlers, remote resources, forms, SVG foreign content, or untrusted URL links.
- Escape text and attribute contexts through the template engine autoescape mode.
- Content Security Policy: `default-src 'none'; style-src 'self' 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` in a meta tag, recognizing header-based CSP is stronger when served.
- Every fixture/response value is treated as text.
- Tests include script tags, malformed tags, attribute breaks, `</style>`, bidi controls, and XML/HTML entity payloads.

## Resource controls

Defaults/hard caps: 1 MiB/16 MiB request, 64 KiB/1 MiB response capture, 1 MiB response drain, 1,000 events, 5,000 attempts, 10/50 delivery concurrency, 64 observer queries, 1 MiB observer output, 64 MiB report field materialization, and configurable run disk quota. Exceeding a cap produces a classified error and bounded evidence rather than partial uncontrolled allocation.

## CI and artifact controls

- Workflows use least permissions; pull-request jobs from forks receive no secrets and cannot authorize public targets.
- Artifact upload happens after secret-canary/redaction validation.
- Public-target authorization is an explicit workflow input unavailable to untrusted PR jobs.
- Actions are pinned by immutable commit digest.
- Logs do not echo environment or command lines containing secret values.
- Retention is configured and documented.

## Supply chain

- Locked dependency graph with hashes/lockfile review.
- Trusted Publishing to PyPI.
- Wheel/sdist and OCI image SBOMs.
- GitHub artifact attestations / SLSA-style provenance where supported.
- Dependency vulnerability scanning, static analysis, secret scanning, and license inventory in release gates.
- Signed tags or release attestations; document verification commands.
- `SECURITY.md` defines supported versions, private reporting, acknowledgement, severity/embargo handling, patch/release process, and disclosure expectations.

## NIST SSDF and OWASP ASVS mapping

Mappings are selective rather than decorative:

| Practice / area | Specification controls |
| --- | --- |
| NIST SSDF PO — prepare | Documented security requirements, threat model, ownership, supported versions, release policy. |
| NIST SSDF PS — protect | Least-privilege CI, secret handling, protected artifacts, signed/attested releases. |
| NIST SSDF PW — produce well-secured software | Target controls, safe parsing/rendering/process execution, code review, automated negative tests. |
| NIST SSDF RV — respond | Vulnerability intake, triage, fix validation, supported-release communication. |
| OWASP ASVS input/encoding | Strict schemas, duplicate-key rejection, bounded parsers, terminal/HTML contextual encoding. |
| OWASP ASVS authentication/crypto | Secret references, HMAC profiles, replay windows, constant-time reference verification. |
| OWASP ASVS communications | TLS validation, no redirects/proxy inheritance, target authorization. |
| OWASP ASVS files/resources | Path containment, no-follow opens, quotas, safe report writes. |

Exact ASVS requirement IDs should be attached during implementation against the pinned 5.0.0 corpus; the specification avoids claiming an unverified one-to-one mapping.
