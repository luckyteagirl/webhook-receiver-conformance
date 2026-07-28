# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's **Security →
Advisories → Report a vulnerability** form for this repository. The repository
security maintainers are the contact and triage owners. Do not open a public issue,
pull request, discussion, or proof-of-concept repository before coordinated
disclosure.

Include the affected package and schema versions, operating system and Python
version, a minimal reproduction, expected impact, and any evidence that secrets,
receiver data, or target-policy controls were exposed. Do not include real signing
secrets, authorization values, observer tokens, or sensitive fixture bodies.

The response process has four stages:

1. **Receipt and triage:** maintainers acknowledge the private report, establish a
   secure contact channel, reproduce the issue, and assign severity.
2. **Containment and remediation:** maintainers identify affected release lines,
   prepare a fix and regression tests, and decide whether temporary operational
   guidance is needed.
3. **Release and notification:** maintainers publish fixed artifacts with SBOM and
   provenance, update the changelog and advisory, and credit the reporter if desired.
4. **Coordinated disclosure:** maintainers and the reporter agree on disclosure
   timing. If active exploitation requires earlier notice, maintainers may publish
   protective guidance before complete technical details.

Reporters should allow a reasonable remediation window and avoid accessing data or
systems beyond what is necessary to demonstrate the issue. Maintainers will provide
status at material stage changes and will not request silence after a fix is broadly
available.

## Supported versions

The current supported package release line is **0.1.x**. Only the latest patch in
that line receives security fixes. Configuration schema version **1**, run/evidence
schema line **1.0**, and observer wire protocol line **1** are supported when used
with that package release.

When a new package minor line is released, the preceding pre-1.0 minor line reaches
end of support 90 days later. A schema or protocol line reaches end of support on
the later of that date or 90 days after its documented replacement is released.
Unsupported versions may receive disclosure guidance but are not promised patches.

## Release compatibility policy

Package versions follow Semantic Versioning. Before 1.0, `0.MINOR.PATCH` has an
explicit meaning: `MINOR` may contain a breaking change and `PATCH` must remain
backward compatible within that minor line. At and after 1.0, normal SemVer major,
minor, and patch rules apply.

The following are breaking changes:

- **CLI:** removing or renaming a command, option, output field, documented exit
  code, or changing its meaning incompatibly.
- **Configuration:** rejecting a previously valid supported configuration or
  changing a field's meaning without a versioned migration path.
- **Run/evidence manifest:** removing or incompatibly changing a serialized field,
  identifier meaning, ordering promise, or replay interpretation.
- **Observer protocol:** changing framing, authentication, messages, lifecycle
  ordering, or failure classification incompatibly.
- **Python API:** removing or incompatibly changing an API explicitly documented as
  public. Internal adapter protocols are not public plugin APIs.

Every release changelog entry must state the compatibility, migration, security, and
schema effects, including an explicit “none” when a category is unaffected. Release
CI rejects a tag whose SemVer does not match project metadata or lacks that complete
entry.

## Dependency and release review

Dependency updates run the complete locked Python 3.12–3.14 test matrix. Dependabot
groups identify transport, parser/schema, crypto/signing, and template/report
dependencies as security-sensitive classes. Changes in those groups require focused
approval from a repository security maintainer; CODEOWNERS or branch protection
should enforce that approval when reviewer identities are configured.

Review must cover destination pinning, redirects/proxies, TLS and cancellation for
transport changes; strict parsing and resource bounds for parser/schema changes;
secret handling and signature compatibility for crypto changes; and terminal, HTML,
XML, and structured-data escaping for template/report changes. Sensitive updates
must not be bundled with routine development-tool updates.

Release CI rejects known HIGH or CRITICAL vulnerabilities unless the finding appears
in a machine-readable exception file with a nonempty owner, reason, and unexpired
ISO date. Exceptions use this closed contract:

```json
{
  "schema_version": 1,
  "exceptions": [
    {
      "vulnerability_id": "CVE-YYYY-NNNN",
      "owner": "@security-owner",
      "expires": "2026-08-31",
      "reason": "Bounded mitigation and upgrade plan"
    }
  ]
}
```

PyPI publication uses OIDC Trusted Publishing. Container publication uses only the
workflow-scoped GitHub token; long-lived PyPI and registry credentials are
prohibited. Publication depends on lint, formatting, typing, tests, schema
validation, package smoke tests, vulnerability scanning, SBOM digest validation,
and provenance checks.
