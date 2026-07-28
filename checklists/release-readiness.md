# Release Readiness Checklist

## Gate policy

Every checked item requires a command transcript or generated record under
`validation/`; workflow configuration alone is not execution evidence. A failing or
unavailable check remains unchecked and is called out in the final release record.

Mutation testing is mandatory before a stable 1.0 release for the journal/state
transition, destination-policy and public-preflight, signature, and report-redaction
modules. The release floor is **90% killed-or-timeout mutants across that locked
scope**, with **no surviving mutant that can weaken a security, privacy, durability, or
ambiguity invariant**. Every survivor must receive a named review disposition
(`equivalent`, `additional-test-required`, or `accepted-low-impact`) with the mutated
location, reviewer, rationale, and linked test or follow-up. Unreviewed survivors fail
the gate. Version 0.1.0 may record this stable-1.0 gate as deferred, but may not mark it
as executed.

- [ ] No critical/high open audit finding.
- [ ] All P0 requirements, transitions, crash points, and high-risk threats verified.
- [ ] Linux/macOS/Windows and Python support matrix passes.
- [ ] Wheel, sdist, pipx, uvx, container, and Action smoke tests pass.
- [ ] Examples and machine artifacts validate.
- [ ] Secret-canary and report-injection corpus passes.
- [ ] Dependency/security/license scans pass.
- [ ] SBOM and provenance/attestations generated and verified.
- [ ] Changelog, compatibility, migration, support, and security policy updated.
- [ ] Final offline reference corpus passes exactly.
