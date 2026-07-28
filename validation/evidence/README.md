# Verification Evidence

Each `VT-*.json` file is an objective record for the correspondingly named
verification test in `machine/traceability.json`. Records identify the requirement,
the exact local command, the observed result, and the repository artifacts that carry
the contract.

Generated test reports, crash-matrix results, performance measurements, package
provenance, and local invocation records live beside those requirement-level records.
No record in this directory implies that an online release, upload, or publication
occurred.

The current record set is bound to implementation commit
`58fc1342ded1e2a568d96aca756333f14f2a87f3`. It includes full-suite JUnit
evidence, the P0 crash matrix, quality-attribute measurements, dependency
security and license results, wheel/source/OCI digest records, and fresh
installed-artifact runs across CPython 3.12 through 3.14.
