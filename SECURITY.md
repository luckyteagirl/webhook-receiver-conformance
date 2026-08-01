# Security policy

## Report a vulnerability

Use the private vulnerability-report form on the repository Security page.

Do not use a public issue, pull request, discussion, or proof-of-concept repository.

Include this information:

- The affected package and schema versions
- The operating system and CPython version
- A minimal reproduction
- The expected impact
- Sanitized evidence

Do not include a real signing secret, authorization value, observer token, or sensitive fixture body.

## Response process

The security maintainers use this process:

1. Acknowledge the private report.
2. Reproduce the problem.
3. Assign the severity.
4. Prepare a fix and regression tests.
5. Publish fixed artifacts and release evidence.
6. Coordinate public disclosure with the reporter.

Maintainers give status when the response stage changes. They can publish early protection instructions when active exploitation causes immediate risk.

## Supported versions

The project supports the latest patch in release line 0.1.x.

The project supports configuration schema 1, evidence schema line 1.0, and observer protocol line 1 with that package release.

The project supports a replaced pre-1.0 minor line for 90 days.

The project supports a replaced schema or protocol line for at least 90 days.

The project can give disclosure instructions for an unsupported version. The project does not promise a patch for that version.

## Release compatibility

Package versions use Semantic Versioning. Read `docs/compatibility-and-releases.md` for the public compatibility rules.

Each release changelog entry states compatibility, migration, security, and schema effects. Use `None` when a category has no effect.

## Dependency and release review

Dependency updates run the locked CPython 3.12 through 3.14 test matrix.

Security-sensitive dependency groups require focused review from the repository owner. `CODEOWNERS` identifies the owner.

Release CI rejects an unapproved high-severity or critical vulnerability.

An approved exception must have an owner, reason, and future expiration date. The exception must use the repository machine-readable format.

PyPI publication uses OIDC trusted publication. Container publication uses only the workflow GitHub token.

The project does not permit a long-lived PyPI or container-registry credential.
