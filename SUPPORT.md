# Support

## Supported software

Version 0.1 supports CPython 3.12 through 3.14. The current package status is pre-alpha.

Read `docs/compatibility-and-releases.md` for the complete compatibility policy.

## Get help

Use a GitHub issue for a usage question, repeatable defect, or documentation problem.

Use the applicable issue form. Search open and closed issues before you create a new issue.

Do not use a public issue for a suspected vulnerability. Use the private process in `SECURITY.md`.

## Include evidence

Include this information in a support request:

- The output from `webhook-conformance --json version`
- The operating system and CPython version
- The exact command without secret values
- The sanitized diagnostic and exit code
- A minimal loopback configuration when possible
- The expected result and the observed result

Remove secrets, authorization values, observer tokens, private fixture data, hostnames, and private user paths.

## Support limits

The project does not give a response-time promise. Maintainers can close requests that are outside the project scope.

The harness does not control an external receiver. It cannot prove an exactly-once network delivery result.
