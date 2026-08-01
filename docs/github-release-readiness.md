# GitHub release-readiness inventory

## Purpose

This inventory shows the work that the project requires for a public GitHub release.

The inventory separates repository readiness from package publication readiness.

## Status values

- `COMPLETE`: Objective evidence confirms the item.
- `IN PROGRESS`: Work on the item continues.
- `OPEN`: Work can start now.
- `BLOCKED`: The item needs external data, authority, or service configuration.

## Local repository work

| ID | Item | Status | Completion evidence |
| --- | --- | --- | --- |
| GH-001 | Add the Apache License 2.0 text. | `COMPLETE` | `LICENSE` exists at the repository root. |
| GH-002 | Put the license in each Python distribution. | `COMPLETE` | The wheel and source distribution contain `LICENSE`. |
| GH-003 | Remove private machine data from tracked evidence. | `COMPLETE` | A tracked-file scan finds no private hostname or user path. |
| GH-004 | Remove private machine data from Git history. | `COMPLETE` | A full history scan finds no private hostname or user path. |
| GH-005 | Add public package metadata. | `COMPLETE` | Author, keywords, license, and project URL metadata exist. |
| GH-006 | Add public project documents. | `COMPLETE` | Contribution, conduct, support, action, and style documents exist. |
| GH-007 | Add GitHub issue and pull-request templates. | `COMPLETE` | Tests parse and check each local template. |
| GH-008 | Add repository hygiene rules. | `COMPLETE` | Git and build tools ignore local output and use stable line endings. |
| GH-009 | Add an ASD-STE100 document check. | `COMPLETE` | The check covers all release-readiness evidence documents. |
| GH-010 | Add a GitHub Action example. | `COMPLETE` | The example uses read-only permissions and no write permission. |
| GH-011 | Run a dedicated secret scan on Git history. | `COMPLETE` | Gitleaks reports no unresolved secret. |
| GH-012 | Refresh local release evidence. | `COMPLETE` | The final scorecard records current tests, artifacts, and digests. |

## Maintainer decisions

| ID | Item | Status | Completion evidence |
| --- | --- | --- | --- |
| GH-101 | Select the GitHub owner and repository name. | `COMPLETE` | The target is `luckyteagirl/webhook-receiver-conformance`. |
| GH-102 | Add package project URLs. | `COMPLETE` | Package metadata uses the target repository URLs. |
| GH-103 | Add `CODEOWNERS`. | `COMPLETE` | `@luckyteagirl` owns all repository paths. |
| GH-104 | Add a private conduct-report contact. | `COMPLETE` | The private Security report form routes reports to the owner. |
| GH-105 | Select the public history method. | `COMPLETE` | The repository uses a sanitized history tip and a local recovery bundle. |

## GitHub service work

| ID | Item | Status | Completion evidence |
| --- | --- | --- | --- |
| GH-201 | Create the public remote repository. | `COMPLETE` | GitHub hosts the repository at the approved owner and name. |
| GH-202 | Enable repository security controls. | `COMPLETE` | Private reports, secret scanning, push protection, and Dependabot security updates operate. |
| GH-203 | Protect the default branch. | `COMPLETE` | Ruleset `20178218` requires pull requests, linear history, and all 19 hosted checks. |
| GH-204 | Run the hosted CI matrix. | `COMPLETE` | Linux, macOS, and Windows pass on CPython 3.12, 3.13, and 3.14. |
| GH-205 | Run the release workflow without publication. | `COMPLETE` | [Run 30696255381](https://github.com/luckyteagirl/webhook-receiver-conformance/actions/runs/30696255381) passes all non-publication jobs. |
| GH-206 | Configure PyPI trusted publication. | `BLOCKED` | A PyPI owner must create the pending OIDC publisher. |
| GH-207 | Verify the first GHCR publication. | `BLOCKED` | The first approved release must publish and verify the protected image. |
| GH-208 | Create the `v0.1.0` release. | `BLOCKED` | GH-206 must finish before the maintainer creates the release. |

## Release rules

Do not create a public release while a required publication item remains incomplete.

Use `validation/final-scorecard.md` as the evidence record for the final decision.

## Local evidence

Run these commands for each local release candidate:

1. Run `uv run python scripts/check_ste_docs.py`.
2. Run `uv run python scripts/validate_artifacts.py`.
3. Run the locked Ruff, Pyright, pytest, and build commands.
4. Run Gitleaks against all Git history.
5. Inspect each built distribution for `LICENSE`.

Gitleaks 8.30.1 reports no unresolved secrets in 137 commits or tracked files.
