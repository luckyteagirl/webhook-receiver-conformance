# GitHub release-readiness inventory

## Purpose

This inventory shows the work that the project must complete before a public GitHub release.

The inventory separates local work from work that needs a remote service or a maintainer decision.

## Status values

- `COMPLETE`: The item has local evidence.
- `IN PROGRESS`: Local work is active.
- `OPEN`: Work can start after the current local work.
- `BLOCKED`: The item needs external data, authority, or a remote service.

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
| GH-009 | Add an ASD-STE100 document check. | `COMPLETE` | The check passes in the locked environment. |
| GH-010 | Add a GitHub Action example. | `COMPLETE` | The example uses read-only permissions and no write permission. |
| GH-011 | Run a dedicated secret scan on Git history. | `COMPLETE` | Gitleaks reports no unresolved secret. |
| GH-012 | Refresh local release evidence. | `IN PROGRESS` | Final package runs and evidence updates are active. |

## Maintainer decisions

| ID | Item | Status | Required decision |
| --- | --- | --- | --- |
| GH-101 | Select the GitHub owner and repository name. | `COMPLETE` | The target is `luckyteagirl/webhook-receiver-conformance`. |
| GH-102 | Add package project URLs. | `COMPLETE` | Package metadata uses the target repository URLs. |
| GH-103 | Add `CODEOWNERS`. | `COMPLETE` | `@luckyteagirl` owns all repository paths. |
| GH-104 | Add a private conduct-report contact. | `COMPLETE` | The private Security report form routes reports to the owner. |
| GH-105 | Select the public history method. | `COMPLETE` | The repository uses a sanitized history tip and a local recovery bundle. |

## GitHub service work

| ID | Item | Status | Completion evidence |
| --- | --- | --- | --- |
| GH-201 | Create the remote repository. | `BLOCKED` | The local repository has the correct remote URL. |
| GH-202 | Enable private vulnerability reports. | `BLOCKED` | The repository Security page has the private report form. |
| GH-203 | Add a default-branch ruleset. | `BLOCKED` | Pull requests and required checks protect the default branch. |
| GH-204 | Run the hosted CI matrix. | `BLOCKED` | All required jobs pass on Linux, macOS, and Windows. |
| GH-205 | Run the release workflow without publication. | `BLOCKED` | The manual workflow run passes all release jobs. |
| GH-206 | Configure PyPI trusted publication. | `BLOCKED` | The `pypi` environment and OIDC publisher match the repository. |
| GH-207 | Verify GHCR publication settings. | `BLOCKED` | The release workflow can publish the protected container package. |
| GH-208 | Create the `v0.1.0` release. | `BLOCKED` | All earlier items are complete. |

## Release rules

Do not push the current history to a public repository while GH-004 is incomplete.

Do not create a public release while any required item is incomplete.

Use `validation/final-scorecard.md` as the evidence record for the final decision.

## Local evidence

Run these commands for each local release candidate:

1. Run `uv run python scripts/check_ste_docs.py`.
2. Run `uv run python scripts/validate_artifacts.py`.
3. Run the locked Ruff, Pyright, pytest, and build commands.
4. Run Gitleaks against all Git history.
5. Inspect each built distribution for `LICENSE`.

Gitleaks 8.30.1 found four false positives in fixed test data.

The `.gitleaksignore` file identifies each reviewed historical fingerprint. Inline comments identify the same fixed test data in current files.
