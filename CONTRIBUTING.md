# Contributing

## Project scope

This project implements a local-first webhook receiver conformance harness.

Read `AGENTS.md` before you change the repository. That file defines scope, authority, security rules, and completion rules.

Do not add a hosted control plane, public tunnel, request bin, gateway, or load-test mode.

## Select work

1. Select a task with complete dependencies.
2. Make sure that no contributor owns the same files.
3. Read each cited requirement, interface, decision, and test.
4. Change only the files in the task scope.
5. Stop when two authoritative sources conflict.
6. Report the conflict before you write code.

Schema files, migrations, CLI registries, error enums, and public protocol models are exclusive integration points.

## Prepare the environment

Install Git, uv, and a supported CPython version.

Run this command from the repository root:

```text
uv sync --locked --all-groups
```

Do not use an unlocked dependency as a substitute.

## Make a change

1. Preserve exact request-body bytes.
2. Preserve deterministic plans and explicit ambiguous outcomes.
3. Keep target-policy checks fail-closed.
4. Add type annotations at all boundaries.
5. Add tests for each changed behavior.
6. Update each affected public document and compatibility note.

Add nominal, malformed, boundary, timeout, cancellation, crash, and security tests when they apply.

Do not use retries to hide a test failure. A test that gives different results is a defect.

## Run the checks

Run each command in this order:

```text
uv sync --locked --all-groups
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -q
uv run python scripts/validate_artifacts.py
uv build
```

Do not omit a failed command from the pull-request report.

## Protect sensitive data

Never commit a signing secret, observer token, authorization value, private fixture, hostname, or private user path.

Use disposable values in tests. Do not use production data in an issue, test, report, or pull request.

Report a suspected vulnerability with the process in `SECURITY.md`. Do not open a public security issue.

## Submit a pull request

Include this information in the pull request:

- Changed files
- Requirements and tests
- Commands and results
- Security and compatibility effects
- Known risks
- Follow-up dependencies

Keep unrelated changes in a different pull request.
