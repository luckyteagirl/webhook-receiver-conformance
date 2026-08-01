# GitHub Action

## Purpose

The composite GitHub Action runs the same locked CLI that the wheel runs.

The action stages sanitized reports. It does not upload an artifact or request a write permission.

## Runner requirements

Use a current GitHub-hosted Linux, macOS, or Windows runner. Install uv before you run the action.

The action uses PowerShell and the CPython versions that the project supports.

## Permissions

Give the workflow read-only repository permission:

```yaml
permissions:
  contents: read
```

Do not give the action a write permission. Add a separate upload step when you need a retained report.

## Inputs

| Input | Default | Purpose |
| --- | --- | --- |
| `command` | `run` | Select a supported CLI command. |
| `config` | `webhook-conformance.yaml` | Set the project-relative configuration path. |
| `manifest` | Empty | Set the manifest or immutable bundle path for replay. |
| `run-directory` | Empty | Set the existing run directory for resume, inspect, or report. |
| `artifact-directory` | `.webhook-conformance/action` | Set the project-relative action artifact directory. |
| `formats` | `json,junit,html` | Select the report formats. |
| `retention-days` | `7` | Give an advisory value to a later upload step. |
| `noninteractive` | `true` | Make the command fail closed without a prompt. |
| `authorize-public-target` | Empty | Give the exact authorized public target as `HOST:PORT`. |
| `include-raw-artifacts` | `false` | Permit sensitive raw artifacts after an explicit choice. |
| `version` | `0.1.0` | Set the expected harness version. |

The public-target input does not bypass target policy. The configuration and the runtime challenge must also authorize the target.

## Outputs

| Output | Purpose |
| --- | --- |
| `run-id` | Identifies the run. |
| `manifest-id` | Identifies the immutable manifest. |
| `result-category` | Gives the stable result category. |
| `exit-code` | Gives the stable process exit code. |
| `report-directory` | Gives the sanitized report directory. |

## Example

The tracked example uses the action from the same checkout. It starts the loopback reference receiver before the action runs.

See `examples/github-action-workflow.yml`.

After publication, use the exact repository tag instead of `uses: ./`.

## Artifact safety

The action excludes raw bundle blobs by default. It also excludes observer standard output and standard error.

Keep `include-raw-artifacts` set to `false` for normal CI use.

Use a separate `actions/upload-artifact` step for the sanitized `report-directory` output.

Do not upload a complete run directory unless the data owner approves every sensitive artifact.
