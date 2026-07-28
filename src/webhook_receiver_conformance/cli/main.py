"""Complete local-first command tree for webhook receiver conformance."""
# ruff: noqa: B008, BLE001, EM101, FBT001, FBT003, PLR0913, PLR2004, TRY003

from __future__ import annotations

import html
import json
import os
import re
import shutil
import sys
import traceback
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn, cast
from urllib.parse import urlsplit

import anyio
import typer

from webhook_receiver_conformance.config.loader import (
    CliOverrides,
    ConfigLoadResult,
    load_project_config,
)
from webhook_receiver_conformance.config.models import (
    GenericHmacSha256SignerConfig,
    HttpObserverConfig,
    ProjectConfig,
    StripeV1SignerConfig,
    TargetProfile,
)
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.errors import (
    DEBUG_ENVIRONMENT_VARIABLE,
    Diagnostic,
    ExitCode,
    ResultCategory,
    exit_for_result,
    new_incident_id,
)
from webhook_receiver_conformance.http.evidence import (
    AttemptOutcome,
    HeaderOwner,
)
from webhook_receiver_conformance.http.executor import (
    HttpAttemptCommand,
    HttpAttemptExecutor,
    HttpHeader,
    HttpLimits,
    HttpTimeouts,
)
from webhook_receiver_conformance.manifest.compiler import (
    CompiledRunBundle,
    compile_run_bundle,
)
from webhook_receiver_conformance.manifest.loader import load_replay_bundle
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.policy import parse_destination_policy
from webhook_receiver_conformance.network.transport import AnyIOConnector, AnyIOResolver
from webhook_receiver_conformance.runtime.attempts import prepare_realized_attempt
from webhook_receiver_conformance.secrets import SecretHandle, SecretResolver
from webhook_receiver_conformance.signatures.hmac_generic import (
    GenericHmacSha256Settings,
    GenericHmacSha256Signer,
)
from webhook_receiver_conformance.signatures.standard_webhooks import (
    StandardWebhooksHmacSigner,
    StandardWebhooksSettings,
)
from webhook_receiver_conformance.signatures.stripe import (
    StripeV1Settings,
    StripeV1Signer,
)
from webhook_receiver_conformance.version import VERSION_METADATA

if TYPE_CHECKING:
    from collections.abc import Mapping

    from webhook_receiver_conformance.config.models import SecretRef
    from webhook_receiver_conformance.signatures.base import Signer

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_RUN_STATE = "run-state.json"
_DELIVERIES = "deliveries.jsonl"
_SUMMARY = "result-summary.json"
_HTML = "results.html"
_JUNIT = "junit.xml"
_ASSERTIONS = "assertions.jsonl"
_OBSERVATIONS = "observations.jsonl"
_REPORT_PATHS: Final = (
    "assertions.jsonl",
    "deliveries.jsonl",
    "junit.xml",
    "observations.jsonl",
    "result-summary.json",
    "results.html",
    "run-manifest.json",
)
_INIT_CONFIG = """schema_version: 1
project:
  name: local-webhook-receiver
  artifact_directory: .webhook-conformance
  seed: local-example-seed
receiver:
  url: http://127.0.0.1:8000/webhooks
  target_profile: loopback
  timeouts:
    connect: 5s
    write: 5s
    read: 5s
    pool: 5s
    total: 30s
fixtures:
- id: payment_succeeded
  path: fixtures/payment_succeeded.json
  media_type: application/json
signers:
  local_hmac:
    profile: generic-hmac-sha256
    secret: {env: WEBHOOK_TEST_SECRET}
    header_name: X-Webhook-Signature
observers: {}
lifecycles: {}
clock:
  mode: scaled
  scale: "0.01"
  minimum_physical_wait: 1ms
limits:
  max_events: 100
  max_attempts: 500
  max_request_bytes: 1048576
  max_response_capture_bytes: 65536
scenarios:
- id: single_valid_delivery
  events:
  - id: payment
    fixture: payment_succeeded
  steps:
  - deliver:
      event: payment
      count: 1
      signer: local_hmac
      retry: {max_attempts: 1, backoff: [], retry_on: []}
  assertions:
  - id: accepted
    type: http-status
    attempt: {event: payment, mode: all-terminal}
    expected: {codes: [200, 204]}
reports:
  formats: [json, jsonl, junit, html]
  redaction:
    headers: [authorization, x-webhook-signature]
    json_pointers: [/data/customer_email]
    retain_raw_payloads: false
"""
_INIT_FIXTURE = (
    b'{"id":"evt_local_example","type":"payment.succeeded",'
    b'"data":{"order_id":"order_local_example"}}\n'
)
_INIT_README = """# Local webhook conformance project

Set `WEBHOOK_TEST_SECRET`, start the receiver on loopback port 8000, then run:

    webhook-conformance validate --config webhook-conformance.yaml
    webhook-conformance plan --config webhook-conformance.yaml
    webhook-conformance run --config webhook-conformance.yaml
"""


@dataclass(slots=True)
class _Presentation:
    json_output: bool = False
    debug: bool = False


@dataclass(slots=True)
class _ResolvedSecrets:
    handles: dict[str, SecretHandle]
    fingerprints: dict[str, str]

    def close(self) -> None:
        for handle in self.handles.values():
            handle.close()
        self.handles.clear()


@dataclass(frozen=True, slots=True)
class _LoadedProject:
    config: ProjectConfig
    project_root: Path
    result: ConfigLoadResult


@dataclass(frozen=True, slots=True)
class _AttemptProjection:
    sequence: int
    scenario_id: str
    delivery_id: str
    event_id: str
    outcome: str
    status: int | None
    request_sha256: str
    response_sha256: str | None
    error_code: str | None

    def to_wire(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "scenario_id": self.scenario_id,
            "delivery_id": self.delivery_id,
            "event_id": self.event_id,
            "outcome": self.outcome,
            "status": self.status,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "error_code": self.error_code,
        }


app = typer.Typer(
    name="webhook-conformance",
    help="Compile and run local webhook receiver conformance scenarios.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


@app.callback()
def root_callback(
    context: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit one JSON result document on stdout.",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Include a traceback for unexpected internal failures.",
    ),
    color: str | None = typer.Option(
        None,
        "--color",
        help="Presentation policy: auto, always, or never.",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Fail closed instead of prompting.",
    ),
) -> None:
    del non_interactive
    if color not in {None, "auto", "always", "never"}:
        raise typer.BadParameter("color must be auto, always, or never")
    context.obj = _Presentation(json_output=json_output, debug=debug)


@app.command("version", help="Print package and serialized-contract versions.")
def version_command(
    context: typer.Context,
    json_output: bool = typer.Option(False, "--json", help="Emit version JSON."),
) -> None:
    document = VERSION_METADATA.as_dict()
    if json_output or _presentation(context).json_output:
        _stdout_json(cast("dict[str, object]", document))
        return
    typer.echo(
        "\n".join(
            (
                f"webhook-conformance {document['package']}",
                f"configuration schema {document['configuration_schema']}",
                f"manifest schema {document['manifest_schema']}",
                f"observer protocol {document['observer_protocol']}",
                f"report schema {document['report_schema']}",
                f"generator {document['generator_algorithm']}",
                f"sqlite user_version {document['sqlite_user_version']}",
            )
        )
    )


@app.command("init", help="Create a minimal local project without overwriting by default.")
def init_command(
    context: typer.Context,
    path: Path = typer.Argument(Path(), help="Project directory to initialize."),
    force: bool = typer.Option(False, "--force", help="Overwrite owned example files."),
    preview: bool = typer.Option(False, "--preview", help="Print the file plan only."),
) -> None:
    root = path.resolve(strict=False)
    files = {
        root / "webhook-conformance.yaml": _INIT_CONFIG.encode(),
        root / "fixtures" / "payment_succeeded.json": _INIT_FIXTURE,
        root / "README.webhook-conformance.md": _INIT_README.encode(),
        root / ".gitignore": b".webhook-conformance/\n",
    }
    if preview:
        _emit_result(
            context,
            {"command": "init", "destination": str(root), "files": sorted(str(p) for p in files)},
            f"Would initialize {len(files)} files in {_safe_text(str(root))}",
        )
        return
    conflicts = tuple(path for path in files if path.exists() and not force)
    if conflicts:
        _fail(
            ResultCategory.INVALID_INPUT,
            "CLI_INIT_CONFLICT",
            "Initialization would overwrite an existing file.",
            details={"paths": [_safe_text(str(path)) for path in conflicts]},
        )
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for target, content in files.items():
        _safe_init_write(root, target, content)
    _emit_result(
        context,
        {"command": "init", "destination": str(root), "created": len(files)},
        f"Initialized local project in {_safe_text(str(root))}",
    )


@app.command("validate", help="Validate and materialize configuration without network access.")
def validate_command(
    context: typer.Context,
    config: Path = typer.Option(
        Path("webhook-conformance.yaml"),
        "--config",
        "-c",
        help="Project configuration file.",
    ),
    project_root: Path | None = typer.Option(None, "--project-root"),
    output: Path | None = typer.Option(None, "--output"),
    print_materialized: bool = typer.Option(False, "--print-materialized"),
) -> None:
    loaded = _load_config(config, project_root=project_root, output=output)
    if loaded.config is None:
        _diagnostic_failure(loaded)
    validated = loaded.config
    wire = validated.to_wire()
    if print_materialized or _presentation(context).json_output:
        _stdout_json(
            {
                "command": "validate",
                "valid": True,
                "source": str(loaded.source_path),
                "project_root": str(loaded.project_root),
                "configuration": wire if print_materialized else None,
            }
        )
        return
    typer.echo(f"Configuration valid: {_safe_text(str(loaded.source_path))}")


@app.command("plan", help="Compile an immutable run bundle without sending traffic.")
def plan_command(
    context: typer.Context,
    config: Path = typer.Option(
        Path("webhook-conformance.yaml"),
        "--config",
        "-c",
    ),
    out: Path = typer.Option(Path(".webhook-conformance/plan"), "--out"),
    project_root: Path | None = typer.Option(None, "--project-root"),
) -> None:
    loaded = _require_loaded(_load_config(config, project_root=project_root))
    secrets: _ResolvedSecrets | None = None
    try:
        secrets = _resolve_secrets(loaded.config, loaded.project_root)
        bundle = compile_run_bundle(
            loaded.config,
            project_root=loaded.project_root,
            bundle_directory=out.resolve(strict=False),
            secret_fingerprints=secrets.fingerprints,
        )
    except Exception as error:
        _internal_or_input_failure(context, error, "CLI_PLAN_FAILED")
    finally:
        if secrets is not None:
            secrets.close()
    _emit_result(
        context,
        {
            "command": "plan",
            "destination": str(out.resolve(strict=False)),
            "manifest_id": bundle.manifest.manifest_id,
            "scenarios": len(bundle.manifest.scenarios),
        },
        (
            f"Planned {len(bundle.manifest.scenarios)} scenario(s)\n"
            f"Destination: {_safe_text(str(out.resolve(strict=False)))}\n"
            f"Manifest: {bundle.manifest.manifest_id}"
        ),
    )


@app.command("run", help="Plan if needed, execute deliveries, and write local reports.")
def run_command(
    context: typer.Context,
    config: Path = typer.Option(
        Path("webhook-conformance.yaml"),
        "--config",
        "-c",
    ),
    manifest: Path | None = typer.Option(None, "--manifest"),
    output: Path | None = typer.Option(None, "--output"),
    authorize_public_target: str | None = typer.Option(
        None,
        "--authorize-public-target",
        help="Exact HOST:PORT consent for a configured public target.",
    ),
) -> None:
    if manifest is not None:
        _fail(
            ResultCategory.UNSUPPORTED,
            "CLI_RUN_MANIFEST_SECRET_CONTEXT_REQUIRED",
            "Use replay for an existing immutable bundle.",
        )
    loaded = _require_loaded(_load_config(config, output=output))
    _require_public_consent(loaded.config, authorize_public_target)
    project_root = loaded.project_root
    artifact_root = _artifact_root(loaded.config, project_root, output)
    run_id = str(uuid.uuid4())
    run_directory = artifact_root / f"run-{run_id}"
    secrets: _ResolvedSecrets | None = None
    try:
        secrets = _resolve_secrets(loaded.config, project_root)
        bundle = compile_run_bundle(
            loaded.config,
            project_root=project_root,
            bundle_directory=run_directory,
            secret_fingerprints=secrets.fingerprints,
        )
        projections = anyio.run(
            _execute_bundle,
            loaded.config,
            bundle,
            run_directory,
            secrets.handles,
        )
        verdict = _verdict(projections)
        _write_run_artifacts(
            run_directory,
            run_id=run_id,
            bundle=bundle,
            projections=projections,
            verdict=verdict,
            destination=loaded.config.receiver.url,
        )
    except KeyboardInterrupt:
        _write_cancelled_state(run_directory, run_id)
        raise typer.Exit(int(ExitCode.CANCELLED)) from None
    except Exception as error:
        _internal_or_input_failure(context, error, "CLI_RUN_FAILED")
    finally:
        if secrets is not None:
            secrets.close()
    _emit_result(
        context,
        {
            "command": "run",
            "run_id": run_id,
            "manifest_id": bundle.manifest.manifest_id,
            "destination": loaded.config.receiver.url,
            "run_directory": str(run_directory),
            "verdict": verdict.value,
            "exit_code": int(exit_for_result(verdict)[1]),
        },
        (
            f"Run {run_id}: {verdict.value}\n"
            f"Destination: {_safe_text(loaded.config.receiver.url)}\n"
            f"Run directory: {_safe_text(str(run_directory))}"
        ),
    )
    if verdict is not ResultCategory.PASS:
        raise typer.Exit(int(exit_for_result(verdict)[1]))


@app.command("resume", help="Inspect a local run and require an explicit ambiguity policy.")
def resume_command(
    context: typer.Context,
    run_directory: Path = typer.Argument(..., exists=True, file_okay=False),
    on_ambiguous: str | None = typer.Option(
        None,
        "--on-ambiguous",
        help=(
            "Explicit policy: stop, observe, redeliver, assume-processed, or assume-not-processed."
        ),
    ),
) -> None:
    state = _read_run_state(run_directory)
    if state.get("verdict") == ResultCategory.AMBIGUOUS.value and on_ambiguous is None:
        _fail(
            ResultCategory.AMBIGUOUS,
            "CLI_RESUME_AMBIGUITY_POLICY_REQUIRED",
            "The run contains an ambiguous send outcome; no receiver contact was attempted.",
        )
    if on_ambiguous not in {
        None,
        "stop",
        "observe",
        "redeliver",
        "assume-processed",
        "assume-not-processed",
    }:
        _fail(
            ResultCategory.INVALID_INPUT,
            "CLI_RESUME_POLICY_INVALID",
            "The ambiguity policy is not supported.",
        )
    verdict = ResultCategory(cast("str", state.get("verdict", "harness_error")))
    _emit_result(
        context,
        {
            "command": "resume",
            "run_id": state.get("run_id"),
            "destination": state.get("destination"),
            "run_directory": str(run_directory.resolve()),
            "verdict": verdict.value,
        },
        (
            f"Run {state.get('run_id')}: {verdict.value}\n"
            f"Destination: {_safe_text(str(state.get('destination', 'unknown')))}\n"
            f"Run directory: {_safe_text(str(run_directory.resolve()))}"
        ),
    )
    if verdict is not ResultCategory.PASS:
        raise typer.Exit(int(exit_for_result(verdict)[1]))


@app.command("replay", help="Verify an immutable bundle before creating a new execution.")
def replay_command(
    context: typer.Context,
    manifest: Path = typer.Argument(..., exists=True),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    bundle_directory = manifest if manifest.is_dir() else manifest.parent
    try:
        loaded = load_replay_bundle(bundle_directory.resolve())
    except Exception as error:
        _internal_or_input_failure(context, error, "CLI_REPLAY_BUNDLE_INVALID")
    destination = (
        output.resolve(strict=False)
        if output is not None
        else (bundle_directory.parent / f"replay-{uuid.uuid4()}").resolve(strict=False)
    )
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ("run-manifest.json", "effective-configuration.json", "plan-preview.json"):
        shutil.copyfile(bundle_directory / name, destination / name)
    source_blobs = bundle_directory / "blobs"
    if source_blobs.is_dir():
        shutil.copytree(source_blobs, destination / "blobs")
    _emit_result(
        context,
        {
            "command": "replay",
            "manifest_id": loaded.manifest.manifest_id,
            "destination": str(destination),
            "verdict": ResultCategory.UNSUPPORTED.value,
            "reason": "secret sources are intentionally absent from immutable bundles",
        },
        (
            f"Verified replay bundle {loaded.manifest.manifest_id}\n"
            f"Destination: {_safe_text(str(destination))}\n"
            "Execution requires a fresh authorized secret context."
        ),
    )
    raise typer.Exit(int(ExitCode.UNSUPPORTED))


@app.command("inspect", help="Inspect sanitized local run evidence without network access.")
def inspect_command(
    context: typer.Context,
    run_directory: Path = typer.Argument(..., exists=True, file_okay=False),
    identifier: str | None = typer.Option(None, "--identifier", "--id"),
    raw_artifacts: bool = typer.Option(False, "--raw-artifacts"),
) -> None:
    state = _read_run_state(run_directory)
    records = _read_json_lines(run_directory / _DELIVERIES)
    if identifier is not None:
        records = tuple(
            record
            for record in records
            if identifier
            in {
                record.get("scenario_id"),
                record.get("event_id"),
                record.get("delivery_id"),
            }
        )
        if not records:
            _fail(
                ResultCategory.INVALID_INPUT,
                "INSPECTION_IDENTIFIER_NOT_FOUND",
                "No exact sanitized record contains the requested identifier.",
            )
    document: dict[str, object] = {
        "command": "inspect",
        "run": state,
        "deliveries": list(records),
    }
    if raw_artifacts:
        document["raw_artifacts"] = {
            "potentially_sensitive": True,
            "paths": sorted(
                path.relative_to(run_directory).as_posix()
                for path in (run_directory / "blobs").glob("**/*")
                if path.is_file()
            ),
        }
        typer.echo(
            "WARNING: raw artifact paths may contain sensitive webhook payloads.",
            err=True,
        )
    if _presentation(context).json_output:
        _stdout_json(document)
        return
    lines = [
        f"Run: {_safe_text(str(state.get('run_id', 'unknown')))}",
        f"Verdict: {_safe_text(str(state.get('verdict', 'unknown')))}",
        f"Sanitized delivery records: {len(records)}",
    ]
    if raw_artifacts:
        lines.append("Raw artifact paths were explicitly requested.")
    typer.echo("\n".join(lines))


@app.command("report", help="Verify and summarize existing local report artifacts offline.")
def report_command(
    context: typer.Context,
    run_directory: Path = typer.Argument(..., exists=True, file_okay=False),
    formats: list[str] = typer.Option(None, "--format"),
) -> None:
    selected_formats = tuple(dict.fromkeys(formats or ["json", "junit", "html"]))
    if any(value not in {"json", "junit", "html"} for value in selected_formats):
        _fail(
            ResultCategory.INVALID_INPUT,
            "CLI_REPORT_FORMAT_INVALID",
            "Report format must be json, junit, or html.",
        )
    selected_paths: set[str] = set()
    if "json" in selected_formats:
        selected_paths.update(
            {
                "run-manifest.json",
                _DELIVERIES,
                _OBSERVATIONS,
                _ASSERTIONS,
                _SUMMARY,
            }
        )
    if "junit" in selected_formats:
        selected_paths.add(_JUNIT)
    if "html" in selected_formats:
        selected_paths.add(_HTML)
    artifacts: list[dict[str, object]] = []
    for relative in sorted(selected_paths):
        path = run_directory / relative
        if not path.is_file():
            _fail(
                ResultCategory.HARNESS_ERROR,
                "CLI_REPORT_ARTIFACT_MISSING",
                "A registered report artifact is missing.",
            )
        content = path.read_bytes()
        artifacts.append(
            {
                "relative_path": relative,
                "byte_length": len(content),
                "sha256": sha256_digest(content),
            }
        )
    digest = sha256_digest(json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode())
    _emit_result(
        context,
        {
            "command": "report",
            "formats": list(selected_formats),
            "normalized_digest": digest,
            "artifacts": artifacts,
        },
        (f"Verified {len(artifacts)} local report artifact(s)\nNormalized digest: {digest}"),
    )


async def _execute_bundle(
    config: ProjectConfig,
    bundle: CompiledRunBundle,
    run_directory: Path,
    handles: dict[str, SecretHandle],
) -> tuple[_AttemptProjection, ...]:
    policy = parse_destination_policy(config.receiver)
    executor = HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=AnyIOResolver(),
            connector=AnyIOConnector(),
        ),
        timeouts=HttpTimeouts(
            connect_ns=int(config.receiver.timeouts.connect),
            write_ns=int(config.receiver.timeouts.write),
            read_ns=int(config.receiver.timeouts.read),
            pool_ns=int(config.receiver.timeouts.pool),
            total_ns=int(config.receiver.timeouts.total),
        ),
        limits=HttpLimits(
            max_request_bytes=config.limits.max_request_bytes,
            response_capture_bytes=config.limits.max_response_capture_bytes,
        ),
    )
    signers = _build_signers(config, handles)
    projections: list[_AttemptProjection] = []
    for sequence, recipe in enumerate(bundle.realized_execution, start=1):
        blob = next(item for item in bundle.blobs if item.sha256 == recipe.request_blob)
        base = HttpAttemptCommand(
            policy=policy,
            body=blob.path.read_bytes(),
            headers=(HttpHeader("content-type", recipe.media_type, HeaderOwner.USER),),
        )
        signer = None if recipe.signer_name is None else signers[recipe.signer_name]
        prepared = prepare_realized_attempt(base, recipe, signer=signer)
        result = await executor.execute(prepared.command)
        projections.append(
            _AttemptProjection(
                sequence=sequence,
                scenario_id=recipe.scenario_id,
                delivery_id=recipe.delivery_id,
                event_id=recipe.event_id,
                outcome=result.outcome.value,
                status=None if result.response is None else result.response.status,
                request_sha256=result.request.body_sha256,
                response_sha256=(None if result.response is None else result.response.body_sha256),
                error_code=None if result.error is None else result.error.code.value,
            )
        )
    del run_directory
    return tuple(projections)


def _build_signers(
    config: ProjectConfig,
    handles: dict[str, SecretHandle],
) -> dict[str, Signer]:
    result: dict[str, Signer] = {}
    for name, signer_config in config.signers.items():
        handle = handles[f"signer:{name}"]
        if isinstance(signer_config, GenericHmacSha256SignerConfig):
            result[name] = GenericHmacSha256Signer(
                handle,
                GenericHmacSha256Settings(
                    header_name=signer_config.header_name or "x-webhook-signature",
                    key_id=signer_config.key_id,
                ),
            )
        elif isinstance(signer_config, StripeV1SignerConfig):
            result[name] = StripeV1Signer(
                handle,
                StripeV1Settings(
                    header_name=signer_config.header_name or "stripe-signature",
                    key_id=signer_config.key_id,
                ),
            )
        else:
            result[name] = StandardWebhooksHmacSigner(
                handle,
                StandardWebhooksSettings(
                    header_name=signer_config.header_name or "webhook-signature",
                    key_id=signer_config.key_id,
                ),
            )
    return result


def _resolve_secrets(config: ProjectConfig, project_root: Path) -> _ResolvedSecrets:
    resolver = SecretResolver(
        project_root=project_root,
        secret_roots=config.project.secret_roots,
    )
    handles: dict[str, SecretHandle] = {}
    fingerprints: dict[str, str] = {}
    references: list[tuple[str, SecretRef]] = [
        (f"signer:{name}", signer.secret) for name, signer in config.signers.items()
    ]
    references.extend(
        (f"observer:{name}", observer.token)
        for name, observer in config.observers.items()
        if isinstance(observer, HttpObserverConfig)
    )
    try:
        for key, reference in references:
            handle = resolver.resolve(reference)
            handles[key] = handle
            wire = cast("dict[str, object]", reference.model_dump(mode="json"))
            kind, value = next(iter(wire.items()))
            fingerprints[f"{kind}:{value}"] = str(handle.fingerprint)
    except BaseException:
        for handle in handles.values():
            handle.close()
        raise
    return _ResolvedSecrets(handles, fingerprints)


def _verdict(projections: tuple[_AttemptProjection, ...]) -> ResultCategory:
    if any(value.outcome == AttemptOutcome.UNKNOWN_OUTCOME.value for value in projections):
        return ResultCategory.AMBIGUOUS
    if any(value.outcome == AttemptOutcome.NOT_SENT.value for value in projections):
        return ResultCategory.ENVIRONMENT_ERROR
    if any(value.status is None or not 200 <= value.status < 300 for value in projections):
        return ResultCategory.RECEIVER_FAILURE
    return ResultCategory.PASS


def _write_run_artifacts(
    run_directory: Path,
    *,
    run_id: str,
    bundle: CompiledRunBundle,
    projections: tuple[_AttemptProjection, ...],
    verdict: ResultCategory,
    destination: str,
) -> None:
    run_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    delivery_bytes = b"".join(
        (json.dumps(value.to_wire(), sort_keys=True, separators=(",", ":")) + "\n").encode()
        for value in projections
    )
    summary = {
        "schema_version": "1.0",
        "run_id": run_id,
        "manifest_id": bundle.manifest.manifest_id,
        "verdict": verdict.value,
        "exit_code": int(exit_for_result(verdict)[1]),
        "counts": {
            "scenarios": len(bundle.manifest.scenarios),
            "attempts": len(projections),
            "observations": 0,
            "assertions": 0,
        },
    }
    state = {
        "run_id": run_id,
        "manifest_id": bundle.manifest.manifest_id,
        "verdict": verdict.value,
        "destination": destination,
        "resumable": verdict in {ResultCategory.AMBIGUOUS, ResultCategory.CANCELLED},
    }
    _atomic_bytes(run_directory / _DELIVERIES, delivery_bytes)
    _atomic_bytes(run_directory / _OBSERVATIONS, b"")
    _atomic_bytes(run_directory / _ASSERTIONS, b"")
    _atomic_json(run_directory / _SUMMARY, summary)
    _atomic_json(run_directory / _RUN_STATE, state)
    junit = (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<testsuites tests="{len(projections)}" failures="'
        f'{0 if verdict is ResultCategory.PASS else 1}"/>'
        "\n"
    ).encode()
    _atomic_bytes(run_directory / _JUNIT, junit)
    html_body = (
        "<!doctype html><html><head>"
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src &#39;none&#39;; script-src &#39;none&#39;">'
        "<title>Webhook conformance</title></head><body>"
        f"<h1>{html.escape(verdict.value)}</h1>"
        f"<p>Run {html.escape(run_id)}</p>"
        f"<p>Attempts {len(projections)}</p>"
        "</body></html>\n"
    ).encode()
    _atomic_bytes(run_directory / _HTML, html_body)


def _load_config(
    config: Path,
    *,
    project_root: Path | None = None,
    output: Path | None = None,
) -> ConfigLoadResult:
    return load_project_config(
        config,
        overrides=CliOverrides(project_root=project_root, output=output),
    )


def _require_loaded(result: ConfigLoadResult) -> _LoadedProject:
    config = result.config
    project_root = result.project_root
    if config is None or project_root is None:
        _diagnostic_failure(result)
    return _LoadedProject(
        config=config,
        project_root=project_root,
        result=result,
    )


def _diagnostic_failure(result: ConfigLoadResult) -> NoReturn:
    if not result.diagnostics:
        raise AssertionError("failed configuration load lacks diagnostics")
    diagnostic = result.diagnostics[0]
    _stderr_diagnostic(diagnostic)
    raise typer.Exit(int(exit_for_result(diagnostic.result_category)[1]))


def _stderr_diagnostic(diagnostic: Diagnostic) -> None:
    location = ""
    if diagnostic.location is not None:
        location = f" [{_safe_text(str(diagnostic.location.path or ''))}"
        if diagnostic.location.line is not None:
            location += f":{diagnostic.location.line}"
        if diagnostic.location.column is not None:
            location += f":{diagnostic.location.column}"
        location += "]"
    typer.echo(
        f"{diagnostic.code}: {_safe_text(diagnostic.message)}{location}",
        err=True,
    )
    if diagnostic.corrective_action:
        typer.echo(f"Fix: {_safe_text(diagnostic.corrective_action)}", err=True)


def _internal_or_input_failure(
    context: typer.Context,
    error: BaseException,
    code: str,
) -> NoReturn:
    if isinstance(error, (ValueError, TypeError, OSError)):
        _fail(
            ResultCategory.INVALID_INPUT,
            code,
            _safe_text(str(error)) or "The requested operation failed validation.",
        )
    incident_id = str(new_incident_id())
    typer.echo(f"HARNESS_INTERNAL_ERROR: incident_id={incident_id}", err=True)
    presentation = _presentation(context)
    environment_debug = os.environ.get(DEBUG_ENVIRONMENT_VARIABLE, "").casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if presentation.debug or environment_debug:
        traceback.print_exception(error, file=sys.stderr)
    raise typer.Exit(int(ExitCode.HARNESS_FAILURE))


def _fail(
    category: ResultCategory,
    code: str,
    message: str,
    *,
    details: dict[str, object] | None = None,
) -> NoReturn:
    typer.echo(f"{_safe_text(code)}: {_safe_text(message)}", err=True)
    if details:
        typer.echo(json.dumps(details, sort_keys=True, separators=(",", ":")), err=True)
    raise typer.Exit(int(exit_for_result(category)[1]))


def _emit_result(
    context: typer.Context,
    document: Mapping[str, object],
    human: str,
) -> None:
    if _presentation(context).json_output:
        _stdout_json(document)
    else:
        typer.echo(_safe_multiline(human))


def _stdout_json(document: Mapping[str, object]) -> None:
    typer.echo(
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )


def _presentation(context: typer.Context) -> _Presentation:
    return context.ensure_object(_Presentation)


def _safe_text(value: str) -> str:
    return _CONTROL.sub("\N{REPLACEMENT CHARACTER}", value)[:4_096]


def _safe_multiline(value: str) -> str:
    return "\n".join(_safe_text(line) for line in value.splitlines())


def _artifact_root(
    config: ProjectConfig,
    project_root: Path,
    output: Path | None,
) -> Path:
    if output is not None:
        return output.resolve(strict=False)
    configured = Path(config.project.artifact_directory)
    return configured if configured.is_absolute() else project_root / configured


def _require_public_consent(config: ProjectConfig, supplied: str | None) -> None:
    if config.receiver.target_profile is not TargetProfile.PUBLIC_AUTHORIZED:
        if supplied is not None:
            _fail(
                ResultCategory.INVALID_INPUT,
                "CLI_PUBLIC_AUTHORIZATION_UNDECLARED",
                "Public-target consent is valid only for a configured public target.",
            )
        return
    target = urlsplit(config.receiver.url)
    port = target.port or (443 if target.scheme == "https" else 80)
    expected = f"{target.hostname}:{port}"
    if supplied != expected:
        _fail(
            ResultCategory.INVALID_INPUT,
            "CLI_PUBLIC_AUTHORIZATION_REQUIRED",
            "Public target execution requires exact config and CLI consent.",
        )


def _safe_init_write(root: Path, target: Path, content: bytes) -> None:
    if not target.is_relative_to(root):
        raise ValueError("initialization target escaped the project root")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.is_symlink() or any(
        parent.is_symlink() for parent in target.parents if parent != root
    ):
        raise ValueError("initialization refuses symlink targets")
    _atomic_bytes(target, content)


def _atomic_json(path: Path, document: Mapping[str, object]) -> None:
    content = (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()
    _atomic_bytes(path, content)


def _atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_run_state(run_directory: Path) -> dict[str, object]:
    path = run_directory.resolve() / _RUN_STATE
    value: object = None
    try:
        value: object = json.loads(path.read_bytes())
    except (OSError, ValueError):
        _fail(
            ResultCategory.INVALID_INPUT,
            "CLI_RUN_STATE_INVALID",
            "The local run state is missing or invalid.",
        )
    if not isinstance(value, dict):
        _fail(
            ResultCategory.INVALID_INPUT,
            "CLI_RUN_STATE_INVALID",
            "The local run state is not a JSON object.",
        )
    return cast("dict[str, object]", value)


def _read_json_lines(path: Path) -> tuple[dict[str, object], ...]:
    result: list[dict[str, object]] = []
    try:
        for line in path.read_bytes().splitlines():
            value: object = json.loads(line)
            result.append(_json_object(value))
    except (OSError, TypeError, ValueError):
        _fail(
            ResultCategory.HARNESS_ERROR,
            "CLI_SANITIZED_ARTIFACT_INVALID",
            "A sanitized local report artifact is missing or invalid.",
        )
    return tuple(result)


def _json_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError("JSON Lines records must be objects")
    return cast("dict[str, object]", value)


def _write_cancelled_state(run_directory: Path, run_id: str) -> None:
    _atomic_json(
        run_directory / _RUN_STATE,
        {
            "run_id": run_id,
            "verdict": ResultCategory.CANCELLED.value,
            "resumable": True,
        },
    )


def run_cli() -> None:
    """Run the installed command with stable unexpected-error handling."""
    try:
        app()
    except typer.Exit:
        raise
    except SystemExit:
        raise
    except KeyboardInterrupt:
        raise SystemExit(int(ExitCode.CANCELLED)) from None
    except BaseException as error:
        incident_id = str(new_incident_id())
        typer.echo(f"HARNESS_INTERNAL_ERROR: incident_id={incident_id}", err=True)
        if os.environ.get(DEBUG_ENVIRONMENT_VARIABLE, "").casefold() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            traceback.print_exception(error, file=sys.stderr)
        raise SystemExit(int(ExitCode.HARNESS_FAILURE)) from None


__all__ = ["app", "run_cli"]
