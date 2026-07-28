"""Complete local-first command tree for webhook receiver conformance."""
# ruff: noqa: B008, BLE001, EM101, FBT001, FBT003, PLR0913, PLR0917, TRY003

from __future__ import annotations

import json
import os
import re
import sys
import traceback
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, cast
from urllib.parse import urlsplit

import anyio
import typer

from webhook_receiver_conformance.cli.inspect import (
    RAW_ARTIFACT_WARNING,
    InspectionIdentifierKind,
    InspectionQuery,
    render_inspection_human,
    render_inspection_json,
)
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
from webhook_receiver_conformance.errors import (
    DEBUG_ENVIRONMENT_VARIABLE,
    Diagnostic,
    ExitCode,
    ResultCategory,
    exit_for_result,
    new_incident_id,
)
from webhook_receiver_conformance.journal.bootstrap import JournalLifecycleRepository
from webhook_receiver_conformance.manifest.compiler import (
    compile_run_bundle,
)
from webhook_receiver_conformance.manifest.loader import load_replay_bundle
from webhook_receiver_conformance.network.dialer import (
    DialTimeouts,
    PinnedDestinationDialer,
)
from webhook_receiver_conformance.network.preflight import (
    PreflightPhase,
    PublicTargetPreflightError,
    PublicTargetPreflightEvidence,
    preflight_public_target,
)
from webhook_receiver_conformance.network.transport import AnyIOConnector, AnyIOResolver
from webhook_receiver_conformance.recovery.policy import (
    AmbiguityPolicy,
    ResumeInvocationPolicy,
)
from webhook_receiver_conformance.runtime.inspection import load_inspection_index
from webhook_receiver_conformance.runtime.observer_assertions import (
    ProjectObserverAssertionExecutorFactory,
)
from webhook_receiver_conformance.runtime.reporting import (
    ReportFormat,
    ReportRegenerationResult,
    regenerate_run_reports,
)
from webhook_receiver_conformance.runtime.resume import (
    ResumeRequest,
    ResumeResult,
    ResumeStatus,
    ResumeWorkflowResult,
    resume_and_continue_sync,
)
from webhook_receiver_conformance.runtime.runner import (
    FullRunLoadedPreparation,
    FullRunPublicPreflight,
    FullRunRequest,
    FullRunResult,
    FullRunResumePreparation,
    FullRunRunner,
)
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
    from webhook_receiver_conformance.journal.resume import ResumeJournalPreflight
    from webhook_receiver_conformance.journal.run_lock import RunLock
    from webhook_receiver_conformance.signatures.base import Signer

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_RUN_STATE = "run-state.json"
_INIT_CONFIG = """schema_version: 1
project:
  name: local-webhook-receiver
  artifact_directory: .webhook-conformance
  seed: local-example-seed
receiver:
  url: http://127.0.0.1:8000/webhooks
  target_profile: loopback
  allowed_hosts: [127.0.0.1]
  allowed_ports: [8000]
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


@dataclass(slots=True)
class _PreparedResumeExecution:
    loaded: _LoadedProject
    secrets: _ResolvedSecrets
    runner: FullRunRunner
    request: FullRunRequest
    preparation: FullRunResumePreparation | None = None


@dataclass(frozen=True, slots=True)
class _CompletedResumeExecution:
    result: FullRunResult
    report: ReportRegenerationResult
    loaded: _LoadedProject


@dataclass(slots=True)
class _ResumeCommandCoordinator:
    context: typer.Context
    run_directory: Path
    config_path: Path
    project_root: Path | None
    on_ambiguous: AmbiguityPolicy | None
    authorize_public_target: str | None
    prepared: _PreparedResumeExecution | None = None

    async def prepare(
        self,
        preflight: ResumeJournalPreflight,
        ownership: RunLock,
    ) -> object:
        if preflight.contains_ambiguity and self.on_ambiguous is AmbiguityPolicy.STOP:
            return self
        loaded = _require_loaded(
            _load_config(
                self.config_path,
                project_root=self.project_root,
                allow_missing_fixture_sources=True,
            )
        )
        _require_public_consent(loaded.config, self.authorize_public_target)
        secrets = _resolve_secrets(loaded.config, loaded.project_root)
        try:
            request = FullRunRequest(
                config=loaded.config,
                project_root=loaded.project_root,
                artifact_directory=self.run_directory.parent,
                secret_fingerprints=secrets.fingerprints,
                signers=_build_signers(loaded.config, secrets.handles),
                runtime_public_authorization=self.authorize_public_target,
                owner_epoch=preflight.owner_epoch + 1,
            )
            runner = _full_run_runner(
                loaded,
                secrets,
                runtime_public_authorization=self.authorize_public_target,
            )
            prepared = _PreparedResumeExecution(
                loaded=loaded,
                secrets=secrets,
                runner=runner,
                request=request,
            )
            self.prepared = prepared
            prepared.preparation = await runner.prepare_resume(
                request,
                self.run_directory,
                ownership=ownership,
            )
        except BaseException:
            if self.prepared is None:
                secrets.close()
            raise
        return prepared

    async def continue_run(
        self,
        result: ResumeResult,
        ownership: RunLock,
        prepared: object,
    ) -> object:
        if not isinstance(prepared, _PreparedResumeExecution):
            raise TypeError("mutable resume continuation lacks validated execution inputs")
        if prepared.preparation is None:
            raise TypeError("mutable resume continuation lacks prepared bundle inputs")
        validation = await prepared.runner.validate_resume(
            prepared.request,
            result,
            ownership=ownership,
            preparation=prepared.preparation,
        )
        try:
            if prepared.loaded.config.receiver.target_profile is TargetProfile.PUBLIC_AUTHORIZED:
                ownership.require_owner(
                    self.run_directory,
                    run_id=result.run_id,
                    owner_epoch=result.owner_epoch,
                )
                if not _presentation(self.context).json_output:
                    typer.echo(
                        "Authorized destination before resumed contact: "
                        f"{_safe_text(prepared.loaded.config.receiver.url)}",
                        err=True,
                    )

                try:
                    await prepared.runner.challenge_public_resume(
                        validation,
                        ownership=ownership,
                    )
                except PublicTargetPreflightError as error:
                    _fail_public_preflight(error)
            resumed = await prepared.runner.resume_validated(
                validation,
                ownership=ownership,
            )
        finally:
            await validation.aclose()
        report = await _regenerate_run_reports(resumed.run_directory)
        _atomic_json(
            resumed.run_directory / _RUN_STATE,
            {
                "run_id": resumed.run_id,
                "manifest_id": resumed.manifest_id,
                "verdict": resumed.result_category.value,
                "destination": prepared.loaded.config.receiver.url,
                "resumable": resumed.result_category
                in {ResultCategory.AMBIGUOUS, ResultCategory.CANCELLED},
                "journal": "journal.sqlite3",
                "normalized_report_digest": report.normalized_digest,
                "owner_epoch": result.owner_epoch,
                "resumed_from_owner_epoch": result.preflight.owner_epoch,
            },
        )
        return _CompletedResumeExecution(
            result=resumed,
            report=report,
            loaded=prepared.loaded,
        )

    def close(self) -> None:
        if self.prepared is not None:
            self.prepared.secrets.close()
            self.prepared = None


def _completed_resume(
    workflow: ResumeWorkflowResult,
) -> _CompletedResumeExecution | None:
    if workflow.continuation is not None:
        if not isinstance(workflow.continuation, _CompletedResumeExecution):
            raise TypeError("resume continuation returned an invalid result")
        return workflow.continuation
    if workflow.recovery.status is ResumeStatus.CONTINUE:
        raise RuntimeError("resume allowed execution without a retained continuation")
    return None


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
def run_command(  # noqa: C901
    context: typer.Context,
    config: Path = typer.Option(
        Path("webhook-conformance.yaml"),
        "--config",
        "-c",
    ),
    manifest: Path | None = typer.Option(
        None,
        "--manifest",
        exists=True,
        help="Existing immutable bundle or run-manifest.json to verify and execute.",
    ),
    project_root: Path | None = typer.Option(None, "--project-root"),
    output: Path | None = typer.Option(None, "--output"),
    authorize_public_target: str | None = typer.Option(
        None,
        "--authorize-public-target",
        help="Exact HOST:PORT consent for a configured public target.",
    ),
) -> None:
    bundle = None
    if manifest is not None:
        bundle_directory = manifest if manifest.is_dir() else manifest.parent
        try:
            bundle = load_replay_bundle(bundle_directory.resolve())
        except Exception as error:
            _internal_or_input_failure(context, error, "CLI_RUN_BUNDLE_INVALID")
    loaded = _require_loaded(
        _load_config(
            config,
            project_root=project_root,
            output=output,
            allow_missing_fixture_sources=bundle is not None,
        )
    )
    _require_public_consent(loaded.config, authorize_public_target)
    project_root = loaded.project_root
    artifact_root = _artifact_root(loaded.config, project_root, output)
    secrets: _ResolvedSecrets | None = None
    preparation: FullRunLoadedPreparation | None = None
    try:
        secrets = _resolve_secrets(loaded.config, project_root)
        runner = _full_run_runner(
            loaded,
            secrets,
            runtime_public_authorization=authorize_public_target,
        )
        request = FullRunRequest(
            config=loaded.config,
            project_root=project_root,
            artifact_directory=artifact_root,
            secret_fingerprints=secrets.fingerprints,
            signers=_build_signers(loaded.config, secrets.handles),
            runtime_public_authorization=authorize_public_target,
        )
        if bundle is not None:
            preparation = runner.prepare_loaded(request, bundle)
        if loaded.config.receiver.target_profile is TargetProfile.PUBLIC_AUTHORIZED:
            if not _presentation(context).json_output:
                typer.echo(
                    "Authorized destination before contact: "
                    f"{_safe_text(loaded.config.receiver.url)}",
                    err=True,
                )
            _perform_public_preflight(loaded.config, authorize_public_target)
        result = (
            anyio.run(runner.run, request)
            if bundle is None
            else anyio.run(
                runner.run_prepared_loaded,
                cast("FullRunLoadedPreparation", preparation),
            )
        )
        report_result = anyio.run(
            _regenerate_run_reports,
            result.run_directory,
        )
        state: dict[str, object] = {
            "run_id": result.run_id,
            "manifest_id": result.manifest_id,
            "verdict": result.result_category.value,
            "destination": loaded.config.receiver.url,
            "resumable": result.result_category
            in {ResultCategory.AMBIGUOUS, ResultCategory.CANCELLED},
            "journal": "journal.sqlite3",
            "normalized_report_digest": report_result.normalized_digest,
        }
        if bundle is not None:
            state["replayed_from"] = str(bundle.directory)
        _atomic_json(
            result.run_directory / _RUN_STATE,
            state,
        )
    except KeyboardInterrupt:
        raise typer.Exit(int(ExitCode.CANCELLED)) from None
    except Exception as error:
        _internal_or_input_failure(context, error, "CLI_RUN_FAILED")
    finally:
        if preparation is not None:
            preparation.close()
        if secrets is not None:
            secrets.close()
    _emit_result(
        context,
        {
            "command": "run",
            "run_id": result.run_id,
            "manifest_id": result.manifest_id,
            "destination": loaded.config.receiver.url,
            "run_directory": str(result.run_directory),
            "verdict": result.result_category.value,
            "exit_code": int(result.exit_code),
            "normalized_report_digest": report_result.normalized_digest,
        },
        (
            f"Run {result.run_id}: {result.result_category.value}\n"
            f"Destination: {_safe_text(loaded.config.receiver.url)}\n"
            f"Run directory: {_safe_text(str(result.run_directory))}"
        ),
    )
    if result.result_category is not ResultCategory.PASS:
        raise typer.Exit(int(result.exit_code))


@app.command("resume", help="Inspect a local run and require an explicit ambiguity policy.")
def resume_command(
    context: typer.Context,
    run_directory: Path = typer.Argument(..., exists=True, file_okay=False),
    config: Path = typer.Option(
        Path("webhook-conformance.yaml"),
        "--config",
        "-c",
        help="Fresh project configuration supplying destination and secret references.",
    ),
    project_root: Path | None = typer.Option(None, "--project-root"),
    on_ambiguous: AmbiguityPolicy | None = typer.Option(
        None,
        "--on-ambiguous",
        case_sensitive=False,
        help="Explicit policy: stop, observe, redeliver, or operator_decision.",
    ),
    authorize_public_target: str | None = typer.Option(
        None,
        "--authorize-public-target",
        help="Exact HOST:PORT consent before a resumed public-target delivery.",
    ),
) -> None:
    resolved_directory = run_directory.resolve()
    coordinator = _ResumeCommandCoordinator(
        context=context,
        run_directory=resolved_directory,
        config_path=config,
        project_root=project_root,
        on_ambiguous=on_ambiguous,
        authorize_public_target=authorize_public_target,
    )
    completed: _CompletedResumeExecution | None = None
    try:
        bundle = load_replay_bundle(resolved_directory)
        target = bundle.manifest.target_policy
        destination = f"{target.authorized_host}:{target.authorized_port}"
        if not _presentation(context).json_output:
            typer.echo(
                f"Resume destination before any possible contact: {_safe_text(destination)}",
                err=True,
            )
        request = ResumeRequest(
            run_directory=resolved_directory,
            invocation=ResumeInvocationPolicy(on_ambiguous=on_ambiguous),
            manifest=bundle.manifest,
            defer_redeliveries=True,
        )
        workflow = resume_and_continue_sync(
            request,
            prepare=coordinator.prepare,
            continuation=coordinator.continue_run,
        )
        result = workflow.recovery
        completed = _completed_resume(workflow)
    except KeyboardInterrupt:
        raise typer.Exit(int(ExitCode.CANCELLED)) from None
    except typer.Exit:
        raise
    except Exception as error:
        _internal_or_input_failure(context, error, "CLI_RESUME_FAILED")
    finally:
        coordinator.close()
    if completed is not None:
        resumed = completed.result
        report_result = completed.report
        loaded = completed.loaded
        redeliveries = 0 if result.policy_plan is None else len(result.policy_plan.redeliveries)
        _emit_result(
            context,
            {
                "command": "resume",
                "run_id": resumed.run_id,
                "manifest_id": resumed.manifest_id,
                "destination": loaded.config.receiver.url,
                "run_directory": str(resumed.run_directory),
                "status": result.status.value,
                "verdict": resumed.result_category.value,
                "read_only": False,
                "owner_epoch": result.owner_epoch,
                "ambiguous_attempt_ids": list(result.ambiguous_attempt_ids),
                "redeliveries_scheduled": redeliveries,
                "observations_invoked": result.observations_invoked,
                "exit_code": int(resumed.exit_code),
                "normalized_report_digest": report_result.normalized_digest,
            },
            (
                f"Resumed run {resumed.run_id}: {resumed.result_category.value}\n"
                f"Destination: {_safe_text(loaded.config.receiver.url)}\n"
                f"Run directory: {_safe_text(str(resumed.run_directory))}"
            ),
        )
        if resumed.result_category is not ResultCategory.PASS:
            raise typer.Exit(int(resumed.exit_code))
        return
    if result.read_only and result.result_category is ResultCategory.AMBIGUOUS:
        typer.echo(
            "Ambiguity remains unresolved; no receiver contact was attempted.",
            err=True,
        )
    verdict = result.result_category
    _emit_result(
        context,
        {
            "command": "resume",
            "run_id": result.run_id,
            "destination": destination,
            "run_directory": str(resolved_directory),
            "status": result.status.value,
            "verdict": None if verdict is None else verdict.value,
            "read_only": result.read_only,
            "owner_epoch": result.owner_epoch,
            "ambiguous_attempt_ids": list(result.ambiguous_attempt_ids),
            "redeliveries_invoked": result.redeliveries_invoked,
            "observations_invoked": result.observations_invoked,
        },
        (
            f"Run {result.run_id}: {result.status.value}\n"
            f"Destination: {_safe_text(destination)}\n"
            f"Run directory: {_safe_text(str(resolved_directory))}"
        ),
    )
    if result.exit_code is not None and result.exit_code is not ExitCode.PASS:
        raise typer.Exit(int(result.exit_code))


@app.command("replay", help="Verify an immutable bundle before creating a new execution.")
def replay_command(
    context: typer.Context,
    manifest: Path = typer.Argument(..., exists=True),
    config: Path = typer.Option(
        Path("webhook-conformance.yaml"),
        "--config",
        "-c",
        help="Fresh project configuration supplying destination and secret references.",
    ),
    project_root: Path | None = typer.Option(None, "--project-root"),
    output: Path | None = typer.Option(None, "--output"),
    authorize_public_target: str | None = typer.Option(
        None,
        "--authorize-public-target",
        help="Exact HOST:PORT consent for a configured public target.",
    ),
) -> None:
    bundle_directory = manifest if manifest.is_dir() else manifest.parent
    try:
        bundle = load_replay_bundle(bundle_directory.resolve())
    except Exception as error:
        _internal_or_input_failure(context, error, "CLI_REPLAY_BUNDLE_INVALID")
    loaded = _require_loaded(
        _load_config(
            config,
            project_root=project_root,
            output=output,
            allow_missing_fixture_sources=True,
        )
    )
    _require_public_consent(loaded.config, authorize_public_target)
    artifact_root = _artifact_root(loaded.config, loaded.project_root, output)
    secrets: _ResolvedSecrets | None = None
    preparation: FullRunLoadedPreparation | None = None
    try:
        secrets = _resolve_secrets(loaded.config, loaded.project_root)
        runner = _full_run_runner(
            loaded,
            secrets,
            runtime_public_authorization=authorize_public_target,
        )
        request = FullRunRequest(
            config=loaded.config,
            project_root=loaded.project_root,
            artifact_directory=artifact_root,
            secret_fingerprints=secrets.fingerprints,
            signers=_build_signers(loaded.config, secrets.handles),
            runtime_public_authorization=authorize_public_target,
        )
        preparation = runner.prepare_loaded(request, bundle)
        if loaded.config.receiver.target_profile is TargetProfile.PUBLIC_AUTHORIZED:
            if not _presentation(context).json_output:
                typer.echo(
                    "Authorized destination before contact: "
                    f"{_safe_text(loaded.config.receiver.url)}",
                    err=True,
                )
            _perform_public_preflight(loaded.config, authorize_public_target)
        result = anyio.run(runner.run_prepared_loaded, preparation)
        report_result = anyio.run(
            _regenerate_run_reports,
            result.run_directory,
        )
        _atomic_json(
            result.run_directory / _RUN_STATE,
            {
                "run_id": result.run_id,
                "manifest_id": result.manifest_id,
                "verdict": result.result_category.value,
                "destination": loaded.config.receiver.url,
                "resumable": result.result_category
                in {ResultCategory.AMBIGUOUS, ResultCategory.CANCELLED},
                "journal": "journal.sqlite3",
                "normalized_report_digest": report_result.normalized_digest,
                "replayed_from": str(bundle.directory),
            },
        )
    except KeyboardInterrupt:
        raise typer.Exit(int(ExitCode.CANCELLED)) from None
    except Exception as error:
        _internal_or_input_failure(context, error, "CLI_REPLAY_FAILED")
    finally:
        if preparation is not None:
            preparation.close()
        if secrets is not None:
            secrets.close()
    _emit_result(
        context,
        {
            "command": "replay",
            "run_id": result.run_id,
            "manifest_id": result.manifest_id,
            "destination": loaded.config.receiver.url,
            "run_directory": str(result.run_directory),
            "verdict": result.result_category.value,
            "exit_code": int(result.exit_code),
            "normalized_report_digest": report_result.normalized_digest,
        },
        (
            f"Replay {result.run_id}: {result.result_category.value}\n"
            f"Destination: {_safe_text(loaded.config.receiver.url)}\n"
            f"Run directory: {_safe_text(str(result.run_directory))}"
        ),
    )
    if result.result_category is not ResultCategory.PASS:
        raise typer.Exit(int(result.exit_code))


@app.command("inspect", help="Inspect sanitized local run evidence without network access.")
def inspect_command(
    context: typer.Context,
    run_directory: Path = typer.Argument(..., exists=True, file_okay=False),
    identifier: str | None = typer.Option(None, "--identifier", "--id"),
    kind: InspectionIdentifierKind | None = typer.Option(
        None,
        "--kind",
        case_sensitive=False,
        help=(
            "Identifier kind: scenario, event, delivery, attempt, "
            "observation, assertion, or diagnostic."
        ),
    ),
    raw_artifacts: bool = typer.Option(False, "--raw-artifacts"),
) -> None:
    if (identifier is None) is not (kind is None):
        _fail(
            ResultCategory.INVALID_INPUT,
            "CLI_INSPECTION_QUERY_INCOMPLETE",
            "--identifier and --kind must be supplied together.",
        )
    try:
        index = anyio.run(load_inspection_index, run_directory.resolve())
    except Exception as error:
        _internal_or_input_failure(context, error, "CLI_INSPECTION_FAILED")
    if raw_artifacts:
        typer.echo(RAW_ARTIFACT_WARNING, err=True)
    if identifier is not None and kind is not None:
        try:
            result = index.query(
                InspectionQuery(kind=kind, identifier=identifier),
                include_raw_artifacts=raw_artifacts,
            )
        except Exception as error:
            _internal_or_input_failure(context, error, "CLI_INSPECTION_QUERY_FAILED")
        if _presentation(context).json_output:
            typer.echo(
                render_inspection_json(
                    result,
                    include_raw_artifacts=raw_artifacts,
                ).decode(),
                nl=False,
            )
            return
        typer.echo(
            render_inspection_human(
                result,
                include_raw_artifacts=raw_artifacts,
                stdout_is_tty=bool(typer.get_text_stream("stdout").isatty()),
            ),
            nl=False,
        )
        return
    document: dict[str, object] = {
        "command": "inspect",
        "run_directory": str(run_directory.resolve()),
        "verified": True,
        "failed_assertion_chains": len(index.chains),
    }
    if raw_artifacts:
        document["raw_artifacts"] = {
            "potentially_sensitive": True,
            "paths": list(index.raw_artifact_paths),
        }
    if _presentation(context).json_output:
        _stdout_json(document)
        return
    lines = [
        f"Verified run directory: {_safe_text(str(run_directory.resolve()))}",
        f"Failed assertion chains: {len(index.chains)}",
    ]
    if raw_artifacts:
        lines.append("Raw artifact paths were explicitly requested.")
    typer.echo("\n".join(lines))


@app.command("report", help="Regenerate selected reports from the local journal offline.")
def report_command(
    context: typer.Context,
    run_directory: Path = typer.Argument(..., exists=True, file_okay=False),
    formats: list[str] = typer.Option(None, "--format"),
) -> None:
    selected_names = tuple(dict.fromkeys(formats or ["json", "junit", "html"]))
    if any(value not in {"json", "junit", "html"} for value in selected_names):
        _fail(
            ResultCategory.INVALID_INPUT,
            "CLI_REPORT_FORMAT_INVALID",
            "Report format must be json, junit, or html.",
        )
    selected_formats = tuple(ReportFormat(value) for value in selected_names)
    try:
        result = anyio.run(
            _regenerate_run_reports,
            run_directory.resolve(),
            selected_formats,
        )
    except Exception as error:
        _internal_or_input_failure(context, error, "CLI_REPORT_REGENERATION_FAILED")
    artifacts = [
        {
            "relative_path": record.relative_path,
            "media_type": record.media_type,
            "byte_length": record.byte_length,
            "sha256": record.sha256,
        }
        for record in result.records
    ]
    _emit_result(
        context,
        {
            "command": "report",
            "run_id": result.run_id,
            "formats": [value.value for value in result.formats],
            "normalized_digest": result.normalized_digest,
            "artifacts": artifacts,
        },
        (
            f"Regenerated {len(artifacts)} local report artifact(s) from journal truth\n"
            f"Normalized digest: {result.normalized_digest}"
        ),
    )


async def _regenerate_run_reports(
    run_directory: Path,
    formats: tuple[ReportFormat, ...] = (
        ReportFormat.JSON,
        ReportFormat.JUNIT,
        ReportFormat.HTML,
    ),
) -> ReportRegenerationResult:
    return await regenerate_run_reports(run_directory, formats=formats)


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
                    header_name=(signer_config.header_name or "x-webhook-signature").casefold(),
                    key_id=signer_config.key_id,
                ),
            )
        elif isinstance(signer_config, StripeV1SignerConfig):
            result[name] = StripeV1Signer(
                handle,
                StripeV1Settings(
                    header_name=(signer_config.header_name or "stripe-signature").casefold(),
                    key_id=signer_config.key_id,
                ),
            )
        else:
            result[name] = StandardWebhooksHmacSigner(
                handle,
                StandardWebhooksSettings(
                    header_name=(signer_config.header_name or "webhook-signature").casefold(),
                    key_id=signer_config.key_id,
                ),
            )
    return result


def _full_run_runner(
    loaded: _LoadedProject,
    secrets: _ResolvedSecrets,
    *,
    runtime_public_authorization: str | None,
) -> FullRunRunner:
    return FullRunRunner(
        journal=JournalLifecycleRepository(),
        public_resume_preflight=FullRunPublicPreflight(
            PinnedDestinationDialer(
                resolver=AnyIOResolver(),
                connector=AnyIOConnector(),
            )
        ),
        observer_assertion_executor_factory=ProjectObserverAssertionExecutorFactory(
            config=loaded.config,
            project_root=loaded.project_root,
            observer_secrets={
                key: value for key, value in secrets.handles.items() if key.startswith("observer:")
            },
            runtime_public_authorization=runtime_public_authorization,
        ),
    )


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


def _load_config(
    config: Path,
    *,
    project_root: Path | None = None,
    output: Path | None = None,
    allow_missing_fixture_sources: bool = False,
) -> ConfigLoadResult:
    return load_project_config(
        config,
        overrides=CliOverrides(project_root=project_root, output=output),
        allow_missing_fixture_sources=allow_missing_fixture_sources,
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
    diagnostic = getattr(error, "diagnostic", None)
    if type(diagnostic) is Diagnostic:
        _stderr_diagnostic(diagnostic)
        raise typer.Exit(int(exit_for_result(diagnostic.result_category)[1]))
    classified_result = getattr(error, "result_category", None)
    if type(classified_result) is ResultCategory:
        classified_code = str(getattr(error, "code", code))
        _fail(
            classified_result,
            classified_code,
            _safe_text(str(error)) or "The requested operation failed.",
        )
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


def _perform_public_preflight(
    config: ProjectConfig,
    runtime_public_authorization: str | None,
) -> None:
    anyio.run(
        _perform_public_preflight_async,
        config,
        runtime_public_authorization,
    )


async def _perform_public_preflight_async(
    config: ProjectConfig,
    runtime_public_authorization: str | None,
) -> PublicTargetPreflightEvidence | None:
    try:
        evidence = await _preflight_public_target(
            config,
            runtime_public_authorization,
        )
    except PublicTargetPreflightError as error:
        _fail_public_preflight(error)
    return evidence


def _fail_public_preflight(error: PublicTargetPreflightError) -> NoReturn:
    if error.phase is PreflightPhase.POLICY:
        category = ResultCategory.INVALID_INPUT
    elif error.phase in {
        PreflightPhase.RESOLUTION,
        PreflightPhase.CONNECTION,
        PreflightPhase.WRITE,
        PreflightPhase.READ,
    }:
        category = ResultCategory.ENVIRONMENT_ERROR
    else:
        category = ResultCategory.RECEIVER_FAILURE
    code = error.code.value.upper().replace("-", "_")
    _fail(
        category,
        f"CLI_PUBLIC_PREFLIGHT_{code}",
        str(error),
    )


async def _preflight_public_target(
    config: ProjectConfig,
    runtime_public_authorization: str | None,
) -> PublicTargetPreflightEvidence | None:
    timeouts = config.receiver.timeouts
    return await preflight_public_target(
        config.receiver,
        runtime_public_authorization=runtime_public_authorization,
        dialer=PinnedDestinationDialer(
            resolver=AnyIOResolver(),
            connector=AnyIOConnector(),
        ),
        dial_timeouts=DialTimeouts(
            resolve_nanoseconds=timeouts.connect.nanoseconds,
            connect_nanoseconds=timeouts.connect.nanoseconds,
            close_nanoseconds=timeouts.pool.nanoseconds,
        ),
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
