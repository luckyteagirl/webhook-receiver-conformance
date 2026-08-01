"""Reproducible local quality-attribute benchmark and evidence scorecard."""
# ruff: noqa: EM101, EM102, INP001, PLR0913, PLR0917, PLR2004, S603, TRY003

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Final, Self

import anyio

from webhook_receiver_conformance.config.loader import load_project_config
from webhook_receiver_conformance.config.models import (
    DeliverStep,
    EventConfig,
    ProjectConfig,
)
from webhook_receiver_conformance.http.executor import (
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_RESPONSE_CAPTURE_BYTES,
    DEFAULT_RESPONSE_DRAIN_BYTES,
    HARD_MAX_REQUEST_BYTES,
    HARD_RESPONSE_CAPTURE_BYTES,
)
from webhook_receiver_conformance.journal.schema import (
    create_run_database,
    open_journal_database,
)
from webhook_receiver_conformance.journal.service import JournalService
from webhook_receiver_conformance.manifest.compiler import compile_run_bundle
from webhook_receiver_conformance.reporting.html import HtmlReportDocument
from webhook_receiver_conformance.reporting.json_reports import (
    JsonReportArtifacts,
    ReportCausalIndex,
)
from webhook_receiver_conformance.reporting.writer import ReportPayloads, ReportWriter
from webhook_receiver_conformance.runtime.cancellation import run_interruptibly
from webhook_receiver_conformance.scenario.validate import validate_project_semantics

if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Sequence

BENCHMARK_SCHEMA_VERSION: Final = "1.0"
RUN_ID: Final = "00000000-0000-4000-8000-000000000807"
MANIFEST_ID: Final = "a" * 64
TIMESTAMP: Final = "2026-07-27T12:34:56.000000Z"
DIGEST: Final = f"sha256:{'b' * 64}"
SECRET_FINGERPRINT: Final = f"sha256:{'c' * 64}"
AUTHORITY_NOTE: Final = (
    "P0 gates use specification/05-product-requirements.md and machine/requirements.yaml; "
    "the stricter, conflicting specification/24 table is retained as secondary evidence."
)


@dataclass(frozen=True, slots=True)
class Evidence:
    """One requirement-linked measured boundary."""

    requirement_id: str
    test_id: str
    metric: str
    observed: float
    budget: float
    unit: str
    samples: int
    passed: bool
    corpus: str
    details: dict[str, object]


@dataclass(frozen=True, slots=True)
class _TrackedResource:
    entered: anyio.Event
    closed: bool = False

    async def __aenter__(self) -> Self:
        self.entered.set()
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        del exc_type, exc, traceback
        object.__setattr__(self, "closed", True)


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        raise ValueError("a percentile requires at least one sample")
    if not 0 < percentile <= 1:
        raise ValueError("percentile must be in (0, 1]")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percentile) - 1)]


def _command_path() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    adjacent = Path(sys.executable).with_name(f"webhook-conformance{suffix}")
    if adjacent.is_file():
        return adjacent
    located = shutil.which("webhook-conformance")
    if located is None:
        raise RuntimeError("the installed webhook-conformance command is unavailable")
    return Path(located)


def _timed_command(argv: Sequence[str], *, cwd: Path | None = None) -> float:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        tuple(argv),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if completed.returncode != 0:
        output_digest = hashlib.sha256(completed.stdout + completed.stderr).hexdigest()
        message = (
            f"benchmark command exited {completed.returncode}; "
            f"sanitized output digest sha256:{output_digest}"
        )
        raise RuntimeError(message)
    return elapsed_ms


def _startup_samples(command: Path, *, count: int = 30) -> tuple[float, ...]:
    argv = (str(command), "version")
    _timed_command(argv)
    return tuple(_timed_command(argv) for _ in range(count))


def _minimal_validation_samples(
    command: Path,
    root: Path,
    *,
    count: int = 10,
) -> tuple[float, ...]:
    project = root / "validation-project"
    _timed_command((str(command), "init", str(project)))
    prefix = b'{"payload":"'
    suffix = b'"}'
    fixture = prefix + (b"x" * (4096 - len(prefix) - len(suffix))) + suffix
    (project / "fixtures" / "payment_succeeded.json").write_bytes(fixture)
    argv = (
        str(command),
        "validate",
        "--config",
        str(project / "webhook-conformance.yaml"),
    )
    _timed_command(argv)
    return tuple(_timed_command(argv) for _ in range(count))


def _corpus_config(
    root: Path,
    *,
    events: int,
    attempts_per_event: int,
) -> ProjectConfig:
    loaded = load_project_config("examples/project-config.minimal.yaml")
    if loaded.config is None:
        raise RuntimeError("the locked minimal configuration did not validate")
    base = loaded.config
    fixture_path = root / "fixture.json"
    fixture_path.write_bytes(
        b'{"id":"evt_benchmark","type":"benchmark.event","payload":"' + (b"x" * 961) + b'"}'
    )
    fixture = base.fixtures[0].model_copy(update={"path": fixture_path.name})
    base_step = base.scenarios[0].steps[0]
    if type(base_step) is not DeliverStep:
        raise RuntimeError("the locked planning fixture lacks a delivery step")
    event_models = tuple(
        EventConfig(id=f"event_{index:04d}", fixture=fixture.id) for index in range(events)
    )
    steps = tuple(
        DeliverStep(
            deliver=base_step.deliver.model_copy(
                update={
                    "event": event.id,
                    "count": attempts_per_event,
                    "signer": None,
                }
            )
        )
        for event in event_models
    )
    assertion = base.scenarios[0].assertions[0]
    selected_attempt = assertion.attempt.model_copy(update={"event": event_models[0].id})
    scenario = base.scenarios[0].model_copy(
        update={
            "events": event_models,
            "steps": steps,
            "assertions": (assertion.model_copy(update={"attempt": selected_attempt}),),
        }
    )
    limits = base.limits.model_copy(
        update={
            "max_events": events,
            "max_attempts": events * attempts_per_event,
        }
    )
    config = base.model_copy(
        update={
            "fixtures": (fixture,),
            "limits": limits,
            "scenarios": (scenario,),
        }
    )
    validation = validate_project_semantics(config)
    if not validation.ok:
        codes = ",".join(str(item.code) for item in validation.diagnostics)
        raise RuntimeError(f"locked planning corpus failed semantic validation: {codes}")
    if (
        validation.total_events != events
        or validation.total_planned_attempts != events * attempts_per_event
    ):
        raise RuntimeError("locked planning corpus totals changed")
    return config


def _compile_once(config: ProjectConfig, root: Path, name: str) -> float:
    started = time.perf_counter_ns()
    bundle = compile_run_bundle(
        config,
        project_root=root,
        bundle_directory=root / name,
        created_at=TIMESTAMP,
        seed="task-0807-performance-seed",
        python_version="3.12",
        dependencies_digest=DIGEST,
        secret_fingerprints={"env:WEBHOOK_TEST_SECRET": SECRET_FINGERPRINT},
        materialize=False,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    expected_attempts = config.limits.max_attempts
    observed_attempts = sum(
        len(delivery.attempt_plan)
        for scenario in bundle.manifest.scenarios
        for delivery in scenario.deliveries
    )
    if observed_attempts != expected_attempts:
        raise RuntimeError("compiled planning corpus has the wrong attempt count")
    return elapsed_ms


def _planning_samples(
    config: ProjectConfig,
    root: Path,
    *,
    count: int = 10,
) -> tuple[float, ...]:
    _compile_once(config, root, "plan-authoritative")
    return tuple(_compile_once(config, root, "plan-authoritative") for _ in range(count))


def _peak_rss_bytes() -> int:
    if os.name == "nt":
        command = (
            f"$value=(Get-Process -Id {os.getpid()}).PeakWorkingSet64; [Console]::Out.Write($value)"
        )
        powershell = shutil.which("powershell")
        if powershell is None:
            raise RuntimeError("PowerShell is required for Windows RSS measurement")
        completed = subprocess.run(
            (powershell, "-NoProfile", "-NonInteractive", "-Command", command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            timeout=10,
            text=True,
        )
        return int(completed.stdout)
    status = Path("/proc/self/status")
    if status.is_file():
        for line in status.read_text(encoding="ascii").splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    import resource  # noqa: PLC0415

    maximum = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return maximum if sys.platform == "darwin" else maximum * 1024


def _planned(prefix: str, suffix: int) -> str:
    return f"{prefix}_{suffix:026d}"


def _seed_journal_graph(connection: sqlite3.Connection, attempts: int) -> None:
    scenario_id = _planned("scenario", 1)
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "INSERT INTO runs (run_id, manifest_id, state, created_at) VALUES (?, ?, 'planned', ?)",
        (RUN_ID, MANIFEST_ID, TIMESTAMP),
    )
    connection.execute(
        "INSERT INTO scenarios (scenario_id, run_id, ordinal, name, state) "
        "VALUES (?, ?, 0, 'benchmark', 'pending')",
        (scenario_id, RUN_ID),
    )
    for index in range(1, attempts + 1):
        event_id = _planned("event", index)
        delivery_id = _planned("delivery", index)
        attempt_id = _planned("attempt", index)
        connection.execute(
            "INSERT INTO events "
            "(event_id, run_id, scenario_id, ordinal, event_type, fixture_blob_hash) "
            "VALUES (?, ?, ?, ?, 'benchmark.event', ?)",
            (event_id, RUN_ID, scenario_id, index - 1, DIGEST),
        )
        connection.execute(
            "INSERT INTO deliveries "
            "(delivery_id, run_id, scenario_id, event_id, ordinal, logical_time_ns, state) "
            "VALUES (?, ?, ?, ?, ?, 0, 'pending')",
            (delivery_id, RUN_ID, scenario_id, event_id, index - 1),
        )
        connection.execute(
            "INSERT INTO attempts "
            "(attempt_id, run_id, scenario_id, event_id, delivery_id, ordinal, state) "
            "VALUES (?, ?, ?, ?, ?, 1, 'scheduled')",
            (attempt_id, RUN_ID, scenario_id, event_id, delivery_id),
        )
    connection.execute("COMMIT")


_ATTEMPT_RECORD_INSERT: Final = """
    INSERT INTO attempt_records (
        record_id, schema_version, run_id, scenario_id, event_id, delivery_id,
        attempt_id, sequence, recorded_at, logical_time_ns, monotonic_elapsed_ns,
        state, classification, request_method, request_url_redacted,
        request_body_sha256, request_byte_length, request_header_names_json,
        response_status, response_body_sha256, response_captured_bytes,
        response_truncated, error_category, error_message_redacted, error_phase,
        response_headers_elapsed_ns
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
"""


def _journal_growth(root: Path, *, attempts: int = 256) -> float:
    run = create_run_database(root / "journal", run_id=RUN_ID)
    connection = open_journal_database(run.database_path)
    _seed_journal_graph(connection, attempts)
    connection.close()
    before = run.database_path.stat().st_size

    connection = open_journal_database(run.database_path)
    scenario_id = _planned("scenario", 1)
    connection.execute("BEGIN IMMEDIATE")
    for index in range(1, attempts + 1):
        event_id = _planned("event", index)
        delivery_id = _planned("delivery", index)
        attempt_id = _planned("attempt", index)
        values = (
            _planned("record", index),
            "1.0",
            RUN_ID,
            scenario_id,
            event_id,
            delivery_id,
            attempt_id,
            index,
            TIMESTAMP,
            0,
            index,
            "acknowledged",
            "receiver_accepted",
            "POST",
            "http://127.0.0.1/webhook",
            DIGEST,
            1024,
            b'["content-type","x-request-id"]',
            204,
            None,
            0,
            0,
            None,
            None,
            None,
            index,
        )
        connection.execute(_ATTEMPT_RECORD_INSERT, values)
    connection.execute("COMMIT")
    connection.close()
    after = run.database_path.stat().st_size
    return max(0, after - before) / attempts


def _report_payloads(attempts: int) -> ReportPayloads:
    deliveries = b"".join(
        (
            json.dumps(
                {
                    "attempt_id": _planned("attempt", index),
                    "classification": "receiver_accepted",
                    "sequence": index,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
        for index in range(1, attempts + 1)
    )
    summary = (
        json.dumps(
            {
                "artifacts": {
                    "assertions": "assertions.jsonl",
                    "deliveries": "deliveries.jsonl",
                    "html": "results.html",
                    "junit": "junit.xml",
                    "manifest": "run-manifest.json",
                    "observations": "observations.jsonl",
                },
                "counts": {
                    "assertions": 0,
                    "attempts": attempts,
                    "observations": 0,
                    "scenarios": 1,
                },
                "exit_code": 0,
                "generated_at": TIMESTAMP,
                "manifest_id": MANIFEST_ID,
                "run_id": RUN_ID,
                "schema_version": "1.0",
                "verdict": "pass",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    json_reports = JsonReportArtifacts(
        manifest_json=(
            json.dumps(
                {"manifest_id": MANIFEST_ID, "schema_version": "1.0"},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode(),
        deliveries_jsonl=deliveries,
        observations_jsonl=b"",
        assertions_jsonl=b"",
        result_summary_json=summary,
        causal_index=ReportCausalIndex(()),
    )
    html = (
        "<!doctype html><html><head>"
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; script-src 'none'\">"
        f"<title>report</title></head><body><p>{attempts}</p></body></html>\n"
    ).encode()
    return ReportPayloads(
        json_reports=json_reports,
        junit_xml=(
            b'<?xml version="1.0" encoding="utf-8"?>'
            + f'<testsuites tests="{attempts}"/>\n'.encode()
        ),
        html_report=HtmlReportDocument(
            content=html,
            sha256=f"sha256:{hashlib.sha256(html).hexdigest()}",
        ),
    )


async def _report_samples_async(
    root: Path,
    *,
    attempts: int,
    count: int,
) -> tuple[float, ...]:
    run = create_run_database(root, run_id=RUN_ID)
    connection = open_journal_database(run.database_path)
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "INSERT INTO runs (run_id, manifest_id, state, created_at) VALUES (?, ?, 'planned', ?)",
        (RUN_ID, MANIFEST_ID, TIMESTAMP),
    )
    connection.execute("COMMIT")
    connection.close()
    samples: list[float] = []
    async with JournalService.open(run.database_path) as service:
        writer = ReportWriter(service=service, run_directory=run.run_directory)
        await writer.regenerate(RUN_ID, _report_payloads(attempts))
        for _ in range(count):
            started = time.perf_counter_ns()
            await writer.regenerate(RUN_ID, _report_payloads(attempts))
            samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return tuple(samples)


def _report_samples(
    root: Path,
    *,
    attempts: int,
    count: int,
) -> tuple[float, ...]:
    return anyio.run(
        partial(
            _report_samples_async,
            root,
            attempts=attempts,
            count=count,
        )
    )


async def _cancellation_sample_async() -> tuple[float, bool]:
    entered = anyio.Event()
    resource = _TrackedResource(entered)

    async def operation() -> None:
        async with resource:
            await anyio.sleep_forever()

    async def interrupt() -> None:
        await entered.wait()

    started = time.perf_counter_ns()
    result = await run_interruptibly(operation, interrupt)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return elapsed_ms, result.interrupted and result.cleanup_completed and resource.closed


def _evidence(
    requirement_id: str,
    test_id: str,
    metric: str,
    observed: float,
    budget: float,
    unit: str,
    samples: int,
    corpus: str,
    **details: object,
) -> Evidence:
    return Evidence(
        requirement_id=requirement_id,
        test_id=test_id,
        metric=metric,
        observed=round(observed, 6),
        budget=budget,
        unit=unit,
        samples=samples,
        passed=observed <= budget,
        corpus=corpus,
        details=details,
    )


def run_benchmarks() -> dict[str, object]:
    """Run all P0 measurements and return one requirement-linked scorecard."""
    command = _command_path()
    with tempfile.TemporaryDirectory(
        prefix=".smoke-benchmark-",
        dir=Path.cwd(),
    ) as temporary:
        root = Path(temporary)
        startup = _startup_samples(command)
        validation = _minimal_validation_samples(command, root)

        authoritative = _corpus_config(root, events=100, attempts_per_event=10)
        planning = _planning_samples(authoritative, root)
        del authoritative
        gc.collect()

        maximum = _corpus_config(root, events=1000, attempts_per_event=5)
        maximum_plan_ms = _compile_once(maximum, root, "plan-maximum")
        del maximum
        gc.collect()
        peak_rss = _peak_rss_bytes()

        growth = _journal_growth(root)
        report = _report_samples(
            root / "reports-authoritative",
            attempts=1000,
            count=5,
        )
        report_rss_before = _peak_rss_bytes()
        maximum_report = _report_samples(
            root / "reports-maximum",
            attempts=5000,
            count=1,
        )
        report_rss_after = _peak_rss_bytes()
        cancellation_ms, streams_closed = anyio.run(_cancellation_sample_async)

    evidence = (
        _evidence(
            "PERF-001",
            "VT-PERF-001",
            "warm_startup_p95",
            _percentile(startup, 0.95),
            1000.0,
            "ms",
            len(startup),
            "webhook-conformance version; warm cache",
            minimum_ms=round(min(startup), 6),
            maximum_ms=round(max(startup), 6),
        ),
        _evidence(
            "PERF-002",
            "VT-PERF-002",
            "plan_100_events_1000_attempts_p95",
            _percentile(planning, 0.95),
            2000.0,
            "ms",
            len(planning),
            "100 events; 1,000 attempt templates; one local 1 KiB fixture",
            network_access=False,
        ),
        _evidence(
            "PERF-003",
            "VT-PERF-003",
            "peak_resident_memory",
            peak_rss / (1024 * 1024),
            256.0,
            "MiB",
            1,
            "maximum 1,000-event/5,000-attempt planning corpus",
            measurement="process peak RSS after corpus compilation",
        ),
        _evidence(
            "PERF-006",
            "VT-PERF-006",
            "journal_growth_per_terminal_attempt",
            growth,
            32768.0,
            "bytes/attempt",
            256,
            "SQLite terminal attempt metadata; raw bodies excluded",
        ),
        _evidence(
            "PERF-007",
            "VT-PERF-007",
            "all_format_report_regeneration_p95",
            _percentile(report, 0.95),
            5000.0,
            "ms",
            len(report),
            "1,000 attempts; seven static report artifacts; no raw bodies",
            network_access=False,
        ),
        _evidence(
            "PERF-008",
            "VT-PERF-008",
            "cancellation_cleanup",
            cancellation_ms,
            5000.0,
            "ms",
            1,
            "in-flight structured task with tracked response resource",
            response_streams_closed=streams_closed,
        ),
    )
    evidence_wire = [asdict(item) for item in evidence]
    all_passed = all(item.passed for item in evidence) and streams_closed
    secondary = {
        "authority": "specification/24-quality-attributes-and-budgets.md",
        "gating": False,
        "reason": AUTHORITY_NOTE,
        "measurements": [
            {
                "metric": "warm_startup_p95",
                "observed": round(_percentile(startup, 0.95), 6),
                "budget": 750.0,
                "unit": "ms",
                "passed": _percentile(startup, 0.95) <= 750.0,
            },
            {
                "metric": "minimal_validation_p95",
                "observed": round(_percentile(validation, 0.95), 6),
                "budget": 1500.0,
                "unit": "ms",
                "samples": len(validation),
                "passed": _percentile(validation, 0.95) <= 1500.0,
            },
            {
                "metric": "plan_1000_events_5000_attempts",
                "observed": round(maximum_plan_ms, 6),
                "budget": 10000.0,
                "unit": "ms",
                "passed": maximum_plan_ms <= 10000.0,
            },
            {
                "metric": "journal_growth_per_terminal_attempt",
                "observed": round(growth, 6),
                "budget": 4096.0,
                "unit": "bytes/attempt",
                "passed": growth <= 4096.0,
            },
            {
                "metric": "report_5000_attempts",
                "observed": round(maximum_report[0], 6),
                "budget": 5000.0,
                "unit": "ms",
                "passed": maximum_report[0] <= 5000.0,
            },
            {
                "metric": "report_incremental_peak_rss",
                "observed": round(
                    max(0, report_rss_after - report_rss_before) / (1024 * 1024),
                    6,
                ),
                "budget": 128.0,
                "unit": "MiB",
                "passed": report_rss_after - report_rss_before <= 128 * 1024 * 1024,
            },
            {
                "metric": "request_and_response_caps",
                "observed": {
                    "default_request_bytes": DEFAULT_MAX_REQUEST_BYTES,
                    "hard_request_bytes": HARD_MAX_REQUEST_BYTES,
                    "default_response_capture_bytes": DEFAULT_RESPONSE_CAPTURE_BYTES,
                    "hard_response_capture_bytes": HARD_RESPONSE_CAPTURE_BYTES,
                    "response_drain_bytes": DEFAULT_RESPONSE_DRAIN_BYTES,
                },
                "passed": (
                    DEFAULT_MAX_REQUEST_BYTES == 1_048_576
                    and HARD_MAX_REQUEST_BYTES == 16_777_216
                    and DEFAULT_RESPONSE_CAPTURE_BYTES == 65_536
                    and HARD_RESPONSE_CAPTURE_BYTES == 1_048_576
                    and DEFAULT_RESPONSE_DRAIN_BYTES == 1_048_576
                ),
            },
        ],
    }
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "benchmark": "webhook-receiver-conformance-quality-attributes",
        "status": "pass" if all_passed else "fail",
        "load_test_claim": False,
        "network_access": False,
        "authority_note": AUTHORITY_NOTE,
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "executable": command.name,
        },
        "evidence": evidence_wire,
        "test_017": {
            "requirement_id": "TEST-017",
            "test_id": "VT-TEST-017",
            "p0_budget_count": len(evidence),
            "all_have_reproducible_evidence": all_passed,
        },
        "secondary_quality_attribute_diagnostics": secondary,
    }


def _write_json_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        scorecard = run_benchmarks()
    except Exception as error:  # noqa: BLE001
        scorecard = {
            "schema_version": BENCHMARK_SCHEMA_VERSION,
            "benchmark": "webhook-receiver-conformance-quality-attributes",
            "status": "error",
            "diagnostic": {
                "code": "BENCHMARK_EXECUTION_FAILED",
                "error_type": type(error).__name__,
                "message": str(error)[:4096],
            },
        }
    if arguments.output is not None:
        _write_json_atomic(arguments.output, scorecard)
    sys.stdout.write(json.dumps(scorecard, sort_keys=True, allow_nan=False) + "\n")
    return 0 if scorecard.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
