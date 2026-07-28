"""Atomic, offline, idempotent report-regeneration integration contract."""
# ruff: noqa: EM101, INP001, PLR2004, TRY003

from __future__ import annotations

import hashlib
import os
import socket
import stat
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Final

import pytest

from webhook_receiver_conformance.journal.schema import (
    RunDatabase,
    create_run_database,
)
from webhook_receiver_conformance.journal.service import (
    JournalService,
    JournalStatement,
    StatementOperation,
)
from webhook_receiver_conformance.reporting.html import (
    HtmlReportDocument,
)
from webhook_receiver_conformance.reporting.json_reports import (
    JsonReportArtifacts,
    ReportCausalIndex,
)
from webhook_receiver_conformance.reporting.writer import (
    BUILTIN_REPORTER_CONTRACTS,
    BUILTIN_REPORTER_IMPLEMENTATIONS,
    GOLDEN_COMPATIBILITY_REVIEW_MARKER,
    ReportContractError,
    ReportPathError,
    ReportPayloads,
    ReportWriter,
    validate_reporter_contracts,
)

if TYPE_CHECKING:
    from pathlib import Path

    from webhook_receiver_conformance.journal.artifacts import ArtifactRecord

RUN_ID: Final = "00000000-0000-4000-8000-000000000605"
MANIFEST_ID: Final = "a" * 64
TIMESTAMP: Final = "2026-07-27T12:34:56.000000Z"
REPORT_PATHS: Final = (
    "assertions.jsonl",
    "deliveries.jsonl",
    "junit.xml",
    "observations.jsonl",
    "result-summary.json",
    "results.html",
    "run-manifest.json",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _run_database(tmp_path: Path) -> RunDatabase:
    return create_run_database(tmp_path, run_id=RUN_ID)


async def _seed_run(service: JournalService) -> None:
    await service.execute(
        StatementOperation(
            JournalStatement(
                """
                INSERT INTO runs (run_id, manifest_id, state, created_at)
                VALUES (?, ?, 'planned', ?)
                """,
                (RUN_ID, MANIFEST_ID, TIMESTAMP),
            )
        )
    )


async def _run_state(service: JournalService) -> str:
    result = await service.execute(
        StatementOperation(
            JournalStatement(
                "SELECT state FROM runs WHERE run_id = ?",
                (RUN_ID,),
            )
        )
    )
    assert len(result.rows) == 1
    value = result.rows[0][0]
    assert type(value) is str
    return value


async def _artifact_count(service: JournalService) -> int:
    result = await service.execute(
        StatementOperation(
            JournalStatement(
                "SELECT COUNT(*) FROM artifacts WHERE run_id = ?",
                (RUN_ID,),
            )
        )
    )
    assert len(result.rows) == 1
    value = result.rows[0][0]
    assert type(value) is int
    return value


def _payloads(*, attempts: int = 1, version: int = 1) -> ReportPayloads:
    delivery_line = (
        b'{"attempt_id":"attempt_00000000000000000000000001",'
        b'"classification":"receiver_rejected","sequence":1}\n'
    )
    deliveries = delivery_line * attempts
    summary = (
        "{"
        f'"artifacts":{{"assertions":"assertions.jsonl","deliveries":"deliveries.jsonl",'
        f'"html":"results.html","junit":"junit.xml","manifest":"run-manifest.json",'
        f'"observations":"observations.jsonl"}},'
        f'"counts":{{"assertions":0,"attempts":{attempts},'
        '"observations":0,"scenarios":1},'
        '"exit_code":1,'
        f'"generated_at":"{TIMESTAMP}",'
        f'"manifest_id":"{MANIFEST_ID}",'
        f'"run_id":"{RUN_ID}",'
        '"schema_version":"1.0",'
        '"verdict":"receiver_failure",'
        f'"writer_test_version":{version}'
        "}\n"
    ).encode()
    json_reports = JsonReportArtifacts(
        manifest_json=(
            f'{{"manifest_id":"{MANIFEST_ID}","schema_version":"1.0",'
            f'"writer_test_version":{version}}}\n'
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
        "<title>report</title></head><body>"
        f"<p>{attempts}:{version}</p></body></html>\n"
    ).encode()
    html_document = HtmlReportDocument(
        content=html,
        sha256=f"sha256:{hashlib.sha256(html).hexdigest()}",
    )
    return ReportPayloads(
        json_reports=json_reports,
        junit_xml=(
            b'<?xml version="1.0" encoding="utf-8"?>'
            + f'<testsuites tests="{attempts}" writer_test_version="{version}"/>\n'.encode()
        ),
        html_report=html_document,
    )


def _digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _assert_records_match_files(
    run_directory: Path,
    records: tuple[ArtifactRecord, ...],
) -> None:
    assert tuple(record.relative_path for record in records) == REPORT_PATHS
    for record in records:
        path = run_directory / record.relative_path
        assert path.is_file()
        assert record.byte_length == path.stat().st_size
        assert record.sha256 == _digest(path)
        assert record.generated_at == TIMESTAMP
        assert record.input_watermark is not None
        assert record.renderer_version == "reporter-1.0"


@pytest.mark.anyio
async def test_regeneration_is_offline_transactional_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run_database(tmp_path)
    payloads = _payloads()
    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        before_state = await _run_state(service)
        writer = ReportWriter(service=service, run_directory=run.run_directory)

        def deny_socket(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("report regeneration attempted network access")

        monkeypatch.setattr(socket, "create_connection", deny_socket)
        monkeypatch.setattr(socket, "getaddrinfo", deny_socket)
        first = await writer.regenerate(RUN_ID, payloads)
        first_bytes = {path: (run.run_directory / path).read_bytes() for path in REPORT_PATHS}
        second = await writer.regenerate(RUN_ID, payloads)
        after_state = await _run_state(service)

    assert before_state == after_state == "planned"
    assert first == second
    assert second.normalized_digest.startswith("sha256:")
    assert first_bytes == {path: (run.run_directory / path).read_bytes() for path in REPORT_PATHS}
    _assert_records_match_files(run.run_directory, second.records)


class _InjectedTerminationError(RuntimeError):
    pass


@dataclass(slots=True)
class _TerminateAt:
    phase: str
    path: str

    def __call__(self, phase: str, relative_path: str) -> None:
        if phase == self.phase and relative_path == self.path:
            raise _InjectedTerminationError("deterministic report termination")


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("phase", "expected"),
    [
        ("temporary_fsynced", b'{"old":"valid"}\n'),
        ("target_replaced", _payloads().json_reports.result_summary_json),
    ],
)
async def test_termination_preserves_old_or_complete_new_target(
    tmp_path: Path,
    phase: str,
    expected: bytes,
) -> None:
    run = _run_database(tmp_path)
    target = run.run_directory / "result-summary.json"
    target.write_bytes(b'{"old":"valid"}\n')
    target.chmod(0o600)
    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        writer = ReportWriter(
            service=service,
            run_directory=run.run_directory,
            checkpoint=_TerminateAt(phase, "result-summary.json"),
        )
        with pytest.raises(_InjectedTerminationError, match="deterministic"):
            await writer.regenerate(RUN_ID, _payloads())
        assert await _artifact_count(service) == 0

    assert target.read_bytes() == expected
    assert not tuple(run.run_directory.glob(".*.tmp-*"))


@pytest.mark.anyio
async def test_symlink_target_cannot_read_or_overwrite_external_canary(
    tmp_path: Path,
) -> None:
    run = _run_database(tmp_path)
    outside = tmp_path / "outside-canary.html"
    outside_content = b"external-secret-canary"
    outside.write_bytes(outside_content)
    link = run.run_directory / "results.html"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")

    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        writer = ReportWriter(service=service, run_directory=run.run_directory)
        with pytest.raises(ReportPathError) as captured:
            await writer.regenerate(RUN_ID, _payloads())
        assert await _artifact_count(service) == 0

    assert outside.read_bytes() == outside_content
    assert "external-secret-canary" not in str(captured.value)


@pytest.mark.anyio
async def test_regeneration_tightens_posix_permissions(
    tmp_path: Path,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX permission bits are not authoritative on this host")
    run = _run_database(tmp_path)
    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        writer = ReportWriter(service=service, run_directory=run.run_directory)
        result = await writer.regenerate(RUN_ID, _payloads())

    assert stat.S_IMODE(run.run_directory.stat().st_mode) == 0o700
    for record in result.records:
        assert stat.S_IMODE((run.run_directory / record.relative_path).stat().st_mode) == 0o600


def test_reporter_contracts_require_registration_and_review_marker() -> None:
    with pytest.raises(ReportContractError, match="differ"):
        validate_reporter_contracts(
            (*BUILTIN_REPORTER_IMPLEMENTATIONS, "unregistered-v1"),
            BUILTIN_REPORTER_CONTRACTS,
        )
    missing_review = replace(
        BUILTIN_REPORTER_CONTRACTS[0],
        compatibility_review_marker="missing-review",
    )
    with pytest.raises(ReportContractError, match="review marker"):
        validate_reporter_contracts(
            BUILTIN_REPORTER_IMPLEMENTATIONS,
            (missing_review, *BUILTIN_REPORTER_CONTRACTS[1:]),
        )
    assert all(
        registration.compatibility_review_marker == GOLDEN_COMPATIBILITY_REVIEW_MARKER
        for registration in BUILTIN_REPORTER_CONTRACTS
    )


@pytest.mark.anyio
async def test_thousand_attempt_corpus_stays_within_regeneration_budget(
    tmp_path: Path,
) -> None:
    run = _run_database(tmp_path)
    payloads = _payloads(attempts=1_000)
    durations: list[float] = []
    records: tuple[ArtifactRecord, ...] = ()
    async with JournalService.open(run.database_path) as service:
        await _seed_run(service)
        writer = ReportWriter(service=service, run_directory=run.run_directory)
        for _ in range(10):
            started = time.perf_counter()
            result = await writer.regenerate(RUN_ID, payloads)
            records = result.records
            durations.append(time.perf_counter() - started)

    ordered = sorted(durations)
    percentile_95 = ordered[min(len(ordered) - 1, round(len(ordered) * 0.95) - 1)]
    assert percentile_95 < 5.0
    _assert_records_match_files(run.run_directory, records)
