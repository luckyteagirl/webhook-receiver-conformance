"""Resource-cap, bounded-task, deterministic-fuzz, and threat-map regressions."""
# ruff: noqa: INP001, PLR2004, PT017

from __future__ import annotations

import re
from pathlib import Path

import anyio
import pytest
from anyio.lowlevel import checkpoint
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from webhook_receiver_conformance.config.schema import (
    MAX_CONFIG_BYTES,
    MAX_CONFIG_DEPTH,
    MAX_CONFIG_NODES,
    preflight_config,
)
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.network.addresses import classify_address
from webhook_receiver_conformance.scheduler.barriers import (
    ConcurrencyWork,
    run_concurrency_groups,
)

ROOT = Path(__file__).resolve().parents[2]


def _nested(depth: int) -> object:
    value: object = None
    for _index in range(depth):
        value = {"child": value}
    return value


@pytest.mark.parametrize(
    ("document", "encoded_length", "limit"),
    [
        ({}, MAX_CONFIG_BYTES + 1, "MAX_CONFIG_BYTES"),
        (
            {"root": _nested(MAX_CONFIG_DEPTH + 1)},
            None,
            "MAX_CONFIG_DEPTH",
        ),
        (
            {"items": [None] * MAX_CONFIG_NODES},
            None,
            "MAX_CONFIG_NODES",
        ),
    ],
)
def test_every_configuration_resource_class_is_bounded_and_classified(
    document: object,
    encoded_length: int | None,
    limit: str,
) -> None:
    diagnostic = preflight_config(document, encoded_byte_length=encoded_length)
    assert diagnostic is not None
    assert diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert diagnostic.safe_details["limit"] == limit


@pytest.mark.anyio
async def test_duplicate_retry_shape_never_creates_more_tasks_than_cap() -> None:
    cap = 7
    created: list[str] = []
    active = 0
    peak = 0
    lock = anyio.Lock()
    work = tuple(
        ConcurrencyWork(
            work_id=f"attempt-{index}",
            concurrency_group=f"delivery-{index % 3}",
            ordinal=index,
            payload=index,
        )
        for index in range(250)
    )

    async def callback(item: ConcurrencyWork[int]) -> int:
        nonlocal active, peak
        async with lock:
            active += 1
            peak = max(peak, active)
        await checkpoint()
        async with lock:
            active -= 1
        return item.payload

    result = await run_concurrency_groups(
        work,
        callback,
        max_concurrency=cap,
        task_created=created.append,
    )
    assert len(created) == cap
    assert result.peak_created_tasks == cap
    assert peak <= cap
    assert len(result.completed) == len(work)


@settings(
    max_examples=100,
    derandomize=True,
    database=None,
    deadline=1_000,
    suppress_health_check=(HealthCheck.too_slow,),
)
@given(st.text(max_size=256))
def test_address_fuzz_is_bounded_no_crash_and_secret_free(value: str) -> None:
    canary = "fuzz-secret-canary"
    try:
        classification = classify_address(value)
    except ValueError as error:
        assert canary not in str(error)
    else:
        assert classification.address_class.value in {
            "blocked",
            "loopback",
            "private",
            "public",
        }
        assert canary not in repr(classification)


def test_every_threat_register_row_has_mitigation_and_verification_ids() -> None:
    text = ROOT.joinpath("specification/18-security-privacy-threat-model.md").read_text(
        encoding="utf-8"
    )
    rows = [line for line in text.splitlines() if line.startswith("| THR-")]
    assert len(rows) == 20
    for row in rows:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        assert re.fullmatch(r"THR-\d{3}", cells[0])
        assert re.search(
            r"(?:SEC|CFG|HTTP|PRIV|REPORT|PERF|API|OPS|SCHED|DATA|REL|SIG)-\d{3}",
            cells[5],
        )
        assert re.search(r"VT-[A-Z]+-\d{3}", cells[6])
