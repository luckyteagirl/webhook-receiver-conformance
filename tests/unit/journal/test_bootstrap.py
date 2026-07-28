"""Atomic manifest-to-journal bootstrap contract."""
# ruff: noqa: INP001, S608

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, cast

import pytest

from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.enums import (
    AttemptClassification,
    AttemptState,
)
from webhook_receiver_conformance.domain.hashing import compute_manifest_id
from webhook_receiver_conformance.domain.identifiers import (
    FreshIdKind,
    PlannedIdKind,
    new_fresh_id,
    planned_id,
)
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.journal.bootstrap import (
    JournalBootstrapError,
    JournalBootstrapRequest,
    JournalCompletionRequest,
    JournalLifecycleRepository,
    SeededAttempt,
    finalize,
    initialize,
)
from webhook_receiver_conformance.journal.service import (
    BatchOperation,
    JournalService,
    JournalStatement,
)
from webhook_receiver_conformance.manifest.models import RunManifest

if TYPE_CHECKING:
    from pathlib import Path

RUN_ID = "12345678-1234-4234-9234-123456789abc"
CREATED_AT = "2026-07-27T20:00:00Z"
SEED_HASH = b"\x42" * 32
GENERATOR = ContextGenerator.from_normalized_seed_hash(SEED_HASH)


def _manifest(*, unknown_delivery_event: bool = False) -> RunManifest:
    scenario_id = planned_id(
        GENERATOR,
        PlannedIdKind.SCENARIO,
        ("bootstrap", "scenario", "0"),
    )
    first_event_id = planned_id(
        GENERATOR,
        PlannedIdKind.EVENT,
        (scenario_id, "event", "0"),
    )
    second_event_id = planned_id(
        GENERATOR,
        PlannedIdKind.EVENT,
        (scenario_id, "event", "1"),
    )
    first_delivery_id = planned_id(
        GENERATOR,
        PlannedIdKind.DELIVERY,
        (scenario_id, "delivery", "0"),
    )
    second_delivery_id = planned_id(
        GENERATOR,
        PlannedIdKind.DELIVERY,
        (scenario_id, "delivery", "1"),
    )
    assertion_id = planned_id(
        GENERATOR,
        PlannedIdKind.ASSERTION,
        (scenario_id, "assertion", "0"),
    )
    fixture_digest = f"sha256:{'1' * 64}"
    headers_digest = f"sha256:{'2' * 64}"
    wire: dict[str, object] = {
        "schema_version": "1.0",
        "manifest_id": "0" * 64,
        "created_at": CREATED_AT,
        "tool": {"version": "0.1.0", "python": "3.12"},
        "generator": {
            "algorithm": GENERATOR.algorithm_id,
            "seed_fingerprint": f"sha256:{GENERATOR.fingerprint}",
            "normalized_seed_hash_hex": SEED_HASH.hex(),
        },
        "configuration_digest": f"sha256:{'3' * 64}",
        "environment": {
            "os": "test",
            "architecture": "test",
            "timezone": "UTC",
        },
        "target_policy": {
            "profile": "loopback",
            "authorized_host": "127.0.0.1",
            "authorized_port": 8080,
        },
        "blobs": [
            {
                "sha256": fixture_digest,
                "byte_length": 2,
                "media_type": "application/json",
            }
        ],
        "scenarios": [
            {
                "scenario_id": scenario_id,
                "events": [
                    {
                        "event_id": first_event_id,
                        "event_type": "payment.created",
                        "fixture_blob": fixture_digest,
                    },
                    {
                        "event_id": second_event_id,
                        "event_type": "payment.updated",
                        "fixture_blob": fixture_digest,
                        "depends_on": [first_event_id],
                    },
                ],
                "deliveries": [
                    {
                        "delivery_id": first_delivery_id,
                        "event_id": (
                            planned_id(
                                GENERATOR,
                                PlannedIdKind.EVENT,
                                (scenario_id, "unknown"),
                            )
                            if unknown_delivery_event
                            else first_event_id
                        ),
                        "logical_time_ns": 11,
                        "ordinal": 0,
                        "attempt_plan": [
                            {
                                "ordinal": 1,
                                "not_before_logical_ns": 11,
                                "request_blob": fixture_digest,
                                "headers_sha256": headers_digest,
                            },
                            {
                                "ordinal": 2,
                                "not_before_logical_ns": 21,
                                "request_blob": fixture_digest,
                                "headers_sha256": headers_digest,
                                "conditional_on": "transport_failed",
                            },
                        ],
                    },
                    {
                        "delivery_id": second_delivery_id,
                        "event_id": second_event_id,
                        "logical_time_ns": 5,
                        "ordinal": 1,
                        "attempt_plan": [
                            {
                                "ordinal": 1,
                                "not_before_logical_ns": 5,
                                "request_blob": fixture_digest,
                                "headers_sha256": headers_digest,
                            }
                        ],
                    },
                ],
                "assertions": [
                    {
                        "assertion_id": assertion_id,
                        "type": "processing-count",
                        "observer": "receiver-state",
                        "parameters": {"minimum": 2},
                    }
                ],
            }
        ],
    }
    wire["manifest_id"] = compute_manifest_id(wire)
    return RunManifest.from_wire(wire)


def _request(
    manifest: RunManifest,
    *,
    owner_epoch: int = 7,
    seeded_attempts: tuple[SeededAttempt, ...] | None = None,
) -> JournalBootstrapRequest:
    return JournalBootstrapRequest(
        run_id=RUN_ID,
        owner_epoch=owner_epoch,
        manifest=manifest,
        created_at=CREATED_AT,
        seeded_attempts=seeded_attempts,
    )


def _rows(
    database: Path,
    sql: str,
    parameters: tuple[object, ...] = (),
) -> tuple[tuple[object, ...], ...]:
    connection = sqlite3.connect(database)
    try:
        return cast(
            "tuple[tuple[object, ...], ...]",
            tuple(connection.execute(sql, parameters)),
        )
    finally:
        connection.close()


async def _prepare_terminal_attempt(
    service: JournalService,
    manifest: RunManifest,
    *,
    attempt_id: str,
    state: AttemptState,
    classification: AttemptClassification,
) -> tuple[str, str, str]:
    scenario = manifest.scenarios[0]
    delivery = scenario.deliveries[0]
    assertion = scenario.assertions[0]
    attempt_plan_id = planned_id(
        GENERATOR,
        PlannedIdKind.ATTEMPT_PLAN,
        (scenario.scenario_id, delivery.delivery_id, "1"),
    )
    await service.execute(
        BatchOperation(
            (
                JournalStatement(
                    "UPDATE runs SET state = 'running' WHERE run_id = ?",
                    (RUN_ID,),
                ),
                JournalStatement(
                    "UPDATE scenarios SET state = 'running' WHERE scenario_id = ?",
                    (scenario.scenario_id,),
                ),
                JournalStatement(
                    "UPDATE deliveries SET state = 'active' WHERE delivery_id = ?",
                    (delivery.delivery_id,),
                ),
                JournalStatement(
                    "UPDATE deliveries SET state = 'skipped' "
                    "WHERE scenario_id = ? AND delivery_id <> ?",
                    (scenario.scenario_id, delivery.delivery_id),
                ),
                JournalStatement(
                    "UPDATE assertions SET state = 'passed' WHERE assertion_id = ?",
                    (assertion.assertion_id,),
                ),
                JournalStatement(
                    """
                    INSERT INTO attempts (
                        attempt_id, run_id, scenario_id, event_id, delivery_id,
                        attempt_plan_id, ordinal, state, outcome_category,
                        owner_epoch, terminal_recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, 7, ?)
                    """,
                    (
                        attempt_id,
                        RUN_ID,
                        scenario.scenario_id,
                        delivery.event_id,
                        delivery.delivery_id,
                        attempt_plan_id,
                        state.value,
                        classification.value,
                        CREATED_AT,
                    ),
                ),
            )
        )
    )
    return scenario.scenario_id, delivery.event_id, delivery.delivery_id


@pytest.mark.anyio
async def test_initialize_seeds_complete_manifest_and_initial_schedules(
    tmp_path: Path,
) -> None:
    database = tmp_path / "journal.sqlite3"
    manifest = _manifest()
    async with JournalService.create(database) as service:
        first = await initialize(service, _request(manifest))

    scenario = manifest.scenarios[0]
    first_due_delivery = scenario.deliveries[1]
    expected_attempt_plan = planned_id(
        GENERATOR,
        PlannedIdKind.ATTEMPT_PLAN,
        (scenario.scenario_id, first_due_delivery.delivery_id, "1"),
    )
    assert first.attempt_plan_id == expected_attempt_plan
    assert first.scenario_ordinal == 0
    assert first.step_ordinal == first.delivery_ordinal == 1
    assert first.attempt_ordinal == 1
    assert first.condition_json is None
    assert _rows(
        database,
        "SELECT run_id, manifest_id, state, owner_epoch, created_at FROM runs",
    ) == ((RUN_ID, manifest.manifest_id, "planned", 7, CREATED_AT),)
    assert _rows(
        database,
        "SELECT scenario_id, ordinal, name, state, required FROM scenarios",
    ) == ((scenario.scenario_id, 0, scenario.scenario_id, "pending", 1),)
    assert _rows(database, "SELECT COUNT(*) FROM events") == ((2,),)
    assert _rows(database, "SELECT COUNT(*) FROM event_dependencies") == ((1,),)
    assert _rows(
        database,
        "SELECT ordinal, step_ordinal, logical_time_ns, state, required "
        "FROM deliveries ORDER BY ordinal",
    ) == ((0, 0, 11, "pending", 1), (1, 1, 5, "pending", 1))
    assert _rows(
        database,
        "SELECT type, policy_json, required, state FROM assertions",
    ) == (
        (
            "processing-count",
            b'{"observer":"receiver-state","parameters":{"minimum":2}}',
            1,
            "pending",
        ),
    )
    assert _rows(
        database,
        "SELECT logical_time_ns, scenario_ordinal, step_ordinal, "
        "delivery_ordinal, attempt_ordinal, condition_json, consumed_at "
        "FROM schedule_entries ORDER BY logical_time_ns",
    ) == ((5, 0, 1, 1, 1, None, None), (11, 0, 0, 0, 1, None, None))
    assert _rows(database, "SELECT COUNT(*) FROM attempts") == ((0,),)


@pytest.mark.anyio
async def test_initialize_is_idempotent_and_rejects_different_owner(
    tmp_path: Path,
) -> None:
    database = tmp_path / "journal.sqlite3"
    manifest = _manifest()
    request = _request(manifest)
    async with JournalService.create(database) as service:
        first = await initialize(service, request)
        replay = await initialize(service, request)
        with pytest.raises(JournalBootstrapError):
            await initialize(service, _request(manifest, owner_epoch=8))

    assert replay == first
    for table, expected in (
        ("runs", 1),
        ("scenarios", 1),
        ("events", 2),
        ("event_dependencies", 1),
        ("deliveries", 2),
        ("assertions", 1),
        ("schedule_entries", 2),
    ):
        assert _rows(database, f"SELECT COUNT(*) FROM {table}") == ((expected,),)
    assert _rows(database, "SELECT owner_epoch FROM runs") == ((7,),)


@pytest.mark.anyio
async def test_initialize_accepts_explicit_deterministic_identities(
    tmp_path: Path,
) -> None:
    database = tmp_path / "journal.sqlite3"
    manifest = _manifest()
    scenario = manifest.scenarios[0]
    supplied = tuple(
        SeededAttempt(
            schedule_entry_id=f"accepted.initial.{delivery.ordinal}",
            attempt_plan_id=planned_id(
                GENERATOR,
                PlannedIdKind.ATTEMPT_PLAN,
                ("accepted", scenario.scenario_id, delivery.delivery_id),
            ),
            scenario_ordinal=0,
            step_ordinal=delivery.ordinal,
            delivery_ordinal=delivery.ordinal,
            attempt_ordinal=1,
        )
        for delivery in scenario.deliveries
    )
    async with JournalService.create(database) as service:
        first = await initialize(
            service,
            _request(manifest, seeded_attempts=supplied),
        )

    assert first == supplied[1]
    assert _rows(
        database,
        "SELECT schedule_entry_id, entity_id FROM schedule_entries ORDER BY delivery_ordinal",
    ) == tuple((identity.schedule_entry_id, identity.attempt_plan_id) for identity in supplied)


@pytest.mark.anyio
async def test_invalid_manifest_graph_leaves_fresh_journal_empty(
    tmp_path: Path,
) -> None:
    database = tmp_path / "journal.sqlite3"
    request = _request(_manifest(unknown_delivery_event=True))
    async with JournalService.create(database) as service:
        with pytest.raises(ValueError, match="delivery event"):
            await initialize(service, request)

    assert _rows(database, "SELECT COUNT(*) FROM runs") == ((0,),)
    assert _rows(database, "SELECT COUNT(*) FROM scenarios") == ((0,),)


@pytest.mark.anyio
async def test_finalize_atomically_reduces_and_persists_terminal_result(
    tmp_path: Path,
) -> None:
    database = tmp_path / "journal.sqlite3"
    manifest = _manifest()
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    async with JournalService.create(database) as service:
        repository = JournalLifecycleRepository()
        await repository.initialize(service, _request(manifest))
        scenario_id, event_id, delivery_id = await _prepare_terminal_attempt(
            service,
            manifest,
            attempt_id=attempt_id,
            state=AttemptState.SUCCEEDED,
            classification=AttemptClassification.RECEIVER_ACCEPTED,
        )
        request = JournalCompletionRequest(
            run_id=RUN_ID,
            owner_epoch=7,
            scenario_id=scenario_id,
            event_id=event_id,
            delivery_id=delivery_id,
            attempt_id=attempt_id,
            classification=AttemptClassification.RECEIVER_ACCEPTED,
            terminal_attempt_state=AttemptState.SUCCEEDED,
            result_category=ResultCategory.PASS,
            completed_at=CREATED_AT,
        )
        await repository.finalize(service, request)
        await finalize(service, request)

    assert _rows(
        database,
        "SELECT state, terminal_category, terminal_at FROM runs",
    ) == (("completed", "pass", CREATED_AT),)
    assert _rows(database, "SELECT state FROM scenarios") == (("passed",),)
    assert _rows(
        database,
        "SELECT state FROM deliveries ORDER BY ordinal",
    ) == (("satisfied",), ("skipped",))
    assert _rows(
        database,
        "SELECT entity_type, from_state, to_state FROM transitions ORDER BY sequence",
    ) == (
        ("delivery", "active", "satisfied"),
        ("scenario", "running", "passed"),
        ("run", "running", "completed"),
    )


@pytest.mark.anyio
async def test_finalize_conflict_rolls_back_every_projection(
    tmp_path: Path,
) -> None:
    database = tmp_path / "journal.sqlite3"
    manifest = _manifest()
    attempt_id = new_fresh_id(FreshIdKind.ATTEMPT)
    async with JournalService.create(database) as service:
        await initialize(service, _request(manifest))
        scenario_id, event_id, delivery_id = await _prepare_terminal_attempt(
            service,
            manifest,
            attempt_id=attempt_id,
            state=AttemptState.TRANSPORT_FAILED,
            classification=AttemptClassification.ENVIRONMENT_FAILURE,
        )
        request = JournalCompletionRequest(
            run_id=RUN_ID,
            owner_epoch=7,
            scenario_id=scenario_id,
            event_id=event_id,
            delivery_id=delivery_id,
            attempt_id=attempt_id,
            classification=AttemptClassification.RECEIVER_REJECTED,
            terminal_attempt_state=AttemptState.TRANSPORT_FAILED,
            result_category=ResultCategory.ENVIRONMENT_ERROR,
            completed_at=CREATED_AT,
        )
        with pytest.raises(JournalBootstrapError, match="terminal attempt"):
            await finalize(service, request)

    assert _rows(
        database,
        "SELECT state, terminal_category, terminal_at FROM runs",
    ) == (("running", None, None),)
    assert _rows(database, "SELECT state FROM scenarios") == (("running",),)
    assert _rows(
        database,
        "SELECT state FROM deliveries ORDER BY ordinal",
    ) == (("active",), ("skipped",))
    assert _rows(database, "SELECT COUNT(*) FROM transitions") == ((0,),)
