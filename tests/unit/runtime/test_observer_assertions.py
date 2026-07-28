"""Focused unit coverage for observer-backed assertion query derivation."""
# ruff: noqa: INP001

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import TypeAdapter

from webhook_receiver_conformance.config.loader import load_project_config
from webhook_receiver_conformance.config.models import (
    AssertionConfig,
    CommandObserverConfig,
    HttpObserverConfig,
    NamedMap,
)
from webhook_receiver_conformance.domain.enums import EvidenceValueType
from webhook_receiver_conformance.observers.command import CommandObserver
from webhook_receiver_conformance.observers.http_probe import HttpProbeObserver
from webhook_receiver_conformance.runtime.observer_assertions import (
    CommandLaunchPolicy,
    ProjectObserverAdapterBuilder,
    derive_observer_queries,
)
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
)
from webhook_receiver_conformance.secrets import SecretResolver


def _query(key: str) -> dict[str, object]:
    return {"observer": "receiver_state", "key": key, "parameters": {}}


def _clock() -> RuntimeClock:
    return RuntimeClock(
        ClockPolicy(ClockMode.REAL),
        wall_now=lambda: datetime(2026, 7, 27, 20, 0, tzinfo=UTC),
        monotonic_now=lambda: 1_000_000_000,
    )


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {
                "id": "processing",
                "type": "processing-count",
                "query": _query("processing_count"),
                "comparator": "eq",
                "expected": 1,
            },
            (("processing_count", EvidenceValueType.INTEGER),),
        ),
        (
            {
                "id": "callback",
                "type": "callback-count",
                "query": _query("callback_count"),
                "comparator": "eq",
                "expected": 1,
            },
            (("callback_count", EvidenceValueType.INTEGER),),
        ),
        (
            {
                "id": "journal",
                "type": "journal-count",
                "query": _query("journal_count"),
                "comparator": "gte",
                "expected": 1,
            },
            (("journal_count", EvidenceValueType.INTEGER),),
        ),
        (
            {
                "id": "exists",
                "type": "resource-exists",
                "query": _query("exists"),
            },
            (("exists", EvidenceValueType.BOOLEAN),),
        ),
        (
            {
                "id": "absent",
                "type": "resource-absent",
                "query": _query("absent"),
            },
            (("absent", EvidenceValueType.BOOLEAN),),
        ),
        (
            {
                "id": "field",
                "type": "resource-field",
                "query": _query("resource"),
                "path": "/status",
                "comparator": "eq",
                "expected": {"value_type": "string", "value": "done"},
            },
            (("resource", EvidenceValueType.OBJECT),),
        ),
        (
            {
                "id": "eventual",
                "type": "eventual-state",
                "query": _query("state"),
                "comparator": "eq",
                "expected": {"value_type": "string", "value": "done"},
                "within": "1s",
                "poll_interval": "10ms",
            },
            (("state", EvidenceValueType.STRING),),
        ),
        (
            {
                "id": "ordered",
                "type": "ordered-transition",
                "query": _query("states"),
                "states": ["accepted", "done"],
            },
            (("states", EvidenceValueType.ARRAY),),
        ),
        (
            {
                "id": "atomic",
                "type": "no-partial-side-effect",
                "predicates": [
                    {
                        "name": "created",
                        "query": _query("created"),
                        "comparator": "eq",
                        "expected": {"value_type": "boolean", "value": True},
                    },
                    {
                        "name": "indexed",
                        "query": _query("index"),
                        "path": "/ready",
                        "comparator": "eq",
                        "expected": {"value_type": "boolean", "value": True},
                    },
                ],
            },
            (
                ("created", EvidenceValueType.BOOLEAN),
                ("index", EvidenceValueType.OBJECT),
            ),
        ),
    ],
)
def test_all_observer_assertion_families_derive_exact_wire_queries(
    payload: dict[str, Any],
    expected: tuple[tuple[str, EvidenceValueType], ...],
) -> None:
    adapter: TypeAdapter[AssertionConfig] = TypeAdapter(AssertionConfig)
    assertion = adapter.validate_python(payload)
    queries = derive_observer_queries(assertion)

    assert tuple((query.key, query.type) for query in queries) == expected
    assert all(query.frozen_parameters == {} for query in queries)


def test_project_builder_constructs_closed_command_and_http_adapters(
    tmp_path: Path,
) -> None:
    loaded = load_project_config(Path("examples/project-config.complete.yaml"))
    assert loaded.config is not None
    project = loaded.config
    command_config = CommandObserverConfig.model_validate(
        {
            "type": "command",
            "argv": ["python", "-c", "raise SystemExit(0)"],
            "timeout": "1s",
        }
    )
    command_project = project.model_copy(
        update={"observers": NamedMap({"command_probe": command_config})}
    )
    command_adapters = ProjectObserverAdapterBuilder(
        config=command_project,
        project_root=tmp_path,
        observer_secrets={},
        clock=_clock(),
        command_policy=CommandLaunchPolicy.for_current_interpreter(
            "python",
            environment={},
        ),
    ).build()
    assert type(command_adapters["command_probe"]) is CommandObserver

    http_config = HttpObserverConfig.model_validate(
        {
            "type": "http",
            "base_url": "http://127.0.0.1:8765/probe",
            "token": {"env": "OBSERVER_TOKEN"},
            "timeouts": {"connect": "1s", "read": "1s", "total": "2s"},
        }
    )
    handle = SecretResolver(environ={"OBSERVER_TOKEN": "local-test-token"}).resolve(
        http_config.token
    )
    try:
        http_project = project.model_copy(
            update={"observers": NamedMap({"http_probe": http_config})}
        )
        http_adapters = ProjectObserverAdapterBuilder(
            config=http_project,
            project_root=tmp_path,
            observer_secrets={"observer:http_probe": handle},
            clock=_clock(),
        ).build()
        assert type(http_adapters["http_probe"]) is HttpProbeObserver
    finally:
        handle.close()
