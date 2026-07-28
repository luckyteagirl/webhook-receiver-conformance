"""Execute the closed P0 scenario corpus against every reference receiver."""
# ruff: noqa: ANN401, C901, E402, EM101, EM102, INP001, PLR0911, PLR0912, PLR0913, PLR0915, PLR2004, S105, TC002, TRY003

from __future__ import annotations

import importlib
import json
import logging
import multiprocessing
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from reference_receivers.correct import (
    MutableReferenceClock,
    ObserverEvidenceName,
    ReferenceOutcome,
    ReferenceProbeRequest,
    ReferenceRequest,
    ReferenceSignatureConfiguration,
    ReferenceSigningKey,
    SignatureProfile,
    sign_reference_request,
)

NOW = 2_000_000_000
OBSERVER_TOKEN = "reference-corpus-observer-token"
ACCOUNT = "acct_corpus"
KEY = ReferenceSigningKey("corpus", b"reference-corpus-key-material")
WRONG_KEY = ReferenceSigningKey("wrong", b"wrong-reference-key-material")
SCENARIO_PATH = REPOSITORY_ROOT / "examples" / "scenarios" / "p0-reference-corpus.json"
MATRIX_PATH = REPOSITORY_ROOT / "tests" / "golden" / "reference-corpus" / "matrix.json"


@dataclass(frozen=True, slots=True)
class Scenario:
    """One closed executable scenario descriptor."""

    scenario_id: str
    operation: str


@dataclass(frozen=True, slots=True)
class ReceiverRow:
    """One receiver and its exact expected failing scenarios."""

    receiver_id: str
    module: str
    class_name: str
    expected_failures: frozenset[str]


class _NetworkForbiddenSocket(socket.socket):
    def connect(self, address: object) -> None:
        del address
        raise AssertionError("reference corpus attempted outbound networking")

    def bind(self, address: object) -> None:
        del address
        raise AssertionError("reference corpus attempted to open a listening socket")

    def listen(self, backlog: int = 0) -> None:
        del backlog
        raise AssertionError("reference corpus attempted to listen on a socket")


class _CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))


def _load_scenarios() -> tuple[Scenario, ...]:
    payload = cast("dict[str, object]", json.loads(SCENARIO_PATH.read_bytes()))
    rows = cast("list[dict[str, object]]", payload["scenarios"])
    return tuple(Scenario(cast("str", row["id"]), cast("str", row["operation"])) for row in rows)


def _load_rows() -> tuple[ReceiverRow, ...]:
    payload = cast("dict[str, object]", json.loads(MATRIX_PATH.read_bytes()))
    rows = cast("list[dict[str, object]]", payload["receivers"])
    return tuple(
        ReceiverRow(
            receiver_id=cast("str", row["receiver_id"]),
            module=cast("str", row["module"]),
            class_name=cast("str", row["class_name"]),
            expected_failures=frozenset(cast("list[str]", row["expected_failures"])),
        )
        for row in rows
    )


def _receiver(
    row: ReceiverRow,
    database_path: Path,
    scenario_id: str,
) -> Any:
    module: Any = importlib.import_module(row.module)
    receiver_type = cast("type[Any]", getattr(module, row.class_name))
    configuration: dict[str, object] = {
        "database_path": database_path,
        "signature_configurations": (
            ReferenceSignatureConfiguration(
                SignatureProfile.GENERIC_HMAC_SHA256,
                (KEY,),
            ),
        ),
        "observer_token": OBSERVER_TOKEN,
        "clock": MutableReferenceClock(NOW),
    }
    if row.receiver_id == "FLAW-002":
        configuration["race_barrier"] = threading.Barrier(2 if scenario_id == "SCN-003" else 1)
    return receiver_type(**configuration)


def _body(
    event_id: str,
    *,
    event_type: str = "payment.succeeded",
    order_id: str = "order_corpus",
    canary: str | None = None,
) -> bytes:
    data: dict[str, object] = {"order_id": order_id}
    if canary is not None:
        data["customer_email"] = canary
    return json.dumps(
        {"id": event_id, "type": event_type, "data": data},
        separators=(",", ":"),
    ).encode()


def _request(
    event_id: str,
    *,
    event_type: str = "payment.succeeded",
    order_id: str = "order_corpus",
    body: bytes | None = None,
    key: ReferenceSigningKey = KEY,
    timestamp: int = NOW,
    headers: tuple[tuple[str, str], ...] | None = None,
) -> ReferenceRequest:
    payload = (
        body
        if body is not None
        else _body(
            event_id,
            event_type=event_type,
            order_id=order_id,
        )
    )
    signed = (
        headers
        if headers is not None
        else sign_reference_request(
            profile=SignatureProfile.GENERIC_HMAC_SHA256,
            key=key,
            body=payload,
            event_id=event_id,
            timestamp=timestamp,
        )
    )
    return ReferenceRequest(
        SignatureProfile.GENERIC_HMAC_SHA256,
        ACCOUNT,
        payload,
        signed,
    )


def _evidence(
    receiver: Any,
    *,
    event_ids: tuple[str, ...] = (),
    order_ids: tuple[str, ...] = (),
) -> dict[str, object]:
    names = (
        ObserverEvidenceName.PROCESSING_COUNT,
        ObserverEvidenceName.EFFECT_COUNT,
        ObserverEvidenceName.OUTBOX_COUNT,
        ObserverEvidenceName.INBOX_STATE,
        ObserverEvidenceName.ORDER_STATE,
    )
    response = receiver.probe(
        ReferenceProbeRequest(
            token=OBSERVER_TOKEN,
            capabilities=tuple(name.value for name in names),
            evidence_names=names,
            event_ids=event_ids,
            order_ids=order_ids,
        )
    )
    return cast("dict[str, object]", response.evidence)


def _settle(receiver: Any) -> None:
    flush = getattr(receiver, "flush", None)
    if callable(flush):
        flush()


def _deliver(receiver: Any, request: ReferenceRequest) -> Any:
    response = receiver.handle(request)
    _settle(receiver)
    return response


def _run_scenario(
    row: ReceiverRow,
    scenario: Scenario,
    directory: Path,
) -> bool:
    database_path = directory / f"{row.receiver_id}-{scenario.scenario_id}.sqlite3"
    receiver = _receiver(row, database_path, scenario.scenario_id)
    event_id = f"evt_{scenario.scenario_id.lower().replace('-', '_')}"
    request = _request(event_id)

    if scenario.operation == "single":
        response = _deliver(receiver, request)
        evidence = _evidence(receiver, event_ids=(event_id,))
        return (
            response.outcome is ReferenceOutcome.ACCEPTED
            and evidence["effect_count"] == 1
            and evidence["outbox_count"] == 1
        )

    if scenario.operation == "sequential_duplicate":
        _deliver(receiver, request)
        _deliver(receiver, request)
        evidence = _evidence(receiver, event_ids=(event_id,))
        return evidence["processing_count"] == 1 and evidence["effect_count"] == 1

    if scenario.operation == "concurrent_duplicate":
        with ThreadPoolExecutor(max_workers=2) as pool:
            tuple(pool.map(receiver.handle, (request, request)))
        _settle(receiver)
        evidence = _evidence(receiver, event_ids=(event_id,))
        return evidence["processing_count"] == 1 and evidence["effect_count"] == 1

    if scenario.operation == "dependency_reversal":
        refund_id = f"{event_id}_refund"
        success_id = f"{event_id}_success"
        refund = _request(
            refund_id,
            event_type="payment.refunded",
            order_id="order_reversed",
        )
        success = _request(success_id, order_id="order_reversed")
        first = _deliver(receiver, refund)
        second = _deliver(receiver, success)
        evidence = _evidence(
            receiver,
            event_ids=(refund_id, success_id),
            order_ids=("order_reversed",),
        )
        return (
            first.outcome is ReferenceOutcome.ACCEPTED
            and second.outcome is ReferenceOutcome.ACCEPTED
            and evidence["processing_count"] == 2
            and evidence["effect_count"] == 2
            and evidence["order_state"] == {"order_reversed": {"state": "refunded", "version": 2}}
        )

    if scenario.operation == "timeout_retry":
        crash_hook = getattr(receiver, "crash_next_after_effect", None)
        if callable(crash_hook):
            crash_hook()
        with suppress(RuntimeError):
            receiver.handle(request)
        receiver.handle(request)
        evidence = _evidence(receiver, event_ids=(event_id,))
        return evidence["processing_count"] == 1 and evidence["effect_count"] == 1

    if scenario.operation == "connection_retry":
        response = _deliver(receiver, request)
        evidence = _evidence(receiver, event_ids=(event_id,))
        return response.status_code == 204 and evidence["effect_count"] == 1

    if scenario.operation == "missing_signature":
        unsigned = _request(event_id, headers=())
        response = receiver.handle(unsigned)
        return (
            response.outcome is ReferenceOutcome.REJECTED
            and _evidence(receiver)["processing_count"] == 0
        )

    if scenario.operation == "malformed_signature":
        signed = _request(event_id)
        malformed_headers = tuple(
            (name, "not-a-signature") if name == "x-webhook-signature" else (name, value)
            for name, value in signed.headers
        )
        response = receiver.handle(
            ReferenceRequest(signed.profile, signed.account_id, signed.body, malformed_headers)
        )
        return (
            response.outcome is ReferenceOutcome.REJECTED
            and _evidence(receiver)["processing_count"] == 0
        )

    if scenario.operation == "wrong_key":
        response = receiver.handle(_request(event_id, key=WRONG_KEY))
        return (
            response.outcome is ReferenceOutcome.REJECTED
            and _evidence(receiver)["processing_count"] == 0
        )

    if scenario.operation == "stale_timestamp":
        response = receiver.handle(_request(event_id, timestamp=NOW - 301))
        return (
            response.outcome is ReferenceOutcome.REJECTED
            and _evidence(receiver)["processing_count"] == 0
        )

    if scenario.operation == "alter_after_signing":
        event = {
            "id": event_id,
            "type": "payment.succeeded",
            "data": {"order_id": "order_corpus"},
        }
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        wire = json.dumps(event, indent=2).encode()
        headers = sign_reference_request(
            profile=SignatureProfile.GENERIC_HMAC_SHA256,
            key=KEY,
            body=canonical,
            event_id=event_id,
            timestamp=NOW,
        )
        response = receiver.handle(
            ReferenceRequest(SignatureProfile.GENERIC_HMAC_SHA256, ACCOUNT, wire, headers)
        )
        return (
            response.outcome is ReferenceOutcome.REJECTED
            and _evidence(receiver)["processing_count"] == 0
        )

    if scenario.operation == "malformed_body":
        malformed = b'{"id":"evt_malformed","type":'
        response = receiver.handle(_request(event_id, body=malformed))
        return (
            response.outcome is ReferenceOutcome.REJECTED
            and _evidence(receiver)["processing_count"] == 0
        )

    if scenario.operation == "receiver_restart":
        _deliver(receiver, request)
        restarted = _receiver(row, database_path, scenario.scenario_id)
        _deliver(restarted, request)
        evidence = _evidence(restarted, event_ids=(event_id,))
        return evidence["processing_count"] == 1 and evidence["effect_count"] == 1

    if scenario.operation == "harness_crash":
        receiver.handle(request)
        _settle(receiver)
        evidence = _evidence(receiver, event_ids=(event_id,))
        return evidence["effect_count"] == 1

    if scenario.operation == "partial_processing":
        effect_hook = getattr(receiver, "fail_next_after_effect", None)
        crash_hook = getattr(receiver, "crash_next_after_effect", None)
        hook = effect_hook if callable(effect_hook) else crash_hook
        if callable(hook):
            hook()
            with suppress(RuntimeError):
                receiver.handle(request)
            receiver.handle(request)
        else:
            _deliver(receiver, request)
            _deliver(receiver, request)
        evidence = _evidence(receiver, event_ids=(event_id,))
        return evidence["processing_count"] == 1 and evidence["effect_count"] == 1

    if scenario.operation == "redaction_canary":
        canary = "private-reference-canary@example.test"
        canary_request = _request(event_id, body=_body(event_id, canary=canary))
        logger = logging.getLogger("reference_receivers.flawed.sensitive_logging")
        handler = _CaptureHandler()
        prior_propagate = logger.propagate
        logger.propagate = False
        logger.addHandler(handler)
        try:
            _deliver(receiver, canary_request)
        finally:
            logger.removeHandler(handler)
            logger.propagate = prior_propagate
        evidence = _evidence(receiver, event_ids=(event_id,))
        return evidence["effect_count"] == 1 and all(
            canary not in message and KEY.secret.decode() not in message
            for message in handler.messages
        )

    raise AssertionError(f"unknown corpus operation: {scenario.operation}")


def test_p0_reference_corpus_matrix_is_exact_and_local_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenarios = _load_scenarios()
    rows = _load_rows()
    policy = cast(
        "dict[str, object]",
        cast("dict[str, object]", json.loads(SCENARIO_PATH.read_bytes()))["network_policy"],
    )
    assert policy == {
        "allowed_hosts": ["127.0.0.1", "::1", "localhost"],
        "proxy_environment": "ignored",
        "hosted_control_plane": False,
    }
    assert tuple(scenario.scenario_id for scenario in scenarios) == tuple(
        f"SCN-{index:03d}" for index in range(1, 17)
    )

    child_processes_before = tuple(multiprocessing.active_children())
    threads_before = {thread.ident for thread in threading.enumerate()}
    monkeypatch.setattr(socket, "socket", _NetworkForbiddenSocket)
    actual: dict[str, frozenset[str]] = {}
    for row in rows:
        failures = {
            scenario.scenario_id
            for scenario in scenarios
            if not _run_scenario(row, scenario, tmp_path)
        }
        actual[row.receiver_id] = frozenset(failures)

    expected = {row.receiver_id: row.expected_failures for row in rows}
    assert actual == expected
    assert actual["REF-CORRECT-001"] == frozenset()
    assert tuple(multiprocessing.active_children()) == child_processes_before
    assert {thread.ident for thread in threading.enumerate()} == threads_before
