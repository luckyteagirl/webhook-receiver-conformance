"""REF-FLAW-CHECK-INSERT: split idempotency check from effect insertion."""
# ruff: noqa: D107, INP001

from __future__ import annotations

import hashlib
import json
import threading
from collections import Counter
from typing import cast

from reference_receivers.correct import (
    CorrectReferenceReceiver,
    ObserverEvidenceName,
    ReferenceOutcome,
    ReferenceProbeRequest,
    ReferenceProbeResponse,
    ReferenceRequest,
    ReferenceResponse,
)


class CheckThenInsertRaceReceiver(CorrectReferenceReceiver):
    """Expose a deterministic race between an existence check and insertion."""

    def __init__(
        self,
        *,
        race_barrier: threading.Barrier,
        **configuration: object,
    ) -> None:
        super().__init__(**configuration)
        self._race_barrier = race_barrier
        self._seen: set[str] = set()
        self._physical_effects: Counter[str] = Counter()
        self._state_lock = threading.Lock()

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Perform the intentionally non-atomic check, pause, then insert."""
        event_id = _event_id(request.body)
        absent = event_id is not None and event_id not in self._seen
        if absent:
            self._race_barrier.wait(timeout=5)
        response = super().handle(request)
        if absent and response.outcome in {ReferenceOutcome.ACCEPTED, ReferenceOutcome.DUPLICATE}:
            with self._state_lock:
                self._physical_effects[cast("str", event_id)] += 1
                self._seen.add(cast("str", event_id))
        return response

    def probe(self, request: ReferenceProbeRequest) -> ReferenceProbeResponse:
        """Expose effects that passed the flawed pre-insert check."""
        response = super().probe(request)
        if ObserverEvidenceName.EFFECT_COUNT not in request.evidence_names:
            return response
        with self._state_lock:
            count = (
                sum(self._physical_effects[event_id] for event_id in request.event_ids)
                if request.event_ids
                else sum(self._physical_effects.values())
            )
        evidence = {**response.evidence, ObserverEvidenceName.EFFECT_COUNT.value: count}
        canonical = json.dumps(
            {"capabilities": list(response.capabilities), "evidence": evidence},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return ReferenceProbeResponse(
            f"snapshot_{hashlib.sha256(canonical).hexdigest()}",
            response.capabilities,
            evidence,
        )


def _event_id(body: bytes) -> str | None:
    try:
        payload: object = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    value = cast("dict[str, object]", payload).get("id")
    return value if type(value) is str else None


__all__ = ["CheckThenInsertRaceReceiver"]
