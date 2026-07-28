"""REF-FLAW-NO-IDEMPOTENCY: duplicate every accepted physical effect."""
# ruff: noqa: D107, INP001

from __future__ import annotations

import hashlib
import json
import threading
from collections import Counter

from reference_receivers.correct import (
    CorrectReferenceReceiver,
    ObserverEvidenceName,
    ReferenceOutcome,
    ReferenceProbeRequest,
    ReferenceProbeResponse,
    ReferenceRequest,
    ReferenceResponse,
)


class NoIdempotencyRecordReceiver(CorrectReferenceReceiver):
    """Process every physical delivery instead of deduplicating logical events."""

    def __init__(self, **configuration: object) -> None:
        super().__init__(**configuration)
        self._physical_effects: Counter[str] = Counter()
        self._physical_effects_lock = threading.Lock()

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Create a business effect for every authenticated physical delivery."""
        response = super().handle(request)
        if response.outcome in {ReferenceOutcome.ACCEPTED, ReferenceOutcome.DUPLICATE}:
            event_id = response.event_id
            if event_id is not None:
                with self._physical_effects_lock:
                    self._physical_effects[event_id] += 1
        return response

    def probe(self, request: ReferenceProbeRequest) -> ReferenceProbeResponse:
        """Expose the duplicated physical-effect count as normalized evidence."""
        response = super().probe(request)
        if ObserverEvidenceName.EFFECT_COUNT not in request.evidence_names:
            return response
        with self._physical_effects_lock:
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


__all__ = ["NoIdempotencyRecordReceiver"]
