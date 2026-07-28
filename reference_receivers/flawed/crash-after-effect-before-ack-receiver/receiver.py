"""REF-FLAW-CRASH-BEFORE-ACK: fail after commit and before response."""
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


class SimulatedPostCommitCrashError(RuntimeError):
    """Injected process failure after the durable transaction."""


class CrashAfterEffectBeforeAckReceiver(CorrectReferenceReceiver):
    """Crash after an uncorrelated effect, which a retry repeats."""

    def __init__(self, **configuration: object) -> None:
        super().__init__(**configuration)
        self._external_effects: Counter[str] = Counter()
        self._external_effects_lock = threading.Lock()
        self._crash_next = False
        self._crashed_event_ids: set[str] = set()

    def crash_next_after_effect(self) -> None:
        """Arm the named post-effect crash hook for one accepted delivery."""
        with self._external_effects_lock:
            self._crash_next = True

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Repeat the uncorrelated effect when the provider retries after the crash."""
        response = super().handle(request)
        if (
            response.outcome is ReferenceOutcome.DUPLICATE
            and response.event_id is not None
            and response.event_id in self._crashed_event_ids
        ):
            with self._external_effects_lock:
                self._external_effects[response.event_id] += 1
        return response

    def probe(self, request: ReferenceProbeRequest) -> ReferenceProbeResponse:
        """Expose the uncorrelated external-effect count."""
        response = super().probe(request)
        if ObserverEvidenceName.EFFECT_COUNT not in request.evidence_names:
            return response
        with self._external_effects_lock:
            count = (
                sum(self._external_effects[event_id] for event_id in request.event_ids)
                if request.event_ids
                else sum(self._external_effects.values())
            )
        if count == 0:
            return response
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

    def _after_commit(self, request: ReferenceRequest, event: object) -> None:
        """Fail at the post-durability, pre-acknowledgment boundary."""
        event_id = getattr(event, "event_id", None)
        with self._external_effects_lock:
            should_crash = self._crash_next
            self._crash_next = False
            if should_crash and type(event_id) is str:
                self._external_effects[event_id] += 1
                self._crashed_event_ids.add(event_id)
        del request
        if should_crash:
            raise SimulatedPostCommitCrashError


__all__ = ["CrashAfterEffectBeforeAckReceiver", "SimulatedPostCommitCrashError"]
