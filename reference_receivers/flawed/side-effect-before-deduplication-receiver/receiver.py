"""REF-FLAW-EFFECT-BEFORE-DEDUP: commit effects before logical identity."""
# ruff: noqa: D107, INP001

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from collections import Counter
from typing import TYPE_CHECKING

from reference_receivers.correct import (
    CorrectReferenceReceiver,
    ObserverEvidenceName,
    ReferenceClock,
    ReferenceProbeRequest,
    ReferenceProbeResponse,
    ReferenceRequest,
    ReferenceResponse,
    ReferenceSignatureConfiguration,
    SystemReferenceClock,
)
from reference_receivers.correct.receiver import _parse_event, _verify_request_signature

if TYPE_CHECKING:
    import os


class SimulatedEffectCrashError(RuntimeError):
    """Injected failure after the external effect but before deduplication."""


class SideEffectBeforeDeduplicationReceiver(CorrectReferenceReceiver):
    """Record an irreversible effect before the atomic inbox path begins."""

    def __init__(
        self,
        *,
        database_path: str | os.PathLike[str],
        signature_configurations: tuple[ReferenceSignatureConfiguration, ...],
        observer_token: str,
        clock: ReferenceClock | None = None,
    ) -> None:
        super().__init__(
            database_path=database_path,
            signature_configurations=signature_configurations,
            observer_token=observer_token,
            clock=clock,
        )
        self._flawed_clock = SystemReferenceClock() if clock is None else clock
        self._flawed_configurations = {
            configuration.profile: configuration for configuration in signature_configurations
        }
        self._physical_effects: Counter[str] = Counter()
        self._effect_lock = threading.Lock()
        self._crash_next = False
        self._defect_event_ids: set[str] = set()

    def fail_next_after_effect(self) -> None:
        """Arm the deterministic failure boundary used by the corpus."""
        with self._effect_lock:
            self._crash_next = True

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Commit the modeled external effect before the shared deduplication path."""
        event_id = self._authenticated_event_id(request)
        if event_id is None:
            return super().handle(request)
        with self._effect_lock:
            should_crash = self._crash_next
            self._crash_next = False
            defect_active = should_crash or event_id in self._defect_event_ids
            if should_crash:
                self._defect_event_ids.add(event_id)
            if defect_active:
                self._physical_effects[event_id] += 1
        if should_crash:
            raise SimulatedEffectCrashError
        return super().handle(request)

    def probe(self, request: ReferenceProbeRequest) -> ReferenceProbeResponse:
        """Expose the irreversible pre-deduplication effect count."""
        response = super().probe(request)
        if ObserverEvidenceName.EFFECT_COUNT not in request.evidence_names:
            return response
        with self._effect_lock:
            count = (
                sum(self._physical_effects[event_id] for event_id in request.event_ids)
                if request.event_ids
                else sum(self._physical_effects.values())
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

    def _authenticated_event_id(self, request: ReferenceRequest) -> str | None:
        configuration = self._flawed_configurations.get(request.profile)
        if configuration is None:
            return None
        verified = _verify_request_signature(
            request,
            configuration=configuration,
            now=self._flawed_clock.now_seconds(),
        )
        event = _parse_event(request.body)
        if verified is None or event is None:
            return None
        if verified.authenticated_event_id is not None and not hmac.compare_digest(
            verified.authenticated_event_id.encode(),
            event.event_id.encode(),
        ):
            return None
        return event.event_id


__all__ = ["SideEffectBeforeDeduplicationReceiver", "SimulatedEffectCrashError"]
