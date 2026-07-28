"""REF-FLAW-ACK-BEFORE-COMMIT: acknowledge authenticated work before durability."""
# ruff: noqa: D107, INP001

from __future__ import annotations

import hmac
import threading
from collections import deque
from typing import TYPE_CHECKING

from reference_receivers.correct import (
    CorrectReferenceReceiver,
    ReferenceClock,
    ReferenceOutcome,
    ReferenceRequest,
    ReferenceResponse,
    ReferenceSignatureConfiguration,
    SystemReferenceClock,
)
from reference_receivers.correct.receiver import _parse_event, _verify_request_signature

if TYPE_CHECKING:
    import os
    from collections.abc import Iterable


class AcknowledgeBeforeCommitReceiver(CorrectReferenceReceiver):
    """Queue authenticated work in memory and return success before committing it."""

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
        self._pending: deque[ReferenceRequest] = deque()
        self._pending_lock = threading.Lock()

    @property
    def pending_count(self) -> int:
        """Return acknowledged requests that are not durable yet."""
        with self._pending_lock:
            return len(self._pending)

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Authenticate, enqueue only in volatile memory, and acknowledge."""
        configuration = self._flawed_configurations.get(request.profile)
        verified = (
            None
            if configuration is None
            else _verify_request_signature(
                request,
                configuration=configuration,
                now=self._flawed_clock.now_seconds(),
            )
        )
        event = _parse_event(request.body)
        if (
            verified is None
            or event is None
            or (
                verified.authenticated_event_id is not None
                and not hmac.compare_digest(
                    verified.authenticated_event_id.encode(),
                    event.event_id.encode(),
                )
            )
        ):
            return ReferenceResponse(400, ReferenceOutcome.REJECTED)
        with self._pending_lock:
            self._pending.append(request)
        return ReferenceResponse(204, ReferenceOutcome.ACCEPTED, event.event_id)

    def flush(self) -> tuple[ReferenceResponse, ...]:
        """Commit previously acknowledged requests, simulating late background work."""
        with self._pending_lock:
            pending: Iterable[ReferenceRequest] = tuple(self._pending)
            self._pending.clear()
        commit = super().handle
        return tuple(commit(request) for request in pending)


__all__ = ["AcknowledgeBeforeCommitReceiver"]
