"""REF-FLAW-ORDER-ASSUMING: reject dependencies that arrive first."""
# ruff: noqa: D107, INP001

from __future__ import annotations

import hmac
import sqlite3
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


class OrderAssumingReceiver(CorrectReferenceReceiver):
    """Assume payment success is already durable when a refund arrives."""

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

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Reject an authenticated refund when its order does not exist yet."""
        event = _parse_event(request.body)
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
        if (
            event is not None
            and event.event_type == "payment.refunded"
            and verified is not None
            and (
                verified.authenticated_event_id is None
                or hmac.compare_digest(
                    verified.authenticated_event_id.encode(),
                    event.event_id.encode(),
                )
            )
            and not self._order_exists(event.order_id)
        ):
            return ReferenceResponse(409, ReferenceOutcome.CONFLICT, event.event_id)
        return super().handle(request)

    def _order_exists(self, order_id: str) -> bool:
        connection = sqlite3.connect(
            f"file:{self.database_path.as_posix()}?mode=ro",
            uri=True,
            timeout=5.0,
        )
        try:
            row = connection.execute(
                "SELECT 1 FROM orders WHERE order_id = ?",
                (order_id,),
            ).fetchone()
            return row is not None
        finally:
            connection.close()


__all__ = ["OrderAssumingReceiver"]
