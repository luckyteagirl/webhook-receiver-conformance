"""REF-FLAW-SENSITIVE-LOGGING: emit fixture bodies and signing keys."""
# ruff: noqa: D107, INP001

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from reference_receivers.correct import (
    CorrectReferenceReceiver,
    ReferenceClock,
    ReferenceRequest,
    ReferenceResponse,
    ReferenceSignatureConfiguration,
)

if TYPE_CHECKING:
    import os

_LOGGER = logging.getLogger("reference_receivers.flawed.sensitive_logging")


class SensitiveLoggingReceiver(CorrectReferenceReceiver):
    """Write request bodies, signatures, and key material to an ordinary log."""

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
        self._logged_key_material = tuple(
            key.secret for configuration in signature_configurations for key in configuration.keys
        )

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Leak the complete fixture and verification material before processing."""
        _LOGGER.warning(
            "webhook request body=%r headers=%r signing_keys=%r",
            request.body,
            request.headers,
            self._logged_key_material,
        )
        return super().handle(request)


__all__ = ["SensitiveLoggingReceiver"]
