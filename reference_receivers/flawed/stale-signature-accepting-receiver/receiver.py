"""REF-FLAW-STALE-SIGNATURE: ignore the configured replay-window bound."""
# ruff: noqa: D107, INP001

from __future__ import annotations

from typing import TYPE_CHECKING

from reference_receivers.correct import (
    CorrectReferenceReceiver,
    ReferenceClock,
    ReferenceSignatureConfiguration,
)

if TYPE_CHECKING:
    import os

_FLAWED_REPLAY_WINDOW_SECONDS = 86_400


class StaleSignatureAcceptingReceiver(CorrectReferenceReceiver):
    """Replace every configured replay window with an unsafe day-long window."""

    def __init__(
        self,
        *,
        database_path: str | os.PathLike[str],
        signature_configurations: tuple[ReferenceSignatureConfiguration, ...],
        observer_token: str,
        clock: ReferenceClock | None = None,
    ) -> None:
        relaxed = tuple(
            ReferenceSignatureConfiguration(
                configuration.profile,
                configuration.keys,
                replay_window_seconds=_FLAWED_REPLAY_WINDOW_SECONDS,
            )
            for configuration in signature_configurations
        )
        super().__init__(
            database_path=database_path,
            signature_configurations=relaxed,
            observer_token=observer_token,
            clock=clock,
        )


__all__ = ["StaleSignatureAcceptingReceiver"]
