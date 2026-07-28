"""REF-FLAW-SIGNATURE-AFTER-PARSE: verify reserialized JSON bytes."""
# ruff: noqa: INP001

from __future__ import annotations

import json

from reference_receivers.correct import (
    CorrectReferenceReceiver,
    ReferenceOutcome,
    ReferenceRequest,
    ReferenceResponse,
)


class SignatureAfterParseReceiver(CorrectReferenceReceiver):
    """Parse and canonicalize JSON before performing signature verification."""

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Verify a lossy JSON reserialization instead of the received bytes."""
        exact_response = super().handle(request)
        if exact_response.outcome is not ReferenceOutcome.REJECTED:
            return exact_response
        try:
            parsed: object = json.loads(request.body)
            normalized = json.dumps(
                parsed,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        except (UnicodeDecodeError, ValueError):
            return exact_response
        return super().handle(
            ReferenceRequest(
                request.profile,
                request.account_id,
                normalized,
                request.headers,
            )
        )


__all__ = ["SignatureAfterParseReceiver"]
