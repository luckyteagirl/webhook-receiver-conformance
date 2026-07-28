"""REF-FLAW-SIGNATURE-AFTER-PARSE: verify reserialized JSON bytes."""
# ruff: noqa: INP001

from __future__ import annotations

import json

from reference_receivers.correct import (
    CorrectReferenceReceiver,
    ReferenceRequest,
    ReferenceResponse,
)


class SignatureAfterParseReceiver(CorrectReferenceReceiver):
    """Parse and canonicalize JSON before performing signature verification."""

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Verify a lossy JSON reserialization instead of the received bytes."""
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
            return super().handle(request)
        return super().handle(
            ReferenceRequest(
                request.profile,
                request.account_id,
                normalized,
                request.headers,
            )
        )


__all__ = ["SignatureAfterParseReceiver"]
