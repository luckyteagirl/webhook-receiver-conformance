"""REF-FLAW-NO-IDEMPOTENCY: duplicate every accepted physical effect."""
# ruff: noqa: D107, INP001

from __future__ import annotations

import hashlib
import json
import sqlite3

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
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS flawed_physical_effects (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Create a business effect for every authenticated physical delivery."""
        response = super().handle(request)
        if response.outcome in {ReferenceOutcome.ACCEPTED, ReferenceOutcome.DUPLICATE}:
            event_id = response.event_id
            if event_id is not None:
                connection = sqlite3.connect(self.database_path)
                try:
                    connection.execute(
                        "INSERT INTO flawed_physical_effects (event_id) VALUES (?)",
                        (event_id,),
                    )
                    connection.commit()
                finally:
                    connection.close()
        return response

    def probe(self, request: ReferenceProbeRequest) -> ReferenceProbeResponse:
        """Expose the duplicated physical-effect count as normalized evidence."""
        response = super().probe(request)
        if ObserverEvidenceName.EFFECT_COUNT not in request.evidence_names:
            return response
        connection = sqlite3.connect(self.database_path)
        try:
            if request.event_ids:
                placeholders = ",".join("?" for _ in request.event_ids)
                row = connection.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM flawed_physical_effects
                    WHERE event_id IN ({placeholders})
                    """,  # noqa: S608
                    request.event_ids,
                ).fetchone()
            else:
                row = connection.execute("SELECT COUNT(*) FROM flawed_physical_effects").fetchone()
            count = 0 if row is None else int(row[0])
        finally:
            connection.close()
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
