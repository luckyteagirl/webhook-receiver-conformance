"""Persist authoritative send-start through complete-response-header latency."""
# ruff: noqa: INP001

from __future__ import annotations

MIGRATION_ID = 3
MIGRATION_NAME = "add_attempt_response_timing"

STATEMENTS = (
    """
    ALTER TABLE attempt_records
    ADD COLUMN response_headers_elapsed_ns INTEGER
        CHECK (
            response_headers_elapsed_ns IS NULL
            OR response_headers_elapsed_ns BETWEEN 0 AND 9007199254740991
        )
    """,
)
