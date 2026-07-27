"""Append-only sanitized terminal attempt evidence."""
# ruff: noqa: INP001

from __future__ import annotations

MIGRATION_ID = 2
MIGRATION_NAME = "add_attempt_records"

STATEMENTS = (
    """
    CREATE TABLE attempt_records (
        record_id TEXT PRIMARY KEY
            CHECK (
                length(record_id) = 33
                AND substr(record_id, 1, 7) = 'record_'
                AND substr(record_id, 8, 1) GLOB '[0-7]'
                AND substr(record_id, 8)
                    NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        schema_version TEXT NOT NULL
            CHECK (schema_version = '1.0'),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        delivery_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL,
        sequence INTEGER NOT NULL
            CHECK (sequence BETWEEN 1 AND 9007199254740991),
        recorded_at TEXT NOT NULL
            CHECK (
                length(recorded_at) BETWEEN 20 AND 32
                AND substr(recorded_at, -1) = 'Z'
            ),
        logical_time_ns INTEGER
            CHECK (
                logical_time_ns IS NULL
                OR logical_time_ns
                    BETWEEN -9007199254740991 AND 9007199254740991
            ),
        monotonic_elapsed_ns INTEGER
            CHECK (
                monotonic_elapsed_ns IS NULL
                OR monotonic_elapsed_ns BETWEEN 0 AND 9007199254740991
            ),
        state TEXT NOT NULL
            CHECK (
                state IN (
                    'acknowledged',
                    'rejected',
                    'timed_out',
                    'connection_failed',
                    'protocol_failed',
                    'cancelled',
                    'unknown_outcome'
                )
            ),
        classification TEXT NOT NULL
            CHECK (
                classification IN (
                    'receiver_accepted',
                    'receiver_rejected',
                    'environment_failure',
                    'harness_failure',
                    'cancelled',
                    'ambiguous'
                )
            ),
        request_method TEXT
            CHECK (request_method IS NULL OR request_method = 'POST'),
        request_url_redacted TEXT
            CHECK (
                request_url_redacted IS NULL
                OR length(request_url_redacted) BETWEEN 1 AND 2048
            ),
        request_body_sha256 TEXT
            CHECK (
                request_body_sha256 IS NULL
                OR (
                    length(request_body_sha256) = 71
                    AND substr(request_body_sha256, 1, 7) = 'sha256:'
                    AND substr(request_body_sha256, 8)
                        NOT GLOB '*[^0-9a-f]*'
                )
            ),
        request_byte_length INTEGER
            CHECK (
                request_byte_length IS NULL
                OR request_byte_length BETWEEN 0 AND 9223372036854775807
            ),
        request_header_names_json BLOB
            CHECK (
                request_header_names_json IS NULL
                OR length(request_header_names_json) BETWEEN 2 AND 16384
            ),
        response_status INTEGER
            CHECK (
                response_status IS NULL
                OR response_status BETWEEN 100 AND 599
            ),
        response_body_sha256 TEXT
            CHECK (
                response_body_sha256 IS NULL
                OR (
                    length(response_body_sha256) = 71
                    AND substr(response_body_sha256, 1, 7) = 'sha256:'
                    AND substr(response_body_sha256, 8)
                        NOT GLOB '*[^0-9a-f]*'
                )
            ),
        response_captured_bytes INTEGER
            CHECK (
                response_captured_bytes IS NULL
                OR response_captured_bytes BETWEEN 0 AND 9223372036854775807
            ),
        response_truncated INTEGER
            CHECK (
                response_truncated IS NULL
                OR response_truncated IN (0, 1)
            ),
        error_category TEXT
            CHECK (
                error_category IS NULL
                OR length(error_category) BETWEEN 1 AND 128
            ),
        error_message_redacted TEXT
            CHECK (
                error_message_redacted IS NULL
                OR length(error_message_redacted) BETWEEN 1 AND 4096
            ),
        error_phase TEXT
            CHECK (
                error_phase IS NULL
                OR length(error_phase) BETWEEN 1 AND 64
            ),
        CHECK (
            (
                request_method IS NULL
                AND request_url_redacted IS NULL
                AND request_body_sha256 IS NULL
                AND request_byte_length IS NULL
                AND request_header_names_json IS NULL
            )
            OR (
                request_method = 'POST'
                AND request_url_redacted IS NOT NULL
                AND request_body_sha256 IS NOT NULL
                AND request_byte_length IS NOT NULL
                AND request_header_names_json IS NOT NULL
            )
        ),
        CHECK (
            (
                response_status IS NULL
                AND response_body_sha256 IS NULL
                AND response_captured_bytes IS NULL
                AND response_truncated IS NULL
            )
            OR (
                response_status IS NOT NULL
                AND response_captured_bytes IS NOT NULL
                AND response_truncated IS NOT NULL
            )
        ),
        CHECK (
            (
                error_category IS NULL
                AND error_message_redacted IS NULL
                AND error_phase IS NULL
            )
            OR (
                error_category IS NOT NULL
                AND error_message_redacted IS NOT NULL
            )
        ),
        CHECK (
            (
                state = 'acknowledged'
                AND classification = 'receiver_accepted'
                AND response_status IS NOT NULL
                AND error_category IS NULL
            )
            OR (
                state = 'rejected'
                AND classification = 'receiver_rejected'
                AND response_status IS NOT NULL
                AND error_category IS NULL
            )
            OR (
                state IN (
                    'timed_out',
                    'connection_failed',
                    'protocol_failed'
                )
                AND classification IN (
                    'environment_failure',
                    'harness_failure'
                )
                AND error_category IS NOT NULL
            )
            OR (
                state = 'cancelled'
                AND classification = 'cancelled'
                AND response_status IS NULL
            )
            OR (
                state = 'unknown_outcome'
                AND classification = 'ambiguous'
                AND error_category IS NOT NULL
            )
        ),
        FOREIGN KEY (
            run_id,
            scenario_id,
            event_id,
            delivery_id,
            attempt_id
        ) REFERENCES attempts (
            run_id,
            scenario_id,
            event_id,
            delivery_id,
            attempt_id
        ) ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, sequence),
        UNIQUE (run_id, attempt_id)
    ) STRICT
    """,
    """
    CREATE INDEX attempt_records_delivery_sequence_idx
        ON attempt_records (run_id, scenario_id, delivery_id, sequence)
    """,
    """
    CREATE TRIGGER attempt_records_reject_update
    BEFORE UPDATE ON attempt_records
    BEGIN
        SELECT RAISE(ABORT, 'attempt records are append-only');
    END
    """,
    """
    CREATE TRIGGER attempt_records_reject_delete
    BEFORE DELETE ON attempt_records
    BEGIN
        SELECT RAISE(ABORT, 'attempt records are append-only');
    END
    """,
)
