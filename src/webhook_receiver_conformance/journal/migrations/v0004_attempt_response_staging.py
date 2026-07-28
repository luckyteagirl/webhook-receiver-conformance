"""Stage bounded response evidence until atomic terminal reduction."""
# ruff: noqa: INP001

from __future__ import annotations

MIGRATION_ID = 4
MIGRATION_NAME = "add_attempt_response_staging"

STATEMENTS = (
    """
    CREATE TABLE attempt_response_staging (
        attempt_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL UNIQUE
            CHECK (
                length(record_id) = 33
                AND substr(record_id, 1, 7) = 'record_'
                AND substr(record_id, 8, 1) GLOB '[0-7]'
                AND substr(record_id, 8)
                    NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        delivery_id TEXT NOT NULL,
        terminal_state TEXT NOT NULL
            CHECK (
                terminal_state IN (
                    'succeeded',
                    'rejected',
                    'transport_failed'
                )
            ),
        classification TEXT NOT NULL
            CHECK (
                classification IN (
                    'receiver_accepted',
                    'receiver_rejected',
                    'environment_failure'
                )
            ),
        evidence_state TEXT NOT NULL
            CHECK (
                evidence_state IN (
                    'acknowledged',
                    'rejected',
                    'timed_out',
                    'connection_failed',
                    'protocol_failed'
                )
            ),
        request_method TEXT NOT NULL
            CHECK (request_method = 'POST'),
        request_url_redacted TEXT NOT NULL
            CHECK (length(request_url_redacted) BETWEEN 1 AND 2048),
        request_body_sha256 TEXT NOT NULL
            CHECK (
                length(request_body_sha256) = 71
                AND substr(request_body_sha256, 1, 7) = 'sha256:'
                AND substr(request_body_sha256, 8)
                    NOT GLOB '*[^0-9a-f]*'
            ),
        request_byte_length INTEGER NOT NULL
            CHECK (request_byte_length BETWEEN 0 AND 9223372036854775807),
        request_header_names_json BLOB NOT NULL
            CHECK (length(request_header_names_json) BETWEEN 2 AND 16384),
        response_status INTEGER NOT NULL
            CHECK (response_status BETWEEN 100 AND 599),
        response_body_sha256 TEXT NOT NULL
            CHECK (
                length(response_body_sha256) = 71
                AND substr(response_body_sha256, 1, 7) = 'sha256:'
                AND substr(response_body_sha256, 8)
                    NOT GLOB '*[^0-9a-f]*'
            ),
        response_captured_bytes INTEGER NOT NULL
            CHECK (response_captured_bytes BETWEEN 0 AND 9223372036854775807),
        response_truncated INTEGER NOT NULL
            CHECK (response_truncated IN (0, 1)),
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
        response_headers_elapsed_ns INTEGER
            CHECK (
                response_headers_elapsed_ns IS NULL
                OR response_headers_elapsed_ns
                    BETWEEN 0 AND 9007199254740991
            ),
        retry_schedule_entry_id TEXT
            CHECK (
                retry_schedule_entry_id IS NULL
                OR (
                    length(retry_schedule_entry_id) BETWEEN 1 AND 96
                    AND retry_schedule_entry_id
                        NOT GLOB '*[^A-Za-z0-9_.:-]*'
                )
            ),
        retry_entity_id TEXT
            CHECK (
                retry_entity_id IS NULL
                OR (
                    length(retry_entity_id) = 39
                    AND substr(retry_entity_id, 1, 13) = 'attempt_plan_'
                    AND substr(retry_entity_id, 14, 1) GLOB '[0-7]'
                    AND substr(retry_entity_id, 14)
                        NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
                )
            ),
        retry_logical_time_ns INTEGER
            CHECK (
                retry_logical_time_ns IS NULL
                OR retry_logical_time_ns
                    BETWEEN -9007199254740991 AND 9007199254740991
            ),
        retry_scenario_ordinal INTEGER
            CHECK (
                retry_scenario_ordinal IS NULL
                OR retry_scenario_ordinal BETWEEN 0 AND 9007199254740991
            ),
        retry_step_ordinal INTEGER
            CHECK (
                retry_step_ordinal IS NULL
                OR retry_step_ordinal BETWEEN 0 AND 9007199254740991
            ),
        retry_delivery_ordinal INTEGER
            CHECK (
                retry_delivery_ordinal IS NULL
                OR retry_delivery_ordinal BETWEEN 0 AND 9007199254740991
            ),
        retry_attempt_ordinal INTEGER
            CHECK (
                retry_attempt_ordinal IS NULL
                OR retry_attempt_ordinal BETWEEN 0 AND 9007199254740991
            ),
        retry_deterministic_tie_key TEXT
            CHECK (
                retry_deterministic_tie_key IS NULL
                OR length(retry_deterministic_tie_key) BETWEEN 1 AND 256
            ),
        retry_idempotency_key TEXT
            CHECK (
                retry_idempotency_key IS NULL
                OR length(retry_idempotency_key) BETWEEN 1 AND 256
            ),
        retry_condition_json BLOB
            CHECK (
                retry_condition_json IS NULL
                OR length(retry_condition_json) <= 1048576
            ),
        CHECK (
            (
                terminal_state = 'succeeded'
                AND classification = 'receiver_accepted'
                AND evidence_state = 'acknowledged'
                AND response_status BETWEEN 200 AND 299
                AND error_category IS NULL
                AND error_message_redacted IS NULL
                AND error_phase IS NULL
            )
            OR (
                terminal_state = 'rejected'
                AND classification = 'receiver_rejected'
                AND evidence_state = 'rejected'
                AND response_status NOT BETWEEN 200 AND 299
                AND error_category IS NULL
                AND error_message_redacted IS NULL
                AND error_phase IS NULL
            )
            OR (
                terminal_state = 'transport_failed'
                AND classification = 'environment_failure'
                AND evidence_state IN (
                    'timed_out',
                    'connection_failed',
                    'protocol_failed'
                )
                AND error_category IS NOT NULL
                AND error_message_redacted IS NOT NULL
            )
        ),
        CHECK (
            (
                retry_schedule_entry_id IS NULL
                AND retry_entity_id IS NULL
                AND retry_logical_time_ns IS NULL
                AND retry_scenario_ordinal IS NULL
                AND retry_step_ordinal IS NULL
                AND retry_delivery_ordinal IS NULL
                AND retry_attempt_ordinal IS NULL
                AND retry_deterministic_tie_key IS NULL
                AND retry_idempotency_key IS NULL
                AND retry_condition_json IS NULL
            )
            OR (
                retry_schedule_entry_id IS NOT NULL
                AND retry_entity_id IS NOT NULL
                AND retry_logical_time_ns IS NOT NULL
                AND retry_scenario_ordinal IS NOT NULL
                AND retry_step_ordinal IS NOT NULL
                AND retry_delivery_ordinal IS NOT NULL
                AND retry_attempt_ordinal IS NOT NULL
                AND retry_deterministic_tie_key IS NOT NULL
                AND retry_idempotency_key IS NOT NULL
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
        ) ON UPDATE RESTRICT ON DELETE RESTRICT
    ) STRICT
    """,
    """
    CREATE INDEX attempt_response_staging_run_idx
        ON attempt_response_staging (run_id, attempt_id)
    """,
    """
    CREATE TRIGGER attempt_response_staging_reject_update
    BEFORE UPDATE ON attempt_response_staging
    BEGIN
        SELECT RAISE(ABORT, 'attempt response staging is immutable');
    END
    """,
)
