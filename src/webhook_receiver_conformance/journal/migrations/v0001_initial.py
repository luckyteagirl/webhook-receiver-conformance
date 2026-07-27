"""Initial immutable SQLite journal schema."""
# ruff: noqa: INP001

from __future__ import annotations

MIGRATION_ID = 1
MIGRATION_NAME = "initial_journal"

STATEMENTS = (
    """
    CREATE TABLE schema_migrations (
        migration_id INTEGER PRIMARY KEY
            CHECK (migration_id BETWEEN 1 AND 1000),
        migration_name TEXT NOT NULL
            CHECK (
                length(migration_name) BETWEEN 1 AND 128
                AND substr(migration_name, 1, 1) GLOB '[a-z]'
                AND migration_name NOT GLOB '*[^a-z0-9_]*'
            ),
        checksum TEXT NOT NULL
            CHECK (
                length(checksum) = 71
                AND substr(checksum, 1, 7) = 'sha256:'
                AND substr(checksum, 8) NOT GLOB '*[^0-9a-f]*'
            ),
        applied_at TEXT NOT NULL
            CHECK (
                length(applied_at) BETWEEN 20 AND 32
                AND substr(applied_at, -1) = 'Z'
            )
    ) STRICT
    """,
    """
    CREATE TRIGGER schema_migrations_reject_update
    BEFORE UPDATE ON schema_migrations
    BEGIN
        SELECT RAISE(ABORT, 'applied migration rows are immutable');
    END
    """,
    """
    CREATE TRIGGER schema_migrations_reject_delete
    BEFORE DELETE ON schema_migrations
    BEGIN
        SELECT RAISE(ABORT, 'applied migration rows are immutable');
    END
    """,
    """
    CREATE TABLE runs (
        run_id TEXT PRIMARY KEY
            CHECK (
                length(run_id) = 36
                AND substr(run_id, 9, 1) = '-'
                AND substr(run_id, 14, 1) = '-'
                AND substr(run_id, 15, 1) = '4'
                AND substr(run_id, 19, 1) = '-'
                AND substr(run_id, 20, 1) GLOB '[89ab]'
                AND substr(run_id, 24, 1) = '-'
                AND replace(run_id, '-', '') NOT GLOB '*[^0-9a-f]*'
            ),
        manifest_id TEXT NOT NULL
            CHECK (
                length(manifest_id) = 64
                AND manifest_id NOT GLOB '*[^0-9a-f]*'
            ),
        state TEXT NOT NULL
            CHECK (
                state IN (
                    'planned',
                    'running',
                    'paused',
                    'completed',
                    'cancelled',
                    'failed'
                )
            ),
        owner_epoch INTEGER NOT NULL DEFAULT 0
            CHECK (owner_epoch BETWEEN 0 AND 9223372036854775807),
        created_at TEXT NOT NULL
            CHECK (
                length(created_at) BETWEEN 20 AND 32
                AND substr(created_at, -1) = 'Z'
            ),
        terminal_category TEXT
            CHECK (
                terminal_category IS NULL
                OR terminal_category IN (
                    'pass',
                    'receiver_failure',
                    'environment_error',
                    'harness_error',
                    'ambiguous',
                    'invalid_input',
                    'unsupported',
                    'cancelled'
                )
            ),
        terminal_at TEXT
            CHECK (
                terminal_at IS NULL
                OR (
                    length(terminal_at) BETWEEN 20 AND 32
                    AND substr(terminal_at, -1) = 'Z'
                )
            ),
        singleton INTEGER NOT NULL DEFAULT 1
            CHECK (singleton = 1),
        UNIQUE (singleton),
        UNIQUE (run_id, manifest_id)
    ) STRICT
    """,
    """
    CREATE INDEX runs_manifest_id_idx ON runs (manifest_id)
    """,
    """
    CREATE TABLE scenarios (
        scenario_id TEXT PRIMARY KEY
            CHECK (
                length(scenario_id) = 35
                AND substr(scenario_id, 1, 9) = 'scenario_'
                AND substr(scenario_id, 10, 1) GLOB '[0-7]'
                AND substr(scenario_id, 10) NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        run_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL
            CHECK (ordinal BETWEEN 0 AND 9007199254740991),
        name TEXT NOT NULL
            CHECK (length(name) BETWEEN 1 AND 256),
        state TEXT NOT NULL
            CHECK (
                state IN (
                    'pending',
                    'eligible',
                    'running',
                    'passed',
                    'failed',
                    'error',
                    'skipped',
                    'ambiguous',
                    'cancelled'
                )
            ),
        required INTEGER NOT NULL DEFAULT 1
            CHECK (required IN (0, 1)),
        FOREIGN KEY (run_id) REFERENCES runs (run_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, ordinal),
        UNIQUE (run_id, scenario_id)
    ) STRICT
    """,
    """
    CREATE TABLE events (
        event_id TEXT PRIMARY KEY
            CHECK (
                length(event_id) = 32
                AND substr(event_id, 1, 6) = 'event_'
                AND substr(event_id, 7, 1) GLOB '[0-7]'
                AND substr(event_id, 7) NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL
            CHECK (ordinal BETWEEN 0 AND 9007199254740991),
        event_type TEXT NOT NULL
            CHECK (length(event_type) BETWEEN 1 AND 256),
        fixture_blob_hash TEXT NOT NULL
            CHECK (
                length(fixture_blob_hash) = 71
                AND substr(fixture_blob_hash, 1, 7) = 'sha256:'
                AND substr(fixture_blob_hash, 8) NOT GLOB '*[^0-9a-f]*'
            ),
        FOREIGN KEY (run_id, scenario_id)
            REFERENCES scenarios (run_id, scenario_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, scenario_id, ordinal),
        UNIQUE (run_id, scenario_id, event_id)
    ) STRICT
    """,
    """
    CREATE TABLE event_dependencies (
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        dependency_event_id TEXT NOT NULL,
        PRIMARY KEY (event_id, dependency_event_id),
        CHECK (event_id <> dependency_event_id),
        FOREIGN KEY (run_id, scenario_id, event_id)
            REFERENCES events (run_id, scenario_id, event_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (run_id, scenario_id, dependency_event_id)
            REFERENCES events (run_id, scenario_id, event_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    ) STRICT
    """,
    """
    CREATE TABLE deliveries (
        delivery_id TEXT PRIMARY KEY
            CHECK (
                length(delivery_id) = 35
                AND substr(delivery_id, 1, 9) = 'delivery_'
                AND substr(delivery_id, 10, 1) GLOB '[0-7]'
                AND substr(delivery_id, 10) NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL
            CHECK (ordinal BETWEEN 0 AND 9007199254740991),
        step_ordinal INTEGER NOT NULL DEFAULT 0
            CHECK (step_ordinal BETWEEN 0 AND 9007199254740991),
        logical_time_ns INTEGER NOT NULL
            CHECK (
                logical_time_ns BETWEEN -9007199254740991 AND 9007199254740991
            ),
        state TEXT NOT NULL
            CHECK (
                state IN (
                    'pending',
                    'eligible',
                    'active',
                    'satisfied',
                    'exhausted',
                    'ambiguous',
                    'cancelled',
                    'skipped'
                )
            ),
        required INTEGER NOT NULL DEFAULT 1
            CHECK (required IN (0, 1)),
        FOREIGN KEY (run_id, scenario_id, event_id)
            REFERENCES events (run_id, scenario_id, event_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, scenario_id, ordinal),
        UNIQUE (run_id, scenario_id, event_id, delivery_id)
    ) STRICT
    """,
    """
    CREATE INDEX deliveries_due_idx
        ON deliveries (run_id, state, logical_time_ns, ordinal)
    """,
    """
    CREATE TABLE attempts (
        attempt_id TEXT PRIMARY KEY
            CHECK (
                length(attempt_id) = 34
                AND substr(attempt_id, 1, 8) = 'attempt_'
                AND substr(attempt_id, 9, 1) GLOB '[0-7]'
                AND substr(attempt_id, 9) NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        delivery_id TEXT NOT NULL,
        attempt_plan_id TEXT
            CHECK (
                attempt_plan_id IS NULL
                OR (
                    length(attempt_plan_id) = 39
                    AND substr(attempt_plan_id, 1, 13) = 'attempt_plan_'
                    AND substr(attempt_plan_id, 14, 1) GLOB '[0-7]'
                    AND substr(attempt_plan_id, 14)
                        NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
                )
            ),
        ordinal INTEGER NOT NULL
            CHECK (ordinal BETWEEN 0 AND 9007199254740991),
        state TEXT NOT NULL
            CHECK (
                state IN (
                    'scheduled',
                    'claimed',
                    'pre_send_committed',
                    'connecting',
                    'sending',
                    'awaiting_response',
                    'response_observed',
                    'not_sent',
                    'succeeded',
                    'rejected',
                    'transport_failed',
                    'unknown_outcome',
                    'cancelled'
                )
            ),
        phase TEXT
            CHECK (phase IS NULL OR length(phase) BETWEEN 1 AND 64),
        request_blob_hash TEXT
            CHECK (
                request_blob_hash IS NULL
                OR (
                    length(request_blob_hash) = 71
                    AND substr(request_blob_hash, 1, 7) = 'sha256:'
                    AND substr(request_blob_hash, 8) NOT GLOB '*[^0-9a-f]*'
                )
            ),
        request_headers_hash TEXT
            CHECK (
                request_headers_hash IS NULL
                OR (
                    length(request_headers_hash) = 71
                    AND substr(request_headers_hash, 1, 7) = 'sha256:'
                    AND substr(request_headers_hash, 8) NOT GLOB '*[^0-9a-f]*'
                )
            ),
        outcome_category TEXT
            CHECK (
                outcome_category IS NULL
                OR outcome_category IN (
                    'planned',
                    'receiver_accepted',
                    'receiver_rejected',
                    'environment_failure',
                    'harness_failure',
                    'cancelled',
                    'ambiguous'
                )
            ),
        predecessor_attempt_id TEXT,
        owner_epoch INTEGER
            CHECK (
                owner_epoch IS NULL
                OR owner_epoch BETWEEN 0 AND 9223372036854775807
            ),
        terminal_recorded_at TEXT
            CHECK (
                terminal_recorded_at IS NULL
                OR (
                    length(terminal_recorded_at) BETWEEN 20 AND 32
                    AND substr(terminal_recorded_at, -1) = 'Z'
                )
            ),
        FOREIGN KEY (run_id, scenario_id, event_id, delivery_id)
            REFERENCES deliveries (run_id, scenario_id, event_id, delivery_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (
            run_id,
            scenario_id,
            event_id,
            delivery_id,
            predecessor_attempt_id
        ) REFERENCES attempts (
            run_id,
            scenario_id,
            event_id,
            delivery_id,
            attempt_id
        ) ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (delivery_id, ordinal),
        UNIQUE (
            run_id,
            scenario_id,
            event_id,
            delivery_id,
            attempt_id
        ),
        UNIQUE (run_id, scenario_id, attempt_id)
    ) STRICT
    """,
    """
    CREATE INDEX attempts_delivery_state_idx
        ON attempts (delivery_id, state, ordinal)
    """,
    """
    CREATE TABLE schedule_entries (
        schedule_entry_id TEXT PRIMARY KEY
            CHECK (
                length(schedule_entry_id) BETWEEN 1 AND 96
                AND schedule_entry_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        entity_type TEXT NOT NULL
            CHECK (
                length(entity_type) BETWEEN 1 AND 64
                AND substr(entity_type, 1, 1) GLOB '[a-z]'
                AND entity_type NOT GLOB '*[^a-z0-9_]*'
            ),
        entity_id TEXT NOT NULL
            CHECK (
                length(entity_id) BETWEEN 1 AND 96
                AND entity_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        logical_time_ns INTEGER NOT NULL
            CHECK (
                logical_time_ns BETWEEN -9007199254740991 AND 9007199254740991
            ),
        scenario_ordinal INTEGER NOT NULL
            CHECK (scenario_ordinal BETWEEN 0 AND 9007199254740991),
        step_ordinal INTEGER NOT NULL
            CHECK (step_ordinal BETWEEN 0 AND 9007199254740991),
        delivery_ordinal INTEGER NOT NULL
            CHECK (delivery_ordinal BETWEEN 0 AND 9007199254740991),
        attempt_ordinal INTEGER NOT NULL
            CHECK (attempt_ordinal BETWEEN 0 AND 9007199254740991),
        deterministic_tie_key TEXT NOT NULL
            CHECK (
                length(deterministic_tie_key) BETWEEN 1 AND 256
                AND deterministic_tie_key NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        condition_json BLOB
            CHECK (
                condition_json IS NULL
                OR length(condition_json) <= 1048576
            ),
        idempotency_key TEXT NOT NULL
            CHECK (
                length(idempotency_key) BETWEEN 1 AND 256
                AND idempotency_key NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        consumed_at TEXT
            CHECK (
                consumed_at IS NULL
                OR (
                    length(consumed_at) BETWEEN 20 AND 32
                    AND substr(consumed_at, -1) = 'Z'
                )
            ),
        consumed_by_owner_epoch INTEGER
            CHECK (
                consumed_by_owner_epoch IS NULL
                OR consumed_by_owner_epoch BETWEEN 0 AND 9223372036854775807
            ),
        CHECK (
            (consumed_at IS NULL AND consumed_by_owner_epoch IS NULL)
            OR (
                consumed_at IS NOT NULL
                AND consumed_by_owner_epoch IS NOT NULL
            )
        ),
        FOREIGN KEY (run_id, scenario_id)
            REFERENCES scenarios (run_id, scenario_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, idempotency_key)
    ) STRICT
    """,
    """
    CREATE INDEX schedule_entries_due_idx
        ON schedule_entries (
            run_id,
            consumed_at,
            logical_time_ns,
            scenario_ordinal,
            step_ordinal,
            delivery_ordinal,
            attempt_ordinal,
            deterministic_tie_key
        )
    """,
    """
    CREATE TABLE observer_series (
        observation_id TEXT PRIMARY KEY
            CHECK (
                length(observation_id) = 38
                AND substr(observation_id, 1, 12) = 'observation_'
                AND substr(observation_id, 13, 1) GLOB '[0-7]'
                AND substr(observation_id, 13)
                    NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        event_id TEXT,
        checkpoint TEXT NOT NULL
            CHECK (length(checkpoint) BETWEEN 1 AND 128),
        observer_id TEXT NOT NULL
            CHECK (length(observer_id) BETWEEN 1 AND 256),
        state TEXT NOT NULL
            CHECK (
                state IN (
                    'scheduled',
                    'running',
                    'ok',
                    'pending',
                    'unsupported',
                    'error',
                    'timed_out',
                    'cancelled'
                )
            ),
        FOREIGN KEY (run_id, scenario_id)
            REFERENCES scenarios (run_id, scenario_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (run_id, scenario_id, event_id)
            REFERENCES events (run_id, scenario_id, event_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, scenario_id, observation_id)
    ) STRICT
    """,
    """
    CREATE UNIQUE INDEX observer_series_scope_without_event_idx
        ON observer_series (run_id, scenario_id, checkpoint, observer_id)
        WHERE event_id IS NULL
    """,
    """
    CREATE UNIQUE INDEX observer_series_scope_with_event_idx
        ON observer_series (
            run_id,
            scenario_id,
            event_id,
            checkpoint,
            observer_id
        )
        WHERE event_id IS NOT NULL
    """,
    """
    CREATE TABLE observation_samples (
        sample_id TEXT PRIMARY KEY
            CHECK (
                length(sample_id) = 33
                AND substr(sample_id, 1, 7) = 'sample_'
                AND substr(sample_id, 8, 1) GLOB '[0-7]'
                AND substr(sample_id, 8) NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        record_id TEXT NOT NULL UNIQUE
            CHECK (
                length(record_id) = 33
                AND substr(record_id, 1, 7) = 'record_'
                AND substr(record_id, 8, 1) GLOB '[0-7]'
                AND substr(record_id, 8) NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        observation_id TEXT NOT NULL,
        sample_sequence INTEGER NOT NULL
            CHECK (sample_sequence BETWEEN 1 AND 9007199254740991),
        status TEXT NOT NULL
            CHECK (status IN ('ok', 'pending', 'unsupported', 'error', 'timeout')),
        recorded_at TEXT NOT NULL
            CHECK (
                length(recorded_at) BETWEEN 20 AND 32
                AND substr(recorded_at, -1) = 'Z'
            ),
        snapshot_id TEXT
            CHECK (
                snapshot_id IS NULL
                OR length(snapshot_id) BETWEEN 1 AND 512
            ),
        evidence_json BLOB
            CHECK (
                evidence_json IS NULL
                OR length(evidence_json) <= 16777216
            ),
        error_json BLOB
            CHECK (
                error_json IS NULL
                OR length(error_json) <= 65536
            ),
        CHECK (status <> 'ok' OR snapshot_id IS NOT NULL),
        FOREIGN KEY (run_id, scenario_id, observation_id)
            REFERENCES observer_series (run_id, scenario_id, observation_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (observation_id, sample_sequence),
        UNIQUE (run_id, scenario_id, observation_id, sample_id)
    ) STRICT
    """,
    """
    CREATE TABLE assertions (
        assertion_id TEXT PRIMARY KEY
            CHECK (
                length(assertion_id) = 36
                AND substr(assertion_id, 1, 10) = 'assertion_'
                AND substr(assertion_id, 11, 1) GLOB '[0-7]'
                AND substr(assertion_id, 11)
                    NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        type TEXT NOT NULL
            CHECK (length(type) BETWEEN 1 AND 128),
        policy_json BLOB
            CHECK (
                policy_json IS NULL
                OR length(policy_json) <= 1048576
            ),
        required INTEGER NOT NULL DEFAULT 1
            CHECK (required IN (0, 1)),
        state TEXT NOT NULL
            CHECK (
                state IN (
                    'pending',
                    'running',
                    'passed',
                    'failed',
                    'error',
                    'unsupported',
                    'cancelled'
                )
            ),
        FOREIGN KEY (run_id, scenario_id)
            REFERENCES scenarios (run_id, scenario_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, scenario_id, assertion_id)
    ) STRICT
    """,
    """
    CREATE TABLE assertion_evaluations (
        evaluation_id TEXT PRIMARY KEY
            CHECK (
                length(evaluation_id) = 37
                AND substr(evaluation_id, 1, 11) = 'evaluation_'
                AND substr(evaluation_id, 12, 1) GLOB '[0-7]'
                AND substr(evaluation_id, 12)
                    NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        record_id TEXT NOT NULL UNIQUE
            CHECK (
                length(record_id) = 33
                AND substr(record_id, 1, 7) = 'record_'
                AND substr(record_id, 8, 1) GLOB '[0-7]'
                AND substr(record_id, 8) NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'
            ),
        run_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        assertion_id TEXT NOT NULL,
        evaluation_sequence INTEGER NOT NULL
            CHECK (evaluation_sequence BETWEEN 1 AND 9007199254740991),
        result TEXT NOT NULL
            CHECK (result IN ('pass', 'fail', 'error', 'skipped', 'pending')),
        recorded_at TEXT NOT NULL
            CHECK (
                length(recorded_at) BETWEEN 20 AND 32
                AND substr(recorded_at, -1) = 'Z'
            ),
        expected_json BLOB
            CHECK (
                expected_json IS NULL
                OR length(expected_json) <= 16777216
            ),
        actual_json BLOB
            CHECK (
                actual_json IS NULL
                OR length(actual_json) <= 16777216
            ),
        comparison TEXT
            CHECK (
                comparison IS NULL
                OR length(comparison) BETWEEN 1 AND 256
            ),
        message TEXT
            CHECK (message IS NULL OR length(message) BETWEEN 1 AND 4096),
        FOREIGN KEY (run_id, scenario_id, assertion_id)
            REFERENCES assertions (run_id, scenario_id, assertion_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (assertion_id, evaluation_sequence),
        UNIQUE (run_id, evaluation_id)
    ) STRICT
    """,
    """
    CREATE TABLE evidence_links (
        evaluation_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL
            CHECK (ordinal BETWEEN 0 AND 9007199254740991),
        evidence_kind TEXT NOT NULL
            CHECK (
                evidence_kind IN (
                    'attempt',
                    'observation',
                    'record',
                    'artifact',
                    'transition',
                    'recovery_decision'
                )
            ),
        evidence_id TEXT NOT NULL
            CHECK (
                length(evidence_id) BETWEEN 1 AND 96
                AND evidence_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        PRIMARY KEY (evaluation_id, ordinal),
        FOREIGN KEY (run_id, evaluation_id)
            REFERENCES assertion_evaluations (run_id, evaluation_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (evaluation_id, evidence_kind, evidence_id)
    ) STRICT
    """,
    """
    CREATE TABLE transitions (
        transition_id TEXT PRIMARY KEY
            CHECK (
                length(transition_id) BETWEEN 1 AND 96
                AND transition_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        run_id TEXT NOT NULL,
        sequence INTEGER NOT NULL
            CHECK (sequence BETWEEN 1 AND 9007199254740991),
        entity_type TEXT NOT NULL
            CHECK (
                entity_type IN (
                    'run',
                    'scenario',
                    'delivery',
                    'attempt',
                    'observation',
                    'assertion'
                )
            ),
        entity_id TEXT NOT NULL
            CHECK (
                length(entity_id) BETWEEN 1 AND 96
                AND entity_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        from_state TEXT,
        to_state TEXT NOT NULL,
        trigger_category TEXT NOT NULL
            CHECK (
                length(trigger_category) BETWEEN 1 AND 64
                AND substr(trigger_category, 1, 1) GLOB '[a-z]'
                AND trigger_category NOT GLOB '*[^a-z0-9_]*'
            ),
        causal_record_id TEXT
            CHECK (
                causal_record_id IS NULL
                OR (
                    length(causal_record_id) BETWEEN 1 AND 96
                    AND causal_record_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
                )
            ),
        wall_time TEXT NOT NULL
            CHECK (
                length(wall_time) BETWEEN 20 AND 32
                AND substr(wall_time, -1) = 'Z'
            ),
        monotonic_elapsed_ns INTEGER
            CHECK (
                monotonic_elapsed_ns IS NULL
                OR monotonic_elapsed_ns BETWEEN 0 AND 9007199254740991
            ),
        monotonic_unavailable INTEGER NOT NULL DEFAULT 0
            CHECK (monotonic_unavailable IN (0, 1)),
        logical_time_ns INTEGER
            CHECK (
                logical_time_ns IS NULL
                OR logical_time_ns
                    BETWEEN -9007199254740991 AND 9007199254740991
            ),
        owner_epoch INTEGER NOT NULL
            CHECK (owner_epoch BETWEEN 0 AND 9223372036854775807),
        idempotency_key TEXT NOT NULL
            CHECK (
                length(idempotency_key) BETWEEN 1 AND 256
                AND idempotency_key NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        CHECK (
            (monotonic_unavailable = 0 AND monotonic_elapsed_ns IS NOT NULL)
            OR (
                monotonic_unavailable = 1
                AND monotonic_elapsed_ns IS NULL
            )
        ),
        CHECK (
            (
                entity_type = 'run'
                AND (
                    (
                        from_state IS NULL
                        AND to_state = 'planned'
                    )
                    OR (
                        from_state IN (
                            'planned',
                            'running',
                            'paused',
                            'completed',
                            'cancelled',
                            'failed'
                        )
                        AND to_state IN (
                            'planned',
                            'running',
                            'paused',
                            'completed',
                            'cancelled',
                            'failed'
                        )
                    )
                )
            )
            OR (
                entity_type = 'scenario'
                AND (
                    (
                        from_state IS NULL
                        AND to_state = 'pending'
                    )
                    OR (
                        from_state IN (
                            'pending',
                            'eligible',
                            'running',
                            'passed',
                            'failed',
                            'error',
                            'skipped',
                            'ambiguous',
                            'cancelled'
                        )
                        AND to_state IN (
                            'pending',
                            'eligible',
                            'running',
                            'passed',
                            'failed',
                            'error',
                            'skipped',
                            'ambiguous',
                            'cancelled'
                        )
                    )
                )
            )
            OR (
                entity_type = 'delivery'
                AND (
                    (
                        from_state IS NULL
                        AND to_state = 'pending'
                    )
                    OR (
                        from_state IN (
                            'pending',
                            'eligible',
                            'active',
                            'satisfied',
                            'exhausted',
                            'ambiguous',
                            'cancelled',
                            'skipped'
                        )
                        AND to_state IN (
                            'pending',
                            'eligible',
                            'active',
                            'satisfied',
                            'exhausted',
                            'ambiguous',
                            'cancelled',
                            'skipped'
                        )
                    )
                )
            )
            OR (
                entity_type = 'attempt'
                AND (
                    (
                        from_state IS NULL
                        AND to_state = 'scheduled'
                    )
                    OR (
                        from_state IN (
                            'scheduled',
                            'claimed',
                            'pre_send_committed',
                            'connecting',
                            'sending',
                            'awaiting_response',
                            'response_observed',
                            'not_sent',
                            'succeeded',
                            'rejected',
                            'transport_failed',
                            'unknown_outcome',
                            'cancelled'
                        )
                        AND to_state IN (
                            'scheduled',
                            'claimed',
                            'pre_send_committed',
                            'connecting',
                            'sending',
                            'awaiting_response',
                            'response_observed',
                            'not_sent',
                            'succeeded',
                            'rejected',
                            'transport_failed',
                            'unknown_outcome',
                            'cancelled'
                        )
                    )
                )
            )
            OR (
                entity_type = 'observation'
                AND (
                    (
                        from_state IS NULL
                        AND to_state = 'scheduled'
                    )
                    OR (
                        from_state IN (
                            'scheduled',
                            'running',
                            'ok',
                            'pending',
                            'unsupported',
                            'error',
                            'timed_out',
                            'cancelled'
                        )
                        AND to_state IN (
                            'scheduled',
                            'running',
                            'ok',
                            'pending',
                            'unsupported',
                            'error',
                            'timed_out',
                            'cancelled'
                        )
                    )
                )
            )
            OR (
                entity_type = 'assertion'
                AND (
                    (
                        from_state IS NULL
                        AND to_state = 'pending'
                    )
                    OR (
                        from_state IN (
                            'pending',
                            'running',
                            'passed',
                            'failed',
                            'error',
                            'unsupported',
                            'cancelled'
                        )
                        AND to_state IN (
                            'pending',
                            'running',
                            'passed',
                            'failed',
                            'error',
                            'unsupported',
                            'cancelled'
                        )
                    )
                )
            )
        ),
        FOREIGN KEY (run_id) REFERENCES runs (run_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, sequence),
        UNIQUE (run_id, idempotency_key)
    ) STRICT
    """,
    """
    CREATE INDEX transitions_entity_sequence_idx
        ON transitions (run_id, entity_type, entity_id, sequence)
    """,
    """
    CREATE TABLE recovery_decisions (
        decision_id TEXT PRIMARY KEY
            CHECK (
                length(decision_id) BETWEEN 1 AND 96
                AND decision_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        run_id TEXT NOT NULL,
        sequence INTEGER NOT NULL
            CHECK (sequence BETWEEN 1 AND 9007199254740991),
        scenario_id TEXT,
        attempt_id TEXT,
        policy TEXT NOT NULL
            CHECK (
                policy IN (
                    'stop',
                    'observe',
                    'redeliver',
                    'operator_decision'
                )
            ),
        decision TEXT NOT NULL
            CHECK (
                length(decision) BETWEEN 1 AND 128
                AND substr(decision, 1, 1) GLOB '[a-z]'
                AND decision NOT GLOB '*[^a-z0-9_]*'
            ),
        reason TEXT NOT NULL
            CHECK (length(reason) BETWEEN 1 AND 4096),
        operator_identity_fingerprint TEXT
            CHECK (
                operator_identity_fingerprint IS NULL
                OR (
                    length(operator_identity_fingerprint) = 71
                    AND substr(operator_identity_fingerprint, 1, 7) = 'sha256:'
                    AND substr(operator_identity_fingerprint, 8)
                        NOT GLOB '*[^0-9a-f]*'
                )
            ),
        operator_input_digest TEXT
            CHECK (
                operator_input_digest IS NULL
                OR (
                    length(operator_input_digest) = 71
                    AND substr(operator_input_digest, 1, 7) = 'sha256:'
                    AND substr(operator_input_digest, 8)
                        NOT GLOB '*[^0-9a-f]*'
                )
            ),
        recorded_at TEXT NOT NULL
            CHECK (
                length(recorded_at) BETWEEN 20 AND 32
                AND substr(recorded_at, -1) = 'Z'
            ),
        CHECK (scenario_id IS NOT NULL OR attempt_id IS NOT NULL),
        CHECK (attempt_id IS NULL OR scenario_id IS NOT NULL),
        FOREIGN KEY (run_id, scenario_id)
            REFERENCES scenarios (run_id, scenario_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (run_id, scenario_id, attempt_id)
            REFERENCES attempts (run_id, scenario_id, attempt_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, sequence),
        UNIQUE (run_id, decision_id)
    ) STRICT
    """,
    """
    CREATE TABLE recovery_decision_evidence (
        decision_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL
            CHECK (ordinal BETWEEN 0 AND 9007199254740991),
        evidence_kind TEXT NOT NULL
            CHECK (
                length(evidence_kind) BETWEEN 1 AND 64
                AND substr(evidence_kind, 1, 1) GLOB '[a-z]'
                AND evidence_kind NOT GLOB '*[^a-z0-9_]*'
            ),
        evidence_id TEXT NOT NULL
            CHECK (
                length(evidence_id) BETWEEN 1 AND 96
                AND evidence_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        PRIMARY KEY (decision_id, ordinal),
        FOREIGN KEY (run_id, decision_id)
            REFERENCES recovery_decisions (run_id, decision_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (decision_id, evidence_kind, evidence_id)
    ) STRICT
    """,
    """
    CREATE TABLE redaction_events (
        redaction_id TEXT PRIMARY KEY
            CHECK (
                length(redaction_id) BETWEEN 1 AND 96
                AND redaction_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        run_id TEXT NOT NULL,
        sequence INTEGER NOT NULL
            CHECK (sequence BETWEEN 1 AND 9007199254740991),
        source_type TEXT NOT NULL
            CHECK (
                length(source_type) BETWEEN 1 AND 64
                AND substr(source_type, 1, 1) GLOB '[a-z]'
                AND source_type NOT GLOB '*[^a-z0-9_]*'
            ),
        source_id TEXT NOT NULL
            CHECK (
                length(source_id) BETWEEN 1 AND 96
                AND source_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        rule_id TEXT NOT NULL
            CHECK (
                length(rule_id) BETWEEN 1 AND 128
                AND rule_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        replacement_type TEXT NOT NULL
            CHECK (
                length(replacement_type) BETWEEN 1 AND 64
                AND substr(replacement_type, 1, 1) GLOB '[a-z]'
                AND replacement_type NOT GLOB '*[^a-z0-9_]*'
            ),
        recorded_at TEXT NOT NULL
            CHECK (
                length(recorded_at) BETWEEN 20 AND 32
                AND substr(recorded_at, -1) = 'Z'
            ),
        FOREIGN KEY (run_id) REFERENCES runs (run_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, sequence)
    ) STRICT
    """,
    """
    CREATE TABLE artifacts (
        artifact_id TEXT PRIMARY KEY
            CHECK (
                length(artifact_id) BETWEEN 1 AND 96
                AND artifact_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
            ),
        run_id TEXT NOT NULL,
        relative_path TEXT NOT NULL
            CHECK (
                length(relative_path) BETWEEN 1 AND 1024
                AND substr(relative_path, 1, 1) <> '/'
                AND instr(relative_path, '\\') = 0
                AND instr(relative_path, ':') = 0
                AND instr(relative_path, '//') = 0
                AND relative_path <> '..'
                AND relative_path NOT LIKE '../%'
                AND relative_path NOT LIKE '%/../%'
                AND relative_path NOT LIKE '%/..'
            ),
        media_type TEXT NOT NULL
            CHECK (length(media_type) BETWEEN 1 AND 255),
        byte_length INTEGER NOT NULL
            CHECK (byte_length BETWEEN 0 AND 9007199254740991),
        sha256 TEXT NOT NULL
            CHECK (
                length(sha256) = 71
                AND substr(sha256, 1, 7) = 'sha256:'
                AND substr(sha256, 8) NOT GLOB '*[^0-9a-f]*'
            ),
        generated_at TEXT NOT NULL
            CHECK (
                length(generated_at) BETWEEN 20 AND 32
                AND substr(generated_at, -1) = 'Z'
            ),
        input_watermark TEXT
            CHECK (
                input_watermark IS NULL
                OR (
                    length(input_watermark) = 71
                    AND substr(input_watermark, 1, 7) = 'sha256:'
                    AND substr(input_watermark, 8) NOT GLOB '*[^0-9a-f]*'
                )
            ),
        renderer_version TEXT
            CHECK (
                renderer_version IS NULL
                OR length(renderer_version) BETWEEN 1 AND 128
            ),
        FOREIGN KEY (run_id) REFERENCES runs (run_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        UNIQUE (run_id, relative_path)
    ) STRICT
    """,
    """
    CREATE TRIGGER transitions_reject_update
    BEFORE UPDATE ON transitions
    BEGIN
        SELECT RAISE(ABORT, 'transition records are append-only');
    END
    """,
    """
    CREATE TRIGGER transitions_reject_delete
    BEFORE DELETE ON transitions
    BEGIN
        SELECT RAISE(ABORT, 'transition records are append-only');
    END
    """,
    """
    CREATE TRIGGER observation_samples_reject_update
    BEFORE UPDATE ON observation_samples
    BEGIN
        SELECT RAISE(ABORT, 'observation samples are append-only');
    END
    """,
    """
    CREATE TRIGGER observation_samples_reject_delete
    BEFORE DELETE ON observation_samples
    BEGIN
        SELECT RAISE(ABORT, 'observation samples are append-only');
    END
    """,
    """
    CREATE TRIGGER assertion_evaluations_reject_update
    BEFORE UPDATE ON assertion_evaluations
    BEGIN
        SELECT RAISE(ABORT, 'assertion evaluations are append-only');
    END
    """,
    """
    CREATE TRIGGER assertion_evaluations_reject_delete
    BEFORE DELETE ON assertion_evaluations
    BEGIN
        SELECT RAISE(ABORT, 'assertion evaluations are append-only');
    END
    """,
    """
    CREATE TRIGGER evidence_links_reject_update
    BEFORE UPDATE ON evidence_links
    BEGIN
        SELECT RAISE(ABORT, 'evidence links are append-only');
    END
    """,
    """
    CREATE TRIGGER evidence_links_reject_delete
    BEFORE DELETE ON evidence_links
    BEGIN
        SELECT RAISE(ABORT, 'evidence links are append-only');
    END
    """,
    """
    CREATE TRIGGER recovery_decisions_reject_update
    BEFORE UPDATE ON recovery_decisions
    BEGIN
        SELECT RAISE(ABORT, 'recovery decisions are append-only');
    END
    """,
    """
    CREATE TRIGGER recovery_decisions_reject_delete
    BEFORE DELETE ON recovery_decisions
    BEGIN
        SELECT RAISE(ABORT, 'recovery decisions are append-only');
    END
    """,
    """
    CREATE TRIGGER recovery_decision_evidence_reject_update
    BEFORE UPDATE ON recovery_decision_evidence
    BEGIN
        SELECT RAISE(ABORT, 'recovery evidence links are append-only');
    END
    """,
    """
    CREATE TRIGGER recovery_decision_evidence_reject_delete
    BEFORE DELETE ON recovery_decision_evidence
    BEGIN
        SELECT RAISE(ABORT, 'recovery evidence links are append-only');
    END
    """,
    """
    CREATE TRIGGER redaction_events_reject_update
    BEFORE UPDATE ON redaction_events
    BEGIN
        SELECT RAISE(ABORT, 'redaction events are append-only');
    END
    """,
    """
    CREATE TRIGGER redaction_events_reject_delete
    BEFORE DELETE ON redaction_events
    BEGIN
        SELECT RAISE(ABORT, 'redaction events are append-only');
    END
    """,
)
