"""Closed vocabularies used by domain entities and evidence records."""
# ruff: noqa: INP001

from __future__ import annotations

from enum import StrEnum


class RunState(StrEnum):
    """Normative STATE-001 run states."""

    PLANNED = "planned"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ScenarioState(StrEnum):
    """Normative STATE-002 scenario states."""

    PENDING = "pending"
    ELIGIBLE = "eligible"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    AMBIGUOUS = "ambiguous"
    CANCELLED = "cancelled"


class DeliveryState(StrEnum):
    """Normative STATE-003 planned-delivery states."""

    PENDING = "pending"
    ELIGIBLE = "eligible"
    ACTIVE = "active"
    SATISFIED = "satisfied"
    EXHAUSTED = "exhausted"
    AMBIGUOUS = "ambiguous"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class AttemptState(StrEnum):
    """Normative STATE-004 physical-attempt states."""

    SCHEDULED = "scheduled"
    CLAIMED = "claimed"
    PRE_SEND_COMMITTED = "pre_send_committed"
    CONNECTING = "connecting"
    SENDING = "sending"
    AWAITING_RESPONSE = "awaiting_response"
    RESPONSE_OBSERVED = "response_observed"
    NOT_SENT = "not_sent"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    TRANSPORT_FAILED = "transport_failed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    CANCELLED = "cancelled"


class ObservationState(StrEnum):
    """Normative STATE-005 observation-series states."""

    SCHEDULED = "scheduled"
    RUNNING = "running"
    OK = "ok"
    PENDING = "pending"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class AssertionState(StrEnum):
    """Normative STATE-006 assertion states."""

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    UNSUPPORTED = "unsupported"
    CANCELLED = "cancelled"


class AttemptEvidenceState(StrEnum):
    """Serialized delivery-record attempt states."""

    SCHEDULED = "scheduled"
    LEASED = "leased"
    SENDING = "sending"
    ACKNOWLEDGED = "acknowledged"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    CONNECTION_FAILED = "connection_failed"
    PROTOCOL_FAILED = "protocol_failed"
    CANCELLED = "cancelled"
    UNKNOWN_OUTCOME = "unknown_outcome"


class AttemptClassification(StrEnum):
    """Serialized delivery-record classifications."""

    PLANNED = "planned"
    RECEIVER_ACCEPTED = "receiver_accepted"
    RECEIVER_REJECTED = "receiver_rejected"
    ENVIRONMENT_FAILURE = "environment_failure"
    HARNESS_FAILURE = "harness_failure"
    CANCELLED = "cancelled"
    AMBIGUOUS = "ambiguous"


class ObservationStatus(StrEnum):
    """Serialized observation-record sample statuses."""

    OK = "ok"
    PENDING = "pending"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    TIMEOUT = "timeout"


class AssertionResult(StrEnum):
    """Serialized assertion-record evaluation results."""

    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"
    PENDING = "pending"


class EvidenceValueType(StrEnum):
    """JSON value-kind annotations used by receiver evidence."""

    NULL = "null"
    BOOLEAN = "boolean"
    INTEGER = "integer"
    NUMBER = "number"
    STRING = "string"
    ARRAY = "array"
    OBJECT = "object"
