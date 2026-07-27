"""Strict, secret-safe internal evidence for one physical HTTP attempt."""
# ruff: noqa: C901, D105, PLR2004, INP001

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from webhook_receiver_conformance.network.transport import SocketFamily

REDACTED_HEADER_VALUE = "[REDACTED]"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_MAX_SIGNED_INT64 = (2**63) - 1


class HeaderOwner(StrEnum):
    """The boundary that owns one emitted request header."""

    USER = "user"
    SIGNER = "signer"
    CLIENT = "client"


class AttemptOutcome(StrEnum):
    """The three transport facts the journal needs for safe recovery."""

    NOT_SENT = "not_sent"
    RESPONSE = "response"
    UNKNOWN_OUTCOME = "unknown_outcome"


class AttemptPhase(StrEnum):
    """Stable physical phases used for timeout and failure evidence."""

    VALIDATION = "validation"
    POOL = "pool"
    RESOLUTION = "resolution"
    CONNECT = "connect"
    WRITE = "write"
    RESPONSE_HEADERS = "response_headers"
    RESPONSE_BODY = "response_body"
    CLOSE = "close"


class AttemptErrorCode(StrEnum):
    """Closed IF-HTTP error vocabulary plus bounded input failures."""

    CONNECT_TIMEOUT = "connect_timeout"
    READ_TIMEOUT = "read_timeout"
    WRITE_TIMEOUT = "write_timeout"
    POOL_TIMEOUT = "pool_timeout"
    TOTAL_TIMEOUT = "total_timeout"
    TLS_ERROR = "tls_error"
    CONNECTION_ERROR = "connection_error"
    PROTOCOL_ERROR = "protocol_error"
    RESPONSE_TOO_LARGE = "response_too_large"
    RESOURCE_LIMIT = "resource_limit"
    INVALID_REQUEST = "invalid_request"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class HeaderEvidence:
    """A header name and owner without its potentially sensitive value."""

    name: str
    owner: HeaderOwner
    value_redacted: str = REDACTED_HEADER_VALUE

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not 1 <= len(self.name) <= 256
            or _HEADER_NAME.fullmatch(self.name) is None
        ):
            message = "evidence header names must be bounded HTTP tokens"
            raise ValueError(message)
        if type(self.owner) is not HeaderOwner:
            message = "header owner must be a HeaderOwner member"
            raise TypeError(message)
        if self.value_redacted != REDACTED_HEADER_VALUE:
            message = "header evidence may contain only the stable redaction marker"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class RequestEvidence:
    """Digest, byte count, and value-free ordered request-header evidence."""

    body_sha256: str
    body_bytes: int
    headers: tuple[HeaderEvidence, ...]
    method: str = "POST"

    def __post_init__(self) -> None:
        _validate_digest(self.body_sha256)
        _nonnegative_int64(self.body_bytes, field_name="request body byte count")
        if self.method != "POST":
            message = "v0.1 request evidence requires POST"
            raise ValueError(message)
        if type(self.headers) is not tuple or any(
            type(header) is not HeaderEvidence for header in self.headers
        ):
            message = "request header evidence must be a tuple of HeaderEvidence"
            raise TypeError(message)


@dataclass(frozen=True, slots=True, repr=False)
class ResponseEvidence:
    """Bounded response facts; retained bytes are deliberately absent from repr."""

    status: int
    headers: tuple[str, ...]
    body_sha256: str | None
    observed_body_sha256: str
    body_bytes: int
    observed_body_bytes: int
    captured_body: bytes = field(repr=False)
    truncated: bool = False
    body_complete: bool = True
    protocol: str = "HTTP/1.1"

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            message = "response status must be an integer from 100 through 599"
            raise ValueError(message)
        if self.protocol != "HTTP/1.1":
            message = "v0.1 response evidence requires HTTP/1.1"
            raise ValueError(message)
        if type(self.headers) is not tuple or any(
            type(name) is not str or _HEADER_NAME.fullmatch(name) is None for name in self.headers
        ):
            message = "response header evidence must contain HTTP token names"
            raise ValueError(message)
        if self.body_sha256 is not None:
            _validate_digest(self.body_sha256)
        _validate_digest(self.observed_body_sha256)
        _nonnegative_int64(self.body_bytes, field_name="response body byte count")
        _nonnegative_int64(
            self.observed_body_bytes,
            field_name="observed response body byte count",
        )
        if self.observed_body_bytes > self.body_bytes:
            message = "observed response bytes cannot exceed total response bytes"
            raise ValueError(message)
        if type(self.captured_body) is not bytes:
            message = "captured response body must be bytes"
            raise TypeError(message)
        if type(self.truncated) is not bool:
            message = "response truncation state must be a bool"
            raise TypeError(message)
        if type(self.body_complete) is not bool:
            message = "response completeness state must be a bool"
            raise TypeError(message)
        if self.body_complete:
            if self.observed_body_bytes != self.body_bytes or self.body_sha256 is None:
                message = "complete response evidence requires a full byte count and digest"
                raise ValueError(message)
            if self.body_sha256 != self.observed_body_sha256:
                message = "complete response digest must equal its observed digest"
                raise ValueError(message)
        elif self.body_sha256 is not None:
            message = "incomplete response evidence cannot claim a full-body digest"
            raise ValueError(message)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(status={self.status!r}, headers={self.headers!r}, "
            f"body_sha256={self.body_sha256!r}, body_bytes={self.body_bytes!r}, "
            f"observed_body_sha256={self.observed_body_sha256!r}, "
            f"observed_body_bytes={self.observed_body_bytes!r}, "
            f"captured_bytes={len(self.captured_body)!r}, truncated={self.truncated!r}, "
            f"body_complete={self.body_complete!r}, protocol={self.protocol!r})"
        )


@dataclass(frozen=True, slots=True)
class PeerEvidence:
    """The authorized pin and actual connected peer."""

    authorized_address: str
    authorized_family: SocketFamily
    peer_address: str
    peer_family: SocketFamily
    tls: bool
    protocol: str = "HTTP/1.1"

    def __post_init__(self) -> None:
        if (
            type(self.authorized_family) is not SocketFamily
            or type(self.peer_family) is not SocketFamily
        ):
            message = "peer evidence requires SocketFamily members"
            raise TypeError(message)
        if type(self.tls) is not bool:
            message = "TLS evidence must be a bool"
            raise TypeError(message)
        if self.protocol != "HTTP/1.1":
            message = "v0.1 peer evidence requires HTTP/1.1"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class AttemptTimings:
    """Monotonic durations used by timeout and acknowledgment assertions."""

    total_elapsed_ns: int
    pool_elapsed_ns: int
    connect_elapsed_ns: int
    write_elapsed_ns: int | None = None
    response_headers_elapsed_ns: int | None = None
    request_send_started_ns: int | None = None
    response_headers_completed_ns: int | None = None

    def __post_init__(self) -> None:
        for field_name, value in (
            ("total elapsed", self.total_elapsed_ns),
            ("pool elapsed", self.pool_elapsed_ns),
            ("connect elapsed", self.connect_elapsed_ns),
        ):
            _nonnegative_int64(value, field_name=field_name)
        for field_name, value in (
            ("write elapsed", self.write_elapsed_ns),
            ("response headers elapsed", self.response_headers_elapsed_ns),
            ("request send start", self.request_send_started_ns),
            ("response headers completion", self.response_headers_completed_ns),
        ):
            if value is not None:
                _nonnegative_int64(value, field_name=field_name)
        if (
            self.request_send_started_ns is not None
            and self.response_headers_completed_ns is not None
            and self.response_headers_completed_ns < self.request_send_started_ns
        ):
            message = "response headers cannot complete before request send starts"
            raise ValueError(message)

    @property
    def acknowledgment_elapsed_ns(self) -> int | None:
        """Return send-start through complete-headers duration when observable."""
        if self.request_send_started_ns is None or self.response_headers_completed_ns is None:
            return None
        return self.response_headers_completed_ns - self.request_send_started_ns


@dataclass(frozen=True, slots=True)
class AttemptError:
    """A bounded machine-readable transport failure."""

    code: AttemptErrorCode
    phase: AttemptPhase
    message_redacted: str
    retryable: bool

    def __post_init__(self) -> None:
        if type(self.code) is not AttemptErrorCode:
            message = "attempt error code must be an AttemptErrorCode member"
            raise TypeError(message)
        if type(self.phase) is not AttemptPhase:
            message = "attempt error phase must be an AttemptPhase member"
            raise TypeError(message)
        if (
            type(self.message_redacted) is not str
            or not 1 <= len(self.message_redacted) <= 512
            or "\r" in self.message_redacted
            or "\n" in self.message_redacted
        ):
            message = "attempt error message must be bounded and line-safe"
            raise ValueError(message)
        if type(self.retryable) is not bool:
            message = "attempt retryability must be a bool"
            raise TypeError(message)


@dataclass(frozen=True, slots=True)
class AttemptResult:
    """Complete internal IF-HTTP result for exactly one physical attempt."""

    outcome: AttemptOutcome
    request: RequestEvidence
    timings: AttemptTimings
    response: ResponseEvidence | None = None
    peer: PeerEvidence | None = None
    error: AttemptError | None = None
    request_bytes_may_have_left: bool = False

    def __post_init__(self) -> None:
        if type(self.outcome) is not AttemptOutcome:
            message = "attempt outcome must be an AttemptOutcome member"
            raise TypeError(message)
        if type(self.request) is not RequestEvidence:
            message = "attempt result requires RequestEvidence"
            raise TypeError(message)
        if type(self.timings) is not AttemptTimings:
            message = "attempt result requires AttemptTimings"
            raise TypeError(message)
        if self.response is not None and type(self.response) is not ResponseEvidence:
            message = "attempt response must be ResponseEvidence"
            raise TypeError(message)
        if self.peer is not None and type(self.peer) is not PeerEvidence:
            message = "attempt peer must be PeerEvidence"
            raise TypeError(message)
        if self.error is not None and type(self.error) is not AttemptError:
            message = "attempt error must be AttemptError"
            raise TypeError(message)
        if type(self.request_bytes_may_have_left) is not bool:
            message = "request send uncertainty must be a bool"
            raise TypeError(message)
        if self.outcome is AttemptOutcome.NOT_SENT and self.request_bytes_may_have_left:
            message = "not_sent cannot claim request bytes may have left"
            raise ValueError(message)
        if self.outcome is AttemptOutcome.UNKNOWN_OUTCOME and not self.request_bytes_may_have_left:
            message = "unknown_outcome requires possible request-byte transmission"
            raise ValueError(message)
        if self.outcome is AttemptOutcome.RESPONSE and self.response is None:
            message = "response outcome requires response evidence"
            raise ValueError(message)
        if self.response is not None and self.outcome is not AttemptOutcome.RESPONSE:
            message = "response evidence requires a response outcome"
            raise ValueError(message)


def _validate_digest(value: object) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        message = "body digest must be a lowercase sha256 digest"
        raise ValueError(message)


def _nonnegative_int64(value: object, *, field_name: str) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_SIGNED_INT64:
        message = f"{field_name} must be a nonnegative signed-int64 integer"
        raise ValueError(message)
