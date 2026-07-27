"""Bounded, one-shot HTTP/1.1 execution over an authorized pinned stream."""
# ruff: noqa: BLE001, C901, D105, D107, EM101, INP001, N818, PLR0911, PLR0912, PLR0913, PLR2004, S113, TRY003, TRY300

from __future__ import annotations

import hashlib
import math
import re
import ssl
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from urllib.parse import quote

import anyio
import httpx

from webhook_receiver_conformance.http.evidence import (
    AttemptError,
    AttemptErrorCode,
    AttemptOutcome,
    AttemptPhase,
    AttemptProgressCheckpoint,
    AttemptResult,
    AttemptTimings,
    HeaderEvidence,
    HeaderOwner,
    PeerEvidence,
    RequestEvidence,
    ResponseEvidence,
)
from webhook_receiver_conformance.network.dialer import (
    DialErrorCode,
    DialPhase,
    DialTimeouts,
    PinnedConnection,
    PinnedDestinationDialer,
    PinnedDialError,
)
from webhook_receiver_conformance.network.policy import (
    DestinationPolicy,
    validate_destination_policy,
)
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
)

DEFAULT_MAX_REQUEST_BYTES: Final = 1_048_576
HARD_MAX_REQUEST_BYTES: Final = 16_777_216
DEFAULT_RESPONSE_CAPTURE_BYTES: Final = 65_536
HARD_RESPONSE_CAPTURE_BYTES: Final = 1_048_576
DEFAULT_RESPONSE_DRAIN_BYTES: Final = 1_048_576
DEFAULT_MAX_HEADER_BYTES: Final = 65_536
DEFAULT_MAX_HEADERS: Final = 128
DEFAULT_CLOSE_TIMEOUT_NS: Final = 1_000_000_000
MAX_TIMEOUT_NS: Final = (2**63) - 1
MAX_HEADER_VALUE_BYTES: Final = 8_192
MAX_HTTP_HEADER_NAME_BYTES: Final = 256
MAX_RECEIVE_BYTES: Final = 65_536
USER_AGENT: Final = "webhook-receiver-conformance/0.1"
_NANOSECONDS_PER_SECOND = 1_000_000_000
_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_STATUS_LINE = re.compile(rb"HTTP/1\.1 ([1-5][0-9]{2})(?: ([\x20-\x7e\t]*))?")
_CONTENT_LENGTH = re.compile(r"(?:0|[1-9][0-9]*)")
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]+")
_MEDIA_TYPE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+/[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_MAX_CONTENT_LENGTH_DIGITS = 19
_MAX_CHUNK_SIZE_DIGITS = 16
_MAX_SIGNED_INT64 = (2**63) - 1
_FORBIDDEN_USER_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    }
)
_CLIENT_OWNED_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "accept-encoding",
        "user-agent",
        "connection",
        "transfer-encoding",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    }
)
_NO_BODY_STATUSES = frozenset({204, 205, 304})

type ResponseRedactor = Callable[[bytes], bytes]
type AttemptProgressSink = Callable[[AttemptProgressCheckpoint], Awaitable[None]]


class HttpInputErrorCode(StrEnum):
    """Stable pre-send input failure categories."""

    INVALID_HEADER = "invalid-header"
    FORBIDDEN_HEADER = "forbidden-header"
    DUPLICATE_HEADER = "duplicate-header"
    REQUEST_TOO_LARGE = "request-too-large"
    REQUEST_TARGET_INVALID = "request-target-invalid"


class HttpInputError(ValueError):
    """A bounded request rejection that never includes a header value or body."""

    code: HttpInputErrorCode

    def __init__(self, code: HttpInputErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class HttpProgressError(RuntimeError):
    """A sanitized progress-sink failure that stopped later transport effects."""


@dataclass(frozen=True, slots=True, repr=False)
class HttpHeader:
    """One ordered caller- or signer-owned request header."""

    name: str
    value: str
    owner: HeaderOwner

    def __post_init__(self) -> None:
        _validate_header_name(self.name)
        _encode_header_value(self.value)
        if self.owner not in {HeaderOwner.USER, HeaderOwner.SIGNER}:
            message = "attempt input headers must be user- or signer-owned"
            raise ValueError(message)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(name={self.name!r}, "
            f"value_length={len(self.value)!r}, owner={self.owner!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class HttpAttemptCommand:
    """Exact bytes, ordered headers, and approved target for one attempt."""

    policy: DestinationPolicy
    body: bytes
    headers: tuple[HttpHeader, ...] = ()

    def __post_init__(self) -> None:
        validate_destination_policy(self.policy)
        if type(self.body) is not bytes:
            message = "attempt body must be exact immutable bytes"
            raise TypeError(message)
        if type(self.headers) is not tuple or any(
            type(header) is not HttpHeader for header in self.headers
        ):
            message = "attempt headers must be a tuple of HttpHeader"
            raise TypeError(message)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(policy={self.policy!r}, "
            f"body_bytes={len(self.body)!r}, "
            f"header_names={tuple(header.name for header in self.headers)!r})"
        )


@dataclass(frozen=True, slots=True)
class HttpTimeouts:
    """Unscaled physical monotonic timeout budget."""

    connect_ns: int
    write_ns: int
    read_ns: int
    pool_ns: int
    total_ns: int
    resolve_ns: int | None = None
    close_ns: int = DEFAULT_CLOSE_TIMEOUT_NS

    def __post_init__(self) -> None:
        for name, value in (
            ("connect", self.connect_ns),
            ("write", self.write_ns),
            ("read", self.read_ns),
            ("pool", self.pool_ns),
            ("total", self.total_ns),
            ("close", self.close_ns),
        ):
            _positive_timeout(value, field_name=name)
        if self.resolve_ns is not None:
            _positive_timeout(self.resolve_ns, field_name="resolve")

    @property
    def effective_resolve_ns(self) -> int:
        """Use the connection budget for resolution unless separately bounded."""
        return self.connect_ns if self.resolve_ns is None else self.resolve_ns


@dataclass(frozen=True, slots=True)
class HttpLimits:
    """Request, response, parser, and cleanup resource bounds."""

    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    response_capture_bytes: int = DEFAULT_RESPONSE_CAPTURE_BYTES
    response_drain_bytes: int = DEFAULT_RESPONSE_DRAIN_BYTES
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES
    max_headers: int = DEFAULT_MAX_HEADERS

    def __post_init__(self) -> None:
        _bounded_integer(
            self.max_request_bytes,
            field_name="request limit",
            minimum=1,
            maximum=HARD_MAX_REQUEST_BYTES,
        )
        _bounded_integer(
            self.response_capture_bytes,
            field_name="response capture limit",
            minimum=1,
            maximum=HARD_RESPONSE_CAPTURE_BYTES,
        )
        _bounded_integer(
            self.response_drain_bytes,
            field_name="response drain limit",
            minimum=1,
            maximum=DEFAULT_RESPONSE_DRAIN_BYTES,
        )
        if self.response_capture_bytes > self.response_drain_bytes:
            message = "response capture limit cannot exceed response drain limit"
            raise ValueError(message)
        _bounded_integer(
            self.max_header_bytes,
            field_name="response header limit",
            minimum=1_024,
            maximum=HARD_RESPONSE_CAPTURE_BYTES,
        )
        _bounded_integer(
            self.max_headers,
            field_name="response header count",
            minimum=1,
            maximum=1_024,
        )


@dataclass(frozen=True, slots=True)
class PoolInstrumentation:
    """One stable snapshot of the executor's connection-slot use."""

    limit: int
    active: int
    peak: int
    acquisitions: int
    keepalive_connections: int = 0


@dataclass(slots=True)
class _AttemptProgress:
    request: RequestEvidence
    started_ns: int
    pool_started_ns: int
    pool_elapsed_ns: int = 0
    connect_started_ns: int | None = None
    connect_elapsed_ns: int = 0
    send_started_ns: int | None = None
    write_elapsed_ns: int | None = None
    headers_completed_ns: int | None = None
    peer: PeerEvidence | None = None
    response: ResponseEvidence | None = None
    request_bytes_may_have_left: bool = False
    phase: AttemptPhase = AttemptPhase.POOL


@dataclass(frozen=True, slots=True)
class _WireRequest:
    target: bytes
    head: bytes
    body: bytes
    evidence: RequestEvidence
    httpx_headers: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True, slots=True)
class _ParsedHead:
    status: int
    headers: tuple[tuple[str, str], ...]
    body_prefix: bytes


class _ProtocolFailure(RuntimeError):
    pass


class _ResponseTooLarge(RuntimeError):
    def __init__(self, response: ResponseEvidence) -> None:
        self.response = response
        super().__init__("response exceeded the configured bounded drain limit")


class _BodyReadTimeoutError(TimeoutError):
    def __init__(self, body: bytes, *, total_body_bytes: int | None = None) -> None:
        self.body = body
        self.total_body_bytes = len(body) if total_body_bytes is None else total_body_bytes
        super().__init__("response body read exceeded its physical timeout")


class _PinnedHttpxTransport(httpx.AsyncBaseTransport):
    """One-use HTTPX transport that delegates to the exact raw executor."""

    __slots__ = ("_command_token", "_execute", "_result", "_used")

    def __init__(
        self,
        *,
        command_token: object,
        execute: Callable[[], Awaitable[AttemptResult]],
    ) -> None:
        self._command_token = command_token
        self._execute = execute
        self._result: AttemptResult | None = None
        self._used = False

    @property
    def result(self) -> AttemptResult:
        if self._result is None:
            message = "HTTPX transport did not produce attempt evidence"
            raise RuntimeError(message)
        return self._result

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._used:
            message = "one-shot pinned transport cannot dispatch twice"
            raise RuntimeError(message)
        if request.extensions.get("webhook_attempt_token") is not self._command_token:
            message = "HTTPX request did not carry the executor's attempt authority"
            raise RuntimeError(message)
        self._used = True
        execute = self._execute
        result = await execute()
        if type(result) is not AttemptResult:
            message = "raw pinned transport returned invalid attempt evidence"
            raise TypeError(message)
        self._result = result
        status = result.response.status if result.response is not None else 599
        return httpx.Response(
            status_code=status,
            headers={"content-length": "0"},
            content=b"",
            request=request,
            extensions={"http_version": b"HTTP/1.1"},
        )

    async def aclose(self) -> None:
        """No pooled stream survives one physical attempt."""


class HttpAttemptExecutor:
    """Execute one physical POST with no retries, redirects, or ambient authority."""

    __slots__ = (
        "_acquisitions",
        "_active",
        "_clock",
        "_dialer",
        "_limiter",
        "_limits",
        "_max_concurrency",
        "_peak",
        "_response_redactor",
        "_timeouts",
    )

    def __init__(
        self,
        *,
        dialer: PinnedDestinationDialer,
        timeouts: HttpTimeouts,
        limits: HttpLimits | None = None,
        max_concurrency: int = 10,
        clock: RuntimeClock | None = None,
        response_redactor: ResponseRedactor | None = None,
    ) -> None:
        if type(dialer) is not PinnedDestinationDialer:
            message = "executor requires a PinnedDestinationDialer"
            raise TypeError(message)
        if type(timeouts) is not HttpTimeouts:
            message = "executor requires HttpTimeouts"
            raise TypeError(message)
        _bounded_integer(
            max_concurrency,
            field_name="connection concurrency",
            minimum=1,
            maximum=50,
        )
        if clock is not None and type(clock) is not RuntimeClock:
            message = "executor clock must be a RuntimeClock"
            raise TypeError(message)
        if response_redactor is not None and not callable(response_redactor):
            message = "response redactor must be callable"
            raise TypeError(message)
        self._dialer = dialer
        self._timeouts = timeouts
        self._limits = HttpLimits() if limits is None else limits
        if type(self._limits) is not HttpLimits:
            message = "executor limits must be HttpLimits"
            raise TypeError(message)
        self._max_concurrency = max_concurrency
        self._limiter = anyio.CapacityLimiter(max_concurrency)
        self._clock = RuntimeClock(ClockPolicy(ClockMode.REAL)) if clock is None else clock
        self._response_redactor = (
            _identity_redactor if response_redactor is None else response_redactor
        )
        self._active = 0
        self._peak = 0
        self._acquisitions = 0

    @property
    def pool_instrumentation(self) -> PoolInstrumentation:
        """Return connection-slot facts without exposing mutable pool state."""
        return PoolInstrumentation(
            limit=self._max_concurrency,
            active=self._active,
            peak=self._peak,
            acquisitions=self._acquisitions,
        )

    async def execute(
        self,
        command: HttpAttemptCommand,
        *,
        progress_sink: AttemptProgressSink | None = None,
    ) -> AttemptResult:
        """Dispatch exactly one physical attempt through an HTTPX one-shot shell."""
        if progress_sink is not None and not callable(progress_sink):
            message = "progress_sink must be an async callable or None"
            raise TypeError(message)
        wire = _build_wire_request(command, limits=self._limits)
        started_ns = self._clock.monotonic_now_ns()
        progress = _AttemptProgress(
            request=wire.evidence,
            started_ns=started_ns,
            pool_started_ns=started_ns,
        )
        token = object()
        transport = _PinnedHttpxTransport(
            command_token=token,
            execute=lambda: self._execute_with_slot(
                command,
                wire,
                progress,
                progress_sink,
            ),
        )
        request = httpx.Request(
            "POST",
            command.policy.destination.normalized_url,
            headers=wire.httpx_headers,
            content=wire.body,
            extensions={"webhook_attempt_token": token},
        )
        try:
            with anyio.fail_after(_seconds(self._timeouts.total_ns)):
                async with httpx.AsyncClient(
                    transport=transport,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=None,
                    headers={},
                    limits=httpx.Limits(
                        max_connections=self._max_concurrency,
                        max_keepalive_connections=0,
                    ),
                ) as client:
                    response = await client.send(request, follow_redirects=False)
                    await response.aclose()
            return transport.result
        except TimeoutError:
            return self._failure_result(
                progress,
                code=AttemptErrorCode.TOTAL_TIMEOUT,
                phase=progress.phase,
                message="attempt exceeded its total physical timeout",
                retryable=True,
            )

    async def _execute_with_slot(
        self,
        command: HttpAttemptCommand,
        wire: _WireRequest,
        progress: _AttemptProgress,
        progress_sink: AttemptProgressSink | None,
    ) -> AttemptResult:
        acquired = False
        try:
            try:
                with anyio.fail_after(_seconds(self._timeouts.pool_ns)):
                    await self._limiter.acquire()
                acquired = True
            except TimeoutError:
                return self._failure_result(
                    progress,
                    code=AttemptErrorCode.POOL_TIMEOUT,
                    phase=AttemptPhase.POOL,
                    message="connection slot acquisition exceeded its physical timeout",
                    retryable=True,
                )
            progress.pool_elapsed_ns = self._clock.elapsed_since(progress.pool_started_ns)
            self._active += 1
            self._acquisitions += 1
            self._peak = max(self._peak, self._active)
            return await self._execute_connected(
                command,
                wire,
                progress,
                progress_sink,
            )
        finally:
            if acquired:
                self._active -= 1
                self._limiter.release()

    async def _execute_connected(
        self,
        command: HttpAttemptCommand,
        wire: _WireRequest,
        progress: _AttemptProgress,
        progress_sink: AttemptProgressSink | None,
    ) -> AttemptResult:
        progress.phase = AttemptPhase.CONNECT
        progress.connect_started_ns = self._clock.monotonic_now_ns()
        await _checkpoint(
            progress_sink,
            AttemptProgressCheckpoint.CONNECTION_ATTEMPT_STARTED,
        )
        try:
            connection = await self._dialer.dial(
                command.policy,
                timeouts=DialTimeouts(
                    resolve_nanoseconds=self._timeouts.effective_resolve_ns,
                    connect_nanoseconds=self._timeouts.connect_ns,
                    close_nanoseconds=self._timeouts.close_ns,
                ),
            )
        except PinnedDialError as error:
            progress.connect_elapsed_ns = self._clock.elapsed_since(progress.connect_started_ns)
            code, phase = _classify_dial_error(error)
            return self._failure_result(
                progress,
                code=code,
                phase=phase,
                message=str(error),
                retryable=error.retryable,
            )
        except ssl.SSLError:
            progress.connect_elapsed_ns = self._clock.elapsed_since(progress.connect_started_ns)
            return self._failure_result(
                progress,
                code=AttemptErrorCode.TLS_ERROR,
                phase=AttemptPhase.CONNECT,
                message="verified TLS connection failed",
                retryable=False,
            )
        except Exception:
            progress.connect_elapsed_ns = self._clock.elapsed_since(progress.connect_started_ns)
            return self._failure_result(
                progress,
                code=AttemptErrorCode.CONNECTION_ERROR,
                phase=AttemptPhase.CONNECT,
                message="pinned connection failed",
                retryable=True,
            )
        progress.connect_elapsed_ns = self._clock.elapsed_since(progress.connect_started_ns)
        progress.peer = PeerEvidence(
            authorized_address=connection.evidence.authorized_address,
            authorized_family=connection.evidence.authorized_family,
            peer_address=connection.evidence.peer_address,
            peer_family=connection.evidence.peer_family,
            tls=connection.plan.ssl_context is not None,
        )
        return await self._use_connection(
            connection,
            wire,
            progress,
            progress_sink,
        )

    async def _use_connection(
        self,
        connection: PinnedConnection,
        wire: _WireRequest,
        progress: _AttemptProgress,
        progress_sink: AttemptProgressSink | None,
    ) -> AttemptResult:
        try:
            write_failure = await self._send_request(
                connection,
                wire,
                progress,
                progress_sink,
            )
            if write_failure is not None:
                return write_failure
            await _checkpoint(
                progress_sink,
                AttemptProgressCheckpoint.AWAITING_RESPONSE,
            )
            return await self._read_response(connection, progress)
        finally:
            progress.phase = AttemptPhase.CLOSE
            with anyio.CancelScope(shield=True):
                with anyio.move_on_after(_seconds(self._timeouts.close_ns)):
                    with suppress(Exception):
                        await connection.aclose()

    async def _send_request(
        self,
        connection: PinnedConnection,
        wire: _WireRequest,
        progress: _AttemptProgress,
        progress_sink: AttemptProgressSink | None,
    ) -> AttemptResult | None:
        progress.phase = AttemptPhase.WRITE
        progress.send_started_ns = self._clock.monotonic_now_ns()
        await _checkpoint(
            progress_sink,
            AttemptProgressCheckpoint.REQUEST_SEND_STARTED,
        )
        try:
            with anyio.fail_after(_seconds(self._timeouts.write_ns)):
                progress.request_bytes_may_have_left = True
                await connection.stream.send(wire.head)
                for start in range(0, len(wire.body), DEFAULT_RESPONSE_DRAIN_BYTES):
                    await connection.stream.send(
                        wire.body[start : start + DEFAULT_RESPONSE_DRAIN_BYTES]
                    )
        except TimeoutError:
            progress.write_elapsed_ns = self._clock.elapsed_since(progress.send_started_ns)
            return self._failure_result(
                progress,
                code=AttemptErrorCode.WRITE_TIMEOUT,
                phase=AttemptPhase.WRITE,
                message="request write exceeded its physical timeout",
                retryable=True,
            )
        except Exception:
            progress.write_elapsed_ns = self._clock.elapsed_since(progress.send_started_ns)
            return self._failure_result(
                progress,
                code=AttemptErrorCode.CONNECTION_ERROR,
                phase=AttemptPhase.WRITE,
                message="connection failed while writing the request",
                retryable=True,
            )
        progress.write_elapsed_ns = self._clock.elapsed_since(progress.send_started_ns)
        return None

    async def _read_response(
        self,
        connection: PinnedConnection,
        progress: _AttemptProgress,
    ) -> AttemptResult:
        progress.phase = AttemptPhase.RESPONSE_HEADERS
        try:
            head = await _read_final_response_head(
                connection,
                timeout_ns=self._timeouts.read_ns,
                limits=self._limits,
            )
        except TimeoutError:
            return self._failure_result(
                progress,
                code=AttemptErrorCode.READ_TIMEOUT,
                phase=AttemptPhase.RESPONSE_HEADERS,
                message="response headers exceeded the physical read timeout",
                retryable=True,
            )
        except _ProtocolFailure:
            return self._failure_result(
                progress,
                code=AttemptErrorCode.PROTOCOL_ERROR,
                phase=AttemptPhase.RESPONSE_HEADERS,
                message="response head violated the bounded HTTP/1.1 contract",
                retryable=False,
            )
        except Exception:
            return self._failure_result(
                progress,
                code=AttemptErrorCode.CONNECTION_ERROR,
                phase=AttemptPhase.RESPONSE_HEADERS,
                message="connection failed before complete response headers",
                retryable=True,
            )
        progress.headers_completed_ns = self._clock.monotonic_now_ns()
        progress.phase = AttemptPhase.RESPONSE_BODY
        try:
            response = await _read_response_body(
                connection,
                head,
                timeout_ns=self._timeouts.read_ns,
                limits=self._limits,
                redactor=self._response_redactor,
            )
        except _BodyReadTimeoutError as error:
            progress.response = _response_evidence(
                head,
                body=error.body,
                redactor=self._response_redactor,
                truncated=True,
                body_bytes=error.total_body_bytes,
                capture_limit=self._limits.response_capture_bytes,
                body_complete=False,
            )
            return self._failure_result(
                progress,
                code=AttemptErrorCode.READ_TIMEOUT,
                phase=AttemptPhase.RESPONSE_BODY,
                message="response body exceeded the physical read timeout",
                retryable=True,
            )
        except _ResponseTooLarge as error:
            progress.response = error.response
            return self._failure_result(
                progress,
                code=AttemptErrorCode.RESPONSE_TOO_LARGE,
                phase=AttemptPhase.RESPONSE_BODY,
                message="response exceeded the bounded body drain limit",
                retryable=False,
            )
        except _ProtocolFailure:
            progress.response = _empty_response_from_head(head)
            return self._failure_result(
                progress,
                code=AttemptErrorCode.PROTOCOL_ERROR,
                phase=AttemptPhase.RESPONSE_BODY,
                message="response body framing violated HTTP/1.1",
                retryable=False,
            )
        except Exception:
            progress.response = _empty_response_from_head(head)
            return self._failure_result(
                progress,
                code=AttemptErrorCode.CONNECTION_ERROR,
                phase=AttemptPhase.RESPONSE_BODY,
                message="connection failed while reading the response body",
                retryable=True,
            )
        progress.response = response
        return self._result(progress, error=None)

    def _failure_result(
        self,
        progress: _AttemptProgress,
        *,
        code: AttemptErrorCode,
        phase: AttemptPhase,
        message: str,
        retryable: bool,
    ) -> AttemptResult:
        return self._result(
            progress,
            error=AttemptError(
                code=code,
                phase=phase,
                message_redacted=message,
                retryable=retryable,
            ),
        )

    def _result(
        self,
        progress: _AttemptProgress,
        *,
        error: AttemptError | None,
    ) -> AttemptResult:
        now = self._clock.monotonic_now_ns()
        timings = AttemptTimings(
            total_elapsed_ns=max(0, now - progress.started_ns),
            pool_elapsed_ns=progress.pool_elapsed_ns,
            connect_elapsed_ns=progress.connect_elapsed_ns,
            write_elapsed_ns=progress.write_elapsed_ns,
            response_headers_elapsed_ns=(
                None
                if progress.send_started_ns is None or progress.headers_completed_ns is None
                else progress.headers_completed_ns - progress.send_started_ns
            ),
            request_send_started_ns=progress.send_started_ns,
            response_headers_completed_ns=progress.headers_completed_ns,
        )
        if progress.response is not None:
            outcome = AttemptOutcome.RESPONSE
        elif progress.request_bytes_may_have_left:
            outcome = AttemptOutcome.UNKNOWN_OUTCOME
        else:
            outcome = AttemptOutcome.NOT_SENT
        return AttemptResult(
            outcome=outcome,
            request=progress.request,
            response=progress.response,
            peer=progress.peer,
            error=error,
            timings=timings,
            request_bytes_may_have_left=progress.request_bytes_may_have_left,
        )


async def _checkpoint(
    sink: AttemptProgressSink | None,
    checkpoint: AttemptProgressCheckpoint,
) -> None:
    if sink is None:
        return
    try:
        await sink(checkpoint)
    except anyio.get_cancelled_exc_class():
        raise
    except Exception:
        message = f"progress sink failed at {checkpoint.value}"
        raise HttpProgressError(message) from None


def _build_wire_request(
    command: HttpAttemptCommand,
    *,
    limits: HttpLimits,
) -> _WireRequest:
    if type(command) is not HttpAttemptCommand:
        message = "executor command must be an HttpAttemptCommand"
        raise TypeError(message)
    if len(command.body) > limits.max_request_bytes:
        raise HttpInputError(
            HttpInputErrorCode.REQUEST_TOO_LARGE,
            "realized request body exceeds the configured resource limit",
        )
    configured: list[tuple[HttpHeader, bytes]] = []
    if len(command.headers) > DEFAULT_MAX_HEADERS:
        raise HttpInputError(
            HttpInputErrorCode.REQUEST_TOO_LARGE,
            "request header count exceeds the configured resource limit",
        )
    seen: set[str] = set()
    for header in command.headers:
        normalized = header.name.casefold()
        forbidden = (
            normalized in _FORBIDDEN_USER_HEADERS
            if header.owner is HeaderOwner.USER
            else normalized in _CLIENT_OWNED_HEADERS
        )
        if forbidden:
            raise HttpInputError(
                HttpInputErrorCode.FORBIDDEN_HEADER,
                "request header is reserved by the HTTP transport",
            )
        if normalized in _CLIENT_OWNED_HEADERS:
            raise HttpInputError(
                HttpInputErrorCode.FORBIDDEN_HEADER,
                "request header conflicts with generated transport framing",
            )
        if normalized in seen:
            raise HttpInputError(
                HttpInputErrorCode.DUPLICATE_HEADER,
                "request header names must be unique case-insensitively",
            )
        seen.add(normalized)
        configured.append((header, _encode_header_value(header.value)))
    target = _request_target(command.policy)
    generated = (
        ("Host", command.policy.destination.authority),
        ("User-Agent", USER_AGENT),
        ("Accept-Encoding", "identity"),
        ("Content-Length", str(len(command.body))),
        ("Connection", "close"),
    )
    raw_headers: list[tuple[bytes, bytes]] = [
        (header.name.encode("ascii"), value) for header, value in configured
    ]
    raw_headers.extend((name.encode("ascii"), value.encode("ascii")) for name, value in generated)
    head = bytearray(b"POST ")
    head.extend(target)
    head.extend(b" HTTP/1.1\r\n")
    for name, value in raw_headers:
        head.extend(name)
        head.extend(b": ")
        head.extend(value)
        head.extend(b"\r\n")
    head.extend(b"\r\n")
    if len(head) > limits.max_header_bytes:
        raise HttpInputError(
            HttpInputErrorCode.REQUEST_TOO_LARGE,
            "serialized request head exceeds the configured resource limit",
        )
    evidence_headers = tuple(
        HeaderEvidence(name=header.name, owner=header.owner) for header, _value in configured
    ) + tuple(HeaderEvidence(name=name, owner=HeaderOwner.CLIENT) for name, _value in generated)
    evidence = RequestEvidence(
        body_sha256=_sha256(command.body),
        body_bytes=len(command.body),
        headers=evidence_headers,
    )
    return _WireRequest(
        target=target,
        head=bytes(head),
        body=command.body,
        evidence=evidence,
        httpx_headers=tuple(raw_headers),
    )


def _request_target(policy: DestinationPolicy) -> bytes:
    destination = policy.destination
    path = destination.path or "/"
    rendered = quote(
        path,
        safe="/:@-._~!$&'()*+,;=%",
        encoding="utf-8",
        errors="strict",
    )
    if destination.query:
        rendered = f"{rendered}?" + quote(
            destination.query,
            safe="/?:@-._~!$&'()*+,;=%",
            encoding="utf-8",
            errors="strict",
        )
    try:
        encoded = rendered.encode("ascii")
    except UnicodeError as error:
        raise HttpInputError(
            HttpInputErrorCode.REQUEST_TARGET_INVALID,
            "request target could not be represented safely",
        ) from error
    if not encoded or len(encoded) > 4_096 or b"\r" in encoded or b"\n" in encoded:
        raise HttpInputError(
            HttpInputErrorCode.REQUEST_TARGET_INVALID,
            "request target is outside the bounded HTTP origin-form contract",
        )
    return encoded


async def _read_final_response_head(
    connection: PinnedConnection,
    *,
    timeout_ns: int,
    limits: HttpLimits,
) -> _ParsedHead:
    buffer = bytearray()
    total_header_bytes = 0
    while True:
        delimiter = buffer.find(b"\r\n\r\n")
        while delimiter < 0:
            if len(buffer) >= limits.max_header_bytes:
                raise _ProtocolFailure("response headers exceeded their byte limit")
            chunk = await _receive(
                connection,
                min(MAX_RECEIVE_BYTES, limits.max_header_bytes - len(buffer)),
                timeout_ns=timeout_ns,
            )
            if not chunk:
                raise _ProtocolFailure("response ended before complete headers")
            buffer.extend(chunk)
            delimiter = buffer.find(b"\r\n\r\n")
        head_end = delimiter + 4
        total_header_bytes += head_end
        if total_header_bytes > limits.max_header_bytes:
            raise _ProtocolFailure("response headers exceeded their cumulative byte limit")
        head = _parse_response_head(bytes(buffer[:delimiter]), limits=limits)
        body_prefix = bytes(buffer[head_end:])
        if 100 <= head[0] < 200:
            if head[0] == 101:
                raise _ProtocolFailure("protocol switching is unsupported")
            informational_headers = _header_map(head[1])
            if (
                "content-length" in informational_headers
                or "transfer-encoding" in informational_headers
            ):
                raise _ProtocolFailure("informational response contains forbidden body framing")
            if body_prefix:
                buffer = bytearray(body_prefix)
            else:
                buffer.clear()
            continue
        return _ParsedHead(status=head[0], headers=head[1], body_prefix=body_prefix)


def _parse_response_head(
    block: bytes,
    *,
    limits: HttpLimits,
) -> tuple[int, tuple[tuple[str, str], ...]]:
    lines = block.split(b"\r\n")
    if not lines or _STATUS_LINE.fullmatch(lines[0]) is None:
        raise _ProtocolFailure("malformed HTTP/1.1 status line")
    status_match = _STATUS_LINE.fullmatch(lines[0])
    if status_match is None:
        raise _ProtocolFailure("malformed HTTP/1.1 status line")
    if len(lines) - 1 > limits.max_headers:
        raise _ProtocolFailure("response header count exceeded its limit")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise _ProtocolFailure("malformed or folded response header")
        raw_name, raw_value = line.split(b":", 1)
        if len(raw_name) > MAX_HTTP_HEADER_NAME_BYTES:
            raise _ProtocolFailure("response header name exceeded its limit")
        try:
            name = raw_name.decode("ascii")
            value = raw_value.strip(b" \t").decode("latin-1")
        except UnicodeError as error:
            raise _ProtocolFailure("response header encoding is invalid") from error
        if _HEADER_NAME.fullmatch(name) is None:
            raise _ProtocolFailure("response header name is not an HTTP token")
        if len(raw_value) > MAX_HEADER_VALUE_BYTES or _has_invalid_field_value(raw_value):
            raise _ProtocolFailure("response header value is invalid")
        headers.append((name, value))
    _validate_response_framing(tuple(headers))
    _response_media_type(tuple(headers))
    return int(status_match.group(1)), tuple(headers)


async def _read_response_body(
    connection: PinnedConnection,
    head: _ParsedHead,
    *,
    timeout_ns: int,
    limits: HttpLimits,
    redactor: ResponseRedactor,
) -> ResponseEvidence:
    header_map = _header_map(head.headers)
    if head.status in _NO_BODY_STATUSES or 100 <= head.status < 200:
        if head.body_prefix:
            raise _ProtocolFailure("body bytes followed a bodyless response")
        declared_length = header_map.get("content-length")
        if "transfer-encoding" in header_map:
            raise _ProtocolFailure("bodyless response declares transfer encoding")
        if declared_length is not None and declared_length != "0":
            raise _ProtocolFailure("bodyless response declares a nonzero body")
        return _response_evidence(head, body=b"", redactor=redactor, truncated=False)
    transfer_encoding = header_map.get("transfer-encoding")
    content_length = header_map.get("content-length")
    if transfer_encoding is not None:
        body, truncated = await _read_chunked(
            connection,
            initial=head.body_prefix,
            timeout_ns=timeout_ns,
            limits=limits,
        )
    elif content_length is not None:
        expected = _parse_content_length(content_length)
        if expected > limits.response_drain_bytes:
            observed = head.body_prefix[: limits.response_drain_bytes]
            response = _response_evidence(
                head,
                body=observed,
                redactor=redactor,
                truncated=True,
                body_bytes=expected,
                capture_limit=limits.response_capture_bytes,
                body_complete=False,
            )
            raise _ResponseTooLarge(response)
        body = await _read_content_length(
            connection,
            initial=head.body_prefix,
            expected=expected,
            timeout_ns=timeout_ns,
        )
        truncated = False
    else:
        body, truncated = await _read_until_close(
            connection,
            initial=head.body_prefix,
            timeout_ns=timeout_ns,
            limit=limits.response_drain_bytes,
        )
    response = _response_evidence(
        head,
        body=body,
        redactor=redactor,
        truncated=truncated or len(body) > limits.response_capture_bytes,
        capture_limit=limits.response_capture_bytes,
        body_complete=not truncated,
    )
    if truncated:
        raise _ResponseTooLarge(response)
    return response


async def _read_content_length(
    connection: PinnedConnection,
    *,
    initial: bytes,
    expected: int,
    timeout_ns: int,
) -> bytes:
    if len(initial) > expected:
        raise _ProtocolFailure("bytes followed the declared response content length")
    body = bytearray(initial)
    while len(body) < expected:
        try:
            chunk = await _receive(
                connection,
                min(MAX_RECEIVE_BYTES, expected - len(body)),
                timeout_ns=timeout_ns,
            )
        except TimeoutError as error:
            raise _BodyReadTimeoutError(
                bytes(body),
                total_body_bytes=expected,
            ) from error
        if not chunk:
            raise _ProtocolFailure("response ended before its declared content length")
        body.extend(chunk)
    return bytes(body)


async def _read_until_close(
    connection: PinnedConnection,
    *,
    initial: bytes,
    timeout_ns: int,
    limit: int,
) -> tuple[bytes, bool]:
    if len(initial) > limit:
        return initial[:limit], True
    body = bytearray(initial)
    while len(body) < limit:
        try:
            chunk = await _receive(
                connection,
                min(MAX_RECEIVE_BYTES, limit - len(body)),
                timeout_ns=timeout_ns,
                allow_eof=True,
            )
        except TimeoutError as error:
            raise _BodyReadTimeoutError(bytes(body)) from error
        if not chunk:
            return bytes(body), False
        body.extend(chunk)
    return bytes(body), True


async def _read_chunked(
    connection: PinnedConnection,
    *,
    initial: bytes,
    timeout_ns: int,
    limits: HttpLimits,
) -> tuple[bytes, bool]:
    buffer = bytearray(initial)
    body = bytearray()
    trailer_bytes = 0
    trailer_count = 0
    while True:
        line = await _read_line(
            connection,
            buffer,
            timeout_ns=timeout_ns,
            maximum=MAX_HEADER_VALUE_BYTES,
        )
        raw_size = line.split(b";", 1)[0]
        extension = line[len(raw_size) :]
        if (
            not raw_size
            or len(raw_size) > _MAX_CHUNK_SIZE_DIGITS
            or _CHUNK_SIZE.fullmatch(raw_size) is None
            or _has_invalid_field_value(extension)
        ):
            raise _ProtocolFailure("chunk size is malformed")
        size = int(raw_size, 16)
        if size > limits.response_drain_bytes - len(body):
            return bytes(body), True
        if size:
            try:
                await _fill_buffer(
                    connection,
                    buffer,
                    size + 2,
                    timeout_ns=timeout_ns,
                )
            except TimeoutError as error:
                raise _BodyReadTimeoutError(bytes(body)) from error
            if bytes(buffer[size : size + 2]) != b"\r\n":
                raise _ProtocolFailure("chunk data lacks its CRLF terminator")
            body.extend(buffer[:size])
            del buffer[: size + 2]
            continue
        while True:
            trailer = await _read_line(
                connection,
                buffer,
                timeout_ns=timeout_ns,
                maximum=MAX_HEADER_VALUE_BYTES,
            )
            trailer_bytes += len(trailer) + 2
            if trailer_bytes > limits.max_header_bytes:
                raise _ProtocolFailure("response trailers exceeded their byte limit")
            if not trailer:
                if buffer:
                    raise _ProtocolFailure("bytes followed the terminal response chunk")
                return bytes(body), False
            trailer_count += 1
            if trailer_count > limits.max_headers:
                raise _ProtocolFailure("response trailer count exceeded its limit")
            if trailer[:1] in {b" ", b"\t"} or b":" not in trailer:
                raise _ProtocolFailure("response trailer is malformed or folded")
            name, value = trailer.split(b":", 1)
            try:
                decoded_name = name.decode("ascii")
            except UnicodeError as error:
                raise _ProtocolFailure("response trailer name is invalid") from error
            if (
                len(name) > MAX_HTTP_HEADER_NAME_BYTES
                or _HEADER_NAME.fullmatch(decoded_name) is None
            ):
                raise _ProtocolFailure("response trailer name is not an HTTP token")
            if decoded_name.casefold() in {
                "content-length",
                "transfer-encoding",
            } or _has_invalid_field_value(value):
                raise _ProtocolFailure("response trailer contains forbidden framing")


async def _read_line(
    connection: PinnedConnection,
    buffer: bytearray,
    *,
    timeout_ns: int,
    maximum: int,
) -> bytes:
    while True:
        delimiter = buffer.find(b"\r\n")
        if delimiter >= 0:
            if delimiter > maximum:
                raise _ProtocolFailure("HTTP/1.1 line exceeded its bound")
            line = bytes(buffer[:delimiter])
            del buffer[: delimiter + 2]
            return line
        if len(buffer) >= maximum:
            raise _ProtocolFailure("HTTP/1.1 line exceeded its bound")
        chunk = await _receive(
            connection,
            min(MAX_RECEIVE_BYTES, maximum - len(buffer)),
            timeout_ns=timeout_ns,
        )
        if not chunk:
            raise _ProtocolFailure("response ended within an HTTP/1.1 line")
        buffer.extend(chunk)


async def _fill_buffer(
    connection: PinnedConnection,
    buffer: bytearray,
    required: int,
    *,
    timeout_ns: int,
) -> None:
    while len(buffer) < required:
        chunk = await _receive(
            connection,
            min(MAX_RECEIVE_BYTES, required - len(buffer)),
            timeout_ns=timeout_ns,
        )
        if not chunk:
            raise _ProtocolFailure("response ended within chunk data")
        buffer.extend(chunk)


async def _receive(
    connection: PinnedConnection,
    maximum: int,
    *,
    timeout_ns: int,
    allow_eof: bool = False,
) -> bytes:
    try:
        with anyio.fail_after(_seconds(timeout_ns)):
            return await connection.stream.receive(maximum)
    except anyio.EndOfStream:
        if allow_eof:
            return b""
        raise _ProtocolFailure("response stream ended unexpectedly") from None


def _validate_response_framing(headers: tuple[tuple[str, str], ...]) -> None:
    lengths = [value for name, value in headers if name.casefold() == "content-length"]
    encodings = [value for name, value in headers if name.casefold() == "transfer-encoding"]
    if len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings):
        raise _ProtocolFailure("response contains conflicting framing headers")
    if lengths:
        _parse_content_length(lengths[0])
    if encodings and encodings[0].casefold() != "chunked":
        raise _ProtocolFailure("unsupported response transfer encoding")


def _header_map(headers: tuple[tuple[str, str], ...]) -> dict[str, str]:
    return {name.casefold(): value for name, value in headers}


def _response_evidence(
    head: _ParsedHead,
    *,
    body: bytes,
    redactor: ResponseRedactor,
    truncated: bool,
    body_bytes: int | None = None,
    capture_limit: int = DEFAULT_RESPONSE_CAPTURE_BYTES,
    body_complete: bool = True,
) -> ResponseEvidence:
    captured_raw = body[:capture_limit]
    redacted = redactor(captured_raw)
    if type(redacted) is not bytes:
        message = "response redactor must return bytes"
        raise TypeError(message)
    captured = redacted[:capture_limit]
    total = len(body) if body_bytes is None else body_bytes
    observed_digest = _sha256(body)
    return ResponseEvidence(
        status=head.status,
        headers=tuple(name for name, _value in head.headers),
        body_sha256=observed_digest if body_complete else None,
        observed_body_sha256=observed_digest,
        body_bytes=total,
        observed_body_bytes=len(body),
        captured_body=captured,
        truncated=truncated,
        body_complete=body_complete,
        media_type=_response_media_type(head.headers),
    )


def _empty_response_from_head(head: _ParsedHead) -> ResponseEvidence:
    return ResponseEvidence(
        status=head.status,
        headers=tuple(name for name, _value in head.headers),
        body_sha256=None,
        observed_body_sha256=_sha256(b""),
        body_bytes=0,
        observed_body_bytes=0,
        captured_body=b"",
        truncated=True,
        body_complete=False,
        media_type=_response_media_type(head.headers),
    )


def _response_media_type(headers: tuple[tuple[str, str], ...]) -> str | None:
    values = tuple(value for name, value in headers if name.casefold() == "content-type")
    if not values:
        return None
    if len(values) != 1:
        raise _ProtocolFailure("response contains duplicate content-type headers")
    media_type = values[0].partition(";")[0].strip()
    if _MEDIA_TYPE.fullmatch(media_type) is None:
        raise _ProtocolFailure("response content type is malformed")
    return media_type.casefold()


def _classify_dial_error(
    error: PinnedDialError,
) -> tuple[AttemptErrorCode, AttemptPhase]:
    if error.code is DialErrorCode.CONNECT_TIMEOUT:
        return AttemptErrorCode.CONNECT_TIMEOUT, AttemptPhase.CONNECT
    if error.code is DialErrorCode.TLS_FAILED:
        return AttemptErrorCode.TLS_ERROR, AttemptPhase.CONNECT
    if error.phase is DialPhase.RESOLUTION:
        return AttemptErrorCode.CONNECTION_ERROR, AttemptPhase.RESOLUTION
    if error.phase is DialPhase.TLS_CONFIGURATION:
        return AttemptErrorCode.TLS_ERROR, AttemptPhase.CONNECT
    return AttemptErrorCode.CONNECTION_ERROR, AttemptPhase.CONNECT


def _parse_content_length(value: str) -> int:
    if len(value) > _MAX_CONTENT_LENGTH_DIGITS or _CONTENT_LENGTH.fullmatch(value) is None:
        raise _ProtocolFailure("response content length is malformed")
    parsed = int(value)
    if parsed > _MAX_SIGNED_INT64:
        raise _ProtocolFailure("response content length exceeds signed-int64 range")
    return parsed


def _validate_header_name(value: object) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_HTTP_HEADER_NAME_BYTES
        or _HEADER_NAME.fullmatch(value) is None
    ):
        raise HttpInputError(
            HttpInputErrorCode.INVALID_HEADER,
            "header name must be a bounded HTTP token",
        )


def _encode_header_value(value: object) -> bytes:
    if type(value) is not str:
        raise HttpInputError(
            HttpInputErrorCode.INVALID_HEADER,
            "header value must be text",
        )
    try:
        encoded = value.encode("latin-1")
    except UnicodeError as error:
        raise HttpInputError(
            HttpInputErrorCode.INVALID_HEADER,
            "header value is outside the HTTP/1.1 byte range",
        ) from error
    if (
        len(encoded) > MAX_HEADER_VALUE_BYTES
        or value != value.strip(" \t")
        or _has_invalid_field_value(encoded)
    ):
        raise HttpInputError(
            HttpInputErrorCode.INVALID_HEADER,
            "header value is unbounded or contains forbidden controls",
        )
    return encoded


def _has_invalid_field_value(value: bytes) -> bool:
    return any(byte == 127 or (byte < 32 and byte != 9) for byte in value)


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _identity_redactor(value: bytes) -> bytes:
    return value


def _positive_timeout(value: object, *, field_name: str) -> None:
    _bounded_integer(
        value,
        field_name=f"{field_name} timeout",
        minimum=1,
        maximum=MAX_TIMEOUT_NS,
    )


def _bounded_integer(
    value: object,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        message = f"{field_name} must be an integer from {minimum} through {maximum}"
        raise ValueError(message)


def _seconds(nanoseconds: int) -> float:
    seconds = nanoseconds / _NANOSECONDS_PER_SECOND
    if not math.isfinite(seconds) or seconds <= 0:
        message = "physical timeout became nonpositive or nonfinite"
        raise ValueError(message)
    return seconds
