"""Wire, timeout, privacy, and resource contracts for TASK-0308."""
# ruff: noqa: D101, D102, INP001, PLR2004

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import anyio
import pytest
from anyio.lowlevel import checkpoint as yield_checkpoint

from webhook_receiver_conformance.config.models import ReceiverConfig
from webhook_receiver_conformance.http.evidence import (
    AttemptErrorCode,
    AttemptOutcome,
    AttemptProgressCheckpoint,
    AttemptResult,
    HeaderOwner,
)
from webhook_receiver_conformance.http.executor import (
    DEFAULT_MAX_REQUEST_BYTES,
    HttpAttemptCommand,
    HttpAttemptExecutor,
    HttpHeader,
    HttpInputError,
    HttpInputErrorCode,
    HttpLimits,
    HttpProgressError,
    HttpTimeouts,
)
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.policy import (
    DestinationPolicy,
    parse_destination_policy,
)
from webhook_receiver_conformance.network.transport import (
    ConnectedByteStream,
    ConnectionPlan,
    Connector,
    PeerAddress,
    Resolver,
)
from webhook_receiver_conformance.scheduler.clocks import (
    ClockMode,
    ClockPolicy,
    RuntimeClock,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

SECOND = 1_000_000_000
FAST_TIMEOUTS = HttpTimeouts(
    connect_ns=SECOND,
    write_ns=SECOND,
    read_ns=SECOND,
    pool_ns=SECOND,
    total_ns=5 * SECOND,
)


def _policy(url: str = "http://127.0.0.1:8443/hook?source=test") -> DestinationPolicy:
    config = ReceiverConfig.model_validate(
        {
            "url": url,
            "target_profile": "loopback",
            "allowed_hosts": [],
            "allowed_ports": [8443],
            "timeouts": {
                "connect": "1s",
                "write": "1s",
                "read": "1s",
                "pool": "1s",
                "total": "5s",
            },
        }
    )
    return parse_destination_policy(config)


@dataclass(slots=True)
class UnusedResolver(Resolver):
    async def resolve(self, host: str, port: int) -> Sequence[str]:
        del host, port
        message = "literal target must not resolve"
        raise AssertionError(message)


@dataclass(slots=True)
class ScriptedStream(ConnectedByteStream):
    peer: PeerAddress
    chunks: list[bytes]
    receive_delay: float = 0.0
    receive_delays: list[float] = field(default_factory=list[float])
    send_delay: float = 0.0
    fail_send: bool = False
    sent: list[bytes] = field(default_factory=list[bytes])
    receive_calls: int = 0
    closed: bool = False
    trace: list[str] | None = None

    @property
    def peer_address(self) -> PeerAddress:
        return self.peer

    async def send(self, item: bytes) -> None:
        if self.trace is not None:
            self.trace.append("send")
        if self.send_delay:
            await anyio.sleep(self.send_delay)
        if self.fail_send:
            message = "private send detail"
            raise OSError(message)
        self.sent.append(item)

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        if self.trace is not None:
            self.trace.append("receive")
        self.receive_calls += 1
        delay = self.receive_delays.pop(0) if self.receive_delays else self.receive_delay
        if delay:
            await anyio.sleep(delay)
        if not self.chunks:
            raise anyio.EndOfStream
        chunk = self.chunks.pop(0)
        if len(chunk) <= max_bytes:
            return chunk
        self.chunks.insert(0, chunk[max_bytes:])
        return chunk[:max_bytes]

    async def send_eof(self) -> None:
        return None

    async def aclose(self) -> None:
        if self.trace is not None:
            self.trace.append("close")
        self.closed = True


@dataclass(slots=True)
class ScriptedConnector(Connector):
    response: bytes
    response_chunks: list[bytes] | None = None
    receive_delay: float = 0.0
    receive_delays: list[float] = field(default_factory=list[float])
    send_delay: float = 0.0
    connect_delay: float = 0.0
    fail_connect: bool = False
    fail_send: bool = False
    calls: int = 0
    streams: list[ScriptedStream] = field(default_factory=list[ScriptedStream])
    connected: anyio.Event = field(default_factory=anyio.Event)
    trace: list[str] | None = None

    async def connect(self, plan: ConnectionPlan) -> ScriptedStream:
        if self.trace is not None:
            self.trace.append("dial")
        self.calls += 1
        if self.connect_delay:
            await anyio.sleep(self.connect_delay)
        if self.fail_connect:
            message = "private refusal detail"
            raise OSError(message)
        stream = ScriptedStream(
            peer=PeerAddress(plan.pinned_address, plan.port, plan.family),
            chunks=(
                [self.response] if self.response_chunks is None else list(self.response_chunks)
            ),
            receive_delay=self.receive_delay,
            receive_delays=list(self.receive_delays),
            send_delay=self.send_delay,
            fail_send=self.fail_send,
            trace=self.trace,
        )
        self.streams.append(stream)
        self.connected.set()
        return stream


def _executor(
    connector: ScriptedConnector,
    *,
    timeouts: HttpTimeouts = FAST_TIMEOUTS,
    limits: HttpLimits | None = None,
    clock: RuntimeClock | None = None,
    max_concurrency: int = 10,
) -> HttpAttemptExecutor:
    return HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=UnusedResolver(),
            connector=connector,
        ),
        timeouts=timeouts,
        limits=limits,
        clock=clock,
        max_concurrency=max_concurrency,
    )


@pytest.mark.anyio
async def test_exact_post_bytes_and_value_free_header_ownership() -> None:
    response = (
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/nope\r\nContent-Length: 2\r\n\r\nok"
    )
    connector = ScriptedConnector(response)
    executor = _executor(connector)
    body = b'{"canary":"request-must-not-appear-in-repr"}'
    command = HttpAttemptCommand(
        policy=_policy(),
        body=body,
        headers=(
            HttpHeader("X-Display-Case", "user-secret", HeaderOwner.USER),
            HttpHeader("X-Signature", "signature-secret", HeaderOwner.SIGNER),
        ),
    )

    result = await executor.execute(command)

    assert connector.calls == 1
    assert result.outcome is AttemptOutcome.RESPONSE
    assert result.response is not None
    assert result.response.status == 302
    assert result.response.protocol == "HTTP/1.1"
    assert result.response.captured_body == b"ok"
    assert result.peer is not None
    assert result.peer.authorized_address == result.peer.peer_address == "127.0.0.1"
    sent = b"".join(connector.streams[0].sent)
    head, delivered_body = sent.split(b"\r\n\r\n", 1)
    assert delivered_body == body
    assert head.startswith(b"POST /hook?source=test HTTP/1.1\r\n")
    assert b"X-Display-Case: user-secret\r\n" in head
    assert b"X-Signature: signature-secret\r\n" in head
    assert b"Accept-Encoding: identity\r\n" in head
    assert b"Content-Length: 44\r\n" in head
    assert b"Content-Encoding:" not in head
    assert tuple(item.name for item in result.request.headers[:2]) == (
        "X-Display-Case",
        "X-Signature",
    )
    assert tuple(item.owner for item in result.request.headers[:2]) == (
        HeaderOwner.USER,
        HeaderOwner.SIGNER,
    )
    assert "user-secret" not in repr(result)
    assert "signature-secret" not in repr(result)
    assert body.decode() not in repr(command)
    assert connector.streams[0].closed


@pytest.mark.anyio
async def test_progress_checkpoints_complete_before_each_transport_effect() -> None:
    trace: list[str] = []
    connector = ScriptedConnector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        trace=trace,
    )

    async def sink(checkpoint: AttemptProgressCheckpoint) -> None:
        trace.append(f"{checkpoint.value}:begin")
        await yield_checkpoint()
        trace.append(f"{checkpoint.value}:complete")

    result = await _executor(connector).execute(
        HttpAttemptCommand(policy=_policy(), body=b"nonsecret"),
        progress_sink=sink,
    )
    assert result.outcome is AttemptOutcome.RESPONSE
    assert trace.index("connection_attempt_started:complete") < trace.index("dial")
    assert trace.index("request_send_started:complete") < trace.index("send")
    assert trace.index("awaiting_response:complete") < trace.index("receive")
    assert trace[-1] == "close"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "target",
    list(AttemptProgressCheckpoint),
)
async def test_progress_failure_stops_later_io_and_closes_connection(
    target: AttemptProgressCheckpoint,
) -> None:
    canary = "sink-secret-canary"
    connector = ScriptedConnector(b"HTTP/1.1 204 No Content\r\n\r\n")

    async def sink(checkpoint: AttemptProgressCheckpoint) -> None:
        if checkpoint is target:
            raise RuntimeError(canary)

    with pytest.raises(HttpProgressError) as captured:
        await _executor(connector).execute(
            HttpAttemptCommand(policy=_policy(), body=b"body-secret"),
            progress_sink=sink,
        )
    assert canary not in str(captured.value)
    assert "body-secret" not in str(captured.value)
    assert repr(target) in {
        "<AttemptProgressCheckpoint.CONNECTION_ATTEMPT_STARTED: 'connection_attempt_started'>",
        "<AttemptProgressCheckpoint.REQUEST_SEND_STARTED: 'request_send_started'>",
        "<AttemptProgressCheckpoint.AWAITING_RESPONSE: 'awaiting_response'>",
    }
    if target is AttemptProgressCheckpoint.CONNECTION_ATTEMPT_STARTED:
        assert connector.calls == 0
        return
    stream = connector.streams[0]
    assert stream.closed
    if target is AttemptProgressCheckpoint.REQUEST_SEND_STARTED:
        assert stream.sent == []
        assert stream.receive_calls == 0
    else:
        assert stream.sent
        assert stream.receive_calls == 0


@pytest.mark.anyio
async def test_progress_cancellation_before_first_send_closes_without_io() -> None:
    connector = ScriptedConnector(b"HTTP/1.1 204 No Content\r\n\r\n")

    async def sink(checkpoint: AttemptProgressCheckpoint) -> None:
        if checkpoint is AttemptProgressCheckpoint.REQUEST_SEND_STARTED:
            raise anyio.get_cancelled_exc_class()

    with pytest.raises(anyio.get_cancelled_exc_class()):
        await _executor(connector).execute(
            HttpAttemptCommand(policy=_policy(), body=b"secret"),
            progress_sink=sink,
        )
    stream = connector.streams[0]
    assert stream.sent == []
    assert stream.receive_calls == 0
    assert stream.closed


@pytest.mark.anyio
@pytest.mark.parametrize(
    "name",
    [
        "Host",
        "content-LENGTH",
        "Transfer-Encoding",
        "Connection",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Upgrade",
    ],
)
async def test_forbidden_headers_fail_case_insensitively_before_dial(name: str) -> None:
    connector = ScriptedConnector(b"")
    executor = _executor(connector)
    command = HttpAttemptCommand(
        policy=_policy(),
        body=b"",
        headers=(HttpHeader(name, "canary", HeaderOwner.USER),),
    )

    with pytest.raises(HttpInputError) as captured:
        await executor.execute(command)

    assert captured.value.code is HttpInputErrorCode.FORBIDDEN_HEADER
    assert connector.calls == 0
    assert "canary" not in str(captured.value)


@pytest.mark.anyio
async def test_request_limit_accepts_boundary_and_rejects_one_more() -> None:
    connector = ScriptedConnector(b"HTTP/1.1 204 No Content\r\n\r\n")
    executor = _executor(connector)

    accepted = await executor.execute(
        HttpAttemptCommand(policy=_policy(), body=b"x" * DEFAULT_MAX_REQUEST_BYTES)
    )
    assert accepted.outcome is AttemptOutcome.RESPONSE

    with pytest.raises(HttpInputError) as captured:
        await executor.execute(
            HttpAttemptCommand(
                policy=_policy(),
                body=b"x" * (DEFAULT_MAX_REQUEST_BYTES + 1),
            )
        )
    assert captured.value.code is HttpInputErrorCode.REQUEST_TOO_LARGE
    assert connector.calls == 1


@pytest.mark.anyio
async def test_large_response_retains_prefix_digest_count_and_truncation() -> None:
    body = b"r" * 70_000
    connector = ScriptedConnector(b"HTTP/1.1 200 OK\r\nContent-Length: 70000\r\n\r\n" + body)

    result = await _executor(connector).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert result.response is not None
    assert result.response.body_bytes == len(body)
    assert result.response.captured_body == body[:65_536]
    assert result.response.body_sha256 == f"sha256:{hashlib.sha256(body).hexdigest()}"
    assert result.response.truncated
    assert b"r" * 100 not in repr(result).encode()


@pytest.mark.anyio
async def test_known_oversized_response_is_closed_and_classified() -> None:
    limits = HttpLimits(response_drain_bytes=1_024, response_capture_bytes=512)
    connector = ScriptedConnector(b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n" + b"x" * 600)

    result = await _executor(connector, limits=limits).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert result.outcome is AttemptOutcome.RESPONSE
    assert result.error is not None
    assert result.error.code is AttemptErrorCode.RESPONSE_TOO_LARGE
    assert result.response is not None
    assert result.response.body_bytes == 2_048
    assert len(result.response.captured_body) == 512
    assert result.response.truncated
    assert connector.streams[0].closed


@pytest.mark.anyio
async def test_chunked_response_and_informational_head_are_parsed_incrementally() -> None:
    connector = ScriptedConnector(
        b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"4\r\ntest\r\n3\r\n123\r\n0\r\nX-Trailer: yes\r\n\r\n"
    )

    result = await _executor(connector).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert result.error is None
    assert result.response is not None
    assert result.response.status == 200
    assert result.response.captured_body == b"test123"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n Folded: bad\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1, 1\r\n\r\nx",
    ],
)
async def test_smuggling_and_malformed_response_heads_are_protocol_failures(
    response: bytes,
) -> None:
    connector = ScriptedConnector(response)

    result = await _executor(connector).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert result.outcome is AttemptOutcome.UNKNOWN_OUTCOME
    assert result.error is not None
    assert result.error.code is AttemptErrorCode.PROTOCOL_ERROR
    assert result.response is None
    assert connector.streams[0].closed


@pytest.mark.anyio
@pytest.mark.parametrize(
    "response",
    [
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"1" * 8_193 + b"\r\n"),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"0\r\n" + b"X" * 257 + b": value\r\n\r\n"
        ),
        b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n",
    ],
)
async def test_chunk_lines_trailer_names_and_bodyless_framing_are_bounded(
    response: bytes,
) -> None:
    connector = ScriptedConnector(response)

    result = await _executor(connector).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert result.outcome is AttemptOutcome.RESPONSE
    assert result.error is not None
    assert result.error.code is AttemptErrorCode.PROTOCOL_ERROR
    assert result.response is not None
    assert result.response.body_sha256 is None
    assert not result.response.body_complete
    assert connector.streams[0].closed


@pytest.mark.anyio
async def test_body_framing_failure_does_not_claim_complete_empty_digest() -> None:
    connector = ScriptedConnector(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")

    result = await _executor(connector).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert result.outcome is AttemptOutcome.RESPONSE
    assert result.error is not None
    assert result.error.code is AttemptErrorCode.PROTOCOL_ERROR
    assert result.response is not None
    assert result.response.body_sha256 is None
    assert result.response.observed_body_sha256 == (f"sha256:{hashlib.sha256(b'').hexdigest()}")
    assert not result.response.body_complete


@pytest.mark.anyio
async def test_connection_refusal_is_known_not_sent_and_retryable() -> None:
    connector = ScriptedConnector(b"", fail_connect=True)

    result = await _executor(connector).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert connector.calls == 1
    assert result.outcome is AttemptOutcome.NOT_SENT
    assert not result.request_bytes_may_have_left
    assert result.error is not None
    assert result.error.code is AttemptErrorCode.CONNECTION_ERROR
    assert result.error.retryable
    assert "private refusal detail" not in result.error.message_redacted


@pytest.mark.anyio
async def test_failed_write_is_ambiguous_and_stream_is_closed() -> None:
    connector = ScriptedConnector(b"", fail_send=True)

    result = await _executor(connector).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert result.outcome is AttemptOutcome.UNKNOWN_OUTCOME
    assert result.request_bytes_may_have_left
    assert result.error is not None
    assert result.error.code is AttemptErrorCode.CONNECTION_ERROR
    assert connector.streams[0].closed


@pytest.mark.anyio
async def test_delayed_body_preserves_prompt_header_acknowledgment_fact() -> None:
    timeouts = HttpTimeouts(
        connect_ns=SECOND,
        write_ns=SECOND,
        read_ns=10_000_000,
        pool_ns=SECOND,
        total_ns=SECOND,
    )
    connector = ScriptedConnector(
        b"",
        response_chunks=[
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n",
            b"x",
        ],
        receive_delays=[0.0, 0.05],
    )
    executor = _executor(connector, timeouts=timeouts)

    result = await executor.execute(HttpAttemptCommand(policy=_policy(), body=b"request"))

    assert result.error is not None
    assert result.error.code is AttemptErrorCode.READ_TIMEOUT
    assert result.outcome is AttemptOutcome.RESPONSE
    assert result.response is not None
    assert result.response.body_sha256 is None
    assert result.response.observed_body_bytes == 0
    assert not result.response.body_complete
    assert result.timings.acknowledgment_elapsed_ns is not None
    assert connector.streams[0].closed


@pytest.mark.anyio
async def test_scaled_schedule_clock_does_not_scale_physical_http_timeout() -> None:
    clock = RuntimeClock(
        ClockPolicy(
            ClockMode.SCALED,
            scale_numerator=100,
            scale_denominator=1,
        )
    )
    timeouts = HttpTimeouts(
        connect_ns=SECOND,
        write_ns=5_000_000,
        read_ns=SECOND,
        pool_ns=SECOND,
        total_ns=SECOND,
    )
    connector = ScriptedConnector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        send_delay=0.05,
    )

    result = await _executor(
        connector,
        timeouts=timeouts,
        clock=clock,
    ).execute(HttpAttemptCommand(policy=_policy(), body=b"request"))

    assert result.error is not None
    assert result.error.code is AttemptErrorCode.WRITE_TIMEOUT
    assert result.timings.total_elapsed_ns < SECOND


@pytest.mark.anyio
async def test_connect_timeout_is_distinct_and_known_not_sent() -> None:
    timeouts = HttpTimeouts(
        connect_ns=5_000_000,
        write_ns=SECOND,
        read_ns=SECOND,
        pool_ns=SECOND,
        total_ns=SECOND,
    )
    connector = ScriptedConnector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        connect_delay=0.05,
    )

    result = await _executor(connector, timeouts=timeouts).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert result.outcome is AttemptOutcome.NOT_SENT
    assert result.error is not None
    assert result.error.code is AttemptErrorCode.CONNECT_TIMEOUT


@pytest.mark.anyio
async def test_pool_timeout_is_distinct_and_does_not_create_a_connection() -> None:
    timeouts = HttpTimeouts(
        connect_ns=SECOND,
        write_ns=SECOND,
        read_ns=SECOND,
        pool_ns=5_000_000,
        total_ns=SECOND,
    )
    connector = ScriptedConnector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        send_delay=0.05,
    )
    executor = _executor(connector, timeouts=timeouts, max_concurrency=1)
    results: list[AttemptResult] = []

    async def first() -> None:
        results.append(await executor.execute(HttpAttemptCommand(policy=_policy(), body=b"first")))

    async def second() -> None:
        await connector.connected.wait()
        results.append(await executor.execute(HttpAttemptCommand(policy=_policy(), body=b"second")))

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(first)
        task_group.start_soon(second)

    pool_failures = [
        result
        for result in results
        if result.error is not None and result.error.code is AttemptErrorCode.POOL_TIMEOUT
    ]
    assert len(pool_failures) == 1
    assert pool_failures[0].outcome is AttemptOutcome.NOT_SENT
    assert connector.calls == 1


@pytest.mark.anyio
async def test_total_timeout_bounds_slow_headers_and_closes_stream() -> None:
    timeouts = HttpTimeouts(
        connect_ns=SECOND,
        write_ns=SECOND,
        read_ns=SECOND,
        pool_ns=SECOND,
        total_ns=5_000_000,
    )
    connector = ScriptedConnector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        receive_delay=0.05,
    )

    result = await _executor(connector, timeouts=timeouts).execute(
        HttpAttemptCommand(policy=_policy(), body=b"request")
    )

    assert result.outcome is AttemptOutcome.UNKNOWN_OUTCOME
    assert result.error is not None
    assert result.error.code is AttemptErrorCode.TOTAL_TIMEOUT
    assert connector.streams[0].closed


@pytest.mark.anyio
async def test_external_cancellation_propagates_after_shielded_stream_close() -> None:
    connector = ScriptedConnector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        receive_delay=1.0,
    )
    executor = _executor(connector)
    completed = False

    async def run() -> None:
        nonlocal completed
        await executor.execute(HttpAttemptCommand(policy=_policy(), body=b"request"))
        completed = True

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(run)
        await connector.connected.wait()
        task_group.cancel_scope.cancel()

    assert not completed
    assert connector.streams[0].closed


@pytest.mark.anyio
async def test_pool_instrumentation_is_bounded_and_has_no_keepalive() -> None:
    connector = ScriptedConnector(
        b"HTTP/1.1 204 No Content\r\n\r\n",
        send_delay=0.01,
    )
    executor = _executor(connector, max_concurrency=2)

    async def execute_one() -> None:
        result = await executor.execute(HttpAttemptCommand(policy=_policy(), body=b"x"))
        assert result.outcome is AttemptOutcome.RESPONSE

    async with anyio.create_task_group() as task_group:
        for _ in range(8):
            task_group.start_soon(execute_one)

    instrumentation = executor.pool_instrumentation
    assert instrumentation.limit == 2
    assert instrumentation.active == 0
    assert instrumentation.peak == 2
    assert instrumentation.acquisitions == 8
    assert instrumentation.keepalive_connections == 0
    assert all(stream.closed for stream in connector.streams)


def test_command_and_response_repr_hide_body_and_header_canaries() -> None:
    command = HttpAttemptCommand(
        policy=_policy(),
        body=b"request-body-canary",
        headers=(
            HttpHeader(
                "Authorization",
                "authorization-canary",
                HeaderOwner.USER,
            ),
        ),
    )

    rendered = repr(command)

    assert "request-body-canary" not in rendered
    assert "authorization-canary" not in rendered
    assert "Authorization" in rendered
