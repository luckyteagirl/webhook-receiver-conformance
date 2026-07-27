"""Public-target preflight contract tests for TASK-0307."""
# ruff: noqa: D101, D102, INP001, PLR2004

from __future__ import annotations

import ssl
from dataclasses import dataclass, field

import anyio
import pytest
from anyio.lowlevel import checkpoint

from webhook_receiver_conformance.config.models import ReceiverConfig
from webhook_receiver_conformance.network.dialer import (
    DialTimeouts,
    PinnedDestinationDialer,
)
from webhook_receiver_conformance.network.preflight import (
    PreflightErrorCode,
    PublicTargetPreflightError,
    preflight_public_target,
)
from webhook_receiver_conformance.network.transport import (
    ConnectedByteStream,
    ConnectionPlan,
    Connector,
    PeerAddress,
    Resolver,
    SocketFamily,
    TLSContextProvider,
)

SECOND = 1_000_000_000
NONCE = b"A" * 43


def _receiver(*, allowed_hosts: list[str] | None = None) -> ReceiverConfig:
    return ReceiverConfig.model_validate(
        {
            "url": "https://events.example:443/hooks",
            "target_profile": "public-authorized",
            "allowed_hosts": ["events.example"] if allowed_hosts is None else allowed_hosts,
            "allowed_ports": [443],
            "public_challenge_path": "/challenge",
            "timeouts": {
                "connect": "1s",
                "write": "1s",
                "read": "1s",
                "pool": "1s",
                "total": "5s",
            },
        }
    )


@dataclass
class RecordingResolver(Resolver):
    answers: tuple[str, ...] = ("93.184.216.34",)
    calls: list[tuple[str, int]] = field(default_factory=list[tuple[str, int]])

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        self.calls.append((host, port))
        return self.answers


@dataclass
class ChallengeStream(ConnectedByteStream):
    response_body: bytes = NONCE
    status: bytes = b"200 OK"
    block_write: bool = False
    block_read: bool = False
    keep_open: bool = False
    trailing_bytes: bytes = b""
    response_headers: bytes = b""
    sent: list[bytes] = field(default_factory=list[bytes])
    delivered: bool = False
    closed: bool = False

    @property
    def peer_address(self) -> PeerAddress:
        return PeerAddress("93.184.216.34", 443, SocketFamily.IPV4)

    async def send(self, item: bytes) -> None:
        if self.block_write:
            await anyio.sleep_forever()
        self.sent.append(item)

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        del max_bytes
        if self.block_read:
            await anyio.sleep_forever()
        if self.delivered:
            if self.keep_open:
                await anyio.sleep_forever()
            return b""
        self.delivered = True
        body = self.response_body
        return (
            b"HTTP/1.1 "
            + self.status
            + b"\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n"
            + self.response_headers
            + b"\r\n"
            + body
            + self.trailing_bytes
        )

    async def send_eof(self) -> None:
        return

    async def aclose(self) -> None:
        self.closed = True


@dataclass
class RecordingConnector(Connector):
    stream: ChallengeStream
    plans: list[ConnectionPlan] = field(default_factory=list[ConnectionPlan])

    async def connect(self, plan: ConnectionPlan) -> ChallengeStream:
        self.plans.append(plan)
        return self.stream


class FakeTLSProvider(TLSContextProvider):
    def create(self, server_hostname: str) -> ssl.SSLContext:
        assert server_hostname == "events.example"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context


def _dialer(
    resolver: RecordingResolver,
    connector: RecordingConnector,
) -> PinnedDestinationDialer:
    return PinnedDestinationDialer(
        resolver=resolver,
        connector=connector,
        tls_context_provider=FakeTLSProvider(),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("authorization", [None, "", "wrong.example:443"])
async def test_missing_or_mismatched_gate_has_zero_network_contact(
    authorization: str | None,
) -> None:
    resolver = RecordingResolver()
    connector = RecordingConnector(ChallengeStream())

    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(),
            runtime_public_authorization=authorization,
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            nonce_source=lambda: NONCE,
        )

    assert captured.value.code is PreflightErrorCode.POLICY_REJECTED
    assert not captured.value.network_contacted
    assert resolver.calls == []
    assert connector.plans == []


@pytest.mark.anyio
async def test_missing_config_allowlist_gate_has_zero_network_contact() -> None:
    resolver = RecordingResolver()
    connector = RecordingConnector(ChallengeStream())

    with pytest.raises(PublicTargetPreflightError):
        await preflight_public_target(
            _receiver(allowed_hosts=[]),
            runtime_public_authorization="events.example:443",
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            nonce_source=lambda: NONCE,
        )

    assert resolver.calls == []
    assert connector.plans == []


@pytest.mark.anyio
async def test_success_uses_pinned_direct_challenge_and_redacted_exact_evidence() -> None:
    resolver = RecordingResolver()
    stream = ChallengeStream()
    connector = RecordingConnector(stream)

    evidence = await preflight_public_target(
        _receiver(),
        runtime_public_authorization="events.example:443",
        dialer=_dialer(resolver, connector),
        dial_timeouts=DialTimeouts(SECOND, SECOND),
        nonce_source=lambda: NONCE,
    )

    assert evidence is not None
    assert evidence.authority == "events.example:443"
    assert evidence.challenge_path == "/challenge"
    assert evidence.status_code == 200
    assert evidence.peer.authorized_address == evidence.peer.peer_address == "93.184.216.34"
    assert evidence.redirects_followed == 0
    assert not evidence.proxy_environment_used
    assert not evidence.fixture_bytes_sent
    assert NONCE not in repr(evidence).encode()
    assert connector.plans[0].follow_redirects is False
    assert connector.plans[0].trust_env is False
    assert stream.sent == [
        b"GET /challenge HTTP/1.1\r\n"
        b"Host: events.example:443\r\n"
        b"User-Agent: webhook-receiver-conformance/0.1\r\n"
        b"Accept: text/plain\r\n"
        b"X-Webhook-Conformance-Challenge: " + NONCE + b"\r\nConnection: close\r\n\r\n"
    ]


@pytest.mark.anyio
@pytest.mark.parametrize("body", [b"", b"B" * 43])
async def test_missing_or_stale_challenge_fails_closed(body: bytes) -> None:
    resolver = RecordingResolver()
    stream = ChallengeStream(response_body=body)
    connector = RecordingConnector(stream)

    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(),
            runtime_public_authorization="events.example:443",
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            nonce_source=lambda: NONCE,
        )

    assert captured.value.code in {
        PreflightErrorCode.CHALLENGE_MISSING,
        PreflightErrorCode.CHALLENGE_MISMATCH,
    }
    assert not captured.value.fixture_bytes_sent


@pytest.mark.anyio
async def test_redirect_is_not_followed() -> None:
    resolver = RecordingResolver()
    stream = ChallengeStream(status=b"302 Found")
    connector = RecordingConnector(stream)

    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(),
            runtime_public_authorization="events.example:443",
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            nonce_source=lambda: NONCE,
        )

    assert captured.value.code is PreflightErrorCode.REDIRECT_REJECTED
    assert len(stream.sent) == 1


@pytest.mark.anyio
async def test_mixed_public_and_private_dns_fails_before_connection() -> None:
    resolver = RecordingResolver(("93.184.216.34", "10.0.0.1"))
    connector = RecordingConnector(ChallengeStream())

    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(),
            runtime_public_authorization="events.example:443",
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            nonce_source=lambda: NONCE,
        )

    assert captured.value.code is PreflightErrorCode.POLICY_REJECTED
    assert connector.plans == []


@pytest.mark.anyio
async def test_blocked_write_is_classified_and_connection_is_closed() -> None:
    resolver = RecordingResolver()
    stream = ChallengeStream(block_write=True)
    connector = RecordingConnector(stream)

    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(),
            runtime_public_authorization="events.example:443",
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            challenge_timeout_ns=1_000_000,
            nonce_source=lambda: NONCE,
        )

    assert captured.value.code is PreflightErrorCode.WRITE_TIMEOUT
    assert captured.value.phase.value == "write"
    assert stream.closed


@pytest.mark.anyio
async def test_blocked_read_is_classified_and_connection_is_closed() -> None:
    resolver = RecordingResolver()
    stream = ChallengeStream(block_read=True)
    connector = RecordingConnector(stream)

    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(),
            runtime_public_authorization="events.example:443",
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            challenge_timeout_ns=1_000_000,
            nonce_source=lambda: NONCE,
        )

    assert captured.value.code is PreflightErrorCode.READ_TIMEOUT
    assert captured.value.phase.value == "read"
    assert stream.closed


@pytest.mark.anyio
async def test_complete_content_length_returns_without_waiting_for_eof() -> None:
    resolver = RecordingResolver()
    stream = ChallengeStream(keep_open=True)
    connector = RecordingConnector(stream)

    evidence = await preflight_public_target(
        _receiver(),
        runtime_public_authorization="events.example:443",
        dialer=_dialer(resolver, connector),
        dial_timeouts=DialTimeouts(SECOND, SECOND),
        challenge_timeout_ns=10_000_000,
        nonce_source=lambda: NONCE,
    )

    assert evidence is not None
    assert stream.closed


@pytest.mark.anyio
@pytest.mark.parametrize(
    "stream",
    [
        ChallengeStream(trailing_bytes=b"x"),
        ChallengeStream(response_body=b"x" * 5000),
    ],
)
async def test_overrun_and_oversized_framing_fail_closed(stream: ChallengeStream) -> None:
    resolver = RecordingResolver()
    connector = RecordingConnector(stream)

    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(),
            runtime_public_authorization="events.example:443",
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            nonce_source=lambda: NONCE,
        )

    assert captured.value.code in {
        PreflightErrorCode.RESPONSE_MALFORMED,
        PreflightErrorCode.RESPONSE_TOO_LARGE,
    }
    assert stream.closed


@pytest.mark.anyio
@pytest.mark.parametrize(
    "response_headers",
    [b"Bad Name: value\r\n", b"X-Test: value\x00\r\n"],
)
async def test_invalid_header_name_or_value_is_malformed(response_headers: bytes) -> None:
    resolver = RecordingResolver()
    stream = ChallengeStream(response_headers=response_headers)
    connector = RecordingConnector(stream)

    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(),
            runtime_public_authorization="events.example:443",
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            nonce_source=lambda: NONCE,
        )

    assert captured.value.code is PreflightErrorCode.RESPONSE_MALFORMED
    assert stream.closed


@pytest.mark.anyio
async def test_cancellation_still_closes_pinned_connection() -> None:
    resolver = RecordingResolver()
    stream = ChallengeStream(block_read=True)
    connector = RecordingConnector(stream)

    async def run_preflight() -> None:
        await preflight_public_target(
            _receiver(),
            runtime_public_authorization="events.example:443",
            dialer=_dialer(resolver, connector),
            dial_timeouts=DialTimeouts(SECOND, SECOND),
            nonce_source=lambda: NONCE,
        )

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(run_preflight)
        while not stream.sent:
            await checkpoint()
        task_group.cancel_scope.cancel()

    assert stream.closed
