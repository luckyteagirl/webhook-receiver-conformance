"""End-to-end security regressions for destination authorization and pinning."""
# ruff: noqa: INP001, S104

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from anyio.lowlevel import checkpoint

from webhook_receiver_conformance.config.models import ReceiverConfig
from webhook_receiver_conformance.network.addresses import AddressClass, classify_address
from webhook_receiver_conformance.network.dialer import (
    DialErrorCode,
    DialTimeouts,
    PinnedDestinationDialer,
    PinnedDialError,
)
from webhook_receiver_conformance.network.policy import (
    DestinationPolicyError,
    PolicyErrorCode,
    authorize_resolved_addresses,
    parse_destination_policy,
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

if TYPE_CHECKING:
    from collections.abc import Sequence

SECOND = 1_000_000_000
TIMEOUTS = DialTimeouts(SECOND, SECOND)
NONCE = b"A" * 43


def _receiver(
    url: str,
    *,
    profile: str = "loopback",
    hosts: list[str] | None = None,
    ports: list[int] | None = None,
) -> ReceiverConfig:
    return ReceiverConfig.model_validate(
        {
            "url": url,
            "target_profile": profile,
            "allowed_hosts": [] if hosts is None else hosts,
            "allowed_ports": [8443] if ports is None else ports,
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


@pytest.mark.parametrize("address", ["127.0.0.1", "127.255.255.254", "::1"])
def test_loopback_profile_accepts_only_loopback(address: str) -> None:
    literal = f"[{address}]" if ":" in address else address
    policy = parse_destination_policy(_receiver(f"http://{literal}:8443/hook"))
    assert authorize_resolved_addresses(policy).addresses[0].address_class is AddressClass.LOOPBACK


@pytest.mark.parametrize(
    "address",
    ["10.0.0.1", "172.16.0.1", "192.168.1.1", "93.184.216.34"],
)
def test_private_and_public_literals_fail_under_default_profile(address: str) -> None:
    with pytest.raises(DestinationPolicyError) as captured:
        parse_destination_policy(_receiver(f"http://{address}:8443/hook"))
    assert captured.value.code is PolicyErrorCode.ADDRESS_PROFILE_MISMATCH


def test_private_profile_requires_exact_host_allowlist() -> None:
    with pytest.raises(DestinationPolicyError) as captured:
        parse_destination_policy(
            _receiver(
                "http://receiver.test:8443/hook",
                profile="private-allowlist",
                hosts=["other.test"],
            )
        )
    assert captured.value.code is PolicyErrorCode.HOST_NOT_ALLOWED


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "100.64.0.1",
        "169.254.169.254",
        "192.0.2.1",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "::",
        "::ffff:127.0.0.1",
        "64:ff9b::1",
        "2001:db8::1",
        "2002::1",
        "fe80::1",
        "ff00::1",
    ],
)
def test_special_address_corpus_is_unconditionally_blocked(address: str) -> None:
    assert classify_address(address).address_class is AddressClass.BLOCKED


def test_mixed_safe_and_unsafe_dns_answer_fails_closed() -> None:
    policy = parse_destination_policy(_receiver("http://localhost:8443/hook"))
    with pytest.raises(DestinationPolicyError) as captured:
        authorize_resolved_addresses(policy, ("127.0.0.1", "10.0.0.1"))
    assert captured.value.code is PolicyErrorCode.ADDRESS_PROFILE_MISMATCH


@dataclass(slots=True)
class _Resolver(Resolver):
    answers: Sequence[str]
    calls: list[tuple[str, int]] = field(default_factory=list[tuple[str, int]])

    async def resolve(self, host: str, port: int) -> Sequence[str]:
        self.calls.append((host, port))
        await checkpoint()
        return self.answers


@dataclass(slots=True)
class _Stream(ConnectedByteStream):
    peer: PeerAddress
    response: bytes = b""
    sent: list[bytes] = field(default_factory=list[bytes])
    closed: bool = False
    delivered: bool = False

    @property
    def peer_address(self) -> PeerAddress:
        return self.peer

    async def send(self, item: bytes) -> None:
        self.sent.append(item)

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        del max_bytes
        if self.delivered:
            return b""
        self.delivered = True
        return self.response

    async def send_eof(self) -> None:
        await checkpoint()

    async def aclose(self) -> None:
        self.closed = True


@dataclass(slots=True)
class _Connector(Connector):
    forced_peer: PeerAddress | None = None
    response: bytes = b""
    plans: list[ConnectionPlan] = field(default_factory=list[ConnectionPlan])
    streams: list[_Stream] = field(default_factory=list[_Stream])

    async def connect(self, plan: ConnectionPlan) -> _Stream:
        self.plans.append(plan)
        peer = self.forced_peer or PeerAddress(
            plan.pinned_address,
            plan.port,
            plan.family,
        )
        stream = _Stream(peer, response=self.response)
        self.streams.append(stream)
        await checkpoint()
        return stream


@pytest.mark.anyio
async def test_authorized_answer_remains_pinned_after_resolver_changes() -> None:
    resolver = _Resolver(("127.0.0.2", "127.0.0.3"))
    connector = _Connector()
    dialer = PinnedDestinationDialer(resolver=resolver, connector=connector)
    policy = parse_destination_policy(_receiver("http://localhost:8443/hook"))

    authorized = await dialer.resolve_and_authorize(policy, timeouts=TIMEOUTS)
    resolver.answers = ("10.0.0.1",)
    connection = await dialer.connect_authorized(authorized, timeouts=TIMEOUTS)

    assert resolver.calls == [("localhost", 8443)]
    assert connector.plans[0].pinned_address == "127.0.0.2"
    assert connection.evidence.peer_address == "127.0.0.2"
    await connection.aclose()


@pytest.mark.anyio
async def test_peer_mismatch_aborts_before_any_body_byte() -> None:
    connector = _Connector(
        forced_peer=PeerAddress("127.0.0.2", 8443, SocketFamily.IPV4)
    )
    dialer = PinnedDestinationDialer(
        resolver=_Resolver(("127.0.0.1",)),
        connector=connector,
    )
    with pytest.raises(PinnedDialError) as captured:
        await dialer.dial(
            parse_destination_policy(_receiver("http://localhost:8443/hook")),
            timeouts=TIMEOUTS,
        )
    assert captured.value.code is DialErrorCode.PEER_MISMATCH
    assert connector.streams[0].sent == []
    assert connector.streams[0].closed


class _TLS(TLSContextProvider):
    def create(self, server_hostname: str) -> ssl.SSLContext:
        assert server_hostname == "events.example"
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _public_dialer(body: bytes, status: bytes = b"200 OK") -> tuple[
    PinnedDestinationDialer,
    _Resolver,
    _Connector,
]:
    response = (
        b"HTTP/1.1 "
        + status
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    resolver = _Resolver(("93.184.216.34",))
    connector = _Connector(response=response)
    return (
        PinnedDestinationDialer(
            resolver=resolver,
            connector=connector,
            tls_context_provider=_TLS(),
        ),
        resolver,
        connector,
    )


@pytest.mark.anyio
@pytest.mark.parametrize("authorization", [None, "", "wrong.example:443"])
async def test_missing_public_gate_prevents_dns_and_delivery(
    authorization: str | None,
) -> None:
    dialer, resolver, connector = _public_dialer(NONCE)
    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(
                "https://events.example:443/hooks",
                profile="public-authorized",
                hosts=["events.example"],
                ports=[443],
            ),
            runtime_public_authorization=authorization,
            dialer=dialer,
            dial_timeouts=TIMEOUTS,
            nonce_source=lambda: NONCE,
        )
    assert captured.value.code is PreflightErrorCode.POLICY_REJECTED
    assert resolver.calls == []
    assert connector.plans == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        (b"", b"200 OK", PreflightErrorCode.CHALLENGE_MISSING),
        (b"B" * 43, b"200 OK", PreflightErrorCode.CHALLENGE_MISMATCH),
        (NONCE, b"302 Found", PreflightErrorCode.REDIRECT_REJECTED),
    ],
)
async def test_missing_wrong_or_redirected_challenge_fails_closed(
    body: bytes,
    status: bytes,
    code: PreflightErrorCode,
) -> None:
    dialer, _resolver, connector = _public_dialer(body, status)
    with pytest.raises(PublicTargetPreflightError) as captured:
        await preflight_public_target(
            _receiver(
                "https://events.example:443/hooks",
                profile="public-authorized",
                hosts=["events.example"],
                ports=[443],
            ),
            runtime_public_authorization="events.example:443",
            dialer=dialer,
            dial_timeouts=TIMEOUTS,
            nonce_source=lambda: NONCE,
        )
    assert captured.value.code is code
    assert len(connector.streams[0].sent) == 1
