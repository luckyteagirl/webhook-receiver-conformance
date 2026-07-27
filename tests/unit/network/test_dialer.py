"""Contract and hostile-transport tests for TASK-0306 pinned dialing."""
# ruff: noqa: D101, D102, D107, INP001

from __future__ import annotations

import copy
import socket
import ssl
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import anyio
import pytest
from anyio.lowlevel import checkpoint

import webhook_receiver_conformance.network.transport as transport_module
from webhook_receiver_conformance.config.models import ReceiverConfig
from webhook_receiver_conformance.network.dialer import (
    DialErrorCode,
    DialPhase,
    DialTimeouts,
    PinnedDestinationDialer,
    PinnedDialError,
)
from webhook_receiver_conformance.network.policy import (
    DestinationPolicy,
    DestinationPolicyError,
    PolicyErrorCode,
    parse_destination_policy,
)
from webhook_receiver_conformance.network.transport import (
    MAX_RESOLVER_RESULTS,
    AnyIOConnectedByteStream,
    AnyIOConnector,
    AnyIOResolver,
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

    from anyio.abc import ByteStream

SECOND = 1_000_000_000
TIMEOUTS = DialTimeouts(
    resolve_nanoseconds=SECOND,
    connect_nanoseconds=SECOND,
)
type GetaddrinfoRecord = tuple[
    socket.AddressFamily,
    socket.SocketKind,
    int,
    str,
    tuple[str, int],
]


def _policy(
    url: str,
    *,
    target_profile: str = "loopback",
    allowed_hosts: list[str] | None = None,
    runtime_public_authorization: str | None = None,
) -> DestinationPolicy:
    receiver = ReceiverConfig.model_validate(
        {
            "url": url,
            "target_profile": target_profile,
            "allowed_hosts": [] if allowed_hosts is None else allowed_hosts,
            "allowed_ports": [443, 8443],
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
    return parse_destination_policy(
        receiver,
        runtime_public_authorization=runtime_public_authorization,
    )


def _resolver_record(
    address: str,
    *,
    port: int = 8443,
    family: socket.AddressFamily = socket.AF_INET,
    socket_kind: socket.SocketKind = socket.SOCK_STREAM,
) -> GetaddrinfoRecord:
    return family, socket_kind, socket.IPPROTO_TCP, "", (address, port)


def _install_getaddrinfo(
    monkeypatch: pytest.MonkeyPatch,
    records: list[GetaddrinfoRecord],
) -> None:
    async def fake_getaddrinfo(  # noqa: PLR0913
        host: bytes | str | None,
        port: str | int | None,
        *,
        family: int | socket.AddressFamily = 0,
        type: int | socket.SocketKind = 0,  # noqa: A002
        proto: int = 0,
        flags: int = 0,
    ) -> list[GetaddrinfoRecord]:
        del host, port, family, type, proto, flags
        return records

    monkeypatch.setattr(transport_module.anyio, "getaddrinfo", fake_getaddrinfo)


@dataclass(slots=True)
class FakeResolver(Resolver):
    answers: Sequence[str]
    calls: list[tuple[str, int]] = field(default_factory=list[tuple[str, int]])

    async def resolve(self, host: str, port: int) -> Sequence[str]:
        self.calls.append((host, port))
        await checkpoint()
        return self.answers


@dataclass(slots=True)
class FakeStream(ConnectedByteStream):
    peer: PeerAddress
    sent: list[bytes] = field(default_factory=list[bytes])
    closed: bool = False
    received: bytes = b""

    @property
    def peer_address(self) -> PeerAddress:
        return self.peer

    async def send(self, item: bytes) -> None:
        self.sent.append(item)

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        return self.received[:max_bytes]

    async def send_eof(self) -> None:
        await checkpoint()

    async def aclose(self) -> None:
        self.closed = True


class RecordingConnector(Connector):
    def __init__(self, *, forced_peer: PeerAddress | None = None) -> None:
        self.forced_peer = forced_peer
        self.plans: list[ConnectionPlan] = []
        self.streams: list[FakeStream] = []

    async def connect(self, plan: ConnectionPlan) -> FakeStream:
        self.plans.append(plan)
        peer = (
            PeerAddress(plan.pinned_address, plan.port, plan.family)
            if self.forced_peer is None
            else self.forced_peer
        )
        stream = FakeStream(peer)
        self.streams.append(stream)
        await checkpoint()
        return stream


class RecordingTLSProvider(TLSContextProvider):
    def __init__(self) -> None:
        self.hostnames: list[str] = []
        self.contexts: list[ssl.SSLContext] = []

    def create(self, server_hostname: str) -> ssl.SSLContext:
        self.hostnames.append(server_hostname)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.contexts.append(context)
        return context


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("answers", "expected_address", "expected_family"),
    [
        (("127.0.0.2",), "127.0.0.2", SocketFamily.IPV4),
        (("::1",), "::1", SocketFamily.IPV6),
    ],
)
async def test_ipv4_and_ipv6_pins_match_actual_peer_evidence(
    answers: tuple[str, ...],
    expected_address: str,
    expected_family: SocketFamily,
) -> None:
    resolver = FakeResolver(answers)
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(resolver=resolver, connector=connector)

    connection = await dialer.dial(
        _policy("http://localhost:8443/webhook"),
        timeouts=TIMEOUTS,
    )

    assert resolver.calls == [("localhost", 8443)]
    assert connection.plan.pinned_address == expected_address
    assert connection.plan.family is expected_family
    assert connection.plan.authorized_addresses == answers
    assert connection.evidence.authorized_address == expected_address
    assert connection.evidence.authorized_family is expected_family
    assert connection.evidence.peer_address == expected_address
    assert connection.evidence.peer_family is expected_family
    assert connection.plan.host_header == "localhost:8443"
    assert connection.plan.trust_env is False
    assert connection.plan.follow_redirects is False
    await connection.aclose()
    assert connector.streams[0].closed


@pytest.mark.anyio
async def test_mixed_safe_and_unsafe_dns_answers_fail_before_connect() -> None:
    resolver = FakeResolver(("127.0.0.1", "10.0.0.1"))
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(resolver=resolver, connector=connector)

    with pytest.raises(DestinationPolicyError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    assert captured.value.code is PolicyErrorCode.ADDRESS_PROFILE_MISMATCH
    assert len(resolver.calls) == 1
    assert connector.plans == []


@pytest.mark.anyio
async def test_anyio_resolver_accepts_exactly_64_complete_safe_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [_resolver_record(f"127.0.0.{index}") for index in range(1, 65)]
    _install_getaddrinfo(monkeypatch, records)
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(
        resolver=AnyIOResolver(),
        connector=connector,
    )

    connection = await dialer.dial(
        _policy("http://localhost:8443/webhook"),
        timeouts=TIMEOUTS,
    )

    assert len(connection.plan.authorized_addresses) == MAX_RESOLVER_RESULTS
    assert connection.plan.pinned_address == "127.0.0.1"
    assert len(connector.plans) == 1


@pytest.mark.anyio
async def test_anyio_resolver_preserves_ipv6_family_and_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_getaddrinfo(
        monkeypatch,
        [_resolver_record("::1", family=socket.AF_INET6)],
    )
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(
        resolver=AnyIOResolver(),
        connector=connector,
    )

    connection = await dialer.dial(
        _policy("http://localhost:8443/webhook"),
        timeouts=TIMEOUTS,
    )

    assert connection.plan.pinned_address == "::1"
    assert connection.plan.family is SocketFamily.IPV6
    assert connection.evidence.peer_family is SocketFamily.IPV6


@pytest.mark.anyio
async def test_65th_unique_unsafe_answer_fails_closed_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [_resolver_record(f"127.0.0.{index}") for index in range(1, 65)]
    records.append(_resolver_record("10.0.0.1"))
    _install_getaddrinfo(monkeypatch, records)
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(
        resolver=AnyIOResolver(),
        connector=connector,
    )

    with pytest.raises(PinnedDialError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    assert captured.value.code is DialErrorCode.RESOLUTION_RESULT_LIMIT
    assert captured.value.phase is DialPhase.RESOLUTION
    assert captured.value.retryable is False
    assert connector.plans == []


@pytest.mark.anyio
async def test_duplicate_raw_record_flood_is_bounded_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_getaddrinfo(
        monkeypatch,
        [_resolver_record("127.0.0.1")] * 257,
    )
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(
        resolver=AnyIOResolver(),
        connector=connector,
    )

    with pytest.raises(PinnedDialError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    assert captured.value.code is DialErrorCode.RESOLUTION_RESULT_LIMIT
    assert captured.value.phase is DialPhase.RESOLUTION
    assert captured.value.retryable is False
    assert connector.plans == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "record",
    [
        _resolver_record("127.0.0.1", socket_kind=socket.SOCK_DGRAM),
        _resolver_record("::1", family=socket.AF_INET),
        _resolver_record("127.0.0.1", port=443),
    ],
)
async def test_malformed_or_unexpected_getaddrinfo_record_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    record: GetaddrinfoRecord,
) -> None:
    _install_getaddrinfo(monkeypatch, [record])
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(
        resolver=AnyIOResolver(),
        connector=connector,
    )

    with pytest.raises(PinnedDialError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    assert captured.value.code is DialErrorCode.RESOLUTION_RESULT_INVALID
    assert captured.value.phase is DialPhase.RESOLUTION
    assert captured.value.retryable is False
    assert connector.plans == []


@pytest.mark.anyio
async def test_copied_mutated_policy_is_rejected_before_resolver_side_effect() -> None:
    resolver = FakeResolver(("127.0.0.1",))
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(resolver=resolver, connector=connector)
    policy = _policy("http://localhost:8443/webhook")
    forged = copy.copy(policy)
    forged_destination = copy.copy(policy.destination)
    object.__setattr__(forged_destination, "host", "evil.test")
    object.__setattr__(forged, "destination", forged_destination)

    with pytest.raises(DestinationPolicyError) as captured:
        await dialer.dial(forged, timeouts=TIMEOUTS)

    assert captured.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID
    assert resolver.calls == []
    assert connector.plans == []


@pytest.mark.anyio
async def test_authorized_dns_answer_is_pinned_without_reresolution_or_fallback() -> None:
    resolver = FakeResolver(("127.0.0.2", "127.0.0.3"))
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(resolver=resolver, connector=connector)
    policy = _policy("http://localhost:8443/webhook")

    authorized = await dialer.resolve_and_authorize(policy, timeouts=TIMEOUTS)
    resolver.answers = ("10.0.0.1",)
    connection = await dialer.connect_authorized(authorized, timeouts=TIMEOUTS)

    assert resolver.calls == [("localhost", 8443)]
    assert len(connector.plans) == 1
    assert connector.plans[0].pinned_address == "127.0.0.2"
    assert connector.plans[0].authorized_addresses == ("127.0.0.2", "127.0.0.3")
    assert connection.evidence.peer_address == "127.0.0.2"


@pytest.mark.anyio
async def test_peer_mismatch_aborts_and_closes_before_any_body_byte() -> None:
    resolver = FakeResolver(("127.0.0.1",))
    connector = RecordingConnector(forced_peer=PeerAddress("127.0.0.2", 8443, SocketFamily.IPV4))
    dialer = PinnedDestinationDialer(resolver=resolver, connector=connector)

    with pytest.raises(PinnedDialError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    assert captured.value.code is DialErrorCode.PEER_MISMATCH
    assert captured.value.body_bytes_sent is False
    assert connector.streams[0].sent == []
    assert connector.streams[0].closed


@pytest.mark.anyio
async def test_connector_cannot_rewrite_plan_and_self_attest_new_peer() -> None:
    class PlanMutatingConnector(Connector):
        stream: FakeStream | None = None

        async def connect(self, plan: ConnectionPlan) -> ConnectedByteStream:
            object.__setattr__(plan, "pinned_address", "10.0.0.1")
            object.__setattr__(plan, "authorized_addresses", ("10.0.0.1",))
            self.stream = FakeStream(PeerAddress("10.0.0.1", 8443, SocketFamily.IPV4))
            return self.stream

    connector = PlanMutatingConnector()
    dialer = PinnedDestinationDialer(
        resolver=FakeResolver(("127.0.0.1",)),
        connector=connector,
    )

    with pytest.raises(PinnedDialError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    assert captured.value.code is DialErrorCode.PEER_MISMATCH
    assert connector.stream is not None
    assert connector.stream.sent == []
    assert connector.stream.closed


@pytest.mark.anyio
async def test_malformed_peer_evidence_aborts_and_closes_before_send() -> None:
    class MalformedPeerStream(FakeStream):
        @property
        def peer_address(self) -> PeerAddress:
            raise ValueError

    class MalformedPeerConnector(Connector):
        stream: MalformedPeerStream

        def __init__(self) -> None:
            self.stream = MalformedPeerStream(PeerAddress("127.0.0.1", 8443, SocketFamily.IPV4))

        async def connect(self, plan: ConnectionPlan) -> ConnectedByteStream:
            del plan
            return self.stream

    connector = MalformedPeerConnector()
    dialer = PinnedDestinationDialer(
        resolver=FakeResolver(("127.0.0.1",)),
        connector=connector,
    )

    with pytest.raises(PinnedDialError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    assert captured.value.code is DialErrorCode.PEER_INVALID
    assert connector.stream.sent == []
    assert connector.stream.closed


@pytest.mark.anyio
async def test_canonical_idna_host_is_preserved_for_host_tls_sni_and_cert_check() -> None:
    resolver = FakeResolver(("10.0.0.8",))
    connector = RecordingConnector()
    tls_provider = RecordingTLSProvider()
    dialer = PinnedDestinationDialer(
        resolver=resolver,
        connector=connector,
        tls_context_provider=tls_provider,
    )
    policy = _policy(
        "https://b\u00fccher.example:443/base",
        target_profile="private-allowlist",
        allowed_hosts=["b\u00fccher.example"],
    )

    connection = await dialer.dial(policy, timeouts=TIMEOUTS)

    assert resolver.calls == [("xn--bcher-kva.example", 443)]
    assert connection.plan.pinned_address == "10.0.0.8"
    assert connection.plan.host_header == "xn--bcher-kva.example:443"
    assert connection.plan.tls_server_hostname == "xn--bcher-kva.example"
    assert tls_provider.hostnames == ["xn--bcher-kva.example"]
    assert connection.plan.ssl_context is tls_provider.contexts[0]
    tls_context = connection.plan.ssl_context
    assert tls_context is not None
    assert tls_context.check_hostname
    assert tls_context.verify_mode is ssl.CERT_REQUIRED


@pytest.mark.anyio
async def test_anyio_connector_uses_numeric_pin_with_canonical_tls_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def fake_connect_tcp(
        remote_host: str,
        remote_port: int,
        *,
        tls: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        tls_hostname: str | None = None,
        **extra: object,
    ) -> ByteStream:
        captured.update(
            {
                "remote_host": remote_host,
                "remote_port": remote_port,
                "tls": tls,
                "ssl_context": ssl_context,
                "tls_hostname": tls_hostname,
                "extra": extra,
            }
        )
        return cast("ByteStream", object())

    monkeypatch.setattr(transport_module.anyio, "connect_tcp", fake_connect_tcp)
    context = RecordingTLSProvider().create("receiver.test")
    plan = ConnectionPlan(
        pinned_address="10.0.0.8",
        port=443,
        family=SocketFamily.IPV4,
        authorized_addresses=("10.0.0.8",),
        host_header="receiver.test:443",
        tls_server_hostname="receiver.test",
        ssl_context=context,
    )

    connected = await AnyIOConnector().connect(plan)

    assert type(connected) is AnyIOConnectedByteStream
    assert captured == {
        "remote_host": "10.0.0.8",
        "remote_port": 443,
        "tls": True,
        "ssl_context": context,
        "tls_hostname": "receiver.test",
        "extra": {},
    }


@pytest.mark.anyio
async def test_ipv6_literal_uses_bracketed_host_authority_without_resolution() -> None:
    resolver = FakeResolver(("127.0.0.1",))
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(resolver=resolver, connector=connector)

    connection = await dialer.dial(
        _policy("http://[::1]:8443/webhook"),
        timeouts=TIMEOUTS,
    )

    assert resolver.calls == []
    assert connection.plan.pinned_address == "::1"
    assert connection.plan.host_header == "[::1]:8443"


@pytest.mark.anyio
@pytest.mark.parametrize("observer_path", ["/capabilities", "/observe"])
async def test_observer_paths_share_direct_no_proxy_no_redirect_dialer(
    observer_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    resolver = FakeResolver(("127.0.0.1",))
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(resolver=resolver, connector=connector)

    connection = await dialer.dial(
        _policy(
            f"http://observer.test:8443{observer_path}",
            target_profile="private-allowlist",
            allowed_hosts=["observer.test"],
        ),
        timeouts=TIMEOUTS,
    )

    assert resolver.calls == [("observer.test", 8443)]
    assert connection.plan.pinned_address == "127.0.0.1"
    assert connection.plan.trust_env is False
    assert connection.plan.follow_redirects is False
    assert connector.plans == [connection.plan]


@pytest.mark.anyio
async def test_resolution_timeout_is_classified_and_never_connects() -> None:
    class BlockingResolver(Resolver):
        async def resolve(self, host: str, port: int) -> Sequence[str]:
            del host, port
            await anyio.sleep_forever()
            raise AssertionError

    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(
        resolver=BlockingResolver(),
        connector=connector,
    )
    timeouts = DialTimeouts(
        resolve_nanoseconds=1_000_000,
        connect_nanoseconds=SECOND,
    )

    with pytest.raises(PinnedDialError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=timeouts,
        )

    assert captured.value.code is DialErrorCode.RESOLUTION_TIMEOUT
    assert captured.value.retryable
    assert connector.plans == []


@pytest.mark.anyio
async def test_resolution_and_connection_errors_are_phase_classified() -> None:
    class FailingResolver(Resolver):
        async def resolve(self, host: str, port: int) -> Sequence[str]:
            del host, port
            raise OSError

    connector = RecordingConnector()
    resolution_dialer = PinnedDestinationDialer(
        resolver=FailingResolver(),
        connector=connector,
    )
    with pytest.raises(PinnedDialError) as resolution_error:
        await resolution_dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )
    assert resolution_error.value.code is DialErrorCode.RESOLUTION_FAILED
    assert resolution_error.value.body_bytes_sent is False

    class FailingTLSConnector(Connector):
        async def connect(self, plan: ConnectionPlan) -> ConnectedByteStream:
            del plan
            raise ssl.SSLError

    tls_dialer = PinnedDestinationDialer(
        resolver=FakeResolver(("10.0.0.8",)),
        connector=FailingTLSConnector(),
        tls_context_provider=RecordingTLSProvider(),
    )
    with pytest.raises(PinnedDialError) as tls_error:
        await tls_dialer.dial(
            _policy(
                "https://receiver.test:443/webhook",
                target_profile="private-allowlist",
                allowed_hosts=["receiver.test"],
            ),
            timeouts=TIMEOUTS,
        )
    assert tls_error.value.code is DialErrorCode.TLS_FAILED
    assert tls_error.value.body_bytes_sent is False


@pytest.mark.anyio
async def test_connection_timeout_is_bounded_and_classified() -> None:
    class BlockingConnector(Connector):
        async def connect(self, plan: ConnectionPlan) -> ConnectedByteStream:
            del plan
            await anyio.sleep_forever()
            raise AssertionError

    dialer = PinnedDestinationDialer(
        resolver=FakeResolver(("127.0.0.1",)),
        connector=BlockingConnector(),
    )
    timeouts = DialTimeouts(
        resolve_nanoseconds=SECOND,
        connect_nanoseconds=1_000_000,
    )

    with pytest.raises(PinnedDialError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=timeouts,
        )

    assert captured.value.code is DialErrorCode.CONNECT_TIMEOUT
    assert captured.value.body_bytes_sent is False


@pytest.mark.anyio
async def test_cancellation_propagates_without_connecting() -> None:
    entered = anyio.Event()

    class BlockingResolver(Resolver):
        async def resolve(self, host: str, port: int) -> Sequence[str]:
            del host, port
            entered.set()
            await anyio.sleep_forever()
            raise AssertionError

    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(
        resolver=BlockingResolver(),
        connector=connector,
    )

    async def run_dial() -> None:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(run_dial)
        await entered.wait()
        task_group.cancel_scope.cancel()

    assert connector.plans == []


@pytest.mark.anyio
async def test_connection_cancellation_is_not_reclassified() -> None:
    entered = anyio.Event()

    class BlockingConnector(Connector):
        async def connect(self, plan: ConnectionPlan) -> ConnectedByteStream:
            del plan
            entered.set()
            await anyio.sleep_forever()
            raise AssertionError

    dialer = PinnedDestinationDialer(
        resolver=FakeResolver(("127.0.0.1",)),
        connector=BlockingConnector(),
    )

    async def run_dial() -> None:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(run_dial)
        await entered.wait()
        task_group.cancel_scope.cancel()


@pytest.mark.anyio
async def test_resolver_result_cap_rejects_before_connection() -> None:
    answers = tuple(f"127.0.0.{index}" for index in range(1, 66))
    resolver = FakeResolver(answers)
    connector = RecordingConnector()
    dialer = PinnedDestinationDialer(resolver=resolver, connector=connector)

    with pytest.raises(DestinationPolicyError) as captured:
        await dialer.dial(
            _policy("http://localhost:8443/webhook"),
            timeouts=TIMEOUTS,
        )

    assert captured.value.code is PolicyErrorCode.ADDRESS_SET_INVALID
    assert connector.plans == []


def test_timeout_and_transport_controls_are_strictly_bounded() -> None:
    for invalid in (0, -1, True, (2**63)):
        with pytest.raises(ValueError, match="positive signed-int64"):
            DialTimeouts(
                resolve_nanoseconds=invalid,
                connect_nanoseconds=SECOND,
            )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with pytest.raises(ValueError, match="proxies or redirects"):
        ConnectionPlan(
            pinned_address="127.0.0.1",
            port=8443,
            family=SocketFamily.IPV4,
            authorized_addresses=("127.0.0.1",),
            host_header="localhost:8443",
            tls_server_hostname="localhost",
            ssl_context=context,
            trust_env=True,  # type: ignore[arg-type]
        )
