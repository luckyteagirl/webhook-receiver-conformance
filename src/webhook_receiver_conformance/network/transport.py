"""Injectable low-level transport seams for pinned network connections."""
# ruff: noqa: INP001

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from enum import IntEnum
from ipaddress import ip_address
from typing import TYPE_CHECKING, Literal, Protocol, cast

import anyio
import httpx
from anyio.abc import ByteStream, SocketAttribute

if TYPE_CHECKING:
    from collections.abc import Sequence

MAX_RESOLVER_RESULTS = 64
MAX_GETADDRINFO_RECORDS = 256
MAX_IO_CHUNK_BYTES = 1_048_576
MAX_TCP_PORT = 65_535
MIN_SOCKET_ADDRESS_PARTS = 2
GETADDRINFO_RECORD_PARTS = 5


class ResolverResultLimitError(RuntimeError):
    """The complete resolver answer exceeded a bounded resource limit."""


class ResolverRecordError(RuntimeError):
    """The resolver returned a malformed or unexpected socket record."""


class SocketFamily(IntEnum):
    """Stable evidence values for supported internet socket families."""

    IPV4 = 4
    IPV6 = 6


@dataclass(frozen=True, slots=True)
class PeerAddress:
    """A normalized connected peer returned by a connector."""

    address: str
    port: int
    family: SocketFamily

    def __post_init__(self) -> None:
        """Require exact canonical peer metadata."""
        parsed = ip_address(self.address)
        if self.address != str(parsed) or self.family.value != parsed.version:
            message = "peer address must be canonical and match its socket family"
            raise ValueError(message)
        if type(self.port) is not int or not 1 <= self.port <= MAX_TCP_PORT:
            message = "peer port must be an integer in the TCP port range"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class ConnectionPlan:
    """One direct connection to a selected, already-authorized address."""

    pinned_address: str
    port: int
    family: SocketFamily
    authorized_addresses: tuple[str, ...]
    host_header: str
    tls_server_hostname: str | None
    ssl_context: ssl.SSLContext | None
    trust_env: Literal[False] = False
    follow_redirects: Literal[False] = False

    def __post_init__(self) -> None:
        """Require a direct, canonical, verified connection plan."""
        parsed = ip_address(self.pinned_address)
        if self.pinned_address != str(parsed) or self.family.value != parsed.version:
            message = "pinned address must be canonical and match its socket family"
            raise ValueError(message)
        if type(self.port) is not int or not 1 <= self.port <= MAX_TCP_PORT:
            message = "connection port must be an integer in the TCP port range"
            raise ValueError(message)
        if (
            type(self.authorized_addresses) is not tuple
            or self.pinned_address not in self.authorized_addresses
            or not self.authorized_addresses
            or any(
                type(address) is not str or address != str(ip_address(address))
                for address in self.authorized_addresses
            )
        ):
            message = "connection plan requires a canonical authorized address set"
            raise ValueError(message)
        if (
            type(self.host_header) is not str
            or not self.host_header
            or "\r" in self.host_header
            or "\n" in self.host_header
        ):
            message = "Host authority must be nonempty and line-safe"
            raise ValueError(message)
        if self.tls_server_hostname is None:
            if self.ssl_context is not None:
                message = "plain connections cannot carry a TLS context"
                raise ValueError(message)
        elif (
            type(self.tls_server_hostname) is not str
            or not self.tls_server_hostname
            or self.ssl_context is None
            or not self.ssl_context.check_hostname
            or self.ssl_context.verify_mode is not ssl.CERT_REQUIRED
        ):
            message = "TLS connections require verified hostname semantics"
            raise ValueError(message)
        if self.trust_env is not False or self.follow_redirects is not False:
            message = "pinned transports cannot enable proxies or redirects"
            raise ValueError(message)


class ConnectedByteStream(Protocol):
    """Minimal connected-stream contract consumed by the later HTTP executor."""

    @property
    def peer_address(self) -> PeerAddress:
        """Return the actual remote socket endpoint."""
        ...

    async def send(self, item: bytes) -> None:
        """Send bytes after the dialer has verified the peer."""
        ...

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        """Receive at most ``max_bytes`` response bytes."""
        ...

    async def send_eof(self) -> None:
        """Signal the end of the byte stream."""
        ...

    async def aclose(self) -> None:
        """Close the stream and its underlying socket."""
        ...


class Resolver(Protocol):
    """Resolver seam whose complete result is authorized as one set."""

    async def resolve(self, host: str, port: int) -> Sequence[str]:
        """Return all A and AAAA candidate addresses."""
        ...


class Connector(Protocol):
    """Direct connector seam that receives a numeric pinned destination."""

    async def connect(self, plan: ConnectionPlan) -> ConnectedByteStream:
        """Connect exactly to ``plan.pinned_address``."""
        ...


class TLSContextProvider(Protocol):
    """TLS policy seam used without changing the selected socket address."""

    def create(self, server_hostname: str) -> ssl.SSLContext:
        """Return a certificate- and hostname-verifying client context."""
        ...


class DefaultTLSContextProvider:
    """System-trust TLS policy with certificate and hostname checks enabled."""

    def create(self, server_hostname: str) -> ssl.SSLContext:
        """Build a verified client context for a canonical hostname."""
        if type(server_hostname) is not str or not server_hostname:
            message = "TLS server hostname must be nonempty"
            raise ValueError(message)
        context = httpx.create_ssl_context(verify=True, trust_env=False)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context


class AnyIOResolver:
    """Resolver adapter using AnyIO on the configured asyncio backend."""

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        """Resolve a bounded complete A/AAAA set without retaining socket aliases."""
        records = await anyio.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        addresses: list[str] = []
        for record_index, record in enumerate(records, start=1):
            if record_index > MAX_GETADDRINFO_RECORDS:
                message = "resolver returned more than 256 raw socket records"
                raise ResolverResultLimitError(message)
            (
                family,
                socket_kind,
                raw_socket_address,
            ) = _unpack_resolver_record(cast("object", record))
            if socket_kind != socket.SOCK_STREAM or family not in {
                socket.AF_INET,
                socket.AF_INET6,
            }:
                message = "resolver returned an unexpected non-TCP internet record"
                raise ResolverRecordError(message)
            raw_host = raw_socket_address[0]
            raw_port = raw_socket_address[1]
            if type(raw_host) is not str or type(raw_port) is not int or raw_port != port:
                message = "resolver returned malformed socket address metadata"
                raise ResolverRecordError(message)
            try:
                parsed = ip_address(raw_host)
            except ValueError as error:
                message = "resolver returned a malformed internet address"
                raise ResolverRecordError(message) from error
            if (family == socket.AF_INET and parsed.version != SocketFamily.IPV4) or (
                family == socket.AF_INET6 and parsed.version != SocketFamily.IPV6
            ):
                message = "resolver address did not match its socket family"
                raise ResolverRecordError(message)
            normalized = str(parsed)
            if normalized not in addresses:
                if len(addresses) == MAX_RESOLVER_RESULTS:
                    message = "resolver returned more than 64 unique addresses"
                    raise ResolverResultLimitError(message)
                addresses.append(normalized)
        return tuple(addresses)


def _unpack_resolver_record(
    record: object,
) -> tuple[socket.AddressFamily, socket.SocketKind, tuple[object, ...]]:
    if type(record) is not tuple:
        message = "resolver socket record must be a tuple"
        raise ResolverRecordError(message)
    parts = cast("tuple[object, ...]", record)
    if len(parts) != GETADDRINFO_RECORD_PARTS:
        message = "resolver socket record must contain exactly five fields"
        raise ResolverRecordError(message)
    family, socket_kind, protocol, canonical_name, raw_socket_address = parts
    if (
        type(family) is not socket.AddressFamily
        or type(socket_kind) is not socket.SocketKind
        or type(protocol) is not int
        or type(canonical_name) is not str
        or type(raw_socket_address) is not tuple
    ):
        message = "resolver socket record contains malformed field types"
        raise ResolverRecordError(message)
    socket_address_parts = cast("tuple[object, ...]", raw_socket_address)
    if len(socket_address_parts) != MIN_SOCKET_ADDRESS_PARTS:
        message = "AnyIO resolver socket address must contain host and port"
        raise ResolverRecordError(message)
    return family, socket_kind, socket_address_parts


class AnyIOConnectedByteStream:
    """Typed adapter around an AnyIO socket or TLS byte stream."""

    __slots__ = ("_stream",)

    def __init__(self, stream: ByteStream) -> None:
        """Wrap one established AnyIO socket or TLS stream."""
        self._stream = stream

    @property
    def peer_address(self) -> PeerAddress:
        """Return normalized peer evidence from the established socket."""
        raw_address = cast(
            "object",
            self._stream.extra(SocketAttribute.remote_address),  # noqa: S610
        )
        if not isinstance(raw_address, tuple):
            message = "connected stream did not expose an internet peer address"
            raise TypeError(message)
        address_parts = cast("tuple[object, ...]", raw_address)
        if len(address_parts) < MIN_SOCKET_ADDRESS_PARTS:
            message = "connected stream did not expose an internet peer address"
            raise ValueError(message)
        raw_host = address_parts[0]
        raw_port = address_parts[1]
        if type(raw_host) is not str or type(raw_port) is not int:
            message = "connected stream returned malformed peer metadata"
            raise ValueError(message)
        parsed = ip_address(raw_host)
        family = SocketFamily(parsed.version)
        return PeerAddress(address=str(parsed), port=raw_port, family=family)

    async def send(self, item: bytes) -> None:
        """Send one bounded immutable byte chunk."""
        if type(item) is not bytes or len(item) > MAX_IO_CHUNK_BYTES:
            message = "transport send chunks must be bytes bounded to 1 MiB"
            raise ValueError(message)
        await self._stream.send(item)

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        """Receive one bounded response chunk."""
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_IO_CHUNK_BYTES:
            message = "transport receive limit must be between 1 byte and 1 MiB"
            raise ValueError(message)
        return await self._stream.receive(max_bytes)

    async def send_eof(self) -> None:
        """Signal the end of the stream."""
        await self._stream.send_eof()

    async def aclose(self) -> None:
        """Close the underlying AnyIO stream."""
        await self._stream.aclose()


class AnyIOConnector:
    """Direct numeric-address connector with optional verified TLS wrapping."""

    async def connect(self, plan: ConnectionPlan) -> AnyIOConnectedByteStream:
        """Connect to the numeric pin while retaining canonical TLS hostname semantics."""
        stream = await anyio.connect_tcp(
            remote_host=plan.pinned_address,
            remote_port=plan.port,
            tls=plan.tls_server_hostname is not None,
            ssl_context=plan.ssl_context,
            tls_hostname=plan.tls_server_hostname,
        )
        return AnyIOConnectedByteStream(stream)
