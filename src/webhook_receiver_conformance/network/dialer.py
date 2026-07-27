"""Resolve-once, authorize-all, pinned destination dialing."""
# ruff: noqa: INP001

from __future__ import annotations

import math
import ssl
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Self

import anyio

from webhook_receiver_conformance.network.policy import (
    AuthorizedDestination,
    DestinationPolicy,
    authorize_resolved_addresses,
    validate_authorized_destination,
    validate_destination_policy,
)
from webhook_receiver_conformance.network.transport import (
    ConnectedByteStream,
    ConnectionPlan,
    Connector,
    DefaultTLSContextProvider,
    PeerAddress,
    Resolver,
    ResolverRecordError,
    ResolverResultLimitError,
    SocketFamily,
    TLSContextProvider,
)

if TYPE_CHECKING:
    from types import TracebackType

MAX_TIMEOUT_NANOSECONDS = (2**63) - 1
DEFAULT_CLOSE_TIMEOUT_NANOSECONDS = 1_000_000_000
_NANOSECONDS_PER_SECOND = 1_000_000_000


class DialPhase(StrEnum):
    """Stable phases for pre-send network failures."""

    RESOLUTION = "resolution"
    TLS_CONFIGURATION = "tls-configuration"
    CONNECTION = "connection"
    PEER_VERIFICATION = "peer-verification"


class DialErrorCode(StrEnum):
    """Stable, bounded dialer failure codes."""

    RESOLUTION_TIMEOUT = "resolution-timeout"
    RESOLUTION_RESULT_LIMIT = "resolution-result-limit"
    RESOLUTION_RESULT_INVALID = "resolution-result-invalid"
    RESOLUTION_FAILED = "resolution-failed"
    TLS_CONFIGURATION_FAILED = "tls-configuration-failed"
    CONNECT_TIMEOUT = "connect-timeout"
    TLS_FAILED = "tls-failed"
    CONNECTION_FAILED = "connection-failed"
    PEER_INVALID = "peer-invalid"
    PEER_MISMATCH = "peer-mismatch"


class PinnedDialError(RuntimeError):
    """Privacy-safe pre-send failure from the pinned transport boundary."""

    code: DialErrorCode
    phase: DialPhase
    retryable: bool
    body_bytes_sent: bool = False

    def __init__(
        self,
        code: DialErrorCode,
        phase: DialPhase,
        message: str,
        *,
        retryable: bool,
    ) -> None:
        """Initialize one classified failure without target-derived text."""
        self.code = code
        self.phase = phase
        self.retryable = retryable
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class DialTimeouts:
    """Physical monotonic bounds for resolution, connection, and cleanup."""

    resolve_nanoseconds: int
    connect_nanoseconds: int
    close_nanoseconds: int = DEFAULT_CLOSE_TIMEOUT_NANOSECONDS

    def __post_init__(self) -> None:
        """Reject unbounded, non-integral, or nonpositive physical durations."""
        for value in (
            self.resolve_nanoseconds,
            self.connect_nanoseconds,
            self.close_nanoseconds,
        ):
            if type(value) is not int or not 1 <= value <= MAX_TIMEOUT_NANOSECONDS:
                message = "dial timeouts must be positive signed-int64 nanoseconds"
                raise ValueError(message)


@dataclass(frozen=True, slots=True)
class PeerAddressEvidence:
    """Authorized pin and actual peer facts captured before request bytes."""

    authorized_address: str
    authorized_family: SocketFamily
    peer_address: str
    peer_family: SocketFamily


@dataclass(frozen=True, slots=True)
class PinnedConnection:
    """A verified stream plus immutable connection plan and peer evidence."""

    stream: ConnectedByteStream
    plan: ConnectionPlan
    evidence: PeerAddressEvidence

    async def __aenter__(self) -> Self:
        """Enter a verified connection context."""
        return self

    async def __aexit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        """Close the stream when leaving its connection context."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the verified transport stream."""
        await self.stream.aclose()


class PinnedDestinationDialer:
    """One-shot resolver, policy authorizer, and numeric-address connector."""

    __slots__ = ("_connector", "_resolver", "_tls_context_provider")

    def __init__(
        self,
        *,
        resolver: Resolver,
        connector: Connector,
        tls_context_provider: TLSContextProvider | None = None,
    ) -> None:
        """Initialize explicit resolver, connector, and TLS policy seams."""
        self._resolver = resolver
        self._connector = connector
        self._tls_context_provider = (
            DefaultTLSContextProvider() if tls_context_provider is None else tls_context_provider
        )

    async def dial(
        self,
        policy: DestinationPolicy,
        *,
        timeouts: DialTimeouts,
    ) -> PinnedConnection:
        """Resolve and authorize exactly once, then connect to one numeric pin."""
        authorized = await self.resolve_and_authorize(policy, timeouts=timeouts)
        return await self.connect_authorized(authorized, timeouts=timeouts)

    async def resolve_and_authorize(
        self,
        policy: DestinationPolicy,
        *,
        timeouts: DialTimeouts,
    ) -> AuthorizedDestination:
        """Resolve the complete current answer set and authorize every address."""
        validated_policy = validate_destination_policy(policy)
        destination = validated_policy.destination
        host = destination.host
        port = destination.port
        literal_address = destination.literal_address
        validate_destination_policy(validated_policy)
        if literal_address is not None:
            return authorize_resolved_addresses(validated_policy)
        resolve_seconds = _seconds(timeouts.resolve_nanoseconds)
        try:
            with anyio.fail_after(resolve_seconds):
                candidates = await self._resolver.resolve(host, port)
        except TimeoutError as error:
            raise PinnedDialError(
                DialErrorCode.RESOLUTION_TIMEOUT,
                DialPhase.RESOLUTION,
                "destination resolution exceeded its physical timeout",
                retryable=True,
            ) from error
        except ResolverResultLimitError as error:
            raise PinnedDialError(
                DialErrorCode.RESOLUTION_RESULT_LIMIT,
                DialPhase.RESOLUTION,
                "destination resolution exceeded its bounded result limit",
                retryable=False,
            ) from error
        except ResolverRecordError as error:
            raise PinnedDialError(
                DialErrorCode.RESOLUTION_RESULT_INVALID,
                DialPhase.RESOLUTION,
                "destination resolution returned invalid socket metadata",
                retryable=False,
            ) from error
        except PinnedDialError:
            raise
        except Exception as error:
            raise PinnedDialError(
                DialErrorCode.RESOLUTION_FAILED,
                DialPhase.RESOLUTION,
                "destination resolution failed",
                retryable=True,
            ) from error
        return authorize_resolved_addresses(validated_policy, candidates)

    async def connect_authorized(
        self,
        authorized: AuthorizedDestination,
        *,
        timeouts: DialTimeouts,
    ) -> PinnedConnection:
        """Validate phase-two authority immediately before direct connection."""
        validated = validate_authorized_destination(authorized)
        selected = validated.addresses[0]
        destination = validated.policy.destination
        pinned_address = selected.normalized
        pinned_family = SocketFamily(selected.version)
        authorized_addresses = tuple(address.normalized for address in validated.addresses)
        scheme = destination.scheme
        host = destination.host
        port = destination.port
        host_header = destination.authority
        validate_authorized_destination(validated)
        connect_seconds = _seconds(timeouts.connect_nanoseconds)
        close_seconds = _seconds(timeouts.close_nanoseconds)
        tls_server_hostname: str | None = None
        tls_context: ssl.SSLContext | None = None
        if scheme == "https":
            tls_server_hostname = host
            try:
                tls_context = self._tls_context_provider.create(tls_server_hostname)
            except Exception as error:
                raise PinnedDialError(
                    DialErrorCode.TLS_CONFIGURATION_FAILED,
                    DialPhase.TLS_CONFIGURATION,
                    "verified TLS context creation failed",
                    retryable=False,
                ) from error
        expected_plan = ConnectionPlan(
            pinned_address=pinned_address,
            port=port,
            family=pinned_family,
            authorized_addresses=authorized_addresses,
            host_header=host_header,
            tls_server_hostname=tls_server_hostname,
            ssl_context=tls_context,
        )
        connector_plan = ConnectionPlan(
            pinned_address=expected_plan.pinned_address,
            port=expected_plan.port,
            family=expected_plan.family,
            authorized_addresses=expected_plan.authorized_addresses,
            host_header=expected_plan.host_header,
            tls_server_hostname=expected_plan.tls_server_hostname,
            ssl_context=expected_plan.ssl_context,
        )
        try:
            with anyio.fail_after(connect_seconds):
                stream = await self._connector.connect(connector_plan)
        except TimeoutError as error:
            raise PinnedDialError(
                DialErrorCode.CONNECT_TIMEOUT,
                DialPhase.CONNECTION,
                "pinned connection exceeded its physical timeout",
                retryable=True,
            ) from error
        except ssl.SSLError as error:
            raise PinnedDialError(
                DialErrorCode.TLS_FAILED,
                DialPhase.CONNECTION,
                "verified TLS connection failed",
                retryable=False,
            ) from error
        except PinnedDialError:
            raise
        except Exception as error:
            raise PinnedDialError(
                DialErrorCode.CONNECTION_FAILED,
                DialPhase.CONNECTION,
                "pinned connection failed",
                retryable=True,
            ) from error
        return await self._verify_peer_and_wrap(
            stream,
            connector_plan=connector_plan,
            expected_plan=expected_plan,
            close_timeout_seconds=close_seconds,
        )

    async def _verify_peer_and_wrap(
        self,
        stream: ConnectedByteStream,
        *,
        connector_plan: ConnectionPlan,
        expected_plan: ConnectionPlan,
        close_timeout_seconds: float,
    ) -> PinnedConnection:
        try:
            peer = _snapshot_peer(stream.peer_address)
        except Exception as error:
            await _close_failed_stream(
                stream,
                close_timeout_seconds=close_timeout_seconds,
            )
            raise PinnedDialError(
                DialErrorCode.PEER_INVALID,
                DialPhase.PEER_VERIFICATION,
                "connected transport returned invalid peer evidence",
                retryable=False,
            ) from error
        if (
            peer.address != expected_plan.pinned_address
            or peer.port != expected_plan.port
            or peer.family is not expected_plan.family
        ):
            await _close_failed_stream(
                stream,
                close_timeout_seconds=close_timeout_seconds,
            )
            raise PinnedDialError(
                DialErrorCode.PEER_MISMATCH,
                DialPhase.PEER_VERIFICATION,
                "connected peer did not match the authorized numeric pin",
                retryable=False,
            )
        try:
            verified_plan = ConnectionPlan(
                pinned_address=expected_plan.pinned_address,
                port=expected_plan.port,
                family=expected_plan.family,
                authorized_addresses=expected_plan.authorized_addresses,
                host_header=expected_plan.host_header,
                tls_server_hostname=expected_plan.tls_server_hostname,
                ssl_context=expected_plan.ssl_context,
            )
        except Exception as error:
            await _close_failed_stream(
                stream,
                close_timeout_seconds=close_timeout_seconds,
            )
            raise PinnedDialError(
                DialErrorCode.PEER_INVALID,
                DialPhase.PEER_VERIFICATION,
                "connection security plan changed during establishment",
                retryable=False,
            ) from error
        if connector_plan != verified_plan:
            await _close_failed_stream(
                stream,
                close_timeout_seconds=close_timeout_seconds,
            )
            raise PinnedDialError(
                DialErrorCode.PEER_MISMATCH,
                DialPhase.PEER_VERIFICATION,
                "connector changed the authorized connection plan",
                retryable=False,
            )
        evidence = PeerAddressEvidence(
            authorized_address=verified_plan.pinned_address,
            authorized_family=verified_plan.family,
            peer_address=peer.address,
            peer_family=peer.family,
        )
        return PinnedConnection(stream=stream, plan=verified_plan, evidence=evidence)


def _snapshot_peer(peer: object) -> PeerAddress:
    if type(peer) is not PeerAddress:
        message = "connector returned an unrecognized peer evidence type"
        raise TypeError(message)
    return PeerAddress(
        address=peer.address,
        port=peer.port,
        family=peer.family,
    )


async def _close_failed_stream(
    stream: ConnectedByteStream,
    *,
    close_timeout_seconds: float,
) -> None:
    with anyio.CancelScope(shield=True):
        with anyio.move_on_after(close_timeout_seconds):
            with suppress(Exception):
                await stream.aclose()


def _seconds(nanoseconds: int) -> float:
    if type(nanoseconds) is not int or not 1 <= nanoseconds <= MAX_TIMEOUT_NANOSECONDS:
        message = "dial timeout is outside positive signed-int64 nanoseconds"
        raise ValueError(message)
    seconds = nanoseconds / _NANOSECONDS_PER_SECOND
    if not math.isfinite(seconds) or seconds <= 0:
        message = "validated timeout became nonfinite"
        raise AssertionError(message)
    return seconds
