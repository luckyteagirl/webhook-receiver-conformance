"""One-time public-target receiver challenge over a pinned destination."""
# ruff: noqa: C901, D107, EM101, INP001, PLR0912, PLR0913, PLR0915, PLR2004, TRY003

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol

import anyio

from webhook_receiver_conformance.config.models import ReceiverConfig, TargetProfile
from webhook_receiver_conformance.network.dialer import (
    DialTimeouts,
    PeerAddressEvidence,
    PinnedDestinationDialer,
    PinnedDialError,
)
from webhook_receiver_conformance.network.policy import (
    DestinationPolicy,
    DestinationPolicyError,
    parse_destination_policy,
)

if TYPE_CHECKING:
    from webhook_receiver_conformance.network.transport import ConnectedByteStream

MAX_CHALLENGE_BYTES: Final = 128
MIN_CHALLENGE_BYTES: Final = 32
MAX_RESPONSE_BYTES: Final = 4096
MAX_HEADER_BYTES: Final = 2048
MAX_HEADERS: Final = 32
DEFAULT_CHALLENGE_TIMEOUT_NS: Final = 5_000_000_000
_NANOSECONDS_PER_SECOND = 1_000_000_000
_NONCE = re.compile(rb"[A-Za-z0-9_-]+")
_STATUS = re.compile(rb"HTTP/1\.1 ([1-5][0-9]{2})(?: [\x20-\x7e\t]*)?")
_CONTENT_LENGTH = re.compile(rb"(?:0|[1-9][0-9]*)")
_HEADER_NAME = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_HEADER_VALUE = re.compile(rb"[\x09\x20-\x7e]*")


class NonceSource(Protocol):
    """Injectable source for one fresh, bounded challenge."""

    def __call__(self) -> bytes:
        """Return an opaque URL/header-safe nonce."""
        ...


class PreflightErrorCode(StrEnum):
    """Stable, target- and secret-free public-preflight classifications."""

    POLICY_REJECTED = "policy-rejected"
    RESOLUTION_FAILED = "resolution-failed"
    CONNECTION_FAILED = "connection-failed"
    WRITE_TIMEOUT = "write-timeout"
    WRITE_FAILED = "write-failed"
    READ_TIMEOUT = "read-timeout"
    READ_FAILED = "read-failed"
    RESPONSE_TOO_LARGE = "response-too-large"
    RESPONSE_MALFORMED = "response-malformed"
    REDIRECT_REJECTED = "redirect-rejected"
    STATUS_REJECTED = "status-rejected"
    CHALLENGE_MISSING = "challenge-missing"
    CHALLENGE_MISMATCH = "challenge-mismatch"
    CHALLENGE_INVALID = "challenge-invalid"


class PreflightPhase(StrEnum):
    """Bounded phases proving whether network contact was possible."""

    POLICY = "policy"
    RESOLUTION = "resolution"
    CONNECTION = "connection"
    WRITE = "write"
    READ = "read"
    VALIDATION = "validation"


class PublicTargetPreflightError(RuntimeError):
    """Classified failure that never retains nonce, target, or response bytes."""

    code: PreflightErrorCode
    phase: PreflightPhase
    retryable: bool
    network_contacted: bool
    fixture_bytes_sent: bool = False

    def __init__(
        self,
        code: PreflightErrorCode,
        phase: PreflightPhase,
        message: str,
        *,
        retryable: bool,
        network_contacted: bool,
    ) -> None:
        self.code = code
        self.phase = phase
        self.retryable = retryable
        self.network_contacted = network_contacted
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class PublicTargetPreflightEvidence:
    """Bounded facts from a successful challenge; nonce bytes are not retained."""

    authority: str
    challenge_path: str
    challenge_sha256: str
    request_bytes: int
    response_bytes: int
    status_code: int
    peer: PeerAddressEvidence
    redirects_followed: int = 0
    proxy_environment_used: bool = False
    fixture_bytes_sent: bool = False


def generate_challenge() -> bytes:
    """Generate 256 bits of entropy in a request-header-safe encoding."""
    return secrets.token_urlsafe(32).encode("ascii")


async def preflight_public_target(
    receiver: ReceiverConfig,
    *,
    runtime_public_authorization: str | None,
    dialer: PinnedDestinationDialer,
    dial_timeouts: DialTimeouts,
    challenge_timeout_ns: int = DEFAULT_CHALLENGE_TIMEOUT_NS,
    nonce_source: NonceSource = generate_challenge,
) -> PublicTargetPreflightEvidence | None:
    """Authorize and challenge a public receiver before fixture construction/delivery.

    Non-public profiles require no receiver challenge and return ``None``. Public
    configuration and runtime gates are evaluated synchronously before the dialer
    is allowed to resolve or connect.
    """
    try:
        policy = parse_destination_policy(
            receiver,
            runtime_public_authorization=runtime_public_authorization,
        )
    except DestinationPolicyError as error:
        raise PublicTargetPreflightError(
            PreflightErrorCode.POLICY_REJECTED,
            PreflightPhase.POLICY,
            "public target authorization policy rejected the destination",
            retryable=False,
            network_contacted=False,
        ) from error

    if policy.target_profile is not TargetProfile.PUBLIC_AUTHORIZED:
        return None
    if type(challenge_timeout_ns) is not int or not 1 <= challenge_timeout_ns <= (2**63) - 1:
        raise ValueError("challenge timeout must be a positive signed-int64 nanosecond value")
    try:
        challenge = nonce_source()
    except Exception as error:
        raise PublicTargetPreflightError(
            PreflightErrorCode.CHALLENGE_INVALID,
            PreflightPhase.POLICY,
            "challenge generation failed",
            retryable=False,
            network_contacted=False,
        ) from error
    _validate_challenge(challenge)

    try:
        authorized = await dialer.resolve_and_authorize(policy, timeouts=dial_timeouts)
    except DestinationPolicyError as error:
        raise PublicTargetPreflightError(
            PreflightErrorCode.POLICY_REJECTED,
            PreflightPhase.RESOLUTION,
            "resolved destination address policy rejected the destination",
            retryable=False,
            network_contacted=False,
        ) from error
    except PinnedDialError as error:
        raise PublicTargetPreflightError(
            PreflightErrorCode.RESOLUTION_FAILED,
            PreflightPhase.RESOLUTION,
            "public target resolution failed",
            retryable=error.retryable,
            network_contacted=False,
        ) from error

    try:
        connection = await dialer.connect_authorized(authorized, timeouts=dial_timeouts)
    except (PinnedDialError, DestinationPolicyError) as error:
        retryable = isinstance(error, PinnedDialError) and error.retryable
        raise PublicTargetPreflightError(
            PreflightErrorCode.CONNECTION_FAILED,
            PreflightPhase.CONNECTION,
            "pinned public target connection failed",
            retryable=retryable,
            network_contacted=True,
        ) from error

    request = _challenge_request(policy, challenge)
    try:
        try:
            with anyio.fail_after(challenge_timeout_ns / _NANOSECONDS_PER_SECOND):
                await connection.stream.send(request)
        except TimeoutError as error:
            raise PublicTargetPreflightError(
                PreflightErrorCode.WRITE_TIMEOUT,
                PreflightPhase.WRITE,
                "public target challenge write exceeded its physical timeout",
                retryable=True,
                network_contacted=True,
            ) from error
        except PublicTargetPreflightError:
            raise
        except Exception as error:
            raise PublicTargetPreflightError(
                PreflightErrorCode.WRITE_FAILED,
                PreflightPhase.WRITE,
                "public target challenge request failed",
                retryable=True,
                network_contacted=True,
            ) from error
        try:
            with anyio.fail_after(challenge_timeout_ns / _NANOSECONDS_PER_SECOND):
                response = await _read_response(connection.stream)
        except TimeoutError as error:
            raise PublicTargetPreflightError(
                PreflightErrorCode.READ_TIMEOUT,
                PreflightPhase.READ,
                "public target challenge read exceeded its physical timeout",
                retryable=True,
                network_contacted=True,
            ) from error
        except PublicTargetPreflightError:
            raise
        except Exception as error:
            raise PublicTargetPreflightError(
                PreflightErrorCode.READ_FAILED,
                PreflightPhase.READ,
                "public target challenge response failed",
                retryable=True,
                network_contacted=True,
            ) from error
    finally:
        with anyio.move_on_after(
            dial_timeouts.close_nanoseconds / _NANOSECONDS_PER_SECOND,
            shield=True,
        ):
            await connection.aclose()

    status, body = _parse_response(response)
    if 300 <= status <= 399:
        raise PublicTargetPreflightError(
            PreflightErrorCode.REDIRECT_REJECTED,
            PreflightPhase.VALIDATION,
            "public target challenge redirects are forbidden",
            retryable=False,
            network_contacted=True,
        )
    if status != 200:
        raise PublicTargetPreflightError(
            PreflightErrorCode.STATUS_REJECTED,
            PreflightPhase.VALIDATION,
            "public target challenge returned a non-success status",
            retryable=False,
            network_contacted=True,
        )
    if not body:
        raise PublicTargetPreflightError(
            PreflightErrorCode.CHALLENGE_MISSING,
            PreflightPhase.VALIDATION,
            "public target challenge response was missing",
            retryable=False,
            network_contacted=True,
        )
    if not secrets.compare_digest(body, challenge):
        raise PublicTargetPreflightError(
            PreflightErrorCode.CHALLENGE_MISMATCH,
            PreflightPhase.VALIDATION,
            "public target challenge response did not match",
            retryable=False,
            network_contacted=True,
        )
    return PublicTargetPreflightEvidence(
        authority=policy.destination.authority,
        challenge_path=policy.public_challenge_path,
        challenge_sha256=hashlib.sha256(challenge).hexdigest(),
        request_bytes=len(request),
        response_bytes=len(response),
        status_code=status,
        peer=connection.evidence,
    )


def _validate_challenge(challenge: bytes) -> None:
    if (
        type(challenge) is not bytes
        or not MIN_CHALLENGE_BYTES <= len(challenge) <= MAX_CHALLENGE_BYTES
        or _NONCE.fullmatch(challenge) is None
    ):
        raise PublicTargetPreflightError(
            PreflightErrorCode.CHALLENGE_INVALID,
            PreflightPhase.POLICY,
            "generated challenge is not a bounded safe nonce",
            retryable=False,
            network_contacted=False,
        )


def _challenge_request(policy: DestinationPolicy, challenge: bytes) -> bytes:
    destination = policy.destination
    path = policy.public_challenge_path
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {destination.authority}\r\n"
        "User-Agent: webhook-receiver-conformance/0.1\r\n"
        "Accept: text/plain\r\n"
        f"X-Webhook-Conformance-Challenge: {challenge.decode('ascii')}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


async def _read_response(stream: ConnectedByteStream) -> bytes:
    response = bytearray()
    while True:
        remaining = MAX_RESPONSE_BYTES + 1 - len(response)
        if remaining <= 0:
            raise _response_too_large()
        chunk = await stream.receive(min(remaining, 65_536))
        if type(chunk) is not bytes:
            raise PublicTargetPreflightError(
                PreflightErrorCode.RESPONSE_MALFORMED,
                PreflightPhase.READ,
                "public target challenge returned invalid response bytes",
                retryable=False,
                network_contacted=True,
            )
        if not chunk:
            break
        response.extend(chunk)
        if len(response) > MAX_RESPONSE_BYTES:
            raise _response_too_large()
        expected_length = _expected_response_length(response)
        if expected_length is not None:
            if len(response) > expected_length:
                raise _malformed()
            if len(response) == expected_length:
                return bytes(response)
    return bytes(response)


def _parse_response(response: bytes) -> tuple[int, bytes]:
    head, separator, body = response.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not separator or not lines or len(lines) > MAX_HEADERS + 1 or len(head) > MAX_HEADER_BYTES:
        raise _malformed()
    status_match = _STATUS.fullmatch(lines[0])
    if status_match is None:
        raise _malformed()
    content_length: int | None = None
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if (
            not colon
            or _HEADER_NAME.fullmatch(name) is None
            or _HEADER_VALUE.fullmatch(value) is None
        ):
            raise _malformed()
        normalized_name = name.lower()
        stripped = value.strip(b" \t")
        if normalized_name == b"transfer-encoding":
            raise _malformed()
        if normalized_name == b"content-length":
            if content_length is not None or _CONTENT_LENGTH.fullmatch(stripped) is None:
                raise _malformed()
            content_length = int(stripped)
    if content_length is None or content_length != len(body):
        raise _malformed()
    return int(status_match.group(1)), body


def _expected_response_length(response: bytearray) -> int | None:
    header_end = response.find(b"\r\n\r\n")
    if header_end < 0:
        if len(response) > MAX_HEADER_BYTES:
            raise _malformed()
        return None
    head_end = header_end + 4
    head = bytes(response[:header_end])
    lines = head.split(b"\r\n")
    if not lines or len(lines) > MAX_HEADERS + 1 or len(head) > MAX_HEADER_BYTES:
        raise _malformed()
    if _STATUS.fullmatch(lines[0]) is None:
        raise _malformed()
    content_length: int | None = None
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if (
            not colon
            or _HEADER_NAME.fullmatch(name) is None
            or _HEADER_VALUE.fullmatch(value) is None
        ):
            raise _malformed()
        normalized_name = name.lower()
        stripped = value.strip(b" \t")
        if normalized_name == b"transfer-encoding":
            raise _malformed()
        if normalized_name == b"content-length":
            if content_length is not None or _CONTENT_LENGTH.fullmatch(stripped) is None:
                raise _malformed()
            content_length = int(stripped)
    if content_length is None:
        raise _malformed()
    expected = head_end + content_length
    if expected > MAX_RESPONSE_BYTES:
        raise _response_too_large()
    return expected


def _malformed() -> PublicTargetPreflightError:
    return PublicTargetPreflightError(
        PreflightErrorCode.RESPONSE_MALFORMED,
        PreflightPhase.VALIDATION,
        "public target challenge response was malformed",
        retryable=False,
        network_contacted=True,
    )


def _response_too_large() -> PublicTargetPreflightError:
    return PublicTargetPreflightError(
        PreflightErrorCode.RESPONSE_TOO_LARGE,
        PreflightPhase.READ,
        "public target challenge response exceeded its bounded limit",
        retryable=False,
        network_contacted=True,
    )
