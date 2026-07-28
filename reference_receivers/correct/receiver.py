"""Correct SQLite-backed webhook reference receiver and read-only observer."""
# ruff: noqa: C901, D105, D107, EM101, EM102, PLR0911, PLR2004, S608, TRY003

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol, cast

MAX_REQUEST_BYTES: Final = 16 * 1024 * 1024
MAX_HEADER_COUNT: Final = 128
MAX_HEADER_NAME: Final = 256
MAX_HEADER_VALUE: Final = 8_192
MAX_IDENTIFIER: Final = 256
MAX_OBSERVER_ITEMS: Final = 1_000
DEFAULT_REPLAY_WINDOW_SECONDS: Final = 300
_LOWER_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_CANONICAL_SECONDS = re.compile(r"(?:0|[1-9][0-9]{0,18})")
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_STANDARD_SIGNATURE = re.compile(r"v1,([A-Za-z0-9+/]{43}=)")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class SignatureProfile(StrEnum):
    """Supported reference signature profiles."""

    GENERIC_HMAC_SHA256 = "generic-hmac-sha256"
    STRIPE_V1 = "stripe-v1"
    STANDARD_WEBHOOKS_HMAC = "standard-webhooks-hmac"


class ReferenceOutcome(StrEnum):
    """Stable transport outcomes exposed by the reference receiver."""

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"
    CONFLICT = "conflict"
    UNAVAILABLE = "unavailable"


class InboxState(StrEnum):
    """Reference inbox processing states."""

    PENDING_DEPENDENCY = "pending_dependency"
    PROCESSED = "processed"


class ObserverEvidenceName(StrEnum):
    """Closed normalized observer evidence inventory."""

    PROCESSING_COUNT = "processing_count"
    EFFECT_COUNT = "effect_count"
    OUTBOX_COUNT = "outbox_count"
    INBOX_STATE = "inbox_state"
    ORDER_STATE = "order_state"


class ReferenceClock(Protocol):
    """Wall-clock boundary used only for replay and key windows."""

    def now_seconds(self) -> int:
        """Return current Unix seconds."""
        ...


@dataclass(slots=True)
class MutableReferenceClock:
    """Explicit test clock for replay and rotation cases."""

    value: int

    def now_seconds(self) -> int:
        """Return the controlled Unix second."""
        return self.value


@dataclass(frozen=True, slots=True)
class SystemReferenceClock:
    """Production wall-clock adapter."""

    def now_seconds(self) -> int:
        """Return current Unix seconds."""
        return int(time.time())


@dataclass(frozen=True, slots=True)
class ReferenceSigningKey:
    """One bounded HMAC key with an explicit active interval."""

    key_id: str
    secret: bytes = field(repr=False)
    active_from: int = 0
    active_until: int | None = None

    def __post_init__(self) -> None:
        _identifier(self.key_id, name="key_id")
        if type(self.secret) is not bytes or not 16 <= len(self.secret) <= 4_096:
            raise ValueError("reference signing secret must contain 16 through 4096 bytes")
        if type(self.active_from) is not int or self.active_from < 0:
            raise ValueError("active_from must be a nonnegative Unix second")
        if self.active_until is not None and (
            type(self.active_until) is not int or self.active_until < self.active_from
        ):
            raise ValueError("active_until must be no earlier than active_from")

    def active_at(self, timestamp: int) -> bool:
        """Return whether this key is accepted at the receiver's current time."""
        return self.active_from <= timestamp and (
            self.active_until is None or timestamp <= self.active_until
        )


@dataclass(frozen=True, slots=True)
class ReferenceSignatureConfiguration:
    """One profile's replay and active-key verification policy."""

    profile: SignatureProfile
    keys: tuple[ReferenceSigningKey, ...]
    replay_window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS

    def __post_init__(self) -> None:
        if type(self.profile) is not SignatureProfile:
            raise TypeError("profile must be a SignatureProfile")
        if (
            type(self.keys) is not tuple
            or not self.keys
            or len(self.keys) > 8
            or any(type(value) is not ReferenceSigningKey for value in self.keys)
        ):
            raise ValueError("keys must contain one through eight reference keys")
        if len({value.key_id for value in self.keys}) != len(self.keys):
            raise ValueError("reference key IDs must be unique")
        if (
            type(self.replay_window_seconds) is not int
            or not 1 <= self.replay_window_seconds <= 86_400
        ):
            raise ValueError("replay window must be one through 86400 seconds")


@dataclass(frozen=True, slots=True)
class ReferenceRequest:
    """Exact inbound bytes plus duplicate-preserving HTTP headers."""

    profile: SignatureProfile
    account_id: str
    body: bytes
    headers: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if type(self.profile) is not SignatureProfile:
            raise TypeError("profile must be a SignatureProfile")
        _identifier(self.account_id, name="account_id")
        if type(self.body) is not bytes or len(self.body) > MAX_REQUEST_BYTES:
            raise ValueError("request body exceeds the reference receiver limit")
        if (
            type(self.headers) is not tuple
            or len(self.headers) > MAX_HEADER_COUNT
            or any(
                type(value) is not tuple
                or len(value) != 2
                or type(value[0]) is not str
                or type(value[1]) is not str
                for value in self.headers
            )
        ):
            raise TypeError("headers must be a bounded tuple of name/value pairs")
        for name, value in self.headers:
            if (
                not name
                or len(name) > MAX_HEADER_NAME
                or len(value) > MAX_HEADER_VALUE
                or _CONTROL.search(name) is not None
                or _CONTROL.search(value) is not None
            ):
                raise ValueError("request header is malformed or unbounded")


@dataclass(frozen=True, slots=True)
class ReferenceResponse:
    """Secret-free receiver result returned only after the transaction boundary."""

    status_code: int
    outcome: ReferenceOutcome
    event_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be an HTTP status")
        if type(self.outcome) is not ReferenceOutcome:
            raise TypeError("outcome must be a ReferenceOutcome")
        if self.event_id is not None:
            _identifier(self.event_id, name="event_id")


@dataclass(frozen=True, slots=True)
class ReferenceProbeRequest:
    """Explicitly minimized observer request."""

    token: str = field(repr=False)
    capabilities: tuple[str, ...]
    evidence_names: tuple[ObserverEvidenceName, ...]
    event_ids: tuple[str, ...] = ()
    order_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.token) is not str
            or not self.token
            or len(self.token) > 4_096
            or _CONTROL.search(self.token) is not None
        ):
            raise ValueError("observer token must be bounded safe text")
        if (
            type(self.capabilities) is not tuple
            or len(self.capabilities) > len(ObserverEvidenceName)
            or any(type(value) is not str for value in self.capabilities)
            or len(set(self.capabilities)) != len(self.capabilities)
        ):
            raise ValueError("capabilities must be a bounded unique tuple")
        if (
            type(self.evidence_names) is not tuple
            or len(self.evidence_names) > len(ObserverEvidenceName)
            or any(type(value) is not ObserverEvidenceName for value in self.evidence_names)
            or len(set(self.evidence_names)) != len(self.evidence_names)
        ):
            raise ValueError("evidence_names must be a bounded unique tuple")
        _identifier_tuple(self.event_ids, name="event_ids")
        _identifier_tuple(self.order_ids, name="order_ids")


@dataclass(frozen=True, slots=True)
class ReferenceProbeResponse:
    """One consistent read-only normalized application snapshot."""

    snapshot_id: str
    capabilities: tuple[str, ...]
    evidence: dict[str, object]

    def __post_init__(self) -> None:
        if (
            type(self.snapshot_id) is not str
            or not self.snapshot_id.startswith("snapshot_")
            or len(self.snapshot_id) != 73
        ):
            raise ValueError("snapshot_id must be a content-derived identifier")
        if type(self.capabilities) is not tuple or any(
            type(value) is not str for value in self.capabilities
        ):
            raise TypeError("capabilities must be a string tuple")
        if type(self.evidence) is not dict:
            raise TypeError("evidence must be a dictionary")


class ReferenceReceiverError(RuntimeError):
    """Safe receiver configuration or observer error."""


class ReferenceAuthenticationError(ReferenceReceiverError):
    """The independent observer token did not match."""


class ReferenceCapabilityError(ReferenceReceiverError):
    """The observer request named an unsupported capability."""


@dataclass(frozen=True, slots=True)
class _VerifiedSignature:
    timestamp: int
    authenticated_event_id: str | None


@dataclass(frozen=True, slots=True)
class _ParsedEvent:
    event_id: str
    event_type: str
    order_id: str


class CorrectReferenceReceiver:
    """REF-CORRECT-001: exact verification and atomic durable processing."""

    __slots__ = (
        "_clock",
        "_configurations",
        "_database_path",
        "_observer_token",
    )

    def __init__(
        self,
        *,
        database_path: str | os.PathLike[str],
        signature_configurations: tuple[
            ReferenceSignatureConfiguration,
            ...,
        ],
        observer_token: str,
        clock: ReferenceClock | None = None,
    ) -> None:
        if (
            type(signature_configurations) is not tuple
            or not signature_configurations
            or any(
                type(value) is not ReferenceSignatureConfiguration
                for value in signature_configurations
            )
        ):
            raise ValueError("signature_configurations must contain reference configurations")
        profiles = tuple(value.profile for value in signature_configurations)
        if len(set(profiles)) != len(profiles):
            raise ValueError("signature profiles must be unique")
        if (
            type(observer_token) is not str
            or not 16 <= len(observer_token) <= 4_096
            or _CONTROL.search(observer_token) is not None
        ):
            raise ValueError("observer_token must contain 16 through 4096 safe characters")
        if clock is not None and not hasattr(clock, "now_seconds"):
            raise TypeError("clock must implement now_seconds")
        path = _validated_database_path(database_path)
        self._database_path = path
        self._configurations = {value.profile: value for value in signature_configurations}
        self._observer_token = observer_token
        self._clock = SystemReferenceClock() if clock is None else clock
        self._initialize_database()

    @property
    def database_path(self) -> Path:
        """Return the confined local reference database path."""
        return self._database_path

    @property
    def supported_capabilities(self) -> tuple[str, ...]:
        """Return the closed read-only observer capability inventory."""
        return tuple(value.value for value in ObserverEvidenceName)

    def handle(self, request: ReferenceRequest) -> ReferenceResponse:
        """Verify raw bytes, commit all durable state atomically, then acknowledge."""
        if type(request) is not ReferenceRequest:
            raise TypeError("request must be a ReferenceRequest")
        configuration = self._configurations.get(request.profile)
        if configuration is None:
            return ReferenceResponse(400, ReferenceOutcome.REJECTED)
        now = self._clock.now_seconds()
        verified = _verify_request_signature(
            request,
            configuration=configuration,
            now=now,
        )
        if verified is None:
            return ReferenceResponse(400, ReferenceOutcome.REJECTED)
        parsed = _parse_event(request.body)
        if parsed is None or (
            verified.authenticated_event_id is not None
            and not hmac.compare_digest(
                verified.authenticated_event_id.encode(),
                parsed.event_id.encode(),
            )
        ):
            return ReferenceResponse(400, ReferenceOutcome.REJECTED)
        payload_digest = f"sha256:{hashlib.sha256(request.body).hexdigest()}"
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                """
                SELECT event_type, order_id, payload_sha256, state
                FROM webhook_inbox
                WHERE provider_profile = ? AND account_id = ? AND event_id = ?
                """,
                (request.profile.value, request.account_id, parsed.event_id),
            ).fetchone()
            if prior is not None:
                compatible = prior[:3] == (
                    parsed.event_type,
                    parsed.order_id,
                    payload_digest,
                )
                connection.commit()
                return ReferenceResponse(
                    204 if compatible else 409,
                    (ReferenceOutcome.DUPLICATE if compatible else ReferenceOutcome.CONFLICT),
                    parsed.event_id,
                )
            state = (
                InboxState.PENDING_DEPENDENCY
                if parsed.event_type == "payment.refunded"
                and not _order_is_paid(connection, parsed.order_id)
                else InboxState.PROCESSED
            )
            connection.execute(
                """
                INSERT INTO webhook_inbox (
                    provider_profile, account_id, event_id, event_type,
                    order_id, payload_sha256, state, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.profile.value,
                    request.account_id,
                    parsed.event_id,
                    parsed.event_type,
                    parsed.order_id,
                    payload_digest,
                    state.value,
                    now,
                ),
            )
            self._after_inbox_insert(connection, request, parsed)
            if state is InboxState.PROCESSED:
                _apply_event(connection, request, parsed, processed_at=now)
                if parsed.event_type == "payment.succeeded":
                    _resolve_pending_refunds(
                        connection,
                        profile=request.profile,
                        account_id=request.account_id,
                        order_id=parsed.order_id,
                        processed_at=now,
                    )
            self._before_commit(connection, request, parsed)
            connection.commit()
            self._after_commit(request, parsed)
            return ReferenceResponse(
                204,
                ReferenceOutcome.ACCEPTED,
                parsed.event_id,
            )
        except sqlite3.Error:
            if connection.in_transaction:
                connection.rollback()
            return ReferenceResponse(503, ReferenceOutcome.UNAVAILABLE)
        finally:
            connection.close()

    def probe(self, request: ReferenceProbeRequest) -> ReferenceProbeResponse:
        """Return only explicitly requested normalized evidence from one read view."""
        if type(request) is not ReferenceProbeRequest:
            raise TypeError("request must be a ReferenceProbeRequest")
        supplied = request.token.encode()
        expected = self._observer_token.encode()
        if not hmac.compare_digest(supplied, expected):
            raise ReferenceAuthenticationError("observer authentication failed")
        supported = set(self.supported_capabilities)
        if any(value not in supported for value in request.capabilities):
            raise ReferenceCapabilityError("observer capability is unsupported")
        if any(value.value not in request.capabilities for value in request.evidence_names):
            raise ReferenceCapabilityError(
                "evidence names must be covered by requested capabilities"
            )
        connection = self._connect(query_only=True)
        try:
            connection.execute("BEGIN")
            evidence = _observe_evidence(connection, request)
            connection.commit()
        finally:
            connection.close()
        normalized = {
            "capabilities": list(request.capabilities),
            "evidence": evidence,
        }
        canonical = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        return ReferenceProbeResponse(
            snapshot_id=f"snapshot_{hashlib.sha256(canonical).hexdigest()}",
            capabilities=request.capabilities,
            evidence=evidence,
        )

    def _initialize_database(self) -> None:
        connection = sqlite3.connect(
            self._database_path,
            timeout=5.0,
            isolation_level=None,
        )
        try:
            _connection_policy(connection)
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS webhook_inbox (
                    provider_profile TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    order_id TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL
                        CHECK (state IN ('pending_dependency', 'processed')),
                    received_at INTEGER NOT NULL,
                    PRIMARY KEY (provider_profile, account_id, event_id)
                );

                CREATE TABLE IF NOT EXISTS orders (
                    order_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL CHECK (state IN ('paid', 'refunded')),
                    version INTEGER NOT NULL CHECK (version >= 1)
                );

                CREATE TABLE IF NOT EXISTS payment_effects (
                    provider_profile TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    order_id TEXT NOT NULL,
                    effect_type TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (provider_profile, account_id, event_id),
                    FOREIGN KEY (provider_profile, account_id, event_id)
                        REFERENCES webhook_inbox (
                            provider_profile, account_id, event_id
                        )
                );

                CREATE TABLE IF NOT EXISTS outbox (
                    provider_profile TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (provider_profile, account_id, event_id),
                    FOREIGN KEY (provider_profile, account_id, event_id)
                        REFERENCES webhook_inbox (
                            provider_profile, account_id, event_id
                        )
                );
                """
            )
        finally:
            connection.close()
        try:
            self._database_path.chmod(0o600)
        except OSError as error:
            raise ReferenceReceiverError(
                "reference database permissions could not be tightened"
            ) from error

    def _connect(self, *, query_only: bool = False) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            timeout=5.0,
            isolation_level=None,
        )
        _connection_policy(connection)
        if query_only:
            connection.execute("PRAGMA query_only = ON")
        return connection

    def _after_inbox_insert(
        self,
        connection: sqlite3.Connection,
        request: ReferenceRequest,
        event: _ParsedEvent,
    ) -> None:
        """Subclass fault boundary after the inbox insert, inside the transaction."""

    def _before_commit(
        self,
        connection: sqlite3.Connection,
        request: ReferenceRequest,
        event: _ParsedEvent,
    ) -> None:
        """Subclass fault boundary before the atomic commit."""

    def _after_commit(
        self,
        request: ReferenceRequest,
        event: _ParsedEvent,
    ) -> None:
        """Subclass fault boundary after durability but before acknowledgement."""


def sign_reference_request(
    *,
    profile: SignatureProfile,
    key: ReferenceSigningKey,
    body: bytes,
    event_id: str,
    timestamp: int,
) -> tuple[tuple[str, str], ...]:
    """Create deterministic exact-byte headers for reference corpus fixtures."""
    if type(profile) is not SignatureProfile:
        raise TypeError("profile must be a SignatureProfile")
    if type(key) is not ReferenceSigningKey:
        raise TypeError("key must be a ReferenceSigningKey")
    if type(body) is not bytes or len(body) > MAX_REQUEST_BYTES:
        raise ValueError("body must be bounded bytes")
    _identifier(event_id, name="event_id")
    if type(timestamp) is not int or timestamp < 0:
        raise ValueError("timestamp must be a nonnegative Unix second")
    if profile is SignatureProfile.GENERIC_HMAC_SHA256:
        canonical = _generic_canonical(timestamp, event_id, body)
        signature = hmac.digest(key.secret, canonical, "sha256").hex()
        return (
            ("content-type", "application/json"),
            ("x-webhook-id", event_id),
            ("x-webhook-timestamp", str(timestamp)),
            ("x-webhook-key-id", key.key_id),
            ("x-webhook-signature", signature),
        )
    if profile is SignatureProfile.STRIPE_V1:
        canonical = _stripe_canonical(timestamp, body)
        signature = hmac.digest(key.secret, canonical, "sha256").hex()
        return (
            ("content-type", "application/json"),
            ("stripe-signature", f"t={timestamp},v1={signature}"),
        )
    canonical = _standard_canonical(event_id, timestamp, body)
    signature = base64.b64encode(hmac.digest(key.secret, canonical, "sha256")).decode("ascii")
    return (
        ("content-type", "application/json"),
        ("webhook-id", event_id),
        ("webhook-timestamp", str(timestamp)),
        ("webhook-signature", f"v1,{signature}"),
    )


def _verify_request_signature(
    request: ReferenceRequest,
    *,
    configuration: ReferenceSignatureConfiguration,
    now: int,
) -> _VerifiedSignature | None:
    if type(now) is not int or now < 0 or request.profile is not configuration.profile:
        return None
    if request.profile is SignatureProfile.GENERIC_HMAC_SHA256:
        return _verify_generic(request, configuration=configuration, now=now)
    if request.profile is SignatureProfile.STRIPE_V1:
        return _verify_stripe(request, configuration=configuration, now=now)
    return _verify_standard(request, configuration=configuration, now=now)


def _verify_generic(
    request: ReferenceRequest,
    *,
    configuration: ReferenceSignatureConfiguration,
    now: int,
) -> _VerifiedSignature | None:
    event_id = _one_header(request.headers, "x-webhook-id")
    timestamp_text = _one_header(request.headers, "x-webhook-timestamp")
    key_id = _one_header(request.headers, "x-webhook-key-id")
    signature_text = _one_header(request.headers, "x-webhook-signature")
    timestamp = _timestamp(timestamp_text)
    supplied = _hex_digest(signature_text)
    if (
        event_id is None
        or key_id is None
        or timestamp is None
        or supplied is None
        or not _fresh(timestamp, now, configuration.replay_window_seconds)
    ):
        return None
    candidates = tuple(
        key for key in configuration.keys if key.key_id == key_id and key.active_at(now)
    )
    if not candidates:
        return None
    canonical = _generic_canonical(timestamp, event_id, request.body)
    return (
        _VerifiedSignature(timestamp, event_id)
        if _matches_any(canonical, supplied=(supplied,), keys=candidates)
        else None
    )


def _verify_stripe(
    request: ReferenceRequest,
    *,
    configuration: ReferenceSignatureConfiguration,
    now: int,
) -> _VerifiedSignature | None:
    header = _one_header(request.headers, "stripe-signature")
    parsed = _parse_stripe_header(header)
    if parsed is None:
        return None
    timestamp, supplied = parsed
    if not _fresh(timestamp, now, configuration.replay_window_seconds):
        return None
    keys = tuple(key for key in configuration.keys if key.active_at(now))
    if not keys:
        return None
    canonical = _stripe_canonical(timestamp, request.body)
    return (
        _VerifiedSignature(timestamp, None)
        if _matches_any(canonical, supplied=supplied, keys=keys)
        else None
    )


def _verify_standard(
    request: ReferenceRequest,
    *,
    configuration: ReferenceSignatureConfiguration,
    now: int,
) -> _VerifiedSignature | None:
    event_id = _one_header(request.headers, "webhook-id")
    timestamp_text = _one_header(request.headers, "webhook-timestamp")
    signature_text = _one_header(request.headers, "webhook-signature")
    timestamp = _timestamp(timestamp_text)
    supplied = _parse_standard_signatures(signature_text)
    if (
        event_id is None
        or timestamp is None
        or supplied is None
        or not _fresh(timestamp, now, configuration.replay_window_seconds)
    ):
        return None
    keys = tuple(key for key in configuration.keys if key.active_at(now))
    if not keys:
        return None
    canonical = _standard_canonical(event_id, timestamp, request.body)
    return (
        _VerifiedSignature(timestamp, event_id)
        if _matches_any(canonical, supplied=supplied, keys=keys)
        else None
    )


def _matches_any(
    canonical: bytes,
    *,
    supplied: tuple[bytes, ...],
    keys: tuple[ReferenceSigningKey, ...],
) -> bool:
    matched = False
    for key in keys:
        expected = hmac.digest(key.secret, canonical, "sha256")
        for value in supplied:
            comparison = hmac.compare_digest(expected, value)
            matched = comparison or matched
    return matched


def _parse_event(body: bytes) -> _ParsedEvent | None:
    try:
        value: object = json.loads(
            body,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_json_number,
        )
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    event = cast("dict[str, object]", value)
    event_id = event.get("id")
    event_type = event.get("type")
    data = event.get("data")
    if (
        type(event_id) is not str
        or _SAFE_IDENTIFIER.fullmatch(event_id) is None
        or event_type not in {"payment.succeeded", "payment.refunded"}
        or not isinstance(data, dict)
    ):
        return None
    normalized_data = cast("dict[str, object]", data)
    order_id = normalized_data.get("order_id")
    if type(order_id) is not str or _SAFE_IDENTIFIER.fullmatch(order_id) is None:
        return None
    return _ParsedEvent(event_id, cast("str", event_type), order_id)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _apply_event(
    connection: sqlite3.Connection,
    request: ReferenceRequest,
    event: _ParsedEvent,
    *,
    processed_at: int,
) -> None:
    if event.event_type == "payment.succeeded":
        row = connection.execute(
            "SELECT state, version FROM orders WHERE order_id = ?",
            (event.order_id,),
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO orders (order_id, state, version) VALUES (?, 'paid', 1)",
                (event.order_id,),
            )
        elif row[0] != "refunded":
            connection.execute(
                """
                UPDATE orders
                SET state = 'paid', version = version + 1
                WHERE order_id = ?
                """,
                (event.order_id,),
            )
    else:
        connection.execute(
            """
            UPDATE orders
            SET state = 'refunded', version = version + 1
            WHERE order_id = ? AND state = 'paid'
            """,
            (event.order_id,),
        )
    connection.execute(
        """
        INSERT INTO payment_effects (
            provider_profile, account_id, event_id,
            order_id, effect_type, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            request.profile.value,
            request.account_id,
            event.event_id,
            event.order_id,
            event.event_type,
            processed_at,
        ),
    )
    connection.execute(
        """
        INSERT INTO outbox (
            provider_profile, account_id, event_id, topic, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            request.profile.value,
            request.account_id,
            event.event_id,
            f"order.{event.event_type.removeprefix('payment.')}",
            processed_at,
        ),
    )


def _resolve_pending_refunds(
    connection: sqlite3.Connection,
    *,
    profile: SignatureProfile,
    account_id: str,
    order_id: str,
    processed_at: int,
) -> None:
    rows = connection.execute(
        """
        SELECT event_id
        FROM webhook_inbox
        WHERE provider_profile = ?
          AND account_id = ?
          AND order_id = ?
          AND event_type = 'payment.refunded'
          AND state = 'pending_dependency'
        ORDER BY event_id
        """,
        (profile.value, account_id, order_id),
    ).fetchall()
    for row in rows:
        event_id = cast("str", row[0])
        request = ReferenceRequest(
            profile=profile,
            account_id=account_id,
            body=b"",
            headers=(),
        )
        event = _ParsedEvent(event_id, "payment.refunded", order_id)
        _apply_event(connection, request, event, processed_at=processed_at)
        connection.execute(
            """
            UPDATE webhook_inbox
            SET state = 'processed'
            WHERE provider_profile = ? AND account_id = ? AND event_id = ?
            """,
            (profile.value, account_id, event_id),
        )


def _order_is_paid(connection: sqlite3.Connection, order_id: str) -> bool:
    row = connection.execute(
        "SELECT state FROM orders WHERE order_id = ?",
        (order_id,),
    ).fetchone()
    return row is not None and row[0] == "paid"


def _observe_evidence(
    connection: sqlite3.Connection,
    request: ReferenceProbeRequest,
) -> dict[str, object]:
    evidence: dict[str, object] = {}
    event_filter, event_parameters = _where_in("event_id", request.event_ids)
    order_filter, order_parameters = _where_in("order_id", request.order_ids)
    for name in request.evidence_names:
        if name is ObserverEvidenceName.PROCESSING_COUNT:
            row = connection.execute(
                f"SELECT COUNT(*) FROM webhook_inbox WHERE state = 'processed'{event_filter}",
                event_parameters,
            ).fetchone()
            evidence[name.value] = cast("int", row[0])
        elif name is ObserverEvidenceName.EFFECT_COUNT:
            row = connection.execute(
                f"SELECT COUNT(*) FROM payment_effects WHERE 1 = 1{event_filter}",
                event_parameters,
            ).fetchone()
            evidence[name.value] = cast("int", row[0])
        elif name is ObserverEvidenceName.OUTBOX_COUNT:
            row = connection.execute(
                f"SELECT COUNT(*) FROM outbox WHERE 1 = 1{event_filter}",
                event_parameters,
            ).fetchone()
            evidence[name.value] = cast("int", row[0])
        elif name is ObserverEvidenceName.INBOX_STATE:
            rows = connection.execute(
                f"""
                SELECT event_id, state
                FROM webhook_inbox
                WHERE 1 = 1{event_filter}
                ORDER BY event_id
                """,
                event_parameters,
            ).fetchall()
            evidence[name.value] = {cast("str", row[0]): cast("str", row[1]) for row in rows}
        elif name is ObserverEvidenceName.ORDER_STATE:
            rows = connection.execute(
                f"""
                SELECT order_id, state, version
                FROM orders
                WHERE 1 = 1{order_filter}
                ORDER BY order_id
                """,
                order_parameters,
            ).fetchall()
            evidence[name.value] = {
                cast("str", row[0]): {
                    "state": cast("str", row[1]),
                    "version": cast("int", row[2]),
                }
                for row in rows
            }
    return evidence


def _where_in(column: str, values: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    if not values:
        return "", ()
    placeholders = ",".join("?" for _ in values)
    return f" AND {column} IN ({placeholders})", values


def _connection_policy(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA journal_mode = DELETE")
    connection.execute("PRAGMA synchronous = EXTRA")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    connection.execute("PRAGMA busy_timeout = 5000")


def _validated_database_path(value: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise ReferenceReceiverError("reference database path must be filesystem text") from error
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if type(raw) is not str or not raw or "\x00" in raw or len(raw) > 4_096:
        raise ReferenceReceiverError("reference database path is malformed")
    path = Path(raw).absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = Path(path.anchor)
    parts = path.parent.parts[1:] if path.anchor else path.parent.parts
    for part in parts:
        current /= part
        metadata = current.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            raise ReferenceReceiverError("reference database path traverses a link")
    if path.exists():
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or _is_reparse(metadata):
            raise ReferenceReceiverError("reference database must be one private regular file")
    return path


def _one_header(
    headers: tuple[tuple[str, str], ...],
    name: str,
) -> str | None:
    values = tuple(value for candidate, value in headers if candidate.casefold() == name.casefold())
    return values[0] if len(values) == 1 else None


def _parse_stripe_header(value: str | None) -> tuple[int, tuple[bytes, ...]] | None:
    if value is None:
        return None
    timestamp: int | None = None
    signatures: list[bytes] = []
    components = value.split(",")
    if not 2 <= len(components) <= 32:
        return None
    for component in components:
        name, separator, component_value = component.partition("=")
        if separator != "=":
            return None
        if name == "t":
            if timestamp is not None:
                return None
            timestamp = _timestamp(component_value)
            if timestamp is None:
                return None
        elif name == "v1":
            digest = _hex_digest(component_value)
            if digest is None:
                return None
            signatures.append(digest)
    if timestamp is None or not signatures or len(signatures) > 8:
        return None
    return timestamp, tuple(signatures)


def _parse_standard_signatures(value: str | None) -> tuple[bytes, ...] | None:
    if value is None:
        return None
    components = value.split(" ")
    if not 1 <= len(components) <= 8:
        return None
    result: list[bytes] = []
    for component in components:
        matched = _STANDARD_SIGNATURE.fullmatch(component)
        if matched is None:
            return None
        try:
            decoded = base64.b64decode(
                matched.group(1),
                validate=True,
            )
        except (binascii.Error, ValueError):
            return None
        if len(decoded) != hashlib.sha256().digest_size:
            return None
        result.append(decoded)
    return tuple(result)


def _hex_digest(value: str | None) -> bytes | None:
    if value is None or _LOWER_HEX_SHA256.fullmatch(value) is None:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _timestamp(value: str | None) -> int | None:
    if value is None or _CANONICAL_SECONDS.fullmatch(value) is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _fresh(timestamp: int, now: int, replay_window: int) -> bool:
    return abs(now - timestamp) <= replay_window


def _generic_canonical(timestamp: int, event_id: str, body: bytes) -> bytes:
    return f"{timestamp}.{event_id}.".encode("ascii") + body


def _stripe_canonical(timestamp: int, body: bytes) -> bytes:
    return f"{timestamp}.".encode("ascii") + body


def _standard_canonical(event_id: str, timestamp: int, body: bytes) -> bytes:
    return f"{event_id}.{timestamp}.".encode("ascii") + body


def _identifier(value: object, *, name: str) -> None:
    if type(value) is not str or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} must be one bounded safe identifier")


def _identifier_tuple(value: tuple[str, ...], *, name: str) -> None:
    if type(value) is not tuple or len(value) > MAX_OBSERVER_ITEMS or len(set(value)) != len(value):
        raise ValueError(f"{name} must be a bounded unique tuple")
    for item in value:
        _identifier(item, name=name)


def _reject_non_json_number(value: str) -> object:
    raise ValueError(f"non-JSON numeric constant is forbidden: {value}")


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)


__all__ = [
    "DEFAULT_REPLAY_WINDOW_SECONDS",
    "CorrectReferenceReceiver",
    "InboxState",
    "MutableReferenceClock",
    "ObserverEvidenceName",
    "ReferenceAuthenticationError",
    "ReferenceCapabilityError",
    "ReferenceClock",
    "ReferenceOutcome",
    "ReferenceProbeRequest",
    "ReferenceProbeResponse",
    "ReferenceRequest",
    "ReferenceResponse",
    "ReferenceSignatureConfiguration",
    "ReferenceSigningKey",
    "SignatureProfile",
    "SystemReferenceClock",
    "sign_reference_request",
]
