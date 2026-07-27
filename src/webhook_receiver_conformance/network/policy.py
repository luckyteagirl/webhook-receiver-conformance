"""Pure destination-policy parsing and post-resolution authorization."""
# ruff: noqa: INP001
# pyright: reportPrivateUsage=false

from __future__ import annotations

import re
import threading
import unicodedata
import weakref
from dataclasses import InitVar, dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from itertools import islice
from typing import TYPE_CHECKING, NoReturn, cast
from urllib.parse import SplitResult, urlsplit

from webhook_receiver_conformance.config.models import (
    MAX_ALLOWED_HOSTS,
    MAX_HTTP_PORT,
    ReceiverConfig,
    TargetProfile,
)
from webhook_receiver_conformance.network.addresses import (
    AddressClass,
    AddressClassification,
    BlockedAddressReason,
    classify_address,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

MAX_DESTINATION_URL_LENGTH = 4096
MAX_HOST_LENGTH = 253
MAX_RESOLVED_ADDRESSES = 64
MAX_CHALLENGE_PATH_LENGTH = 2048
_CONTROL_CHARACTER_LIMIT = 32
_DELETE_CHARACTER_CODEPOINT = 127
_DEFAULT_PORTS = {"http": 80, "https": 443}
_ASCII_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NUMERIC_HOST_LABEL = re.compile(r"(?:[0-9]+|0x[0-9a-f]+)", re.IGNORECASE)
_DESTINATION_CONSTRUCTOR_SEAL = object()
_POLICY_CONSTRUCTOR_SEAL = object()
_AUTHORIZED_CONSTRUCTOR_SEAL = object()
_PUBLIC_AUTHORIZATION_PART_COUNT = 2
_AUTHORITY_LOCK = threading.RLock()
_AUTHORITY_RECORDS: dict[int, _AuthorityRecord] = {}


class PolicyErrorCode(StrEnum):
    """Bounded machine-readable destination-policy rejection codes."""

    INVALID_URL = "invalid-url"
    INVALID_SCHEME = "invalid-scheme"
    USERINFO_FORBIDDEN = "userinfo-forbidden"
    FRAGMENT_FORBIDDEN = "fragment-forbidden"
    INVALID_HOST = "invalid-host"
    INVALID_PORT = "invalid-port"
    HOST_NOT_ALLOWED = "host-not-allowed"
    PORT_NOT_ALLOWED = "port-not-allowed"
    PUBLIC_HTTPS_REQUIRED = "public-https-required"
    PUBLIC_AUTHORIZATION_REQUIRED = "public-authorization-required"
    PUBLIC_AUTHORIZATION_MISMATCH = "public-authorization-mismatch"
    PREFLIGHT_CONFIGURATION_INVALID = "preflight-configuration-invalid"
    ADDRESS_INVALID = "address-invalid"
    ADDRESS_BLOCKED = "address-blocked"
    ADDRESS_PROFILE_MISMATCH = "address-profile-mismatch"
    ADDRESS_SET_INVALID = "address-set-invalid"


class DestinationPolicyError(ValueError):
    """Privacy-safe invalid-input rejection from the destination policy."""

    code: PolicyErrorCode

    def __init__(self, code: PolicyErrorCode, message: str) -> None:
        """Initialize a bounded rejection with no target-derived message text."""
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class _AuthorityRecord:
    """One weak identity-bound capability record held outside protected objects."""

    reference: weakref.ReferenceType[object]
    kind: str
    binding: tuple[object, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ParsedDestination:
    """A strictly parsed URL with a canonical authority."""

    scheme: str
    host: str
    port: int
    path: str
    query: str
    literal_address: str | None
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        """Reject construction outside the strict destination parser."""
        if _seal is not _DESTINATION_CONSTRUCTOR_SEAL:
            msg = "ParsedDestination instances must be produced by destination parsing"
            raise TypeError(msg)
        _mint_authority(self, kind="destination", binding=_destination_binding(self))

    @property
    def authority(self) -> str:
        """Return the canonical explicit host-and-port authority."""
        rendered_host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{rendered_host}:{self.port}"

    @property
    def normalized_url(self) -> str:
        """Return a deterministic URL with an explicit effective port."""
        suffix = self.path
        if self.query:
            suffix = f"{suffix}?{self.query}"
        return f"{self.scheme}://{self.authority}{suffix}"


@dataclass(frozen=True, slots=True, weakref_slot=True)
class DestinationPolicy:
    """Pre-resolution authorization produced without DNS or delivery."""

    destination: ParsedDestination
    target_profile: TargetProfile
    allowed_hosts: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    public_challenge_path: str
    _seal: InitVar[object | None] = None
    _public_authorization: InitVar[tuple[str, int] | None] = None

    def __post_init__(
        self,
        _seal: object | None,
        _public_authorization: tuple[str, int] | None,
    ) -> None:
        """Reject construction outside pre-resolution gate validation."""
        if _seal is not _POLICY_CONSTRUCTOR_SEAL:
            msg = "DestinationPolicy instances must be produced by destination parsing"
            raise TypeError(msg)
        _mint_authority(
            self,
            kind="policy",
            binding=_policy_binding(self, _public_authorization),
        )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class AuthorizedDestination:
    """A policy plus the complete validated candidate-address set."""

    policy: DestinationPolicy
    addresses: tuple[AddressClassification, ...]
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        """Reject construction outside resolved-address authorization."""
        if _seal is not _AUTHORIZED_CONSTRUCTOR_SEAL:
            msg = "AuthorizedDestination instances must be produced by address authorization"
            raise TypeError(msg)
        policy_binding = _authority_binding(self.policy, kind="policy")
        if policy_binding is None:
            msg = "AuthorizedDestination requires an authorized destination policy"
            raise TypeError(msg)
        _mint_authority(
            self,
            kind="authorized",
            binding=_authorized_destination_binding(self),
        )


def parse_destination_policy(
    receiver: ReceiverConfig,
    *,
    runtime_public_authorization: str | None = None,
) -> DestinationPolicy:
    """Apply every configuration/runtime gate without resolving or delivering."""
    destination = _parse_destination_url(receiver.url)
    allowed_hosts = _normalize_allowed_hosts(receiver.allowed_hosts)
    allowed_ports = tuple(sorted(receiver.allowed_ports))

    if destination.port not in allowed_ports:
        _reject(
            PolicyErrorCode.PORT_NOT_ALLOWED,
            "destination port is not explicitly allowed",
        )

    public_authorization: tuple[str, int] | None = None
    if receiver.target_profile is TargetProfile.PRIVATE_ALLOWLIST:
        _require_allowed_host(destination.host, allowed_hosts)
    elif receiver.target_profile is TargetProfile.PUBLIC_AUTHORIZED:
        public_authorization = _validate_public_gates(
            destination,
            allowed_hosts=allowed_hosts,
            challenge_path=receiver.public_challenge_path,
            runtime_authorization=runtime_public_authorization,
        )

    policy = DestinationPolicy(
        destination=destination,
        target_profile=receiver.target_profile,
        allowed_hosts=allowed_hosts,
        allowed_ports=allowed_ports,
        public_challenge_path=receiver.public_challenge_path,
        _seal=_POLICY_CONSTRUCTOR_SEAL,
        _public_authorization=public_authorization,
    )
    if destination.literal_address is not None:
        try:
            classification = classify_address(destination.literal_address)
        except ValueError as error:
            raise DestinationPolicyError(
                PolicyErrorCode.ADDRESS_INVALID,
                "literal destination address is invalid",
            ) from error
        _enforce_address_profile(policy, classification)
    return policy


def authorize_resolved_addresses(
    policy: DestinationPolicy,
    candidates: Sequence[str] | None = None,
) -> AuthorizedDestination:
    """Validate every supplied resolver candidate without performing resolution."""
    _validate_policy_provenance(policy)
    if candidates is None:
        literal = policy.destination.literal_address
        if literal is None:
            _reject(
                PolicyErrorCode.ADDRESS_SET_INVALID,
                "a hostname destination requires resolved address candidates",
            )
        candidate_values = (literal,)
    else:
        candidate_values = _materialize_candidates(candidates)

    classifications: dict[tuple[int, str], AddressClassification] = {}
    for candidate in candidate_values:
        try:
            classification = classify_address(candidate)
        except (TypeError, ValueError) as error:
            raise DestinationPolicyError(
                PolicyErrorCode.ADDRESS_INVALID,
                "resolved address candidate is invalid",
            ) from error
        _enforce_address_profile(policy, classification)
        classifications[(classification.version, classification.normalized)] = classification

    ordered = tuple(classifications[key] for key in sorted(classifications))
    literal = policy.destination.literal_address
    if literal is not None and (len(ordered) != 1 or ordered[0].normalized != literal):
        _reject(
            PolicyErrorCode.ADDRESS_SET_INVALID,
            "literal destination does not match the supplied address set",
        )
    return AuthorizedDestination(
        policy=policy,
        addresses=ordered,
        _seal=_AUTHORIZED_CONSTRUCTOR_SEAL,
    )


def validate_authorized_destination(
    authorized: AuthorizedDestination,
) -> AuthorizedDestination:
    """Validate phase-two authority before a transport consumes its fields."""
    if type(authorized) is not AuthorizedDestination:
        _reject(
            PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID,
            "authorized destination provenance or binding is invalid",
        )
    _validate_policy_provenance(authorized.policy)
    try:
        authority_binding = _authority_binding(authorized, kind="authorized")
        binding_valid = (
            authority_binding is not None
            and authority_binding == _authorized_destination_binding(authorized)
        )
        addresses_valid = _authorized_address_set_is_valid(
            authorized.policy,
            authorized.addresses,
        )
    except Exception:  # noqa: BLE001 - malformed or mutated capabilities fail closed
        binding_valid = False
        addresses_valid = False
    if not binding_valid or not addresses_valid:
        _reject(
            PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID,
            "authorized destination provenance or binding is invalid",
        )
    return authorized


def _materialize_candidates(candidates: Sequence[str]) -> tuple[str, ...]:
    try:
        declared_length = len(candidates)
    except Exception as error:
        raise DestinationPolicyError(
            PolicyErrorCode.ADDRESS_SET_INVALID,
            "resolved address set does not expose a stable bounded length",
        ) from error

    if not 1 <= declared_length <= MAX_RESOLVED_ADDRESSES:
        _reject(
            PolicyErrorCode.ADDRESS_SET_INVALID,
            "resolved address set must contain between 1 and 64 candidates",
        )

    try:
        realized = tuple(islice(iter(candidates), MAX_RESOLVED_ADDRESSES + 1))
        final_length = len(candidates)
    except Exception as error:
        raise DestinationPolicyError(
            PolicyErrorCode.ADDRESS_SET_INVALID,
            "resolved address set could not be materialized safely",
        ) from error

    if declared_length != final_length or declared_length != len(realized):
        _reject(
            PolicyErrorCode.ADDRESS_SET_INVALID,
            "resolved address set length is inconsistent",
        )
    return realized


def _mint_authority(
    instance: object,
    *,
    kind: str,
    binding: tuple[object, ...],
) -> None:
    identity = id(instance)

    def remove(reference: weakref.ReferenceType[object]) -> None:
        with _AUTHORITY_LOCK:
            current = _AUTHORITY_RECORDS.get(identity)
            if current is not None and current.reference is reference:
                del _AUTHORITY_RECORDS[identity]

    reference = weakref.ref(instance, remove)
    record = _AuthorityRecord(reference=reference, kind=kind, binding=binding)
    with _AUTHORITY_LOCK:
        current = _AUTHORITY_RECORDS.get(identity)
        if current is not None and current.reference() is not None:
            msg = "destination authority identity collision"
            raise RuntimeError(msg)
        _AUTHORITY_RECORDS[identity] = record


def _authority_binding(instance: object, *, kind: str) -> tuple[object, ...] | None:
    with _AUTHORITY_LOCK:
        record = _AUTHORITY_RECORDS.get(id(instance))
        if record is None or record.kind != kind or record.reference() is not instance:
            return None
        return record.binding


def _authority_registry_size() -> int:  # pyright: ignore[reportUnusedFunction]
    """Return the live private capability count for lifecycle regression tests."""
    with _AUTHORITY_LOCK:
        return len(_AUTHORITY_RECORDS)


def _destination_binding(destination: ParsedDestination) -> tuple[object, ...]:
    return (
        _typed_value(destination.scheme),
        _typed_value(destination.host),
        _typed_value(destination.port),
        _typed_value(destination.path),
        _typed_value(destination.query),
        _typed_value(destination.literal_address),
    )


def _policy_binding(
    policy: DestinationPolicy,
    public_authorization: tuple[str, int] | None,
) -> tuple[object, ...]:
    destination_binding = _authority_binding(policy.destination, kind="destination")
    if destination_binding is None:
        msg = "destination policy requires a minted parsed destination"
        raise TypeError(msg)
    return (
        id(policy.destination),
        destination_binding,
        _typed_value(policy.target_profile),
        _typed_sequence(policy.allowed_hosts),
        _typed_sequence(policy.allowed_ports),
        _typed_value(policy.public_challenge_path),
        public_authorization,
    )


def _authorized_destination_binding(
    authorized: AuthorizedDestination,
) -> tuple[object, ...]:
    policy_binding = _authority_binding(authorized.policy, kind="policy")
    if policy_binding is None:
        msg = "authorized destination requires a minted destination policy"
        raise TypeError(msg)
    return (
        id(authorized.policy),
        policy_binding,
        id(authorized.addresses),
        tuple(_address_binding(address) for address in authorized.addresses),
    )


def _address_binding(address: AddressClassification) -> tuple[object, ...]:
    return (
        _typed_value(address.normalized),
        _typed_value(address.version),
        _typed_value(address.address_class),
        _typed_value(address.blocked_reason),
    )


def _typed_value(value: object) -> tuple[type[object], object]:
    return type(value), value


def _typed_sequence(values: tuple[object, ...]) -> tuple[tuple[type[object], object], ...]:
    return tuple(_typed_value(value) for value in values)


def _bound_public_authorization(
    policy_binding: tuple[object, ...] | None,
) -> tuple[bool, tuple[str, int] | None]:
    if policy_binding is None:
        return False, None
    candidate = policy_binding[-1]
    if candidate is None:
        return True, None
    if type(candidate) is not tuple:
        return False, None
    parts = cast("tuple[object, ...]", candidate)
    if (
        len(parts) != _PUBLIC_AUTHORIZATION_PART_COUNT
        or type(parts[0]) is not str
        or type(parts[1]) is not int
    ):
        return False, None
    return True, cast("tuple[str, int]", parts)


def _authorized_address_set_is_valid(
    policy: DestinationPolicy,
    addresses: tuple[AddressClassification, ...],
) -> bool:
    if (
        type(addresses) is not tuple
        or not 1 <= len(addresses) <= MAX_RESOLVED_ADDRESSES
        or any(type(address) is not AddressClassification for address in addresses)
    ):
        return False
    keys: list[tuple[int, str]] = []
    try:
        for address in addresses:
            if (
                type(address.normalized) is not str
                or type(address.version) is not int
                or type(address.address_class) is not AddressClass
                or (
                    address.blocked_reason is not None
                    and type(address.blocked_reason) is not BlockedAddressReason
                )
                or classify_address(address.normalized) != address
            ):
                return False
            _enforce_address_profile(policy, address)
            keys.append((address.version, address.normalized))
    except (DestinationPolicyError, TypeError, ValueError):
        return False
    if keys != sorted(set(keys)):
        return False
    literal = policy.destination.literal_address
    return literal is None or (len(addresses) == 1 and addresses[0].normalized == literal)


def _validate_policy_provenance(policy: DestinationPolicy) -> None:
    try:
        destination = policy.destination
        destination_binding = _authority_binding(destination, kind="destination")
        policy_binding = _authority_binding(policy, kind="policy")
        (
            public_authorization_valid,
            public_authorization,
        ) = _bound_public_authorization(
            policy_binding,
        )
        destination_valid = type(
            destination
        ) is ParsedDestination and destination_binding == _destination_binding(destination)
        policy_valid = (
            type(policy) is DestinationPolicy
            and policy_binding is not None
            and public_authorization_valid
            and policy_binding == _policy_binding(policy, public_authorization)
        )
        allowed_hosts_valid = (
            type(policy.allowed_hosts) is tuple
            and policy.allowed_hosts == tuple(sorted(set(policy.allowed_hosts)))
            and all(normalize_host(host) == host for host in policy.allowed_hosts)
        )
        allowed_ports_valid = (
            type(policy.allowed_ports) is tuple
            and policy.allowed_ports == tuple(sorted(set(policy.allowed_ports)))
            and all(
                type(port) is int and 1 <= port <= MAX_HTTP_PORT for port in policy.allowed_ports
            )
        )
        literal_address: str | None
        try:
            literal_address = str(ip_address(destination.host))
        except ValueError:
            literal_address = None
        destination_valid = (
            destination_valid
            and destination.scheme in _DEFAULT_PORTS
            and normalize_host(destination.host) == destination.host
            and type(destination.port) is int
            and 1 <= destination.port <= MAX_HTTP_PORT
            and destination.literal_address == literal_address
        )
        common_gates_valid = (
            type(policy.target_profile) is TargetProfile
            and destination.port in policy.allowed_ports
        )
        profile_gates_valid = _policy_profile_gates_are_valid(
            policy,
            public_authorization=public_authorization,
        )
    except Exception:  # noqa: BLE001 - malformed or mutated capabilities fail closed
        destination_valid = False
        policy_valid = False
        allowed_hosts_valid = False
        allowed_ports_valid = False
        common_gates_valid = False
        profile_gates_valid = False

    if not all(
        (
            destination_valid,
            policy_valid,
            allowed_hosts_valid,
            allowed_ports_valid,
            common_gates_valid,
            profile_gates_valid,
        )
    ):
        _reject(
            PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID,
            "destination policy provenance or binding is invalid",
        )


def _policy_profile_gates_are_valid(
    policy: DestinationPolicy,
    *,
    public_authorization: tuple[str, int] | None,
) -> bool:
    destination = policy.destination
    if policy.target_profile is TargetProfile.LOOPBACK:
        return public_authorization is None
    if policy.target_profile is TargetProfile.PRIVATE_ALLOWLIST:
        return destination.host in policy.allowed_hosts and public_authorization is None
    if policy.target_profile is TargetProfile.PUBLIC_AUTHORIZED:
        _validate_challenge_path(policy.public_challenge_path)
        return (
            destination.scheme == "https"
            and destination.host in policy.allowed_hosts
            and public_authorization == (destination.host, destination.port)
        )
    return False


def normalize_host(value: str) -> str:
    """Normalize a strict hostname or literal address without resolving it."""
    _validate_host_text(value)

    if ":" in value:
        return _normalize_ipv6_literal(value)

    candidate = value.removesuffix(".")
    if not candidate or candidate.endswith("."):
        _reject(PolicyErrorCode.INVALID_HOST, "destination host is invalid")
    try:
        parsed_ip = ip_address(candidate)
    except ValueError:
        parsed_ip = None
    if parsed_ip is not None:
        if not isinstance(parsed_ip, IPv4Address):
            _reject(PolicyErrorCode.INVALID_HOST, "destination host is invalid")
        return str(parsed_ip)

    return _normalize_dns_hostname(candidate)


def _validate_host_text(value: str) -> None:
    if (
        not value
        or len(value) > MAX_HOST_LENGTH + 1
        or value != value.strip()
        or _contains_control(value)
        or any(character in value for character in ("/", "\\", "@", "#", "?", "%", "[", "]"))
    ):
        _reject(PolicyErrorCode.INVALID_HOST, "destination host is invalid")


def _normalize_ipv6_literal(value: str) -> str:
    try:
        parsed_ipv6 = ip_address(value)
    except ValueError as error:
        raise DestinationPolicyError(
            PolicyErrorCode.INVALID_HOST,
            "destination IPv6 literal is invalid",
        ) from error
    if not isinstance(parsed_ipv6, IPv6Address):
        _reject(PolicyErrorCode.INVALID_HOST, "destination host is invalid")
    return parsed_ipv6.compressed.lower()


def _normalize_dns_hostname(candidate: str) -> str:
    if all(_NUMERIC_HOST_LABEL.fullmatch(label) is not None for label in candidate.split(".")):
        _reject(PolicyErrorCode.INVALID_HOST, "ambiguous numeric destination host is forbidden")
    if unicodedata.normalize("NFC", candidate) != candidate:
        _reject(PolicyErrorCode.INVALID_HOST, "destination host must use normalized Unicode")

    try:
        ascii_host = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise DestinationPolicyError(
            PolicyErrorCode.INVALID_HOST,
            "destination host has invalid IDNA encoding",
        ) from error
    if len(ascii_host) > MAX_HOST_LENGTH:
        _reject(PolicyErrorCode.INVALID_HOST, "destination host is too long")

    labels = ascii_host.split(".")
    if any(_ASCII_LABEL.fullmatch(label) is None for label in labels):
        _reject(PolicyErrorCode.INVALID_HOST, "destination host has an invalid label")
    _validate_idna_round_trip(candidate, ascii_host)
    return ascii_host


def _parse_destination_url(value: str) -> ParsedDestination:
    _validate_url_text(value)
    if "#" in value:
        _reject(PolicyErrorCode.FRAGMENT_FORBIDDEN, "receiver URL fragments are forbidden")

    scheme, raw_authority = _extract_scheme_and_authority(value)
    raw_host, explicit_port = _split_authority(raw_authority)
    host = normalize_host(raw_host)
    port = _parse_port(explicit_port, default=_DEFAULT_PORTS[scheme])
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise DestinationPolicyError(
            PolicyErrorCode.INVALID_URL,
            "receiver URL is invalid",
        ) from error
    _require_parser_agreement(parsed, scheme=scheme, raw_authority=raw_authority)

    literal_address: str | None
    try:
        literal_address = str(ip_address(host))
    except ValueError:
        literal_address = None
    return ParsedDestination(
        scheme=scheme,
        host=host,
        port=port,
        path=parsed.path,
        query=parsed.query,
        literal_address=literal_address,
        _seal=_DESTINATION_CONSTRUCTOR_SEAL,
    )


def _validate_url_text(value: str) -> None:
    if (
        not value
        or len(value) > MAX_DESTINATION_URL_LENGTH
        or value != value.strip()
        or "\\" in value
        or _contains_control(value)
    ):
        _reject(PolicyErrorCode.INVALID_URL, "receiver URL is invalid")


def _extract_scheme_and_authority(value: str) -> tuple[str, str]:
    scheme_end = value.find("://")
    if scheme_end < 1:
        _reject(PolicyErrorCode.INVALID_URL, "receiver URL must be absolute")
    scheme = value[:scheme_end].lower()
    if scheme not in _DEFAULT_PORTS:
        _reject(PolicyErrorCode.INVALID_SCHEME, "receiver URL scheme is not supported")

    remainder = value[scheme_end + 3 :]
    authority_end = len(remainder)
    for delimiter in ("/", "?"):
        index = remainder.find(delimiter)
        if index >= 0:
            authority_end = min(authority_end, index)
    raw_authority = remainder[:authority_end]
    if not raw_authority:
        _reject(PolicyErrorCode.INVALID_URL, "receiver URL authority is required")
    if "@" in raw_authority:
        _reject(PolicyErrorCode.USERINFO_FORBIDDEN, "receiver URL userinfo is forbidden")
    if "%" in raw_authority:
        _reject(
            PolicyErrorCode.INVALID_HOST,
            "percent-encoded or scoped receiver authorities are forbidden",
        )
    return scheme, raw_authority


def _split_authority(authority: str) -> tuple[str, str | None]:
    if authority.startswith("["):
        bracket = authority.find("]")
        if bracket < 0:
            _reject(PolicyErrorCode.INVALID_HOST, "IPv6 receiver host must close its bracket")
        raw_host = authority[1:bracket]
        suffix = authority[bracket + 1 :]
        if not suffix:
            explicit_port = None
        elif suffix.startswith(":"):
            explicit_port = suffix[1:]
        else:
            _reject(PolicyErrorCode.INVALID_HOST, "receiver authority is invalid")
        try:
            parsed = ip_address(raw_host)
        except ValueError as error:
            raise DestinationPolicyError(
                PolicyErrorCode.INVALID_HOST,
                "bracketed receiver host must be IPv6",
            ) from error
        if not isinstance(parsed, IPv6Address):
            _reject(PolicyErrorCode.INVALID_HOST, "bracketed receiver host must be IPv6")
        return raw_host, explicit_port

    if "[" in authority or "]" in authority or authority.count(":") > 1:
        _reject(PolicyErrorCode.INVALID_HOST, "IPv6 receiver host must be bracketed")
    if ":" not in authority:
        return authority, None
    raw_host, explicit_port = authority.rsplit(":", maxsplit=1)
    return raw_host, explicit_port


def _parse_port(value: str | None, *, default: int | None) -> int:
    if value is None:
        if default is None:
            _reject(PolicyErrorCode.INVALID_PORT, "an explicit destination port is required")
        return default
    if (
        not value
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        _reject(PolicyErrorCode.INVALID_PORT, "destination port is invalid or ambiguous")
    port = int(value)
    if not 1 <= port <= MAX_HTTP_PORT:
        _reject(PolicyErrorCode.INVALID_PORT, "destination port is outside the valid range")
    return port


def _normalize_allowed_hosts(values: Sequence[str]) -> tuple[str, ...]:
    if len(values) > MAX_ALLOWED_HOSTS:
        _reject(PolicyErrorCode.HOST_NOT_ALLOWED, "host allowlist exceeds its limit")
    normalized = tuple(normalize_host(value) for value in values)
    if len(set(normalized)) != len(normalized):
        _reject(
            PolicyErrorCode.HOST_NOT_ALLOWED,
            "host allowlist contains normalization-equivalent entries",
        )
    return tuple(sorted(normalized))


def _validate_public_gates(
    destination: ParsedDestination,
    *,
    allowed_hosts: tuple[str, ...],
    challenge_path: str,
    runtime_authorization: str | None,
) -> tuple[str, int]:
    if destination.scheme != "https":
        _reject(
            PolicyErrorCode.PUBLIC_HTTPS_REQUIRED,
            "public destinations require HTTPS",
        )
    _require_allowed_host(destination.host, allowed_hosts)
    _validate_challenge_path(challenge_path)
    if runtime_authorization is None:
        _reject(
            PolicyErrorCode.PUBLIC_AUTHORIZATION_REQUIRED,
            "public destination runtime authorization is required",
        )
    authorized_host, authorized_port = _parse_runtime_authorization(runtime_authorization)
    if (authorized_host, authorized_port) != (destination.host, destination.port):
        _reject(
            PolicyErrorCode.PUBLIC_AUTHORIZATION_MISMATCH,
            "public destination runtime authorization does not match",
        )
    return authorized_host, authorized_port


def _parse_runtime_authorization(value: str) -> tuple[str, int]:
    if (
        not value
        or len(value) > MAX_HOST_LENGTH + 8
        or value != value.strip()
        or _contains_control(value)
    ):
        _reject(
            PolicyErrorCode.PUBLIC_AUTHORIZATION_MISMATCH,
            "public destination runtime authorization is invalid",
        )
    try:
        raw_host, explicit_port = _split_authority(value)
        if explicit_port is None:
            _reject(
                PolicyErrorCode.PUBLIC_AUTHORIZATION_MISMATCH,
                "public destination runtime authorization requires an explicit port",
            )
        port = _parse_port(explicit_port, default=None)
        host = normalize_host(raw_host)
    except DestinationPolicyError as error:
        raise DestinationPolicyError(
            PolicyErrorCode.PUBLIC_AUTHORIZATION_MISMATCH,
            "public destination runtime authorization is invalid",
        ) from error
    return host, port


def _validate_challenge_path(value: str) -> None:
    if (
        not value
        or len(value) > MAX_CHALLENGE_PATH_LENGTH
        or not value.startswith("/")
        or value.startswith("//")
        or "?" in value
        or "#" in value
        or "\\" in value
        or _contains_control(value)
    ):
        _reject(
            PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID,
            "public destination challenge path configuration is invalid",
        )


def _require_allowed_host(host: str, allowed_hosts: tuple[str, ...]) -> None:
    if host not in allowed_hosts:
        _reject(
            PolicyErrorCode.HOST_NOT_ALLOWED,
            "destination host is not explicitly allowed",
        )


def _enforce_address_profile(
    policy: DestinationPolicy,
    classification: AddressClassification,
) -> None:
    if classification.address_class is AddressClass.BLOCKED:
        _reject(
            PolicyErrorCode.ADDRESS_BLOCKED,
            "destination address is permanently blocked",
        )

    profile = policy.target_profile
    if profile is TargetProfile.LOOPBACK:
        accepted = classification.address_class is AddressClass.LOOPBACK
    elif profile is TargetProfile.PRIVATE_ALLOWLIST:
        accepted = classification.address_class in {
            AddressClass.PRIVATE,
            AddressClass.LOOPBACK,
        }
    else:
        accepted = classification.address_class is AddressClass.PUBLIC
    if not accepted:
        _reject(
            PolicyErrorCode.ADDRESS_PROFILE_MISMATCH,
            "destination address does not match its configured target profile",
        )


def _validate_idna_round_trip(source: str, ascii_host: str) -> None:
    try:
        decoded = ascii_host.encode("ascii").decode("idna")
        encoded = decoded.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise DestinationPolicyError(
            PolicyErrorCode.INVALID_HOST,
            "destination host has invalid IDNA encoding",
        ) from error
    if encoded != ascii_host:
        _reject(PolicyErrorCode.INVALID_HOST, "destination host IDNA encoding is ambiguous")
    if not source.isascii() and decoded.lower() != source.lower():
        _reject(PolicyErrorCode.INVALID_HOST, "destination host IDNA mapping is ambiguous")


def _require_parser_agreement(
    parsed: SplitResult,
    *,
    scheme: str,
    raw_authority: str,
) -> None:
    if parsed.scheme.lower() != scheme or parsed.netloc != raw_authority:
        _reject(PolicyErrorCode.INVALID_URL, "receiver URL parsing is ambiguous")
    if parsed.username is not None or parsed.password is not None:
        _reject(PolicyErrorCode.USERINFO_FORBIDDEN, "receiver URL userinfo is forbidden")
    if parsed.fragment:
        _reject(PolicyErrorCode.FRAGMENT_FORBIDDEN, "receiver URL fragments are forbidden")


def _reject(code: PolicyErrorCode, message: str) -> NoReturn:
    raise DestinationPolicyError(code, message)


def _contains_control(value: str) -> bool:
    return any(
        ord(character) < _CONTROL_CHARACTER_LIMIT or ord(character) == _DELETE_CHARACTER_CODEPOINT
        for character in value
    )
