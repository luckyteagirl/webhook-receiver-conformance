"""Deterministic, resolver-independent destination address classification."""
# ruff: noqa: INP001

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
)

MAX_ADDRESS_TEXT_LENGTH = 128
_CONTROL_CHARACTER_LIMIT = 32
_DELETE_CHARACTER_CODEPOINT = 127


class AddressClass(StrEnum):
    """Security-relevant destination address classes."""

    LOOPBACK = "loopback"
    PRIVATE = "private"
    PUBLIC = "public"
    BLOCKED = "blocked"


class BlockedAddressReason(StrEnum):
    """Stable reasons for permanently forbidden address classes."""

    UNSPECIFIED = "unspecified"
    MULTICAST = "multicast"
    LINK_LOCAL = "link-local"
    METADATA = "metadata"
    DOCUMENTATION = "documentation"
    BENCHMARK = "benchmark"
    RESERVED = "reserved"
    TRANSITION = "transition"
    SPECIAL_USE = "special-use"
    SCOPED = "scoped"


@dataclass(frozen=True, slots=True)
class AddressClassification:
    """A canonical address and its deterministic policy classification."""

    normalized: str
    version: int
    address_class: AddressClass
    blocked_reason: BlockedAddressReason | None = None


_IPV4_LOOPBACK = IPv4Network("127.0.0.0/8")
_IPV4_PRIVATE: tuple[IPv4Network, ...] = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)
_IPV4_METADATA: tuple[IPv4Network, ...] = (
    IPv4Network("100.100.100.200/32"),
    IPv4Network("168.63.129.16/32"),
    IPv4Network("169.254.169.254/32"),
    IPv4Network("169.254.170.2/32"),
    IPv4Network("192.0.0.192/32"),
)
_IPV4_BLOCKED: tuple[tuple[IPv4Network, BlockedAddressReason], ...] = (
    (IPv4Network("0.0.0.0/8"), BlockedAddressReason.UNSPECIFIED),
    (IPv4Network("100.64.0.0/10"), BlockedAddressReason.SPECIAL_USE),
    (IPv4Network("169.254.0.0/16"), BlockedAddressReason.LINK_LOCAL),
    (IPv4Network("192.0.0.0/24"), BlockedAddressReason.SPECIAL_USE),
    (IPv4Network("192.0.2.0/24"), BlockedAddressReason.DOCUMENTATION),
    (IPv4Network("192.31.196.0/24"), BlockedAddressReason.SPECIAL_USE),
    (IPv4Network("192.52.193.0/24"), BlockedAddressReason.TRANSITION),
    (IPv4Network("192.88.99.0/24"), BlockedAddressReason.TRANSITION),
    (IPv4Network("192.175.48.0/24"), BlockedAddressReason.SPECIAL_USE),
    (IPv4Network("198.18.0.0/15"), BlockedAddressReason.BENCHMARK),
    (IPv4Network("198.51.100.0/24"), BlockedAddressReason.DOCUMENTATION),
    (IPv4Network("203.0.113.0/24"), BlockedAddressReason.DOCUMENTATION),
    (IPv4Network("224.0.0.0/4"), BlockedAddressReason.MULTICAST),
    (IPv4Network("240.0.0.0/4"), BlockedAddressReason.RESERVED),
)

_IPV6_LOOPBACK = IPv6Network("::1/128")
_IPV6_PRIVATE = IPv6Network("fc00::/7")
_IPV6_METADATA: tuple[IPv6Network, ...] = (
    IPv6Network("fd00:ec2::254/128"),
    IPv6Network("fd20:ce::254/128"),
)
# IANA IPv6 Global Unicast Address Space registry allocations, excluding
# IANA special-purpose space and 6to4. Space outside these allocations is
# reserved and must not become reachable merely because ipaddress considers it
# global on a particular CPython release.
_IPV6_PUBLIC: tuple[IPv6Network, ...] = (
    IPv6Network("2001:200::/23"),
    IPv6Network("2001:400::/23"),
    IPv6Network("2001:600::/23"),
    IPv6Network("2001:800::/22"),
    IPv6Network("2001:c00::/23"),
    IPv6Network("2001:e00::/23"),
    IPv6Network("2001:1200::/23"),
    IPv6Network("2001:1400::/22"),
    IPv6Network("2001:1800::/23"),
    IPv6Network("2001:1a00::/23"),
    IPv6Network("2001:1c00::/22"),
    IPv6Network("2001:2000::/19"),
    IPv6Network("2001:4000::/23"),
    IPv6Network("2001:4200::/23"),
    IPv6Network("2001:4400::/23"),
    IPv6Network("2001:4600::/23"),
    IPv6Network("2001:4800::/23"),
    IPv6Network("2001:4a00::/23"),
    IPv6Network("2001:4c00::/23"),
    IPv6Network("2001:5000::/20"),
    IPv6Network("2001:8000::/19"),
    IPv6Network("2001:a000::/20"),
    IPv6Network("2001:b000::/20"),
    IPv6Network("2003::/18"),
    IPv6Network("2400::/12"),
    IPv6Network("2410::/12"),
    IPv6Network("2600::/12"),
    IPv6Network("2610::/23"),
    IPv6Network("2620::/23"),
    IPv6Network("2630::/12"),
    IPv6Network("2800::/12"),
    IPv6Network("2a00::/12"),
    IPv6Network("2a10::/12"),
    IPv6Network("2c00::/12"),
)
_IPV6_BLOCKED: tuple[tuple[IPv6Network, BlockedAddressReason], ...] = (
    (IPv6Network("::/128"), BlockedAddressReason.UNSPECIFIED),
    (IPv6Network("::/96"), BlockedAddressReason.TRANSITION),
    (IPv6Network("::ffff:0:0/96"), BlockedAddressReason.TRANSITION),
    (IPv6Network("64:ff9b::/96"), BlockedAddressReason.TRANSITION),
    (IPv6Network("64:ff9b:1::/48"), BlockedAddressReason.TRANSITION),
    (IPv6Network("100::/64"), BlockedAddressReason.SPECIAL_USE),
    (IPv6Network("100:0:0:1::/64"), BlockedAddressReason.SPECIAL_USE),
    (IPv6Network("2001::/23"), BlockedAddressReason.SPECIAL_USE),
    (IPv6Network("2001:db8::/32"), BlockedAddressReason.DOCUMENTATION),
    (IPv6Network("2002::/16"), BlockedAddressReason.TRANSITION),
    (IPv6Network("2620:4f:8000::/48"), BlockedAddressReason.SPECIAL_USE),
    (IPv6Network("3ffe::/16"), BlockedAddressReason.TRANSITION),
    (IPv6Network("3fff::/20"), BlockedAddressReason.DOCUMENTATION),
    (IPv6Network("5f00::/16"), BlockedAddressReason.DOCUMENTATION),
    (IPv6Network("fec0::/10"), BlockedAddressReason.RESERVED),
    (IPv6Network("fe80::/10"), BlockedAddressReason.LINK_LOCAL),
    (IPv6Network("ff00::/8"), BlockedAddressReason.MULTICAST),
)


def classify_address(value: str) -> AddressClassification:
    """Classify one strict IPv4/IPv6 candidate without DNS or ambient state."""
    if (
        not value
        or len(value) > MAX_ADDRESS_TEXT_LENGTH
        or value != value.strip()
        or any(
            ord(character) < _CONTROL_CHARACTER_LIMIT
            or ord(character) == _DELETE_CHARACTER_CODEPOINT
            for character in value
        )
    ):
        msg = "address candidate must be bounded, nonempty, and control-free"
        raise ValueError(msg)

    if "%" in value:
        base, separator, zone = value.partition("%")
        if not separator or not base or not zone or "%" in zone:
            msg = "address candidate has an invalid scope identifier"
            raise ValueError(msg)
        parsed_scoped = _parse_address(base)
        return AddressClassification(
            normalized=str(parsed_scoped),
            version=parsed_scoped.version,
            address_class=AddressClass.BLOCKED,
            blocked_reason=BlockedAddressReason.SCOPED,
        )

    parsed = _parse_address(value)
    if isinstance(parsed, IPv4Address):
        return _classify_ipv4(parsed)
    return _classify_ipv6(parsed)


def _parse_address(value: str) -> IPv4Address | IPv6Address:
    try:
        return ip_address(value)
    except ValueError as error:
        msg = "address candidate is not a canonical IPv4 or IPv6 address"
        raise ValueError(msg) from error


def _classify_ipv4(address: IPv4Address) -> AddressClassification:
    normalized = str(address)
    if address in _IPV4_LOOPBACK:
        return AddressClassification(normalized, 4, AddressClass.LOOPBACK)
    for network in _IPV4_PRIVATE:
        if address in network:
            return AddressClassification(normalized, 4, AddressClass.PRIVATE)
    for network in _IPV4_METADATA:
        if address in network:
            return AddressClassification(
                normalized,
                4,
                AddressClass.BLOCKED,
                BlockedAddressReason.METADATA,
            )
    for network, reason in _IPV4_BLOCKED:
        if address in network:
            return AddressClassification(normalized, 4, AddressClass.BLOCKED, reason)
    return AddressClassification(normalized, 4, AddressClass.PUBLIC)


def _classify_ipv6(address: IPv6Address) -> AddressClassification:
    normalized = address.compressed.lower()
    if address in _IPV6_LOOPBACK:
        return AddressClassification(normalized, 6, AddressClass.LOOPBACK)
    for network in _IPV6_METADATA:
        if address in network:
            return AddressClassification(
                normalized,
                6,
                AddressClass.BLOCKED,
                BlockedAddressReason.METADATA,
            )
    if address in _IPV6_PRIVATE:
        return AddressClassification(normalized, 6, AddressClass.PRIVATE)
    for network, reason in _IPV6_BLOCKED:
        if address in network:
            return AddressClassification(normalized, 6, AddressClass.BLOCKED, reason)
    if any(address in network for network in _IPV6_PUBLIC):
        return AddressClassification(normalized, 6, AddressClass.PUBLIC)
    return AddressClassification(
        normalized,
        6,
        AddressClass.BLOCKED,
        BlockedAddressReason.RESERVED,
    )
