"""Contract tests for TASK-0305 destination policy parsing."""
# ruff: noqa: INP001, SLF001

from __future__ import annotations

import copy
import gc
import pickle
import weakref
from collections.abc import Sequence
from dataclasses import astuple, replace
from typing import TYPE_CHECKING, overload

import pytest

import webhook_receiver_conformance.network.policy as policy_module
from webhook_receiver_conformance.config.models import ReceiverConfig, TargetProfile
from webhook_receiver_conformance.network.addresses import (
    AddressClass,
    BlockedAddressReason,
    classify_address,
)
from webhook_receiver_conformance.network.policy import (
    MAX_RESOLVED_ADDRESSES,
    AuthorizedDestination,
    DestinationPolicy,
    DestinationPolicyError,
    ParsedDestination,
    PolicyErrorCode,
    authorize_resolved_addresses,
    normalize_host,
    parse_destination_policy,
    validate_authorized_destination,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_HTTP_PORT = 80


def _receiver(
    *,
    url: str,
    target_profile: str = "loopback",
    allowed_hosts: list[str] | None = None,
    allowed_ports: list[int] | None = None,
    public_challenge_path: str = "/.well-known/webhook-conformance-challenge",
) -> ReceiverConfig:
    return ReceiverConfig.model_validate(
        {
            "url": url,
            "target_profile": target_profile,
            "allowed_hosts": [] if allowed_hosts is None else allowed_hosts,
            "allowed_ports": [8443] if allowed_ports is None else allowed_ports,
            "public_challenge_path": public_challenge_path,
            "timeouts": {
                "connect": "1s",
                "write": "1s",
                "read": "1s",
                "pool": "1s",
                "total": "5s",
            },
        }
    )


def _receiver_with_unchecked_url(url: str) -> ReceiverConfig:
    return _receiver(url="http://127.0.0.1:8443").model_copy(update={"url": url})


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("ftp://127.0.0.1:21/hook", PolicyErrorCode.INVALID_SCHEME),
        ("http://user:secret@127.0.0.1:8443/hook", PolicyErrorCode.USERINFO_FORBIDDEN),
        ("http://127.0.0.1:8443/hook#fragment", PolicyErrorCode.FRAGMENT_FORBIDDEN),
        ("http://127.0.0.1:8443/hook#", PolicyErrorCode.FRAGMENT_FORBIDDEN),
        ("http://127.0.0.1:08443/hook", PolicyErrorCode.INVALID_PORT),
        ("http://127.0.0.1:/hook", PolicyErrorCode.INVALID_PORT),
        ("http://127.0.0.1:65536/hook", PolicyErrorCode.INVALID_PORT),
        ("http://127.0.0.1%2f.example:8443/hook", PolicyErrorCode.INVALID_HOST),
        ("http://[127.0.0.1]:8443/hook", PolicyErrorCode.INVALID_HOST),
        ("http://::1:8443/hook", PolicyErrorCode.INVALID_HOST),
        ("http://[::1:8443/hook", PolicyErrorCode.INVALID_HOST),
        ("http://127.000.000.001:8443/hook", PolicyErrorCode.INVALID_HOST),
        ("http://2130706433:8443/hook", PolicyErrorCode.INVALID_HOST),
        ("http://0x7f000001:8443/hook", PolicyErrorCode.INVALID_HOST),
        ("http://localhost\\@public.example:8443/hook", PolicyErrorCode.INVALID_URL),
    ],
)
def test_rejects_unsupported_or_ambiguous_urls(
    url: str,
    code: PolicyErrorCode,
) -> None:
    with pytest.raises(DestinationPolicyError) as captured:
        parse_destination_policy(_receiver_with_unchecked_url(url))

    assert captured.value.code is code


@pytest.mark.parametrize("url", ["http://127.0.0.1:8443/hook", "http://[::1]:8443/hook"])
def test_default_profile_allows_loopback_literals(url: str) -> None:
    policy = parse_destination_policy(_receiver(url=url))
    authorized = authorize_resolved_addresses(policy)

    assert authorized.addresses[0].address_class is AddressClass.LOOPBACK


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.1:8443/hook",
        "http://172.16.0.1:8443/hook",
        "http://192.168.0.1:8443/hook",
        "http://93.184.216.34:8443/hook",
    ],
)
def test_default_profile_rejects_private_and_public_literals_before_resolution(
    url: str,
) -> None:
    with pytest.raises(DestinationPolicyError) as captured:
        parse_destination_policy(_receiver(url=url))

    assert captured.value.code is PolicyErrorCode.ADDRESS_PROFILE_MISMATCH


def test_default_profile_validates_every_hostname_answer() -> None:
    policy = parse_destination_policy(
        _receiver(url="http://LOCALHOST.:8443/hook"),
    )
    authorized = authorize_resolved_addresses(policy, ("::1", "127.0.0.2"))

    assert tuple(item.normalized for item in authorized.addresses) == ("127.0.0.2", "::1")

    with pytest.raises(DestinationPolicyError) as captured:
        authorize_resolved_addresses(policy, ("127.0.0.1", "192.168.0.2"))
    assert captured.value.code is PolicyErrorCode.ADDRESS_PROFILE_MISMATCH


def test_effective_default_port_must_be_explicitly_allowlisted() -> None:
    policy = parse_destination_policy(
        _receiver(url="http://127.0.0.1/hook", allowed_ports=[80]),
    )

    assert policy.destination.port == _HTTP_PORT
    assert policy.destination.normalized_url == "http://127.0.0.1:80/hook"

    with pytest.raises(DestinationPolicyError) as captured:
        parse_destination_policy(_receiver(url="http://127.0.0.1/hook", allowed_ports=[]))
    assert captured.value.code is PolicyErrorCode.PORT_NOT_ALLOWED


def test_private_profile_requires_exact_normalized_host_and_port() -> None:
    receiver = _receiver(
        url="http://RECEIVER.TEST.:8080/hook",
        target_profile="private-allowlist",
        allowed_hosts=["receiver.test"],
        allowed_ports=[8080],
    )
    policy = parse_destination_policy(receiver)
    authorized = authorize_resolved_addresses(policy, ("10.2.3.4", "fd00::1"))

    assert policy.destination.host == "receiver.test"
    assert {item.address_class for item in authorized.addresses} == {AddressClass.PRIVATE}


@pytest.mark.parametrize(
    ("allowed_hosts", "allowed_ports", "code"),
    [
        (["other.test"], [8080], PolicyErrorCode.HOST_NOT_ALLOWED),
        (["receiver.test"], [8081], PolicyErrorCode.PORT_NOT_ALLOWED),
    ],
)
def test_private_profile_rejects_unlisted_targets(
    allowed_hosts: list[str],
    allowed_ports: list[int],
    code: PolicyErrorCode,
) -> None:
    receiver = _receiver(
        url="http://receiver.test:8080/hook",
        target_profile="private-allowlist",
        allowed_hosts=allowed_hosts,
        allowed_ports=allowed_ports,
    )

    with pytest.raises(DestinationPolicyError) as captured:
        parse_destination_policy(receiver)
    assert captured.value.code is code


def test_private_profile_rejects_public_and_permanently_blocked_answers() -> None:
    policy = parse_destination_policy(
        _receiver(
            url="http://receiver.test:8080/hook",
            target_profile="private-allowlist",
            allowed_hosts=["receiver.test"],
            allowed_ports=[8080],
        )
    )

    with pytest.raises(DestinationPolicyError) as public:
        authorize_resolved_addresses(policy, ("10.0.0.1", "93.184.216.34"))
    assert public.value.code is PolicyErrorCode.ADDRESS_PROFILE_MISMATCH

    with pytest.raises(DestinationPolicyError) as metadata:
        authorize_resolved_addresses(policy, ("10.0.0.1", "169.254.169.254"))
    assert metadata.value.code is PolicyErrorCode.ADDRESS_BLOCKED


def test_private_profile_can_separately_allowlist_loopback() -> None:
    policy = parse_destination_policy(
        _receiver(
            url="http://127.0.0.1:8080/hook",
            target_profile="private-allowlist",
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[8080],
        )
    )

    assert authorize_resolved_addresses(policy).addresses[0].address_class is AddressClass.LOOPBACK


def test_public_profile_requires_all_gates_and_allows_public_unicast() -> None:
    receiver = _receiver(
        url="https://Events.Example.:443/hook",
        target_profile="public-authorized",
        allowed_hosts=["events.example"],
        allowed_ports=[443],
    )
    policy = parse_destination_policy(
        receiver,
        runtime_public_authorization="EVENTS.EXAMPLE.:443",
    )
    authorized = authorize_resolved_addresses(
        policy,
        ("2606:4700:4700::1111", "93.184.216.34"),
    )

    assert policy.destination.authority == "events.example:443"
    assert {item.address_class for item in authorized.addresses} == {AddressClass.PUBLIC}


@pytest.mark.parametrize(
    ("receiver_factory", "authorization", "expected_code"),
    [
        (
            lambda: _receiver(
                url="https://93.184.216.34:443/hook",
                target_profile="loopback",
                allowed_ports=[443],
            ),
            None,
            PolicyErrorCode.ADDRESS_PROFILE_MISMATCH,
        ),
        (
            lambda: _receiver(
                url="https://events.example:443/hook",
                target_profile="public-authorized",
                allowed_ports=[443],
            ),
            "events.example:443",
            PolicyErrorCode.HOST_NOT_ALLOWED,
        ),
        (
            lambda: _receiver(
                url="https://events.example:443/hook",
                target_profile="public-authorized",
                allowed_hosts=["events.example"],
                allowed_ports=[],
            ),
            "events.example:443",
            PolicyErrorCode.PORT_NOT_ALLOWED,
        ),
        (
            lambda: _receiver(
                url="https://events.example:443/hook",
                target_profile="public-authorized",
                allowed_hosts=["events.example"],
                allowed_ports=[443],
            ),
            None,
            PolicyErrorCode.PUBLIC_AUTHORIZATION_REQUIRED,
        ),
        (
            lambda: _receiver(
                url="https://events.example:443/hook",
                target_profile="public-authorized",
                allowed_hosts=["events.example"],
                allowed_ports=[443],
            ),
            "other.example:443",
            PolicyErrorCode.PUBLIC_AUTHORIZATION_MISMATCH,
        ),
        (
            lambda: _receiver(
                url="https://events.example:443/hook",
                target_profile="public-authorized",
                allowed_hosts=["events.example"],
                allowed_ports=[443],
                public_challenge_path="/challenge?ambiguous=true",
            ),
            "events.example:443",
            PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID,
        ),
        (
            lambda: _receiver(
                url="http://events.example:80/hook",
                target_profile="public-authorized",
                allowed_hosts=["events.example"],
                allowed_ports=[80],
            ),
            "events.example:80",
            PolicyErrorCode.PUBLIC_HTTPS_REQUIRED,
        ),
    ],
)
def test_omitting_each_public_gate_never_reaches_resolution_or_delivery(
    receiver_factory: Callable[[], ReceiverConfig],
    authorization: str | None,
    expected_code: PolicyErrorCode,
) -> None:
    resolver_calls: list[str] = []
    delivery_calls: list[str] = []

    def guarded_operation() -> None:
        policy = parse_destination_policy(
            receiver_factory(),
            runtime_public_authorization=authorization,
        )
        resolver_calls.append(policy.destination.host)
        delivery_calls.append(policy.destination.normalized_url)

    with pytest.raises(DestinationPolicyError) as captured:
        guarded_operation()

    assert captured.value.code is expected_code
    assert resolver_calls == []
    assert delivery_calls == []


def test_public_profile_rejects_private_or_mixed_dns_answers() -> None:
    policy = parse_destination_policy(
        _receiver(
            url="https://events.example:443/hook",
            target_profile="public-authorized",
            allowed_hosts=["events.example"],
            allowed_ports=[443],
        ),
        runtime_public_authorization="events.example:443",
    )

    with pytest.raises(DestinationPolicyError) as private:
        authorize_resolved_addresses(policy, ("10.0.0.1",))
    assert private.value.code is PolicyErrorCode.ADDRESS_PROFILE_MISMATCH

    with pytest.raises(DestinationPolicyError) as mixed:
        authorize_resolved_addresses(policy, ("93.184.216.34", "fe80::1"))
    assert mixed.value.code is PolicyErrorCode.ADDRESS_BLOCKED


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",  # noqa: S104
        "0.1.2.3",
        "100.64.0.1",
        "100.100.100.200",
        "168.63.129.16",
        "169.254.1.1",
        "169.254.169.254",
        "169.254.170.2",
        "192.0.0.1",
        "192.0.0.192",
        "192.0.2.1",
        "192.31.196.1",
        "192.52.193.1",
        "192.88.99.1",
        "192.175.48.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::192.0.2.1",
        "::ffff:127.0.0.1",
        "::ffff:8.8.8.8",
        "64:ff9b::c000:201",
        "64:ff9b:1::c000:201",
        "100::1",
        "100:0:0:1::1",
        "2001::1",
        "2001:2::1",
        "2001:db8::1",
        "2002::1",
        "2620:4f:8000::1",
        "3ffe::1",
        "3fff::1",
        "5f00::1",
        "fec0::1",
        "fe80::1",
        "ff02::1",
        "fd00:ec2::254",
        "fd20:ce::254",
    ],
)
def test_authoritative_special_address_corpus_is_permanently_blocked(address: str) -> None:
    classification = classify_address(address)

    assert classification.address_class is AddressClass.BLOCKED
    assert classification.blocked_reason is not None


@pytest.mark.parametrize("address", ["fe80::1%3", "2001:4860:4860::8888%ethernet"])
def test_scoped_ipv6_forms_are_permanently_blocked(address: str) -> None:
    classification = classify_address(address)

    assert classification.address_class is AddressClass.BLOCKED
    assert classification.blocked_reason is BlockedAddressReason.SCOPED


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("127.255.255.254", AddressClass.LOOPBACK),
        ("::1", AddressClass.LOOPBACK),
        ("10.255.255.255", AddressClass.PRIVATE),
        ("172.31.255.255", AddressClass.PRIVATE),
        ("192.168.255.255", AddressClass.PRIVATE),
        ("fdff:ffff::1", AddressClass.PRIVATE),
        ("8.8.8.8", AddressClass.PUBLIC),
        ("2001:4860:4860::8888", AddressClass.PUBLIC),
    ],
)
def test_address_class_boundaries(address: str, expected: AddressClass) -> None:
    assert classify_address(address).address_class is expected


@pytest.mark.parametrize(
    "address",
    ["", " 127.0.0.1", "127.0.0.1 ", "127.000.000.001", "[::1]", "fe80::1%%3"],
)
def test_malformed_address_candidates_fail_closed(address: str) -> None:
    with pytest.raises(ValueError, match="address candidate"):
        classify_address(address)


def test_idna_normalization_is_deterministic_and_rejects_ambiguous_mappings() -> None:
    assert normalize_host("BÜCHER.Example.") == "xn--bcher-kva.example"
    assert normalize_host("xn--bcher-kva.example") == "xn--bcher-kva.example"

    with pytest.raises(DestinationPolicyError) as mapped:
        normalize_host("faß.example")
    assert mapped.value.code is PolicyErrorCode.INVALID_HOST

    with pytest.raises(DestinationPolicyError) as decomposed:
        normalize_host("bu\u0308cher.example")
    assert decomposed.value.code is PolicyErrorCode.INVALID_HOST


def test_normalization_equivalent_allowlist_entries_are_rejected() -> None:
    receiver = _receiver(
        url="http://receiver.test:8080/hook",
        target_profile="private-allowlist",
        allowed_hosts=["RECEIVER.TEST", "receiver.test."],
        allowed_ports=[8080],
    )

    with pytest.raises(DestinationPolicyError) as captured:
        parse_destination_policy(receiver)
    assert captured.value.code is PolicyErrorCode.HOST_NOT_ALLOWED


def test_candidate_set_is_bounded_nonempty_and_literal_locked() -> None:
    hostname_policy = parse_destination_policy(_receiver(url="http://localhost:8443/hook"))
    with pytest.raises(DestinationPolicyError) as empty:
        authorize_resolved_addresses(hostname_policy, ())
    assert empty.value.code is PolicyErrorCode.ADDRESS_SET_INVALID

    with pytest.raises(DestinationPolicyError) as excessive:
        authorize_resolved_addresses(hostname_policy, ("127.0.0.1",) * 65)
    assert excessive.value.code is PolicyErrorCode.ADDRESS_SET_INVALID

    literal_policy = parse_destination_policy(_receiver(url="http://127.0.0.1:8443/hook"))
    with pytest.raises(DestinationPolicyError) as mismatch:
        authorize_resolved_addresses(literal_policy, ("127.0.0.2",))
    assert mismatch.value.code is PolicyErrorCode.ADDRESS_SET_INVALID


@pytest.mark.parametrize(
    "url",
    [
        "http://0x7f.0.0.1:8443/hook",
        "http://127.0x0.0.1:8443/hook",
        "http://127.0.0.0x1:8443/hook",
        "http://0177.0.0.1:8443/hook",
        "http://0xa9.0xfe.0xa9.0xfe:8443/hook",
        "http://2130706433:8443/hook",
        "http://0x7f000001:8443/hook",
    ],
)
def test_rejects_every_legacy_numeric_ipv4_authority_form(url: str) -> None:
    with pytest.raises(DestinationPolicyError) as captured:
        parse_destination_policy(_receiver_with_unchecked_url(url))

    assert captured.value.code is PolicyErrorCode.INVALID_HOST


@pytest.mark.parametrize(
    "address",
    [
        "1::1",
        "101::1",
        "200::1",
        "400::1",
        "800::1",
        "1000::1",
        "2d00::1",
        "3000::1",
        "3e00::1",
        "4000::1",
        "6000::1",
        "8000::1",
        "a000::1",
        "c000::1",
        "e000::1",
        "f000::1",
        "f800::1",
        "fe00::1",
    ],
)
def test_unallocated_or_reserved_ipv6_space_denies_by_default(address: str) -> None:
    classification = classify_address(address)

    assert classification.address_class is AddressClass.BLOCKED
    assert classification.blocked_reason is BlockedAddressReason.RESERVED


@pytest.mark.parametrize(
    "address",
    [
        "2001:200::1",
        "2003::1",
        "2400::1",
        "2410::1",
        "2600::1",
        "2610::1",
        "2620::1",
        "2630::1",
        "2800::1",
        "2a00::1",
        "2a10::1",
        "2c00::1",
    ],
)
def test_iana_allocated_ipv6_unicast_space_remains_public(address: str) -> None:
    assert classify_address(address).address_class is AddressClass.PUBLIC


def test_phase_objects_cannot_be_directly_constructed_or_replaced() -> None:
    policy = parse_destination_policy(
        _receiver(
            url="http://receiver.test:8080/hook",
            target_profile="private-allowlist",
            allowed_hosts=["receiver.test"],
            allowed_ports=[8080],
        )
    )
    authorized = authorize_resolved_addresses(policy, ("10.0.0.1",))

    with pytest.raises(TypeError, match="destination parsing"):
        ParsedDestination("http", "evil.test", 8080, "/hook", "", None)
    with pytest.raises(TypeError, match="destination parsing"):
        DestinationPolicy(
            policy.destination,
            TargetProfile.PRIVATE_ALLOWLIST,
            ("evil.test",),
            (8080,),
            "/challenge",
        )
    with pytest.raises(TypeError, match="address authorization"):
        AuthorizedDestination(policy, authorized.addresses)
    with pytest.raises(TypeError, match="destination parsing"):
        replace(policy.destination, host="evil.test")
    with pytest.raises(TypeError, match="destination parsing"):
        replace(policy, allowed_hosts=("evil.test",))
    with pytest.raises(TypeError, match="address authorization"):
        replace(authorized, addresses=())


def test_phase_two_rejects_mutated_or_deserialized_policy_provenance() -> None:
    policy = parse_destination_policy(
        _receiver(
            url="http://receiver.test:8080/hook",
            target_profile="private-allowlist",
            allowed_hosts=["receiver.test"],
            allowed_ports=[8080],
        )
    )

    copied_policy = copy.copy(policy)
    with pytest.raises(DestinationPolicyError) as copied:
        authorize_resolved_addresses(copied_policy, ("10.0.0.1",))
    assert copied.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID

    mutated_destination = copy.copy(policy.destination)
    object.__setattr__(mutated_destination, "host", "evil.test")
    mutated_policy = copy.copy(policy)
    object.__setattr__(mutated_policy, "destination", mutated_destination)
    with pytest.raises(DestinationPolicyError) as mutated:
        authorize_resolved_addresses(mutated_policy, ("10.0.0.1",))
    assert mutated.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID

    original_host = policy.destination.host
    try:
        object.__setattr__(policy.destination, "host", "evil.test")
        with pytest.raises(DestinationPolicyError) as original_mutated:
            authorize_resolved_addresses(policy, ("10.0.0.1",))
        assert original_mutated.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID
    finally:
        object.__setattr__(policy.destination, "host", original_host)

    deserialized_policy = pickle.loads(pickle.dumps(policy))  # noqa: S301
    with pytest.raises(DestinationPolicyError) as deserialized:
        authorize_resolved_addresses(deserialized_policy, ("10.0.0.1",))
    assert deserialized.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID


def test_copy_and_field_reconstruction_cannot_turn_loopback_into_public_authority() -> None:
    loopback = parse_destination_policy(
        _receiver(url="https://localhost:443/hook", allowed_ports=[443])
    )
    public = parse_destination_policy(
        _receiver(
            url="https://events.example:443/hook",
            target_profile="public-authorized",
            allowed_hosts=["events.example"],
            allowed_ports=[443],
        ),
        runtime_public_authorization="events.example:443",
    )
    forged = copy.copy(loopback)
    for name in (
        "destination",
        "target_profile",
        "allowed_hosts",
        "allowed_ports",
        "public_challenge_path",
    ):
        object.__setattr__(forged, name, getattr(public, name))

    with pytest.raises(DestinationPolicyError) as captured:
        authorize_resolved_addresses(forged, ("93.184.216.34",))
    assert captured.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID

    with pytest.raises(TypeError, match="destination parsing"):
        DestinationPolicy(*astuple(loopback))


def test_minted_destination_identity_cannot_be_swapped_or_reused() -> None:
    first = parse_destination_policy(
        _receiver(
            url="http://first.test:8080/hook",
            target_profile="private-allowlist",
            allowed_hosts=["first.test"],
            allowed_ports=[8080],
        )
    )
    second = parse_destination_policy(
        _receiver(
            url="http://second.test:8080/hook",
            target_profile="private-allowlist",
            allowed_hosts=["second.test"],
            allowed_ports=[8080],
        )
    )
    original_destination = first.destination
    try:
        object.__setattr__(first, "destination", second.destination)
        with pytest.raises(DestinationPolicyError) as swapped:
            authorize_resolved_addresses(first, ("10.0.0.1",))
        assert swapped.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID
    finally:
        object.__setattr__(first, "destination", original_destination)

    copied_destination = copy.copy(first.destination)
    try:
        object.__setattr__(first, "destination", copied_destination)
        with pytest.raises(DestinationPolicyError) as reused:
            authorize_resolved_addresses(first, ("10.0.0.1",))
        assert reused.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID
    finally:
        object.__setattr__(first, "destination", original_destination)

    assert authorize_resolved_addresses(first, ("10.0.0.1",)).addresses


def test_authorized_destination_boundary_rejects_copy_mutation_and_swaps() -> None:
    first_policy = parse_destination_policy(
        _receiver(
            url="http://first.test:8080/hook",
            target_profile="private-allowlist",
            allowed_hosts=["first.test"],
            allowed_ports=[8080],
        )
    )
    second_policy = parse_destination_policy(
        _receiver(
            url="http://second.test:8080/hook",
            target_profile="private-allowlist",
            allowed_hosts=["second.test"],
            allowed_ports=[8080],
        )
    )
    first = authorize_resolved_addresses(first_policy, ("10.0.0.1",))
    second = authorize_resolved_addresses(second_policy, ("10.0.0.2",))

    assert validate_authorized_destination(first) is first

    copied = copy.copy(first)
    with pytest.raises(DestinationPolicyError) as copied_error:
        validate_authorized_destination(copied)
    assert copied_error.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID

    deserialized = pickle.loads(pickle.dumps(first))  # noqa: S301
    with pytest.raises(DestinationPolicyError) as deserialized_error:
        validate_authorized_destination(deserialized)
    assert deserialized_error.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID

    original_policy = first.policy
    try:
        object.__setattr__(first, "policy", second.policy)
        with pytest.raises(DestinationPolicyError) as swapped_policy:
            validate_authorized_destination(first)
        assert swapped_policy.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID
    finally:
        object.__setattr__(first, "policy", original_policy)

    original_addresses = first.addresses
    try:
        object.__setattr__(first, "addresses", second.addresses)
        with pytest.raises(DestinationPolicyError) as swapped_addresses:
            validate_authorized_destination(first)
        assert swapped_addresses.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID
    finally:
        object.__setattr__(first, "addresses", original_addresses)

    rebuilt_addresses = tuple(copy.copy(address) for address in original_addresses)
    try:
        object.__setattr__(first, "addresses", rebuilt_addresses)
        with pytest.raises(DestinationPolicyError) as rebuilt:
            validate_authorized_destination(first)
        assert rebuilt.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID
    finally:
        object.__setattr__(first, "addresses", original_addresses)

    original_normalized = original_addresses[0].normalized
    try:
        object.__setattr__(original_addresses[0], "normalized", "10.0.0.2")
        with pytest.raises(DestinationPolicyError) as mutated:
            validate_authorized_destination(first)
        assert mutated.value.code is PolicyErrorCode.PREFLIGHT_CONFIGURATION_INVALID
    finally:
        object.__setattr__(
            original_addresses[0],
            "normalized",
            original_normalized,
        )

    assert validate_authorized_destination(first) is first


def test_authority_is_external_and_weak_lifecycle_cleanup_is_bounded() -> None:
    gc.collect()
    before = policy_module._authority_registry_size()  # pyright: ignore[reportPrivateUsage]
    policy = parse_destination_policy(_receiver(url="http://localhost:8443/hook"))
    authorized = authorize_resolved_addresses(policy, ("127.0.0.1",))
    references = (
        weakref.ref(policy.destination),
        weakref.ref(policy),
        weakref.ref(authorized),
    )

    assert policy_module._authority_registry_size() == before + 3  # pyright: ignore[reportPrivateUsage]
    assert not hasattr(policy.destination, "_provenance")
    assert not hasattr(policy, "_provenance")
    assert not hasattr(policy, "_bound_public_authorization")

    del authorized
    del policy
    gc.collect()

    assert all(reference() is None for reference in references)
    assert policy_module._authority_registry_size() == before  # pyright: ignore[reportPrivateUsage]


def test_phase_two_rejects_lie_about_candidate_sequence_length_under_hard_cap() -> None:
    policy = parse_destination_policy(_receiver(url="http://localhost:8443/hook"))

    class EmptyLiar(Sequence[str]):
        def __len__(self) -> int:
            return 1

        @overload
        def __getitem__(self, index: int) -> str: ...

        @overload
        def __getitem__(self, index: slice) -> Sequence[str]: ...

        def __getitem__(self, index: int | slice) -> str | Sequence[str]:
            raise IndexError(index)

    class UnboundedLiar(Sequence[str]):
        calls = 0

        def __len__(self) -> int:
            return 1

        @overload
        def __getitem__(self, index: int) -> str: ...

        @overload
        def __getitem__(self, index: slice) -> Sequence[str]: ...

        def __getitem__(self, index: int | slice) -> str | Sequence[str]:
            if isinstance(index, slice):
                return ()
            self.calls += 1
            return "127.0.0.1"

    with pytest.raises(DestinationPolicyError) as empty:
        authorize_resolved_addresses(policy, EmptyLiar())
    assert empty.value.code is PolicyErrorCode.ADDRESS_SET_INVALID

    unbounded = UnboundedLiar()
    with pytest.raises(DestinationPolicyError) as excessive:
        authorize_resolved_addresses(policy, unbounded)
    assert excessive.value.code is PolicyErrorCode.ADDRESS_SET_INVALID
    assert unbounded.calls <= MAX_RESOLVED_ADDRESSES + 1
