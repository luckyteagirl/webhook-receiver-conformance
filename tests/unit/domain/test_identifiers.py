"""Contract tests for identifier and canonical-hashing primitives."""
# ruff: noqa: INP001

from __future__ import annotations

import re
from typing import cast

import pytest

from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.hashing import (
    canonical_json_bytes,
    canonical_manifest_bytes,
    compute_manifest_id,
    sha256_digest,
    validate_manifest_id,
    validate_sha256_digest,
)
from webhook_receiver_conformance.domain.identifiers import (
    PLANNED_ID_ALGORITHM,
    FreshIdKind,
    IdentifierCollisionError,
    PlannedIdKind,
    PlannedIdRegistry,
    decode_crockford_ulid,
    encode_crockford_ulid,
    new_fresh_id,
    new_run_id,
    parse_fresh_id,
    parse_planned_id,
    planned_id,
    validate_fresh_id,
    validate_planned_id,
    validate_run_id,
)

UUID_V4_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
SHA256_EMPTY = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
FRESH_ID_SAMPLE_SIZE = 100
UNICODE_NATURAL_KEY_VARIANTS = 3
SHA256_HEX_LENGTH = 64


def test_run_ids_are_independent_canonical_uuid_v4_values() -> None:
    run_ids = {new_run_id() for _ in range(FRESH_ID_SAMPLE_SIZE)}
    assert len(run_ids) == FRESH_ID_SAMPLE_SIZE
    assert all(UUID_V4_PATTERN.fullmatch(run_id) for run_id in run_ids)
    assert all(validate_run_id(run_id) == run_id for run_id in run_ids)


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "550e8400-e29b-41d4-a716-446655440000".upper(),
        "550e8400-e29b-11d4-a716-446655440000",
        "550e8400e29b41d4a716446655440000",
        "not-a-uuid",
    ],
)
def test_run_id_validation_rejects_noncanonical_or_non_v4_values(invalid: str) -> None:
    with pytest.raises(ValueError, match="UUIDv4"):
        validate_run_id(invalid)


def test_prefixed_and_manifest_digest_encodings_are_distinct() -> None:
    assert sha256_digest(b"") == SHA256_EMPTY
    assert validate_sha256_digest(SHA256_EMPTY) == SHA256_EMPTY
    raw_manifest_id = SHA256_EMPTY.removeprefix("sha256:")
    assert validate_manifest_id(raw_manifest_id) == raw_manifest_id
    with pytest.raises(ValueError, match="manifest_id"):
        validate_manifest_id(SHA256_EMPTY)
    with pytest.raises(ValueError, match="SHA-256 digest"):
        validate_sha256_digest(raw_manifest_id)


@pytest.mark.parametrize(
    "invalid",
    [
        "sha256:" + ("A" * 64),
        "sha256:" + ("0" * 63),
        "sha512:" + ("0" * 64),
        "0" * 64,
    ],
)
def test_prefixed_digest_validation_is_strict(invalid: str) -> None:
    with pytest.raises(ValueError, match="SHA-256 digest"):
        validate_sha256_digest(invalid)


def test_crockford_ulid_encoding_round_trips_boundaries() -> None:
    zero = bytes(16)
    maximum = b"\xff" * 16
    assert encode_crockford_ulid(zero) == "0" * 26
    assert encode_crockford_ulid(maximum) == "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
    assert decode_crockford_ulid(encode_crockford_ulid(zero)) == zero
    assert decode_crockford_ulid(encode_crockford_ulid(maximum)) == maximum


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "0" * 25,
        "8" + ("0" * 25),
        "0" * 25 + "I",
        "0" * 25 + "l",
        "0" * 25 + "u",
    ],
)
def test_crockford_ulid_rejects_wrong_length_alphabet_or_overflow(invalid: str) -> None:
    with pytest.raises(ValueError, match="ULID payload"):
        decode_crockford_ulid(invalid)


def test_planned_ids_are_versioned_typed_and_stable() -> None:
    generator = ContextGenerator.from_text_seed("stable planned identifier seed")
    expected = {
        PlannedIdKind.SCENARIO: "scenario_59AHMVKBWNKZV329G8TQGM4W6V",
        PlannedIdKind.EVENT: "event_3YBEFHZSXZ4T5J5K6H5QFTAYC8",
        PlannedIdKind.DELIVERY: "delivery_06Z59A112RQWQJTD5N885H4AGZ",
        PlannedIdKind.ATTEMPT_PLAN: "attempt_plan_7P1DX52XZRA0Y6KWX5X6TD48F6",
        PlannedIdKind.OBSERVATION: "observation_7CA03AVSWHSE0F7VZMZ6K4E8GC",
        PlannedIdKind.ASSERTION: "assertion_4X56T78WF3NCMPSM8TNBTYVZNN",
    }
    assert PLANNED_ID_ALGORITHM == "planned-id-v1"
    assert len(set(expected.values())) == len(PlannedIdKind)
    for kind, identifier in expected.items():
        assert identifier.startswith(f"{kind.value}_")
        assert validate_planned_id(identifier, expected_kind=kind) == identifier
        assert parse_planned_id(identifier)[0] is kind
        assert planned_id(generator, kind, ("checkout", "ordinal:0")) == identifier


def test_unrelated_entity_insertion_does_not_change_planned_ids() -> None:
    generator = ContextGenerator.from_text_seed("stable planned identifier seed")
    natural_key = ("checkout", "event:payment-succeeded")
    expected = planned_id(generator, PlannedIdKind.EVENT, natural_key)

    for ordinal in reversed(range(100)):
        planned_id(
            generator,
            PlannedIdKind.EVENT,
            ("unrelated", f"event:{ordinal}"),
        )

    assert planned_id(generator, PlannedIdKind.EVENT, natural_key) == expected


@pytest.mark.parametrize(
    "natural_key",
    [
        (),
        ("",),
        ("\ud800",),
        ("x" * 4097,),
        ("valid", 1),
    ],
)
def test_planned_id_rejects_malformed_natural_keys(natural_key: object) -> None:
    generator = ContextGenerator.from_text_seed("seed")
    with pytest.raises((TypeError, ValueError)):
        planned_id(
            generator,
            PlannedIdKind.EVENT,
            natural_key,  # type: ignore[arg-type]
        )


def test_planned_id_natural_keys_use_exact_utf8_without_normalization() -> None:
    generator = ContextGenerator.from_text_seed("seed")
    composed = planned_id(generator, PlannedIdKind.EVENT, ("café",))
    decomposed = planned_id(generator, PlannedIdKind.EVENT, ("cafe\u0301",))
    with_spaces = planned_id(generator, PlannedIdKind.EVENT, ("Payment Succeeded",))
    assert composed != decomposed
    assert len({composed, decomposed, with_spaces}) == UNICODE_NATURAL_KEY_VARIANTS


def test_planned_and_fresh_identifier_namespaces_are_not_interchangeable() -> None:
    generator = ContextGenerator.from_text_seed("seed")
    stable = planned_id(generator, PlannedIdKind.ATTEMPT_PLAN, ("delivery:0", "attempt:1"))
    fresh = new_fresh_id(FreshIdKind.ATTEMPT)

    with pytest.raises(ValueError, match="physical-entity"):
        parse_planned_id(fresh)
    with pytest.raises(ValueError, match="planned-entity"):
        parse_fresh_id(stable)
    with pytest.raises(ValueError, match="scenario_"):
        validate_planned_id(stable, expected_kind=PlannedIdKind.SCENARIO)


def test_physical_and_evidence_ids_are_fresh_and_typed() -> None:
    identifiers = {
        kind: {new_fresh_id(kind) for _ in range(FRESH_ID_SAMPLE_SIZE)} for kind in FreshIdKind
    }
    assert all(len(values) == FRESH_ID_SAMPLE_SIZE for values in identifiers.values())
    all_identifiers: set[str] = set()
    for values in identifiers.values():
        all_identifiers.update(values)
    assert len(all_identifiers) == FRESH_ID_SAMPLE_SIZE * len(FreshIdKind)
    for kind, values in identifiers.items():
        for identifier in values:
            assert validate_fresh_id(identifier, expected_kind=kind) == identifier
            assert parse_fresh_id(identifier)[0] is kind


def test_collision_registry_allows_idempotence_but_rejects_distinct_claims() -> None:
    generator = ContextGenerator.from_text_seed("seed")
    identifier = planned_id(generator, PlannedIdKind.ASSERTION, ("scenario:0", "assertion:0"))
    registry = PlannedIdRegistry()
    registry.claim(identifier, ("scenario:0", "assertion:0"))
    registry.claim(identifier, ("scenario:0", "assertion:0"))
    with pytest.raises(IdentifierCollisionError, match=re.escape(identifier)):
        registry.claim(identifier, ("scenario:0", "assertion:1"))


def test_canonical_json_cross_language_vector() -> None:
    # RFC 8785 property sorting is by UTF-16 code units, so the astral key sorts
    # before U+E000 even though Python code-point ordering does not.
    value = cast(
        "object",
        {
            "\ue000": "private-use",
            "\U0001f600": "grin",
            "controls": '\b\t\n\f\r\u000f"\\/',
            "integer": 9007199254740991,
            "array": [True, False, None, -9007199254740991],
        },
    )
    canonical = (
        b'{"array":[true,false,null,-9007199254740991],'
        b'"controls":"\\b\\t\\n\\f\\r\\u000f\\"\\\\/",'
        b'"integer":9007199254740991,'
        b'"\xf0\x9f\x98\x80":"grin","\xee\x80\x80":"private-use"}'
    )
    assert canonical_json_bytes(value) == canonical  # type: ignore[arg-type]
    assert (
        sha256_digest(canonical)
        == "sha256:db199e8275e6f3f4be5df82eec29736ad8cb60d66164b3efff54034eb5928d15"
    )


def test_canonical_manifest_is_insertion_order_independent_and_omits_root_id() -> None:
    first = {
        "schema_version": "1.0",
        "manifest_id": "0" * 64,
        "nested": {"z": 2, "a": 1, "manifest_id": "nested-value-is-retained"},
    }
    second = {
        "nested": {"manifest_id": "nested-value-is-retained", "a": 1, "z": 2},
        "manifest_id": "f" * 64,
        "schema_version": "1.0",
    }
    assert canonical_manifest_bytes(first) == canonical_manifest_bytes(second)
    expected_id = "b2e83e5ae4bc32617824b21f58e1d933f9772aa237da7eca164af71fbdf0cb6c"
    assert compute_manifest_id(first) == compute_manifest_id(second) == expected_id
    assert len(compute_manifest_id(first)) == SHA256_HEX_LENGTH
    assert re.fullmatch(r"[0-9a-f]{64}", compute_manifest_id(first))


def test_manifest_rejects_execution_identity_and_reference_cycles() -> None:
    with pytest.raises(ValueError, match="must not appear"):
        canonical_manifest_bytes({"schema_version": "1.0", "run_id": new_run_id()})

    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    with pytest.raises(ValueError, match="reference cycles"):
        canonical_manifest_bytes({"schema_version": "1.0", "value": cyclic})


def test_replay_run_ids_are_fresh_while_plan_identity_is_unchanged() -> None:
    immutable_plan = {
        "schema_version": "1.0",
        "scenarios": [{"scenario_id": "scenario_00000000000000000000000000"}],
    }
    manifest_id = compute_manifest_id(immutable_plan)
    first_run_id = new_run_id()
    second_run_id = new_run_id()
    assert first_run_id != second_run_id
    assert compute_manifest_id(immutable_plan) == manifest_id


@pytest.mark.parametrize(
    ("value", "exception"),
    [
        (1.0, TypeError),
        (float("nan"), TypeError),
        (float("inf"), TypeError),
        (-(1 << 53), ValueError),
        (1 << 53, ValueError),
        ("\ud800", ValueError),
        ({"bad": "\udfff"}, ValueError),
        ({"\ud800": "bad-key"}, ValueError),
        ({1: "non-string-key"}, TypeError),
        (b"bytes", TypeError),
    ],
)
def test_canonical_json_rejects_values_outside_lossless_manifest_domain(
    value: object,
    exception: type[Exception],
) -> None:
    with pytest.raises(exception):
        canonical_json_bytes(cast("object", value))  # type: ignore[arg-type]


def test_bool_is_encoded_as_json_boolean_not_integer() -> None:
    assert canonical_json_bytes({"false": False, "true": True}) == (b'{"false":false,"true":true}')
