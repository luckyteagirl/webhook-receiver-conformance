"""Golden and property tests for the deterministic byte generator."""
# ruff: noqa: INP001

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TypedDict

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from webhook_receiver_conformance.determinism.generator import (
    ALGORITHM_ID,
    INITIAL_COUNTER,
    MESSAGE_DOMAIN_SEPARATOR,
    SEED_FINGERPRINT_DOMAIN_SEPARATOR,
    ContextGenerator,
    encode_context,
    normalize_text_seed,
    seed_fingerprint,
    validate_normalized_seed_hash,
)

GOLDEN_PATH = Path(__file__).parents[2] / "golden" / "prng-v1.json"
DETERMINISTIC_SETTINGS = settings(
    max_examples=100,
    derandomize=True,
    database=None,
)
MULTIBLOCK_DRAW_LENGTH = 65


class JitterArguments(TypedDict):
    """Typed keyword arguments for the stable jitter contract."""

    scenario_id: str
    planned_delivery_id: str
    attempt_ordinal: int
    jitter_policy_version: str
    magnitude_bound: int


def test_seed_normalization_and_fingerprint_domains() -> None:
    text_seed = "reproducible café seed"
    normalized = hashlib.sha256(text_seed.encode("utf-8")).digest()

    assert normalize_text_seed(text_seed) == normalized
    assert (
        seed_fingerprint(normalized)
        == hashlib.sha256(
            SEED_FINGERPRINT_DOMAIN_SEPARATOR + normalized,
        ).hexdigest()
    )
    assert ContextGenerator.from_text_seed(text_seed) == ContextGenerator.from_normalized_seed_hash(
        normalized
    )


@pytest.mark.parametrize("invalid", [b"", b"x" * 31, b"x" * 33])
def test_normalized_seed_hash_requires_exactly_32_bytes(invalid: bytes) -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        validate_normalized_seed_hash(invalid)


@pytest.mark.parametrize("invalid", ["hash", bytearray(32), memoryview(b"x" * 32)])
def test_normalized_seed_hash_requires_bytes(invalid: object) -> None:
    with pytest.raises(TypeError, match="must be bytes"):
        validate_normalized_seed_hash(invalid)  # type: ignore[arg-type]


def test_context_encoding_uses_utf8_uint32_big_endian_lengths() -> None:
    assert encode_context(("alpha", "β")) == (b"\x00\x00\x00\x05alpha\x00\x00\x00\x02\xce\xb2")


@pytest.mark.parametrize(
    ("context", "exception"),
    [
        ((), ValueError),
        (("",), ValueError),
        ("not-a-path", TypeError),
        ((b"bytes",), TypeError),
        ((1,), TypeError),
    ],
)
def test_context_rejects_malformed_paths(
    context: object,
    exception: type[Exception],
) -> None:
    with pytest.raises(exception):
        encode_context(context)  # type: ignore[arg-type]


@pytest.mark.parametrize("invalid", [-1, True, 1.5, "1"])
def test_draw_rejects_invalid_lengths(invalid: object) -> None:
    generator = ContextGenerator.from_text_seed("seed")
    with pytest.raises((TypeError, ValueError)):
        generator.draw_bytes(("bytes",), invalid)  # type: ignore[arg-type]


def test_draw_rejects_uint64_counter_overflow_before_allocating() -> None:
    generator = ContextGenerator.from_text_seed("seed")
    impossible_length = ((1 << 64) + 1) * hashlib.sha256().digest_size
    with pytest.raises(OverflowError, match="uint64 counter"):
        generator.draw_bytes(("bytes",), impossible_length)


def test_zero_length_and_multiblock_draws_are_exact_prefixes() -> None:
    generator = ContextGenerator.from_text_seed("seed")
    context = ("byte-draw", "multi-block")

    assert generator.draw_bytes(context, 0) == b""
    assert len(generator.draw_bytes(context, MULTIBLOCK_DRAW_LENGTH)) == MULTIBLOCK_DRAW_LENGTH
    assert generator.draw_bytes(context, MULTIBLOCK_DRAW_LENGTH)[:32] == generator.draw_bytes(
        context,
        32,
    )


def test_draws_are_order_independent_and_context_isolated() -> None:
    generator = ContextGenerator.from_text_seed("seed")
    stable_context = ("event", "stable", "payload")
    expected = generator.draw_bytes(stable_context, 48)

    generator.draw_bytes(("unrelated", "inserted"), 4096)
    generator.bounded_int(("another", "unrelated"), 0, 17)

    assert generator.draw_bytes(stable_context, 48) == expected
    assert generator.draw_bytes(("event", "other", "payload"), 48) != expected


@DETERMINISTIC_SETTINGS
@given(
    lower=st.integers(min_value=-(1 << 63), max_value=(1 << 63) - 1),
    span=st.integers(min_value=1, max_value=1 << 20),
    label=st.text(min_size=1, max_size=24),
)
def test_bounded_integer_property(lower: int, span: int, label: str) -> None:
    generator = ContextGenerator.from_text_seed("property seed")
    result = generator.bounded_int(("bounded-property", label), lower, lower + span)
    assert lower <= result < lower + span
    assert result == generator.bounded_int(
        ("bounded-property", label),
        lower,
        lower + span,
    )


@pytest.mark.parametrize(
    ("lower", "upper", "exception"),
    [
        (0, 0, ValueError),
        (1, 0, ValueError),
        (True, 2, TypeError),
        (0, False, TypeError),
        (0.0, 2, TypeError),
    ],
)
def test_bounded_integer_rejects_invalid_ranges(
    lower: object,
    upper: object,
    exception: type[Exception],
) -> None:
    generator = ContextGenerator.from_text_seed("seed")
    with pytest.raises(exception):
        generator.bounded_int(
            ("bounded",),
            lower,  # type: ignore[arg-type]
            upper,  # type: ignore[arg-type]
        )


@DETERMINISTIC_SETTINGS
@given(
    bound=st.integers(min_value=0, max_value=1 << 31),
    attempt=st.integers(min_value=0, max_value=(1 << 64) - 1),
)
def test_signed_jitter_property(bound: int, attempt: int) -> None:
    generator = ContextGenerator.from_text_seed("jitter property seed")
    result = generator.signed_retry_jitter(
        scenario_id="scenario_01",
        planned_delivery_id="delivery_01",
        attempt_ordinal=attempt,
        jitter_policy_version="jitter-policy-v1",
        magnitude_bound=bound,
    )
    assert -bound <= result <= bound


def test_jitter_is_task_order_independent() -> None:
    generator = ContextGenerator.from_text_seed("seed")
    arguments: JitterArguments = {
        "scenario_id": "scenario_01",
        "planned_delivery_id": "delivery_02",
        "attempt_ordinal": 3,
        "jitter_policy_version": "jitter-policy-v1",
        "magnitude_bound": 1_000_000,
    }
    expected = generator.signed_retry_jitter(**arguments)

    generator.signed_retry_jitter(
        scenario_id="scenario_unrelated",
        planned_delivery_id="delivery_unrelated",
        attempt_ordinal=0,
        jitter_policy_version="jitter-policy-v1",
        magnitude_bound=1_000_000,
    )
    assert generator.signed_retry_jitter(**arguments) == expected


@pytest.mark.parametrize(
    ("override", "exception"),
    [
        ({"scenario_id": ""}, ValueError),
        ({"planned_delivery_id": ""}, ValueError),
        ({"jitter_policy_version": ""}, ValueError),
        ({"attempt_ordinal": -1}, ValueError),
        ({"attempt_ordinal": 1 << 64}, OverflowError),
        ({"magnitude_bound": -1}, ValueError),
        ({"magnitude_bound": True}, TypeError),
    ],
)
def test_jitter_rejects_malformed_inputs(
    override: dict[str, object],
    exception: type[Exception],
) -> None:
    arguments: dict[str, object] = {
        "scenario_id": "scenario_01",
        "planned_delivery_id": "delivery_01",
        "attempt_ordinal": 0,
        "jitter_policy_version": "jitter-policy-v1",
        "magnitude_bound": 10,
    }
    arguments.update(override)
    generator = ContextGenerator.from_text_seed("seed")
    with pytest.raises(exception):
        generator.signed_retry_jitter(**arguments)  # type: ignore[arg-type]


def test_golden_prng_v1_vectors() -> None:
    golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    generator = ContextGenerator.from_text_seed(golden["text_seed"])

    assert golden["algorithm_id"] == ALGORITHM_ID
    assert golden["message_domain_separator_hex"] == MESSAGE_DOMAIN_SEPARATOR.hex()
    assert golden["initial_counter"] == INITIAL_COUNTER
    assert golden["counter_encoding"] == "uint64-big-endian"
    assert golden["context_encoding"] == "uint32-big-endian-length-plus-utf8"
    assert golden["normalized_seed_hash_hex"] == (generator.normalized_seed_hash.hex())
    assert golden["seed_fingerprint"] == generator.fingerprint
    assert golden["compatibility_review"]

    for vector in golden["byte_draws"]:
        assert (
            generator.draw_bytes(tuple(vector["context"]), vector["length"]).hex()
            == vector["output_hex"]
        )

    bounded = golden["bounded_rejection"]
    raw_candidates = generator.draw_bytes(
        tuple(bounded["context"]),
        bounded["candidate_width_bytes"] * len(bounded["candidates"]),
    )
    assert [
        int.from_bytes(
            raw_candidates[index : index + bounded["candidate_width_bytes"]],
            "big",
        )
        for index in range(
            0,
            len(raw_candidates),
            bounded["candidate_width_bytes"],
        )
    ] == bounded["candidates"]
    assert (
        generator.bounded_int(
            tuple(bounded["context"]),
            bounded["lower"],
            bounded["upper"],
        )
        == bounded["result"]
    )

    for vector in golden["jitter"]:
        assert (
            generator.signed_retry_jitter(
                scenario_id=vector["scenario_id"],
                planned_delivery_id=vector["planned_delivery_id"],
                attempt_ordinal=vector["attempt_ordinal"],
                jitter_policy_version=vector["jitter_policy_version"],
                magnitude_bound=vector["magnitude_bound"],
            )
            == vector["result"]
        )
