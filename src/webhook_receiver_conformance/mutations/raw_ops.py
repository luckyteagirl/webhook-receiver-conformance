"""Versioned bounded raw-body and content-header mutation operators."""
# ruff: noqa: INP001

from __future__ import annotations

from typing import Final, cast

from webhook_receiver_conformance.mutations.base import (
    MutationError,
    MutationInput,
    MutationOutput,
    MutationRegistration,
    MutationStage,
    StaticMutationRegistry,
    thaw_parameter_object,
)
from webhook_receiver_conformance.signatures.base import MAX_SIGNING_BODY_BYTES, SignatureHeader

OPERATOR_VERSION: Final = 1
CONTROL_CHARACTER_LIMIT: Final = 32
DELETE_CHARACTER_CODEPOINT: Final = 127
TRUNCATE_BYTES_V1: Final = "truncate-bytes-v1"
INVALID_JSON_V1: Final = "invalid-json-v1"
CONTENT_TYPE_MISMATCH_V1: Final = "content-type-mismatch-v1"
ALTER_AFTER_SIGNING_V1: Final = "alter-after-signing-v1"
OVERSIZED_BODY_V1: Final = "oversized-body-v1"
INVALID_JSON_CASES: Final = (
    "truncated-object",
    "bad-escape",
    "trailing-comma",
)
_INVALID_JSON_BYTES: Final = {
    "truncated-object": b'{"_":',
    "bad-escape": b'"\\x"',
    "trailing-comma": b'{"_":0,}',
}


def _parameters(
    mutation_input: MutationInput,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, object]:
    values = cast(
        "dict[str, object]",
        thaw_parameter_object(mutation_input.parameters),
    )
    if set(values) - required - optional or not required.issubset(values):
        raise _invalid(
            mutation_input,
            "MUT_RAW_PARAMETERS_INVALID",
            "The realized raw mutation parameters do not match the operator contract.",
        )
    return values


def _integer(
    mutation_input: MutationInput,
    value: object,
    *,
    code: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _invalid(
            mutation_input,
            code,
            "The realized integer parameter is outside its bounded range.",
        )
    return value


def _text(
    mutation_input: MutationInput,
    value: object,
    *,
    code: str,
    maximum: int = 255,
) -> str:
    is_ascii = False
    if type(value) is str:
        try:
            value.encode("ascii")
        except UnicodeEncodeError:
            pass
        else:
            is_ascii = True
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or not is_ascii
        or any(
            ord(character) < CONTROL_CHARACTER_LIMIT or ord(character) == DELETE_CHARACTER_CODEPOINT
            for character in value
        )
    ):
        raise _invalid(
            mutation_input,
            code,
            "The realized text parameter is invalid.",
        )
    return value


def _invalid(
    mutation_input: MutationInput,
    code: str,
    message: str,
) -> MutationError:
    realized = mutation_input.realized
    return MutationError.invalid_parameter(
        code,
        message,
        operator_id=realized.operator_id,
        operator_version=realized.operator_version,
    )


def _not_applicable(
    mutation_input: MutationInput,
    code: str,
    message: str,
) -> MutationError:
    realized = mutation_input.realized
    return MutationError.not_applicable(
        code,
        message,
        operator_id=realized.operator_id,
        operator_version=realized.operator_version,
    )


def _output(
    mutation_input: MutationInput,
    *,
    body: bytes | None = None,
    headers: tuple[SignatureHeader, ...] | None = None,
) -> MutationOutput:
    state = mutation_input.state
    return MutationOutput(
        body=state.body if body is None else body,
        headers=state.headers if headers is None else headers,
        signing_time_ns=state.signing_time_ns,
        signer=state.signer,
    )


class TruncateBytesV1:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        values = _parameters(mutation_input, required=frozenset({"length"}))
        retained = _integer(
            mutation_input,
            values["length"],
            code="MUT_TRUNCATE_LENGTH_INVALID",
            minimum=0,
            maximum=len(mutation_input.state.body),
        )
        return _output(mutation_input, body=mutation_input.state.body[:retained])


class InvalidJsonV1:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        values = _parameters(mutation_input, required=frozenset({"strategy"}))
        strategy = values["strategy"]
        if type(strategy) is not str or strategy not in _INVALID_JSON_BYTES:
            raise _invalid(
                mutation_input,
                "MUT_INVALID_JSON_CASE_INVALID",
                "The invalid-json catalog case is unknown.",
            )
        base_type = mutation_input.media_type.partition(";")[0].strip().casefold()
        if base_type != "application/json" and not base_type.endswith("+json"):
            raise _not_applicable(
                mutation_input,
                "MUT_INVALID_JSON_MEDIA_TYPE",
                "invalid-json-v1 requires a declared JSON media type.",
            )
        return _output(mutation_input, body=_INVALID_JSON_BYTES[strategy])


class ContentTypeMismatchV1:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        values = _parameters(mutation_input, required=frozenset({"media_type"}))
        media_type = _text(
            mutation_input,
            values["media_type"],
            code="MUT_CONTENT_TYPE_INVALID",
        )
        headers = tuple(
            header for header in mutation_input.state.headers if header.name != "content-type"
        )
        return _output(
            mutation_input,
            headers=(*headers, SignatureHeader(name="content-type", value=media_type)),
        )


class AlterAfterSigningV1:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        values = _parameters(
            mutation_input,
            required=frozenset({"offset", "xor"}),
        )
        body = mutation_input.state.body
        offset = _integer(
            mutation_input,
            values["offset"],
            code="MUT_ALTER_OFFSET_INVALID",
            minimum=0,
            maximum=max(0, len(body) - 1),
        )
        if not body:
            raise _not_applicable(
                mutation_input,
                "MUT_ALTER_EMPTY_BODY",
                "alter-after-signing-v1 cannot alter an empty body.",
            )
        xor = _integer(
            mutation_input,
            values["xor"],
            code="MUT_ALTER_XOR_INVALID",
            minimum=1,
            maximum=255,
        )
        changed = bytearray(body)
        changed[offset] ^= xor
        return _output(mutation_input, body=bytes(changed))


class OversizedBodyV1:
    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        values = _parameters(
            mutation_input,
            required=frozenset({"target_bytes", "fill"}),
        )
        target = _integer(
            mutation_input,
            values["target_bytes"],
            code="MUT_OVERSIZED_TARGET_INVALID",
            minimum=1,
            maximum=MAX_SIGNING_BODY_BYTES,
        )
        if values["fill"] != "ascii-space":
            raise _invalid(
                mutation_input,
                "MUT_OVERSIZED_FILL_INVALID",
                "The oversized-body fill strategy is unknown.",
            )
        if target <= len(mutation_input.state.body):
            raise _not_applicable(
                mutation_input,
                "MUT_OVERSIZED_TARGET_NOT_LARGER",
                "The oversized target must exceed the current body length.",
            )
        return _output(
            mutation_input,
            body=mutation_input.state.body + b" " * (target - len(mutation_input.state.body)),
        )


RAW_MUTATION_REGISTRATIONS: Final = (
    MutationRegistration(
        operator_id=TRUNCATE_BYTES_V1,
        operator_version=OPERATOR_VERSION,
        stage=MutationStage.RAW_PRE_SIGN,
        implementation=TruncateBytesV1(),
        changes_body=True,
    ),
    MutationRegistration(
        operator_id=INVALID_JSON_V1,
        operator_version=OPERATOR_VERSION,
        stage=MutationStage.RAW_PRE_SIGN,
        implementation=InvalidJsonV1(),
        changes_body=True,
        invalidates_json=True,
    ),
    MutationRegistration(
        operator_id=CONTENT_TYPE_MISMATCH_V1,
        operator_version=OPERATOR_VERSION,
        stage=MutationStage.HEADER_PRE_SIGN,
        implementation=ContentTypeMismatchV1(),
        written_headers=("content-type",),
    ),
    MutationRegistration(
        operator_id=ALTER_AFTER_SIGNING_V1,
        operator_version=OPERATOR_VERSION,
        stage=MutationStage.RAW_POST_SIGN,
        implementation=AlterAfterSigningV1(),
        changes_body=True,
    ),
    MutationRegistration(
        operator_id=OVERSIZED_BODY_V1,
        operator_version=OPERATOR_VERSION,
        stage=MutationStage.RAW_PRE_SIGN,
        implementation=OversizedBodyV1(),
        changes_body=True,
    ),
)
RAW_MUTATION_REGISTRY: Final = StaticMutationRegistry(RAW_MUTATION_REGISTRATIONS)

__all__ = [
    "ALTER_AFTER_SIGNING_V1",
    "CONTENT_TYPE_MISMATCH_V1",
    "INVALID_JSON_CASES",
    "INVALID_JSON_V1",
    "OVERSIZED_BODY_V1",
    "RAW_MUTATION_REGISTRATIONS",
    "RAW_MUTATION_REGISTRY",
    "TRUNCATE_BYTES_V1",
]
