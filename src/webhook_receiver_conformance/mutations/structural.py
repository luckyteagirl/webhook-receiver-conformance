"""Strict deterministic structural JSON mutation operators."""
# ruff: noqa: C901, EM101, INP001, PLR0912, TRY003

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final, NoReturn, cast

from webhook_receiver_conformance.domain.hashing import (
    CanonicalJson,
    canonical_json_bytes,
)
from webhook_receiver_conformance.mutations.base import (
    MAX_PARAMETER_COLLECTION_ITEMS,
    MAX_PARAMETER_DEPTH,
    MAX_PARAMETER_KEY_LENGTH,
    MAX_PARAMETER_NODES,
    MAX_PARAMETER_STRING_LENGTH,
    MutationError,
    MutationInput,
    MutationOutput,
    MutationRegistration,
    MutationStage,
    StaticMutationRegistry,
    thaw_parameter_object,
)
from webhook_receiver_conformance.signatures.base import MAX_SIGNING_BODY_BYTES

if TYPE_CHECKING:
    from collections.abc import Callable

    from webhook_receiver_conformance.types import JsonObject

JSON_COMPACT_UTF8_V1: Final = "json-compact-utf8-v1"
STRUCTURAL_OPERATOR_VERSION: Final = 1

REMOVE_JSON_POINTER_V1: Final = "remove-json-pointer-v1"
REPLACE_JSON_VALUE_V1: Final = "replace-json-value-v1"
REPLACE_JSON_TYPE_V1: Final = "replace-json-type-v1"
ADD_JSON_FIELD_V1: Final = "add-json-field-v1"
CHANGE_EVENT_ID_FIELD_V1: Final = "change-event-id-field-v1"
CHANGE_EVENT_TYPE_FIELD_V1: Final = "change-event-type-field-v1"

_SAFE_INTEGER_MAX: Final = (1 << 53) - 1
_SAFE_INTEGER_DIGITS: Final = 16
_MAX_ARRAY_INDEX_DIGITS: Final = len(str(MAX_PARAMETER_COLLECTION_ITEMS))
_SURROGATE_MIN: Final = 0xD800
_SURROGATE_MAX: Final = 0xDFFF
_TARGET_TYPES: Final = frozenset({"null", "boolean", "integer", "string", "array", "object"})

type _JsonContainer = list[CanonicalJson] | dict[str, CanonicalJson]


class _DuplicateMemberError(ValueError):
    __slots__ = ()


class _UnsupportedNumberError(ValueError):
    __slots__ = ()


class _UnsupportedUnicodeError(ValueError):
    __slots__ = ()


class _UnsupportedJsonShapeError(ValueError):
    __slots__ = ()


class _JsonResourceError(ValueError):
    __slots__ = ()


class _PointerSyntaxError(ValueError):
    __slots__ = ()


class _PointerArrayIndexError(ValueError):
    __slots__ = ()


class _PointerMissingError(LookupError):
    __slots__ = ()


def serialize_json_compact_utf8_v1(value: object) -> bytes:
    """Serialize the bounded lossless JSON domain with the v1 byte contract.

    The byte contract is compact UTF-8 without a BOM, uses the repository's
    UTF-16 code-unit key order, preserves Unicode scalar values as UTF-8, and
    accepts only booleans, safe integers, strings, arrays, objects, and null.
    """
    validated = _validate_json_tree(value)
    _measure_encoded_size(validated, remaining=MAX_SIGNING_BODY_BYTES)
    return canonical_json_bytes(validated)


def _parse_structural_json(
    mutation_input: MutationInput,
) -> CanonicalJson:
    body = mutation_input.state.body
    if len(body) > MAX_SIGNING_BODY_BYTES:
        raise MutationError.resource_limit(
            "MUT_STRUCTURAL_JSON_BODY_LIMIT",
            "Structural JSON input exceeds the hard body-size limit.",
        )
    try:
        decoded = body.decode("utf-8")
        parsed = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_int=_lossless_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_constant,
        )
        return _validate_json_tree(parsed)
    except _DuplicateMemberError:
        raise _not_applicable(
            mutation_input,
            "MUT_STRUCTURAL_JSON_DUPLICATE_MEMBER",
            "Structural JSON does not permit duplicate object member names.",
        ) from None
    except _UnsupportedNumberError:
        raise _not_applicable(
            mutation_input,
            "MUT_STRUCTURAL_JSON_NUMBER_UNSUPPORTED",
            "Structural JSON requires lossless safe-integer numbers.",
        ) from None
    except _UnsupportedUnicodeError:
        raise _not_applicable(
            mutation_input,
            "MUT_STRUCTURAL_JSON_UNICODE_UNSUPPORTED",
            "Structural JSON strings must contain Unicode scalar values.",
        ) from None
    except _JsonResourceError:
        raise MutationError.resource_limit(
            "MUT_STRUCTURAL_JSON_RESOURCE_LIMIT",
            "Structural JSON exceeds a hard resource limit.",
        ) from None
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _UnsupportedJsonShapeError,
        RecursionError,
    ):
        raise _not_applicable(
            mutation_input,
            "MUT_STRUCTURAL_JSON_UNSUPPORTED",
            "Structural mutation input is not supported JSON.",
        ) from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateMemberError
        result[key] = value
    return result


def _lossless_integer(token: str) -> int:
    digit_count = len(token) - int(token.startswith("-"))
    if digit_count > _SAFE_INTEGER_DIGITS:
        raise _UnsupportedNumberError
    try:
        value = int(token)
    except ValueError:
        raise _UnsupportedNumberError from None
    if not -_SAFE_INTEGER_MAX <= value <= _SAFE_INTEGER_MAX:
        raise _UnsupportedNumberError
    return value


def _unsupported_number(_token: str) -> NoReturn:
    raise _UnsupportedNumberError


def _unsupported_constant(_token: str) -> NoReturn:
    raise _UnsupportedNumberError


def _validate_json_tree(value: object) -> CanonicalJson:
    stack: list[tuple[object, int, bool]] = [(value, 1, False)]
    active_containers: set[int] = set()
    nodes = 0
    while stack:
        current, depth, exiting = stack.pop()
        if exiting:
            active_containers.remove(id(current))
            continue
        nodes += 1
        if nodes > MAX_PARAMETER_NODES:
            raise _JsonResourceError
        if depth > MAX_PARAMETER_DEPTH:
            raise _JsonResourceError
        if current is None or type(current) is bool:
            continue
        if type(current) is int:
            if not -_SAFE_INTEGER_MAX <= current <= _SAFE_INTEGER_MAX:
                raise _UnsupportedNumberError
            continue
        if type(current) is float:
            raise _UnsupportedNumberError
        if type(current) is str:
            _validate_json_string(current, maximum=MAX_PARAMETER_STRING_LENGTH)
            continue
        if type(current) is list:
            sequence = cast("list[object]", current)
            if len(sequence) > MAX_PARAMETER_COLLECTION_ITEMS:
                raise _JsonResourceError
            _enter_container(
                sequence,
                depth=depth,
                children=tuple(sequence),
                stack=stack,
                active_containers=active_containers,
            )
            continue
        if type(current) is dict:
            mapping = cast("dict[object, object]", current)
            if len(mapping) > MAX_PARAMETER_COLLECTION_ITEMS:
                raise _JsonResourceError
            children: list[object] = []
            for key, item in mapping.items():
                if type(key) is not str:
                    raise _UnsupportedJsonShapeError
                _validate_json_string(key, maximum=MAX_PARAMETER_KEY_LENGTH)
                children.append(item)
            _enter_container(
                mapping,
                depth=depth,
                children=tuple(children),
                stack=stack,
                active_containers=active_containers,
            )
            continue
        raise _UnsupportedJsonShapeError
    return cast("CanonicalJson", value)


def _enter_container(
    container: object,
    *,
    depth: int,
    children: tuple[object, ...],
    stack: list[tuple[object, int, bool]],
    active_containers: set[int],
) -> None:
    marker = id(container)
    if marker in active_containers:
        raise _UnsupportedJsonShapeError
    active_containers.add(marker)
    stack.append((container, depth, True))
    stack.extend((child, depth + 1, False) for child in reversed(children))


def _validate_json_string(value: str, *, maximum: int) -> None:
    if len(value) > maximum:
        raise _JsonResourceError
    if any(_SURROGATE_MIN <= ord(character) <= _SURROGATE_MAX for character in value):
        raise _UnsupportedUnicodeError


def _measure_encoded_size(
    value: CanonicalJson,
    *,
    remaining: int,
) -> int:
    if value is None or value is True:
        size = 4
    elif value is False:
        size = 5
    elif type(value) is int:
        size = len(str(value))
    elif type(value) is str:
        size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    elif type(value) is list:
        sequence = cast("list[CanonicalJson]", value)
        size = 2 + max(0, len(sequence) - 1)
        if size > remaining:
            raise _JsonResourceError
        for item in sequence:
            size += _measure_encoded_size(item, remaining=remaining - size)
        return size
    else:
        mapping = cast("dict[str, CanonicalJson]", value)
        size = 2 + max(0, len(mapping) - 1) + len(mapping)
        if size > remaining:
            raise _JsonResourceError
        for key, item in mapping.items():
            size += _measure_encoded_size(key, remaining=remaining - size)
            size += _measure_encoded_size(item, remaining=remaining - size)
        return size
    if size > remaining:
        raise _JsonResourceError
    return size


def _serialize_output(
    mutation_input: MutationInput,
    value: CanonicalJson,
) -> MutationOutput:
    try:
        body = serialize_json_compact_utf8_v1(value)
    except _JsonResourceError:
        raise MutationError.resource_limit(
            "MUT_STRUCTURAL_JSON_OUTPUT_LIMIT",
            "Structural JSON output exceeds a hard resource limit.",
        ) from None
    except _UnsupportedNumberError:
        raise _invalid_parameter(
            mutation_input,
            "MUT_STRUCTURAL_VALUE_NUMBER_UNSUPPORTED",
            "A structural replacement value is outside the lossless numeric domain.",
        ) from None
    except (_UnsupportedJsonShapeError, _UnsupportedUnicodeError):
        raise _invalid_parameter(
            mutation_input,
            "MUT_STRUCTURAL_VALUE_UNSUPPORTED",
            "A structural replacement value is not supported JSON.",
        ) from None
    state = mutation_input.state
    return MutationOutput(
        body=body,
        headers=state.headers,
        signing_time_ns=state.signing_time_ns,
        signer=state.signer,
    )


def _parameters(
    mutation_input: MutationInput,
    *,
    required: frozenset[str],
    optional: frozenset[str],
) -> JsonObject:
    values = thaw_parameter_object(mutation_input.parameters)
    keys = frozenset(values)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        raise _invalid_parameter(
            mutation_input,
            "MUT_STRUCTURAL_PARAMETERS_INVALID",
            "Structural mutation parameters do not match the operator schema.",
        )
    if "accept_prior_mutation" in values:
        _require_boolean(
            mutation_input,
            values["accept_prior_mutation"],
            code="MUT_ACCEPT_PRIOR_MUTATION_INVALID",
        )
    return values


def _pointer_parameter(
    mutation_input: MutationInput,
    values: JsonObject,
) -> tuple[str, ...]:
    raw = values["pointer"]
    if type(raw) is not str:
        raise _invalid_parameter(
            mutation_input,
            "MUT_JSON_POINTER_INVALID",
            "The structural mutation JSON Pointer is invalid.",
        )
    try:
        return _parse_json_pointer(raw)
    except (_PointerSyntaxError, _UnsupportedUnicodeError):
        raise _invalid_parameter(
            mutation_input,
            "MUT_JSON_POINTER_INVALID",
            "The structural mutation JSON Pointer is invalid.",
        ) from None
    except _JsonResourceError:
        raise MutationError.resource_limit(
            "MUT_JSON_POINTER_LIMIT",
            "The structural mutation JSON Pointer exceeds a hard resource limit.",
        ) from None


def _parse_json_pointer(pointer: str) -> tuple[str, ...]:
    if len(pointer) > MAX_PARAMETER_STRING_LENGTH:
        raise _JsonResourceError
    _validate_json_string(pointer, maximum=MAX_PARAMETER_STRING_LENGTH)
    if not pointer:
        return ()
    if not pointer.startswith("/"):
        raise _PointerSyntaxError
    encoded_tokens = pointer[1:].split("/")
    if len(encoded_tokens) > MAX_PARAMETER_DEPTH:
        raise _JsonResourceError
    return tuple(_decode_pointer_token(token) for token in encoded_tokens)


def _decode_pointer_token(token: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(token):
        character = token[index]
        if character != "~":
            decoded.append(character)
            index += 1
            continue
        if index + 1 >= len(token):
            raise _PointerSyntaxError
        escaped = token[index + 1]
        if escaped == "0":
            decoded.append("~")
        elif escaped == "1":
            decoded.append("/")
        else:
            raise _PointerSyntaxError
        index += 2
    return "".join(decoded)


def _resolve_parent(
    document: CanonicalJson,
    tokens: tuple[str, ...],
) -> tuple[_JsonContainer, str]:
    if not tokens:
        raise AssertionError("root JSON Pointer has no parent")
    current = document
    for token in tokens[:-1]:
        if type(current) is dict:
            mapping = cast("dict[str, CanonicalJson]", current)
            if token not in mapping:
                raise _PointerMissingError
            current = mapping[token]
            continue
        if type(current) is list:
            sequence = cast("list[CanonicalJson]", current)
            current = sequence[_existing_array_index(token, length=len(sequence))]
            continue
        raise _PointerMissingError
    if type(current) is dict:
        return cast("dict[str, CanonicalJson]", current), tokens[-1]
    if type(current) is list:
        return cast("list[CanonicalJson]", current), tokens[-1]
    raise _PointerMissingError


def _resolve_target(
    document: CanonicalJson,
    tokens: tuple[str, ...],
) -> CanonicalJson:
    if not tokens:
        return document
    parent, token = _resolve_parent(document, tokens)
    if type(parent) is dict:
        mapping = parent
        if token not in mapping:
            raise _PointerMissingError
        return mapping[token]
    sequence = cast("list[CanonicalJson]", parent)
    return sequence[_existing_array_index(token, length=len(sequence))]


def _existing_array_index(reference_token: str, *, length: int) -> int:
    if reference_token == "0":  # noqa: S105
        index = 0
    elif (
        reference_token
        and reference_token[0] in "123456789"
        and all("0" <= character <= "9" for character in reference_token)
    ):
        if len(reference_token) > _MAX_ARRAY_INDEX_DIGITS:
            raise _PointerMissingError
        index = int(reference_token)
    else:
        raise _PointerArrayIndexError
    if index >= length:
        raise _PointerMissingError
    return index


def _replace(
    document: CanonicalJson,
    tokens: tuple[str, ...],
    replacement: CanonicalJson,
) -> CanonicalJson:
    if not tokens:
        return replacement
    parent, token = _resolve_parent(document, tokens)
    if type(parent) is dict:
        mapping = parent
        if token not in mapping:
            raise _PointerMissingError
        mapping[token] = replacement
    else:
        sequence = cast("list[CanonicalJson]", parent)
        sequence[_existing_array_index(token, length=len(sequence))] = replacement
    return document


def _remove(
    document: CanonicalJson,
    tokens: tuple[str, ...],
) -> CanonicalJson:
    if not tokens:
        raise _PointerSyntaxError
    parent, token = _resolve_parent(document, tokens)
    if type(parent) is dict:
        mapping = parent
        if token not in mapping:
            raise _PointerMissingError
        del mapping[token]
    else:
        sequence = cast("list[CanonicalJson]", parent)
        sequence.pop(_existing_array_index(token, length=len(sequence)))
    return document


def _parameter_json_value(
    mutation_input: MutationInput,
    values: JsonObject,
) -> CanonicalJson:
    try:
        return _validate_json_tree(values["value"])
    except _JsonResourceError:
        raise MutationError.resource_limit(
            "MUT_STRUCTURAL_VALUE_LIMIT",
            "A structural replacement value exceeds a hard resource limit.",
        ) from None
    except _UnsupportedNumberError:
        raise _invalid_parameter(
            mutation_input,
            "MUT_STRUCTURAL_VALUE_NUMBER_UNSUPPORTED",
            "A structural replacement value is outside the lossless numeric domain.",
        ) from None
    except (_UnsupportedJsonShapeError, _UnsupportedUnicodeError):
        raise _invalid_parameter(
            mutation_input,
            "MUT_STRUCTURAL_VALUE_UNSUPPORTED",
            "A structural replacement value is not supported JSON.",
        ) from None


def _require_text(
    mutation_input: MutationInput,
    value: object,
    *,
    code: str,
    maximum: int = MAX_PARAMETER_STRING_LENGTH,
) -> str:
    if type(value) is not str or not value:
        raise _invalid_parameter(
            mutation_input,
            code,
            "A structural mutation text parameter is invalid.",
        )
    try:
        _validate_json_string(value, maximum=maximum)
    except (_JsonResourceError, _UnsupportedUnicodeError):
        raise _invalid_parameter(
            mutation_input,
            code,
            "A structural mutation text parameter is invalid.",
        ) from None
    return value


def _require_boolean(
    mutation_input: MutationInput,
    value: object,
    *,
    code: str,
) -> bool:
    if type(value) is not bool:
        raise _invalid_parameter(
            mutation_input,
            code,
            "A structural mutation boolean parameter is invalid.",
        )
    return value


def _apply_pointer_operation(
    mutation_input: MutationInput,
    operation: Callable[[], CanonicalJson],
    *,
    missing_is_ignored: bool = False,
) -> MutationOutput:
    try:
        document = operation()
    except _PointerArrayIndexError:
        raise _invalid_parameter(
            mutation_input,
            "MUT_JSON_POINTER_ARRAY_INDEX_INVALID",
            "A JSON Pointer array token is not a canonical existing index.",
        ) from None
    except _PointerSyntaxError:
        raise _invalid_parameter(
            mutation_input,
            "MUT_JSON_POINTER_ROOT_OPERATION_INVALID",
            "The requested JSON Pointer operation is invalid at the document root.",
        ) from None
    except _PointerMissingError:
        if not missing_is_ignored:
            raise _not_applicable(
                mutation_input,
                "MUT_JSON_POINTER_MISSING",
                "The structural mutation JSON Pointer does not resolve.",
            ) from None
        document = _parse_structural_json(mutation_input)
    return _serialize_output(mutation_input, document)


def _representative(target_type: str) -> CanonicalJson:
    representatives: dict[str, CanonicalJson] = {
        "null": None,
        "boolean": False,
        "integer": 0,
        "string": "",
        "array": [],
        "object": {},
    }
    return representatives[target_type]


def _json_type(value: CanonicalJson) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    return "object"


def _require_invocation(mutation_input: MutationInput, operator_id: str) -> None:
    if type(mutation_input) is not MutationInput:
        raise TypeError("structural operators require MutationInput")
    realized = mutation_input.realized
    if (
        realized.operator_id != operator_id
        or realized.operator_version != STRUCTURAL_OPERATOR_VERSION
        or realized.stage is not MutationStage.STRUCTURAL
    ):
        raise MutationError.conflict(
            "MUT_STRUCTURAL_INVOCATION_CONFLICT",
            "A structural operator received a mismatched realized invocation.",
            operator_id=realized.operator_id,
            operator_version=realized.operator_version,
        )


def _invalid_parameter(
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


class RemoveJsonPointerV1:
    """Remove an existing RFC 6901 target, with an explicit missing policy."""

    __slots__ = ()

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        """Remove the realized pointer from a parsed structural document."""
        _require_invocation(mutation_input, REMOVE_JSON_POINTER_V1)
        values = _parameters(
            mutation_input,
            required=frozenset({"pointer"}),
            optional=frozenset({"if_missing", "accept_prior_mutation"}),
        )
        tokens = _pointer_parameter(mutation_input, values)
        if_missing = values.get("if_missing", "error")
        if if_missing not in ("error", "ignore"):
            raise _invalid_parameter(
                mutation_input,
                "MUT_REMOVE_IF_MISSING_INVALID",
                "The remove mutation missing-pointer policy is invalid.",
            )
        document = _parse_structural_json(mutation_input)
        return _apply_pointer_operation(
            mutation_input,
            lambda: _remove(document, tokens),
            missing_is_ignored=if_missing == "ignore",
        )


class ReplaceJsonValueV1:
    """Replace one existing RFC 6901 target with an exact realized JSON value."""

    __slots__ = ()

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        """Replace the realized pointer with the exact realized JSON value."""
        _require_invocation(mutation_input, REPLACE_JSON_VALUE_V1)
        values = _parameters(
            mutation_input,
            required=frozenset({"pointer", "value"}),
            optional=frozenset({"accept_prior_mutation"}),
        )
        tokens = _pointer_parameter(mutation_input, values)
        replacement = _parameter_json_value(mutation_input, values)
        document = _parse_structural_json(mutation_input)
        return _apply_pointer_operation(
            mutation_input,
            lambda: _replace(document, tokens, replacement),
        )


class ReplaceJsonTypeV1:
    """Replace one value with the fixed representative of another JSON type."""

    __slots__ = ()

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        """Replace the realized pointer with a fixed other-type representative."""
        _require_invocation(mutation_input, REPLACE_JSON_TYPE_V1)
        values = _parameters(
            mutation_input,
            required=frozenset({"pointer", "target_type"}),
            optional=frozenset({"accept_prior_mutation"}),
        )
        tokens = _pointer_parameter(mutation_input, values)
        target_type = values["target_type"]
        if type(target_type) is not str or target_type not in _TARGET_TYPES:
            raise _invalid_parameter(
                mutation_input,
                "MUT_REPLACE_JSON_TYPE_INVALID",
                "The structural target type is invalid.",
            )
        document = _parse_structural_json(mutation_input)
        try:
            current = _resolve_target(document, tokens)
        except _PointerArrayIndexError:
            raise _invalid_parameter(
                mutation_input,
                "MUT_JSON_POINTER_ARRAY_INDEX_INVALID",
                "A JSON Pointer array token is not a canonical existing index.",
            ) from None
        except _PointerMissingError:
            raise _not_applicable(
                mutation_input,
                "MUT_JSON_POINTER_MISSING",
                "The structural mutation JSON Pointer does not resolve.",
            ) from None
        if _json_type(current) == target_type:
            raise _invalid_parameter(
                mutation_input,
                "MUT_REPLACE_JSON_TYPE_UNCHANGED",
                "The target type must differ from the existing JSON type.",
            )
        replacement = _representative(target_type)
        return _apply_pointer_operation(
            mutation_input,
            lambda: _replace(document, tokens, replacement),
        )


class AddJsonFieldV1:
    """Add one named member to the object selected by an RFC 6901 pointer."""

    __slots__ = ()

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        """Add or explicitly overwrite the realized object member."""
        _require_invocation(mutation_input, ADD_JSON_FIELD_V1)
        values = _parameters(
            mutation_input,
            required=frozenset({"pointer", "name", "value"}),
            optional=frozenset({"overwrite", "accept_prior_mutation"}),
        )
        tokens = _pointer_parameter(mutation_input, values)
        name = _require_text(
            mutation_input,
            values["name"],
            code="MUT_ADD_JSON_FIELD_NAME_INVALID",
            maximum=MAX_PARAMETER_KEY_LENGTH,
        )
        replacement = _parameter_json_value(mutation_input, values)
        overwrite = _require_boolean(
            mutation_input,
            values.get("overwrite", False),
            code="MUT_ADD_JSON_FIELD_OVERWRITE_INVALID",
        )
        document = _parse_structural_json(mutation_input)
        try:
            target = _resolve_target(document, tokens)
        except _PointerArrayIndexError:
            raise _invalid_parameter(
                mutation_input,
                "MUT_JSON_POINTER_ARRAY_INDEX_INVALID",
                "A JSON Pointer array token is not a canonical existing index.",
            ) from None
        except _PointerMissingError:
            raise _not_applicable(
                mutation_input,
                "MUT_JSON_POINTER_MISSING",
                "The structural mutation JSON Pointer does not resolve.",
            ) from None
        if type(target) is not dict:
            raise _not_applicable(
                mutation_input,
                "MUT_ADD_JSON_FIELD_TARGET_NOT_OBJECT",
                "The add-field JSON Pointer must resolve to an object.",
            )
        target_object = cast("dict[str, CanonicalJson]", target)
        if name in target_object and not overwrite:
            realized = mutation_input.realized
            raise MutationError.conflict(
                "MUT_ADD_JSON_FIELD_COLLISION",
                "The requested JSON object member already exists.",
                operator_id=realized.operator_id,
                operator_version=realized.operator_version,
            )
        target_object[name] = replacement
        return _serialize_output(mutation_input, document)


class _ChangeEventFieldV1:
    __slots__ = ("_operator_id",)

    def __init__(self, operator_id: str) -> None:
        self._operator_id = operator_id

    def apply(self, mutation_input: MutationInput) -> MutationOutput:
        _require_invocation(mutation_input, self._operator_id)
        values = _parameters(
            mutation_input,
            required=frozenset({"pointer", "value"}),
            optional=frozenset({"accept_prior_mutation"}),
        )
        tokens = _pointer_parameter(mutation_input, values)
        replacement = _require_text(
            mutation_input,
            values["value"],
            code="MUT_EVENT_FIELD_VALUE_INVALID",
        )
        document = _parse_structural_json(mutation_input)
        return _apply_pointer_operation(
            mutation_input,
            lambda: _replace(document, tokens, replacement),
        )


STRUCTURAL_MUTATION_REGISTRATIONS: Final = (
    MutationRegistration(
        operator_id=REMOVE_JSON_POINTER_V1,
        operator_version=STRUCTURAL_OPERATOR_VERSION,
        stage=MutationStage.STRUCTURAL,
        implementation=RemoveJsonPointerV1(),
        changes_body=True,
        requires_valid_json=True,
    ),
    MutationRegistration(
        operator_id=REPLACE_JSON_VALUE_V1,
        operator_version=STRUCTURAL_OPERATOR_VERSION,
        stage=MutationStage.STRUCTURAL,
        implementation=ReplaceJsonValueV1(),
        changes_body=True,
        requires_valid_json=True,
    ),
    MutationRegistration(
        operator_id=REPLACE_JSON_TYPE_V1,
        operator_version=STRUCTURAL_OPERATOR_VERSION,
        stage=MutationStage.STRUCTURAL,
        implementation=ReplaceJsonTypeV1(),
        changes_body=True,
        requires_valid_json=True,
    ),
    MutationRegistration(
        operator_id=ADD_JSON_FIELD_V1,
        operator_version=STRUCTURAL_OPERATOR_VERSION,
        stage=MutationStage.STRUCTURAL,
        implementation=AddJsonFieldV1(),
        changes_body=True,
        requires_valid_json=True,
    ),
    MutationRegistration(
        operator_id=CHANGE_EVENT_ID_FIELD_V1,
        operator_version=STRUCTURAL_OPERATOR_VERSION,
        stage=MutationStage.STRUCTURAL,
        implementation=_ChangeEventFieldV1(CHANGE_EVENT_ID_FIELD_V1),
        changes_body=True,
        requires_valid_json=True,
    ),
    MutationRegistration(
        operator_id=CHANGE_EVENT_TYPE_FIELD_V1,
        operator_version=STRUCTURAL_OPERATOR_VERSION,
        stage=MutationStage.STRUCTURAL,
        implementation=_ChangeEventFieldV1(CHANGE_EVENT_TYPE_FIELD_V1),
        changes_body=True,
        requires_valid_json=True,
    ),
)

STRUCTURAL_MUTATION_REGISTRY: Final = StaticMutationRegistry(STRUCTURAL_MUTATION_REGISTRATIONS)
