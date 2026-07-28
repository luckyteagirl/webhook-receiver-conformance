"""Public structural JSON mutation contract.

The first implementation landed in :mod:`mutations.structural`.  This module
is the task-owned import surface named by the implementation plan and keeps
the existing implementation available without creating a second registry.
"""
# ruff: noqa: INP001

from webhook_receiver_conformance.mutations.structural import (
    ADD_JSON_FIELD_V1,
    CHANGE_EVENT_ID_FIELD_V1,
    CHANGE_EVENT_TYPE_FIELD_V1,
    JSON_COMPACT_UTF8_V1,
    REMOVE_JSON_POINTER_V1,
    REPLACE_JSON_TYPE_V1,
    REPLACE_JSON_VALUE_V1,
    STRUCTURAL_MUTATION_REGISTRATIONS,
    STRUCTURAL_MUTATION_REGISTRY,
    STRUCTURAL_OPERATOR_VERSION,
    AddJsonFieldV1,
    RemoveJsonPointerV1,
    ReplaceJsonTypeV1,
    ReplaceJsonValueV1,
    serialize_json_compact_utf8_v1,
)

__all__ = [
    "ADD_JSON_FIELD_V1",
    "CHANGE_EVENT_ID_FIELD_V1",
    "CHANGE_EVENT_TYPE_FIELD_V1",
    "JSON_COMPACT_UTF8_V1",
    "REMOVE_JSON_POINTER_V1",
    "REPLACE_JSON_TYPE_V1",
    "REPLACE_JSON_VALUE_V1",
    "STRUCTURAL_MUTATION_REGISTRATIONS",
    "STRUCTURAL_MUTATION_REGISTRY",
    "STRUCTURAL_OPERATOR_VERSION",
    "AddJsonFieldV1",
    "RemoveJsonPointerV1",
    "ReplaceJsonTypeV1",
    "ReplaceJsonValueV1",
    "serialize_json_compact_utf8_v1",
]
