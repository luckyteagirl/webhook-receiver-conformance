"""Executable observer protocol, schema, policy, and registry contracts."""
# ruff: noqa: INP001, PLR0913, SLF001
# pyright: reportPrivateUsage=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import json
from copy import deepcopy
from enum import StrEnum
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError
from referencing import Registry, Resource

from webhook_receiver_conformance.domain.enums import (
    EvidenceValueType,
    ObservationStatus,
)
from webhook_receiver_conformance.errors import ErrorCategory, ResultCategory
from webhook_receiver_conformance.observers import protocol as protocol_module
from webhook_receiver_conformance.observers.protocol import (
    BUILTIN_OBSERVER_MODULES,
    BUILTIN_OBSERVER_REGISTRY,
    CAPABILITIES_HTTP_ROUTE,
    HTTP_CAPABILITIES_PATH,
    HTTP_OBSERVE_PATH,
    HTTP_OBSERVER_METHOD,
    MAX_IJSON_INTEGER,
    MAX_JSON_ARRAY_ITEMS,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MAX_JSON_OBJECT_KEY_LENGTH,
    MAX_JSON_OBJECT_PROPERTIES,
    MAX_JSON_STRING_LENGTH,
    MAX_OBSERVER_MESSAGE_BYTES,
    MIN_IJSON_INTEGER,
    OBSERVATION_RECORD_SCHEMA_VERSION,
    OBSERVE_HTTP_ROUTE,
    OBSERVER_PROTOCOL_VERSION,
    AssertionUnsupportedDisposition,
    BuiltinObserverKind,
    BytesDigestMetadata,
    CapabilityNegotiation,
    FrozenJsonObject,
    ObservationRecord,
    ObservationRecordError,
    Observer,
    ObserverCapabilities,
    ObserverContractRegistration,
    ObserverEvidence,
    ObserverOperation,
    ObserverProtocolError,
    ObserverQuery,
    ObserverRegistryError,
    ObserverRequest,
    ObserverResponse,
    ObserverResponseStatus,
    ObserverWireError,
    ProtocolModel,
    SnapshotIdentityLedger,
    StaticObserverRegistry,
    UnsupportedPolicy,
    automatic_polling_allowed,
    automatic_retry_allowed,
    canonical_observer_wire_bytes,
    discover_builtin_observer_modules,
    http_route_for,
    map_response_status,
    map_unsupported_policy,
    negotiate_capabilities,
    parse_observation_record,
    parse_observer_evidence,
    parse_observer_request,
    parse_observer_response,
    resume_reconciliation_allowed,
    retry_observe_request,
    validate_builtin_registry_completeness,
    validate_response_for_request,
)

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).parents[3]
SCHEMAS = ROOT / "schemas"
EXAMPLES = ROOT / "examples"

REQUEST_ID = "request_01J00000000000000000000000"
OTHER_REQUEST_ID = "request_01J00000000000000000000001"
SAMPLE_ID = "sample_01J00000000000000000000000"
OTHER_SAMPLE_ID = "sample_01J00000000000000000000001"
RECORD_ID = "record_01J00000000000000000000002"
RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
SCENARIO_ID = "scenario_01J00000000000000000000000"
EVENT_ID = "event_01J00000000000000000000000"
OBSERVATION_ID = "observation_01J00000000000000000000000"
DIGEST = "sha256:" + ("a" * 64)
CANARY = "observer-super-secret-canary"

SCHEMA_FILES = (
    "observer-evidence.schema.json",
    "observer-request.schema.json",
    "observer-response.schema.json",
    "observation-record.schema.json",
)

JsonObject = dict[str, Any]


class _BoundaryWireModel(ProtocolModel):
    """Test-only protocol model for exact outbound byte boundaries."""

    payload: str


def _load_json(path: Path) -> JsonObject:
    return cast("JsonObject", json.loads(path.read_text(encoding="utf-8")))


SCHEMA_DOCUMENTS = {name: _load_json(SCHEMAS / name) for name in SCHEMA_FILES}
SCHEMA_REGISTRY: Registry[Any] = Registry[Any]().with_resources(
    (
        cast("str", document["$id"]),
        Resource.from_contents(document),
    )
    for document in SCHEMA_DOCUMENTS.values()
)


def _schema_errors(schema_name: str, value: object) -> list[Any]:
    validator = Draft202012Validator(
        SCHEMA_DOCUMENTS[schema_name],
        registry=SCHEMA_REGISTRY,
    )
    return list(validator.iter_errors(cast("Any", value)))


def _assert_schema_accepts(schema_name: str, value: object) -> None:
    assert _schema_errors(schema_name, value) == []


def _capabilities(**overrides: object) -> ObserverCapabilities:
    data: dict[str, object] = {
        "evidence_types": [
            EvidenceValueType.INTEGER.value,
            EvidenceValueType.STRING.value,
        ],
        "evidence_keys": ["processing_count", "resource"],
        "read_only": True,
        "idempotent": True,
        "max_queries": 64,
        "supports_pending": True,
        "stable_snapshot_ids": True,
    }
    data.update(overrides)
    return ObserverCapabilities.model_validate(data)


def _query(
    key: str = "processing_count",
    value_type: EvidenceValueType = EvidenceValueType.INTEGER,
    *,
    parameters: object | None = None,
) -> ObserverQuery:
    return ObserverQuery.model_validate(
        {
            "key": key,
            "type": value_type.value,
            "parameters": {} if parameters is None else parameters,
        }
    )


def _observe_request(
    *,
    queries: tuple[ObserverQuery, ...] | None = None,
    request_id: str = REQUEST_ID,
    sample_id: str = SAMPLE_ID,
    prior_snapshot_id: str | None = None,
) -> ObserverRequest:
    data: dict[str, object] = {
        "protocol_version": OBSERVER_PROTOCOL_VERSION,
        "request_id": request_id,
        "operation": ObserverOperation.OBSERVE.value,
        "sample_id": sample_id,
        "run_id": RUN_ID,
        "scenario_id": SCENARIO_ID,
        "event_id": EVENT_ID,
        "checkpoint": "after_delivery",
        "queries": list(queries or (_query(),)),
    }
    if prior_snapshot_id is not None:
        data["prior_snapshot_id"] = prior_snapshot_id
    return ObserverRequest.model_validate(data)


def _capability_request() -> ObserverRequest:
    return ObserverRequest.model_validate(
        {
            "protocol_version": OBSERVER_PROTOCOL_VERSION,
            "request_id": REQUEST_ID,
            "operation": ObserverOperation.CAPABILITIES.value,
        }
    )


def _evidence(
    key: str = "processing_count",
    value_type: EvidenceValueType = EvidenceValueType.INTEGER,
    value: object | None = 1,
    *,
    sensitive: bool = False,
) -> ObserverEvidence:
    return ObserverEvidence.model_validate(
        {
            "key": key,
            "value_type": value_type.value,
            "value": value,
            "sensitive": sensitive,
        }
    )


def _response(
    *,
    status: ObserverResponseStatus = ObserverResponseStatus.OK,
    request_id: str = REQUEST_ID,
    capabilities: ObserverCapabilities | None = None,
    evidence: tuple[ObserverEvidence, ...] | None = None,
    snapshot_id: str | None = "snapshot-1",
    error: ObserverWireError | None = None,
) -> ObserverResponse:
    if status is not ObserverResponseStatus.OK:
        snapshot_id = None
        evidence = ()
    if status is ObserverResponseStatus.ERROR and error is None:
        error = ObserverWireError(
            category="observer_unavailable",
            message="safe redacted message",
            retryable=False,
        )
    return ObserverResponse(
        protocol_version=OBSERVER_PROTOCOL_VERSION,
        request_id=request_id,
        status=status,
        capabilities=capabilities or _capabilities(),
        snapshot_id=snapshot_id,
        evidence=(_evidence(),) if evidence is None else evidence,
        error=error,
    )


def _record(
    *,
    status: ObservationStatus = ObservationStatus.OK,
    evidence: tuple[ObserverEvidence, ...] | None = None,
    snapshot_id: str | None = "snapshot-1",
    error: ObservationRecordError | None = None,
) -> ObservationRecord:
    if status is not ObservationStatus.OK:
        evidence = ()
        snapshot_id = None
    if status in {ObservationStatus.ERROR, ObservationStatus.TIMEOUT} and error is None:
        error = ObservationRecordError(
            category="observer_unavailable",
            message_redacted="safe redacted message",
        )
    return ObservationRecord(
        schema_version=OBSERVATION_RECORD_SCHEMA_VERSION,
        record_id=RECORD_ID,
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        event_id=EVENT_ID,
        observation_id=OBSERVATION_ID,
        sample_id=SAMPLE_ID,
        observer_id="receiver_state",
        sample_sequence=1,
        recorded_at="2026-07-26T20:00:00.150Z",
        status=status,
        snapshot_id=snapshot_id,
        evidence=(_evidence(),) if evidence is None else evidence,
        error=error,
    )


def _protocol_error_code(action: Callable[[], object]) -> str:
    with pytest.raises(ObserverProtocolError) as captured:
        action()
    return str(captured.value.diagnostic.code)


def test_versioned_examples_parse_and_round_trip_through_owned_schemas() -> None:
    request_document = _load_json(EXAMPLES / "observer-request.example.json")
    response_document = _load_json(EXAMPLES / "observer-response.example.json")
    observation_document = cast(
        "JsonObject",
        json.loads(
            (EXAMPLES / "observations.example.jsonl").read_text(encoding="utf-8").splitlines()[0]
        ),
    )

    request = ObserverRequest.model_validate(request_document)
    response = ObserverResponse.model_validate(response_document)
    record = ObservationRecord.model_validate(observation_document)

    _assert_schema_accepts("observer-request.schema.json", request.wire_dict())
    _assert_schema_accepts("observer-response.schema.json", response.wire_dict())
    _assert_schema_accepts("observation-record.schema.json", record.wire_dict())
    for item in response.evidence:
        _assert_schema_accepts("observer-evidence.schema.json", item.wire_dict())


def test_all_owned_schemas_are_draft_2020_12_and_closed_at_root() -> None:
    for document in SCHEMA_DOCUMENTS.values():
        Draft202012Validator.check_schema(document)
        assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        if document.get("type") == "object":
            assert document["additionalProperties"] is False


@pytest.mark.parametrize(
    ("model", "schema_name", "value"),
    [
        (
            ObserverRequest,
            "observer-request.schema.json",
            {
                "protocol_version": "1.0",
                "request_id": REQUEST_ID,
                "operation": "capabilities",
                "unexpected": True,
            },
        ),
        (
            ObserverRequest,
            "observer-request.schema.json",
            {
                "protocol_version": "1.0",
                "request_id": "request_not_an_id",
                "operation": "capabilities",
            },
        ),
        (
            ObserverResponse,
            "observer-response.schema.json",
            {
                **_response().wire_dict(),
                "status": "complete",
            },
        ),
        (
            ObservationRecord,
            "observation-record.schema.json",
            {
                **_record().wire_dict(),
                "sample_sequence": MAX_IJSON_INTEGER + 1,
            },
        ),
        (
            ObserverEvidence,
            "observer-evidence.schema.json",
            {
                "key": "count",
                "value_type": "integer",
                "value": 1.5,
                "sensitive": False,
            },
        ),
        (
            ObserverEvidence,
            "observer-evidence.schema.json",
            {
                "key": "bad\u0000key",
                "value_type": "string",
                "value": "safe",
                "sensitive": False,
            },
        ),
    ],
)
def test_representative_hostile_documents_are_rejected_by_model_and_schema(
    model: type[BaseModel],
    schema_name: str,
    value: JsonObject,
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(value)
    assert _schema_errors(schema_name, value)


def test_models_are_strict_frozen_and_reject_unknown_or_coerced_fields() -> None:
    request = _observe_request()
    with pytest.raises(ValidationError, match="frozen"):
        request.request_id = OTHER_REQUEST_ID  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(ValidationError, match="Extra inputs"):
        ObserverRequest.model_validate({**request.wire_dict(), "unknown": "field"})
    with pytest.raises(ValidationError):
        ObserverCapabilities.model_validate(
            {
                **_capabilities().wire_dict(),
                "read_only": 1,
            }
        )
    with pytest.raises(ValidationError):
        ObserverEvidence.model_validate(
            {
                "key": "count",
                "value_type": "integer",
                "value": "1",
                "sensitive": False,
            }
        )


def test_capability_request_has_no_observe_fields_and_observe_requires_identity() -> None:
    request = _capability_request()
    assert request.sample_id is None
    assert request.queries == ()
    with pytest.raises(ValidationError, match="observe-only"):
        ObserverRequest.model_validate(
            {
                **request.wire_dict(),
                "sample_id": SAMPLE_ID,
            }
        )
    for missing in ("sample_id", "run_id", "queries"):
        document = _observe_request().wire_dict()
        document.pop(missing)
        with pytest.raises(ValidationError, match="require"):
            ObserverRequest.model_validate(document)


def test_event_scoped_request_requires_scenario_and_query_keys_are_unique() -> None:
    document = _observe_request().wire_dict()
    document.pop("scenario_id")
    with pytest.raises(ValidationError, match="scenario"):
        ObserverRequest.model_validate(document)
    with pytest.raises(ValidationError, match="unique"):
        _observe_request(queries=(_query(), _query(parameters={"other": True})))


@pytest.mark.parametrize(
    ("operation", "expected_path"),
    [
        (ObserverOperation.CAPABILITIES, HTTP_CAPABILITIES_PATH),
        (ObserverOperation.OBSERVE, HTTP_OBSERVE_PATH),
    ],
)
def test_http_contract_uses_fixed_post_methods_and_paths(
    operation: ObserverOperation,
    expected_path: str,
) -> None:
    route = http_route_for(operation)
    assert route.method == HTTP_OBSERVER_METHOD == "POST"
    assert route.path == expected_path
    assert route.operation is operation
    assert CAPABILITIES_HTTP_ROUTE.path == "/capabilities"
    assert OBSERVE_HTTP_ROUTE.path == "/observe"


def test_typed_ids_reject_cross_kind_or_non_v4_values() -> None:
    request = _observe_request().wire_dict()
    invalid_fields = {
        "request_id": SAMPLE_ID,
        "sample_id": RECORD_ID,
        "run_id": "123e4567-e89b-12d3-a456-426614174000",
        "scenario_id": EVENT_ID,
        "event_id": SCENARIO_ID,
    }
    for field, invalid in invalid_fields.items():
        document = deepcopy(request)
        document[field] = invalid
        with pytest.raises(ValidationError):
            ObserverRequest.model_validate(document)


def test_retry_preserves_logical_request_and_replaces_sample_identity() -> None:
    request = _observe_request()
    retried = retry_observe_request(request, OTHER_SAMPLE_ID)
    assert retried.request_id == request.request_id
    assert retried.sample_id == OTHER_SAMPLE_ID
    assert retried.queries == request.queries
    assert retried is not request
    with pytest.raises(ValueError, match="fresh"):
        retry_observe_request(request, SAMPLE_ID)
    with pytest.raises(ValueError, match="observe"):
        retry_observe_request(_capability_request(), OTHER_SAMPLE_ID)


@pytest.mark.parametrize(
    ("value_type", "value"),
    [
        (EvidenceValueType.NULL, None),
        (EvidenceValueType.BOOLEAN, True),
        (EvidenceValueType.INTEGER, MIN_IJSON_INTEGER),
        (EvidenceValueType.INTEGER, MAX_IJSON_INTEGER),
        (EvidenceValueType.DECIMAL_STRING, "-12.500e+3"),
        (EvidenceValueType.STRING, "receiver-state"),
        (
            EvidenceValueType.BYTES_DIGEST,
            {
                "sha256": DIGEST,
                "byte_length": 4,
                "media_type": "application/octet-stream",
            },
        ),
        (EvidenceValueType.TIMESTAMP, "2026-07-26T20:00:00.150Z"),
        (EvidenceValueType.ARRAY, [None, True, 1, "value", {"nested": []}]),
        (EvidenceValueType.OBJECT, {"nested": [None, True, 1, "value"]}),
    ],
)
def test_all_evidence_tags_are_strict_and_schema_backed(
    value_type: EvidenceValueType,
    value: object,
) -> None:
    evidence = _evidence("typed", value_type, value)
    assert evidence.value_type is value_type
    _assert_schema_accepts("observer-evidence.schema.json", evidence.wire_dict())


@pytest.mark.parametrize(
    ("value_type", "value"),
    [
        (EvidenceValueType.NULL, False),
        (EvidenceValueType.BOOLEAN, 1),
        (EvidenceValueType.INTEGER, True),
        (EvidenceValueType.INTEGER, MAX_IJSON_INTEGER + 1),
        (EvidenceValueType.DECIMAL_STRING, "01.0"),
        (EvidenceValueType.DECIMAL_STRING, 1),
        (EvidenceValueType.STRING, b"raw"),
        (EvidenceValueType.BYTES_DIGEST, b"raw"),
        (EvidenceValueType.TIMESTAMP, "2026-02-30T00:00:00Z"),
        (EvidenceValueType.ARRAY, {"not": "array"}),
        (EvidenceValueType.OBJECT, ["not", "object"]),
    ],
)
def test_evidence_tag_mismatches_and_binary_bytes_are_rejected(
    value_type: EvidenceValueType,
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        _evidence("typed", value_type, value)


def test_binary_evidence_keeps_only_digest_metadata() -> None:
    evidence = _evidence(
        "body",
        EvidenceValueType.BYTES_DIGEST,
        {
            "sha256": DIGEST,
            "byte_length": 4,
            "media_type": "application/json",
        },
    )
    assert isinstance(evidence.typed_value, BytesDigestMetadata)
    projection = evidence.wire_dict()
    assert projection["value"] == {
        "sha256": DIGEST,
        "byte_length": 4,
        "media_type": "application/json",
    }
    assert "bytes" not in cast("JsonObject", projection["value"])
    assert b"raw-body" not in canonical_observer_wire_bytes(evidence)


def test_nested_json_is_deeply_immutable_and_canonical_projection_is_detached() -> None:
    source = {"outer": [{"inner": "value"}]}
    query = _query(parameters=source)
    source["outer"] = []
    outer = cast("tuple[object, ...]", query.frozen_parameters["outer"])
    nested = cast("FrozenJsonObject", outer[0])
    assert nested["inner"] == "value"
    with pytest.raises(TypeError):
        query.frozen_parameters["new"] = "value"  # pyright: ignore[reportIndexIssue]
    with pytest.raises(AttributeError):
        query.frozen_parameters._items = ()  # pyright: ignore[reportAttributeAccessIssue]
    projection = query.wire_dict()
    cast("JsonObject", projection["parameters"])["outer"] = []
    assert cast("tuple[object, ...]", query.frozen_parameters["outer"]) == outer


def test_floats_controls_oversized_integers_cycles_and_excessive_depth_are_rejected() -> None:
    bad_values: list[object] = [
        1.5,
        {"nested": 1.5},
        {"nested": MAX_IJSON_INTEGER + 1},
        {"nested": "control\u0000value"},
    ]
    cycle: list[object] = []
    cycle.append(cycle)
    bad_values.append(cycle)
    deep: object = None
    for _ in range(MAX_JSON_DEPTH + 1):
        deep = [deep]
    bad_values.append(deep)
    for value in bad_values:
        with pytest.raises(ValidationError):
            _query(parameters={"value": value})


def test_safe_repr_omits_values_parameters_and_messages() -> None:
    evidence = _evidence("secret", EvidenceValueType.STRING, CANARY, sensitive=True)
    query = _query(parameters={"secret": CANARY})
    wire_error = ObserverWireError(
        category="observer_error",
        message=CANARY,
        retryable=False,
    )
    record_error = ObservationRecordError(
        category="observer_error",
        message_redacted=CANARY,
    )
    for value in (evidence, query, wire_error, record_error):
        assert CANARY not in repr(value)


def test_response_has_one_closed_status_and_status_specific_shape() -> None:
    for status in ObserverResponseStatus:
        response = _response(status=status)
        assert response.status is status
        assert map_response_status(status).value == status.value
        _assert_schema_accepts("observer-response.schema.json", response.wire_dict())
    for status in ("complete", ["ok", "error"], None):
        document = _response().wire_dict()
        document["status"] = status
        with pytest.raises(ValidationError):
            ObserverResponse.model_validate(document)


def test_response_status_invariants_reject_ambiguous_terminal_fields() -> None:
    base = _response().wire_dict()
    cases = [
        {**base, "snapshot_id": None},
        {
            **base,
            "error": {
                "category": "observer_error",
                "retryable": False,
            },
        },
        {
            **base,
            "status": "pending",
            "snapshot_id": "snapshot-1",
            "evidence": [],
            "error": None,
        },
        {
            **base,
            "status": "unsupported",
            "snapshot_id": None,
            "evidence": [_evidence().wire_dict()],
            "error": None,
        },
        {
            **base,
            "status": "error",
            "snapshot_id": None,
            "evidence": [],
            "error": None,
        },
    ]
    for document in cases:
        with pytest.raises(ValidationError):
            ObserverResponse.model_validate(document)
        assert _schema_errors("observer-response.schema.json", document)


def test_capabilities_require_supported_types_and_strict_retry_facts() -> None:
    base = _capabilities().wire_dict()
    for missing in ("evidence_types", "read_only", "idempotent"):
        document = deepcopy(base)
        document.pop(missing)
        with pytest.raises(ValidationError):
            ObserverCapabilities.model_validate(document)
    for field, value in (
        ("evidence_types", []),
        ("evidence_types", ["integer", "integer"]),
        ("evidence_keys", ["count", "count"]),
        ("max_queries", 0),
        ("max_queries", 65),
    ):
        document = deepcopy(base)
        document[field] = value
        with pytest.raises(ValidationError):
            ObserverCapabilities.model_validate(document)


def test_capability_negotiation_reports_all_mismatches_in_query_order() -> None:
    capabilities = _capabilities(
        evidence_types=["integer"],
        evidence_keys=["processing_count"],
        max_queries=1,
        stable_snapshot_ids=False,
    )
    queries = (
        _query(),
        _query("resource", EvidenceValueType.STRING),
        _query("missing", EvidenceValueType.TIMESTAMP),
    )
    negotiation = negotiate_capabilities(
        capabilities,
        queries,
        requires_stable_snapshot=True,
    )
    assert negotiation == CapabilityNegotiation(
        missing_evidence_keys=("resource", "missing"),
        unsupported_evidence_types=(
            EvidenceValueType.STRING,
            EvidenceValueType.TIMESTAMP,
        ),
        query_limit_exceeded=True,
        stable_snapshot_unavailable=True,
    )
    assert negotiation.supported is False
    assert negotiation.response_status is ObserverResponseStatus.UNSUPPORTED
    assert negotiation.error_category is ErrorCategory.UNSUPPORTED_CAPABILITY


def test_capability_mismatch_is_rejected_before_response_evidence_processing() -> None:
    request = _observe_request(queries=(_query("missing"),))
    response = _response(
        capabilities=_capabilities(evidence_keys=["processing_count"]),
        evidence=(_evidence("missing"),),
    )
    assert (
        _protocol_error_code(lambda: validate_response_for_request(request, response))
        == "OBS_CAPABILITY_MISMATCH"
    )
    negotiation = negotiate_capabilities(response.capabilities, request.queries)
    assert automatic_polling_allowed(response.capabilities, negotiation) is False


def test_supported_negotiation_allows_polling_only_when_all_safety_facts_hold() -> None:
    request = _observe_request()
    safe = _capabilities()
    negotiation = negotiate_capabilities(safe, request.queries)
    assert negotiation.supported is True
    assert negotiation.response_status is None
    assert automatic_polling_allowed(safe, negotiation) is True
    assert (
        automatic_polling_allowed(
            _capabilities(read_only=False),
            negotiation,
        )
        is False
    )
    assert (
        automatic_polling_allowed(
            _capabilities(idempotent=False),
            negotiation,
        )
        is False
    )
    assert (
        automatic_polling_allowed(
            _capabilities(supports_pending=False),
            negotiation,
        )
        is False
    )


def test_read_only_idempotent_and_snapshot_facts_gate_retry_and_reconciliation() -> None:
    retryable = _response(
        status=ObserverResponseStatus.ERROR,
        error=ObserverWireError(
            category="temporary_failure",
            message="safe",
            retryable=True,
        ),
    )
    for read_only, idempotent, expected in (
        (True, True, True),
        (False, True, False),
        (True, False, False),
        (False, False, False),
    ):
        capabilities = _capabilities(
            read_only=read_only,
            idempotent=idempotent,
        )
        assert capabilities.automatic_reinvocation_safe is expected
        assert capabilities.explicit_invocation_limit == (None if read_only else 1)
        assert automatic_retry_allowed(capabilities, retryable) is expected
    assert (
        automatic_retry_allowed(
            _capabilities(),
            _response(status=ObserverResponseStatus.ERROR),
        )
        is False
    )
    assert resume_reconciliation_allowed(_capabilities()) is True
    assert resume_reconciliation_allowed(_capabilities(read_only=False)) is False
    assert resume_reconciliation_allowed(_capabilities(idempotent=False)) is False
    assert resume_reconciliation_allowed(_capabilities(stable_snapshot_ids=False)) is False


def test_pending_must_be_declared_and_capability_response_is_shape_checked() -> None:
    pending = _response(
        status=ObserverResponseStatus.PENDING,
        capabilities=_capabilities(supports_pending=False),
    )
    assert (
        _protocol_error_code(lambda: validate_response_for_request(_observe_request(), pending))
        == "OBS_PENDING_NOT_DECLARED"
    )
    invalid_capability_response = _response(status=ObserverResponseStatus.PENDING)
    assert (
        _protocol_error_code(
            lambda: validate_response_for_request(
                _capability_request(),
                invalid_capability_response,
            )
        )
        == "OBS_CAPABILITIES_RESPONSE_INVALID"
    )


def test_unsupported_policy_maps_facts_without_reducing_cli_exit_code() -> None:
    unsupported = map_unsupported_policy(UnsupportedPolicy.UNSUPPORTED)
    skipped = map_unsupported_policy(UnsupportedPolicy.SKIP)
    assert unsupported.observation_status is ObserverResponseStatus.UNSUPPORTED
    assert unsupported.assertion_disposition is AssertionUnsupportedDisposition.UNSUPPORTED
    assert unsupported.error_category is ErrorCategory.UNSUPPORTED_CAPABILITY
    assert unsupported.result_category is ResultCategory.UNSUPPORTED
    assert unsupported.polling_allowed is False
    assert skipped.assertion_disposition is AssertionUnsupportedDisposition.SKIPPED
    assert not hasattr(unsupported, "exit_code")


def test_ok_response_returns_only_requested_complete_typed_evidence() -> None:
    request = _observe_request(
        queries=(
            _query("processing_count", EvidenceValueType.INTEGER),
            _query("resource", EvidenceValueType.STRING),
        )
    )
    response = _response(
        evidence=(
            _evidence("resource", EvidenceValueType.STRING, "payment"),
            _evidence("processing_count", EvidenceValueType.INTEGER, 1),
        )
    )
    assert validate_response_for_request(request, response) is response
    for evidence, expected_code in (
        (
            (
                _evidence("processing_count"),
                _evidence("resource", EvidenceValueType.STRING, "payment"),
                _evidence("extra", EvidenceValueType.STRING, "value"),
            ),
            "OBS_UNREQUESTED_EVIDENCE",
        ),
        ((_evidence("processing_count"),), "OBS_EVIDENCE_MISSING"),
        (
            (
                _evidence("processing_count"),
                _evidence("resource", EvidenceValueType.INTEGER, 1),
            ),
            "OBS_EVIDENCE_TYPE_MISMATCH",
        ),
    ):
        invalid = _response(
            capabilities=_capabilities(
                evidence_types=["integer", "string"],
                evidence_keys=["processing_count", "resource", "extra"],
            ),
            evidence=evidence,
        )
        assert (
            _protocol_error_code(
                lambda invalid=invalid: validate_response_for_request(request, invalid)
            )
            == expected_code
        )


def test_response_correlation_rejects_a_different_request_id() -> None:
    assert (
        _protocol_error_code(
            lambda: validate_response_for_request(
                _observe_request(),
                _response(request_id=OTHER_REQUEST_ID),
            )
        )
        == "OBS_RESPONSE_REQUEST_ID_MISMATCH"
    )


def test_snapshot_identity_is_opaque_stable_and_never_reused_for_other_state() -> None:
    ledger = SnapshotIdentityLedger()
    first = ledger.bind("opaque:snapshot/1", DIGEST)
    assert first is not ledger
    assert first.bind("opaque:snapshot/1", DIGEST) is first
    with pytest.raises(ObserverProtocolError) as captured:
        first.bind("opaque:snapshot/1", "sha256:" + ("b" * 64))
    assert str(captured.value.diagnostic.code) == "OBS_SNAPSHOT_ID_CONFLICT"


def test_canonical_wire_bytes_are_deterministic_sorted_and_float_free() -> None:
    first = _query(parameters={"z": {"b": 2, "a": 1}, "a": "first"})
    second = _query(parameters={"a": "first", "z": {"a": 1, "b": 2}})
    first_bytes = canonical_observer_wire_bytes(first)
    assert first_bytes == canonical_observer_wire_bytes(second)
    assert first_bytes == (
        b'{"key":"processing_count","parameters":{"a":"first","z":{"a":1,"b":2}},"type":"integer"}'
    )
    assert b".0" not in first_bytes


@pytest.mark.parametrize(
    ("parser", "model"),
    [
        (parse_observer_request, _capability_request()),
        (parse_observer_response, _response()),
        (parse_observer_evidence, _evidence()),
        (parse_observation_record, _record()),
    ],
)
def test_bounded_parsers_round_trip_canonical_models(
    parser: Callable[[bytes], BaseModel],
    model: BaseModel,
) -> None:
    assert parser(canonical_observer_wire_bytes(cast("Any", model))) == model


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"[]",
        b"{",
        b"\xff",
        b'{"protocol_version":"1.0","protocol_version":"1.0"}',
        b'{"protocol_version":1.0}',
        b'{"value":NaN}',
        b'{"value":9007199254740992}',
    ],
)
def test_parser_rejects_malformed_duplicate_float_constant_and_unsafe_integer_json(
    payload: bytes,
) -> None:
    assert _protocol_error_code(lambda: parse_observer_request(payload)) == (
        "OBS_PROTOCOL_INVALID_JSON"
    )


def test_parser_enforces_message_depth_and_size_bounds() -> None:
    too_large = b"{" + (b" " * MAX_OBSERVER_MESSAGE_BYTES) + b"}"
    with pytest.raises(ObserverProtocolError) as captured:
        parse_observer_request(too_large)
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert str(captured.value.diagnostic.code) == "OBS_PROTOCOL_MESSAGE_TOO_LARGE"


def test_json_resource_caps_accept_exact_boundaries() -> None:
    depth_boundary: object = None
    for _ in range(MAX_JSON_DEPTH - 2):
        depth_boundary = [depth_boundary]
    node_boundary = [
        *([[None] * 1000 for _ in range(9)]),
        [None] * (MAX_JSON_NODES - 9012),
    ]
    exact_values: tuple[object, ...] = (
        [None] * MAX_JSON_ARRAY_ITEMS,
        {f"k{index}": None for index in range(MAX_JSON_OBJECT_PROPERTIES)},
        "x" * MAX_JSON_STRING_LENGTH,
        {"k" * MAX_JSON_OBJECT_KEY_LENGTH: None},
        depth_boundary,
        node_boundary,
    )
    for value in exact_values:
        payload = json.dumps({"value": value}, separators=(",", ":")).encode()
        assert _protocol_error_code(lambda payload=payload: parse_observer_request(payload)) == (
            "OBS_PROTOCOL_INVALID_REQUEST"
        )


def test_json_resource_cap_overruns_have_distinct_content_free_diagnostics() -> None:
    node_overrun = [
        *([[None] * 1000 for _ in range(9)]),
        [None] * (MAX_JSON_NODES - 9011),
    ]
    overruns: tuple[tuple[object, str], ...] = (
        ([None] * (MAX_JSON_ARRAY_ITEMS + 1), "OBS_PROTOCOL_JSON_ARRAY_LIMIT"),
        (
            {f"k{index}": None for index in range(MAX_JSON_OBJECT_PROPERTIES + 1)},
            "OBS_PROTOCOL_JSON_OBJECT_LIMIT",
        ),
        ("x" * (MAX_JSON_STRING_LENGTH + 1), "OBS_PROTOCOL_JSON_STRING_LIMIT"),
        (
            {"k" * (MAX_JSON_OBJECT_KEY_LENGTH + 1): None},
            "OBS_PROTOCOL_JSON_KEY_LIMIT",
        ),
        (node_overrun, "OBS_PROTOCOL_JSON_NODE_LIMIT"),
    )
    for value, expected_code in overruns:
        payload = json.dumps({"value": value}, separators=(",", ":")).encode()
        with pytest.raises(ObserverProtocolError) as captured:
            parse_observer_request(payload)
        error = captured.value
        assert error.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
        assert str(error.diagnostic.code) == expected_code
        assert repr(value) not in error.diagnostic.message

    for nesting in (MAX_JSON_DEPTH + 2, 2000):
        nested = "[" * nesting + "null" + "]" * nesting
        payload = ('{"value":' + nested + "}").encode()
        with pytest.raises(ObserverProtocolError) as captured:
            parse_observer_request(payload)
        assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
        assert str(captured.value.diagnostic.code) == "OBS_PROTOCOL_JSON_DEPTH_LIMIT"


def test_outbound_canonical_wire_enforces_exact_message_size_boundary() -> None:
    empty = _BoundaryWireModel(payload="")
    overhead = len(canonical_observer_wire_bytes(empty))
    boundary = _BoundaryWireModel(payload="x" * (MAX_OBSERVER_MESSAGE_BYTES - overhead))
    assert len(canonical_observer_wire_bytes(boundary)) == MAX_OBSERVER_MESSAGE_BYTES

    over_boundary = _BoundaryWireModel(payload="x" * (MAX_OBSERVER_MESSAGE_BYTES - overhead + 1))
    with pytest.raises(ObserverProtocolError) as captured:
        canonical_observer_wire_bytes(over_boundary)
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert str(captured.value.diagnostic.code) == "OBS_PROTOCOL_MESSAGE_TOO_LARGE"


def test_legal_observe_request_cannot_serialize_past_outbound_cap() -> None:
    parameters = {f"p{index}": "x" * MAX_JSON_STRING_LENGTH for index in range(5)}
    queries = tuple(_query(f"key_{index}", parameters=parameters) for index in range(64))
    request = _observe_request(queries=queries)
    with pytest.raises(ObserverProtocolError) as captured:
        canonical_observer_wire_bytes(request)
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert str(captured.value.diagnostic.code) == "OBS_PROTOCOL_MESSAGE_TOO_LARGE"


def test_invalid_input_diagnostics_do_not_retain_or_render_secret_content() -> None:
    payload = json.dumps(
        {
            "protocol_version": "1.0",
            "request_id": REQUEST_ID,
            "operation": "capabilities",
            "unknown_secret": CANARY,
        }
    ).encode()
    with pytest.raises(ObserverProtocolError) as captured:
        parse_observer_request(payload)
    error = captured.value
    assert CANARY not in str(error)
    assert CANARY not in repr(error)
    assert CANARY not in error.diagnostic.message
    assert error.__cause__ is None


def test_observation_record_statuses_and_error_shapes_match_schema() -> None:
    for status in ObservationStatus:
        record = _record(status=status)
        _assert_schema_accepts("observation-record.schema.json", record.wire_dict())
    base = _record().wire_dict()
    cases = [
        {**base, "snapshot_id": None},
        {
            **base,
            "status": "error",
            "snapshot_id": None,
            "evidence": [],
            "error": None,
        },
        {
            **base,
            "status": "timeout",
            "snapshot_id": None,
            "evidence": [_evidence().wire_dict()],
            "error": {
                "category": "timeout",
                "message_redacted": "safe",
            },
        },
    ]
    for document in cases:
        with pytest.raises(ValidationError):
            ObservationRecord.model_validate(document)
        assert _schema_errors("observation-record.schema.json", document)


def test_observation_record_rejects_cross_kind_ids_invalid_time_and_duplicates() -> None:
    base = _record().wire_dict()
    for field, invalid in (
        ("record_id", SAMPLE_ID),
        ("scenario_id", EVENT_ID),
        ("event_id", SCENARIO_ID),
        ("observation_id", EVENT_ID),
        ("sample_id", RECORD_ID),
        ("recorded_at", "2026-02-30T00:00:00Z"),
    ):
        document = deepcopy(base)
        document[field] = invalid
        with pytest.raises(ValidationError):
            ObservationRecord.model_validate(document)
    duplicate = deepcopy(base)
    duplicate["evidence"] = [_evidence().wire_dict(), _evidence().wire_dict()]
    with pytest.raises(ValidationError, match="unique"):
        ObservationRecord.model_validate(duplicate)


def test_static_registry_is_closed_complete_and_has_full_shared_contract_suite() -> None:
    expected_test_ids = {
        "VT-API-004",
        "VT-ASSERT-016",
        "VT-OBS-001",
        "VT-OBS-009",
        "VT-OBS-012",
        "VT-OBS-013",
        "VT-OBS-014",
        "VT-OBS-015",
        "VT-OBS-016",
        "VT-OBS-020",
        "VT-PRIV-009",
        "VT-REL-009",
        "VT-TEST-002",
    }
    assert set(BUILTIN_OBSERVER_REGISTRY.kinds) == set(BuiltinObserverKind)
    suites = {
        registration.contract_test_ids for registration in BUILTIN_OBSERVER_REGISTRY.registrations
    }
    assert len(suites) == 1
    assert set(next(iter(suites))) == expected_test_ids
    assert {
        registration.module_name for registration in BUILTIN_OBSERVER_REGISTRY.registrations
    } == set(BUILTIN_OBSERVER_MODULES.values())


def test_registry_completeness_accepts_one_nominal_implementation_per_module() -> None:
    class CommandObserver(Observer):
        BUILTIN_KIND = BuiltinObserverKind.COMMAND

        async def invoke(self, request: ObserverRequest) -> ObserverResponse:
            return _response(request_id=request.request_id)

    class HttpObserver(Observer):
        BUILTIN_KIND = BuiltinObserverKind.HTTP

        async def invoke(self, request: ObserverRequest) -> ObserverResponse:
            return _response(request_id=request.request_id)

    CommandObserver.__module__ = BUILTIN_OBSERVER_MODULES[BuiltinObserverKind.COMMAND]
    HttpObserver.__module__ = BUILTIN_OBSERVER_MODULES[BuiltinObserverKind.HTTP]
    validate_builtin_registry_completeness(
        BUILTIN_OBSERVER_REGISTRY,
        implementation_types=(CommandObserver, HttpObserver),
        present_modules=tuple(BUILTIN_OBSERVER_MODULES.values()),
    )


def test_module_inventory_recurses_without_importing_and_covers_package_native_artifacts(
    tmp_path: Path,
) -> None:
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "protocol.py").write_text("raise RuntimeError('must not import')", encoding="utf-8")
    (tmp_path / "command.py").write_text("raise RuntimeError('must not import')", encoding="utf-8")
    (tmp_path / "ignored.pyi").write_text("", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "__init__.py").write_text(
        "raise RuntimeError('must not import')",
        encoding="utf-8",
    )
    native_suffix = EXTENSION_SUFFIXES[0]
    (nested / f"native{native_suffix}").write_bytes(b"not-a-loadable-extension")

    modules = discover_builtin_observer_modules(
        tmp_path,
        package_module="test_observers",
    )

    assert modules == (
        "test_observers",
        "test_observers.command",
        "test_observers.nested",
        "test_observers.nested.native",
    )


def test_recursive_or_native_unregistered_module_fails_completeness(tmp_path: Path) -> None:
    nested = tmp_path / "rogue"
    nested.mkdir()
    (nested / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / f"native{EXTENSION_SUFFIXES[0]}").write_bytes(b"not-loadable")
    modules = discover_builtin_observer_modules(
        tmp_path,
        package_module="webhook_receiver_conformance.observers",
    )
    assert "webhook_receiver_conformance.observers.native" in modules
    assert "webhook_receiver_conformance.observers.rogue" in modules
    with pytest.raises(ObserverRegistryError) as captured:
        validate_builtin_registry_completeness(
            BUILTIN_OBSERVER_REGISTRY,
            implementation_types=(),
            present_modules=modules,
        )
    assert captured.value.code == "OBS_BUILTIN_MODULE_UNDECLARED"


def test_added_enum_and_mapping_category_cannot_expand_frozen_v01_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExpandedBuiltinObserverKind(StrEnum):
        COMMAND = "command"
        HTTP = "http"
        NATIVE = "native"

    expanded_modules = MappingProxyType(
        {
            ExpandedBuiltinObserverKind.COMMAND: BUILTIN_OBSERVER_MODULES[
                BuiltinObserverKind.COMMAND
            ],
            ExpandedBuiltinObserverKind.HTTP: BUILTIN_OBSERVER_MODULES[BuiltinObserverKind.HTTP],
            ExpandedBuiltinObserverKind.NATIVE: ("webhook_receiver_conformance.observers.native"),
        }
    )
    monkeypatch.setattr(
        protocol_module,
        "BuiltinObserverKind",
        ExpandedBuiltinObserverKind,
    )
    monkeypatch.setattr(protocol_module, "BUILTIN_OBSERVER_MODULES", expanded_modules)
    with pytest.raises(ObserverRegistryError) as captured:
        validate_builtin_registry_completeness(
            BUILTIN_OBSERVER_REGISTRY,
            implementation_types=(),
            present_modules=(),
        )
    assert captured.value.code == "OBS_BUILTIN_REGISTRY_INCOMPLETE"


def test_registry_snapshots_registration_values_against_alias_mutation() -> None:
    command = BUILTIN_OBSERVER_REGISTRY.registration(BuiltinObserverKind.COMMAND)
    http = BUILTIN_OBSERVER_REGISTRY.registration(BuiltinObserverKind.HTTP)
    registry = StaticObserverRegistry((command, http))
    expected_module = command.module_name
    expected_tests = command.contract_test_ids

    object.__setattr__(command, "module_name", "webhook_receiver_conformance.observers.rogue")
    object.__setattr__(command, "contract_test_ids", ("VT-ROGUE",))
    assert registry.registration(BuiltinObserverKind.COMMAND).module_name == expected_module
    assert registry.registration(BuiltinObserverKind.COMMAND).contract_test_ids == expected_tests

    exposed = registry.registration(BuiltinObserverKind.COMMAND)
    object.__setattr__(exposed, "module_name", "webhook_receiver_conformance.observers.rogue")
    assert registry.registration(BuiltinObserverKind.COMMAND).module_name == expected_module
    validate_builtin_registry_completeness(
        registry,
        implementation_types=(),
        present_modules=(),
    )


def test_unregistered_module_or_missing_contract_implementation_fails_completeness() -> None:
    with pytest.raises(ObserverRegistryError) as undeclared:
        validate_builtin_registry_completeness(
            BUILTIN_OBSERVER_REGISTRY,
            implementation_types=(),
            present_modules=("webhook_receiver_conformance.observers.third_party",),
        )
    assert undeclared.value.code == "OBS_BUILTIN_MODULE_UNDECLARED"
    with pytest.raises(ObserverRegistryError) as missing:
        validate_builtin_registry_completeness(
            BUILTIN_OBSERVER_REGISTRY,
            implementation_types=(),
            present_modules=tuple(BUILTIN_OBSERVER_MODULES.values()),
        )
    assert missing.value.code == "OBS_BUILTIN_REGISTRY_INCOMPLETE"


def test_registry_rejects_omitted_closed_category_and_duplicate_registration() -> None:
    command = BUILTIN_OBSERVER_REGISTRY.registration(BuiltinObserverKind.COMMAND)
    incomplete = StaticObserverRegistry((command,))
    with pytest.raises(ObserverRegistryError) as captured:
        validate_builtin_registry_completeness(
            incomplete,
            implementation_types=(),
            present_modules=(),
        )
    assert captured.value.code == "OBS_BUILTIN_REGISTRY_INCOMPLETE"
    with pytest.raises(ValueError, match="more than once"):
        StaticObserverRegistry((command, command))
    with pytest.raises(ValueError, match="stable VT"):
        ObserverContractRegistration(
            kind=BuiltinObserverKind.COMMAND,
            module_name=BUILTIN_OBSERVER_MODULES[BuiltinObserverKind.COMMAND],
            contract_test_ids=("not-a-vt",),
        )


def test_protocol_source_has_no_plugin_or_dynamic_loader_surface() -> None:
    source = (
        ROOT / "src" / "webhook_receiver_conformance" / "observers" / "protocol.py"
    ).read_text(encoding="utf-8")
    assert "entry_points" not in source
    assert "import_module" not in source
    assert "plugin loader" not in source.lower()
