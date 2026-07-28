"""Shared read-only behavior for the command and HTTP observer examples."""
# ruff: noqa: EM101, INP001, RUF100, TC003, TRY003

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Final, cast

from webhook_receiver_conformance.observers.protocol import ObserverRequest

_CAPABILITIES: Final = {
    "evidence_types": ["integer"],
    "evidence_keys": ["processing_count"],
    "read_only": True,
    "idempotent": True,
    "max_queries": 64,
    "supports_pending": False,
    "stable_snapshot_ids": True,
}


class ObserverExampleError(RuntimeError):
    """Safe error raised for invalid local example configuration."""


def response_for(
    request_document: dict[str, object],
    *,
    database: Path,
) -> dict[str, object]:
    """Return one schema-valid, read-only observer response."""
    request = ObserverRequest.model_validate(request_document)
    base: dict[str, object] = {
        "protocol_version": "1.0",
        "request_id": request.request_id,
        "capabilities": _CAPABILITIES,
        "evidence": [],
        "error": None,
    }
    if request.operation.value == "capabilities":
        return {
            **base,
            "status": "ok",
            "snapshot_id": "snapshot_capabilities_v1",
        }
    if any(
        query.key != "processing_count" or query.type.value != "integer"
        for query in request.queries
    ):
        return {
            **base,
            "status": "unsupported",
            "snapshot_id": None,
        }
    processing_count = _processing_count(database)
    evidence = [
        {
            "key": query.key,
            "value_type": "integer",
            "value": processing_count,
            "sensitive": False,
        }
        for query in request.queries
    ]
    canonical = json.dumps(
        evidence,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        **base,
        "status": "ok",
        "snapshot_id": f"snapshot_{hashlib.sha256(canonical).hexdigest()}",
        "evidence": evidence,
    }


def parse_request(payload: bytes) -> dict[str, object]:
    """Parse one bounded JSON object without retaining malformed content."""
    if len(payload) > 1024 * 1024:
        raise ObserverExampleError("observer request exceeds the example byte limit")
    try:
        value: object = json.loads(payload)
    except (UnicodeDecodeError, ValueError) as error:
        raise ObserverExampleError("observer request is not valid JSON") from error
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise ObserverExampleError("observer request must be a JSON object")
    return cast("dict[str, object]", value)


def encode_response(document: dict[str, object]) -> bytes:
    """Encode one deterministic observer response."""
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()


def _processing_count(database: Path) -> int:
    if not database.is_file():
        raise ObserverExampleError("reference receiver database does not exist")
    uri = f"{database.resolve(strict=True).as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=2.0, isolation_level=None)
    try:
        connection.execute("PRAGMA query_only = ON")
        row = connection.execute(
            "SELECT COUNT(*) FROM webhook_inbox WHERE state = 'processed'"
        ).fetchone()
    except sqlite3.Error as error:
        raise ObserverExampleError("reference receiver evidence query failed") from error
    finally:
        connection.close()
    if row is None or type(row[0]) is not int:
        raise ObserverExampleError("reference receiver returned invalid evidence")
    return row[0]
