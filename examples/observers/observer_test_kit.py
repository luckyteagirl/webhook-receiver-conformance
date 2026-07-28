"""Run the same schema and behavior checks against both example observer transports."""
# ruff: noqa: EM102, I001, INP001, RUF100, S105, S310, S603, T201, TC003, TRY003

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from http_observer import make_server

ROOT = Path(__file__).resolve().parents[2]
OBSERVER_ROOT = Path(__file__).resolve().parent
TOKEN = "local-observer-token-for-tests"
CAPABILITY_REQUEST = {
    "protocol_version": "1.0",
    "request_id": "request_01J00000000000000000000000",
    "operation": "capabilities",
}
OBSERVE_REQUEST = {
    "protocol_version": "1.0",
    "request_id": "request_01J00000000000000000000001",
    "sample_id": "sample_01J00000000000000000000000",
    "operation": "observe",
    "run_id": "123e4567-e89b-42d3-a456-426614174000",
    "scenario_id": "scenario_01J00000000000000000000000",
    "event_id": "event_01J00000000000000000000000",
    "checkpoint": "after_delivery",
    "queries": [{"key": "processing_count", "type": "integer", "parameters": {}}],
}


def _validators() -> tuple[Draft202012Validator, Draft202012Validator]:
    documents = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((ROOT / "schemas").glob("observer-*.schema.json"))
    ]
    resources = [
        (cast("str", document["$id"]), Resource.from_contents(document)) for document in documents
    ]
    registry = Registry().with_resources(resources)
    by_title = {cast("str", document["title"]): document for document in documents}
    return (
        Draft202012Validator(by_title["Observer protocol request"], registry=registry),
        Draft202012Validator(by_title["Observer protocol response"], registry=registry),
    )


def _create_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE webhook_inbox (
                state TEXT NOT NULL
            );
            INSERT INTO webhook_inbox (state) VALUES ('processed');
            """
        )
    finally:
        connection.close()


def _command_invoke(database: Path, request: dict[str, object]) -> dict[str, object]:
    environment = {
        **os.environ,
        "WEBHOOK_OBSERVER_TOKEN": TOKEN,
        "WEBHOOK_RECEIVER_DB": str(database),
    }
    completed = subprocess.run(
        [sys.executable, str(OBSERVER_ROOT / "command_observer.py")],
        input=json.dumps(request),
        capture_output=True,
        check=True,
        encoding="utf-8",
        env=environment,
        timeout=5,
    )
    return cast("dict[str, object]", json.loads(completed.stdout))


def _http_invoke(base_url: str, request: dict[str, object]) -> dict[str, object]:
    route = cast("str", request["operation"])
    wire = json.dumps(request, separators=(",", ":")).encode()
    http_request = urllib.request.Request(
        f"{base_url}/{route}",
        data=wire,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(http_request, timeout=5) as response:  # noqa: S310
        return cast("dict[str, object]", json.load(response))


def _exercise(
    name: str,
    invoke: Callable[[dict[str, object]], dict[str, object]],
) -> None:
    request_validator, response_validator = _validators()
    for request in (CAPABILITY_REQUEST, OBSERVE_REQUEST):
        request_validator.validate(request)
        response = invoke(request)
        response_validator.validate(response)
        if response["request_id"] != request["request_id"]:
            raise RuntimeError(f"{name} observer did not preserve request_id")
        if response["status"] != "ok":
            raise RuntimeError(f"{name} observer did not return ok")
    observed = invoke(OBSERVE_REQUEST)
    if observed["evidence"] != [
        {
            "key": "processing_count",
            "sensitive": False,
            "value": 1,
            "value_type": "integer",
        }
    ]:
        raise RuntimeError(f"{name} observer returned unexpected evidence")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="observer-example-kit-") as temporary:
        database = Path(temporary) / "receiver.sqlite3"
        _create_database(database)
        _exercise("command", lambda request: _command_invoke(database, request))
        server = make_server(database=database, token=TOKEN, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            _exercise(
                "http",
                lambda request: _http_invoke(f"http://{host}:{port}", request),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print("command and HTTP observer examples passed the shared test kit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
