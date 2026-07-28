"""Dependency-light ASGI surface for the correct reference receiver."""
# ruff: noqa: EM101, EM102, PLR0911, PLR2004, TRY003

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, Final, cast
from urllib.parse import unquote

from .receiver import (
    MAX_REQUEST_BYTES,
    CorrectReferenceReceiver,
    ObserverEvidenceName,
    ReferenceAuthenticationError,
    ReferenceCapabilityError,
    ReferenceProbeRequest,
    ReferenceRequest,
    SignatureProfile,
)

AsgiMessage = MutableMapping[str, Any]
AsgiReceive = Callable[[], Awaitable[AsgiMessage]]
AsgiSend = Callable[[AsgiMessage], Awaitable[None]]
_MAX_PROBE_BYTES: Final = 64 * 1024


class ReferenceAsgiApp:
    """Expose webhook and isolated test-probe routes without framework coupling."""

    __slots__ = ("_receiver",)

    def __init__(self, receiver: CorrectReferenceReceiver) -> None:
        """Bind the ASGI surface to one configured receiver."""
        self._receiver = receiver

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        """Handle one ASGI HTTP or lifespan interaction."""
        scope_type = scope.get("type")
        if scope_type == "lifespan":
            await _lifespan(receive, send)
            return
        if scope_type != "http":
            await _plain_response(send, 404)
            return
        method = scope.get("method")
        path = scope.get("path")
        if type(method) is not str or type(path) is not str:
            await _plain_response(send, 400)
            return
        if method == "GET" and path == "/health":
            await _json_response(send, 200, {"status": "ok"})
            return
        if method == "POST" and path == "/__test__/observe":
            await self._observe(receive, send)
            return
        if method != "POST" or not path.startswith("/webhooks/"):
            await _plain_response(send, 404)
            return
        segments = path.split("/")
        if len(segments) != 4:
            await _plain_response(send, 404)
            return
        try:
            profile = SignatureProfile(unquote(segments[2]))
            account_id = unquote(segments[3])
            body = await _read_body(receive, limit=MAX_REQUEST_BYTES)
            headers = _headers(scope)
            request = ReferenceRequest(profile, account_id, body, headers)
        except (LookupError, TypeError, ValueError):
            await _plain_response(send, 400)
            return
        response = self._receiver.handle(request)
        await _empty_response(
            send,
            response.status_code,
            ((b"x-reference-outcome", response.outcome.value.encode("ascii")),),
        )

    async def _observe(self, receive: AsgiReceive, send: AsgiSend) -> None:
        try:
            body = await _read_body(receive, limit=_MAX_PROBE_BYTES)
            payload = _json_object(body)
            token = _required_text(payload, "token")
            capabilities = _text_tuple(payload, "capabilities")
            raw_names = _text_tuple(payload, "evidence_names")
            request = ReferenceProbeRequest(
                token=token,
                capabilities=capabilities,
                evidence_names=tuple(ObserverEvidenceName(value) for value in raw_names),
                event_ids=_text_tuple(payload, "event_ids", default=()),
                order_ids=_text_tuple(payload, "order_ids", default=()),
            )
            response = self._receiver.probe(request)
        except ReferenceAuthenticationError:
            await _plain_response(send, 401)
            return
        except ReferenceCapabilityError:
            await _plain_response(send, 422)
            return
        except (LookupError, TypeError, UnicodeDecodeError, ValueError):
            await _plain_response(send, 400)
            return
        await _json_response(
            send,
            200,
            {
                "snapshot_id": response.snapshot_id,
                "capabilities": list(response.capabilities),
                "evidence": response.evidence,
            },
        )


async def _lifespan(receive: AsgiReceive, send: AsgiSend) -> None:
    while True:
        message = await receive()
        message_type = message.get("type")
        if message_type == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif message_type == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return


async def _read_body(receive: AsgiReceive, *, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            raise ValueError("unexpected ASGI message")
        chunk = message.get("body", b"")
        if type(chunk) is not bytes:
            raise TypeError("ASGI request body must be bytes")
        size += len(chunk)
        if size > limit:
            raise ValueError("request body exceeds limit")
        chunks.append(chunk)
        if message.get("more_body", False) is not True:
            return b"".join(chunks)


def _headers(scope: MutableMapping[str, Any]) -> tuple[tuple[str, str], ...]:
    value = scope.get("headers", [])
    if not isinstance(value, list):
        raise TypeError("ASGI headers must be a list")
    result: list[tuple[str, str]] = []
    for raw_item in cast("list[object]", value):
        if not isinstance(raw_item, tuple):
            raise TypeError("ASGI header entry is malformed")
        item = cast("tuple[object, ...]", raw_item)
        if len(item) != 2 or type(item[0]) is not bytes or type(item[1]) is not bytes:
            raise TypeError("ASGI header entry is malformed")
        result.append((item[0].decode("latin-1"), item[1].decode("latin-1")))
    return tuple(result)


def _json_object(body: bytes) -> dict[str, object]:
    value: object = json.loads(body)
    if not isinstance(value, dict):
        raise TypeError("request JSON must be an object")
    return cast("dict[str, object]", value)


def _required_text(value: dict[str, object], name: str) -> str:
    result = value.get(name)
    if type(result) is not str:
        raise TypeError(f"{name} must be text")
    return result


def _text_tuple(
    value: dict[str, object],
    name: str,
    *,
    default: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    raw = value.get(name, default)
    if not isinstance(raw, (list, tuple)):
        raise TypeError(f"{name} must be a text array")
    items = cast("list[object] | tuple[object, ...]", raw)
    if any(type(item) is not str for item in items):
        raise TypeError(f"{name} must be a text array")
    return tuple(cast("str", item) for item in items)


async def _json_response(
    send: AsgiSend,
    status: int,
    payload: dict[str, object],
) -> None:
    body = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _plain_response(send: AsgiSend, status: int) -> None:
    await _empty_response(send, status, ())


async def _empty_response(
    send: AsgiSend,
    status: int,
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    response_headers = [
        (b"content-length", b"0"),
        (b"cache-control", b"no-store"),
        *headers,
    ]
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": response_headers,
        }
    )
    await send({"type": "http.response.body", "body": b""})


__all__ = ["ReferenceAsgiApp"]
