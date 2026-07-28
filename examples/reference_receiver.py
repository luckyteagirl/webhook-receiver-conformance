"""Loopback server for the repository's correct SQLite-backed reference receiver."""
# ruff: noqa: E402, EM102, INP001, PLR2004, RUF100, T201, TRY003, TRY301

from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar, Final
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reference_receivers.correct.receiver import (
    MAX_REQUEST_BYTES,
    CorrectReferenceReceiver,
    MutableReferenceClock,
    ReferenceRequest,
    ReferenceSignatureConfiguration,
    ReferenceSigningKey,
    SignatureProfile,
    sign_reference_request,
)

_DEFAULT_DATABASE: Final = Path(".webhook-conformance/reference-receiver.sqlite3")
_DEFAULT_PORT: Final = 8000
_FIXED_LOGICAL_SECOND: Final = 0


class _ReferenceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    receiver: ClassVar[CorrectReferenceReceiver]
    signing_key: ClassVar[ReferenceSigningKey]

    def do_GET(self) -> None:
        if urlsplit(self.path).path != "/health":
            self._empty(404)
            return
        body = b'{"status":"ok"}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        parts = urlsplit(self.path).path.split("/")
        if len(parts) != 4 or parts[:2] != ["", "webhooks"]:
            self._empty(404)
            return
        try:
            profile = SignatureProfile(unquote(parts[2]))
            account_id = unquote(parts[3])
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= MAX_REQUEST_BYTES:
                raise ValueError
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError
            headers = tuple(self.headers.items())
            if profile is SignatureProfile.GENERIC_HMAC_SHA256:
                headers = self._verified_reference_headers(body, headers)
            request = ReferenceRequest(
                profile=profile,
                account_id=account_id,
                body=body,
                headers=headers,
            )
        except (TypeError, ValueError):
            self._empty(400)
            return
        response = self.receiver.handle(request)
        self.send_response(response.status_code)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Reference-Outcome", response.outcome.value)
        self.end_headers()

    def _verified_reference_headers(
        self,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
    ) -> tuple[tuple[str, str], ...]:
        supplied = [value for name, value in headers if name.casefold() == "x-test-signature"]
        expected = hmac.digest(self.signing_key.secret, body, "sha256").hex()
        if len(supplied) != 1 or not hmac.compare_digest(supplied[0], expected):
            raise ValueError
        document = json.loads(body)
        if not isinstance(document, dict) or type(document.get("id")) is not str:
            raise ValueError
        return sign_reference_request(
            profile=SignatureProfile.GENERIC_HMAC_SHA256,
            key=self.signing_key,
            body=body,
            event_id=document["id"],
            timestamp=_FIXED_LOGICAL_SECOND,
        )

    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not 16 <= len(value.encode()) <= 4096:
        raise SystemExit(f"{name} must contain 16 through 4096 bytes")
    return value


def _port(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65535:
        message = "port must be between 1 and 65535"
        raise argparse.ArgumentTypeError(message)
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=_DEFAULT_DATABASE)
    parser.add_argument("--port", type=_port, default=_DEFAULT_PORT)
    options = parser.parse_args()
    secret = _required_environment("WEBHOOK_TEST_SECRET")
    observer_token = _required_environment("WEBHOOK_OBSERVER_TOKEN")
    database = options.database.resolve(strict=False)
    database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    signing_key = ReferenceSigningKey("local-example", secret.encode())
    _ReferenceHandler.signing_key = signing_key
    _ReferenceHandler.receiver = CorrectReferenceReceiver(
        database_path=database,
        signature_configurations=(
            ReferenceSignatureConfiguration(
                SignatureProfile.GENERIC_HMAC_SHA256,
                (signing_key,),
            ),
        ),
        observer_token=observer_token,
        clock=MutableReferenceClock(_FIXED_LOGICAL_SECOND),
    )
    server = ThreadingHTTPServer(("127.0.0.1", options.port), _ReferenceHandler)
    print(f"reference receiver listening on http://127.0.0.1:{options.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
