"""Loopback HTTP observer exposing the v1 /capabilities and /observe routes."""
# ruff: noqa: EM101, INP001, PLR2004, RUF100, T201, TRY003, TRY301

from __future__ import annotations

import argparse
import hmac
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from observer_service import ObserverExampleError, encode_response, parse_request, response_for

_MAX_MESSAGE_BYTES: Final = 1024 * 1024
_DEFAULT_PORT: Final = 8001


def make_server(
    *,
    database: Path,
    token: str,
    port: int,
) -> ThreadingHTTPServer:
    """Create a loopback-only server for tests or the example command."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            route = urlsplit(self.path).path
            if route not in {"/capabilities", "/observe"}:
                self._empty(404)
                return
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied, f"Bearer {token}"):
                self._empty(401)
                return
            if self.headers.get_content_type() != "application/json":
                self._empty(415)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= _MAX_MESSAGE_BYTES:
                    raise ValueError
                request = parse_request(self.rfile.read(length))
                expected_operation = route.removeprefix("/")
                if request.get("operation") != expected_operation:
                    raise ValueError
                response = encode_response(response_for(request, database=database))
            except (ObserverExampleError, ValueError):
                self._empty(400)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(response)

        def _empty(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            del format, args

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def _port(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65535:
        message = "port must be between 1 and 65535"
        raise argparse.ArgumentTypeError(message)
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--port", type=_port, default=_DEFAULT_PORT)
    options = parser.parse_args()
    token = os.environ.get("WEBHOOK_OBSERVER_TOKEN")
    if token is None or not 16 <= len(token.encode()) <= 4096:
        raise SystemExit("WEBHOOK_OBSERVER_TOKEN must contain 16 through 4096 bytes")
    server = make_server(database=options.database, token=token, port=options.port)
    print(f"HTTP observer listening on http://127.0.0.1:{options.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
