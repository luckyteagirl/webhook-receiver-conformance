"""JSON stdin/stdout command observer for the local example receiver."""
# ruff: noqa: INP001, RUF100, T201

from __future__ import annotations

import os
import sys
from pathlib import Path

from observer_service import ObserverExampleError, encode_response, parse_request, response_for


def main() -> int:
    database_value = os.environ.get("WEBHOOK_RECEIVER_DB")
    token = os.environ.get("WEBHOOK_OBSERVER_TOKEN")
    if database_value is None or token is None:
        print("observer environment is incomplete", file=sys.stderr)
        return 2
    try:
        request = parse_request(sys.stdin.buffer.read(1024 * 1024 + 1))
        response = response_for(request, database=Path(database_value))
    except (ObserverExampleError, ValueError):
        print("observer request could not be processed", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(encode_response(response))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
