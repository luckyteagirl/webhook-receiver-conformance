"""Compatibility entry point for the minimal configuration's command observer."""
# ruff: noqa: E402, INP001, RUF100

from __future__ import annotations

import os
import sys
from pathlib import Path

OBSERVER_ROOT = Path(__file__).resolve().parents[1] / "observers"
if str(OBSERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(OBSERVER_ROOT))

from observer_service import ObserverExampleError, encode_response, parse_request, response_for


def main() -> int:
    database_value = os.environ.get("TEST_DATABASE_URL")
    if database_value is None:
        return 2
    try:
        request = parse_request(sys.stdin.buffer.read(1024 * 1024 + 1))
        response = response_for(request, database=Path(database_value))
    except (ObserverExampleError, ValueError):
        return 2
    sys.stdout.buffer.write(encode_response(response))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
