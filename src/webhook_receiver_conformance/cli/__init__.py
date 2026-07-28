"""Public command-line entry point with bounded startup fast paths."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .main import app as app

_HELP = """Usage: webhook-conformance [OPTIONS] COMMAND [ARGS]...

Compile and run local webhook receiver conformance scenarios.

Options:
  --json             Emit one JSON result document on stdout.
  --debug            Include a traceback for unexpected internal failures.
  --color TEXT       Presentation policy: auto, always, or never.
  --non-interactive  Fail closed instead of prompting.
  --help             Show this message and exit.

Commands:
  init      Create a minimal local project without overwriting by default.
  validate  Validate configuration and local inputs without network access.
  plan      Compile an immutable run bundle without sending traffic.
  run       Plan if needed, execute deliveries, and write local reports.
  resume    Resume a prior interrupted local run under an explicit policy.
  replay    Verify and replay an immutable local bundle.
  inspect   Inspect sanitized local run evidence.
  report    Verify or regenerate sanitized static reports offline.
  version   Print package and serialized-contract versions.
"""


def _version_fast_path(arguments: list[str]) -> bool:
    if arguments.count("version") != 1 or any(
        value not in {"version", "--json"} for value in arguments
    ):
        return False
    from webhook_receiver_conformance.version import VERSION_METADATA  # noqa: PLC0415

    document = VERSION_METADATA.as_dict()
    if "--json" in arguments:
        sys.stdout.write(
            json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        )
        return True
    sys.stdout.write(
        "\n".join(
            (
                f"webhook-conformance {document['package']}",
                f"configuration schema {document['configuration_schema']}",
                f"manifest schema {document['manifest_schema']}",
                f"observer protocol {document['observer_protocol']}",
                f"report schema {document['report_schema']}",
                f"generator {document['generator_algorithm']}",
                f"sqlite user_version {document['sqlite_user_version']}",
            )
        )
        + "\n"
    )
    return True


def run_cli() -> None:
    """Run the installed CLI, avoiding heavy imports for version and root help."""
    arguments = sys.argv[1:]
    if _version_fast_path(arguments):
        return
    if not arguments or arguments in (["--help"], ["-h"]):
        sys.stdout.write(_HELP)
        raise SystemExit(0 if arguments else 2)
    from .main import run_cli as run_full_cli  # noqa: PLC0415

    run_full_cli()


def __getattr__(name: str) -> object:
    """Lazily expose the Typer application for embedded callers and tests."""
    if name == "app":
        from .main import app  # noqa: PLC0415

        return app
    raise AttributeError(name)


__all__ = ["app", "run_cli"]
