"""Remove local host and workspace data from a JUnit XML evidence file."""
# ruff: noqa: INP001, T201

from __future__ import annotations

import argparse
import re
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE: Final = ROOT / "validation" / "evidence" / "windows-cpython-3.12.junit.xml"
_PUBLIC_HOSTNAME: Final = "local-host"
_PUBLIC_WORKSPACE: Final = "WORKSPACE"


def sanitized_junit(
    source: bytes,
    *,
    workspace: Path,
    private_hostname: str,
) -> bytes:
    """Return JUnit XML without the supplied local host or workspace values."""
    text = source.decode("utf-8")
    variants = {
        str(workspace.resolve()),
        str(workspace.resolve()).replace("\\", "/"),
        workspace.resolve().as_posix(),
    }
    for value in sorted(variants, key=len, reverse=True):
        text = re.sub(re.escape(value), _PUBLIC_WORKSPACE, text, flags=re.IGNORECASE)
    if private_hostname:
        text = re.sub(
            re.escape(private_hostname),
            _PUBLIC_HOSTNAME,
            text,
            flags=re.IGNORECASE,
        )
    root = ET.fromstring(text)  # noqa: S314
    for suite in root.iter("testsuite"):
        suite.set("hostname", _PUBLIC_HOSTNAME)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def sanitize_file(
    path: Path,
    *,
    workspace: Path = ROOT,
    private_hostname: str | None = None,
    check: bool = False,
) -> bool:
    """Sanitize one file and return true when its content needs a change."""
    source = path.read_bytes()
    sanitized = sanitized_junit(
        source,
        workspace=workspace,
        private_hostname=private_hostname or socket.gethostname(),
    )
    changed = source != sanitized
    if changed and not check:
        path.write_bytes(sanitized)
    return changed


def main() -> int:
    """Sanitize or check one JUnit evidence file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, nargs="?", default=DEFAULT_EVIDENCE)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--hostname", default=socket.gethostname())
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    changed = sanitize_file(
        arguments.path.resolve(),
        workspace=arguments.workspace.resolve(),
        private_hostname=arguments.hostname,
        check=arguments.check,
    )
    if arguments.check and changed:
        print(f"{arguments.path}: private JUnit data needs sanitization")
        return 1
    print(f"{arguments.path}: {'sanitized' if changed else 'already sanitized'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
