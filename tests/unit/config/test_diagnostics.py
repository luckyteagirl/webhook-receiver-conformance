"""Isolated tests for privacy-safe configuration diagnostics."""
# ruff: noqa: INP001

from __future__ import annotations

from pathlib import Path

import pytest

from webhook_receiver_conformance.config.diagnostics import (
    format_field_path,
    safe_source_label,
)


@pytest.mark.parametrize(
    ("parts", "expected"),
    [
        ((), "$"),
        (("receivers", 0, "target-url"), "$.receivers[0].target-url"),
        (("space key",), "$['space key']"),
        (("quote'key",), "$['quote\\'key']"),
        (("slash\\key",), "$['slash\\\\key']"),
    ],
)
def test_format_field_path_is_stable(
    parts: tuple[str | int, ...],
    expected: str,
) -> None:
    assert format_field_path(parts) == expected


def test_format_field_path_redacts_control_characters_and_oversized_parts() -> None:
    assert format_field_path(("secret\nkey",)) == "$['<invalid-key>']"
    assert format_field_path(("x" * 129,)) == "$['<invalid-key>']"


def test_format_field_path_bounds_the_complete_projection() -> None:
    path = tuple(f"field_{index:04d}" for index in range(100))

    assert format_field_path(path) == "$['<path-omitted>']"


def test_safe_source_label_preserves_normal_paths() -> None:
    path = Path("configuration") / "project.yaml"

    assert safe_source_label(path) == str(path)


def test_safe_source_label_rejects_terminal_controls() -> None:
    assert safe_source_label("project.yaml\x1b[31m") == "<configuration>"
