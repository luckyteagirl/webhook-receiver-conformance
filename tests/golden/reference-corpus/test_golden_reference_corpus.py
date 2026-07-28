"""Structural checks for the committed reference-corpus golden matrix."""
# ruff: noqa: INP001, PLR2004

from __future__ import annotations

import json
from pathlib import Path
from typing import cast


def test_golden_matrix_is_closed_and_attributes_one_primary_defect() -> None:
    path = Path(__file__).with_name("matrix.json")
    payload = cast("dict[str, object]", json.loads(path.read_bytes()))
    receivers = cast("list[dict[str, object]]", payload["receivers"])

    assert payload["schema_version"] == "1.0"
    assert payload["result_categories"] == ["pass", "receiver_failure"]
    assert len(receivers) == 10
    assert receivers[0]["receiver_id"] == "REF-CORRECT-001"
    assert receivers[0]["expected_failures"] == []
    assert receivers[0]["primary_violated_requirements"] == []
    assert len({cast("str", row["receiver_id"]) for row in receivers}) == len(receivers)
    for row in receivers[1:]:
        assert cast("list[str]", row["primary_violated_requirements"])
        assert cast("list[str]", row["expected_failures"])
