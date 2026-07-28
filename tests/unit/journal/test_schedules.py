"""Focused contracts for durable schedule and run-finalization requests."""
# ruff: noqa: INP001

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from webhook_receiver_conformance.domain.enums import RunState
from webhook_receiver_conformance.errors import ResultCategory
from webhook_receiver_conformance.journal.schedules import FullRunCompletionRequest
from webhook_receiver_conformance.journal.transitions import EntityType, TransitionCommand
from webhook_receiver_conformance.scheduler.clocks import TransitionTimestamp

RUN_ID = "00000000-0000-4000-8000-000000000091"
COMPLETED_AT = "2026-07-27T12:00:00Z"
COMPLETED_WALL_TIME = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)


def test_paused_ambiguity_cannot_be_written_as_terminal_completion() -> None:
    """Keep resumable ambiguity free of terminal category and timestamp metadata."""
    transition = TransitionCommand(
        run_id=RUN_ID,
        transition_id="run.pause.ambiguous",
        entity_type=EntityType.RUN,
        entity_id=RUN_ID,
        expected_state=RunState.RUNNING,
        new_state=RunState.PAUSED,
        trigger_category="run_reduction",
        timestamp=TransitionTimestamp(COMPLETED_WALL_TIME, 1),
        owner_epoch=1,
        idempotency_key="run.pause.ambiguous",
    )

    with pytest.raises(ValueError, match="resumable"):
        FullRunCompletionRequest(
            run_id=RUN_ID,
            owner_epoch=1,
            result_category=ResultCategory.AMBIGUOUS,
            completed_at=COMPLETED_AT,
            transition=transition,
        )
