"""Result-summary and stable CLI exit-code contract."""
# ruff: noqa: INP001

from __future__ import annotations

from datetime import UTC, datetime
from itertools import product

import pytest

from webhook_receiver_conformance.cli.exit_codes import (
    EXIT_CODE_MAPPINGS,
    CommandSurface,
    exit_mapping_for,
    process_exit_code,
)
from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AttemptClassification,
    AttemptEvidenceState,
    EvidenceValueType,
    ObservationStatus,
)
from webhook_receiver_conformance.domain.models import (
    ArtifactPaths,
    AssertionEvaluation,
    AttemptEvidence,
    RequestMetadata,
    ResponseMetadata,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory
from webhook_receiver_conformance.observers.protocol import (
    ObservationRecord,
    ObserverEvidence,
)
from webhook_receiver_conformance.reporting.summary import (
    SummarySource,
    build_result_summary,
    pairwise_reduce,
    reduce_result_categories,
)

RUN_ID = "00000000-0000-4000-8000-000000000602"
OTHER_RUN_ID = "00000000-0000-4000-8000-000000000603"
MANIFEST_ID = "a" * 64
SCENARIO_ID = f"scenario_{1:026d}"
NOW = datetime(2026, 7, 27, 23, 0, tzinfo=UTC)

PRECEDENCE = (
    ResultCategory.HARNESS_ERROR,
    ResultCategory.INVALID_INPUT,
    ResultCategory.AMBIGUOUS,
    ResultCategory.ENVIRONMENT_ERROR,
    ResultCategory.UNSUPPORTED,
    ResultCategory.RECEIVER_FAILURE,
    ResultCategory.CANCELLED,
    ResultCategory.PASS,
)
EXPECTED_EXITS = {
    ResultCategory.PASS: ExitCode.PASS,
    ResultCategory.RECEIVER_FAILURE: ExitCode.RECEIVER_FAILURE,
    ResultCategory.INVALID_INPUT: ExitCode.INVALID_INPUT,
    ResultCategory.ENVIRONMENT_ERROR: ExitCode.ENVIRONMENT_FAILURE,
    ResultCategory.AMBIGUOUS: ExitCode.AMBIGUOUS,
    ResultCategory.HARNESS_ERROR: ExitCode.HARNESS_FAILURE,
    ResultCategory.UNSUPPORTED: ExitCode.UNSUPPORTED,
    ResultCategory.CANCELLED: ExitCode.CANCELLED,
}


def _attempt(*, run_id: str = RUN_ID) -> AttemptEvidence:
    return AttemptEvidence(
        record_id=f"record_{1:026d}",
        run_id=run_id,
        scenario_id=SCENARIO_ID,
        event_id=f"event_{1:026d}",
        delivery_id=f"delivery_{1:026d}",
        attempt_id=f"attempt_{1:026d}",
        sequence=1,
        recorded_at=NOW,
        state=AttemptEvidenceState.ACKNOWLEDGED,
        classification=AttemptClassification.RECEIVER_ACCEPTED,
        request=RequestMetadata(
            url_redacted="https://receiver.invalid/[REDACTED]",
            body_sha256=f"sha256:{'b' * 64}",
            byte_length=12,
            header_names=("content-type",),
        ),
        response=ResponseMetadata(
            status=204,
            captured_bytes=0,
        ),
    )


def _observation(*, run_id: str = RUN_ID) -> ObservationRecord:
    return ObservationRecord(
        schema_version="1.0",
        record_id=f"record_{2:026d}",
        run_id=run_id,
        scenario_id=SCENARIO_ID,
        event_id=f"event_{1:026d}",
        observation_id=f"observation_{1:026d}",
        sample_id=f"sample_{1:026d}",
        observer_id="receiver_state",
        sample_sequence=1,
        recorded_at="2026-07-27T23:00:00.000000Z",
        status=ObservationStatus.OK,
        snapshot_id="snapshot-1",
        evidence=(
            ObserverEvidence(
                key="processing_count",
                value_type=EvidenceValueType.INTEGER,
                value=1,
            ),
        ),
    )


def _assertion(
    *,
    run_id: str = RUN_ID,
    result: AssertionResult = AssertionResult.PASS,
) -> AssertionEvaluation:
    return AssertionEvaluation(
        record_id=f"record_{3:026d}",
        run_id=run_id,
        scenario_id=SCENARIO_ID,
        assertion_id=f"assertion_{1:026d}",
        evaluation_sequence=1,
        recorded_at=NOW,
        type="processing-count",
        result=result,
        expected=1,
        actual=1,
        comparison="eq",
        evidence_refs=(f"sample_{1:026d}",),
    )


def _source(**overrides: object) -> SummarySource:
    values: dict[str, object] = {
        "run_id": RUN_ID,
        "manifest_id": MANIFEST_ID,
        "generated_at": NOW,
        "scenario_ids": (SCENARIO_ID,),
        "attempts": (_attempt(),),
        "observations": (_observation(),),
        "assertions": (_assertion(),),
        "categories": (ResultCategory.PASS,),
        "failure_refs": (),
        "artifacts": ArtifactPaths(
            manifest="run-manifest.json",
            deliveries="deliveries.jsonl",
            observations="observations.jsonl",
            assertions="assertions.jsonl",
        ),
    }
    values.update(overrides)
    return SummarySource(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("left", "right"),
    tuple(product(ResultCategory, repeat=2)),
)
def test_every_pairwise_category_combination_uses_exact_precedence(
    left: ResultCategory,
    right: ResultCategory,
) -> None:
    expected = min((left, right), key=PRECEDENCE.index)
    assert pairwise_reduce(left, right) is expected
    assert pairwise_reduce(right, left) is expected


def test_reduction_is_order_independent_and_maps_one_terminal_result() -> None:
    result = reduce_result_categories(
        tuple(reversed(PRECEDENCE)),
        surface=CommandSurface.RUN,
    )
    assert result.category is ResultCategory.HARNESS_ERROR
    assert result.exit_code is ExitCode.HARNESS_FAILURE


@pytest.mark.parametrize("surface", tuple(CommandSurface))
@pytest.mark.parametrize("category", tuple(ResultCategory))
def test_run_resume_and_replay_share_the_exact_exit_table(
    surface: CommandSurface,
    category: ResultCategory,
) -> None:
    assert process_exit_code(category, surface=surface) is EXPECTED_EXITS[category]
    assert exit_mapping_for(category, surface=surface).result is category


def test_exit_table_is_total_unique_and_has_no_command_overrides() -> None:
    assert {mapping.result for mapping in EXIT_CODE_MAPPINGS} == set(ResultCategory)
    assert len(EXIT_CODE_MAPPINGS) == len(ResultCategory)
    for category in ResultCategory:
        assert {process_exit_code(category, surface=surface) for surface in CommandSurface} == {
            EXPECTED_EXITS[category]
        }


def test_cancellation_only_overrides_while_run_is_not_durably_terminal() -> None:
    active = reduce_result_categories(
        (ResultCategory.PASS,),
        surface=CommandSurface.RESUME,
        cancellation_requested=True,
    )
    durable = reduce_result_categories(
        (ResultCategory.HARNESS_ERROR,),
        surface=CommandSurface.RESUME,
        durably_terminal=ResultCategory.PASS,
        cancellation_requested=True,
    )
    stronger = reduce_result_categories(
        (ResultCategory.RECEIVER_FAILURE,),
        surface=CommandSurface.RESUME,
        cancellation_requested=True,
    )
    assert active.category is ResultCategory.CANCELLED
    assert durable.category is ResultCategory.PASS
    assert stronger.category is ResultCategory.RECEIVER_FAILURE


def test_empty_fact_set_is_pass() -> None:
    assert (
        reduce_result_categories((), surface=CommandSurface.REPLAY).category is ResultCategory.PASS
    )


def test_summary_derives_counts_and_process_code_from_exported_records() -> None:
    summary = build_result_summary(
        _source(
            categories=(
                ResultCategory.PASS,
                ResultCategory.RECEIVER_FAILURE,
            ),
            failure_refs=(f"record_{3:026d}",),
        )
    )
    assert summary.verdict is ResultCategory.RECEIVER_FAILURE
    assert summary.exit_code is ExitCode.RECEIVER_FAILURE
    assert summary.counts.model_dump() == {
        "scenarios": 1,
        "attempts": 1,
        "observations": 1,
        "assertions": 1,
    }
    wire = summary.model_dump(mode="json")
    assert set(wire) == {
        "schema_version",
        "run_id",
        "manifest_id",
        "generated_at",
        "verdict",
        "exit_code",
        "counts",
        "failure_refs",
        "artifacts",
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"attempts": (_attempt(run_id=OTHER_RUN_ID),)},
        {"observations": (_observation(run_id=OTHER_RUN_ID),)},
        {"assertions": (_assertion(run_id=OTHER_RUN_ID),)},
        {"assertions": (_assertion(result=AssertionResult.PENDING),)},
        {"failure_refs": (f"record_{99:026d}",)},
        {"scenario_ids": (SCENARIO_ID, SCENARIO_ID)},
    ],
)
def test_inconsistent_summary_inputs_are_rejected(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(
        ValueError,
        match=r"(outside the summary scope|must be terminal|failure_refs|must be unique)",
    ):
        _source(**overrides)
