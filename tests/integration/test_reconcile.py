"""Observer-assisted ambiguity reconciliation integration contract."""
# ruff: noqa: EM101, INP001, PLR0913, S105, TRY003

from __future__ import annotations

from dataclasses import dataclass

import pytest

from webhook_receiver_conformance.domain.enums import (
    AssertionResult,
    AssertionState,
    EvidenceValueType,
    ObservationStatus,
)
from webhook_receiver_conformance.errors import ExitCode, ResultCategory
from webhook_receiver_conformance.observers.protocol import (
    ObservationRecord,
    ObserverCapabilities,
    ObserverEvidence,
)
from webhook_receiver_conformance.recovery.policy import (
    ObservationReconciliationPlan,
)
from webhook_receiver_conformance.recovery.reconcile import (
    AmbiguityReconciler,
    ReconciliationAssertionFact,
    ReconciliationEvidence,
    ReconciliationOutcome,
    ReconciliationReason,
)

RUN_ID = "00000000-0000-4000-8000-000000000509"
SCENARIO_ID = f"scenario_{1:026d}"
DELIVERY_ID = f"delivery_{1:026d}"
ATTEMPT_ID = f"attempt_{1:026d}"
OBSERVATION_ID = f"observation_{1:026d}"
ASSERTION_ONE = f"assertion_{1:026d}"
ASSERTION_TWO = f"assertion_{2:026d}"
SAMPLE_ONE = f"sample_{1:026d}"
SAMPLE_TWO = f"sample_{2:026d}"
SNAPSHOT_ONE = "snapshot-1"
SNAPSHOT_TWO = "snapshot-2"
RECORDED_AT = "2026-07-27T22:00:00.000000Z"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _plan() -> ObservationReconciliationPlan:
    return ObservationReconciliationPlan(
        attempt_id=ATTEMPT_ID,
        scenario_id=SCENARIO_ID,
        delivery_id=DELIVERY_ID,
        observation_id=OBSERVATION_ID,
        assertion_ids=(ASSERTION_ONE, ASSERTION_TWO),
    )


def _capabilities(
    *,
    read_only: bool = True,
    idempotent: bool = True,
    stable_snapshot_ids: bool = True,
) -> ObserverCapabilities:
    return ObserverCapabilities(
        evidence_types=(EvidenceValueType.INTEGER,),
        evidence_keys=("processing_count",),
        read_only=read_only,
        idempotent=idempotent,
        supports_pending=True,
        stable_snapshot_ids=stable_snapshot_ids,
    )


def _record(
    *,
    sample_id: str = SAMPLE_TWO,
    sequence: int = 2,
    status: ObservationStatus = ObservationStatus.OK,
    snapshot_id: str | None = SNAPSHOT_TWO,
    observation_id: str = OBSERVATION_ID,
) -> ObservationRecord:
    return ObservationRecord(
        schema_version="1.0",
        record_id=f"record_{sequence:026d}",
        run_id=RUN_ID,
        scenario_id=SCENARIO_ID,
        observation_id=observation_id,
        sample_id=sample_id,
        observer_id="receiver_state",
        sample_sequence=sequence,
        recorded_at=RECORDED_AT,
        status=status,
        snapshot_id=snapshot_id,
        evidence=(
            (
                ObserverEvidence(
                    key="processing_count",
                    value_type=EvidenceValueType.INTEGER,
                    value=1,
                ),
            )
            if status is ObservationStatus.OK
            else ()
        ),
    )


def _fact(
    assertion_id: str,
    ordinal: int,
    *,
    state: AssertionState = AssertionState.PASSED,
    result: AssertionResult = AssertionResult.PASS,
    sample_id: str = SAMPLE_TWO,
    snapshot_id: str = SNAPSHOT_TWO,
    observation_id: str = OBSERVATION_ID,
) -> ReconciliationAssertionFact:
    return ReconciliationAssertionFact(
        assertion_id=assertion_id,
        evaluation_id=f"evaluation_{ordinal:026d}",
        state=state,
        result=result,
        observation_id=observation_id,
        sample_id=sample_id,
        snapshot_id=snapshot_id,
    )


def _decisive_evidence() -> ReconciliationEvidence:
    return ReconciliationEvidence(
        observations=(
            _record(
                sample_id=SAMPLE_ONE,
                sequence=1,
                status=ObservationStatus.PENDING,
                snapshot_id=None,
            ),
            _record(),
        ),
        assertions=(
            _fact(ASSERTION_ONE, 1),
            _fact(ASSERTION_TWO, 2),
        ),
    )


@pytest.mark.anyio
async def test_decisive_single_snapshot_reconciles_without_rewriting_attempt() -> None:
    calls = 0

    async def supply() -> ReconciliationEvidence:
        nonlocal calls
        calls += 1
        return _decisive_evidence()

    decision = await AmbiguityReconciler().reconcile(
        _plan(),
        _capabilities(),
        supply,
    )

    assert calls == 1
    assert decision.attempt_id == ATTEMPT_ID
    assert decision.outcome is ReconciliationOutcome.RECONCILED
    assert decision.reason is ReconciliationReason.DECISIVE_ASSERTIONS_PASSED
    assert decision.result_category is ResultCategory.PASS
    assert decision.exit_code is ExitCode.PASS
    assert decision.observation_record_ids == (
        f"record_{1:026d}",
        f"record_{2:026d}",
    )
    assert decision.evaluation_ids == (
        f"evaluation_{1:026d}",
        f"evaluation_{2:026d}",
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "capabilities",
    [
        _capabilities(read_only=False),
        _capabilities(idempotent=False),
        _capabilities(stable_snapshot_ids=False),
    ],
)
async def test_ineligible_observer_is_rejected_before_contact(
    capabilities: ObserverCapabilities,
) -> None:
    calls = 0

    async def must_not_supply() -> ReconciliationEvidence:
        nonlocal calls
        calls += 1
        raise AssertionError("ineligible observer must not be contacted")

    decision = await AmbiguityReconciler().reconcile(
        _plan(),
        capabilities,
        must_not_supply,
    )
    assert calls == 0
    assert decision.reason is ReconciliationReason.OBSERVER_INELIGIBLE
    assert decision.outcome is ReconciliationOutcome.AMBIGUOUS
    assert decision.exit_code is ExitCode.AMBIGUOUS


def test_non_read_only_observer_has_one_explicit_call_and_cannot_reconcile() -> None:
    capabilities = _capabilities(read_only=False)
    assert capabilities.explicit_invocation_limit == 1
    decision = AmbiguityReconciler.assess(
        _plan(),
        capabilities,
        _decisive_evidence(),
    )
    assert not decision.reconciled
    assert decision.reason is ReconciliationReason.OBSERVER_INELIGIBLE


@pytest.mark.parametrize(
    ("fact", "reason"),
    [
        (
            _fact(
                ASSERTION_ONE,
                1,
                state=AssertionState.RUNNING,
                result=AssertionResult.PENDING,
            ),
            ReconciliationReason.ASSERTION_PENDING,
        ),
        (
            _fact(
                ASSERTION_ONE,
                1,
                state=AssertionState.UNSUPPORTED,
                result=AssertionResult.SKIPPED,
            ),
            ReconciliationReason.ASSERTION_UNSUPPORTED,
        ),
        (
            _fact(
                ASSERTION_ONE,
                1,
                state=AssertionState.ERROR,
                result=AssertionResult.ERROR,
            ),
            ReconciliationReason.ASSERTION_ERROR,
        ),
        (
            _fact(
                ASSERTION_ONE,
                1,
                state=AssertionState.FAILED,
                result=AssertionResult.FAIL,
            ),
            ReconciliationReason.ASSERTION_CONTRARY,
        ),
    ],
)
def test_nonpassing_assertion_evidence_preserves_ambiguity(
    fact: ReconciliationAssertionFact,
    reason: ReconciliationReason,
) -> None:
    evidence = ReconciliationEvidence(
        observations=(_record(),),
        assertions=(fact, _fact(ASSERTION_TWO, 2)),
    )
    decision = AmbiguityReconciler.assess(
        _plan(),
        _capabilities(),
        evidence,
    )
    assert decision.outcome is ReconciliationOutcome.AMBIGUOUS
    assert decision.reason is reason
    assert decision.result_category is ResultCategory.AMBIGUOUS
    assert decision.exit_code is ExitCode.AMBIGUOUS


@pytest.mark.parametrize(
    ("evidence", "reason"),
    [
        (
            ReconciliationEvidence(
                observations=(),
                assertions=(),
            ),
            ReconciliationReason.OBSERVATION_MISSING,
        ),
        (
            ReconciliationEvidence(
                observations=(
                    _record(
                        status=ObservationStatus.PENDING,
                        snapshot_id=None,
                    ),
                ),
                assertions=(),
            ),
            ReconciliationReason.OBSERVATION_INCONCLUSIVE,
        ),
        (
            ReconciliationEvidence(
                observations=(
                    _record(
                        status=ObservationStatus.UNSUPPORTED,
                        snapshot_id=None,
                    ),
                ),
                assertions=(),
            ),
            ReconciliationReason.OBSERVATION_INCONCLUSIVE,
        ),
        (
            ReconciliationEvidence(
                observations=(_record(),),
                assertions=(_fact(ASSERTION_ONE, 1),),
            ),
            ReconciliationReason.ASSERTION_SET_INCOMPLETE,
        ),
        (
            ReconciliationEvidence(
                observations=(_record(),),
                assertions=(
                    _fact(ASSERTION_ONE, 1),
                    _fact(ASSERTION_ONE, 3),
                    _fact(ASSERTION_TWO, 2),
                ),
            ),
            ReconciliationReason.ASSERTION_SET_CONTRADICTORY,
        ),
        (
            ReconciliationEvidence(
                observations=(_record(),),
                assertions=(
                    _fact(ASSERTION_ONE, 1, snapshot_id=SNAPSHOT_ONE),
                    _fact(ASSERTION_TWO, 2),
                ),
            ),
            ReconciliationReason.SNAPSHOT_MISMATCH,
        ),
    ],
)
def test_incomplete_or_contradictory_evidence_preserves_ambiguity(
    evidence: ReconciliationEvidence,
    reason: ReconciliationReason,
) -> None:
    decision = AmbiguityReconciler.assess(
        _plan(),
        _capabilities(),
        evidence,
    )
    assert not decision.reconciled
    assert decision.reason is reason
    assert decision.exit_code is ExitCode.AMBIGUOUS


@pytest.mark.anyio
async def test_observer_failure_is_sanitized_and_preserves_ambiguity() -> None:
    secret = "observer-secret-must-not-escape"

    async def fail() -> ReconciliationEvidence:
        raise RuntimeError(secret)

    decision = await AmbiguityReconciler().reconcile(
        _plan(),
        _capabilities(),
        fail,
    )
    assert decision.reason is ReconciliationReason.OBSERVER_ERROR
    assert secret not in repr(decision)
    assert decision.exit_code is ExitCode.AMBIGUOUS


@dataclass
class _NotEvidence:
    value: str = "wrong"


@pytest.mark.anyio
async def test_supplier_contract_violation_never_resolves_ambiguity() -> None:
    async def supply_wrong_type() -> ReconciliationEvidence:
        return _NotEvidence()  # type: ignore[return-value]

    decision = await AmbiguityReconciler().reconcile(
        _plan(),
        _capabilities(),
        supply_wrong_type,
    )
    assert decision.reason is ReconciliationReason.OBSERVER_ERROR
    assert decision.exit_code is ExitCode.AMBIGUOUS
