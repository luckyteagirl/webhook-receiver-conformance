"""Focused conformance tests for the realized run-bundle compiler."""
# ruff: noqa: INP001

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator

from webhook_receiver_conformance.config.loader import load_project_config
from webhook_receiver_conformance.config.models import (
    ChangeEventTypeFieldMutation,
    DeliverStep,
    ProjectConfig,
    ReplaceJsonValueMutation,
    RetryOn,
    TruncateBytesMutation,
)
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.fixtures.blobs import BlobStoreError
from webhook_receiver_conformance.manifest.compiler import (
    EFFECTIVE_CONFIG_FILENAME,
    MANIFEST_FILENAME,
    CompiledRunBundle,
    compile_run_bundle,
    generate_preview,
    load_run_manifest,
    manifest_relative_path,
    next_attempt,
)
from webhook_receiver_conformance.manifest.models import RunManifest
from webhook_receiver_conformance.mutations.base import MutationStage, RealizedMutation
from webhook_receiver_conformance.mutations.pipeline import MutationPipeline
from webhook_receiver_conformance.mutations.structural import STRUCTURAL_MUTATION_REGISTRY

_CREATED_AT = "2026-07-26T20:00:00Z"
_SEED = "task-0109-deterministic-seed"
_FINGERPRINT = "sha256:" + ("a5" * 32)
_SECRET_LOOKUP = {"env:WEBHOOK_TEST_SECRET": _FINGERPRINT}


def _config() -> tuple[ProjectConfig, Path]:
    result = load_project_config("examples/project-config.minimal.yaml")
    assert result.config is not None
    assert result.project_root is not None
    return result.config, result.project_root


def _compile(tmp_path: Path, *, config: ProjectConfig | None = None) -> CompiledRunBundle:
    default_config, project_root = _config()
    selected = _unsigned(default_config if config is None else config)
    return compile_run_bundle(
        selected,
        project_root=project_root,
        bundle_directory=tmp_path,
        seed=_SEED,
        created_at=_CREATED_AT,
        python_version="3.13.5",
        dependencies_digest="sha256:" + ("00" * 32),
        secret_fingerprints=_SECRET_LOOKUP,
    )


def _unsigned(selected: ProjectConfig) -> ProjectConfig:
    step = cast("DeliverStep", selected.scenarios[0].steps[0])
    unsigned_action = step.deliver.model_copy(update={"signer": None})
    unsigned_scenario = selected.scenarios[0].model_copy(
        update={
            "steps": (
                step.model_copy(update={"deliver": unsigned_action}),
                *selected.scenarios[0].steps[1:],
            )
        }
    )
    return selected.model_copy(update={"scenarios": (unsigned_scenario,)})


def test_vt_sched_011_persists_normalized_seed_hash_hex(tmp_path: Path) -> None:
    bundle = _compile(tmp_path)
    assert bundle.manifest.generator.normalized_seed_hash_hex == sha256_digest(
        _SEED.encode()
    ).removeprefix("sha256:")
    assert bundle.manifest.generator.seed_fingerprint.startswith("sha256:")
    schema = json.loads(Path("schemas/run-manifest.schema.json").read_bytes())
    assert (
        list(
            Draft202012Validator(schema).iter_errors(  # pyright: ignore[reportUnknownMemberType, reportArgumentType]
                bundle.manifest.to_wire()  # pyright: ignore[reportArgumentType]
            )
        )
        == []
    )


def test_selected_signer_is_rejected_instead_of_silently_miscompiled(
    tmp_path: Path,
) -> None:
    config, project_root = _config()
    with pytest.raises(ValueError, match="selected signer"):
        compile_run_bundle(
            config,
            project_root=project_root,
            bundle_directory=tmp_path,
            seed=_SEED,
            created_at=_CREATED_AT,
            secret_fingerprints={},
        )


def test_non_structural_mutation_is_rejected_instead_of_ignored(tmp_path: Path) -> None:
    config, project_root = _config()
    step = cast("DeliverStep", config.scenarios[0].steps[0])
    action = step.deliver.model_copy(
        update={
            "signer": None,
            "mutations": (TruncateBytesMutation(type="truncate-bytes-v1", length=8),),
        }
    )
    scenario = config.scenarios[0].model_copy(
        update={
            "steps": (
                step.model_copy(update={"deliver": action}),
                *config.scenarios[0].steps[1:],
            )
        }
    )
    changed = config.model_copy(update={"scenarios": (scenario,)})
    with pytest.raises(ValueError, match="non-structural mutations"):
        compile_run_bundle(
            changed,
            project_root=project_root,
            bundle_directory=tmp_path,
            seed=_SEED,
            created_at=_CREATED_AT,
            secret_fingerprints=_SECRET_LOOKUP,
        )


def test_replanning_preserves_ids_schedules_and_manifest(tmp_path: Path) -> None:
    first = _compile(tmp_path / "first")
    second = _compile(tmp_path / "second")
    assert first.manifest_bytes == second.manifest_bytes
    assert first.manifest.manifest_id == second.manifest.manifest_id
    assert first.manifest.scenarios == second.manifest.scenarios
    assert "run_id" not in first.manifest.to_wire()


def test_retry_templates_and_replay_decision_are_deterministic(tmp_path: Path) -> None:
    config, _root = _config()
    step = cast("DeliverStep", config.scenarios[0].steps[0])
    retry = step.deliver.retry
    assert retry is not None
    changed_retry = retry.model_copy(
        update={
            "max_attempts": 2,
            "backoff": (type(retry.jitter)("10ms"),),
            "retry_on": (RetryOn.TIMED_OUT,),
        }
    )
    action = step.deliver.model_copy(update={"retry": changed_retry})
    scenario = config.scenarios[0].model_copy(
        update={
            "steps": (step.model_copy(update={"deliver": action}), *config.scenarios[0].steps[1:])
        }
    )
    changed = config.model_copy(update={"scenarios": (scenario,)})
    delivery = _compile(tmp_path, config=changed).manifest.scenarios[0].deliveries[0]
    assert tuple(item.ordinal for item in delivery.attempt_plan) == (1, 2)
    assert next_attempt(delivery, predecessor_result=None, completed_attempts=0) is not None
    assert next_attempt(delivery, predecessor_result="timed_out", completed_attempts=1) is not None
    assert (
        next_attempt(delivery, predecessor_result="connection_failed", completed_attempts=1) is None
    )
    with pytest.raises(TypeError, match="integer"):
        next_attempt(delivery, predecessor_result=None, completed_attempts=True)
    with pytest.raises(TypeError, match="string or None"):
        next_attempt(delivery, predecessor_result=1, completed_attempts=1)  # type: ignore[arg-type]


def test_structural_lowering_matches_committed_pipeline_bytes(tmp_path: Path) -> None:
    config, project_root = _config()
    step = cast("DeliverStep", config.scenarios[0].steps[0])
    mutation = ChangeEventTypeFieldMutation(
        type="change-event-type-field-v1",
        value="payment.changed",
    )
    action = step.deliver.model_copy(update={"mutations": (mutation,)})
    scenario = config.scenarios[0].model_copy(
        update={
            "steps": (step.model_copy(update={"deliver": action}), *config.scenarios[0].steps[1:])
        }
    )
    changed = config.model_copy(update={"scenarios": (scenario,)})
    bundle = _compile(tmp_path, config=changed)
    request_digest = bundle.manifest.scenarios[0].deliveries[0].attempt_plan[0].request_blob
    request_path = next(item.path for item in bundle.blobs if item.sha256 == request_digest)
    source = (project_root / "fixtures/payment_succeeded.json").read_bytes()
    expected = (
        MutationPipeline(STRUCTURAL_MUTATION_REGISTRY)
        .execute(
            body=source,
            headers=(),
            event_id="planning-event",
            logical_time_ns=0,
            media_type="application/json",
            signer=None,
            mutations=(
                RealizedMutation(
                    operator_id="change-event-type-field-v1",
                    operator_version=1,
                    stage=MutationStage.STRUCTURAL,
                    parameters={
                        "pointer": "/type",
                        "value": "payment.changed",
                        "accept_prior_mutation": False,
                    },
                    parameters_safe={
                        "pointer": "/type",
                        "value": "payment.changed",
                        "accept_prior_mutation": False,
                    },
                ),
            ),
        )
        .body
    )
    assert request_path.read_bytes() == expected
    assert request_digest == sha256_digest(expected)
    golden = json.loads(Path("tests/golden/manifests/structural-pipeline-v1.json").read_bytes())
    assert golden["compatibility_review"]
    assert request_digest == golden["request_blob_sha256"]


def test_effective_config_requires_fingerprints_and_omits_secret_canary(
    tmp_path: Path,
) -> None:
    config, project_root = _config()
    with pytest.raises(ValueError, match="fingerprint"):
        compile_run_bundle(
            _unsigned(config),
            project_root=project_root,
            bundle_directory=tmp_path / "rejected",
            seed=_SEED,
            created_at=_CREATED_AT,
            secret_fingerprints={},
        )
    bundle = _compile(tmp_path / "accepted")
    assert b"WEBHOOK_TEST_SECRET" not in bundle.effective_configuration_bytes
    assert b"env:WEBHOOK_TEST_SECRET" not in bundle.effective_configuration_bytes
    assert _FINGERPRINT.encode() in bundle.effective_configuration_bytes


def test_effective_config_redacts_fixture_paths_but_preserves_literal_env_json(
    tmp_path: Path,
) -> None:
    config, _project_root = _config()
    step = cast("DeliverStep", config.scenarios[0].steps[0])
    mutation = ReplaceJsonValueMutation.model_validate(
        {
            "type": "replace-json-value-v1",
            "pointer": "/data/order_id",
            "value": {"env": "literal-not-a-secret-reference"},
        }
    )
    action = step.deliver.model_copy(update={"mutations": (mutation,)})
    scenario = config.scenarios[0].model_copy(
        update={
            "steps": (
                step.model_copy(update={"deliver": action}),
                *config.scenarios[0].steps[1:],
            )
        }
    )
    changed = config.model_copy(update={"scenarios": (scenario,)})
    bundle = _compile(tmp_path, config=changed)
    effective = json.loads(bundle.effective_configuration_bytes)
    fixture = effective["fixtures"][0]
    assert "path" not in fixture
    assert "schema_path" not in fixture
    assert fixture["path_fingerprint"] == sha256_digest(b"fixtures/payment_succeeded.json")
    assert b"fixtures/payment_succeeded.json" not in bundle.effective_configuration_bytes
    literal = effective["scenarios"][0]["steps"][0]["deliver"]["mutations"][0]["value"]
    assert literal == {"env": "literal-not-a-secret-reference"}


def test_preview_regenerates_exactly_from_bundle_artifacts(tmp_path: Path) -> None:
    bundle = _compile(tmp_path)
    effective = (tmp_path / EFFECTIVE_CONFIG_FILENAME).read_bytes()
    assert generate_preview(bundle.manifest, effective) == bundle.preview_bytes
    assert _FINGERPRINT.encode() not in bundle.preview_bytes
    assert b"WEBHOOK_TEST_SECRET" not in bundle.preview_bytes


@pytest.mark.parametrize(
    "tampered",
    [
        b'{"duplicate":1,"duplicate":2}',
        b'{"float":1.5}',
        b"{",
        (b"[" * 10_000) + b"0" + (b"]" * 10_000),
        b"[]",
        b"\xff",
    ],
)
def test_preview_rejects_invalid_or_tampered_effective_config(
    tmp_path: Path,
    tampered: bytes,
) -> None:
    bundle = _compile(tmp_path)
    with pytest.raises(
        ValueError,
        match=r"duplicate|floating-point|valid JSON|nesting|JSON object|UTF-8",
    ):
        generate_preview(bundle.manifest, tampered)


def test_preview_rejects_valid_json_with_wrong_configuration_digest(
    tmp_path: Path,
) -> None:
    bundle = _compile(tmp_path)
    with pytest.raises(ValueError, match="digest"):
        generate_preview(bundle.manifest, b'{"schema_version":1}')


def test_compiled_bundle_repr_hides_byte_artifacts(tmp_path: Path) -> None:
    bundle = _compile(tmp_path)
    rendered = repr(bundle)
    assert bundle.manifest_bytes.decode() not in rendered
    assert bundle.effective_configuration_bytes.decode() not in rendered
    assert bundle.preview_bytes.decode() not in rendered
    assert "manifest_bytes=" not in rendered


def test_manifest_and_blob_tampering_are_rejected(tmp_path: Path) -> None:
    bundle = _compile(tmp_path)
    manifest_path = tmp_path / MANIFEST_FILENAME
    manifest_wire = json.loads(manifest_path.read_bytes())
    manifest_wire["tool"]["version"] = "tampered"
    manifest_path.write_text(json.dumps(manifest_wire), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest_id"):
        load_run_manifest(tmp_path)

    manifest_path.write_bytes(bundle.manifest_bytes)
    blob = bundle.blobs[0]
    blob.path.write_bytes(blob.path.read_bytes() + b"x")
    with pytest.raises(BlobStoreError):
        load_run_manifest(tmp_path)


def test_manifest_loader_rejects_floats_unsafe_integers_and_changed_content(
    tmp_path: Path,
) -> None:
    bundle = _compile(tmp_path)
    wire = bundle.manifest.to_wire()
    wire["manifest_id"] = "0" * 64
    with pytest.raises(ValueError, match="manifest_id"):
        RunManifest.from_wire(wire)
    with pytest.raises(ValueError, match="floating-point"):
        RunManifest.from_bytes(b'{"schema_version":1.0}')
    wire = bundle.manifest.to_wire()
    scenarios = cast("list[dict[str, object]]", wire["scenarios"])
    deliveries = cast("list[dict[str, object]]", scenarios[0]["deliveries"])
    deliveries[0]["logical_time_ns"] = 9007199254740992
    with pytest.raises(ValueError, match="less than or equal"):
        RunManifest.from_wire(wire, verify=False)


def test_paths_are_forward_slash_relative_and_contained(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b.json"
    assert manifest_relative_path(nested, project_root=tmp_path) == "a/b.json"
    with pytest.raises(ValueError, match="contained"):
        manifest_relative_path(tmp_path.parent / "outside", project_root=tmp_path)
