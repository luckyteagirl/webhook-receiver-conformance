"""End-to-end planning and exact-byte request preparation for TASK-0407."""
# ruff: noqa: ANN202, EM101, INP001, PLR2004, S105, TC003, TRY003

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from webhook_receiver_conformance.config.loader import load_project_config
from webhook_receiver_conformance.config.models import (
    AlterAfterSigningMutation,
    ContentTypeMismatchMutation,
    DeliverStep,
    ReplaceJsonValueMutation,
    TruncateBytesMutation,
)
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.http.evidence import HeaderOwner
from webhook_receiver_conformance.http.executor import HttpAttemptCommand
from webhook_receiver_conformance.manifest.compiler import (
    compile_run_bundle,
    load_realized_execution,
)
from webhook_receiver_conformance.network.policy import parse_destination_policy
from webhook_receiver_conformance.runtime.attempts import prepare_realized_attempt
from webhook_receiver_conformance.secrets import SecretResolver
from webhook_receiver_conformance.signatures.hmac_generic import (
    GenericHmacSha256Settings,
    GenericHmacSha256Signer,
)

_CREATED_AT = "2026-07-27T22:00:00Z"
_SEED = "task-0407-realized-seed"
_SECRET = "task-0407-secret-canary"
_FINGERPRINT = "sha256:" + ("42" * 32)


def _mutated_config():
    loaded = load_project_config("examples/project-config.minimal.yaml")
    assert loaded.config is not None
    assert loaded.project_root is not None
    config = loaded.config
    step = cast("DeliverStep", config.scenarios[0].steps[0])
    action = step.deliver.model_copy(
        update={
            "mutations": (
                ReplaceJsonValueMutation.model_validate(
                    {
                        "type": "replace-json-value-v1",
                        "pointer": "/data/amount",
                        "value": 7,
                    }
                ),
                TruncateBytesMutation(type="truncate-bytes-v1", length=64),
                ContentTypeMismatchMutation(
                    type="content-type-mismatch-v1",
                    media_type="text/plain",
                ),
                AlterAfterSigningMutation(
                    type="alter-after-signing-v1",
                    offset=1,
                    xor=1,
                ),
            )
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
    return (
        config.model_copy(
            update={
                "receiver": config.receiver.model_copy(update={"allowed_ports": (8000,)}),
                "scenarios": (scenario,),
            }
        ),
        loaded.project_root,
    )


def _compile(directory: Path):
    config, project_root = _mutated_config()
    return compile_run_bundle(
        config,
        project_root=project_root,
        bundle_directory=directory,
        seed=_SEED,
        created_at=_CREATED_AT,
        python_version="3.13.5",
        dependencies_digest="sha256:" + ("00" * 32),
        secret_fingerprints={"env:WEBHOOK_TEST_SECRET": _FINGERPRINT},
    )


def test_vt_mut_002_replay_loads_realized_parameters_without_generator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _compile(tmp_path / "first")
    second = _compile(tmp_path / "second")
    assert first.manifest_bytes == second.manifest_bytes
    assert tuple(item.to_wire() for item in first.realized_execution) == tuple(
        item.to_wire() for item in second.realized_execution
    )

    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("replay invoked the planning generator")

    monkeypatch.setattr(
        "webhook_receiver_conformance.determinism.generator.ContextGenerator.from_text_seed",
        explode,
    )
    replayed = load_realized_execution(
        first.manifest,
        first.effective_configuration_bytes,
    )
    assert tuple(item.to_wire() for item in replayed) == tuple(
        item.to_wire() for item in first.realized_execution
    )
    assert replayed[0].runtime_mutation_offset == 2
    assert [item.stage.value for item in replayed[0].mutations] == [
        "structural",
        "raw-pre-sign",
        "header-pre-sign",
        "raw-post-sign",
    ]


def test_execution_signs_planned_blob_then_applies_post_sign_bytes(
    tmp_path: Path,
) -> None:
    bundle = _compile(tmp_path)
    recipe = bundle.realized_execution[0]
    snapshot = next(item for item in bundle.blobs if item.sha256 == recipe.request_blob)
    planned_body = snapshot.path.read_bytes()
    assert sha256_digest(planned_body) == recipe.request_blob
    assert len(planned_body) == 64

    config, _project_root = _mutated_config()
    signer_config = config.signers["test_hmac"]
    handle = SecretResolver(environ={"WEBHOOK_TEST_SECRET": _SECRET}).resolve(
        signer_config.secret
    )
    try:
        signer = GenericHmacSha256Signer(
            handle,
            GenericHmacSha256Settings(
                header_name=(signer_config.header_name or "x-webhook-signature").casefold(),
                key_id=signer_config.key_id,
            ),
        )
        base = HttpAttemptCommand(
            policy=parse_destination_policy(config.receiver),
            body=planned_body,
        )
        first = prepare_realized_attempt(base, recipe, signer=signer)
        second = prepare_realized_attempt(base, recipe, signer=signer)
    finally:
        handle.close()

    assert first.command.body == second.command.body
    assert first.command.headers == second.command.headers
    assert first.pipeline.signing_evidence == second.pipeline.signing_evidence
    assert first.pipeline.signed_body_sha256 == recipe.request_blob
    assert first.pipeline.delivered_body_sha256 != recipe.request_blob
    assert first.command.body[1] == (planned_body[1] ^ 1)
    assert [(item.name, item.owner) for item in first.command.headers] == [
        ("content-type", HeaderOwner.USER),
        ("x-test-signature", HeaderOwner.SIGNER),
    ]
    assert first.pipeline.signing_evidence is not None
    assert first.pipeline.signing_evidence.logical_time_ns == recipe.logical_time_ns
    rendered = repr(first)
    assert _SECRET not in rendered
    assert all(header.value not in rendered for header in first.command.headers)


def test_recipe_digest_and_identity_tampering_fail_before_signing(tmp_path: Path) -> None:
    bundle = _compile(tmp_path)
    recipe = bundle.realized_execution[0]
    snapshot = next(item for item in bundle.blobs if item.sha256 == recipe.request_blob)
    config, _project_root = _mutated_config()
    base = HttpAttemptCommand(
        policy=parse_destination_policy(config.receiver),
        body=snapshot.path.read_bytes() + b"x",
    )
    handle = SecretResolver(environ={"WEBHOOK_TEST_SECRET": _SECRET}).resolve(
        config.signers["test_hmac"].secret
    )
    try:
        signer = GenericHmacSha256Signer(handle)
        with pytest.raises(ValueError, match="request blob"):
            prepare_realized_attempt(base, recipe, signer=signer)
    finally:
        handle.close()
