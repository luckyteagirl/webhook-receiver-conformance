"""Deterministic compiler and atomic materializer for realized run bundles."""
# ruff: noqa: D105, EM101, INP001, PLR0913, TC003, TRY003, TRY004

from __future__ import annotations

import json
import os
import platform
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast
from urllib.parse import urlsplit

from webhook_receiver_conformance.config import models as config_models
from webhook_receiver_conformance.config.schema import MAX_CONFIG_BYTES
from webhook_receiver_conformance.determinism.generator import ContextGenerator
from webhook_receiver_conformance.domain.hashing import (
    CanonicalJson,
    canonical_json_bytes,
    compute_manifest_id,
    sha256_digest,
    validate_sha256_digest,
)
from webhook_receiver_conformance.domain.identifiers import (
    PlannedIdKind,
    planned_id,
    validate_planned_id,
)
from webhook_receiver_conformance.fixtures.blobs import BlobSnapshot, BlobStore
from webhook_receiver_conformance.fixtures.loader import LoadedFixture, load_fixture
from webhook_receiver_conformance.manifest.models import (
    AssertionPlan,
    AttemptTemplate,
    DeliveryPlan,
    EventPlan,
    RunManifest,
    ScenarioPlan,
    validate_blob_entries,
)
from webhook_receiver_conformance.mutations.base import (
    PIPELINE_STAGE_RANK,
    MutationStage,
    RealizedMutation,
    StaticMutationRegistry,
    thaw_parameter_object,
)
from webhook_receiver_conformance.mutations.pipeline import MutationPipeline
from webhook_receiver_conformance.mutations.raw_ops import RAW_MUTATION_REGISTRATIONS
from webhook_receiver_conformance.mutations.signature_ops import (
    SIGNATURE_MUTATION_REGISTRATIONS,
)
from webhook_receiver_conformance.mutations.structural import (
    STRUCTURAL_MUTATION_REGISTRATIONS,
)
from webhook_receiver_conformance.version import VERSION_METADATA

MANIFEST_FILENAME: Final = "run-manifest.json"
EFFECTIVE_CONFIG_FILENAME: Final = "effective-configuration.json"
PREVIEW_FILENAME: Final = "plan-preview.json"
JITTER_POLICY_VERSION: Final = "retry-jitter-v1"
_EMPTY_HEADERS_DIGEST: Final = sha256_digest(b"[]")
_PLANNING_STAGE_MAX_RANK: Final = PIPELINE_STAGE_RANK[MutationStage.RAW_PRE_SIGN]
_ALL_MUTATION_REGISTRATIONS: Final = (
    *STRUCTURAL_MUTATION_REGISTRATIONS,
    *RAW_MUTATION_REGISTRATIONS,
    *SIGNATURE_MUTATION_REGISTRATIONS,
)
_ALL_MUTATION_REGISTRY: Final = StaticMutationRegistry(_ALL_MUTATION_REGISTRATIONS)
_MUTATION_STAGE_BY_ID: Final = {
    registration.operator_id: registration.stage for registration in _ALL_MUTATION_REGISTRATIONS
}


@dataclass(frozen=True, slots=True)
class CompiledRunBundle:
    """Immutable compiler result, including non-manifest bundle artifacts."""

    manifest: RunManifest
    manifest_bytes: bytes = field(repr=False)
    effective_configuration_bytes: bytes = field(repr=False)
    preview_bytes: bytes = field(repr=False)
    blobs: tuple[BlobSnapshot, ...]
    realized_execution: tuple[RealizedDeliveryExecution, ...] = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class RealizedDeliveryExecution:
    """Digest-bound execution recipe whose stochastic inputs are already fixed."""

    scenario_id: str
    delivery_id: str
    event_id: str
    logical_time_ns: int
    request_blob: str
    media_type: str
    signer_name: str | None
    mutations: tuple[RealizedMutation, ...]
    runtime_mutation_offset: int

    def __post_init__(self) -> None:
        validate_planned_id(self.scenario_id, expected_kind=PlannedIdKind.SCENARIO)
        validate_planned_id(self.delivery_id, expected_kind=PlannedIdKind.DELIVERY)
        validate_planned_id(self.event_id, expected_kind=PlannedIdKind.EVENT)
        if (
            type(self.logical_time_ns) is not int
            or not -((1 << 53) - 1) <= self.logical_time_ns <= (1 << 53) - 1
        ):
            raise ValueError("realized execution logical time must be an I-JSON-safe integer")
        validate_sha256_digest(self.request_blob)
        if type(self.media_type) is not str or not self.media_type:
            raise ValueError("realized execution media type must be a nonempty string")
        if self.signer_name is not None and (
            type(self.signer_name) is not str or not self.signer_name
        ):
            raise ValueError("realized execution signer name must be nonempty or None")
        if type(self.mutations) is not tuple or any(
            type(item) is not RealizedMutation for item in self.mutations
        ):
            raise TypeError("realized execution mutations must be a tuple")
        if type(
            self.runtime_mutation_offset
        ) is not int or not 0 <= self.runtime_mutation_offset <= len(self.mutations):
            raise ValueError("runtime mutation offset is outside the realized sequence")
        ranks = tuple(PIPELINE_STAGE_RANK[item.stage] for item in self.mutations)
        if ranks != tuple(sorted(ranks)):
            raise ValueError("realized mutations are not in fixed pipeline stage order")
        if any(
            rank > _PLANNING_STAGE_MAX_RANK for rank in ranks[: self.runtime_mutation_offset]
        ) or any(
            rank <= _PLANNING_STAGE_MAX_RANK for rank in ranks[self.runtime_mutation_offset :]
        ):
            raise ValueError("runtime mutation offset does not split planning stages")

    @property
    def runtime_mutations(self) -> tuple[RealizedMutation, ...]:
        """Return only stages that must execute around the live signer."""
        return self.mutations[self.runtime_mutation_offset :]

    def to_wire(self) -> dict[str, object]:
        """Return the canonical secret-free execution recipe projection."""
        return {
            "scenario_id": self.scenario_id,
            "delivery_id": self.delivery_id,
            "event_id": self.event_id,
            "logical_time_ns": self.logical_time_ns,
            "request_blob": self.request_blob,
            "media_type": self.media_type,
            "signer_name": self.signer_name,
            "runtime_mutation_offset": self.runtime_mutation_offset,
            "mutations": [
                {
                    "operator_id": mutation.operator_id,
                    "operator_version": mutation.operator_version,
                    "stage": mutation.stage.value,
                    "parameters": thaw_parameter_object(mutation.parameters),
                    "parameters_safe": thaw_parameter_object(mutation.parameters_safe),
                }
                for mutation in self.mutations
            ],
        }

    @classmethod
    def from_wire(cls, value: object) -> RealizedDeliveryExecution:
        """Strictly reconstruct a recipe without invoking a generator."""
        if type(value) is not dict:
            raise ValueError("realized execution entry must be an object")
        wire = cast("dict[str, object]", value)
        expected = {
            "scenario_id",
            "delivery_id",
            "event_id",
            "logical_time_ns",
            "request_blob",
            "media_type",
            "signer_name",
            "runtime_mutation_offset",
            "mutations",
        }
        if set(wire) != expected:
            raise ValueError("realized execution entry has an invalid field set")
        mutation_values = wire["mutations"]
        if type(mutation_values) is not list:
            raise ValueError("realized execution mutations must be an array")
        mutations = tuple(
            _realized_mutation_from_wire(item) for item in cast("list[object]", mutation_values)
        )
        signer_name = wire["signer_name"]
        if signer_name is not None and type(signer_name) is not str:
            raise ValueError("realized execution signer name is invalid")
        return cls(
            scenario_id=_wire_string(wire["scenario_id"], "scenario_id"),
            delivery_id=_wire_string(wire["delivery_id"], "delivery_id"),
            event_id=_wire_string(wire["event_id"], "event_id"),
            logical_time_ns=_wire_integer(wire["logical_time_ns"], "logical_time_ns"),
            request_blob=_wire_string(wire["request_blob"], "request_blob"),
            media_type=_wire_string(wire["media_type"], "media_type"),
            signer_name=signer_name,
            mutations=mutations,
            runtime_mutation_offset=_wire_integer(
                wire["runtime_mutation_offset"],
                "runtime_mutation_offset",
            ),
        )


def compile_run_bundle(
    config: config_models.ProjectConfig,
    *,
    project_root: Path,
    bundle_directory: Path,
    created_at: str | None = None,
    seed: str | None = None,
    tool_version: str = VERSION_METADATA.package,
    python_version: str | None = None,
    dependencies_digest: str | None = None,
    secret_fingerprints: Mapping[str, str] | None = None,
    materialize: bool = True,
) -> CompiledRunBundle:
    """Compile fixed inputs without network activity or execution identity."""
    if type(config) is not config_models.ProjectConfig:
        raise TypeError("config must be a validated ProjectConfig")
    selected_seed = config.project.seed if seed is None else seed
    if selected_seed is None:
        raise ValueError("planning requires a normalized non-secret project seed")
    generator = ContextGenerator.from_text_seed(selected_seed)

    bundle_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    store = BlobStore(bundle_directory)
    loaded = {
        fixture.id: load_fixture(
            fixture,
            project_root=project_root,
            max_bytes=config.limits.max_request_bytes,
        )
        for fixture in config.fixtures
    }
    snapshots: dict[str, BlobSnapshot] = {}
    fixture_by_id = {fixture.id: fixture for fixture in config.fixtures}
    for fixture in config.fixtures:
        source = loaded[fixture.id]
        snapshot = store.snapshot(source.body, media_type=source.media_type)
        snapshots[snapshot.sha256] = snapshot

    realized_execution: list[RealizedDeliveryExecution] = []
    scenarios = tuple(
        _compile_scenario(
            scenario,
            scenario_index=scenario_index,
            generator=generator,
            loaded=loaded,
            fixture_by_id=fixture_by_id,
            store=store,
            snapshots=snapshots,
            realized_execution=realized_execution,
        )
        for scenario_index, scenario in enumerate(config.scenarios)
    )
    redacted = _effective_configuration(
        config,
        secret_fingerprints or {},
        selected_seed=selected_seed,
        realized_execution=tuple(realized_execution),
    )
    effective_bytes = canonical_json_bytes(cast("dict[str, CanonicalJson]", redacted))
    configuration_digest = sha256_digest(effective_bytes)
    parsed_target = urlsplit(config.receiver.url)
    if parsed_target.hostname is None:
        raise ValueError("receiver URL has no authorized host")
    manifest_without_id: dict[str, object] = {
        "schema_version": "1.0",
        "created_at": created_at or _utc_now(),
        "tool": {
            "version": tool_version,
            "python": python_version or platform.python_version(),
            **(
                {"dependencies_digest": dependencies_digest}
                if dependencies_digest is not None
                else {}
            ),
        },
        "generator": {
            "algorithm": generator.algorithm_id,
            "seed_fingerprint": f"sha256:{generator.fingerprint}",
            "normalized_seed_hash_hex": generator.normalized_seed_hash.hex(),
        },
        "configuration_digest": configuration_digest,
        "environment": {
            "os": platform.system().casefold(),
            "architecture": platform.machine().casefold(),
            "timezone": "UTC",
        },
        "target_policy": {
            "profile": config.receiver.target_profile.value,
            "authorized_host": parsed_target.hostname,
            "authorized_port": parsed_target.port
            or (443 if parsed_target.scheme == "https" else 80),
        },
        "blobs": [
            snapshot.to_manifest_entry()
            for snapshot in sorted(snapshots.values(), key=lambda item: item.sha256)
        ],
        "scenarios": [
            scenario.model_dump(mode="json", exclude_none=True) for scenario in scenarios
        ],
    }
    manifest_id = compute_manifest_id(manifest_without_id)
    manifest = RunManifest.from_wire(
        {"manifest_id": manifest_id, **manifest_without_id},
        verify=True,
    )
    validate_blob_entries(manifest.blobs)
    preview_bytes = generate_preview(manifest, effective_bytes)
    result = CompiledRunBundle(
        manifest=manifest,
        manifest_bytes=manifest.serialized_bytes(),
        effective_configuration_bytes=effective_bytes + b"\n",
        preview_bytes=preview_bytes,
        blobs=tuple(sorted(snapshots.values(), key=lambda item: item.sha256)),
        realized_execution=tuple(realized_execution),
    )
    if materialize:
        materialize_run_bundle(result, bundle_directory)
    return result


compile_manifest = compile_run_bundle


def materialize_run_bundle(bundle: CompiledRunBundle, directory: Path) -> None:
    """Atomically install the three bounded bundle metadata artifacts."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _atomic_write(directory / MANIFEST_FILENAME, bundle.manifest_bytes)
    _atomic_write(
        directory / EFFECTIVE_CONFIG_FILENAME,
        bundle.effective_configuration_bytes,
    )
    _atomic_write(directory / PREVIEW_FILENAME, bundle.preview_bytes)


def load_run_manifest(directory: Path) -> RunManifest:
    """Load, validate, hash-check, and blob-verify a bundle manifest."""
    manifest = RunManifest.from_bytes((directory / MANIFEST_FILENAME).read_bytes())
    validate_blob_entries(manifest.blobs)
    store = BlobStore(directory)
    for entry in manifest.blobs:
        snapshot = BlobSnapshot(
            sha256=entry.sha256,
            byte_length=entry.byte_length,
            media_type=entry.media_type,
            path=store.path_for(entry.sha256),
        )
        store.verify(snapshot)
    return manifest


def load_realized_execution(
    manifest: RunManifest,
    effective_configuration_bytes: bytes,
) -> tuple[RealizedDeliveryExecution, ...]:
    """Load digest-bound execution recipes without source config or randomness."""
    if type(manifest) is not RunManifest:
        raise TypeError("manifest must be a RunManifest")
    effective = _parse_effective_configuration(effective_configuration_bytes)
    canonical = canonical_json_bytes(cast("dict[str, CanonicalJson]", effective))
    if sha256_digest(canonical) != manifest.configuration_digest:
        raise ValueError("effective configuration digest does not match the manifest")
    raw_entries = effective.get("realized_execution")
    if type(raw_entries) is not list:
        raise ValueError("effective configuration lacks realized execution recipes")
    recipes = tuple(
        RealizedDeliveryExecution.from_wire(item) for item in cast("list[object]", raw_entries)
    )
    planned = {
        delivery.delivery_id: (scenario.scenario_id, delivery)
        for scenario in manifest.scenarios
        for delivery in scenario.deliveries
    }
    if len(recipes) != len(planned) or len({item.delivery_id for item in recipes}) != len(recipes):
        raise ValueError("realized execution recipes do not match manifest deliveries")
    for recipe in recipes:
        expected = planned.get(recipe.delivery_id)
        if expected is None:
            raise ValueError("realized execution references an unknown delivery")
        scenario_id, delivery = expected
        if (
            recipe.scenario_id != scenario_id
            or recipe.event_id != delivery.event_id
            or recipe.logical_time_ns != delivery.logical_time_ns
            or any(attempt.request_blob != recipe.request_blob for attempt in delivery.attempt_plan)
        ):
            raise ValueError("realized execution conflicts with its manifest delivery")
    return recipes


def manifest_relative_path(path: Path, *, project_root: Path) -> str:
    """Serialize a contained artifact path in host-independent POSIX form."""
    try:
        return path.resolve(strict=False).relative_to(project_root.resolve(strict=False)).as_posix()
    except ValueError:
        raise ValueError("artifact path must be contained by project_root") from None


def next_attempt(
    delivery: DeliveryPlan,
    *,
    predecessor_result: str | None,
    completed_attempts: int,
) -> AttemptTemplate | None:
    """Evaluate deterministic conditional attempt templates."""
    if type(completed_attempts) is not int:
        raise TypeError("completed_attempts must be an integer")
    if predecessor_result is not None and type(predecessor_result) is not str:
        raise TypeError("predecessor_result must be a string or None")
    if completed_attempts < 0:
        raise ValueError("completed_attempts cannot be negative")
    if completed_attempts >= len(delivery.attempt_plan):
        return None
    candidate = delivery.attempt_plan[completed_attempts]
    if candidate.conditional_on is None:
        return candidate
    predicates = frozenset(candidate.conditional_on.split("|"))
    return candidate if predecessor_result in predicates else None


def _compile_scenario(
    scenario: config_models.ScenarioConfig,
    *,
    scenario_index: int,
    generator: ContextGenerator,
    loaded: Mapping[str, LoadedFixture],
    fixture_by_id: Mapping[str, config_models.FixtureConfig],
    store: BlobStore,
    snapshots: dict[str, BlobSnapshot],
    realized_execution: list[RealizedDeliveryExecution],
) -> ScenarioPlan:
    scenario_key = (str(scenario_index), scenario.id)
    scenario_id = planned_id(generator, PlannedIdKind.SCENARIO, scenario_key)
    event_ids = {
        event.id: planned_id(
            generator,
            PlannedIdKind.EVENT,
            (*scenario_key, str(index), event.id),
        )
        for index, event in enumerate(scenario.events)
    }
    events: list[EventPlan] = []
    for event in scenario.events:
        fixture = fixture_by_id[event.fixture]
        source = loaded[event.fixture]
        event_type = _json_pointer_text(source.body, fixture.event_type_pointer)
        events.append(
            EventPlan(
                event_id=event_ids[event.id],
                event_type=event_type,
                fixture_blob=source.blob_sha256,
                depends_on=(
                    tuple(event_ids[item] for item in event.depends_on)
                    if event.depends_on is not None
                    else ()
                ),
            )
        )

    deliveries: list[DeliveryPlan] = []
    logical_time_ns = 0
    ordinal = 0
    for step_index, step in enumerate(scenario.steps):
        if isinstance(step, config_models.WaitStep):
            logical_time_ns += step.wait.nanoseconds
            continue
        if not isinstance(step, config_models.DeliverStep):
            continue
        action = step.deliver
        for count_index in range(action.count):
            natural_key = (*scenario_key, str(step_index), str(count_index), action.event)
            delivery_id = planned_id(generator, PlannedIdKind.DELIVERY, natural_key)
            source_event = next(item for item in scenario.events if item.id == action.event)
            fixture = fixture_by_id[source_event.fixture]
            source = loaded[source_event.fixture]
            mutations = _realize_mutations(action.mutations, fixture)
            body, runtime_mutation_offset = _realize_planning_mutations(
                source.body,
                mutations,
                fixture,
            )
            request = store.snapshot(body, media_type=source.media_type)
            snapshots[request.sha256] = request
            attempts = _attempt_templates(
                action,
                generator=generator,
                scenario_id=scenario_id,
                delivery_id=delivery_id,
                logical_time_ns=logical_time_ns,
                request_blob=request.sha256,
            )
            deliveries.append(
                DeliveryPlan(
                    delivery_id=delivery_id,
                    event_id=event_ids[action.event],
                    logical_time_ns=logical_time_ns,
                    ordinal=ordinal,
                    concurrency_group=action.concurrency_group,
                    attempt_plan=attempts,
                )
            )
            realized_execution.append(
                RealizedDeliveryExecution(
                    scenario_id=scenario_id,
                    delivery_id=delivery_id,
                    event_id=event_ids[action.event],
                    logical_time_ns=logical_time_ns,
                    request_blob=request.sha256,
                    media_type=source.media_type,
                    signer_name=action.signer,
                    mutations=mutations,
                    runtime_mutation_offset=runtime_mutation_offset,
                )
            )
            ordinal += 1

    assertions = tuple(
        _compile_assertion(
            assertion,
            generator=generator,
            natural_key=(*scenario_key, str(index)),
        )
        for index, assertion in enumerate(scenario.assertions)
    )
    return ScenarioPlan(
        scenario_id=scenario_id,
        events=tuple(events),
        deliveries=tuple(deliveries),
        assertions=assertions,
    )


def _attempt_templates(
    action: config_models.DeliverAction,
    *,
    generator: ContextGenerator,
    scenario_id: str,
    delivery_id: str,
    logical_time_ns: int,
    request_blob: str,
) -> tuple[AttemptTemplate, ...]:
    retry = action.retry
    count = 1 if retry is None else retry.max_attempts
    delays = () if retry is None else retry.backoff
    jitter = 0 if retry is None else retry.jitter.nanoseconds
    predicates = None if retry is None else "|".join(item.value for item in retry.retry_on)
    result: list[AttemptTemplate] = []
    not_before = logical_time_ns
    for index in range(count):
        if index:
            not_before += delays[index - 1].nanoseconds
            if jitter:
                not_before += generator.signed_retry_jitter(
                    scenario_id=scenario_id,
                    planned_delivery_id=delivery_id,
                    attempt_ordinal=index + 1,
                    jitter_policy_version=JITTER_POLICY_VERSION,
                    magnitude_bound=jitter,
                )
        result.append(
            AttemptTemplate(
                ordinal=index + 1,
                not_before_logical_ns=not_before,
                request_blob=request_blob,
                headers_sha256=_EMPTY_HEADERS_DIGEST,
                conditional_on=None if index == 0 else predicates,
            )
        )
    return tuple(result)


def _realize_mutations(
    mutations: tuple[config_models.MutationConfig, ...] | None,
    fixture: config_models.FixtureConfig,
) -> tuple[RealizedMutation, ...]:
    realized = tuple(_lower_mutation(mutation, fixture) for mutation in (mutations or ()))
    ranks = tuple(PIPELINE_STAGE_RANK[item.stage] for item in realized)
    if ranks != tuple(sorted(ranks)):
        raise ValueError("configured mutations are not in fixed pipeline stage order")
    return realized


def _realize_planning_mutations(
    body: bytes,
    mutations: tuple[RealizedMutation, ...],
    fixture: config_models.FixtureConfig,
) -> tuple[bytes, int]:
    if not mutations:
        return body, 0
    runtime_offset = next(
        (
            index
            for index, mutation in enumerate(mutations)
            if PIPELINE_STAGE_RANK[mutation.stage] > _PLANNING_STAGE_MAX_RANK
        ),
        len(mutations),
    )
    planning_mutations = mutations[:runtime_offset]
    if not planning_mutations:
        return body, 0
    result = MutationPipeline(_ALL_MUTATION_REGISTRY).execute(
        body=body,
        headers=(),
        event_id="planning-event",
        logical_time_ns=0,
        media_type=fixture.media_type,
        signer=None,
        mutations=planning_mutations,
    )
    return result.body, runtime_offset


def _lower_mutation(
    mutation: config_models.MutationConfig,
    fixture: config_models.FixtureConfig,
) -> RealizedMutation:
    parameters = cast(
        "dict[str, object]",
        mutation.model_dump(mode="json", exclude={"type"}, exclude_none=True),
    )
    if isinstance(mutation, config_models.ChangeEventIdFieldMutation):
        parameters["pointer"] = fixture.event_id_pointer
    elif isinstance(mutation, config_models.ChangeEventTypeFieldMutation):
        parameters["pointer"] = fixture.event_type_pointer
    elif isinstance(mutation, config_models.StaleSignatureTimestampMutation):
        parameters = cast("dict[str, object]", {"age_ns": mutation.age.nanoseconds})
    stage = _MUTATION_STAGE_BY_ID.get(mutation.type)
    if stage is None:
        message = f"unregistered mutation operator: {mutation.type}"
        raise ValueError(message)
    return RealizedMutation(
        operator_id=mutation.type,
        operator_version=1,
        stage=stage,
        parameters=parameters,
        parameters_safe=parameters,
    )


def _realized_mutation_from_wire(value: object) -> RealizedMutation:
    if type(value) is not dict:
        raise ValueError("realized mutation must be an object")
    wire = cast("dict[str, object]", value)
    if set(wire) != {
        "operator_id",
        "operator_version",
        "stage",
        "parameters",
        "parameters_safe",
    }:
        raise ValueError("realized mutation has an invalid field set")
    parameters = wire["parameters"]
    parameters_safe = wire["parameters_safe"]
    if type(parameters) is not dict or type(parameters_safe) is not dict:
        raise ValueError("realized mutation parameters must be objects")
    try:
        stage = MutationStage(_wire_string(wire["stage"], "stage"))
    except ValueError:
        raise ValueError("realized mutation stage is unsupported") from None
    return RealizedMutation(
        operator_id=_wire_string(wire["operator_id"], "operator_id"),
        operator_version=_wire_integer(wire["operator_version"], "operator_version"),
        stage=stage,
        parameters=cast("dict[str, object]", parameters),
        parameters_safe=cast("dict[str, object]", parameters_safe),
    )


def _wire_string(value: object, field_name: str) -> str:
    if type(value) is not str or not value:
        message = f"realized execution {field_name} must be a nonempty string"
        raise ValueError(message)
    return value


def _wire_integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        message = f"realized execution {field_name} must be an integer"
        raise ValueError(message)
    return value


def _compile_assertion(
    assertion: config_models.AssertionConfig,
    *,
    generator: ContextGenerator,
    natural_key: tuple[str, ...],
) -> AssertionPlan:
    dumped = cast(
        "dict[str, object]",
        assertion.model_dump(mode="json", exclude_none=True),
    )
    assertion_type = cast("str", dumped.pop("type"))
    observer = cast("str | None", dumped.pop("observer", None))
    parameters = {key: config_models.CanonicalJsonValue(value) for key, value in dumped.items()}
    return AssertionPlan(
        assertion_id=planned_id(generator, PlannedIdKind.ASSERTION, natural_key),
        type=assertion_type,
        observer=observer,
        parameters=parameters or None,
    )


def _effective_configuration(
    config: config_models.ProjectConfig,
    fingerprints: Mapping[str, str],
    *,
    selected_seed: str,
    realized_execution: tuple[RealizedDeliveryExecution, ...],
) -> dict[str, object]:
    wire = cast("dict[str, object]", config.model_dump(mode="json", exclude_none=True))
    project = cast("dict[str, object]", wire["project"])
    project.pop("seed", None)
    project["seed_fingerprint"] = sha256_digest(selected_seed.encode())
    fixture_values = cast("list[object]", wire["fixtures"])
    for fixture in fixture_values:
        fixture_wire = cast("dict[str, object]", fixture)
        path = cast("str", fixture_wire.pop("path"))
        fixture_wire["path_fingerprint"] = sha256_digest(path.encode())
        schema_path = fixture_wire.pop("schema_path", None)
        if schema_path is not None:
            fixture_wire["schema_path_fingerprint"] = sha256_digest(
                cast("str", schema_path).encode()
            )
    signer_values = cast("dict[str, object]", wire["signers"])
    for name, signer_config in config.signers.items():
        signer_wire = cast("dict[str, object]", signer_values[name])
        signer_wire["secret"] = _safe_secret_snapshot(
            signer_config.secret,
            fingerprints,
        )
    observer_values = cast("dict[str, object]", wire["observers"])
    for name, observer_config in config.observers.items():
        if not isinstance(observer_config, config_models.HttpObserverConfig):
            continue
        observer_wire = cast("dict[str, object]", observer_values[name])
        observer_wire["token"] = _safe_secret_snapshot(
            observer_config.token,
            fingerprints,
        )
    wire["realized_execution"] = [item.to_wire() for item in realized_execution]
    return wire


def _safe_secret_snapshot(
    reference: config_models.SecretRef,
    fingerprints: Mapping[str, str],
) -> dict[str, str]:
    reference_wire = cast(
        "dict[str, object]",
        reference.model_dump(mode="json"),
    )
    kind, raw_value = next(iter(reference_wire.items()))
    fingerprint = fingerprints.get(f"{kind}:{raw_value}")
    if fingerprint is None:
        raise ValueError("every configured secret reference requires a safe fingerprint")
    return {
        "reference_kind": kind,
        "fingerprint": validate_sha256_digest(fingerprint),
    }


def generate_preview(
    manifest: RunManifest,
    effective_configuration_bytes: bytes,
) -> bytes:
    """Regenerate the secret-free preview solely from bundle-resident artifacts."""
    effective = _parse_effective_configuration(effective_configuration_bytes)
    try:
        canonical_effective = canonical_json_bytes(cast("dict[str, CanonicalJson]", effective))
    except RecursionError:
        raise ValueError("effective configuration exceeds the nesting limit") from None
    if sha256_digest(canonical_effective) != manifest.configuration_digest:
        raise ValueError("effective configuration digest does not match the manifest")
    configuration = effective
    signers = cast("dict[str, object]", configuration.get("signers", {}))
    observers = cast("dict[str, object]", configuration.get("observers", {}))
    configured_scenarios = cast("list[object]", configuration.get("scenarios", []))
    operators: set[str] = set()
    for scenario_value in configured_scenarios:
        scenario = cast("dict[str, object]", scenario_value)
        for step_value in cast("list[object]", scenario.get("steps", [])):
            step = cast("dict[str, object]", step_value)
            delivery = step.get("deliver")
            if not isinstance(delivery, dict):
                continue
            delivery_object = cast("dict[str, object]", delivery)
            for mutation in cast("list[object]", delivery_object.get("mutations", [])):
                mutation_object = cast("dict[str, object]", mutation)
                operator = mutation_object.get("type")
                if isinstance(operator, str):
                    operators.add(operator)
    preview = {
        "manifest_id": manifest.manifest_id,
        "scenarios": len(manifest.scenarios),
        "events": sum(len(item.events) for item in manifest.scenarios),
        "deliveries": sum(len(item.deliveries) for item in manifest.scenarios),
        "attempt_templates": sum(
            len(delivery.attempt_plan)
            for scenario in manifest.scenarios
            for delivery in scenario.deliveries
        ),
        "target_policy": manifest.target_policy.profile,
        "signers": sorted(signers),
        "observers": sorted(observers),
        "fault_operators": sorted(operators),
        "logical_duration_ns": max(
            (
                delivery.logical_time_ns
                for scenario in manifest.scenarios
                for delivery in scenario.deliveries
            ),
            default=0,
        ),
    }
    return canonical_json_bytes(cast("dict[str, CanonicalJson]", preview)) + b"\n"


def _parse_effective_configuration(value: bytes) -> dict[str, object]:
    if type(value) is not bytes:
        raise TypeError("effective configuration input must be bytes")
    if len(value) > MAX_CONFIG_BYTES:
        raise ValueError("effective configuration exceeds the byte limit")

    try:
        decoded = value.decode("utf-8")
        parsed = json.loads(
            decoded,
            parse_float=_reject_effective_float,
            parse_constant=_reject_effective_constant,
            object_pairs_hook=_unique_effective_object,
        )
    except UnicodeDecodeError:
        raise ValueError("effective configuration must be valid UTF-8 JSON") from None
    except json.JSONDecodeError:
        raise ValueError("effective configuration must be valid JSON") from None
    except RecursionError:
        raise ValueError("effective configuration exceeds the nesting limit") from None
    if not isinstance(parsed, dict):
        raise ValueError("effective configuration must be a JSON object")
    return cast("dict[str, object]", parsed)


def _reject_effective_float(_value: str) -> object:
    raise ValueError("effective configuration does not permit floating-point values")


def _reject_effective_constant(_value: str) -> object:
    raise ValueError("effective configuration contains a non-JSON number")


def _unique_effective_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("effective configuration contains duplicate object keys")
        result[key] = item
    return result


def _json_pointer_text(body: bytes, pointer: str) -> str:
    value = _pointer_get(json.loads(body), pointer)
    if not isinstance(value, str):
        raise ValueError("fixture event type pointer must resolve to a string")
    return value


def _pointer_parts(pointer: str) -> tuple[str, ...]:
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise ValueError("invalid JSON Pointer")
    return tuple(item.replace("~1", "/").replace("~0", "~") for item in pointer[1:].split("/"))


def _pointer_get(value: object, pointer: str) -> object:
    current = value
    for part in _pointer_parts(pointer):
        current = (
            cast("list[object]", current)[int(part)]
            if isinstance(current, list)
            else cast("dict[str, object]", current)[part]
        )
    return current


def _atomic_write(path: Path, value: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


__all__ = [
    "CompiledRunBundle",
    "RealizedDeliveryExecution",
    "compile_manifest",
    "compile_run_bundle",
    "generate_preview",
    "load_realized_execution",
    "load_run_manifest",
    "manifest_relative_path",
    "materialize_run_bundle",
    "next_attempt",
]
