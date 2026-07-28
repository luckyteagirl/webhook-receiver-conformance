"""Deterministic export of scenario-reduced immutable replay bundles."""
# ruff: noqa: EM101, INP001, PLR0913, TRY003

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path
from typing import Final, cast

from webhook_receiver_conformance.config.schema import MAX_CONFIG_BYTES
from webhook_receiver_conformance.domain.hashing import (
    CanonicalJson,
    canonical_json_bytes,
    compute_manifest_id,
    sha256_digest,
)
from webhook_receiver_conformance.domain.identifiers import (
    PlannedIdKind,
    validate_planned_id,
)
from webhook_receiver_conformance.fixtures.blobs import BlobSnapshot, BlobStore
from webhook_receiver_conformance.fixtures.loader import HARD_MAX_FIXTURE_BYTES
from webhook_receiver_conformance.manifest.compiler import (
    EFFECTIVE_CONFIG_FILENAME,
    CompiledRunBundle,
    RealizedDeliveryExecution,
    generate_preview,
    load_realized_execution,
    materialize_run_bundle,
)
from webhook_receiver_conformance.manifest.loader import (
    LoadedRunBundle,
    load_replay_bundle,
)
from webhook_receiver_conformance.manifest.models import (
    BlobEntry,
    RunManifest,
    ScenarioPlan,
    validate_blob_entries,
)

_WINDOWS_REPARSE_ATTRIBUTE: Final = 0x400


def export_reduced_replay_bundle(
    source: LoadedRunBundle,
    *,
    scenario_ids: tuple[str, ...],
    destination: Path,
) -> LoadedRunBundle:
    """Export selected scenarios as a complete, independently verified replay bundle.

    Selection order never affects the result: selected scenarios retain their order
    from the source manifest. The destination must not already exist.
    """
    if type(source) is not LoadedRunBundle:
        raise TypeError("source must be a verified LoadedRunBundle")
    selected_ids = _validate_selection(scenario_ids)
    output_directory = _validate_destination(source.directory, destination)
    verified_source = load_replay_bundle(source.directory)
    _require_unchanged_source(source, verified_source)
    retained_indexes, retained_scenarios = _select_scenarios(
        verified_source.manifest,
        selected_ids,
    )
    effective_bytes = _read_effective_configuration(verified_source.directory)
    reduced_effective_bytes, retained_recipes = _reduce_effective_configuration(
        verified_source.manifest,
        effective_bytes,
        retained_indexes=retained_indexes,
        retained_scenarios=retained_scenarios,
    )
    retained_blob_entries = _select_blob_entries(
        verified_source.manifest,
        retained_scenarios,
    )
    manifest = _reduce_manifest(
        verified_source.manifest,
        scenarios=retained_scenarios,
        blobs=retained_blob_entries,
        effective_configuration_bytes=reduced_effective_bytes,
    )
    preview_bytes = generate_preview(manifest, reduced_effective_bytes)
    return _materialize_reduced_bundle(
        verified_source,
        destination=output_directory,
        manifest=manifest,
        effective_configuration_bytes=reduced_effective_bytes,
        preview_bytes=preview_bytes,
        blobs=retained_blob_entries,
        recipes=retained_recipes,
    )


def materialize_verified_replay_bundle(
    source: LoadedRunBundle,
    *,
    destination: Path,
) -> LoadedRunBundle:
    """Copy verified replay inputs into an existing, otherwise fresh run directory."""
    if type(source) is not LoadedRunBundle:
        raise TypeError("source must be a verified LoadedRunBundle")
    output_directory = _validate_existing_destination(source.directory, destination)
    verified_source = load_replay_bundle(source.directory)
    _require_unchanged_source(source, verified_source)
    effective_bytes = _read_effective_configuration(verified_source.directory)
    recipes = load_realized_execution(verified_source.manifest, effective_bytes)
    preview_bytes = generate_preview(verified_source.manifest, effective_bytes)
    output_store = BlobStore(output_directory)
    output_blobs: list[BlobSnapshot] = []
    for source_blob in verified_source.blobs:
        body = _read_verified_blob(source_blob)
        output_blob = output_store.snapshot(body, media_type=source_blob.media_type)
        if (
            output_blob.sha256 != source_blob.sha256
            or output_blob.byte_length != source_blob.byte_length
        ):
            raise ValueError("source blob changed during replay materialization")
        output_blobs.append(output_blob)
    materialize_run_bundle(
        CompiledRunBundle(
            manifest=verified_source.manifest,
            manifest_bytes=verified_source.manifest_bytes,
            effective_configuration_bytes=effective_bytes,
            preview_bytes=preview_bytes,
            blobs=tuple(output_blobs),
            realized_execution=recipes,
        ),
        output_directory,
    )
    loaded = load_replay_bundle(output_directory)
    materialized_recipes = load_realized_execution(
        loaded.manifest,
        _read_effective_configuration(output_directory),
    )
    if loaded.manifest_bytes != verified_source.manifest_bytes or materialized_recipes != recipes:
        raise ValueError("materialized replay bundle differs from its verified source")
    return loaded


def _materialize_reduced_bundle(
    source: LoadedRunBundle,
    *,
    destination: Path,
    manifest: RunManifest,
    effective_configuration_bytes: bytes,
    preview_bytes: bytes,
    blobs: tuple[BlobEntry, ...],
    recipes: tuple[RealizedDeliveryExecution, ...],
) -> LoadedRunBundle:
    source_blobs = {item.sha256: item for item in source.blobs}
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    completed = False
    try:
        output_store = BlobStore(destination)
        output_blobs: list[BlobSnapshot] = []
        for entry in blobs:
            source_blob = source_blobs.get(entry.sha256)
            if source_blob is None:
                raise ValueError("selected scenarios reference a missing verified blob")
            body = _read_verified_blob(source_blob)
            output_blob = output_store.snapshot(body, media_type=entry.media_type)
            if output_blob.sha256 != entry.sha256 or output_blob.byte_length != entry.byte_length:
                raise ValueError("source blob changed during reduced bundle export")
            output_blobs.append(output_blob)

        reduced = CompiledRunBundle(
            manifest=manifest,
            manifest_bytes=manifest.serialized_bytes(),
            effective_configuration_bytes=effective_configuration_bytes,
            preview_bytes=preview_bytes,
            blobs=tuple(output_blobs),
            realized_execution=recipes,
        )
        materialize_run_bundle(reduced, destination)
        loaded = load_replay_bundle(destination)
        replay_recipes = load_realized_execution(
            loaded.manifest,
            _read_effective_configuration(destination),
        )
        if replay_recipes != recipes:
            raise ValueError("reduced bundle replay recipes failed verification")
        completed = True
        return loaded
    finally:
        if not completed:
            shutil.rmtree(destination, ignore_errors=True)


def _require_unchanged_source(
    expected: LoadedRunBundle,
    reloaded: LoadedRunBundle,
) -> None:
    if (
        reloaded.manifest.manifest_id != expected.manifest.manifest_id
        or reloaded.manifest_bytes != expected.manifest_bytes
    ):
        raise ValueError("source bundle changed after it was loaded")


def _select_scenarios(
    manifest: RunManifest,
    selected_ids: frozenset[str],
) -> tuple[tuple[int, ...], tuple[ScenarioPlan, ...]]:
    source_ids = tuple(item.scenario_id for item in manifest.scenarios)
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("source manifest scenario IDs must be unique")
    if selected_ids.difference(source_ids):
        raise ValueError("selected scenario is not present in the source manifest")
    indexes = tuple(
        index for index, scenario_id in enumerate(source_ids) if scenario_id in selected_ids
    )
    return indexes, tuple(manifest.scenarios[index] for index in indexes)


def _reduce_effective_configuration(
    manifest: RunManifest,
    effective_bytes: bytes,
    *,
    retained_indexes: tuple[int, ...],
    retained_scenarios: tuple[ScenarioPlan, ...],
) -> tuple[bytes, tuple[RealizedDeliveryExecution, ...]]:
    recipes = load_realized_execution(manifest, effective_bytes)
    effective = _parse_effective_configuration(effective_bytes)
    configured_scenarios = effective.get("scenarios")
    if type(configured_scenarios) is not list:
        raise ValueError("effective configuration scenario inventory differs from the manifest")
    scenario_values = cast("list[object]", configured_scenarios)
    if len(scenario_values) != len(manifest.scenarios):
        raise ValueError("effective configuration scenario inventory differs from the manifest")
    if any(type(item) is not dict for item in scenario_values):
        raise ValueError("effective configuration scenarios must be objects")
    retained_ids = {item.scenario_id for item in retained_scenarios}
    retained_recipes = tuple(recipe for recipe in recipes if recipe.scenario_id in retained_ids)
    effective["scenarios"] = [scenario_values[index] for index in retained_indexes]
    effective["realized_execution"] = [item.to_wire() for item in retained_recipes]
    canonical = canonical_json_bytes(cast("dict[str, CanonicalJson]", effective))
    return canonical + b"\n", retained_recipes


def _select_blob_entries(
    manifest: RunManifest,
    scenarios: tuple[ScenarioPlan, ...],
) -> tuple[BlobEntry, ...]:
    referenced = _referenced_blob_digests(scenarios)
    retained = tuple(entry for entry in manifest.blobs if entry.sha256 in referenced)
    if {entry.sha256 for entry in retained} != referenced:
        raise ValueError("selected scenarios reference a missing source blob")
    validate_blob_entries(retained)
    return retained


def _reduce_manifest(
    source: RunManifest,
    *,
    scenarios: tuple[ScenarioPlan, ...],
    blobs: tuple[BlobEntry, ...],
    effective_configuration_bytes: bytes,
) -> RunManifest:
    canonical_effective = effective_configuration_bytes.removesuffix(b"\n")
    manifest_wire = source.to_wire()
    manifest_wire["configuration_digest"] = sha256_digest(canonical_effective)
    manifest_wire["blobs"] = [entry.model_dump(mode="json", exclude_none=True) for entry in blobs]
    manifest_wire["scenarios"] = [
        scenario.model_dump(mode="json", exclude_none=True) for scenario in scenarios
    ]
    manifest_wire["manifest_id"] = compute_manifest_id(manifest_wire)
    return RunManifest.from_wire(manifest_wire, verify=True)


def _validate_selection(scenario_ids: tuple[str, ...]) -> frozenset[str]:
    if type(scenario_ids) is not tuple:
        raise TypeError("scenario_ids must be a tuple")
    if not scenario_ids:
        raise ValueError("at least one scenario must be selected")
    for scenario_id in scenario_ids:
        if type(scenario_id) is not str:
            raise TypeError("scenario_ids must contain strings")
        validate_planned_id(scenario_id, expected_kind=PlannedIdKind.SCENARIO)
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("scenario_ids must be unique")
    return frozenset(scenario_ids)


def _validate_destination(source: Path, destination: Path) -> Path:
    if not isinstance(destination, Path):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("destination must be a pathlib.Path")
    if os.name == "nt" and destination.drive.startswith("\\\\"):
        raise ValueError("reduced replay bundles must use a local destination")
    output = destination.absolute()
    source_root = source.resolve(strict=True)
    output_root = output.resolve(strict=False)
    if output_root == source_root or output_root.is_relative_to(source_root):
        raise ValueError("destination must be separate from the immutable source bundle")
    if source_root.is_relative_to(output_root):
        raise ValueError("destination cannot contain the immutable source bundle")
    if output.exists() or output.is_symlink():
        raise FileExistsError("reduced replay bundle destination already exists")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = output.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or _is_windows_reparse(parent)
    ):
        raise ValueError("reduced replay bundle parent must be a regular local directory")
    return output


def _validate_existing_destination(source: Path, destination: Path) -> Path:
    if not isinstance(destination, Path):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("destination must be a pathlib.Path")
    output = destination.absolute()
    source_root = source.resolve(strict=True)
    try:
        output_root = output.resolve(strict=True)
        metadata = output.lstat()
    except OSError:
        raise ValueError("replay destination must be an existing local directory") from None
    if (
        output_root == source_root
        or output_root.is_relative_to(source_root)
        or source_root.is_relative_to(output_root)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_windows_reparse(metadata)
    ):
        raise ValueError("replay destination must be separate from its immutable source")
    owned_paths = (
        output / "run-manifest.json",
        output / EFFECTIVE_CONFIG_FILENAME,
        output / "plan-preview.json",
        output / "blobs",
    )
    if any(path.exists() or path.is_symlink() for path in owned_paths):
        raise FileExistsError("replay destination already contains bundle artifacts")
    return output


def _read_effective_configuration(directory: Path) -> bytes:
    path = directory / EFFECTIVE_CONFIG_FILENAME
    try:
        metadata = path.lstat()
    except OSError:
        raise ValueError("replay bundle lacks an effective configuration") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_windows_reparse(metadata)
    ):
        raise ValueError("replay effective configuration must be a regular file")
    try:
        with path.open("rb") as stream:
            value = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ValueError("replay effective configuration could not be read") from None
    if len(value) > MAX_CONFIG_BYTES:
        raise ValueError("replay effective configuration exceeds its resource bound")
    return value


def _parse_effective_configuration(value: bytes) -> dict[str, object]:
    try:
        parsed = json.loads(
            value.decode("utf-8"),
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("effective configuration must be bounded strict JSON") from None
    if type(parsed) is not dict:
        raise ValueError("effective configuration must be a JSON object")
    return cast("dict[str, object]", parsed)


def _reject_float(_value: str) -> object:
    raise ValueError("effective configuration does not permit floating-point values")


def _reject_constant(_value: str) -> object:
    raise ValueError("effective configuration contains a non-JSON number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("effective configuration contains duplicate object keys")
        result[key] = value
    return result


def _referenced_blob_digests(scenarios: tuple[ScenarioPlan, ...]) -> set[str]:
    return {event.fixture_blob for scenario in scenarios for event in scenario.events} | {
        attempt.request_blob
        for scenario in scenarios
        for delivery in scenario.deliveries
        for attempt in delivery.attempt_plan
    }


def _read_verified_blob(snapshot: BlobSnapshot) -> bytes:
    if snapshot.byte_length > HARD_MAX_FIXTURE_BYTES:
        raise ValueError("verified source blob exceeds the hard fixture byte limit")
    try:
        with snapshot.path.open("rb") as stream:
            body = stream.read(snapshot.byte_length + 1)
    except OSError:
        raise ValueError("verified source blob could not be read") from None
    if len(body) != snapshot.byte_length or sha256_digest(body) != snapshot.sha256:
        raise ValueError("source blob changed during reduced bundle export")
    return body


def _is_windows_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_ATTRIBUTE)


__all__ = [
    "export_reduced_replay_bundle",
    "materialize_verified_replay_bundle",
]
