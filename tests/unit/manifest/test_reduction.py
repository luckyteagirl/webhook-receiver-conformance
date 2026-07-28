"""Focused contracts for deterministic scenario-reduced replay bundle export."""
# ruff: noqa: INP001, PLR2004, TC003

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from webhook_receiver_conformance.config.models import ProjectConfig
from webhook_receiver_conformance.domain.hashing import sha256_digest
from webhook_receiver_conformance.manifest.compiler import (
    EFFECTIVE_CONFIG_FILENAME,
    PREVIEW_FILENAME,
    compile_run_bundle,
    load_realized_execution,
)
from webhook_receiver_conformance.manifest.loader import load_replay_bundle
from webhook_receiver_conformance.manifest.reduction import (
    export_reduced_replay_bundle,
    materialize_verified_replay_bundle,
)

_CREATED_AT = "2026-07-27T20:00:00Z"
_FINGERPRINT = "sha256:" + ("a5" * 32)


def _config(project: Path, *, port: int = 8000) -> ProjectConfig:
    fixtures = project / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "first.json").write_bytes(b'{"id":"evt_first","type":"test.first","value":1}\n')
    (fixtures / "second.json").write_bytes(b'{"id":"evt_second","type":"test.second","value":2}\n')
    return ProjectConfig.model_validate(
        {
            "schema_version": 1,
            "project": {
                "name": "reduced-replay",
                "artifact_directory": "runs",
                "seed": "reduced-replay-seed",
            },
            "receiver": {
                "url": f"http://127.0.0.1:{port}/webhook",
                "target_profile": "loopback",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_ports": [port],
                "timeouts": {
                    "connect": "2s",
                    "write": "2s",
                    "read": "2s",
                    "pool": "2s",
                    "total": "5s",
                },
            },
            "fixtures": [
                {
                    "id": "first",
                    "path": "fixtures/first.json",
                    "media_type": "application/json",
                },
                {
                    "id": "second",
                    "path": "fixtures/second.json",
                    "media_type": "application/json",
                },
            ],
            "signers": {
                "unused": {
                    "profile": "generic-hmac-sha256",
                    "secret": {"generated": "hmac-256"},
                }
            },
            "observers": {},
            "clock": {"mode": "real"},
            "limits": {
                "max_events": 8,
                "max_attempts": 8,
                "max_concurrency": 2,
                "max_request_bytes": 65_536,
                "max_response_capture_bytes": 8_192,
            },
            "scenarios": [
                _scenario("first-case", "first"),
                _scenario("second-case", "second"),
            ],
            "reports": {
                "formats": ["json"],
                "redaction": {
                    "headers": [],
                    "json_pointers": [],
                    "retain_raw_payloads": False,
                },
            },
        }
    )


def _scenario(name: str, fixture: str) -> dict[str, object]:
    return {
        "id": name,
        "events": [{"id": "event", "fixture": fixture}],
        "steps": [{"deliver": {"event": "event"}}],
        "assertions": [
            {
                "id": "status",
                "type": "http-status",
                "attempt": {"event": "event", "mode": "all-terminal"},
                "expected": {"codes": [204]},
            }
        ],
    }


def _compiled_source(tmp_path: Path) -> tuple[ProjectConfig, Path]:
    project = tmp_path / "project"
    config = _config(project)
    source_directory = tmp_path / "source"
    compile_run_bundle(
        config,
        project_root=project,
        bundle_directory=source_directory,
        created_at=_CREATED_AT,
        python_version="3.13.5",
        dependencies_digest="sha256:" + ("00" * 32),
        secret_fingerprints={"generated:hmac-256": _FINGERPRINT},
    )
    return config, source_directory


def _json_object(path: Path) -> dict[str, object]:
    parsed = json.loads(path.read_bytes())
    assert isinstance(parsed, dict)
    return cast("dict[str, object]", parsed)


def test_vt_mut_022_export_is_deterministic_complete_and_scenario_reduced(
    tmp_path: Path,
) -> None:
    _config_value, source_directory = _compiled_source(tmp_path)
    source = load_replay_bundle(source_directory)
    selected = source.manifest.scenarios[1]

    first = export_reduced_replay_bundle(
        source,
        scenario_ids=(selected.scenario_id,),
        destination=tmp_path / "reduced-first",
    )
    second = export_reduced_replay_bundle(
        source,
        scenario_ids=(selected.scenario_id,),
        destination=tmp_path / "reduced-second",
    )

    assert first.manifest_bytes == second.manifest_bytes
    assert (first.directory / EFFECTIVE_CONFIG_FILENAME).read_bytes() == (
        second.directory / EFFECTIVE_CONFIG_FILENAME
    ).read_bytes()
    assert (first.directory / PREVIEW_FILENAME).read_bytes() == (
        second.directory / PREVIEW_FILENAME
    ).read_bytes()
    assert first.manifest.manifest_id != source.manifest.manifest_id
    assert first.manifest.configuration_digest != source.manifest.configuration_digest
    assert first.manifest.scenarios == (selected,)
    assert len(first.manifest.blobs) == 1
    assert len(source.manifest.blobs) == 2
    assert (
        first.blobs[0].path.read_bytes()
        == (tmp_path / "project" / "fixtures" / "second.json").read_bytes()
    )
    first.manifest.verify_id()

    effective_bytes = (first.directory / EFFECTIVE_CONFIG_FILENAME).read_bytes()
    recipes = load_realized_execution(first.manifest, effective_bytes)
    assert {item.scenario_id for item in recipes} == {selected.scenario_id}
    assert first.manifest.configuration_digest == sha256_digest(effective_bytes.removesuffix(b"\n"))


def test_reduction_preserves_target_config_and_secret_fingerprint_safeguards(
    tmp_path: Path,
) -> None:
    _config_value, source_directory = _compiled_source(tmp_path)
    source = load_replay_bundle(source_directory)
    reduced = export_reduced_replay_bundle(
        source,
        scenario_ids=(source.manifest.scenarios[0].scenario_id,),
        destination=tmp_path / "reduced",
    )
    source_effective = _json_object(source_directory / EFFECTIVE_CONFIG_FILENAME)
    reduced_effective = _json_object(reduced.directory / EFFECTIVE_CONFIG_FILENAME)

    assert reduced.manifest.target_policy == source.manifest.target_policy
    assert reduced.manifest.generator == source.manifest.generator
    for key in source_effective.keys() - {"scenarios", "realized_execution"}:
        assert reduced_effective[key] == source_effective[key]
    signers = cast("dict[str, object]", reduced_effective["signers"])
    unused = cast("dict[str, object]", signers["unused"])
    assert unused["secret"] == {
        "reference_kind": "generated",
        "fingerprint": _FINGERPRINT,
    }

    tampered = cast("dict[str, object]", json.loads(json.dumps(reduced_effective)))
    receiver = cast("dict[str, object]", tampered["receiver"])
    receiver["url"] = "http://127.0.0.1:9999/redirected"
    with pytest.raises(ValueError, match="digest"):
        load_realized_execution(
            reduced.manifest,
            json.dumps(tampered, sort_keys=True).encode(),
        )


def test_materialize_verified_replay_bundle_makes_an_existing_run_self_contained(
    tmp_path: Path,
) -> None:
    _config_value, source_directory = _compiled_source(tmp_path)
    source = load_replay_bundle(source_directory)
    destination = tmp_path / "fresh-run"
    destination.mkdir()
    journal = destination / "journal.sqlite3"
    journal.write_bytes(b"owned-by-the-run")

    materialized = materialize_verified_replay_bundle(
        source,
        destination=destination,
    )

    assert materialized.manifest_bytes == source.manifest_bytes
    assert (destination / EFFECTIVE_CONFIG_FILENAME).read_bytes() == (
        source_directory / EFFECTIVE_CONFIG_FILENAME
    ).read_bytes()
    assert journal.read_bytes() == b"owned-by-the-run"
    assert tuple(item.sha256 for item in materialized.blobs) == tuple(
        item.sha256 for item in source.blobs
    )
    assert all(item.path.is_relative_to(destination) for item in materialized.blobs)
    with pytest.raises(FileExistsError, match="already contains"):
        materialize_verified_replay_bundle(
            source,
            destination=destination,
        )


def test_reduction_rejects_ambiguous_selection_and_existing_destination(
    tmp_path: Path,
) -> None:
    _config_value, source_directory = _compiled_source(tmp_path)
    source = load_replay_bundle(source_directory)
    selected = source.manifest.scenarios[0].scenario_id

    with pytest.raises(ValueError, match="at least one"):
        export_reduced_replay_bundle(
            source,
            scenario_ids=(),
            destination=tmp_path / "empty",
        )
    with pytest.raises(ValueError, match="unique"):
        export_reduced_replay_bundle(
            source,
            scenario_ids=(selected, selected),
            destination=tmp_path / "duplicate",
        )
    with pytest.raises(ValueError, match="not present"):
        export_reduced_replay_bundle(
            source,
            scenario_ids=("scenario_" + ("0" * 26),),
            destination=tmp_path / "unknown",
        )

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    marker = occupied / "user-owned.txt"
    marker.write_text("preserve", encoding="utf-8")
    with pytest.raises(FileExistsError, match="already exists"):
        export_reduced_replay_bundle(
            source,
            scenario_ids=(selected,),
            destination=occupied,
        )
    assert marker.read_text(encoding="utf-8") == "preserve"
