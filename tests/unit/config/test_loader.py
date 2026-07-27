"""Contract tests for the bounded restricted-YAML project loader."""
# ruff: noqa: C901, INP001, PLR0911, PLR0912, PLR0913, PLR0915, PLR0917, S603, S607, SLF001
# pyright: reportPrivateUsage=false

from __future__ import annotations

import ctypes
import os
import socket
import subprocess
from dataclasses import FrozenInstanceError, dataclass
from pathlib import Path
from typing import NoReturn

import pytest
from pydantic import ValidationError

from webhook_receiver_conformance.config import loader as config_loader
from webhook_receiver_conformance.config.loader import (
    CliOverrides,
    ConfigLoadResult,
    load_project_config,
)
from webhook_receiver_conformance.config.schema import (
    MAX_CONFIG_BYTES,
    MAX_CONFIG_DEPTH,
    MAX_CONFIG_NODES,
)
from webhook_receiver_conformance.errors import Diagnostic, ErrorCategory, ResultCategory
from webhook_receiver_conformance.types import DiagnosticCode

REPOSITORY_ROOT = Path(__file__).parents[3]
MINIMAL_EXAMPLE = REPOSITORY_ROOT / "examples" / "project-config.minimal.yaml"
COMPLETE_EXAMPLE = REPOSITORY_ROOT / "examples" / "project-config.complete.yaml"
TAG_LOCATION = (3, 9)
MERGE_LOCATION = (3, 3)
SCHEMA_VERSION_LOCATION = (1, 17)
DEFAULT_MAX_CONCURRENCY = 10
YAML_MAX_CONCURRENCY = 7
MAX_RENDERED_DIAGNOSTIC = 2048


@dataclass(frozen=True, slots=True)
class _WindowsRelativeRace:
    source_path: Path
    overrides: CliOverrides | None
    trigger_parent: Path
    trigger_name: str
    trigger_directory: bool
    trigger_read_content: bool
    swap_path: Path
    moved_path: Path
    external: Path
    expected_code: str
    trigger_occurrence: int = 1


def test_authoritative_minimal_loads_as_immutable_schema_version_one() -> None:
    result = load_project_config(MINIMAL_EXAMPLE)

    assert result.ok
    assert result.diagnostics == ()
    assert result.config is not None
    assert result.config.schema_version == 1
    assert result.project_root == MINIMAL_EXAMPLE.parent.resolve()
    assert result.source_path == MINIMAL_EXAMPLE.resolve()

    with pytest.raises(ValidationError):
        result.config.schema_version = 2
    with pytest.raises(FrozenInstanceError):
        result.project_root = REPOSITORY_ROOT  # pyright: ignore[reportAttributeAccessIssue]


def test_authoritative_complete_loads_with_required_secret_metadata(
    tmp_path: Path,
) -> None:
    path = _write_config(
        tmp_path,
        COMPLETE_EXAMPLE.read_text(encoding="utf-8"),
    )
    secret_directory = tmp_path / ".secrets"
    secret_directory.mkdir()
    (secret_directory / "standard-webhooks.key").write_bytes(b"metadata-only-test")

    result = load_project_config(path)

    assert result.ok
    assert result.config is not None
    assert result.config.schema_version == 1
    assert result.config.project.secret_roots == (".secrets",)


def test_precedence_materializes_defaults_then_yaml_then_documented_cli(
    tmp_path: Path,
) -> None:
    default_path = _write_config(
        tmp_path,
        MINIMAL_EXAMPLE.read_text(encoding="utf-8"),
    )
    default_result = load_project_config(default_path)
    assert default_result.config is not None
    assert default_result.config.limits.max_concurrency == DEFAULT_MAX_CONCURRENCY
    assert default_result.config.project.artifact_directory == ".webhook-conformance"

    yaml_text = (
        default_path.read_text(encoding="utf-8")
        .replace(
            "max_attempts: 500",
            "max_attempts: 500\n  max_concurrency: 7",
        )
        .replace(
            "artifact_directory: .webhook-conformance",
            "artifact_directory: reports/from-yaml",
        )
    )
    reports_directory = tmp_path / "reports"
    reports_directory.mkdir()
    yaml_path = _write_config(tmp_path, yaml_text)
    yaml_result = load_project_config(yaml_path)
    assert yaml_result.config is not None
    assert yaml_result.config.limits.max_concurrency == YAML_MAX_CONCURRENCY
    assert yaml_result.config.project.artifact_directory == "reports/from-yaml"

    (reports_directory / "from-cli").mkdir()
    cli_result = load_project_config(
        yaml_path,
        overrides=CliOverrides(output="reports/./from-cli//nested"),
    )
    assert cli_result.config is not None
    assert cli_result.config.limits.max_concurrency == YAML_MAX_CONCURRENCY
    assert cli_result.config.project.artifact_directory == "reports/from-cli/nested"


def test_environment_secret_reference_is_not_interpolated_or_injected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "ENVIRONMENT_SECRET_CANARY"
    monkeypatch.setenv("WEBHOOK_TEST_SECRET", canary)
    path = _write_config(
        tmp_path,
        MINIMAL_EXAMPLE.read_text(encoding="utf-8").replace(
            "  artifact_directory: .webhook-conformance",
            "  artifact_directory: .webhook-conformance\n  seed: ${UNEXPANDED_SEED}",
        ),
    )

    result = load_project_config(path)

    assert result.config is not None
    assert result.config.project.seed == "${UNEXPANDED_SEED}"
    signer = result.config.signers["test_hmac"]
    assert signer.secret.to_wire() == {"env": "WEBHOOK_TEST_SECRET"}
    assert canary not in result.config.model_dump_json()


def test_output_is_applied_before_strict_project_model_validation(tmp_path: Path) -> None:
    path = _minimal_with(
        tmp_path,
        "artifact_directory: .webhook-conformance",
        "artifact_directory:",
    )
    (tmp_path / "reports").mkdir()

    result = load_project_config(path, overrides={"output": "reports/cli"})

    assert result.ok
    assert result.config is not None
    assert result.config.project.artifact_directory == "reports/cli"


@pytest.mark.parametrize(
    "overrides",
    [
        {"signers.test_hmac.secret": "not-allowed"},
        {"receiver.target_profile": "public-authorized"},
        {"receiver": {"target_profile": "public-authorized"}},
        {"extra": True},
    ],
)
def test_undeclared_cli_override_is_rejected(
    overrides: dict[str, object],
) -> None:
    diagnostic = _only_diagnostic(load_project_config(MINIMAL_EXAMPLE, overrides=overrides))

    assert diagnostic.code == DiagnosticCode("CFG_CLI_OVERRIDE_UNDECLARED")
    assert diagnostic.safe_details == {"rule": "CFG-006"}


@pytest.mark.parametrize(
    "output",
    [
        "/absolute/output",
        "../escape",
        "reports/../../escape",
        r"reports\alternate",
        "C:/drive/output",
        r"C:\drive\output",
        r"\\server\share",
        "//server/share",
        "https://example.invalid/output",
    ],
)
def test_output_override_rejects_non_project_relative_forms(output: str) -> None:
    diagnostic = _only_diagnostic(
        load_project_config(MINIMAL_EXAMPLE, overrides={"output": output})
    )

    assert str(diagnostic.code).startswith("CFG_CLI_OUTPUT_")
    assert diagnostic.field_path == "cli.output"


def test_cli_overrides_are_strict_and_immutable() -> None:
    overrides = CliOverrides(project_root=".", output=Path("reports") / "cli")
    assert overrides.output == Path("reports") / "cli"

    with pytest.raises(FrozenInstanceError):
        overrides.output = "changed"  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(TypeError):
        CliOverrides(output=1)  # type: ignore[arg-type]

    diagnostic = _only_diagnostic(load_project_config(MINIMAL_EXAMPLE, overrides={"output": 1}))
    assert diagnostic.code == DiagnosticCode("CFG_CLI_OVERRIDE_INVALID")


def test_project_root_override_is_config_relative_and_cwd_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_directory = tmp_path / "configuration"
    config_directory.mkdir()
    selected_root = config_directory / "selected-root"
    selected_root.mkdir()
    config_path = config_directory / "project.yaml"
    config_path.write_text(
        MINIMAL_EXAMPLE.read_text(encoding="utf-8").replace(
            "path: fixtures/payment_succeeded.json",
            "path: ./fixtures//payment_succeeded.json",
        ),
        encoding="utf-8",
    )
    for root in (config_directory, selected_root):
        fixture_directory = root / "fixtures"
        fixture_directory.mkdir()
        (fixture_directory / "payment_succeeded.json").write_bytes(b"{}")
    other_cwd = tmp_path / "other-cwd"
    other_cwd.mkdir()

    default_result = load_project_config(config_path)
    monkeypatch.chdir(other_cwd)
    overridden_result = load_project_config(
        config_path,
        overrides=CliOverrides(project_root="selected-root"),
    )

    assert default_result.project_root == config_directory.resolve()
    assert overridden_result.project_root == selected_root.resolve()
    assert overridden_result.config == default_result.config
    assert overridden_result.config is not None
    assert overridden_result.config.fixtures[0].path == "fixtures/payment_succeeded.json"


@pytest.mark.parametrize(
    ("fixture_path", "code"),
    [
        ("/absolute/payload.json", "CFG_PATH_ABSOLUTE"),
        ("../outside.json", "CFG_PATH_TRAVERSAL"),
        (r"fixtures\payload.json", "CFG_PATH_ALTERNATE_SEPARATOR"),
        ("C:/payload.json", "CFG_PATH_WINDOWS_DRIVE"),
        (r"C:\payload.json", "CFG_PATH_WINDOWS_DRIVE"),
        (r"\\server\share\payload.json", "CFG_PATH_UNC"),
        ("//server/share/payload.json", "CFG_PATH_UNC"),
        ("https://example.invalid/payload.json", "CFG_PATH_REMOTE"),
        ("NUL", "CFG_PATH_DEVICE"),
        ("fixtures/CON.txt", "CFG_PATH_DEVICE"),
        ("fixtures/missing.json", "CFG_PATH_MISSING"),
    ],
)
def test_fixture_path_security_matrix(
    tmp_path: Path,
    fixture_path: str,
    code: str,
) -> None:
    path = _minimal_with(
        tmp_path,
        "path: fixtures/payment_succeeded.json",
        f"path: {fixture_path}",
    )

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode(code)
    assert diagnostic.field_path == "$.fixtures[0].path"
    assert diagnostic.safe_details == {"path_kind": "fixture", "rule": "SEC-016"}


def test_fixture_must_be_regular_and_normalizes_project_relative_text(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "fixtures" / "not-a-file"
    directory.mkdir(parents=True)
    invalid_path = _minimal_with(
        tmp_path,
        "path: fixtures/payment_succeeded.json",
        "path: fixtures/not-a-file",
    )
    assert _only_diagnostic(load_project_config(invalid_path)).code == DiagnosticCode(
        "CFG_PATH_NOT_REGULAR_FILE"
    )

    valid_path = _minimal_with(
        tmp_path,
        "path: fixtures/payment_succeeded.json",
        "path: ./fixtures//payment_succeeded.json",
    )
    result = load_project_config(valid_path)
    assert result.config is not None
    assert result.config.fixtures[0].path == "fixtures/payment_succeeded.json"


def test_fixture_rejects_final_and_intermediate_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "payload.json"
    outside_file.write_bytes(b"outside")
    fixture_directory = tmp_path / "fixtures"

    final_link = fixture_directory / "linked.json"
    _symlink_or_skip(final_link, outside_file)
    final_config = _minimal_with(
        tmp_path,
        "path: fixtures/payment_succeeded.json",
        "path: fixtures/linked.json",
    )
    assert _only_diagnostic(load_project_config(final_config)).code == DiagnosticCode(
        "CFG_PATH_SYMLINK"
    )

    linked_directory = fixture_directory / "linked-directory"
    _symlink_or_skip(linked_directory, outside, target_is_directory=True)
    intermediate_config = _minimal_with(
        tmp_path,
        "path: fixtures/payment_succeeded.json",
        "path: fixtures/linked-directory/payload.json",
    )
    assert _only_diagnostic(load_project_config(intermediate_config)).code == DiagnosticCode(
        "CFG_PATH_SYMLINK"
    )


@pytest.mark.parametrize(
    "case",
    [
        "configuration_source",
        "project_root",
        "fixture",
        "fixture_schema",
        "output_existing",
        "output_missing",
        "output_existing_revalidate",
        "output_missing_revalidate",
        "secret_root",
        "signer_secret",
        "receiver_test_ca",
        "command_observer_executable",
        "command_observer_working_directory",
        "http_observer_file_token",
        "lifecycle_executable",
        "lifecycle_working_directory",
    ],
)
def test_windows_pre_relative_open_junction_swaps_never_touch_external_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction race")
    race = _prepare_windows_relative_race(tmp_path, case)
    _warm_windows_junction_support(tmp_path)
    warm_session = config_loader._WindowsMetadataSession.open(tmp_path)
    warm_session.close()
    _windows_process_handle_count()
    baseline_handles = _windows_process_handle_count()
    external_before = _tree_snapshot(race.external)
    real_absolute_open = config_loader._windows_open_path
    real_relative_open = config_loader._windows_open_relative_path
    real_attributes = config_loader._windows_file_attributes
    real_identity = config_loader._windows_file_identity
    real_final_path = config_loader._windows_final_path
    real_read = config_loader.os.read
    real_write = config_loader.os.write
    swapped = False
    reads_after_swap = 0
    writes_after_swap = 0
    external_metadata_handles: set[str] = set()
    absolute_child_opens: list[Path] = []
    trigger_matches = 0

    def record_external_handle(handle: int) -> None:
        if not swapped:
            return
        actual = real_final_path(handle)
        if config_loader._windows_path_is_within(actual, race.external):
            external_metadata_handles.add(str(actual))

    def recording_absolute_open(
        opened_path: Path,
        *,
        directory: bool,
    ) -> int:
        expected = config_loader._absolute_windows_path(opened_path)
        if not config_loader._same_windows_path(expected, Path(expected.anchor)):
            absolute_child_opens.append(expected)
        return real_absolute_open(opened_path, directory=directory)

    def racing_relative_open(
        parent_handle: int,
        name: str,
        *,
        directory: bool,
        read_content: bool = False,
    ) -> int:
        nonlocal swapped, trigger_matches
        parent_path = real_final_path(parent_handle)
        matches_trigger = (
            config_loader._same_windows_path(parent_path, race.trigger_parent)
            and name == race.trigger_name
            and directory is race.trigger_directory
            and read_content is race.trigger_read_content
        )
        if matches_trigger:
            trigger_matches += 1
        if not swapped and trigger_matches == race.trigger_occurrence:
            race.swap_path.rename(race.moved_path)
            _make_directory_junction(race.swap_path, race.external)
            swapped = True
        return real_relative_open(
            parent_handle,
            name,
            directory=directory,
            read_content=read_content,
        )

    def recording_attributes(handle: int) -> int:
        record_external_handle(handle)
        return real_attributes(handle)

    def recording_identity(handle: int) -> tuple[int, int]:
        record_external_handle(handle)
        return real_identity(handle)

    def recording_final_path(handle: int) -> Path:
        actual = real_final_path(handle)
        if swapped and config_loader._windows_path_is_within(actual, race.external):
            external_metadata_handles.add(str(actual))
        return actual

    def recording_read(descriptor: int, length: int) -> bytes:
        nonlocal reads_after_swap
        if swapped:
            reads_after_swap += 1
        return real_read(descriptor, length)

    def recording_write(descriptor: int, body: object) -> int:
        nonlocal writes_after_swap
        if swapped:
            writes_after_swap += 1
        return real_write(descriptor, body)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(config_loader, "_windows_open_path", recording_absolute_open)
    monkeypatch.setattr(config_loader, "_windows_open_relative_path", racing_relative_open)
    monkeypatch.setattr(config_loader, "_windows_file_attributes", recording_attributes)
    monkeypatch.setattr(config_loader, "_windows_file_identity", recording_identity)
    monkeypatch.setattr(config_loader, "_windows_final_path", recording_final_path)
    monkeypatch.setattr(config_loader.os, "read", recording_read)
    monkeypatch.setattr(config_loader.os, "write", recording_write)

    diagnostic = _only_diagnostic(load_project_config(race.source_path, overrides=race.overrides))

    assert diagnostic.code == DiagnosticCode(race.expected_code)
    assert swapped is True
    assert reads_after_swap == 0
    assert writes_after_swap == 0
    assert external_metadata_handles == set()
    assert absolute_child_opens == []
    assert _windows_process_handle_count() == baseline_handles
    assert _tree_snapshot(race.external) == external_before


def test_secret_roots_and_file_references_are_contained_metadata_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_directory = tmp_path / ".secrets"
    secret_directory.mkdir()
    secret_file = secret_directory / "key"
    secret_file.write_bytes(b"SECRET_CANARY_MUST_NOT_BE_READ")
    path = _file_secret_config(
        tmp_path,
        root_path="./.secrets",
        reference_path="./.secrets//key",
    )
    fixture = tmp_path / "fixtures" / "payment_succeeded.json"
    original_open = Path.open

    def guarded_open(
        opened_path: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> object:
        if opened_path in {fixture, secret_file}:
            message = "configuration validation read fixture or secret content"
            raise AssertionError(message)
        return original_open(
            opened_path,
            mode,
            buffering,
            encoding,
            errors,
            newline,
        )

    monkeypatch.setattr(Path, "open", guarded_open)

    result = load_project_config(path)

    assert result.config is not None
    assert result.config.project.secret_roots == (".secrets",)
    signer = result.config.signers["test_hmac"]
    assert signer.secret.to_wire() == {"file": ".secrets/key"}


def test_secret_file_must_be_within_a_declared_regular_root(tmp_path: Path) -> None:
    secret_directory = tmp_path / ".secrets"
    secret_directory.mkdir()
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    (outside_directory / "key").write_bytes(b"outside")
    outside_config = _file_secret_config(
        tmp_path,
        root_path=".secrets",
        reference_path="outside/key",
    )

    diagnostic = _only_diagnostic(load_project_config(outside_config))
    assert diagnostic.code == DiagnosticCode("CFG_SECRET_PATH_OUTSIDE_ROOT")
    assert diagnostic.category is ErrorCategory.SECRET_REFERENCE_ERROR

    (secret_directory / "directory-key").mkdir()
    directory_config = _file_secret_config(
        tmp_path,
        root_path=".secrets",
        reference_path=".secrets/directory-key",
    )
    diagnostic = _only_diagnostic(load_project_config(directory_config))
    assert diagnostic.code == DiagnosticCode("CFG_PATH_NOT_REGULAR_FILE")
    assert diagnostic.category is ErrorCategory.SECRET_REFERENCE_ERROR


def test_secret_root_must_exist_as_a_real_directory(tmp_path: Path) -> None:
    root_file = tmp_path / "not-a-directory"
    root_file.write_bytes(b"file")
    path = _file_secret_config(
        tmp_path,
        root_path="not-a-directory",
        reference_path="not-a-directory/key",
    )

    codes = {diagnostic.code for diagnostic in load_project_config(path).diagnostics}

    assert DiagnosticCode("CFG_PATH_NOT_DIRECTORY") in codes


def test_command_observer_explicit_paths_are_normalized_and_validated(
    tmp_path: Path,
) -> None:
    tool_directory = tmp_path / "tools"
    tool_directory.mkdir()
    executable = tool_directory / "observer"
    executable.write_bytes(b"metadata")
    working_directory = tmp_path / "observer-work"
    working_directory.mkdir()
    text = (
        MINIMAL_EXAMPLE.read_text(encoding="utf-8")
        .replace("- python\n    - tests/observer.py", "- ./tools//observer\n    - ignored-argument")
        .replace(
            "    timeout: 2s",
            "    timeout: 2s\n    working_directory: ./observer-work",
        )
    )
    path = _write_config(tmp_path, text)

    result = load_project_config(path)

    assert result.config is not None
    observer = result.config.observers["receiver_state"]
    assert observer.type == "command"
    assert observer.argv[0] == "tools/observer"
    assert observer.working_directory == "observer-work"

    executable.unlink()
    assert _only_diagnostic(load_project_config(path)).code == DiagnosticCode("CFG_PATH_MISSING")


def test_lifecycle_working_directory_and_explicit_executables_are_validated(
    tmp_path: Path,
) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("stop", "start", "restart"):
        (tools / name).write_bytes(b"metadata")
    working_directory = tmp_path / "receiver-work"
    working_directory.mkdir()
    path = _write_config(
        tmp_path,
        MINIMAL_EXAMPLE.read_text(encoding="utf-8").replace(
            "lifecycles: {}",
            """lifecycles:
  receiver:
    enabled: true
    stop_argv:
    - ./tools/stop
    start_argv:
    - ./tools/start
    restart_argv:
    - ./tools/restart
    working_directory: ./receiver-work
    environment_allowlist: []
    timeout: 5s
    readiness_observer: receiver_state""",
        ),
    )

    result = load_project_config(path)

    assert result.config is not None
    lifecycle = result.config.lifecycles["receiver"]
    assert lifecycle.working_directory == "receiver-work"
    assert lifecycle.stop_argv[0] == "tools/stop"
    assert lifecycle.start_argv[0] == "tools/start"
    assert lifecycle.restart_argv[0] == "tools/restart"

    (tools / "restart").unlink()
    assert _only_diagnostic(load_project_config(path)).code == DiagnosticCode("CFG_PATH_MISSING")


def test_artifact_destination_allows_only_a_missing_final_directory(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing-reports"
    existing.mkdir()
    existing_config = _minimal_with(
        tmp_path,
        "artifact_directory: .webhook-conformance",
        "artifact_directory: ./existing-reports",
    )
    existing_result = load_project_config(existing_config)
    assert existing_result.config is not None
    assert existing_result.config.project.artifact_directory == "existing-reports"

    parent = tmp_path / "reports"
    parent.mkdir()
    missing_final = _minimal_with(
        tmp_path,
        "artifact_directory: .webhook-conformance",
        "artifact_directory: reports/new-run",
    )
    assert load_project_config(missing_final).ok

    missing_parent = _minimal_with(
        tmp_path,
        "artifact_directory: .webhook-conformance",
        "artifact_directory: unavailable/new-run",
    )
    assert _only_diagnostic(load_project_config(missing_parent)).code == DiagnosticCode(
        "CFG_PATH_MISSING"
    )

    file_destination = tmp_path / "not-a-directory"
    file_destination.write_bytes(b"file")
    file_config = _minimal_with(
        tmp_path,
        "artifact_directory: .webhook-conformance",
        "artifact_directory: not-a-directory",
    )
    assert _only_diagnostic(load_project_config(file_config)).code == DiagnosticCode(
        "CFG_PATH_NOT_DIRECTORY"
    )


def test_cli_output_missing_final_destination_requires_existing_parent(
    tmp_path: Path,
) -> None:
    path = _write_config(
        tmp_path,
        MINIMAL_EXAMPLE.read_text(encoding="utf-8"),
    )
    reports = tmp_path / "reports"
    reports.mkdir()

    valid = load_project_config(path, overrides={"output": "reports/new-run"})
    invalid = load_project_config(path, overrides={"output": "missing/new-run"})

    assert valid.ok
    assert _only_diagnostic(invalid).code == DiagnosticCode("CFG_PATH_MISSING")


def test_test_ca_path_requires_a_real_regular_file(tmp_path: Path) -> None:
    certificate_directory = tmp_path / "certificates"
    certificate_directory.mkdir()
    certificate = certificate_directory / "test-ca.pem"
    certificate.write_bytes(b"certificate metadata")
    path = _minimal_with(
        tmp_path,
        "  timeouts:",
        "  test_ca_file: ./certificates//test-ca.pem\n  timeouts:",
    )

    result = load_project_config(path)

    assert result.config is not None
    assert result.config.receiver.test_ca_file == "certificates/test-ca.pem"

    certificate.unlink()
    certificate.mkdir()
    assert _only_diagnostic(load_project_config(path)).code == DiagnosticCode(
        "CFG_PATH_NOT_REGULAR_FILE"
    )


def test_project_root_override_must_be_a_real_directory(tmp_path: Path) -> None:
    root_file = tmp_path / "root-file"
    root_file.write_bytes(b"file")

    diagnostic = _only_diagnostic(
        load_project_config(
            MINIMAL_EXAMPLE,
            overrides=CliOverrides(project_root=root_file),
        )
    )

    assert diagnostic.code == DiagnosticCode("CFG_CLI_PROJECT_ROOT_INVALID")


def test_project_root_override_rejects_a_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "root-link"
    _symlink_or_skip(link, target, target_is_directory=True)

    diagnostic = _only_diagnostic(
        load_project_config(
            MINIMAL_EXAMPLE,
            overrides=CliOverrides(project_root=link),
        )
    )

    assert diagnostic.code == DiagnosticCode("CFG_CLI_PROJECT_ROOT_INVALID")


def test_duplicate_receiver_key_reports_second_key_line_and_column(tmp_path: Path) -> None:
    original = MINIMAL_EXAMPLE.read_text(encoding="utf-8")
    duplicate_line = len(original.splitlines()) + 2
    path = _write_config(
        tmp_path,
        f"{original}\nreceiver:\n  url: http://127.0.0.1:8000/duplicate\n",
    )

    result = load_project_config(path)

    diagnostic = _only_diagnostic(result)
    assert diagnostic.code == DiagnosticCode("CFG_YAML_DUPLICATE_KEY")
    assert diagnostic.field_path == "$.receiver"
    assert diagnostic.location is not None
    assert diagnostic.location.path == str(path.resolve())
    assert diagnostic.location.line == duplicate_line
    assert diagnostic.location.column == 1


@pytest.mark.parametrize(
    ("replacement", "code"),
    [
        ("name: !application/custom project", "CFG_YAML_TAG"),
        ("name: !!python/object:builtins.object {}", "CFG_YAML_TAG"),
        ("name: !!binary c2VjcmV0", "CFG_YAML_TAG"),
        ("name: 2026-07-27", "CFG_YAML_TIMESTAMP"),
    ],
)
def test_unsafe_or_non_json_yaml_tags_are_rejected_without_construction(
    tmp_path: Path,
    replacement: str,
    code: str,
) -> None:
    path = _minimal_with(
        tmp_path,
        "name: minimal-local-receiver-test",
        replacement,
    )

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode(code)
    assert diagnostic.location is not None
    assert (diagnostic.location.line, diagnostic.location.column) == TAG_LOCATION


def test_python_apply_tag_never_invokes_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoked = False

    def forbidden(_command: str) -> NoReturn:
        nonlocal invoked
        invoked = True
        message = "unsafe YAML constructor executed"
        raise AssertionError(message)

    monkeypatch.setattr("os.system", forbidden)
    path = _minimal_with(
        tmp_path,
        "name: minimal-local-receiver-test",
        "name: !!python/object/apply:os.system ['never-run']",
    )

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode("CFG_YAML_TAG")
    assert invoked is False


def test_anchor_is_rejected_before_yaml_composition(tmp_path: Path) -> None:
    text = MINIMAL_EXAMPLE.read_text(encoding="utf-8")
    text = text.replace(
        "name: minimal-local-receiver-test",
        "name: &project_name minimal-local-receiver-test",
    ).replace(
        "artifact_directory: .webhook-conformance",
        "artifact_directory: *project_name",
    )

    diagnostic = _only_diagnostic(load_project_config(_write_config(tmp_path, text)))

    assert diagnostic.code == DiagnosticCode("CFG_YAML_ANCHOR")
    assert diagnostic.location is not None
    assert (diagnostic.location.line, diagnostic.location.column) == TAG_LOCATION


@pytest.mark.parametrize(
    ("case", "expected_code", "expected_limit"),
    [
        ("nodes", "CFG_RESOURCE_LIMIT", "MAX_CONFIG_NODES"),
        ("depth", "CFG_RESOURCE_LIMIT", "MAX_CONFIG_DEPTH"),
        ("alias", "CFG_YAML_ALIAS", None),
        ("anchor", "CFG_YAML_ANCHOR", None),
        ("tag", "CFG_YAML_TAG", None),
        ("version", "CFG_YAML_VERSION", None),
    ],
)
def test_event_preflight_rejects_before_composition_or_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_code: str,
    expected_limit: str | None,
) -> None:
    if case == "nodes":
        text = "- 0\n" * MAX_CONFIG_NODES
    elif case == "depth":
        text = ("[" * MAX_CONFIG_DEPTH) + "0" + ("]" * MAX_CONFIG_DEPTH)
    elif case == "alias":
        text = "value: *missing\n"
    elif case == "anchor":
        text = "value: &named explicit\n"
    elif case == "tag":
        text = "value: !application/unsafe payload\n"
    else:
        text = "%YAML 1.1\n---\nvalue: explicit\n"

    def forbidden(*_args: object, **_kwargs: object) -> NoReturn:
        pytest.fail("event preflight must reject before composition or construction")

    monkeypatch.setattr(config_loader.yaml, "compose", forbidden)
    monkeypatch.setattr(config_loader, "_construct_json_document", forbidden)

    path = _write_config(tmp_path, "")
    path.write_bytes(text.encode("utf-8"))
    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode(expected_code)
    if expected_limit is not None:
        assert diagnostic.category is ErrorCategory.RESOURCE_LIMIT
        assert diagnostic.safe_details == {
            "limit": expected_limit,
            "maximum": (
                MAX_CONFIG_NODES if expected_limit == "MAX_CONFIG_NODES" else MAX_CONFIG_DEPTH
            ),
        }


def test_event_preflight_allows_exact_node_limit_to_reach_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "- 0\n" * (MAX_CONFIG_NODES - 1)
    compose_calls = 0

    def recording_compose(*_args: object, **_kwargs: object) -> None:
        nonlocal compose_calls
        compose_calls += 1

    monkeypatch.setattr(config_loader.yaml, "compose", recording_compose)

    diagnostic = _only_diagnostic(load_project_config(_write_config(tmp_path, text)))

    assert compose_calls == 1
    assert diagnostic.code == DiagnosticCode("CFG_SCHEMA_VERSION_REQUIRED")


def test_near_byte_cap_node_failure_stops_before_composition_with_bounded_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_prefix = "- 0\n" * MAX_CONFIG_NODES
    padding_length = MAX_CONFIG_BYTES - len(node_prefix.encode("utf-8"))
    assert padding_length > 1
    text = node_prefix + "#" + ("X" * (padding_length - 1))
    assert len(text.encode("utf-8")) == MAX_CONFIG_BYTES

    def forbidden(*_args: object, **_kwargs: object) -> NoReturn:
        pytest.fail("node-limited input must not be composed")

    monkeypatch.setattr(config_loader.yaml, "compose", forbidden)
    monkeypatch.setattr(config_loader, "_construct_json_document", forbidden)

    path = _write_config(tmp_path, "")
    path.write_bytes(text.encode("utf-8"))
    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode("CFG_RESOURCE_LIMIT")
    assert diagnostic.safe_details == {
        "limit": "MAX_CONFIG_NODES",
        "maximum": MAX_CONFIG_NODES,
    }
    rendered = diagnostic.model_dump_json()
    assert len(rendered) < MAX_RENDERED_DIAGNOSTIC
    assert "XXXXXXXX" not in rendered


def test_yaml_version_directive_must_be_1_2(tmp_path: Path) -> None:
    original = MINIMAL_EXAMPLE.read_text(encoding="utf-8")
    unsupported = _write_config(tmp_path, f"%YAML 1.1\n---\n{original}")

    diagnostic = _only_diagnostic(load_project_config(unsupported))

    assert diagnostic.code == DiagnosticCode("CFG_YAML_VERSION")

    supported = _write_config(tmp_path, f"%YAML 1.2\n---\n{original}")
    assert load_project_config(supported).ok


def test_merge_key_is_rejected_without_applying_it(tmp_path: Path) -> None:
    path = _minimal_with(
        tmp_path,
        "  name: minimal-local-receiver-test",
        "  <<: {name: merged}\n  name: minimal-local-receiver-test",
    )

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode("CFG_YAML_MERGE_KEY")
    assert diagnostic.field_path == "$.project['<<']"
    assert diagnostic.location is not None
    assert (diagnostic.location.line, diagnostic.location.column) == MERGE_LOCATION


@pytest.mark.parametrize(
    ("needle", "replacement", "code", "field_path"),
    [
        (
            "max_events: 100",
            "max_events: 1.0",
            "CFG_YAML_FLOAT",
            "$.limits.max_events",
        ),
        (
            "max_events: 100",
            "max_events: .nan",
            "CFG_YAML_FLOAT",
            "$.limits.max_events",
        ),
        (
            "schema_version: 1",
            "[schema_version]: 1",
            "CFG_YAML_NON_STRING_KEY",
            "$",
        ),
    ],
)
def test_non_json_yaml_values_are_rejected(
    tmp_path: Path,
    needle: str,
    replacement: str,
    code: str,
    field_path: str,
) -> None:
    diagnostic = _only_diagnostic(load_project_config(_minimal_with(tmp_path, needle, replacement)))

    assert diagnostic.code == DiagnosticCode(code)
    assert diagnostic.field_path == field_path


@pytest.mark.parametrize(
    "value",
    [
        "!!int not-an-integer",
        "!!bool maybe",
        "!!null present",
    ],
)
def test_invalid_explicit_scalar_tags_return_diagnostics(
    tmp_path: Path,
    value: str,
) -> None:
    path = _minimal_with(
        tmp_path,
        "name: minimal-local-receiver-test",
        f"name: {value}",
    )

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode("CFG_YAML_SCALAR")


def test_excessive_integer_lexeme_returns_bounded_diagnostic(tmp_path: Path) -> None:
    path = _minimal_with(
        tmp_path,
        "max_events: 100",
        f"max_events: {'9' * 10000}",
    )

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode("CFG_YAML_INTEGER_RANGE")


def test_unknown_model_field_has_structured_secret_safe_diagnostic(tmp_path: Path) -> None:
    canary = "DO_NOT_RENDER_THIS_SECRET_VALUE"
    original = MINIMAL_EXAMPLE.read_text(encoding="utf-8")
    path = _write_config(tmp_path, f"{original}\ninclude: {canary}\n")

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode("CFG_UNKNOWN_FIELD")
    assert diagnostic.category is ErrorCategory.CONFIGURATION_ERROR
    assert diagnostic.result_category is ResultCategory.INVALID_INPUT
    assert diagnostic.retryable is False
    assert diagnostic.user_correctable is True
    assert diagnostic.field_path == "$.include"
    assert diagnostic.corrective_action is not None
    assert canary not in diagnostic.model_dump_json()


def test_unsupported_schema_is_classified_before_model_validation(tmp_path: Path) -> None:
    path = _minimal_with(tmp_path, "schema_version: 1", "schema_version: 2")

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode("CFG_SCHEMA_VERSION_UNSUPPORTED")
    assert diagnostic.category is ErrorCategory.UNSUPPORTED_SCHEMA
    assert diagnostic.result_category is ResultCategory.UNSUPPORTED
    assert diagnostic.location is not None
    assert diagnostic.location.path == str(path.resolve())
    assert (
        diagnostic.location.line,
        diagnostic.location.column,
    ) == SCHEMA_VERSION_LOCATION


def test_byte_limit_is_enforced_before_decoding_or_yaml_parsing(tmp_path: Path) -> None:
    path = tmp_path / "oversized.yaml"
    path.write_bytes(b"\xff" + (b" " * MAX_CONFIG_BYTES))

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode("CFG_RESOURCE_LIMIT")
    assert diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert diagnostic.safe_details == {
        "limit": "MAX_CONFIG_BYTES",
        "maximum": MAX_CONFIG_BYTES,
    }


def test_depth_limit_is_enforced_before_model_construction(tmp_path: Path) -> None:
    # The root mapping adds one level; 64 nested sequences cross MAX_CONFIG_DEPTH.
    nested = ("[" * 64) + "1" + ("]" * 64)
    path = _write_config(tmp_path, f"schema_version: 1\nextra: {nested}\n")

    diagnostic = _only_diagnostic(load_project_config(path))

    assert diagnostic.code == DiagnosticCode("CFG_RESOURCE_LIMIT")
    assert diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert diagnostic.safe_details["limit"] == "MAX_CONFIG_DEPTH"


def test_validation_performs_no_network_or_process_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> NoReturn:
        message = "validation attempted external execution"
        raise AssertionError(message)

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)

    result = load_project_config(MINIMAL_EXAMPLE)

    assert result.ok


def test_missing_and_non_regular_configuration_paths_are_diagnostic(
    tmp_path: Path,
) -> None:
    missing = load_project_config(tmp_path / "missing.yaml")
    directory = load_project_config(tmp_path)

    assert _only_diagnostic(missing).code == DiagnosticCode("CFG_FILE_UNREADABLE")
    assert _only_diagnostic(directory).code == DiagnosticCode("CFG_FILE_NOT_REGULAR")


def _minimal_with(tmp_path: Path, needle: str, replacement: str) -> Path:
    original = MINIMAL_EXAMPLE.read_text(encoding="utf-8")
    assert needle in original
    return _write_config(tmp_path, original.replace(needle, replacement, 1))


def _file_secret_config(
    tmp_path: Path,
    *,
    root_path: str,
    reference_path: str,
) -> Path:
    text = (
        MINIMAL_EXAMPLE.read_text(encoding="utf-8")
        .replace(
            "  artifact_directory: .webhook-conformance",
            f"  artifact_directory: .webhook-conformance\n  secret_roots:\n  - {root_path}",
        )
        .replace(
            "    secret:\n      env: WEBHOOK_TEST_SECRET",
            f"    secret:\n      file: {reference_path}",
        )
    )
    return _write_config(tmp_path, text)


def _prepare_windows_relative_race(
    tmp_path: Path,
    case: str,
) -> _WindowsRelativeRace:
    minimal = MINIMAL_EXAMPLE.read_text(encoding="utf-8")
    external = tmp_path / f"external-{case.replace('_', '-')}"
    external.mkdir()
    (external / "external-canary.bin").write_bytes(f"EXTERNAL-{case}-CANARY".encode())

    if case == "configuration_source":
        configuration = tmp_path / "configuration"
        configuration.mkdir()
        source_path = _write_config(configuration, minimal)
        (external / "project.yaml").write_bytes(b"EXTERNAL-CONFIGURATION-CANARY")
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=configuration,
            trigger_name="project.yaml",
            trigger_directory=False,
            trigger_read_content=True,
            swap_path=configuration,
            moved_path=tmp_path / "configuration-before-swap",
            external=external,
            expected_code="CFG_FILE_UNREADABLE",
        )

    if case == "project_root":
        configuration = tmp_path / "configuration"
        configuration.mkdir()
        source_path = _write_config(configuration, minimal)
        selected_root = configuration / "selected-root"
        selected_fixture_directory = selected_root / "fixtures"
        selected_fixture_directory.mkdir(parents=True)
        (selected_fixture_directory / "payment_succeeded.json").write_bytes(b"{}")
        external_selected_root = external / "selected-root"
        (external_selected_root / "fixtures").mkdir(parents=True)
        (external_selected_root / "fixtures" / "payment_succeeded.json").write_bytes(
            b"EXTERNAL-PROJECT-ROOT-CANARY"
        )
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=CliOverrides(project_root="selected-root"),
            trigger_parent=configuration,
            trigger_name="selected-root",
            trigger_directory=True,
            trigger_read_content=False,
            swap_path=configuration,
            moved_path=tmp_path / "configuration-before-root-swap",
            external=external,
            expected_code="CFG_CLI_PROJECT_ROOT_INVALID",
        )

    if case == "fixture":
        source_path = _write_config(tmp_path, minimal)
        fixtures = tmp_path / "fixtures"
        (external / "payment_succeeded.json").write_bytes(b"EXTERNAL-FIXTURE-CANARY")
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=fixtures,
            trigger_name="payment_succeeded.json",
            trigger_directory=False,
            trigger_read_content=False,
            swap_path=fixtures,
            moved_path=tmp_path / "fixtures-before-swap",
            external=external,
            expected_code="CFG_PATH_SYMLINK",
        )

    if case == "fixture_schema":
        source_path = _write_config(
            tmp_path,
            minimal.replace(
                "  media_type: application/json",
                "  media_type: application/json\n  schema_path: schemas/event.schema.json",
            ),
        )
        schemas = tmp_path / "schemas"
        schemas.mkdir()
        (schemas / "event.schema.json").write_bytes(b"{}")
        (external / "event.schema.json").write_bytes(b"EXTERNAL-SCHEMA-CANARY")
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=schemas,
            trigger_name="event.schema.json",
            trigger_directory=False,
            trigger_read_content=False,
            swap_path=schemas,
            moved_path=tmp_path / "schemas-before-swap",
            external=external,
            expected_code="CFG_PATH_SYMLINK",
        )

    if case in {
        "output_existing",
        "output_missing",
        "output_existing_revalidate",
        "output_missing_revalidate",
    }:
        reports = tmp_path / "reports"
        reports.mkdir()
        missing = "missing" in case
        revalidate = case.endswith("_revalidate")
        output_name = "new-run" if missing else "existing-run"
        if not missing:
            (reports / output_name).mkdir()
        (external / output_name).mkdir()
        source_path = _write_config(
            tmp_path,
            minimal.replace(
                "artifact_directory: .webhook-conformance",
                f"artifact_directory: reports/{output_name}",
            ),
        )
        swap_path = reports
        moved_path = tmp_path / f"reports-before-{output_name}-swap"
        if revalidate and not missing:
            swap_path = reports / output_name
            moved_path = reports / f"{output_name}-before-revalidation-swap"
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=reports,
            trigger_name=output_name,
            trigger_directory=True,
            trigger_read_content=False,
            swap_path=swap_path,
            moved_path=moved_path,
            external=external,
            expected_code=("CFG_PATH_METADATA_ERROR" if revalidate else "CFG_PATH_SYMLINK"),
            trigger_occurrence=(2 if revalidate else 1),
        )

    if case == "secret_root":
        secrets = tmp_path / ".secrets"
        secrets.mkdir()
        (secrets / "key").write_bytes(b"LOCAL-SECRET-CANARY")
        (external / "key").write_bytes(b"EXTERNAL-SECRET-ROOT-CANARY")
        source_path = _write_config(
            tmp_path,
            minimal.replace(
                "  artifact_directory: .webhook-conformance",
                "  artifact_directory: .webhook-conformance\n  secret_roots:\n  - .secrets",
            ),
        )
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=tmp_path,
            trigger_name=".secrets",
            trigger_directory=True,
            trigger_read_content=False,
            swap_path=secrets,
            moved_path=tmp_path / ".secrets-before-root-swap",
            external=external,
            expected_code="CFG_PATH_SYMLINK",
        )

    if case == "signer_secret":
        secrets = tmp_path / ".secrets"
        secrets.mkdir()
        (secrets / "key").write_bytes(b"LOCAL-SIGNER-SECRET-CANARY")
        (external / "key").write_bytes(b"EXTERNAL-SIGNER-SECRET-CANARY")
        source_path = _file_secret_config(
            tmp_path,
            root_path=".secrets",
            reference_path=".secrets/key",
        )
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=secrets,
            trigger_name="key",
            trigger_directory=False,
            trigger_read_content=False,
            swap_path=secrets,
            moved_path=tmp_path / ".secrets-before-file-swap",
            external=external,
            expected_code="CFG_PATH_SYMLINK",
        )

    if case == "receiver_test_ca":
        certificates = tmp_path / "certificates"
        certificates.mkdir()
        (certificates / "test-ca.pem").write_bytes(b"LOCAL-CA-CANARY")
        (external / "test-ca.pem").write_bytes(b"EXTERNAL-CA-CANARY")
        source_path = _write_config(
            tmp_path,
            minimal.replace(
                "  timeouts:",
                "  test_ca_file: certificates/test-ca.pem\n  timeouts:",
            ),
        )
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=certificates,
            trigger_name="test-ca.pem",
            trigger_directory=False,
            trigger_read_content=False,
            swap_path=certificates,
            moved_path=tmp_path / "certificates-before-swap",
            external=external,
            expected_code="CFG_PATH_SYMLINK",
        )

    if case == "command_observer_executable":
        tools = tmp_path / "tools"
        tools.mkdir()
        (tools / "observer").write_bytes(b"LOCAL-OBSERVER-CANARY")
        (external / "observer").write_bytes(b"EXTERNAL-OBSERVER-CANARY")
        source_path = _write_config(
            tmp_path,
            minimal.replace(
                "- python\n    - tests/observer.py",
                "- tools/observer\n    - ignored-argument",
            ),
        )
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=tools,
            trigger_name="observer",
            trigger_directory=False,
            trigger_read_content=False,
            swap_path=tools,
            moved_path=tmp_path / "tools-before-observer-swap",
            external=external,
            expected_code="CFG_PATH_SYMLINK",
        )

    if case == "command_observer_working_directory":
        working_directory = tmp_path / "observer-work"
        working_directory.mkdir()
        source_path = _write_config(
            tmp_path,
            minimal.replace(
                "    timeout: 2s",
                "    timeout: 2s\n    working_directory: observer-work",
            ),
        )
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=tmp_path,
            trigger_name="observer-work",
            trigger_directory=True,
            trigger_read_content=False,
            swap_path=working_directory,
            moved_path=tmp_path / "observer-work-before-swap",
            external=external,
            expected_code="CFG_PATH_SYMLINK",
        )

    if case == "http_observer_file_token":
        secrets = tmp_path / ".observer-secrets"
        secrets.mkdir()
        (secrets / "token").write_bytes(b"LOCAL-OBSERVER-TOKEN-CANARY")
        (external / "token").write_bytes(b"EXTERNAL-OBSERVER-TOKEN-CANARY")
        command_observer = """observers:
  receiver_state:
    type: command
    argv:
    - python
    - tests/observer.py
    timeout: 2s
    environment_allowlist:
    - TEST_DATABASE_URL"""
        http_observer = """observers:
  receiver_state:
    type: http
    base_url: http://127.0.0.1:9000
    token:
      file: .observer-secrets/token
    timeouts:
      connect: 1s
      read: 1s
      total: 2s"""
        assert command_observer in minimal
        source_path = _write_config(
            tmp_path,
            minimal.replace(
                "  artifact_directory: .webhook-conformance",
                "  artifact_directory: .webhook-conformance\n"
                "  secret_roots:\n"
                "  - .observer-secrets",
            ).replace(command_observer, http_observer),
        )
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=secrets,
            trigger_name="token",
            trigger_directory=False,
            trigger_read_content=False,
            swap_path=secrets,
            moved_path=tmp_path / ".observer-secrets-before-swap",
            external=external,
            expected_code="CFG_PATH_SYMLINK",
        )

    if case in {"lifecycle_executable", "lifecycle_working_directory"}:
        working_directory = tmp_path / "receiver-work"
        working_directory.mkdir()
        tools = tmp_path / "tools"
        tools.mkdir()
        (tools / "stop").write_bytes(b"LOCAL-LIFECYCLE-CANARY")
        (external / "stop").write_bytes(b"EXTERNAL-LIFECYCLE-CANARY")
        stop_argv = "tools/stop" if case == "lifecycle_executable" else "stop"
        lifecycle = f"""lifecycles:
  receiver:
    enabled: true
    stop_argv:
    - {stop_argv}
    start_argv:
    - start
    restart_argv:
    - restart
    working_directory: receiver-work
    environment_allowlist: []
    timeout: 5s
    readiness_observer: receiver_state"""
        source_path = _write_config(
            tmp_path,
            minimal.replace("lifecycles: {}", lifecycle),
        )
        if case == "lifecycle_executable":
            return _WindowsRelativeRace(
                source_path=source_path,
                overrides=None,
                trigger_parent=tools,
                trigger_name="stop",
                trigger_directory=False,
                trigger_read_content=False,
                swap_path=tools,
                moved_path=tmp_path / "tools-before-lifecycle-swap",
                external=external,
                expected_code="CFG_PATH_SYMLINK",
            )
        return _WindowsRelativeRace(
            source_path=source_path,
            overrides=None,
            trigger_parent=tmp_path,
            trigger_name="receiver-work",
            trigger_directory=True,
            trigger_read_content=False,
            swap_path=working_directory,
            moved_path=tmp_path / "receiver-work-before-swap",
            external=external,
            expected_code="CFG_PATH_SYMLINK",
        )

    message = f"unknown Windows relative race case: {case}"
    raise AssertionError(message)


def _tree_snapshot(root: Path) -> dict[str, bytes | None]:
    snapshot: dict[str, bytes | None] = {}
    for child in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = child.relative_to(root).as_posix()
        snapshot[relative] = None if child.is_dir() else child.read_bytes()
    return snapshot


def _symlink_or_skip(
    link: Path,
    target: Path,
    *,
    target_is_directory: bool = False,
) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as error:
        pytest.skip(f"real symlink unavailable on this platform: {type(error).__name__}")


def _make_directory_junction(link: Path, target: Path) -> None:
    completed = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def _warm_windows_junction_support(tmp_path: Path) -> None:
    target = tmp_path / "junction-warm-target"
    target.mkdir(exist_ok=True)
    link = tmp_path / "junction-warm-link"
    _make_directory_junction(link, target)
    link.rmdir()


def _windows_process_handle_count() -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_current_process = kernel32.GetCurrentProcess
    get_current_process.restype = ctypes.c_void_p
    get_handle_count = kernel32.GetProcessHandleCount
    get_handle_count.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    get_handle_count.restype = ctypes.c_int
    count = ctypes.c_uint32()
    succeeded = get_handle_count(get_current_process(), ctypes.byref(count))
    assert succeeded
    return int(count.value)


def _write_config(tmp_path: Path, contents: str) -> Path:
    fixture_directory = tmp_path / "fixtures"
    fixture_directory.mkdir(exist_ok=True)
    fixture = fixture_directory / "payment_succeeded.json"
    if not fixture.exists():
        fixture.write_bytes(b"{}")
    path = tmp_path / "project.yaml"
    path.write_text(contents, encoding="utf-8")
    return path


def _only_diagnostic(result: ConfigLoadResult) -> Diagnostic:
    assert not result.ok
    assert result.config is None
    assert result.project_root is None
    assert len(result.diagnostics) == 1
    return result.diagnostics[0]
