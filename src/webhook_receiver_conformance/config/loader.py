"""Bounded, deterministic loader for the restricted project YAML contract."""
# ruff: noqa: ANN401, C901, D105, EM101, INP001, PLC0415, PLR0911, PLR0912, PLR0913, PTH100, RUF012, TRY301
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false

from __future__ import annotations

import ctypes
import os
import re
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Final, cast

import yaml
from pydantic import ValidationError
from yaml.error import Mark
from yaml.events import (
    AliasEvent,
    DocumentStartEvent,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from webhook_receiver_conformance.config.diagnostics import (
    MAX_CONFIG_DIAGNOSTICS,
    ConfigFieldPath,
    configuration_diagnostic,
    format_field_path,
    safe_source_label,
    validation_diagnostics,
)
from webhook_receiver_conformance.config.models import ProjectConfig
from webhook_receiver_conformance.config.schema import (
    MAX_CONFIG_BYTES,
    MAX_CONFIG_DEPTH,
    MAX_CONFIG_NODES,
    preflight_config,
)
from webhook_receiver_conformance.errors import (
    Diagnostic,
    DiagnosticLocation,
    ErrorCategory,
)

type StrPath = str | os.PathLike[str]
type JsonDocument = bool | int | str | list[JsonDocument] | dict[str, JsonDocument] | None

_YAML_MAP_TAG: Final = "tag:yaml.org,2002:map"
_YAML_SEQUENCE_TAG: Final = "tag:yaml.org,2002:seq"
_YAML_STRING_TAG: Final = "tag:yaml.org,2002:str"
_YAML_NULL_TAG: Final = "tag:yaml.org,2002:null"
_YAML_BOOLEAN_TAG: Final = "tag:yaml.org,2002:bool"
_YAML_INTEGER_TAG: Final = "tag:yaml.org,2002:int"
_YAML_FLOAT_TAG: Final = "tag:yaml.org,2002:float"
_YAML_TIMESTAMP_TAG: Final = "tag:yaml.org,2002:timestamp"
_YAML_ALLOWED_SCALAR_TAGS = frozenset(
    {
        _YAML_STRING_TAG,
        _YAML_NULL_TAG,
        _YAML_BOOLEAN_TAG,
        _YAML_INTEGER_TAG,
    }
)
_YAML_ALLOWED_TAGS = _YAML_ALLOWED_SCALAR_TAGS | {
    _YAML_MAP_TAG,
    _YAML_SEQUENCE_TAG,
}
_YAML_VERSION = (1, 2)
_MAX_INTEGER_LEXEME_LENGTH = 32
_MAX_CONFIG_PATH_LENGTH = 4096
_MAX_EVENT_PATH_PART_LENGTH = 128
_MAX_DIAGNOSTIC_COORDINATE = MAX_CONFIG_BYTES + 1
_INVALID_EVENT_KEY = "<invalid-key>"
_CONTROL_CHARACTER_LIMIT = 32
_DELETE_CHARACTER_CODEPOINT = 127
_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_WINDOWS_RESERVED_NAME = re.compile(
    r"^(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9]|LPT[1-9])"
    r"(?:\..*)?$",
    re.IGNORECASE,
)
_WINDOWS_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_DEVICE: Final = 0x00000040
_WINDOWS_FILE_ATTRIBUTE_NORMAL: Final = 0x00000080
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
_WINDOWS_FILE_ATTRIBUTE_TAG_INFO: Final = 9
_WINDOWS_FILE_DIRECTORY_FILE: Final = 0x00000001
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
_WINDOWS_FILE_LIST_DIRECTORY: Final = 0x00000001
_WINDOWS_FILE_NON_DIRECTORY_FILE: Final = 0x00000040
_WINDOWS_FILE_OPEN: Final = 1
_WINDOWS_FILE_OPEN_REPARSE_POINT: Final = 0x00200000
_WINDOWS_FILE_READ_ATTRIBUTES: Final = 0x00000080
_WINDOWS_FILE_READ_DATA: Final = 0x00000001
_WINDOWS_FILE_SHARE_DELETE: Final = 0x00000004
_WINDOWS_FILE_SHARE_READ: Final = 0x00000001
_WINDOWS_FILE_SHARE_WRITE: Final = 0x00000002
_WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT: Final = 0x00000020
_WINDOWS_FILE_TYPE_DISK: Final = 0x0001
_WINDOWS_FILE_TRAVERSE: Final = 0x00000020
_WINDOWS_OBJ_CASE_INSENSITIVE: Final = 0x00000040
_WINDOWS_OPEN_EXISTING: Final = 3
_WINDOWS_INVALID_HANDLE: Final = ctypes.c_void_p(-1).value
_WINDOWS_STATUS_FILE_IS_A_DIRECTORY: Final = 0xC00000BA
_WINDOWS_STATUS_NOT_A_DIRECTORY: Final = 0xC0000103
_WINDOWS_STATUS_OBJECT_NAME_NOT_FOUND: Final = 0xC0000034
_WINDOWS_STATUS_OBJECT_PATH_NOT_FOUND: Final = 0xC000003A
_WINDOWS_SYNCHRONIZE: Final = 0x00100000
_NULL_PATTERN = re.compile(r"^(?:~|null|Null|NULL)?$")
_BOOLEAN_PATTERN = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
_INTEGER_PATTERN = re.compile(r"^[-+]?(?:[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$")
_FLOAT_PATTERN = re.compile(
    r"^(?:"
    r"[-+]?(?:(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?"
    r"|[0-9]+[eE][-+]?[0-9]+)"
    r"|[-+]?\.(?:inf|Inf|INF|nan|NaN|NAN)"
    r")$"
)


class _WindowsFileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("reparse_tag", ctypes.c_uint32),
    ]


class _WindowsUnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", ctypes.c_void_p),
    ]


class _WindowsObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("root_directory", ctypes.c_void_p),
        ("object_name", ctypes.POINTER(_WindowsUnicodeString)),
        ("attributes", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


class _WindowsIoStatusValue(ctypes.Union):
    _fields_ = [
        ("status", ctypes.c_int32),
        ("pointer", ctypes.c_void_p),
    ]


class _WindowsIoStatusBlock(ctypes.Structure):
    _fields_ = [
        ("value", _WindowsIoStatusValue),
        ("information", ctypes.c_size_t),
    ]


class _WindowsByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("creation_time_low", ctypes.c_uint32),
        ("creation_time_high", ctypes.c_uint32),
        ("last_access_time_low", ctypes.c_uint32),
        ("last_access_time_high", ctypes.c_uint32),
        ("last_write_time_low", ctypes.c_uint32),
        ("last_write_time_high", ctypes.c_uint32),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


class _JsonYamlLoader(yaml.SafeLoader):
    """Resolver limited to the JSON-compatible YAML 1.2 core data model."""


_JsonYamlLoader.yaml_implicit_resolvers = {}
_JsonYamlLoader.add_implicit_resolver(
    _YAML_NULL_TAG,
    _NULL_PATTERN,
    ["~", "n", "N", None],
)
_JsonYamlLoader.add_implicit_resolver(
    _YAML_BOOLEAN_TAG,
    _BOOLEAN_PATTERN,
    ["t", "T", "f", "F"],
)
_JsonYamlLoader.add_implicit_resolver(
    _YAML_INTEGER_TAG,
    _INTEGER_PATTERN,
    list("-+0123456789"),
)
_JsonYamlLoader.add_implicit_resolver(
    _YAML_FLOAT_TAG,
    _FLOAT_PATTERN,
    list("-+0123456789."),
)
for _resolver_initial, _resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items():
    for _resolver_tag, _resolver_pattern in _resolvers:
        if _resolver_tag == _YAML_TIMESTAMP_TAG:
            _JsonYamlLoader.add_implicit_resolver(
                _resolver_tag,
                _resolver_pattern,
                None if _resolver_initial is None else [_resolver_initial],
            )


@dataclass(frozen=True, slots=True)
class CliOverrides:
    """Strict immutable v0.1 configuration-affecting CLI overrides."""

    project_root: StrPath | None = None
    output: StrPath | None = None

    def __post_init__(self) -> None:
        _require_str_path(self.project_root, field_name="project_root")
        _require_str_path(self.output, field_name="output")


@dataclass(frozen=True, slots=True)
class ConfigLoadResult:
    """One immutable configuration result or a bounded ordered diagnostic set."""

    config: ProjectConfig | None
    diagnostics: tuple[Diagnostic, ...]
    project_root: Path | None
    source_path: Path

    def __post_init__(self) -> None:
        if (self.config is None) == (not self.diagnostics):
            message = "a config load result must contain either a config or diagnostics"
            raise ValueError(message)
        if self.config is not None and self.project_root is None:
            message = "a successful config load result requires a project root"
            raise ValueError(message)

    @property
    def ok(self) -> bool:
        """Return whether loading completed without user-facing diagnostics."""
        return self.config is not None


@dataclass(frozen=True, slots=True)
class _ParsedDocument:
    document: JsonDocument
    source_locations: dict[ConfigFieldPath, tuple[int, int]]


@dataclass(frozen=True, slots=True)
class _ContainedPath:
    normalized: str
    candidate: Path


@dataclass(slots=True)
class _YamlEventFrame:
    kind: str
    path: ConfigFieldPath
    expecting_key: bool = False
    pending_key: str = _INVALID_EVENT_KEY
    next_index: int = 0


class _WindowsReparsePointError(OSError):
    pass


class _WindowsWrongKindError(OSError):
    pass


class _WindowsPathValidationError(Exception):
    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _PinnedWindowsPath:
    expected: Path
    handle: int
    directory: bool
    volume_serial: int
    file_index: int
    parent_key: str | None
    leaf_name: str | None


@dataclass(frozen=True, slots=True)
class _MissingWindowsPath:
    expected: Path
    parent_key: str
    leaf_name: str
    directory: bool


@dataclass(slots=True)
class _WindowsMetadataSession:
    root: Path
    root_volume_serial: int
    root_ancestors: tuple[_PinnedWindowsPath, ...]
    pins: dict[str, _PinnedWindowsPath]
    missing: dict[str, _MissingWindowsPath]

    @classmethod
    def open(cls, root: Path) -> _WindowsMetadataSession:
        expected = _absolute_windows_path(root)
        root_pin, ancestors, volume_serial = _windows_open_directory_chain(expected)
        return cls(
            root=expected,
            root_volume_serial=volume_serial,
            root_ancestors=ancestors,
            pins={_windows_path_key(expected): root_pin},
            missing={},
        )

    def validate_relative(
        self,
        parts: tuple[str, ...],
        *,
        expected_kind: str,
        allow_missing_final: bool,
    ) -> Path:
        if not parts:
            if expected_kind != "directory":
                raise _WindowsPathValidationError("CFG_PATH_NOT_REGULAR_FILE")
            self._require_pin_stable(self.pins[_windows_path_key(self.root)])
            return self.root

        current = self.root
        parent_key = _windows_path_key(self.root)
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            directory = not final or expected_kind == "directory"
            expected = current / part
            key = _windows_path_key(expected)
            existing = self.pins.get(key)
            if existing is not None:
                if existing.directory != directory:
                    if not final:
                        code = "CFG_PATH_PARENT_NOT_DIRECTORY"
                    else:
                        code = (
                            "CFG_PATH_NOT_DIRECTORY" if directory else "CFG_PATH_NOT_REGULAR_FILE"
                        )
                    raise _WindowsPathValidationError(code)
                self._require_pin_stable(existing)
                current = existing.expected
                parent_key = key
                continue

            parent = self._pin_for_key(parent_key)
            self._require_pin_stable(parent)
            try:
                handle = _windows_open_relative_path(
                    parent.handle,
                    part,
                    directory=directory,
                )
            except FileNotFoundError:
                if allow_missing_final and final:
                    self._require_pin_stable(parent)
                    self.missing[key] = _MissingWindowsPath(
                        expected=expected,
                        parent_key=parent_key,
                        leaf_name=part,
                        directory=directory,
                    )
                    self._require_pin_stable(parent)
                    return expected
                raise _WindowsPathValidationError("CFG_PATH_MISSING") from None
            except _WindowsReparsePointError:
                raise _WindowsPathValidationError("CFG_PATH_SYMLINK") from None
            except _WindowsWrongKindError:
                code = (
                    "CFG_PATH_NOT_DIRECTORY"
                    if directory and final
                    else ("CFG_PATH_NOT_REGULAR_FILE" if final else "CFG_PATH_PARENT_NOT_DIRECTORY")
                )
                raise _WindowsPathValidationError(code) from None
            except OSError:
                raise _WindowsPathValidationError("CFG_PATH_METADATA_ERROR") from None

            try:
                pin = self._capture_pin(
                    expected=expected,
                    handle=handle,
                    directory=directory,
                    parent_key=parent_key,
                    leaf_name=part,
                )
                self._require_pin_stable(parent)
                self._require_pin_stable(pin)
            except BaseException:
                _windows_close_handle(handle)
                raise
            self.pins[key] = pin
            current = pin.expected
            parent_key = key
        return current

    def revalidate(self) -> bool:
        try:
            root_pin = self.pins[_windows_path_key(self.root)]
            root_chain = (*self.root_ancestors, root_pin)
            for index, pin in enumerate(root_chain):
                contained = index == len(root_chain) - 1
                self._require_pin_stable(pin, contained=contained)
                if index == 0:
                    continue
                parent = root_chain[index - 1]
                if pin.leaf_name is None:
                    return False
                probe = _windows_open_relative_path(
                    parent.handle,
                    pin.leaf_name,
                    directory=True,
                )
                try:
                    if not self._probe_matches_pin(probe, pin, contained=contained):
                        return False
                finally:
                    _windows_close_handle(probe)
                self._require_pin_stable(parent, contained=False)

            root_key = _windows_path_key(self.root)
            for key, pin in tuple(self.pins.items()):
                if key == root_key:
                    continue
                if pin.parent_key is None or pin.leaf_name is None:
                    return False
                parent = self._pin_for_key(pin.parent_key)
                self._require_pin_stable(parent)
                probe = _windows_open_relative_path(
                    parent.handle,
                    pin.leaf_name,
                    directory=pin.directory,
                )
                try:
                    if not self._probe_matches_pin(probe, pin):
                        return False
                finally:
                    _windows_close_handle(probe)
                self._require_pin_stable(parent)

            for missing in tuple(self.missing.values()):
                parent = self._pin_for_key(missing.parent_key)
                self._require_pin_stable(parent)
                try:
                    unexpected = _windows_open_relative_path(
                        parent.handle,
                        missing.leaf_name,
                        directory=missing.directory,
                    )
                except FileNotFoundError:
                    pass
                except OSError:
                    return False
                else:
                    _windows_close_handle(unexpected)
                    return False
                self._require_pin_stable(parent)
        except (OSError, _WindowsPathValidationError):
            return False
        return True

    def close(self) -> None:
        closed: set[int] = set()
        all_pins = (*tuple(self.pins.values()), *self.root_ancestors)
        for pin in reversed(all_pins):
            if pin.handle not in closed:
                _windows_close_handle(pin.handle)
                closed.add(pin.handle)
        self.pins.clear()
        self.missing.clear()
        self.root_ancestors = ()

    def _capture_pin(
        self,
        *,
        expected: Path,
        handle: int,
        directory: bool,
        parent_key: str,
        leaf_name: str,
    ) -> _PinnedWindowsPath:
        actual = _windows_final_path(handle)
        volume_serial, file_index = _windows_file_identity(handle)
        if (
            volume_serial != self.root_volume_serial
            or not _same_windows_path(actual, expected)
            or not _windows_path_is_within(actual, self.root)
        ):
            raise _WindowsReparsePointError
        return _PinnedWindowsPath(
            expected=expected,
            handle=handle,
            directory=directory,
            volume_serial=volume_serial,
            file_index=file_index,
            parent_key=parent_key,
            leaf_name=leaf_name,
        )

    def _pin_for_key(self, key: str) -> _PinnedWindowsPath:
        pin = self.pins.get(key)
        if pin is not None:
            return pin
        for ancestor in self.root_ancestors:
            if _windows_path_key(ancestor.expected) == key:
                return ancestor
        raise _WindowsPathValidationError("CFG_PATH_METADATA_ERROR")

    def _require_pin_stable(
        self,
        pin: _PinnedWindowsPath,
        *,
        contained: bool = True,
    ) -> None:
        if not self._probe_matches_pin(pin.handle, pin, contained=contained):
            raise _WindowsPathValidationError("CFG_PATH_SYMLINK")

    def _probe_matches_pin(
        self,
        handle: int,
        pin: _PinnedWindowsPath,
        *,
        contained: bool = True,
    ) -> bool:
        try:
            actual = _windows_final_path(handle)
            volume_serial, file_index = _windows_file_identity(handle)
            return (
                volume_serial == pin.volume_serial == self.root_volume_serial
                and file_index == pin.file_index
                and _same_windows_path(actual, pin.expected)
                and (not contained or _windows_path_is_within(actual, self.root))
                and _windows_handle_matches_kind(handle, directory=pin.directory)
            )
        except OSError:
            return False


@dataclass(frozen=True, slots=True)
class _ProjectRootSelection:
    path: Path
    windows_session: _WindowsMetadataSession | None = None

    def close(self) -> None:
        if self.windows_session is not None:
            self.windows_session.close()


def load_project_config(
    path: StrPath,
    *,
    overrides: CliOverrides | Mapping[str, object] | None = None,
) -> ConfigLoadResult:
    """Load one project configuration without network or process side effects."""
    requested_path = Path(path)
    if _is_unc_path(requested_path):
        return _failure(
            requested_path,
            configuration_diagnostic(
                code="CFG_FILE_UNREADABLE",
                message="Configuration file must be local.",
                field_path="$",
                corrective_action="Provide the path to a local regular configuration file.",
                source_path=requested_path,
            ),
        )
    if os.name == "nt":
        source_path = _absolute_windows_path(requested_path)
    else:
        try:
            source_path = requested_path.resolve(strict=True)
        except (OSError, RuntimeError):
            return _failure(
                requested_path,
                configuration_diagnostic(
                    code="CFG_FILE_UNREADABLE",
                    message="Configuration file cannot be opened.",
                    field_path="$",
                    corrective_action="Provide the path to a readable regular configuration file.",
                    source_path=requested_path,
                ),
            )

    encoded, read_error = _read_bounded(source_path)
    if read_error is not None:
        return _failure(source_path, read_error)

    parsed, parse_diagnostics = _parse_yaml(encoded, source_path=source_path)
    if parse_diagnostics:
        return _failure(source_path, *parse_diagnostics)
    if parsed is None:
        message = "a successful parse must return a document"
        raise AssertionError(message)

    preflight_error = preflight_config(
        parsed.document,
        encoded_byte_length=len(encoded),
    )
    if preflight_error is not None:
        location = parsed.source_locations.get(
            ("schema_version",),
            parsed.source_locations.get((), (1, 1)),
        )
        return _failure(
            source_path,
            _with_source(preflight_error, source_path, location=location),
        )

    cli_overrides, override_diagnostics = _coerce_overrides(overrides)
    if override_diagnostics:
        return _failure(source_path, *override_diagnostics)
    if cli_overrides is None:
        message = "valid CLI override input must produce an override value"
        raise AssertionError(message)

    normalized_output, output_error = _normalize_output_override(cli_overrides.output)
    if output_error is not None:
        return _failure(source_path, output_error)

    document = cast("dict[str, JsonDocument]", parsed.document)
    if normalized_output is not None:
        project = document.get("project")
        if isinstance(project, dict):
            project["artifact_directory"] = normalized_output

    try:
        config = ProjectConfig.model_validate(document)
    except ValidationError as error:
        return _failure(
            source_path,
            *validation_diagnostics(
                error,
                source_path=source_path,
                source_locations=parsed.source_locations,
            ),
        )

    root_selection, root_error = _select_project_root(
        source_path=source_path,
        override=cli_overrides.project_root,
    )
    if root_error is not None:
        return _failure(source_path, root_error)
    if root_selection is None:
        message = "valid project-root selection must produce a path"
        raise AssertionError(message)
    try:
        wire = config.to_wire()
        path_diagnostics = _normalize_config_paths(
            wire,
            project_root=root_selection.path,
            source_path=source_path,
            source_locations=parsed.source_locations,
            output_is_cli=normalized_output is not None,
            windows_session=root_selection.windows_session,
        )
        if path_diagnostics:
            return _failure(source_path, *path_diagnostics)

        try:
            normalized_config = ProjectConfig.model_validate(wire)
        except ValidationError as error:
            return _failure(
                source_path,
                *validation_diagnostics(
                    error,
                    source_path=source_path,
                    source_locations=parsed.source_locations,
                ),
            )

        if (
            root_selection.windows_session is not None
            and not root_selection.windows_session.revalidate()
        ):
            return _failure(source_path, _windows_path_race_diagnostic(source_path))
        return ConfigLoadResult(
            config=normalized_config,
            diagnostics=(),
            project_root=root_selection.path,
            source_path=source_path,
        )
    finally:
        root_selection.close()


def _read_bounded(path: Path) -> tuple[bytes, Diagnostic | None]:
    if os.name == "nt":
        return _read_bounded_windows(path)
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            return b"", configuration_diagnostic(
                code="CFG_FILE_NOT_REGULAR",
                message="Configuration source must be a regular file.",
                field_path="$",
                corrective_action="Provide the path to a readable regular configuration file.",
                source_path=path,
            )
        with path.open("rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return b"", configuration_diagnostic(
                    code="CFG_FILE_NOT_REGULAR",
                    message="Configuration source must be a regular file.",
                    field_path="$",
                    corrective_action="Provide the path to a readable regular configuration file.",
                    source_path=path,
                )
            encoded = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        return b"", configuration_diagnostic(
            code="CFG_FILE_UNREADABLE",
            message="Configuration file cannot be read.",
            field_path="$",
            corrective_action="Provide a readable regular configuration file.",
            source_path=path,
        )
    if len(encoded) > MAX_CONFIG_BYTES:
        return b"", configuration_diagnostic(
            code="CFG_RESOURCE_LIMIT",
            message="Configuration exceeds a resource limit.",
            field_path="$",
            corrective_action="Reduce the configuration size or structural complexity.",
            source_path=path,
            safe_details={"limit": "MAX_CONFIG_BYTES", "maximum": MAX_CONFIG_BYTES},
            category=ErrorCategory.RESOURCE_LIMIT,
        )
    return encoded, None


def _read_bounded_windows(path: Path) -> tuple[bytes, Diagnostic | None]:
    import msvcrt

    parent_session: _WindowsMetadataSession | None = None
    handle: int | None = None
    descriptor = -1
    try:
        expected = _absolute_windows_path(path)
        parent_session = _WindowsMetadataSession.open(expected.parent)
        parent_key = _windows_path_key(parent_session.root)
        parent = parent_session.pins[parent_key]
        if not _windows_pin_matches(
            parent.handle,
            parent,
            volume_serial=parent_session.root_volume_serial,
            containment_root=parent_session.root,
        ):
            raise _WindowsReparsePointError
        handle = _windows_open_relative_path(
            parent.handle,
            expected.name,
            directory=False,
            read_content=True,
        )
        actual = _windows_final_path(handle)
        volume_serial, file_index = _windows_file_identity(handle)
        if (
            volume_serial != parent_session.root_volume_serial
            or not _same_windows_path(actual, expected)
            or not _windows_path_is_within(actual, parent_session.root)
        ):
            raise _WindowsReparsePointError
        source_pin = _PinnedWindowsPath(
            expected=expected,
            handle=handle,
            directory=False,
            volume_serial=volume_serial,
            file_index=file_index,
            parent_key=parent_key,
            leaf_name=expected.name,
        )
        if not _windows_pin_matches(
            parent.handle,
            parent,
            volume_serial=parent_session.root_volume_serial,
            containment_root=parent_session.root,
        ):
            raise _WindowsReparsePointError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        descriptor = msvcrt.open_osfhandle(handle, flags)
        handle = None
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _WindowsWrongKindError
        encoded = _read_descriptor_bounded(descriptor)
        source_handle = int(msvcrt.get_osfhandle(descriptor))
        if (
            not _windows_pin_matches(
                source_handle,
                source_pin,
                volume_serial=parent_session.root_volume_serial,
                containment_root=parent_session.root,
            )
            or not parent_session.revalidate()
        ):
            raise _WindowsReparsePointError
    except _WindowsWrongKindError:
        return b"", configuration_diagnostic(
            code="CFG_FILE_NOT_REGULAR",
            message="Configuration source must be a regular file.",
            field_path="$",
            corrective_action="Provide the path to a readable regular configuration file.",
            source_path=path,
        )
    except OSError:
        return b"", configuration_diagnostic(
            code="CFG_FILE_UNREADABLE",
            message="Configuration file cannot be read.",
            field_path="$",
            corrective_action="Provide a readable regular configuration file.",
            source_path=path,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if handle is not None:
            _windows_close_handle(handle)
        if parent_session is not None:
            parent_session.close()
    if len(encoded) > MAX_CONFIG_BYTES:
        return b"", configuration_diagnostic(
            code="CFG_RESOURCE_LIMIT",
            message="Configuration exceeds a resource limit.",
            field_path="$",
            corrective_action="Reduce the configuration size or structural complexity.",
            source_path=path,
            safe_details={"limit": "MAX_CONFIG_BYTES", "maximum": MAX_CONFIG_BYTES},
            category=ErrorCategory.RESOURCE_LIMIT,
        )
    return encoded, None


def _read_descriptor_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_CONFIG_BYTES:
        chunk = os.read(descriptor, min(65_536, MAX_CONFIG_BYTES - total + 1))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _parse_yaml(
    encoded: bytes,
    *,
    source_path: Path,
) -> tuple[_ParsedDocument | None, tuple[Diagnostic, ...]]:
    try:
        text = encoded.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, (
            configuration_diagnostic(
                code="CFG_YAML_ENCODING",
                message="Configuration must use UTF-8 encoding.",
                field_path="$",
                corrective_action="Encode the configuration as UTF-8.",
                source_path=source_path,
            ),
        )

    scan_error = _scan_yaml(text, source_path=source_path)
    if scan_error is not None:
        return None, (scan_error,)
    try:
        root = yaml.compose(text, Loader=_JsonYamlLoader)
    except yaml.YAMLError as error:
        return None, (
            _yaml_diagnostic(
                code="CFG_YAML_SYNTAX",
                message="Configuration is not valid YAML.",
                corrective_action="Correct the YAML syntax and validate again.",
                source_path=source_path,
                mark=_yaml_error_mark(error),
            ),
        )
    if root is None:
        return _ParsedDocument(document=None, source_locations={(): (1, 1)}), ()

    structural_diagnostics = _validate_yaml_nodes(root, source_path=source_path)
    if structural_diagnostics:
        return None, structural_diagnostics
    document, source_locations = _construct_json_document(root)
    return _ParsedDocument(document=document, source_locations=source_locations), ()


def _scan_yaml(text: str, *, source_path: Path) -> Diagnostic | None:
    """Reject unsafe or oversized YAML while retaining only bounded parser state."""
    frames: list[_YamlEventFrame] = []
    node_count = 0
    try:
        for event in yaml.parse(text, Loader=_JsonYamlLoader):
            if isinstance(event, DocumentStartEvent):
                if event.version is not None and event.version != _YAML_VERSION:
                    return _yaml_diagnostic(
                        code="CFG_YAML_VERSION",
                        message="Configuration declares an unsupported YAML version.",
                        corrective_action="Use YAML 1.2 or omit the YAML version directive.",
                        source_path=source_path,
                        mark=event.start_mark,
                    )
                if event.tags:
                    return _yaml_diagnostic(
                        code="CFG_YAML_TAG",
                        message="Custom YAML tag directives are not supported.",
                        corrective_action=(
                            "Remove the tag directive and use JSON-compatible values."
                        ),
                        source_path=source_path,
                        mark=event.start_mark,
                    )
                continue
            if isinstance(event, AliasEvent):
                return _yaml_diagnostic(
                    code="CFG_YAML_ALIAS",
                    message="YAML aliases are not supported.",
                    corrective_action="Replace the alias with an explicit JSON-compatible value.",
                    source_path=source_path,
                    mark=event.start_mark,
                )
            if isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                if frames:
                    frames.pop()
                continue
            if not isinstance(event, (MappingStartEvent, SequenceStartEvent, ScalarEvent)):
                continue

            node_count += 1
            if node_count > MAX_CONFIG_NODES:
                return _resource_diagnostic_at_mark(
                    source_path=source_path,
                    mark=event.start_mark,
                    limit="MAX_CONFIG_NODES",
                    maximum=MAX_CONFIG_NODES,
                )
            depth = len(frames) + 1
            if depth > MAX_CONFIG_DEPTH:
                return _resource_diagnostic_at_mark(
                    source_path=source_path,
                    mark=event.start_mark,
                    limit="MAX_CONFIG_DEPTH",
                    maximum=MAX_CONFIG_DEPTH,
                )

            path, is_mapping_key = _consume_event_node(frames, event)
            anchor = getattr(event, "anchor", None)
            if anchor is not None:
                return _yaml_diagnostic(
                    code="CFG_YAML_ANCHOR",
                    message="YAML anchors are not supported.",
                    corrective_action="Remove the anchor and write the value explicitly.",
                    source_path=source_path,
                    mark=event.start_mark,
                    field_path=format_field_path(path),
                )
            if is_mapping_key and isinstance(event, ScalarEvent) and event.value == "<<":
                return _yaml_diagnostic(
                    code="CFG_YAML_MERGE_KEY",
                    message="YAML merge keys are not supported.",
                    corrective_action="Write each configuration field explicitly.",
                    source_path=source_path,
                    mark=event.start_mark,
                    field_path=format_field_path(path),
                )
            tag_error = _event_tag_diagnostic(event, path=path, source_path=source_path)
            if tag_error is not None:
                return tag_error

            if isinstance(event, MappingStartEvent):
                frames.append(_YamlEventFrame(kind="mapping", path=path, expecting_key=True))
            elif isinstance(event, SequenceStartEvent):
                frames.append(_YamlEventFrame(kind="sequence", path=path))
    except yaml.YAMLError as error:
        return _yaml_diagnostic(
            code="CFG_YAML_SYNTAX",
            message="Configuration is not valid YAML.",
            corrective_action="Correct the YAML syntax and validate again.",
            source_path=source_path,
            mark=_yaml_error_mark(error),
        )
    return None


def _consume_event_node(
    frames: list[_YamlEventFrame],
    event: MappingStartEvent | SequenceStartEvent | ScalarEvent,
) -> tuple[ConfigFieldPath, bool]:
    if not frames:
        return (), False
    parent = frames[-1]
    if parent.kind == "sequence":
        path = (*parent.path, parent.next_index)
        parent.next_index += 1
        return path, False
    if parent.expecting_key:
        key = _event_key(event)
        parent.pending_key = key
        parent.expecting_key = False
        return (*parent.path, key), True
    path = (*parent.path, parent.pending_key)
    parent.pending_key = _INVALID_EVENT_KEY
    parent.expecting_key = True
    return path, False


def _event_key(event: MappingStartEvent | SequenceStartEvent | ScalarEvent) -> str:
    if not isinstance(event, ScalarEvent):
        return _INVALID_EVENT_KEY
    if _resolved_scalar_event_tag(event) != _YAML_STRING_TAG:
        return _INVALID_EVENT_KEY
    if len(event.value) > _MAX_EVENT_PATH_PART_LENGTH or _contains_control(event.value):
        return _INVALID_EVENT_KEY
    return event.value


def _event_tag_diagnostic(
    event: MappingStartEvent | SequenceStartEvent | ScalarEvent,
    *,
    path: ConfigFieldPath,
    source_path: Path,
) -> Diagnostic | None:
    field_path = format_field_path(path)
    if isinstance(event, MappingStartEvent):
        if event.tag not in {None, _YAML_MAP_TAG}:
            return _unsupported_event_tag(
                source_path=source_path,
                mark=event.start_mark,
                field_path=field_path,
            )
        return None
    if isinstance(event, SequenceStartEvent):
        if event.tag not in {None, _YAML_SEQUENCE_TAG}:
            return _unsupported_event_tag(
                source_path=source_path,
                mark=event.start_mark,
                field_path=field_path,
            )
        return None

    tag = _resolved_scalar_event_tag(event)
    if tag == _YAML_FLOAT_TAG:
        return _yaml_diagnostic(
            code="CFG_YAML_FLOAT",
            message="Floating-point YAML values are not supported.",
            corrective_action="Use an integer or a quoted exact decimal string.",
            source_path=source_path,
            mark=event.start_mark,
            field_path=field_path,
        )
    if tag == _YAML_TIMESTAMP_TAG:
        return _yaml_diagnostic(
            code="CFG_YAML_TIMESTAMP",
            message="Timestamp YAML values are not supported.",
            corrective_action="Quote the timestamp so it remains a string.",
            source_path=source_path,
            mark=event.start_mark,
            field_path=field_path,
        )
    if tag not in _YAML_ALLOWED_SCALAR_TAGS:
        return _unsupported_event_tag(
            source_path=source_path,
            mark=event.start_mark,
            field_path=field_path,
        )
    return _scalar_lexical_diagnostic_values(
        tag,
        event.value,
        source_path=source_path,
        mark=event.start_mark,
        field_path=field_path,
    )


def _resolved_scalar_event_tag(event: ScalarEvent) -> str:
    if event.tag is not None:
        return event.tag
    if event.implicit[0]:
        initial = "" if not event.value else event.value[0]
        resolvers = _JsonYamlLoader.yaml_implicit_resolvers.get(initial, [])
        wildcard_resolvers = _JsonYamlLoader.yaml_implicit_resolvers.get(None, [])
        for tag, pattern in (*resolvers, *wildcard_resolvers):
            if pattern.match(event.value):
                return tag
    return _YAML_STRING_TAG


def _unsupported_event_tag(
    *,
    source_path: Path,
    mark: Mark,
    field_path: str,
) -> Diagnostic:
    return _yaml_diagnostic(
        code="CFG_YAML_TAG",
        message="Configuration contains an unsupported YAML tag.",
        corrective_action="Remove the tag and use a JSON-compatible value.",
        source_path=source_path,
        mark=mark,
        field_path=field_path,
    )


def _validate_yaml_nodes(
    root: Node,
    *,
    source_path: Path,
) -> tuple[Diagnostic, ...]:
    diagnostics: list[Diagnostic] = []
    stack: list[tuple[Node, ConfigFieldPath, int]] = [(root, (), 1)]
    node_count = 0
    while stack:
        node, path, depth = stack.pop()
        node_count += 1
        if node_count > MAX_CONFIG_NODES:
            return (
                _resource_diagnostic(
                    source_path=source_path,
                    node=node,
                    limit="MAX_CONFIG_NODES",
                    maximum=MAX_CONFIG_NODES,
                ),
            )
        if depth > MAX_CONFIG_DEPTH:
            return (
                _resource_diagnostic(
                    source_path=source_path,
                    node=node,
                    limit="MAX_CONFIG_DEPTH",
                    maximum=MAX_CONFIG_DEPTH,
                ),
            )
        tag_error = _node_tag_diagnostic(node, path=path, source_path=source_path)
        if tag_error is not None and len(diagnostics) < MAX_CONFIG_DIAGNOSTICS:
            diagnostics.append(tag_error)
        if isinstance(node, MappingNode):
            seen: set[str] = set()
            children: list[tuple[Node, ConfigFieldPath, int]] = []
            for key_node, value_node in node.value:
                if not isinstance(key_node, ScalarNode) or key_node.tag != _YAML_STRING_TAG:
                    if len(diagnostics) < MAX_CONFIG_DIAGNOSTICS:
                        diagnostics.append(
                            _yaml_diagnostic(
                                code="CFG_YAML_NON_STRING_KEY",
                                message="Configuration mapping keys must be strings.",
                                corrective_action="Replace the key with a JSON-compatible string.",
                                source_path=source_path,
                                mark=key_node.start_mark,
                                field_path=format_field_path(path),
                            )
                        )
                    children.append((value_node, path, depth + 1))
                    continue
                key = key_node.value
                key_path = (*path, key)
                if key == "<<":
                    if len(diagnostics) < MAX_CONFIG_DIAGNOSTICS:
                        diagnostics.append(
                            _yaml_diagnostic(
                                code="CFG_YAML_MERGE_KEY",
                                message="YAML merge keys are not supported.",
                                corrective_action="Write each configuration field explicitly.",
                                source_path=source_path,
                                mark=key_node.start_mark,
                                field_path=format_field_path(key_path),
                            )
                        )
                    children.append((value_node, key_path, depth + 1))
                    continue
                if key in seen:
                    if len(diagnostics) < MAX_CONFIG_DIAGNOSTICS:
                        diagnostics.append(
                            _yaml_diagnostic(
                                code="CFG_YAML_DUPLICATE_KEY",
                                message="Configuration mapping keys must be unique.",
                                corrective_action="Remove the duplicate key.",
                                source_path=source_path,
                                mark=key_node.start_mark,
                                field_path=format_field_path(key_path),
                            )
                        )
                    children.append((value_node, key_path, depth + 1))
                    continue
                seen.add(key)
                children.append((value_node, key_path, depth + 1))
            stack.extend(reversed(children))
        elif isinstance(node, SequenceNode):
            stack.extend(
                (child, (*path, index), depth + 1)
                for index, child in reversed(tuple(enumerate(node.value)))
            )
    return tuple(diagnostics)


def _node_tag_diagnostic(
    node: Node,
    *,
    path: ConfigFieldPath,
    source_path: Path,
) -> Diagnostic | None:
    field_path = format_field_path(path)
    if node.tag == _YAML_FLOAT_TAG:
        return _yaml_diagnostic(
            code="CFG_YAML_FLOAT",
            message="Floating-point YAML values are not supported.",
            corrective_action="Use an integer or a quoted exact decimal string.",
            source_path=source_path,
            mark=node.start_mark,
            field_path=field_path,
        )
    if node.tag == _YAML_TIMESTAMP_TAG:
        return _yaml_diagnostic(
            code="CFG_YAML_TIMESTAMP",
            message="Timestamp YAML values are not supported.",
            corrective_action="Quote the timestamp so it remains a string.",
            source_path=source_path,
            mark=node.start_mark,
            field_path=field_path,
        )
    if node.tag not in _YAML_ALLOWED_TAGS:
        return _yaml_diagnostic(
            code="CFG_YAML_TAG",
            message="Configuration contains an unsupported YAML tag.",
            corrective_action="Remove the tag and use a JSON-compatible value.",
            source_path=source_path,
            mark=node.start_mark,
            field_path=field_path,
        )
    if isinstance(node, MappingNode) and node.tag != _YAML_MAP_TAG:
        return _yaml_diagnostic(
            code="CFG_YAML_TAG",
            message="Configuration contains an unsupported YAML tag.",
            corrective_action="Use an ordinary YAML mapping.",
            source_path=source_path,
            mark=node.start_mark,
            field_path=field_path,
        )
    if isinstance(node, SequenceNode) and node.tag != _YAML_SEQUENCE_TAG:
        return _yaml_diagnostic(
            code="CFG_YAML_TAG",
            message="Configuration contains an unsupported YAML tag.",
            corrective_action="Use an ordinary YAML sequence.",
            source_path=source_path,
            mark=node.start_mark,
            field_path=field_path,
        )
    if isinstance(node, ScalarNode) and node.tag not in _YAML_ALLOWED_SCALAR_TAGS:
        return _yaml_diagnostic(
            code="CFG_YAML_TAG",
            message="Configuration contains an unsupported YAML scalar.",
            corrective_action="Use a null, boolean, integer, or string value.",
            source_path=source_path,
            mark=node.start_mark,
            field_path=field_path,
        )
    if isinstance(node, ScalarNode):
        scalar_error = _scalar_lexical_diagnostic(
            node,
            source_path=source_path,
            field_path=field_path,
        )
        if scalar_error is not None:
            return scalar_error
    return None


def _scalar_lexical_diagnostic(
    node: ScalarNode,
    *,
    source_path: Path,
    field_path: str,
) -> Diagnostic | None:
    return _scalar_lexical_diagnostic_values(
        node.tag,
        node.value,
        source_path=source_path,
        mark=node.start_mark,
        field_path=field_path,
    )


def _scalar_lexical_diagnostic_values(
    tag: str,
    value: str,
    *,
    source_path: Path,
    mark: Mark,
    field_path: str,
) -> Diagnostic | None:
    if tag == _YAML_INTEGER_TAG and len(value) > _MAX_INTEGER_LEXEME_LENGTH:
        return _yaml_diagnostic(
            code="CFG_YAML_INTEGER_RANGE",
            message="YAML integer is outside the supported configuration range.",
            corrective_action="Use an integer accepted by the schema version 1 field.",
            source_path=source_path,
            mark=mark,
            field_path=field_path,
        )
    patterns = {
        _YAML_NULL_TAG: _NULL_PATTERN,
        _YAML_BOOLEAN_TAG: _BOOLEAN_PATTERN,
        _YAML_INTEGER_TAG: _INTEGER_PATTERN,
    }
    pattern = patterns.get(tag)
    if pattern is None or pattern.fullmatch(value) is not None:
        return None
    return _yaml_diagnostic(
        code="CFG_YAML_SCALAR",
        message="Explicit YAML scalar tag does not match its value.",
        corrective_action="Remove the tag or provide a valid JSON-compatible scalar.",
        source_path=source_path,
        mark=mark,
        field_path=field_path,
    )


def _construct_json_document(
    root: Node,
) -> tuple[JsonDocument, dict[ConfigFieldPath, tuple[int, int]]]:
    locations: dict[ConfigFieldPath, tuple[int, int]] = {}

    def construct(node: Node, path: ConfigFieldPath) -> JsonDocument:
        locations[path] = (node.start_mark.line + 1, node.start_mark.column + 1)
        if isinstance(node, MappingNode):
            result: dict[str, JsonDocument] = {}
            for key_node, value_node in node.value:
                key = cast("ScalarNode", key_node).value
                key_path = (*path, key)
                locations[key_path] = (
                    key_node.start_mark.line + 1,
                    key_node.start_mark.column + 1,
                )
                result[key] = construct(value_node, key_path)
            return result
        if isinstance(node, SequenceNode):
            return [construct(item, (*path, index)) for index, item in enumerate(node.value)]
        scalar = cast("ScalarNode", node)
        if scalar.tag == _YAML_NULL_TAG:
            return None
        if scalar.tag == _YAML_BOOLEAN_TAG:
            return scalar.value.casefold() == "true"
        if scalar.tag == _YAML_INTEGER_TAG:
            return _construct_integer(scalar.value)
        return scalar.value

    return construct(root, ()), locations


def _construct_integer(value: str) -> int:
    sign = -1 if value.startswith("-") else 1
    unsigned = value[1:] if value[:1] in {"+", "-"} else value
    if unsigned.startswith(("0o", "0x")):
        return sign * int(unsigned, 0)
    return sign * int(unsigned, 10)


def _resource_diagnostic(
    *,
    source_path: Path,
    node: Node,
    limit: str,
    maximum: int,
) -> Diagnostic:
    return _resource_diagnostic_at_mark(
        source_path=source_path,
        mark=node.start_mark,
        limit=limit,
        maximum=maximum,
    )


def _resource_diagnostic_at_mark(
    *,
    source_path: Path,
    mark: Mark,
    limit: str,
    maximum: int,
) -> Diagnostic:
    line, column = _bounded_mark_coordinates(mark)
    return configuration_diagnostic(
        code="CFG_RESOURCE_LIMIT",
        message="Configuration exceeds a resource limit.",
        field_path="$",
        corrective_action="Reduce the configuration size or structural complexity.",
        source_path=source_path,
        line=line,
        column=column,
        safe_details={"limit": limit, "maximum": maximum},
        category=ErrorCategory.RESOURCE_LIMIT,
    )


def _yaml_diagnostic(
    *,
    code: str,
    message: str,
    corrective_action: str,
    source_path: Path,
    mark: Mark | None,
    field_path: str = "$",
) -> Diagnostic:
    line, column = _bounded_mark_coordinates(mark)
    return configuration_diagnostic(
        code=code,
        message=message,
        field_path=field_path,
        corrective_action=corrective_action,
        source_path=source_path,
        line=line,
        column=column,
        safe_details={"rule": "YAML_1_2_JSON_MODEL"},
    )


def _bounded_mark_coordinates(mark: Mark | None) -> tuple[int | None, int | None]:
    if mark is None:
        return None, None
    return (
        min(max(mark.line + 1, 1), _MAX_DIAGNOSTIC_COORDINATE),
        min(max(mark.column + 1, 1), _MAX_DIAGNOSTIC_COORDINATE),
    )


def _with_source(
    diagnostic: Diagnostic,
    source_path: Path,
    *,
    location: tuple[int, int],
) -> Diagnostic:
    return diagnostic.model_copy(
        update={
            "location": DiagnosticLocation(
                path=safe_source_label(source_path),
                line=location[0],
                column=location[1],
            )
        }
    )


def _normalize_config_paths(
    wire: dict[str, object],
    *,
    project_root: Path,
    source_path: Path,
    source_locations: Mapping[ConfigFieldPath, tuple[int, int]],
    output_is_cli: bool,
    windows_session: _WindowsMetadataSession | None,
) -> tuple[Diagnostic, ...]:
    diagnostics: list[Diagnostic] = []

    def normalize(
        container: dict[str, object] | list[object],
        key: str | int,
        *,
        field_path: ConfigFieldPath,
        expected_kind: str,
        path_kind: str,
        allow_missing_final: bool = False,
        from_cli: bool = False,
        category: ErrorCategory = ErrorCategory.CONFIGURATION_ERROR,
    ) -> _ContainedPath | None:
        if isinstance(container, list):
            value = container[cast("int", key)]
        else:
            value = container.get(cast("str", key))
        if not isinstance(value, str):
            return None
        contained, code = _contained_metadata_path(
            value,
            project_root=project_root,
            expected_kind=expected_kind,
            allow_missing_final=allow_missing_final,
            windows_session=windows_session,
        )
        if code is not None:
            if len(diagnostics) < MAX_CONFIG_DIAGNOSTICS:
                diagnostics.append(
                    _path_diagnostic(
                        code=code,
                        field_path=("cli", "output") if from_cli else field_path,
                        path_kind=path_kind,
                        source_path=None if from_cli else source_path,
                        source_locations=source_locations,
                        category=category,
                    )
                )
            return None
        if contained is None:
            message = "successful path validation must return a contained path"
            raise AssertionError(message)
        if isinstance(container, list):
            container[cast("int", key)] = contained.normalized
        else:
            container[cast("str", key)] = contained.normalized
        return contained

    project = cast("dict[str, object]", wire["project"])
    secret_root_values = cast("list[object]", project.get("secret_roots", []))
    secret_roots: list[_ContainedPath] = []
    for index in range(len(secret_root_values)):
        root = normalize(
            secret_root_values,
            index,
            field_path=("project", "secret_roots", index),
            expected_kind="directory",
            path_kind="secret_root",
            category=ErrorCategory.SECRET_REFERENCE_ERROR,
        )
        if root is not None:
            secret_roots.append(root)

    normalize(
        project,
        "artifact_directory",
        field_path=("project", "artifact_directory"),
        expected_kind="directory",
        path_kind="artifact_directory",
        allow_missing_final=True,
        from_cli=output_is_cli,
    )

    receiver = cast("dict[str, object]", wire["receiver"])
    if "test_ca_file" in receiver:
        normalize(
            receiver,
            "test_ca_file",
            field_path=("receiver", "test_ca_file"),
            expected_kind="file",
            path_kind="test_ca_file",
        )

    fixtures = cast("list[dict[str, object]]", wire["fixtures"])
    for index, fixture in enumerate(fixtures):
        normalize(
            fixture,
            "path",
            field_path=("fixtures", index, "path"),
            expected_kind="file",
            path_kind="fixture",
        )
        if "schema_path" in fixture:
            normalize(
                fixture,
                "schema_path",
                field_path=("fixtures", index, "schema_path"),
                expected_kind="file",
                path_kind="fixture_schema",
            )

    signers = cast("dict[str, dict[str, object]]", wire["signers"])
    for name, signer in signers.items():
        _normalize_secret_reference(
            cast("dict[str, object]", signer["secret"]),
            field_path=("signers", name, "secret"),
            project_root=project_root,
            secret_roots=secret_roots,
            source_path=source_path,
            source_locations=source_locations,
            diagnostics=diagnostics,
            windows_session=windows_session,
        )

    observers = cast("dict[str, dict[str, object]]", wire["observers"])
    for name, observer in observers.items():
        if observer.get("type") == "command":
            argv = cast("list[object]", observer["argv"])
            if argv and isinstance(argv[0], str) and _is_explicit_path(argv[0]):
                normalize(
                    argv,
                    0,
                    field_path=("observers", name, "argv", 0),
                    expected_kind="file",
                    path_kind="observer_executable",
                )
            if "working_directory" in observer:
                normalize(
                    observer,
                    "working_directory",
                    field_path=("observers", name, "working_directory"),
                    expected_kind="directory",
                    path_kind="observer_working_directory",
                )
        else:
            _normalize_secret_reference(
                cast("dict[str, object]", observer["token"]),
                field_path=("observers", name, "token"),
                project_root=project_root,
                secret_roots=secret_roots,
                source_path=source_path,
                source_locations=source_locations,
                diagnostics=diagnostics,
                windows_session=windows_session,
            )

    lifecycles = cast("dict[str, dict[str, object]]", wire["lifecycles"])
    for name, lifecycle in lifecycles.items():
        normalize(
            lifecycle,
            "working_directory",
            field_path=("lifecycles", name, "working_directory"),
            expected_kind="directory",
            path_kind="lifecycle_working_directory",
        )
        for argv_name in ("stop_argv", "start_argv", "restart_argv"):
            argv = cast("list[object]", lifecycle[argv_name])
            if argv and isinstance(argv[0], str) and _is_explicit_path(argv[0]):
                normalize(
                    argv,
                    0,
                    field_path=("lifecycles", name, argv_name, 0),
                    expected_kind="file",
                    path_kind="lifecycle_executable",
                )

    return tuple(diagnostics)


def _normalize_secret_reference(
    reference: dict[str, object],
    *,
    field_path: ConfigFieldPath,
    project_root: Path,
    secret_roots: list[_ContainedPath],
    source_path: Path,
    source_locations: Mapping[ConfigFieldPath, tuple[int, int]],
    diagnostics: list[Diagnostic],
    windows_session: _WindowsMetadataSession | None,
) -> None:
    value = reference.get("file")
    if not isinstance(value, str):
        return
    file_path = (*field_path, "file")
    contained, code = _contained_metadata_path(
        value,
        project_root=project_root,
        expected_kind="file",
        allow_missing_final=False,
        windows_session=windows_session,
    )
    if code is not None:
        if len(diagnostics) < MAX_CONFIG_DIAGNOSTICS:
            diagnostics.append(
                _path_diagnostic(
                    code=code,
                    field_path=file_path,
                    path_kind="secret_file",
                    source_path=source_path,
                    source_locations=source_locations,
                    category=ErrorCategory.SECRET_REFERENCE_ERROR,
                )
            )
        return
    if contained is None:
        message = "successful secret path validation must return a contained path"
        raise AssertionError(message)
    if not any(_is_relative_to(contained.candidate, root.candidate) for root in secret_roots):
        if len(diagnostics) < MAX_CONFIG_DIAGNOSTICS:
            diagnostics.append(
                _path_diagnostic(
                    code="CFG_SECRET_PATH_OUTSIDE_ROOT",
                    field_path=file_path,
                    path_kind="secret_file",
                    source_path=source_path,
                    source_locations=source_locations,
                    category=ErrorCategory.SECRET_REFERENCE_ERROR,
                )
            )
        return
    reference["file"] = contained.normalized


def _contained_metadata_path(
    value: str,
    *,
    project_root: Path,
    expected_kind: str,
    allow_missing_final: bool,
    windows_session: _WindowsMetadataSession | None,
) -> tuple[_ContainedPath | None, str | None]:
    lexical_error = _path_lexical_error(value)
    if lexical_error is not None:
        return None, lexical_error

    parts = PurePosixPath(value).parts
    normalized = "." if not parts else PurePosixPath(*parts).as_posix()
    candidate = project_root.joinpath(*parts)
    if windows_session is not None:
        try:
            candidate = windows_session.validate_relative(
                parts,
                expected_kind=expected_kind,
                allow_missing_final=allow_missing_final,
            )
        except _WindowsPathValidationError as error:
            return None, error.code
        except _WindowsReparsePointError:
            return None, "CFG_PATH_SYMLINK"
        except OSError:
            return None, "CFG_PATH_METADATA_ERROR"
        return _ContainedPath(normalized=normalized, candidate=candidate), None

    current = project_root
    for index, part in enumerate(parts):
        current = current / part
        is_final = index == len(parts) - 1
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if allow_missing_final and is_final:
                return _ContainedPath(normalized=normalized, candidate=candidate), None
            return None, "CFG_PATH_MISSING"
        except OSError:
            return None, "CFG_PATH_METADATA_ERROR"
        if _is_link_or_reparse(metadata):
            return None, "CFG_PATH_SYMLINK"
        if not is_final and not stat.S_ISDIR(metadata.st_mode):
            return None, "CFG_PATH_PARENT_NOT_DIRECTORY"

    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        if allow_missing_final and parts:
            return _ContainedPath(normalized=normalized, candidate=candidate), None
        return None, "CFG_PATH_MISSING"
    except OSError:
        return None, "CFG_PATH_METADATA_ERROR"
    if _is_link_or_reparse(metadata):
        return None, "CFG_PATH_SYMLINK"
    if expected_kind == "file" and not stat.S_ISREG(metadata.st_mode):
        return None, "CFG_PATH_NOT_REGULAR_FILE"
    if expected_kind == "directory" and not stat.S_ISDIR(metadata.st_mode):
        return None, "CFG_PATH_NOT_DIRECTORY"
    return _ContainedPath(normalized=normalized, candidate=candidate), None


def _path_lexical_error(value: str) -> str | None:
    if not value or len(value) > _MAX_CONFIG_PATH_LENGTH or _contains_control(value):
        return "CFG_PATH_INVALID"
    if value.startswith(("//", "\\\\")):
        return "CFG_PATH_UNC"
    windows_path = PureWindowsPath(value)
    if windows_path.drive:
        return "CFG_PATH_WINDOWS_DRIVE"
    if PurePosixPath(value).is_absolute() or windows_path.is_absolute():
        return "CFG_PATH_ABSOLUTE"
    if "\\" in value:
        return "CFG_PATH_ALTERNATE_SEPARATOR"
    raw_parts = value.split("/")
    if ".." in raw_parts:
        return "CFG_PATH_TRAVERSAL"
    if _URI_SCHEME.match(value) is not None or any(":" in part for part in raw_parts):
        return "CFG_PATH_REMOTE"
    for part in raw_parts:
        if not part or part == ".":
            continue
        if part.endswith((" ", ".")) or _is_windows_device_name(part):
            return "CFG_PATH_DEVICE"
    return None


def _path_diagnostic(
    *,
    code: str,
    field_path: ConfigFieldPath,
    path_kind: str,
    source_path: Path | None,
    source_locations: Mapping[ConfigFieldPath, tuple[int, int]],
    category: ErrorCategory,
) -> Diagnostic:
    line, column = _nearest_location(field_path, source_locations)
    return configuration_diagnostic(
        code=code,
        message="Configuration path failed contained metadata validation.",
        field_path=format_field_path(field_path),
        corrective_action="Use the required real path beneath the selected project root.",
        source_path=source_path,
        line=None if source_path is None else line,
        column=None if source_path is None else column,
        safe_details={"path_kind": path_kind, "rule": "SEC-016"},
        category=category,
    )


def _windows_path_race_diagnostic(source_path: Path) -> Diagnostic:
    return configuration_diagnostic(
        code="CFG_PATH_METADATA_ERROR",
        message="Configuration path identity changed during validation.",
        field_path="$",
        corrective_action="Restore stable real paths beneath the selected project root.",
        source_path=source_path,
        safe_details={"path_kind": "project_metadata", "rule": "SEC-016"},
    )


def _nearest_location(
    path: ConfigFieldPath,
    locations: Mapping[ConfigFieldPath, tuple[int, int]],
) -> tuple[int | None, int | None]:
    candidate = path
    while candidate:
        location = locations.get(candidate)
        if location is not None:
            return location
        candidate = candidate[:-1]
    return locations.get((), (None, None))


def _is_explicit_path(value: str) -> bool:
    return (
        "/" in value
        or "\\" in value
        or value.startswith(".")
        or bool(PureWindowsPath(value).drive)
        or _URI_SCHEME.match(value) is not None
        or _is_windows_device_name(value)
    )


def _is_windows_device_name(part: str) -> bool:
    return _WINDOWS_RESERVED_NAME.fullmatch(part.rstrip(" .")) is not None


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & _WINDOWS_REPARSE_ATTRIBUTE)


def _absolute_windows_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _windows_kernel32() -> Any:
    if os.name != "nt":
        raise OSError
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _windows_open_directory_chain(
    path: Path,
) -> tuple[_PinnedWindowsPath, tuple[_PinnedWindowsPath, ...], int]:
    expected = _absolute_windows_path(path)
    if _is_unc_path(expected):
        raise OSError
    anchor_text = expected.anchor
    if not anchor_text:
        raise OSError
    anchor = Path(anchor_text)
    if _is_unc_path(anchor):
        raise OSError
    try:
        parts = expected.relative_to(anchor).parts
    except ValueError:
        raise OSError from None

    pins: list[_PinnedWindowsPath] = []
    handles: list[int] = []
    try:
        handle = _windows_open_path(anchor, directory=True)
        handles.append(handle)
        actual = _windows_final_path(handle)
        volume_serial, file_index = _windows_file_identity(handle)
        if not _same_windows_path(actual, anchor):
            raise _WindowsReparsePointError
        current = _PinnedWindowsPath(
            expected=anchor,
            handle=handle,
            directory=True,
            volume_serial=volume_serial,
            file_index=file_index,
            parent_key=None,
            leaf_name=None,
        )
        pins.append(current)
        for part in parts:
            if not _windows_pin_matches(
                current.handle,
                current,
                volume_serial=volume_serial,
            ):
                raise _WindowsReparsePointError
            child_expected = current.expected / part
            child_handle = _windows_open_relative_path(
                current.handle,
                part,
                directory=True,
            )
            handles.append(child_handle)
            child_actual = _windows_final_path(child_handle)
            child_volume_serial, child_file_index = _windows_file_identity(child_handle)
            if (
                child_volume_serial != volume_serial
                or not _same_windows_path(child_actual, child_expected)
                or not _windows_pin_matches(
                    current.handle,
                    current,
                    volume_serial=volume_serial,
                )
            ):
                raise _WindowsReparsePointError
            current = _PinnedWindowsPath(
                expected=child_expected,
                handle=child_handle,
                directory=True,
                volume_serial=child_volume_serial,
                file_index=child_file_index,
                parent_key=_windows_path_key(pins[-1].expected),
                leaf_name=part,
            )
            if not _windows_pin_matches(
                current.handle,
                current,
                volume_serial=volume_serial,
            ):
                raise _WindowsReparsePointError
            pins.append(current)
        return pins[-1], tuple(pins[:-1]), volume_serial
    except BaseException:
        for opened_handle in reversed(handles):
            _windows_close_handle(opened_handle)
        raise


def _windows_open_path(
    path: Path,
    *,
    directory: bool,
) -> int:
    expected = _absolute_windows_path(path)
    anchor = Path(expected.anchor)
    if (
        not directory
        or not expected.anchor
        or _is_unc_path(expected)
        or not _same_windows_path(expected, anchor)
    ):
        raise OSError
    kernel32 = _windows_kernel32()
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(anchor),
        (
            _WINDOWS_FILE_LIST_DIRECTORY
            | _WINDOWS_FILE_TRAVERSE
            | _WINDOWS_FILE_READ_ATTRIBUTES
            | _WINDOWS_SYNCHRONIZE
        ),
        (_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE),
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle in {None, _WINDOWS_INVALID_HANDLE}:
        raise ctypes.WinError(ctypes.get_last_error())
    integer_handle = int(handle)
    try:
        attributes = _windows_file_attributes(integer_handle)
        if attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            raise _WindowsReparsePointError
        if attributes & _WINDOWS_FILE_ATTRIBUTE_DEVICE:
            raise _WindowsWrongKindError
        if not _windows_handle_matches_kind(integer_handle, directory=directory):
            raise _WindowsWrongKindError
    except BaseException:
        _windows_close_handle(integer_handle)
        raise
    return integer_handle


def _windows_open_relative_path(
    parent_handle: int,
    name: str,
    *,
    directory: bool,
    read_content: bool = False,
) -> int:
    _require_windows_leaf_name(name)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    nt_create_file = ntdll.NtCreateFile
    nt_create_file.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.POINTER(_WindowsObjectAttributes),
        ctypes.POINTER(_WindowsIoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    nt_create_file.restype = ctypes.c_int32

    name_buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    unicode_name = _WindowsUnicodeString(
        length=encoded_length,
        maximum_length=encoded_length,
        buffer=ctypes.cast(name_buffer, ctypes.c_void_p),
    )
    object_attributes = _WindowsObjectAttributes(
        length=ctypes.sizeof(_WindowsObjectAttributes),
        root_directory=ctypes.c_void_p(parent_handle),
        object_name=ctypes.pointer(unicode_name),
        attributes=_WINDOWS_OBJ_CASE_INSENSITIVE,
        security_descriptor=None,
        security_quality_of_service=None,
    )
    desired_access = _WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE
    if directory:
        desired_access |= _WINDOWS_FILE_LIST_DIRECTORY | _WINDOWS_FILE_TRAVERSE
    elif read_content:
        desired_access |= _WINDOWS_FILE_READ_DATA
    share_access = (
        _WINDOWS_FILE_SHARE_READ
        if read_content
        else (_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE)
    )
    io_status = _WindowsIoStatusBlock()
    handle = ctypes.c_void_p()
    status = int(
        nt_create_file(
            ctypes.byref(handle),
            desired_access,
            ctypes.byref(object_attributes),
            ctypes.byref(io_status),
            None,
            (_WINDOWS_FILE_ATTRIBUTE_DIRECTORY if directory else _WINDOWS_FILE_ATTRIBUTE_NORMAL),
            share_access,
            _WINDOWS_FILE_OPEN,
            (
                (_WINDOWS_FILE_DIRECTORY_FILE if directory else _WINDOWS_FILE_NON_DIRECTORY_FILE)
                | _WINDOWS_FILE_OPEN_REPARSE_POINT
                | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
            ),
            None,
            0,
        )
    )
    if status < 0:
        if handle.value is not None:
            _windows_close_handle(int(handle.value))
        _raise_windows_ntstatus(status)
    if handle.value is None:
        raise OSError
    integer_handle = int(handle.value)
    try:
        attributes = _windows_file_attributes(integer_handle)
        if attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            raise _WindowsReparsePointError
        if attributes & _WINDOWS_FILE_ATTRIBUTE_DEVICE:
            raise _WindowsWrongKindError
        if not _windows_handle_matches_kind(integer_handle, directory=directory):
            raise _WindowsWrongKindError
    except BaseException:
        _windows_close_handle(integer_handle)
        raise
    return integer_handle


def _raise_windows_ntstatus(status: int) -> None:
    normalized = status & 0xFFFFFFFF
    if normalized in {
        _WINDOWS_STATUS_OBJECT_NAME_NOT_FOUND,
        _WINDOWS_STATUS_OBJECT_PATH_NOT_FOUND,
    }:
        raise FileNotFoundError(2, "secure relative Windows path open failed")
    if normalized in {
        _WINDOWS_STATUS_FILE_IS_A_DIRECTORY,
        _WINDOWS_STATUS_NOT_A_DIRECTORY,
    }:
        raise _WindowsWrongKindError
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    translate = ntdll.RtlNtStatusToDosError
    translate.argtypes = [ctypes.c_int32]
    translate.restype = ctypes.c_uint32
    raise OSError(
        int(translate(ctypes.c_int32(status))),
        "secure relative Windows path open failed",
    )


def _require_windows_leaf_name(name: str) -> None:
    if not name or "\x00" in name or "/" in name or "\\" in name or ":" in name:
        raise OSError


def _windows_pin_matches(
    handle: int,
    pin: _PinnedWindowsPath,
    *,
    volume_serial: int,
    containment_root: Path | None = None,
) -> bool:
    try:
        actual = _windows_final_path(handle)
        actual_volume_serial, file_index = _windows_file_identity(handle)
        return (
            actual_volume_serial == pin.volume_serial == volume_serial
            and file_index == pin.file_index
            and _same_windows_path(actual, pin.expected)
            and (containment_root is None or _windows_path_is_within(actual, containment_root))
            and _windows_handle_matches_kind(handle, directory=pin.directory)
        )
    except OSError:
        return False


def _windows_handle_matches_kind(handle: int, *, directory: bool) -> bool:
    attributes = _windows_file_attributes(handle)
    if attributes & (_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT | _WINDOWS_FILE_ATTRIBUTE_DEVICE):
        return False
    if directory:
        return bool(attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY)
    return (
        not attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY
        and _windows_file_type(handle) == _WINDOWS_FILE_TYPE_DISK
    )


def _windows_file_attributes(handle: int) -> int:
    kernel32 = _windows_kernel32()
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    get_information.restype = ctypes.c_int
    information = _WindowsFileAttributeTagInfo()
    succeeded = get_information(
        ctypes.c_void_p(handle),
        _WINDOWS_FILE_ATTRIBUTE_TAG_INFO,
        ctypes.byref(information),
        ctypes.sizeof(information),
    )
    if not succeeded:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(information.file_attributes)


def _windows_file_type(handle: int) -> int:
    kernel32 = _windows_kernel32()
    get_file_type = kernel32.GetFileType
    get_file_type.argtypes = [ctypes.c_void_p]
    get_file_type.restype = ctypes.c_uint32
    return int(get_file_type(ctypes.c_void_p(handle)))


def _windows_final_path(handle: int) -> Path:
    kernel32 = _windows_kernel32()
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    get_final_path.restype = ctypes.c_uint32
    required = int(get_final_path(ctypes.c_void_p(handle), None, 0, 0))
    if required == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = int(
        get_final_path(
            ctypes.c_void_p(handle),
            buffer,
            len(buffer),
            0,
        )
    )
    if written == 0 or written >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _windows_file_identity(handle: int) -> tuple[int, int]:
    kernel32 = _windows_kernel32()
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsByHandleFileInformation),
    ]
    get_information.restype = ctypes.c_int
    information = _WindowsByHandleFileInformation()
    if not get_information(ctypes.c_void_p(handle), ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    file_index = (int(information.file_index_high) << 32) | int(information.file_index_low)
    return int(information.volume_serial_number), file_index


def _windows_close_handle(handle: int) -> None:
    kernel32 = _windows_kernel32()
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    with suppress(Exception):
        close_handle(ctypes.c_void_p(handle))


def _windows_path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _same_windows_path(first: Path, second: Path) -> bool:
    return _windows_path_key(first) == _windows_path_key(second)


def _windows_path_is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate_text = _windows_path_key(candidate)
        root_text = _windows_path_key(root)
        return os.path.commonpath((candidate_text, root_text)) == root_text
    except (OSError, ValueError):
        return False


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _coerce_overrides(
    overrides: object,
) -> tuple[CliOverrides | None, tuple[Diagnostic, ...]]:
    if overrides is None:
        return CliOverrides(), ()
    if isinstance(overrides, CliOverrides):
        return overrides, ()
    if not isinstance(overrides, Mapping):
        return None, (
            configuration_diagnostic(
                code="CFG_CLI_OVERRIDE_INVALID",
                message="CLI overrides must be a mapping.",
                field_path="cli",
                corrective_action="Use only project_root and output CLI overrides.",
                safe_details={"rule": "CFG-006"},
            ),
        )

    allowed = frozenset({"project_root", "output"})
    unknown = tuple(key for key in overrides if not isinstance(key, str) or key not in allowed)
    if unknown:
        return None, tuple(
            configuration_diagnostic(
                code="CFG_CLI_OVERRIDE_UNDECLARED",
                message="CLI override is not declared by the v0.1 contract.",
                field_path=(format_field_path(("cli", key)) if isinstance(key, str) else "cli"),
                corrective_action="Remove the override or use project_root or output.",
                safe_details={"rule": "CFG-006"},
            )
            for key in unknown[:MAX_CONFIG_DIAGNOSTICS]
        )

    project_root = overrides.get("project_root")
    output = overrides.get("output")
    invalid_fields = tuple(
        name
        for name, value in (("project_root", project_root), ("output", output))
        if not _is_str_path(value)
    )
    if invalid_fields:
        return None, tuple(
            configuration_diagnostic(
                code="CFG_CLI_OVERRIDE_INVALID",
                message="CLI path override has an invalid type.",
                field_path=f"cli.{name}",
                corrective_action="Provide a string or filesystem path.",
                safe_details={"rule": "CFG-006"},
            )
            for name in invalid_fields
        )

    return (
        CliOverrides(
            project_root=cast("StrPath | None", project_root),
            output=cast("StrPath | None", output),
        ),
        (),
    )


def _normalize_output_override(
    output: StrPath | None,
) -> tuple[str | None, Diagnostic | None]:
    if output is None:
        return None, None
    raw = os.fspath(output)
    if not isinstance(output, str) and os.name == "nt":
        raw = raw.replace("\\", "/")
    if not raw or len(raw) > _MAX_CONFIG_PATH_LENGTH or _contains_control(raw):
        return None, _output_diagnostic(
            code="CFG_CLI_OUTPUT_INVALID",
            corrective_action="Provide a nonempty bounded project-relative output path.",
        )
    if raw.startswith(("//", "\\\\")):
        return None, _output_diagnostic(
            code="CFG_CLI_OUTPUT_UNC",
            corrective_action="Use a local project-relative output path.",
        )
    windows_path = PureWindowsPath(raw)
    if windows_path.drive:
        return None, _output_diagnostic(
            code="CFG_CLI_OUTPUT_DRIVE",
            corrective_action="Remove the Windows drive prefix.",
        )
    if PurePosixPath(raw).is_absolute() or windows_path.is_absolute():
        return None, _output_diagnostic(
            code="CFG_CLI_OUTPUT_ABSOLUTE",
            corrective_action="Use a project-relative output path.",
        )
    if "\\" in raw:
        return None, _output_diagnostic(
            code="CFG_CLI_OUTPUT_ALTERNATE_SEPARATOR",
            corrective_action="Use forward slashes in the project-relative output path.",
        )
    if ".." in raw.split("/"):
        return None, _output_diagnostic(
            code="CFG_CLI_OUTPUT_TRAVERSAL",
            corrective_action="Remove every parent-directory traversal segment.",
        )
    if _URI_SCHEME.match(raw) is not None or any(":" in part for part in raw.split("/")):
        return None, _output_diagnostic(
            code="CFG_CLI_OUTPUT_INVALID",
            corrective_action="Use a local project-relative output path.",
        )
    normalized = PurePosixPath(raw).as_posix()
    return normalized, None


def _select_project_root(
    *,
    source_path: Path,
    override: StrPath | None,
) -> tuple[_ProjectRootSelection | None, Diagnostic | None]:
    if override is None:
        candidate = source_path.parent
    else:
        raw = os.fspath(override)
        if (
            not raw
            or len(raw) > _MAX_CONFIG_PATH_LENGTH
            or _contains_control(raw)
            or raw.startswith(("//", "\\\\"))
        ):
            return None, _project_root_diagnostic()
        windows_path = PureWindowsPath(raw)
        if _URI_SCHEME.match(raw) is not None and not windows_path.drive:
            return None, _project_root_diagnostic()
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = source_path.parent / candidate

    if os.name == "nt":
        try:
            session = _WindowsMetadataSession.open(candidate)
        except OSError:
            return None, _project_root_diagnostic()
        return _ProjectRootSelection(path=session.root, windows_session=session), None

    try:
        candidate_metadata = candidate.lstat()
        if _is_link_or_reparse(candidate_metadata) or not stat.S_ISDIR(candidate_metadata.st_mode):
            return None, _project_root_diagnostic()
        selected = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, _project_root_diagnostic()
    return _ProjectRootSelection(path=selected), None


def _output_diagnostic(*, code: str, corrective_action: str) -> Diagnostic:
    return configuration_diagnostic(
        code=code,
        message="CLI output path is not safely project-relative.",
        field_path="cli.output",
        corrective_action=corrective_action,
        safe_details={"rule": "SEC-016"},
    )


def _project_root_diagnostic() -> Diagnostic:
    return configuration_diagnostic(
        code="CFG_CLI_PROJECT_ROOT_INVALID",
        message="CLI project root must resolve to a local directory.",
        field_path="cli.project_root",
        corrective_action="Choose an existing local project directory.",
        safe_details={"rule": "CFG-010"},
    )


def _require_str_path(value: object, *, field_name: str) -> None:
    if _is_str_path(value):
        return
    message = f"{field_name} must be a string or filesystem path"
    raise TypeError(message)


def _is_str_path(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, (str, os.PathLike)):
        return False
    try:
        return isinstance(os.fspath(value), str)
    except TypeError:
        return False


def _contains_control(value: str) -> bool:
    return any(
        ord(character) < _CONTROL_CHARACTER_LIMIT or ord(character) == _DELETE_CHARACTER_CODEPOINT
        for character in value
    )


def _failure(source_path: Path, *diagnostics: Diagnostic) -> ConfigLoadResult:
    return ConfigLoadResult(
        config=None,
        diagnostics=tuple(diagnostics),
        project_root=None,
        source_path=source_path,
    )


def _yaml_error_mark(error: yaml.YAMLError) -> Mark | None:
    mark = getattr(error, "problem_mark", None)
    return mark if isinstance(mark, Mark) else None


def _is_unc_path(path: Path) -> bool:
    value = os.fspath(path)
    return value.startswith(("\\\\", "//"))
