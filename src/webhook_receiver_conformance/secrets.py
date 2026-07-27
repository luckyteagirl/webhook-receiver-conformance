"""Opaque secret handles, safe fingerprints, and run-local correlation hashes.

Secret material is deliberately available only inside a caller-supplied callback.
The safe, reportable surface is :class:`SecretMetadata`, which contains the
configured reference and a domain-separated fingerprint but never secret bytes.
"""
# ruff: noqa: ANN401, BLE001, D105, D107, EM101, PLC0415, PLR2004, PTH100, PTH116, TRY300, TRY301

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import secrets as _stdlib_secrets
import stat
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Literal, NoReturn, Protocol, Self, TypeVar

from webhook_receiver_conformance.config.models import (
    EnvironmentSecretRef,
    FileSecretRef,
    GeneratedSecretRef,
    SecretRef,
)
from webhook_receiver_conformance.errors import (
    Diagnostic,
    ErrorCategory,
    ResultCategory,
)
from webhook_receiver_conformance.types import DiagnosticCode, Sha256Digest

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from types import TracebackType
    from typing import Any

SECRET_FINGERPRINT_DOMAIN_SEPARATOR = b"secret-fingerprint-v1\x00"
CORRELATION_DOMAIN_SEPARATOR = b"value-correlation-v1\x00"
GENERATED_HMAC_KEY_BYTES = 32
MAX_SECRET_BYTES = 1_048_576
FINGERPRINT_ALGORITHM = "sha256"
CORRELATION_ALGORITHM = "hmac-sha256"

_T = TypeVar("_T")
type _SecretBuffer = bytes | bytearray | memoryview[int]
type _PathInput = str | os.PathLike[str]
_ReferenceKind = Literal["environment", "file", "generated"]
_PATH_SEPARATOR = re.compile(r"[\\/]")
_WINDOWS_DEVICE_NAME = re.compile(r"(?i)(?:CON|PRN|AUX|NUL|CLOCK\$|COM[1-9]|LPT[1-9])(?:\..*)?")
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_DEVICE = 0x00000040
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_ATTRIBUTE_TAG_INFO = 9
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_TYPE_DISK = 0x0001
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_GENERIC_ALL = 0x10000000
_WINDOWS_MAXIMUM_ALLOWED = 0x02000000
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_INVALID_HANDLE = ctypes.c_void_p(-1).value
_WINDOWS_SE_FILE_OBJECT = 1
_WINDOWS_OWNER_SECURITY_INFORMATION = 0x00000001
_WINDOWS_DACL_SECURITY_INFORMATION = 0x00000004
_WINDOWS_TOKEN_QUERY = 0x0008
_WINDOWS_TOKEN_USER = 1
_WINDOWS_ERROR_INSUFFICIENT_BUFFER = 122
_WINDOWS_ACL_SIZE_INFORMATION = 2
_WINDOWS_ACCESS_ALLOWED_ACE_TYPE = 0
_WINDOWS_ACCESS_DENIED_ACE_TYPE = 1
_WINDOWS_FILE_READ_DATA = 0x00000001
_WINDOWS_FILE_READ_EA = 0x00000008
_WINDOWS_SECRET_READ_ACCESS = (
    _WINDOWS_FILE_READ_DATA
    | _WINDOWS_FILE_READ_EA
    | _WINDOWS_FILE_READ_ATTRIBUTES
    | _WINDOWS_GENERIC_READ
    | _WINDOWS_GENERIC_ALL
    | _WINDOWS_MAXIMUM_ALLOWED
)
_WINDOWS_TRUSTED_FILE_SIDS = (
    "S-1-5-18",  # LocalSystem; analogous to the POSIX privileged override.
    "S-1-5-32-544",  # Builtin Administrators.
    "S-1-3-0",  # Creator Owner inheritance placeholder.
    "S-1-3-4",  # Owner Rights.
)


class _WindowsFileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("reparse_tag", ctypes.c_uint32),
    ]


class _WindowsAceHeader(ctypes.Structure):
    _fields_ = [
        ("ace_type", ctypes.c_ubyte),
        ("ace_flags", ctypes.c_ubyte),
        ("ace_size", ctypes.c_ushort),
    ]


class _WindowsAclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("ace_count", ctypes.c_uint32),
        ("acl_bytes_in_use", ctypes.c_uint32),
        ("acl_bytes_free", ctypes.c_uint32),
    ]


class _WindowsSidAndAttributes(ctypes.Structure):
    _fields_ = [
        ("sid", ctypes.c_void_p),
        ("attributes", ctypes.c_uint32),
    ]


class _WindowsTokenUser(ctypes.Structure):
    _fields_ = [("user", _WindowsSidAndAttributes)]


class SecretResolutionError(RuntimeError):
    """A classified, secret-safe failure resolving or using a secret."""

    diagnostic: Diagnostic
    __slots__ = ("diagnostic",)

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.message)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"category={self.diagnostic.category.value!r}, "
            f"code={str(self.diagnostic.code)!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SecretMetadata:
    """The only reportable representation of a resolved secret."""

    reference: SecretRef
    fingerprint: Sha256Digest

    def __post_init__(self) -> None:
        _validate_fingerprint(self.fingerprint)

    @property
    def reference_kind(self) -> _ReferenceKind:
        """Return a safe reference discriminator without its configured contents."""
        return _reference_kind(self.reference)

    def model_dump(
        self,
        *,
        mode: Literal["json", "python"] = "python",
    ) -> dict[str, object]:
        """Return only the configured reference and non-secret fingerprint."""
        if mode not in {"json", "python"}:
            message = "mode must be 'json' or 'python'"
            raise ValueError(message)
        return {
            "reference": self.reference.to_wire(),
            "fingerprint": str(self.fingerprint),
        }

    def model_dump_json(self) -> str:
        """Serialize only the configured reference and non-secret fingerprint."""
        return json.dumps(self.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"reference_kind={self.reference_kind!r}, "
            f"fingerprint={str(self.fingerprint)!r})"
        )


class _SecretProvider(Protocol):
    def load(self) -> bytearray:
        """Load one ephemeral mutable copy of the secret."""
        ...

    def close(self) -> None:
        """Release or wipe provider-owned state."""
        ...


class _EnvironmentProvider:
    __slots__ = ("_lookup", "_name")

    _lookup: Callable[[str], object]
    _name: str

    def __init__(self, lookup: Callable[[str], object], name: str) -> None:
        self._lookup = lookup
        self._name = name

    def load(self) -> bytearray:
        value: object | None = None
        lookup_failed = False
        try:
            value = self._lookup(self._name)
        except Exception:
            lookup_failed = True
        if lookup_failed:
            raise _unavailable_error("environment") from None
        if not isinstance(value, str):
            value = None
            raise _unavailable_error("environment") from None
        return _encode_environment_secret(value)

    def close(self) -> None:
        return

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class _GeneratedProvider:
    __slots__ = ("_closed", "_lock", "_material")

    _closed: bool
    _lock: threading.RLock
    _material: bytearray

    def __init__(self, material: bytes) -> None:
        if len(material) != GENERATED_HMAC_KEY_BYTES:
            message = "generated key source returned an invalid byte count"
            raise ValueError(message)
        self._material = bytearray(material)
        self._closed = False
        self._lock = threading.RLock()

    def load(self) -> bytearray:
        with self._lock:
            if self._closed:
                raise _unavailable_error("generated")
            return bytearray(self._material)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                _wipe(self._material)
                self._closed = True

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


@dataclass(frozen=True, slots=True, repr=False)
class _ContainedSecretPath:
    project_root: Path
    secret_root: Path
    root_relative_parts: tuple[str, ...]
    secret_relative_parts: tuple[str, ...]


class _FileProvider:
    __slots__ = ("_location",)

    _location: _ContainedSecretPath

    def __init__(self, location: _ContainedSecretPath) -> None:
        self._location = location

    def load(self) -> bytearray:
        return _read_contained_secret(self._location)

    def close(self) -> None:
        return

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class SecretHandle:
    """Opaque, non-copyable access to secret material through ``use_with``."""

    __slots__ = ("_closed", "_lock", "_metadata", "_provider")

    _closed: bool
    _lock: threading.RLock
    _metadata: SecretMetadata
    _provider: _SecretProvider

    def __init__(self, metadata: SecretMetadata, provider: _SecretProvider) -> None:
        object.__setattr__(self, "_metadata", metadata)
        object.__setattr__(self, "_provider", provider)
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_lock", threading.RLock())

    @property
    def metadata(self) -> SecretMetadata:
        """Return the immutable, secret-free metadata projection."""
        return self._metadata

    @property
    def reference(self) -> SecretRef:
        """Return the configured reference, never its resolved value."""
        return self._metadata.reference

    @property
    def fingerprint(self) -> Sha256Digest:
        """Return the domain-separated SHA-256 fingerprint."""
        return self._metadata.fingerprint

    def use_with(self, callback: Callable[[memoryview[int]], _T]) -> _T:
        """Use an ephemeral read-only view, then wipe its backing buffer."""
        if not callable(callback):
            message = "secret callback must be callable"
            raise TypeError(message)

        with self._lock:
            if self._closed:
                raise _unavailable_error(self._metadata.reference_kind)
            material = _load_provider_safely(
                self._provider,
                reference_kind=self._metadata.reference_kind,
            )
            view: memoryview[int] | None = None
            callback_failed = False
            callback_results: list[_T] = []
            try:
                current_fingerprint = secret_fingerprint(material)
                if not hmac.compare_digest(
                    str(current_fingerprint),
                    str(self._metadata.fingerprint),
                ):
                    raise _changed_error(self._metadata.reference_kind)
                view = memoryview(material).toreadonly()
                try:
                    callback_results.append(callback(view))
                except BaseException:
                    callback_failed = True
            finally:
                if view is not None:
                    view.release()
                _wipe(material)
            if callback_failed:
                del callback
                raise _callback_error(self._metadata.reference_kind) from None
            return callback_results[0]

    def close(self) -> None:
        """Wipe provider-owned generated material and make the handle unusable."""
        with self._lock:
            if not self._closed:
                self._provider.close()
                object.__setattr__(self, "_closed", True)

    def model_dump(
        self,
        *,
        mode: Literal["json", "python"] = "python",
    ) -> dict[str, object]:
        """Return the safe metadata projection; secret material is not serializable."""
        return self._metadata.model_dump(mode=mode)

    def model_dump_json(self) -> str:
        """Serialize the safe metadata projection only."""
        return self._metadata.model_dump_json()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"reference_kind={self._metadata.reference_kind!r}, "
            f"fingerprint={str(self._metadata.fingerprint)!r})"
        )

    __str__ = __repr__

    def __copy__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise _nonserializable_handle_error()

    def __reduce__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __reduce_ex__(self, _protocol: object) -> NoReturn:
        raise _nonserializable_handle_error()

    def __getstate__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __bytes__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __del__(self) -> None:
        with suppress(Exception):
            # Destructors must not obscure interpreter shutdown or partial init.
            self.close()


class SecretResolver:
    """Resolve typed secret references under an explicit local path policy."""

    __slots__ = ("_environment_lookup", "_project_root", "_secret_roots", "_token_bytes")

    _environment_lookup: Callable[[str], object]
    _project_root: Path | None
    _secret_roots: tuple[Path, ...]
    _token_bytes: Callable[[int], object]

    def __init__(
        self,
        *,
        project_root: _PathInput | None = None,
        secret_roots: Sequence[_PathInput] = (),
        environ: Mapping[str, str] | None = None,
        token_bytes: Callable[[int], object] | None = None,
    ) -> None:
        environment = os.environ if environ is None else environ
        self._environment_lookup = environment.__getitem__
        self._project_root, self._secret_roots = _normalize_secret_roots(
            project_root,
            secret_roots,
        )
        self._token_bytes = _stdlib_secrets.token_bytes if token_bytes is None else token_bytes

    def resolve(self, reference: object) -> SecretHandle:
        """Resolve a typed reference to an opaque callback-only handle."""
        provider: _SecretProvider
        typed_reference: SecretRef
        if isinstance(reference, EnvironmentSecretRef):
            typed_reference = reference
            provider = _EnvironmentProvider(self._environment_lookup, reference.env)
        elif isinstance(reference, GeneratedSecretRef):
            typed_reference = reference
            generation_failed = False
            generated: object | None = None
            try:
                generated = self._token_bytes(GENERATED_HMAC_KEY_BYTES)
            except Exception:
                generation_failed = True
            if generation_failed:
                raise _unavailable_error("generated") from None
            if not isinstance(generated, bytes) or len(generated) != GENERATED_HMAC_KEY_BYTES:
                generated = None
                raise _unavailable_error("generated")
            provider = _GeneratedProvider(generated)
        elif isinstance(reference, FileSecretRef):
            typed_reference = reference
            provider = _FileProvider(
                _contained_secret_path(
                    reference.file,
                    project_root=self._project_root,
                    secret_roots=self._secret_roots,
                )
            )
        else:
            raise SecretResolutionError(inline_secret_diagnostic())

        material: bytearray | None = None
        load_failure: SecretResolutionError | None = None
        try:
            material = _load_provider_safely(
                provider,
                reference_kind=_reference_kind(typed_reference),
            )
        except SecretResolutionError as exception:
            load_failure = _detach_resolution_error(exception)
        if load_failure is not None:
            with suppress(Exception):
                provider.close()
            raise load_failure from None
        if material is None:
            with suppress(Exception):
                provider.close()
            raise _unavailable_error(_reference_kind(typed_reference)) from None
        try:
            fingerprint = secret_fingerprint(material)
        finally:
            _wipe(material)
        metadata = SecretMetadata(reference=typed_reference, fingerprint=fingerprint)
        return SecretHandle(metadata, provider)

    def __copy__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise _nonserializable_handle_error()

    def __reduce__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __reduce_ex__(self, _protocol: object) -> NoReturn:
        raise _nonserializable_handle_error()

    def __getstate__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __bytes__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def model_dump(self, *_args: object, **_kwargs: object) -> NoReturn:
        """Reject model-style serialization of retained runtime providers."""
        raise _nonserializable_handle_error()

    def model_dump_json(self, *_args: object, **_kwargs: object) -> NoReturn:
        """Reject JSON model serialization of retained runtime providers."""
        raise _nonserializable_handle_error()


class RunCorrelationHasher:
    """HMAC correlation service with an ephemeral, non-persistable run key."""

    __slots__ = ("_closed", "_key", "_lock")

    _closed: bool
    _key: bytearray
    _lock: threading.RLock

    def __init__(
        self,
        *,
        token_bytes: Callable[[int], object] | None = None,
    ) -> None:
        generator = _stdlib_secrets.token_bytes if token_bytes is None else token_bytes
        generation_failed = False
        key: object | None = None
        try:
            key = generator(GENERATED_HMAC_KEY_BYTES)
        except Exception:
            generation_failed = True
        if generation_failed:
            raise _unavailable_error("generated") from None
        if not isinstance(key, bytes) or len(key) != GENERATED_HMAC_KEY_BYTES:
            key = None
            raise _unavailable_error("generated")
        object.__setattr__(self, "_key", bytearray(key))
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_lock", threading.RLock())

    def correlate(self, value: str | _SecretBuffer) -> str:
        """Return a stable correlation token scoped to this hasher instance."""
        encoded, owned_buffer = _correlation_input(value)
        try:
            with self._lock:
                if self._closed:
                    raise _unavailable_error("generated")
                digest_builder = hmac.new(self._key, digestmod=FINGERPRINT_ALGORITHM)
                digest_builder.update(CORRELATION_DOMAIN_SEPARATOR)
                digest_builder.update(encoded)
                digest = digest_builder.digest()
            return f"{CORRELATION_ALGORITHM}:{digest.hex()}"
        finally:
            if owned_buffer is not None:
                _wipe(owned_buffer)

    def close(self) -> None:
        """Wipe the ephemeral run key."""
        with self._lock:
            if not self._closed:
                _wipe(self._key)
                object.__setattr__(self, "_closed", True)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(algorithm={CORRELATION_ALGORITHM!r})"

    __str__ = __repr__

    def __copy__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise _nonserializable_handle_error()

    def __reduce__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __reduce_ex__(self, _protocol: object) -> NoReturn:
        raise _nonserializable_handle_error()

    def __getstate__(self) -> NoReturn:
        raise _nonserializable_handle_error()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


def secret_fingerprint(material: object) -> Sha256Digest:
    """Return a domain-separated, schema-compatible SHA-256 fingerprint."""
    if not isinstance(material, (bytes, bytearray, memoryview)):
        message = "secret fingerprint input must be bytes-like"
        raise TypeError(message)
    digest = hashlib.sha256()
    digest.update(SECRET_FINGERPRINT_DOMAIN_SEPARATOR)
    if isinstance(material, memoryview):
        digest.update(material.cast("B"))
    else:
        digest.update(material)
    return Sha256Digest(f"{FINGERPRINT_ALGORITHM}:{digest.hexdigest()}")


def inline_secret_diagnostic(*, field_path: str = "secret") -> Diagnostic:
    """Return the stable CFG-009 diagnostic without retaining the literal value."""
    return Diagnostic(
        category=ErrorCategory.CONFIGURATION_ERROR,
        code=DiagnosticCode("CFG_INLINE_SECRET"),
        message="Plaintext secret values are not accepted.",
        retryable=False,
        safe_details={"accepted_reference_kinds": ["env", "file", "generated"]},
        result_category=ResultCategory.INVALID_INPUT,
        user_correctable=True,
        field_path=field_path,
        corrective_action=(
            "Use an explicit env, contained file, or generated hmac-256 secret reference."
        ),
    )


def verify_observer_credential(
    secret: SecretHandle | None,
    presented_credential: object,
) -> Diagnostic | None:
    """Compare observer credentials in constant time or return one safe error.

    The single failure diagnostic deliberately does not distinguish a missing
    configured credential from a wrong presented credential and accepts no
    response body, so neither value can enter diagnostic evidence.
    """
    candidate = _observer_credential_buffer(presented_credential)
    if secret is None or candidate is None or not candidate:
        if candidate is not None:
            _wipe(candidate)
        return _observer_auth_diagnostic()

    try:
        try:
            matches = secret.use_with(
                lambda expected: bool(expected) and hmac.compare_digest(expected, candidate)
            )
        except SecretResolutionError:
            return _observer_auth_diagnostic()
        return None if matches else _observer_auth_diagnostic()
    finally:
        _wipe(candidate)


def _reference_kind(reference: SecretRef) -> _ReferenceKind:
    if isinstance(reference, EnvironmentSecretRef):
        return "environment"
    if isinstance(reference, FileSecretRef):
        return "file"
    return "generated"


def _encode_environment_secret(value: str) -> bytearray:
    if not value:
        raise _unavailable_error("environment") from None
    if len(value) > MAX_SECRET_BYTES:
        raise _environment_resource_error() from None

    material = bytearray()
    invalid_unicode = False
    resource_limit = False
    for start in range(0, len(value), 65_536):
        chunk = value[start : start + 65_536]
        encoded_chunk: bytearray | None = None
        try:
            encoded_chunk = bytearray(chunk, "utf-8")
        except UnicodeEncodeError:
            invalid_unicode = True
        if invalid_unicode:
            break
        if encoded_chunk is None:
            invalid_unicode = True
            break
        if len(encoded_chunk) > MAX_SECRET_BYTES - len(material):
            _wipe(encoded_chunk)
            resource_limit = True
            break
        material.extend(encoded_chunk)
        _wipe(encoded_chunk)

    if invalid_unicode:
        _wipe(material)
        value = ""
        chunk = ""
        raise _unavailable_error("environment") from None
    if resource_limit:
        _wipe(material)
        value = ""
        chunk = ""
        raise _environment_resource_error() from None
    return material


def _load_provider_safely(
    provider: _SecretProvider,
    *,
    reference_kind: _ReferenceKind,
) -> bytearray:
    failure: SecretResolutionError | None = None
    try:
        return provider.load()
    except SecretResolutionError as exception:
        failure = _detach_resolution_error(exception)
    except Exception:
        failure = _unavailable_error(reference_kind)
    del provider
    raise failure from None


def _detach_resolution_error(exception: SecretResolutionError) -> SecretResolutionError:
    exception.__cause__ = None
    exception.__context__ = None
    exception.__traceback__ = None
    return exception


def _normalize_secret_roots(
    project_root: _PathInput | None,
    secret_roots: Sequence[_PathInput],
) -> tuple[Path | None, tuple[Path, ...]]:
    if project_root is None:
        if secret_roots:
            raise _file_policy_error("SECRET_FILE_ROOT_POLICY")
        return None, ()

    try:
        project_text = os.fspath(project_root)
    except TypeError:
        project_text = ""
    if not project_text:
        raise _file_policy_error("SECRET_FILE_ROOT_POLICY") from None
    project = Path(os.path.abspath(project_text))

    normalized: list[Path] = []
    for configured_root in secret_roots:
        try:
            root_text = os.fspath(configured_root)
        except TypeError:
            root_text = ""
        if not root_text:
            raise _file_policy_error("SECRET_FILE_ROOT_POLICY") from None

        native_root = Path(root_text)
        if native_root.is_absolute():
            root = Path(os.path.abspath(root_text))
        else:
            root_parts = _safe_relative_parts(root_text, allow_current_directory=True)
            root = project.joinpath(*root_parts)
        if not _path_is_within(root, project):
            raise _file_policy_error("SECRET_FILE_ROOT_POLICY")
        normalized.append(root)
    return project, tuple(normalized)


def _contained_secret_path(
    reference_path: str,
    *,
    project_root: Path | None,
    secret_roots: tuple[Path, ...],
) -> _ContainedSecretPath:
    if project_root is None or not secret_roots:
        raise _file_policy_error("SECRET_FILE_ROOT_REQUIRED")
    reference_parts = _safe_relative_parts(reference_path)
    candidate = project_root.joinpath(*reference_parts)
    matching_roots = tuple(root for root in secret_roots if _path_is_within(candidate, root))
    if not matching_roots:
        raise _file_policy_error("SECRET_FILE_OUTSIDE_ROOT")

    secret_root = max(matching_roots, key=lambda root: len(root.parts))
    root_relative_parts = _relative_parts(secret_root, project_root)
    secret_relative_parts = _relative_parts(candidate, secret_root)
    if not secret_relative_parts:
        raise _file_policy_error("SECRET_FILE_NOT_REGULAR")
    return _ContainedSecretPath(
        project_root=project_root,
        secret_root=secret_root,
        root_relative_parts=root_relative_parts,
        secret_relative_parts=secret_relative_parts,
    )


def _safe_relative_parts(
    value: str,
    *,
    allow_current_directory: bool = False,
) -> tuple[str, ...]:
    if (
        not value
        or len(value) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise _file_policy_error("SECRET_FILE_PATH_INVALID")
    windows_path = PureWindowsPath(value)
    if (
        PurePosixPath(value).is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or bool(windows_path.root)
    ):
        raise _file_policy_error("SECRET_FILE_PATH_INVALID")
    if allow_current_directory and value == ".":
        return ()

    parts = tuple(_PATH_SEPARATOR.split(value))
    if any(part in {"", ".", ".."} for part in parts):
        raise _file_policy_error("SECRET_FILE_PATH_INVALID")
    for part in parts:
        if (
            ":" in part
            or part.endswith((" ", "."))
            or _WINDOWS_DEVICE_NAME.fullmatch(part) is not None
        ):
            raise _file_policy_error("SECRET_FILE_PATH_INVALID")
    return parts


def _path_is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate_text = os.path.normcase(os.path.abspath(candidate))
        root_text = os.path.normcase(os.path.abspath(root))
        return os.path.commonpath((candidate_text, root_text)) == root_text
    except (OSError, ValueError):
        return False


def _relative_parts(candidate: Path, root: Path) -> tuple[str, ...]:
    relative_failed = False
    relative = ""
    try:
        relative = os.path.relpath(candidate, root)
    except ValueError:
        relative_failed = True
    if relative_failed:
        raise _file_policy_error("SECRET_FILE_OUTSIDE_ROOT") from None
    if relative == ".":
        return ()
    parts = Path(relative).parts
    if any(part == ".." for part in parts):
        raise _file_policy_error("SECRET_FILE_OUTSIDE_ROOT")
    return tuple(parts)


def _read_contained_secret(location: _ContainedSecretPath) -> bytearray:
    failure: SecretResolutionError | None = None
    try:
        if os.name == "nt":
            return _read_contained_secret_windows(location)
        return _read_contained_secret_posix(location)
    except SecretResolutionError as exception:
        failure = _detach_resolution_error(exception)
    except OSError as exception:
        failure = _normalize_file_os_error(exception.errno)
    except Exception:
        failure = _file_unavailable_error()
    raise failure from None


def _read_contained_secret_posix(location: _ContainedSecretPath) -> bytearray:
    directory_fds: list[int] = []
    final_fd: int | None = None
    try:
        project_fd = _open_posix_directory(location.project_root)
        directory_fds.append(project_fd)
        current_fd = project_fd
        directory_parts = (
            *location.root_relative_parts,
            *location.secret_relative_parts[:-1],
        )
        for part in directory_parts:
            current_fd = _open_posix_directory(part, directory_fd=current_fd)
            directory_fds.append(current_fd)

        final_name = location.secret_relative_parts[-1]
        expected = os.stat(final_name, dir_fd=current_fd, follow_symlinks=False)
        if stat.S_ISLNK(expected.st_mode):
            raise _file_policy_error("SECRET_FILE_SYMLINK")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        final_fd = os.open(final_name, flags, dir_fd=current_fd)
        actual = os.fstat(final_fd)
        if not _same_file_identity(expected, actual):
            raise _file_race_error()
        return _read_regular_secret_fd(final_fd, enforce_posix_permissions=True)
    finally:
        if final_fd is not None:
            with suppress(OSError):
                os.close(final_fd)
        for directory_fd in reversed(directory_fds):
            with suppress(OSError):
                os.close(directory_fd)


def _open_posix_directory(
    path: Path | str,
    *,
    directory_fd: int | None = None,
) -> int:
    if directory_fd is None:
        expected = os.stat(path, follow_symlinks=False)
    else:
        expected = os.stat(path, dir_fd=directory_fd, follow_symlinks=False)
    if stat.S_ISLNK(expected.st_mode):
        raise _file_policy_error("SECRET_FILE_SYMLINK")
    if not stat.S_ISDIR(expected.st_mode):
        raise _file_policy_error("SECRET_FILE_NOT_REGULAR")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    if directory_fd is None:
        opened = os.open(path, flags)
    else:
        opened = os.open(path, flags, dir_fd=directory_fd)
    actual = os.fstat(opened)
    if not _same_file_identity(expected, actual):
        with suppress(OSError):
            os.close(opened)
        raise _file_race_error()
    return opened


def _read_contained_secret_windows(location: _ContainedSecretPath) -> bytearray:
    import msvcrt

    directory_handles: list[int] = []
    file_handle: int | None = None
    file_descriptor: int | None = None
    try:
        project_handle = _windows_open_path(location.project_root, directory=True)
        directory_handles.append(project_handle)
        actual_project = _windows_final_path(project_handle)
        actual_root = actual_project
        traversed: list[str] = []
        directory_parts = (
            *location.root_relative_parts,
            *location.secret_relative_parts[:-1],
        )
        for index, part in enumerate(directory_parts, start=1):
            traversed.append(part)
            directory_path = location.project_root.joinpath(*traversed)
            directory_handle = _windows_open_path(directory_path, directory=True)
            directory_handles.append(directory_handle)
            actual_directory = _windows_final_path(directory_handle)
            expected_directory = actual_project.joinpath(*traversed)
            if not _same_path(actual_directory, expected_directory):
                raise _file_policy_error("SECRET_FILE_SYMLINK")
            if index == len(location.root_relative_parts):
                actual_root = actual_directory

        file_path = location.project_root.joinpath(
            *location.root_relative_parts,
            *location.secret_relative_parts,
        )
        file_handle = _windows_open_path(file_path, directory=False)
        actual_file = _windows_final_path(file_handle)
        expected_file = actual_project.joinpath(
            *location.root_relative_parts,
            *location.secret_relative_parts,
        )
        if not _same_path(actual_file, expected_file) or not _path_is_within(
            actual_file,
            actual_root,
        ):
            raise _file_policy_error("SECRET_FILE_SYMLINK")
        _validate_windows_secret_permissions(file_handle)

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        file_descriptor = msvcrt.open_osfhandle(file_handle, flags)
        file_handle = None
        return _read_regular_secret_fd(file_descriptor, enforce_posix_permissions=False)
    finally:
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
        if file_handle is not None:
            _windows_close_handle(file_handle)
        for directory_handle in reversed(directory_handles):
            _windows_close_handle(directory_handle)


def _windows_kernel32() -> Any:
    if os.name != "nt":
        message = "Windows file APIs are unavailable on this platform"
        raise RuntimeError(message)
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _windows_advapi32() -> Any:
    if os.name != "nt":
        message = "Windows security APIs are unavailable on this platform"
        raise RuntimeError(message)
    return ctypes.WinDLL("advapi32", use_last_error=True)


def _validate_windows_secret_permissions(handle: int) -> None:
    """Require owner-only-like Windows access on the already pinned file handle.

    Every inherited and explicit ACE is inspected. Standard deny ACEs cannot
    create exposure and are accepted. A standard allow ACE carrying file-read,
    generic-read/all, or maximum-allowed rights is accepted only for the current
    owner, LocalSystem, Builtin Administrators, Creator Owner, or Owner Rights.
    Null/missing DACLs, unsupported ACE forms, malformed SIDs, API failures, and
    any read-capable allow ACE for another trustee fail closed.
    """
    failure = False
    try:
        _require_windows_secret_permissions(handle)
    except Exception:
        failure = True
    if failure:
        raise _file_policy_error("SECRET_FILE_PERMISSIONS") from None


def _require_windows_secret_permissions(handle: int) -> None:
    advapi32 = _windows_advapi32()
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    get_security_info = advapi32.GetSecurityInfo
    get_security_info.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_security_info.restype = ctypes.c_uint32
    status = int(
        get_security_info(
            ctypes.c_void_p(handle),
            _WINDOWS_SE_FILE_OBJECT,
            _WINDOWS_OWNER_SECURITY_INFORMATION | _WINDOWS_DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(security_descriptor),
        )
    )
    if status != 0 or not security_descriptor.value or not owner.value:
        raise OSError(status, "secure Windows ACL inspection failed")

    try:
        actual_dacl = _windows_descriptor_dacl(security_descriptor)
        if not dacl.value or actual_dacl != int(dacl.value):
            raise OSError
        token_buffer, current_user_sid = _windows_current_user_sid()
        if not _windows_equal_sid(int(owner.value), current_user_sid):
            raise OSError
        _require_windows_private_dacl(actual_dacl, current_user_sid)
        del token_buffer
    finally:
        _windows_local_free(int(security_descriptor.value))


def _windows_descriptor_dacl(security_descriptor: ctypes.c_void_p) -> int:
    advapi32 = _windows_advapi32()
    is_valid_descriptor = advapi32.IsValidSecurityDescriptor
    is_valid_descriptor.argtypes = [ctypes.c_void_p]
    is_valid_descriptor.restype = ctypes.c_int
    if not is_valid_descriptor(security_descriptor):
        raise OSError

    dacl_present = ctypes.c_int()
    dacl_defaulted = ctypes.c_int()
    dacl = ctypes.c_void_p()
    get_dacl = advapi32.GetSecurityDescriptorDacl
    get_dacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_int),
    ]
    get_dacl.restype = ctypes.c_int
    if not get_dacl(
        security_descriptor,
        ctypes.byref(dacl_present),
        ctypes.byref(dacl),
        ctypes.byref(dacl_defaulted),
    ):
        raise OSError
    if not dacl_present.value or not dacl.value:
        raise OSError
    return int(dacl.value)


def _windows_current_user_sid() -> tuple[Any, int]:
    kernel32 = _windows_kernel32()
    advapi32 = _windows_advapi32()
    get_current_process = kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = ctypes.c_void_p
    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    open_process_token.restype = ctypes.c_int
    token = ctypes.c_void_p()
    if not open_process_token(
        get_current_process(),
        _WINDOWS_TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise OSError

    try:
        get_token_information = advapi32.GetTokenInformation
        get_token_information.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        get_token_information.restype = ctypes.c_int
        required = ctypes.c_uint32()
        ctypes.set_last_error(0)
        first_call = get_token_information(
            token,
            _WINDOWS_TOKEN_USER,
            None,
            0,
            ctypes.byref(required),
        )
        if (
            first_call
            or ctypes.get_last_error() != _WINDOWS_ERROR_INSUFFICIENT_BUFFER
            or required.value == 0
        ):
            raise OSError
        buffer = ctypes.create_string_buffer(required.value)
        if not get_token_information(
            token,
            _WINDOWS_TOKEN_USER,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError
        token_user = ctypes.cast(buffer, ctypes.POINTER(_WindowsTokenUser)).contents
        if not token_user.user.sid or not _windows_valid_sid(int(token_user.user.sid)):
            raise OSError
        return buffer, int(token_user.user.sid)
    finally:
        if token.value:
            _windows_close_handle(int(token.value))


def _require_windows_private_dacl(dacl: int, current_user_sid: int) -> None:
    advapi32 = _windows_advapi32()
    is_valid_acl = advapi32.IsValidAcl
    is_valid_acl.argtypes = [ctypes.c_void_p]
    is_valid_acl.restype = ctypes.c_int
    if not is_valid_acl(ctypes.c_void_p(dacl)):
        raise OSError

    get_acl_information = advapi32.GetAclInformation
    get_acl_information.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    get_acl_information.restype = ctypes.c_int
    information = _WindowsAclSizeInformation()
    if not get_acl_information(
        ctypes.c_void_p(dacl),
        ctypes.byref(information),
        ctypes.sizeof(information),
        _WINDOWS_ACL_SIZE_INFORMATION,
    ):
        raise OSError

    trusted_sids: list[int] = []
    try:
        trusted_sids.append(current_user_sid)
        trusted_sids.extend(_windows_sid_from_string(value) for value in _WINDOWS_TRUSTED_FILE_SIDS)
        get_ace = advapi32.GetAce
        get_ace.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        get_ace.restype = ctypes.c_int
        for index in range(information.ace_count):
            ace = ctypes.c_void_p()
            if not get_ace(ctypes.c_void_p(dacl), index, ctypes.byref(ace)) or not ace.value:
                raise OSError
            _require_windows_safe_ace(int(ace.value), trusted_sids)
    finally:
        for sid in trusted_sids[1:]:
            _windows_local_free(sid)


def _require_windows_safe_ace(ace: int, trusted_sids: Sequence[int]) -> None:
    header = ctypes.cast(ctypes.c_void_p(ace), ctypes.POINTER(_WindowsAceHeader)).contents
    if header.ace_type == _WINDOWS_ACCESS_DENIED_ACE_TYPE:
        return
    if header.ace_type != _WINDOWS_ACCESS_ALLOWED_ACE_TYPE or header.ace_size < 16:
        raise OSError

    mask = ctypes.c_uint32.from_address(ace + ctypes.sizeof(_WindowsAceHeader)).value
    sid = ace + ctypes.sizeof(_WindowsAceHeader) + ctypes.sizeof(ctypes.c_uint32)
    if not _windows_valid_sid(sid):
        raise OSError
    sid_length = _windows_sid_length(sid)
    if sid_length <= 0 or ctypes.sizeof(_WindowsAceHeader) + 4 + sid_length > header.ace_size:
        raise OSError
    if mask & _WINDOWS_SECRET_READ_ACCESS and not any(
        _windows_equal_sid(sid, trusted_sid) for trusted_sid in trusted_sids
    ):
        raise OSError


def _windows_sid_from_string(value: str) -> int:
    advapi32 = _windows_advapi32()
    convert = advapi32.ConvertStringSidToSidW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    convert.restype = ctypes.c_int
    sid = ctypes.c_void_p()
    if not convert(value, ctypes.byref(sid)) or not sid.value:
        raise OSError
    return int(sid.value)


def _windows_valid_sid(sid: int) -> bool:
    advapi32 = _windows_advapi32()
    is_valid = advapi32.IsValidSid
    is_valid.argtypes = [ctypes.c_void_p]
    is_valid.restype = ctypes.c_int
    return bool(is_valid(ctypes.c_void_p(sid)))


def _windows_sid_length(sid: int) -> int:
    advapi32 = _windows_advapi32()
    get_length = advapi32.GetLengthSid
    get_length.argtypes = [ctypes.c_void_p]
    get_length.restype = ctypes.c_uint32
    return int(get_length(ctypes.c_void_p(sid)))


def _windows_equal_sid(first: int, second: int) -> bool:
    advapi32 = _windows_advapi32()
    equal = advapi32.EqualSid
    equal.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    equal.restype = ctypes.c_int
    return bool(equal(ctypes.c_void_p(first), ctypes.c_void_p(second)))


def _windows_local_free(pointer: int) -> None:
    kernel32 = _windows_kernel32()
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    local_free(ctypes.c_void_p(pointer))


def _windows_open_path(path: Path, *, directory: bool) -> int:
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
    desired_access = (
        _WINDOWS_FILE_READ_ATTRIBUTES
        if directory
        else _WINDOWS_GENERIC_READ | _WINDOWS_FILE_READ_ATTRIBUTES
    )
    share_mode = (
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE
        if directory
        else _WINDOWS_FILE_SHARE_READ
    )
    handle = create_file(
        str(path),
        desired_access,
        share_mode,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle in {None, _WINDOWS_INVALID_HANDLE}:
        raise _safe_windows_os_error()
    integer_handle = int(handle)
    try:
        attributes = _windows_file_attributes(integer_handle)
        if attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            raise _file_policy_error("SECRET_FILE_SYMLINK")
        if attributes & _WINDOWS_FILE_ATTRIBUTE_DEVICE:
            raise _file_policy_error("SECRET_FILE_NOT_REGULAR")
        if directory:
            if not attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
                raise _file_policy_error("SECRET_FILE_NOT_REGULAR")
        else:
            if attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
                raise _file_policy_error("SECRET_FILE_NOT_REGULAR")
            if _windows_file_type(integer_handle) != _WINDOWS_FILE_TYPE_DISK:
                raise _file_policy_error("SECRET_FILE_NOT_REGULAR")
    except Exception:
        _windows_close_handle(integer_handle)
        raise
    return integer_handle


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
        raise _safe_windows_os_error()
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
        raise _safe_windows_os_error()
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
        raise _safe_windows_os_error()
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _windows_close_handle(handle: int) -> None:
    kernel32 = _windows_kernel32()
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    with suppress(Exception):
        close_handle(ctypes.c_void_p(handle))


def _safe_windows_os_error() -> OSError:
    error_number = ctypes.get_last_error()
    return OSError(error_number, "secure Windows file operation failed")


def _same_path(first: Path, second: Path) -> bool:
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


def _read_regular_secret_fd(
    file_descriptor: int,
    *,
    enforce_posix_permissions: bool,
) -> bytearray:
    before = os.fstat(file_descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise _file_policy_error("SECRET_FILE_NOT_REGULAR")
    if enforce_posix_permissions:
        _validate_posix_secret_permissions(before)
    if before.st_size > MAX_SECRET_BYTES:
        raise _file_resource_error()

    material = bytearray()
    try:
        while len(material) <= MAX_SECRET_BYTES:
            remaining = MAX_SECRET_BYTES + 1 - len(material)
            chunk = os.read(file_descriptor, min(65_536, remaining))
            if not chunk:
                break
            material.extend(chunk)
        if len(material) > MAX_SECRET_BYTES:
            raise _file_resource_error()
        after = os.fstat(file_descriptor)
        if not _stable_file_snapshot(before, after) or len(material) != before.st_size:
            raise _file_race_error()
        if not material:
            raise _file_policy_error("SECRET_FILE_EMPTY")
        return material
    except Exception:
        _wipe(material)
        raise


def _validate_posix_secret_permissions(file_status: os.stat_result) -> None:
    effective_uid = getattr(os, "geteuid", None)
    if effective_uid is not None and file_status.st_uid != effective_uid():
        raise _file_policy_error("SECRET_FILE_PERMISSIONS")
    permission_bits = stat.S_IMODE(file_status.st_mode)
    if not permission_bits & stat.S_IRUSR or permission_bits & 0o077:
        raise _file_policy_error("SECRET_FILE_PERMISSIONS")


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _stable_file_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        _same_file_identity(first, second)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


def _validate_fingerprint(value: object) -> None:
    if not isinstance(value, str):
        message = "secret fingerprint must be a string"
        raise TypeError(message)
    prefix = f"{FINGERPRINT_ALGORITHM}:"
    hexadecimal = value.removeprefix(prefix)
    if (
        not value.startswith(prefix)
        or len(hexadecimal) != hashlib.sha256().digest_size * 2
        or any(character not in "0123456789abcdef" for character in hexadecimal)
    ):
        message = "secret fingerprint must use sha256: plus 64 lowercase hexadecimal characters"
        raise ValueError(message)


def _correlation_input(
    value: object,
) -> tuple[_SecretBuffer, bytearray | None]:
    if isinstance(value, str):
        encoded = bytearray(value, "utf-8")
        return encoded, encoded
    if isinstance(value, (bytes, bytearray)):
        return value, None
    if isinstance(value, memoryview):
        return value.cast("B"), None
    message = "correlation input must be a string or bytes-like value"
    raise TypeError(message)


def _observer_credential_buffer(value: object) -> bytearray | None:
    try:
        if isinstance(value, str):
            return bytearray(value, "utf-8")
        if isinstance(value, (bytes, bytearray)):
            return bytearray(value)
        if isinstance(value, memoryview):
            return bytearray(value.cast("B"))
    except (TypeError, UnicodeEncodeError, ValueError):
        return None
    return None


def _wipe(material: bytearray) -> None:
    material[:] = b"\x00" * len(material)


def _unavailable_error(reference_kind: _ReferenceKind) -> SecretResolutionError:
    return SecretResolutionError(
        Diagnostic(
            category=ErrorCategory.KEY_UNAVAILABLE,
            code=DiagnosticCode("SECRET_KEY_UNAVAILABLE"),
            message="Secret key material is unavailable.",
            retryable=False,
            safe_details={"reference_kind": reference_kind},
            result_category=ResultCategory.ENVIRONMENT_ERROR,
        )
    )


def _environment_resource_error() -> SecretResolutionError:
    return SecretResolutionError(
        Diagnostic(
            category=ErrorCategory.RESOURCE_LIMIT,
            code=DiagnosticCode("SECRET_ENV_TOO_LARGE"),
            message="Environment secret material exceeds the byte limit.",
            retryable=False,
            safe_details={
                "reference_kind": "environment",
                "maximum_bytes": MAX_SECRET_BYTES,
            },
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="secret.env",
            corrective_action="Use an environment secret within the documented byte limit.",
        )
    )


def _callback_error(reference_kind: _ReferenceKind) -> SecretResolutionError:
    return SecretResolutionError(
        Diagnostic(
            category=ErrorCategory.KEY_UNAVAILABLE,
            code=DiagnosticCode("SECRET_CALLBACK_FAILED"),
            message="The operation using secret material failed.",
            retryable=False,
            safe_details={"reference_kind": reference_kind},
            result_category=ResultCategory.ENVIRONMENT_ERROR,
        )
    )


def _changed_error(reference_kind: _ReferenceKind) -> SecretResolutionError:
    return SecretResolutionError(
        Diagnostic(
            category=ErrorCategory.KEY_UNAVAILABLE,
            code=DiagnosticCode("SECRET_VALUE_CHANGED"),
            message="Secret key material changed after it was fingerprinted.",
            retryable=False,
            safe_details={"reference_kind": reference_kind},
            result_category=ResultCategory.ENVIRONMENT_ERROR,
        )
    )


def _file_policy_error(code: str) -> SecretResolutionError:
    return SecretResolutionError(
        Diagnostic(
            category=ErrorCategory.SECRET_REFERENCE_ERROR,
            code=DiagnosticCode(code),
            message="The file secret reference violates the local file policy.",
            retryable=False,
            safe_details={"reference_kind": "file"},
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="secret.file",
            corrective_action=(
                "Use a nonempty protected regular file contained by a configured secret root."
            ),
        )
    )


def _file_unavailable_error() -> SecretResolutionError:
    return SecretResolutionError(
        Diagnostic(
            category=ErrorCategory.KEY_UNAVAILABLE,
            code=DiagnosticCode("SECRET_FILE_UNAVAILABLE"),
            message="File secret material is unavailable.",
            retryable=False,
            safe_details={"reference_kind": "file"},
            result_category=ResultCategory.ENVIRONMENT_ERROR,
            user_correctable=True,
            field_path="secret.file",
            corrective_action=(
                "Make the configured protected file readable without changing its reference."
            ),
        )
    )


def _file_resource_error() -> SecretResolutionError:
    return SecretResolutionError(
        Diagnostic(
            category=ErrorCategory.RESOURCE_LIMIT,
            code=DiagnosticCode("SECRET_FILE_TOO_LARGE"),
            message="File secret material exceeds the byte limit.",
            retryable=False,
            safe_details={
                "reference_kind": "file",
                "maximum_bytes": MAX_SECRET_BYTES,
            },
            result_category=ResultCategory.INVALID_INPUT,
            user_correctable=True,
            field_path="secret.file",
            corrective_action="Use a secret file within the documented byte limit.",
        )
    )


def _file_race_error() -> SecretResolutionError:
    return SecretResolutionError(
        Diagnostic(
            category=ErrorCategory.SECRET_REFERENCE_ERROR,
            code=DiagnosticCode("SECRET_FILE_RACE"),
            message="File secret identity or content changed during secure loading.",
            retryable=False,
            safe_details={"reference_kind": "file"},
            result_category=ResultCategory.ENVIRONMENT_ERROR,
        )
    )


def _normalize_file_os_error(error_number: int | None) -> SecretResolutionError:
    if error_number == errno.ELOOP:
        return _file_policy_error("SECRET_FILE_SYMLINK")
    if error_number in {errno.EISDIR, errno.ENODEV, errno.ENOTDIR, errno.ENXIO}:
        return _file_policy_error("SECRET_FILE_NOT_REGULAR")
    if error_number == errno.EFBIG:
        return _file_resource_error()
    return _file_unavailable_error()


def _observer_auth_diagnostic() -> Diagnostic:
    return Diagnostic(
        category=ErrorCategory.OBSERVER_AUTH_ERROR,
        code=DiagnosticCode("OBSERVER_AUTH_FAILED"),
        message="Observer authentication failed.",
        retryable=False,
        safe_details={},
        result_category=ResultCategory.ENVIRONMENT_ERROR,
    )


def _nonserializable_handle_error() -> TypeError:
    return TypeError("secret-bearing runtime objects cannot be copied or serialized")


__all__ = [
    "CORRELATION_ALGORITHM",
    "CORRELATION_DOMAIN_SEPARATOR",
    "FINGERPRINT_ALGORITHM",
    "GENERATED_HMAC_KEY_BYTES",
    "MAX_SECRET_BYTES",
    "SECRET_FINGERPRINT_DOMAIN_SEPARATOR",
    "RunCorrelationHasher",
    "SecretHandle",
    "SecretMetadata",
    "SecretResolutionError",
    "SecretResolver",
    "inline_secret_diagnostic",
    "secret_fingerprint",
    "verify_observer_credential",
]
