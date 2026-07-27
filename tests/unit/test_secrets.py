# ruff: noqa: INP001

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import pickle
import re
import subprocess
import traceback
from typing import TYPE_CHECKING

import pytest

import webhook_receiver_conformance.secrets as secrets_module
from webhook_receiver_conformance.config.models import (
    EnvironmentSecretRef,
    FileSecretRef,
    GeneratedSecretRef,
)
from webhook_receiver_conformance.errors import ErrorCategory, ResultCategory
from webhook_receiver_conformance.secrets import (
    CORRELATION_DOMAIN_SEPARATOR,
    GENERATED_HMAC_KEY_BYTES,
    MAX_SECRET_BYTES,
    SECRET_FINGERPRINT_DOMAIN_SEPARATOR,
    RunCorrelationHasher,
    SecretHandle,
    SecretResolutionError,
    SecretResolver,
    inline_secret_diagnostic,
    secret_fingerprint,
    verify_observer_credential,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

CANARY = b"secret-canary-0106-never-serialize"
SHA256_HEX_LENGTH = hashlib.sha256().digest_size * 2


def _extract_bytes(value: memoryview[int]) -> bytes:
    assert value.readonly
    return value.tobytes()


def _serialization_surfaces(handle: SecretHandle) -> bytes:
    return b"\n".join(
        (
            repr(handle).encode(),
            str(handle).encode(),
            repr(handle.metadata).encode(),
            json.dumps(handle.model_dump(mode="json"), sort_keys=True).encode(),
            handle.model_dump_json().encode(),
        )
    )


def _exception_surfaces(exception: BaseException) -> bytes:
    rendered = "".join(traceback.format_exception(exception))
    return (repr(exception) + "\n" + str(exception) + "\n" + rendered).encode(
        "utf-8", errors="backslashreplace"
    )


def _write_protected_secret(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    if os.name != "nt":
        path.chmod(0o600)


def _file_resolver(project_root: Path) -> SecretResolver:
    return SecretResolver(
        project_root=project_root,
        secret_roots=(".secrets",),
        environ={},
    )


def _create_symlink_or_skip(
    link: Path,
    target: Path,
    *,
    target_is_directory: bool = False,
) -> None:
    if os.name == "nt" and target_is_directory:
        command_interpreter = os.environ.get("COMSPEC")
        if command_interpreter is not None:
            completed = subprocess.run(  # noqa: S603
                [
                    command_interpreter,
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    str(link),
                    str(target),
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if completed.returncode == 0:
                return
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exception:
        pytest.skip(f"symlink creation unavailable: {type(exception).__name__}")


def _grant_windows_sid_read(path: Path, sid: str) -> None:
    completed = subprocess.run(  # noqa: S603
        ["icacls", str(path), "/grant", f"*{sid}:(R)"],  # noqa: S607
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert completed.returncode == 0


def _grant_windows_sid_inheritable_read(path: Path, sid: str) -> None:
    completed = subprocess.run(  # noqa: S603
        ["icacls", str(path), "/grant", f"*{sid}:(OI)(CI)(R)"],  # noqa: S607
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert completed.returncode == 0


def test_environment_reference_resolves_only_inside_callback_and_is_fingerprinted() -> None:
    reference = EnvironmentSecretRef(env="WEBHOOK_TEST_SECRET")
    resolver = SecretResolver(environ={"WEBHOOK_TEST_SECRET": CANARY.decode()})

    handle = resolver.resolve(reference)

    assert handle.reference is reference
    assert handle.use_with(_extract_bytes) == CANARY
    assert handle.fingerprint == secret_fingerprint(CANARY)
    expected = hashlib.sha256(SECRET_FINGERPRINT_DOMAIN_SEPARATOR + CANARY).hexdigest()
    assert handle.fingerprint == f"sha256:{expected}"
    assert handle.model_dump() == {
        "reference": {"env": "WEBHOOK_TEST_SECRET"},
        "fingerprint": f"sha256:{expected}",
    }


def test_free_form_interpolation_syntax_is_never_resolved() -> None:
    literal = "${WEBHOOK_TEST_SECRET}"
    resolver = SecretResolver(environ={"WEBHOOK_TEST_SECRET": CANARY.decode()})

    with pytest.raises(SecretResolutionError) as raised:
        resolver.resolve(literal)

    assert literal == "${WEBHOOK_TEST_SECRET}"
    assert raised.value.diagnostic.category is ErrorCategory.CONFIGURATION_ERROR
    assert raised.value.diagnostic.code == "CFG_INLINE_SECRET"
    assert CANARY not in str(raised.value).encode()


def test_missing_environment_secret_has_exact_safe_classification() -> None:
    resolver = SecretResolver(environ={})

    with pytest.raises(SecretResolutionError) as raised:
        resolver.resolve(EnvironmentSecretRef(env="MISSING_SECRET"))

    diagnostic = raised.value.diagnostic
    assert diagnostic.category is ErrorCategory.KEY_UNAVAILABLE
    assert diagnostic.code == "SECRET_KEY_UNAVAILABLE"
    assert diagnostic.result_category is ResultCategory.ENVIRONMENT_ERROR
    assert diagnostic.safe_details == {"reference_kind": "environment"}
    assert "MISSING_SECRET" not in str(raised.value)
    assert "MISSING_SECRET" not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_environment_change_after_resolution_fails_without_using_new_value() -> None:
    environ = {"WEBHOOK_TEST_SECRET": CANARY.decode()}
    handle = SecretResolver(environ=environ).resolve(
        EnvironmentSecretRef(env="WEBHOOK_TEST_SECRET")
    )
    replacement = "replacement-secret-must-not-escape"
    environ["WEBHOOK_TEST_SECRET"] = replacement
    called = False

    def callback(_material: memoryview[int]) -> None:
        nonlocal called
        called = True

    with pytest.raises(SecretResolutionError) as raised:
        handle.use_with(callback)

    assert not called
    assert raised.value.diagnostic.code == "SECRET_VALUE_CHANGED"
    rendered = repr(raised.value) + str(raised.value)
    assert replacement not in rendered
    assert CANARY.decode() not in rendered


def test_callback_view_is_read_only_and_released_after_use() -> None:
    handle = SecretResolver(environ={"KEY": CANARY.decode()}).resolve(
        EnvironmentSecretRef(env="KEY")
    )
    retained: memoryview[int] | None = None
    retained_alias: memoryview[int] | None = None

    def retain(view: memoryview[int]) -> None:
        nonlocal retained, retained_alias
        retained = view
        retained_alias = view[:]
        with pytest.raises(TypeError):
            view[0] = 0

    handle.use_with(retain)

    assert retained is not None
    with pytest.raises(ValueError, match="released memoryview"):
        retained.tobytes()
    assert retained_alias is not None
    assert retained_alias.tobytes() == b"\x00" * len(CANARY)
    retained_alias.release()


def test_callback_exception_is_replaced_after_ephemeral_views_are_wiped() -> None:
    handle = SecretResolver(environ={"KEY": CANARY.decode()}).resolve(
        EnvironmentSecretRef(env="KEY")
    )
    retained: memoryview[int] | None = None
    retained_alias: memoryview[int] | None = None

    class SentinelError(Exception):
        def __init__(self, secret: bytes) -> None:
            self.secret = secret
            super().__init__(secret)

    def fail(view: memoryview[int]) -> None:
        nonlocal retained, retained_alias
        retained = view
        retained_alias = view[:]
        raise SentinelError(view.tobytes())

    with pytest.raises(SecretResolutionError) as raised:
        handle.use_with(fail)

    assert raised.value.diagnostic.code == "SECRET_CALLBACK_FAILED"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert CANARY not in _exception_surfaces(raised.value)
    assert retained is not None
    with pytest.raises(ValueError, match="released memoryview"):
        retained.tobytes()
    assert retained_alias is not None
    assert retained_alias.tobytes() == b"\x00" * len(CANARY)
    retained_alias.release()


def test_generated_reference_requests_exactly_32_bytes_and_retains_safe_projection() -> None:
    calls: list[int] = []
    generated_key = bytes(range(GENERATED_HMAC_KEY_BYTES))

    def token_bytes(length: int) -> bytes:
        calls.append(length)
        return generated_key

    reference = GeneratedSecretRef(generated="hmac-256")
    handle = SecretResolver(environ={}, token_bytes=token_bytes).resolve(reference)

    assert calls == [32]
    assert handle.use_with(_extract_bytes) == generated_key
    assert handle.model_dump() == {
        "reference": {"generated": "hmac-256"},
        "fingerprint": secret_fingerprint(generated_key),
    }
    assert set(handle.model_dump()) == {"reference", "fingerprint"}
    assert generated_key not in _serialization_surfaces(handle)
    assert base64.b64encode(generated_key) not in _serialization_surfaces(handle)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: b"too-short",
        lambda: b"x" * (GENERATED_HMAC_KEY_BYTES + 1),
        lambda: "not-bytes",
    ],
)
def test_generated_reference_rejects_invalid_entropy_source_without_leak(
    factory: Callable[[], object],
) -> None:
    def token_bytes(_length: int) -> bytes:
        return factory()  # type: ignore[return-value]

    with pytest.raises(SecretResolutionError) as raised:
        SecretResolver(token_bytes=token_bytes).resolve(GeneratedSecretRef(generated="hmac-256"))

    assert raised.value.diagnostic.category is ErrorCategory.KEY_UNAVAILABLE
    assert raised.value.diagnostic.safe_details == {"reference_kind": "generated"}
    assert "too-short" not in str(raised.value)


def test_handle_repr_dump_json_copy_pickle_and_bytes_never_expose_secret() -> None:
    handle = SecretResolver(environ={"KEY": CANARY.decode()}).resolve(
        EnvironmentSecretRef(env="KEY")
    )
    encoded_canary = base64.b64encode(CANARY)

    surfaces = _serialization_surfaces(handle)
    assert CANARY not in surfaces
    assert encoded_canary not in surfaces
    assert re.fullmatch(rb"(?s).*sha256:[0-9a-f]{64}.*", surfaces)
    with pytest.raises(TypeError, match="cannot be copied or serialized"):
        copy.copy(handle)
    with pytest.raises(TypeError, match="cannot be copied or serialized"):
        copy.deepcopy(handle)
    with pytest.raises(TypeError, match="cannot be copied or serialized"):
        pickle.dumps(handle)
    with pytest.raises(TypeError, match="cannot be copied or serialized"):
        bytes(handle)
    with pytest.raises(TypeError):
        json.dumps(handle)


def test_resolver_copy_pickle_bytes_and_model_serialization_are_canary_safe() -> None:
    token_canary = CANARY + b"-token-provider"

    def token_bytes(_length: int) -> bytes:
        return token_canary[:GENERATED_HMAC_KEY_BYTES]

    resolver = SecretResolver(
        environ={"KEY": CANARY.decode()},
        token_bytes=token_bytes,
    )
    encoded_canary = base64.b64encode(CANARY)
    captured_pickle = io.BytesIO()

    def model_dump() -> object:
        return resolver.model_dump()

    def model_dump_json() -> object:
        return resolver.model_dump_json()

    operations: tuple[Callable[[], object], ...] = (
        lambda: copy.copy(resolver),
        lambda: copy.deepcopy(resolver),
        lambda: bytes(resolver),
        model_dump,
        model_dump_json,
        lambda: json.dumps(resolver),
        lambda: pickle.Pickler(captured_pickle).dump(resolver),
    )
    for operation in operations:
        with pytest.raises(TypeError) as raised:
            operation()
        surfaces = _exception_surfaces(raised.value)
        assert CANARY not in surfaces
        assert token_canary not in surfaces
        assert encoded_canary not in surfaces

    assert CANARY not in captured_pickle.getvalue()
    assert token_canary not in captured_pickle.getvalue()


def test_environment_provider_exception_chain_drops_secret_objects() -> None:
    class ExplodingEnvironment(dict[str, str]):
        def __getitem__(self, key: str) -> str:
            raise RuntimeError(CANARY, key)

    resolver = SecretResolver(environ=ExplodingEnvironment())

    with pytest.raises(SecretResolutionError) as raised:
        resolver.resolve(EnvironmentSecretRef(env="SENSITIVE_ENV_NAME"))

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    surfaces = _exception_surfaces(raised.value)
    assert CANARY not in surfaces
    assert "SENSITIVE_ENV_NAME" not in repr(raised.value)
    assert "SENSITIVE_ENV_NAME" not in str(raised.value)


def test_generated_provider_exception_chain_drops_secret_objects() -> None:
    def explode(_length: int) -> bytes:
        raise RuntimeError(CANARY)

    resolver = SecretResolver(token_bytes=explode)

    with pytest.raises(SecretResolutionError) as raised:
        resolver.resolve(GeneratedSecretRef(generated="hmac-256"))

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert CANARY not in _exception_surfaces(raised.value)


def test_environment_values_reject_empty_oversize_and_invalid_unicode_safely() -> None:
    cases = (
        ("", "SECRET_KEY_UNAVAILABLE", ErrorCategory.KEY_UNAVAILABLE),
        (
            "x" * (MAX_SECRET_BYTES + 1),
            "SECRET_ENV_TOO_LARGE",
            ErrorCategory.RESOURCE_LIMIT,
        ),
        (
            "é" * ((MAX_SECRET_BYTES // 2) + 1),
            "SECRET_ENV_TOO_LARGE",
            ErrorCategory.RESOURCE_LIMIT,
        ),
        (
            "\ud800" + CANARY.decode(),
            "SECRET_KEY_UNAVAILABLE",
            ErrorCategory.KEY_UNAVAILABLE,
        ),
    )

    for value, code, category in cases:
        with pytest.raises(SecretResolutionError) as raised:
            SecretResolver(environ={"KEY": value}).resolve(EnvironmentSecretRef(env="KEY"))
        assert raised.value.diagnostic.code == code
        assert raised.value.diagnostic.category is category
        assert raised.value.__cause__ is None
        assert raised.value.__context__ is None
        assert CANARY not in _exception_surfaces(raised.value)


def test_environment_value_exact_utf8_byte_limit_is_accepted() -> None:
    value = "é" * (MAX_SECRET_BYTES // 2)
    handle = SecretResolver(environ={"KEY": value}).resolve(EnvironmentSecretRef(env="KEY"))

    assert handle.use_with(len) == MAX_SECRET_BYTES


def test_closed_handle_is_unavailable_and_generated_material_is_not_reported() -> None:
    generated_key = b"z" * GENERATED_HMAC_KEY_BYTES
    handle = SecretResolver(token_bytes=lambda _length: generated_key).resolve(
        GeneratedSecretRef(generated="hmac-256")
    )

    handle.close()
    handle.close()

    with pytest.raises(SecretResolutionError) as raised:
        handle.use_with(_extract_bytes)
    assert raised.value.diagnostic.category is ErrorCategory.KEY_UNAVAILABLE
    assert generated_key not in _serialization_surfaces(handle)


def test_inline_secret_diagnostic_directs_to_all_reference_kinds_without_literal() -> None:
    diagnostic = inline_secret_diagnostic(field_path="signers.demo.secret")
    wire = diagnostic.model_dump_json()

    assert diagnostic.category is ErrorCategory.CONFIGURATION_ERROR
    assert diagnostic.result_category is ResultCategory.INVALID_INPUT
    assert diagnostic.field_path == "signers.demo.secret"
    assert diagnostic.safe_details == {"accepted_reference_kinds": ["env", "file", "generated"]}
    assert diagnostic.corrective_action is not None
    assert all(name in diagnostic.corrective_action for name in ("env", "file", "generated"))
    assert CANARY.decode() not in wire


def test_correlation_is_equal_within_run_unlinkable_across_runs_and_not_persisted() -> None:
    first_key = b"a" * GENERATED_HMAC_KEY_BYTES
    second_key = b"b" * GENERATED_HMAC_KEY_BYTES
    first = RunCorrelationHasher(
        token_bytes=lambda length: first_key if length == GENERATED_HMAC_KEY_BYTES else b""
    )
    second = RunCorrelationHasher(
        token_bytes=lambda length: second_key if length == GENERATED_HMAC_KEY_BYTES else b""
    )

    first_hash = first.correlate("low-entropy-value")

    assert first_hash == first.correlate("low-entropy-value")
    assert first_hash != first.correlate("other-value")
    assert first_hash != second.correlate("low-entropy-value")
    assert first_hash.startswith("hmac-sha256:")
    assert len(first_hash.removeprefix("hmac-sha256:")) == SHA256_HEX_LENGTH
    assert CORRELATION_DOMAIN_SEPARATOR not in repr(first).encode()
    assert first_key not in repr(first).encode()
    with pytest.raises(TypeError, match="cannot be copied or serialized"):
        pickle.dumps(first)
    with pytest.raises(TypeError, match="cannot be copied or serialized"):
        copy.deepcopy(first)


def test_correlation_accepts_text_and_bytes_with_the_same_utf8_value() -> None:
    hasher = RunCorrelationHasher(token_bytes=lambda _length: b"k" * 32)

    assert hasher.correlate("café") == hasher.correlate("café".encode())


def test_correlation_closed_state_and_invalid_inputs_are_safe() -> None:
    hasher = RunCorrelationHasher(token_bytes=lambda _length: b"k" * 32)

    with pytest.raises(TypeError, match="string or bytes-like"):
        hasher.correlate(42)  # type: ignore[arg-type]
    hasher.close()
    with pytest.raises(SecretResolutionError) as raised:
        hasher.correlate("value")
    assert raised.value.diagnostic.category is ErrorCategory.KEY_UNAVAILABLE


@pytest.mark.parametrize(
    "reference_path",
    [
        "../outside",
        "..\\outside",
        ".secrets/../outside",
        ".secrets\\..\\outside",
        ".secrets//key",
        ".secrets\\\\key",
        "/absolute/key",
        "\\absolute\\key",
        "C:\\outside\\key",
        "\\\\server\\share\\key",
        ".secrets/NUL",
        ".secrets/COM1.txt",
        ".secrets/key:stream",
        ".secrets/key.",
    ],
)
def test_file_reference_rejects_traversal_absolute_alternate_and_device_paths(
    tmp_path: Path,
    reference_path: str,
) -> None:
    (tmp_path / ".secrets").mkdir()
    resolver = _file_resolver(tmp_path)

    with pytest.raises(SecretResolutionError) as raised:
        resolver.resolve(FileSecretRef(file=reference_path))

    diagnostic = raised.value.diagnostic
    assert diagnostic.category is ErrorCategory.SECRET_REFERENCE_ERROR
    assert diagnostic.result_category is ResultCategory.INVALID_INPUT
    assert diagnostic.code == "SECRET_FILE_PATH_INVALID"
    rendered = repr(raised.value) + str(raised.value) + diagnostic.model_dump_json()
    assert reference_path not in rendered


def test_file_reference_requires_explicit_containing_root(tmp_path: Path) -> None:
    secret_path = tmp_path / ".secrets" / "key"
    _write_protected_secret(secret_path, CANARY)

    with pytest.raises(SecretResolutionError) as no_roots:
        SecretResolver(project_root=tmp_path).resolve(FileSecretRef(file=".secrets/key"))
    with pytest.raises(SecretResolutionError) as outside_root:
        SecretResolver(
            project_root=tmp_path,
            secret_roots=("other-secrets",),
        ).resolve(FileSecretRef(file=".secrets/key"))

    assert no_roots.value.diagnostic.code == "SECRET_FILE_ROOT_REQUIRED"
    assert outside_root.value.diagnostic.code == "SECRET_FILE_OUTSIDE_ROOT"


def test_file_reference_loads_exact_bytes_with_both_portable_separators(
    tmp_path: Path,
) -> None:
    secret_path = tmp_path / ".secrets" / "nested" / "key"
    _write_protected_secret(secret_path, CANARY)
    resolver = _file_resolver(tmp_path)

    slash_handle = resolver.resolve(FileSecretRef(file=".secrets/nested/key"))
    backslash_handle = resolver.resolve(FileSecretRef(file=".secrets\\nested\\key"))

    assert slash_handle.use_with(_extract_bytes) == CANARY
    assert backslash_handle.use_with(_extract_bytes) == CANARY
    assert slash_handle.fingerprint == backslash_handle.fingerprint
    assert slash_handle.model_dump()["reference"] == {"file": ".secrets/nested/key"}
    assert CANARY not in _serialization_surfaces(slash_handle)


def test_file_reference_missing_file_is_safe_key_unavailable(tmp_path: Path) -> None:
    (tmp_path / ".secrets").mkdir()
    reference_path = ".secrets/missing-sensitive-name"

    with pytest.raises(SecretResolutionError) as raised:
        _file_resolver(tmp_path).resolve(FileSecretRef(file=reference_path))

    diagnostic = raised.value.diagnostic
    assert diagnostic.category is ErrorCategory.KEY_UNAVAILABLE
    assert diagnostic.code == "SECRET_FILE_UNAVAILABLE"
    assert diagnostic.result_category is ResultCategory.ENVIRONMENT_ERROR
    assert reference_path not in repr(raised.value)
    assert reference_path not in diagnostic.model_dump_json()
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_file_reference_rejects_directory_and_empty_file(tmp_path: Path) -> None:
    directory = tmp_path / ".secrets" / "directory"
    directory.mkdir(parents=True)
    empty = tmp_path / ".secrets" / "empty"
    _write_protected_secret(empty, b"")
    resolver = _file_resolver(tmp_path)

    with pytest.raises(SecretResolutionError) as directory_error:
        resolver.resolve(FileSecretRef(file=".secrets/directory"))
    with pytest.raises(SecretResolutionError) as empty_error:
        resolver.resolve(FileSecretRef(file=".secrets/empty"))

    assert directory_error.value.diagnostic.code == "SECRET_FILE_NOT_REGULAR"
    assert empty_error.value.diagnostic.code == "SECRET_FILE_EMPTY"


def test_file_reference_rejects_oversize_before_callback(tmp_path: Path) -> None:
    secret_path = tmp_path / ".secrets" / "oversize"
    _write_protected_secret(secret_path, b"x" * (MAX_SECRET_BYTES + 1))

    with pytest.raises(SecretResolutionError) as raised:
        _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/oversize"))

    diagnostic = raised.value.diagnostic
    assert diagnostic.category is ErrorCategory.RESOURCE_LIMIT
    assert diagnostic.code == "SECRET_FILE_TOO_LARGE"
    assert diagnostic.safe_details == {
        "reference_kind": "file",
        "maximum_bytes": MAX_SECRET_BYTES,
    }


@pytest.mark.skipif(os.name == "nt", reason="owner/mode-bit policy is POSIX-only")
def test_file_reference_rejects_non_owner_only_permissions(tmp_path: Path) -> None:
    secret_path = tmp_path / ".secrets" / "permissions"
    _write_protected_secret(secret_path, CANARY)
    secret_path.chmod(0o640)

    with pytest.raises(SecretResolutionError) as raised:
        _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/permissions"))

    assert raised.value.diagnostic.category is ErrorCategory.SECRET_REFERENCE_ERROR
    assert raised.value.diagnostic.code == "SECRET_FILE_PERMISSIONS"


@pytest.mark.skipif(os.name != "nt", reason="Windows owner/DACL policy is Windows-only")
def test_windows_file_reference_accepts_private_temp_acl(tmp_path: Path) -> None:
    secret_path = tmp_path / ".secrets" / "private"
    _write_protected_secret(secret_path, CANARY)

    handle = _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/private"))

    assert handle.use_with(_extract_bytes) == CANARY


@pytest.mark.skipif(os.name != "nt", reason="Windows owner/DACL policy is Windows-only")
@pytest.mark.parametrize(
    "broad_sid",
    [
        "S-1-1-0",  # Everyone
        "S-1-5-7",  # Anonymous
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-545",  # Builtin Users
    ],
)
def test_windows_file_reference_rejects_broad_read_acl(
    tmp_path: Path,
    broad_sid: str,
) -> None:
    secret_path = tmp_path / ".secrets" / broad_sid.replace("-", "_")
    _write_protected_secret(secret_path, CANARY)
    _grant_windows_sid_read(secret_path, broad_sid)

    with pytest.raises(SecretResolutionError) as raised:
        _file_resolver(tmp_path).resolve(FileSecretRef(file=f".secrets/{secret_path.name}"))

    assert raised.value.diagnostic.code == "SECRET_FILE_PERMISSIONS"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    rendered = _exception_surfaces(raised.value)
    assert CANARY not in rendered
    assert broad_sid.encode() not in rendered
    assert str(secret_path).encode() not in rendered


@pytest.mark.skipif(os.name != "nt", reason="Windows owner/DACL policy is Windows-only")
def test_windows_file_reference_rejects_inherited_broad_read_acl(tmp_path: Path) -> None:
    secret_root = tmp_path / ".secrets"
    secret_root.mkdir()
    _grant_windows_sid_inheritable_read(secret_root, "S-1-1-0")
    secret_path = secret_root / "inherited"
    secret_path.write_bytes(CANARY)

    with pytest.raises(SecretResolutionError) as raised:
        _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/inherited"))

    assert raised.value.diagnostic.code == "SECRET_FILE_PERMISSIONS"
    assert CANARY not in _exception_surfaces(raised.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows owner/DACL policy is Windows-only")
def test_windows_acl_introspection_failure_is_safe_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_path = tmp_path / ".secrets" / "private"
    _write_protected_secret(secret_path, CANARY)

    def fail(_handle: int) -> None:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(secrets_module, "_require_windows_secret_permissions", fail)

    with pytest.raises(SecretResolutionError) as raised:
        _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/private"))

    assert raised.value.diagnostic.code == "SECRET_FILE_PERMISSIONS"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert CANARY not in _exception_surfaces(raised.value)


@pytest.mark.skipif(os.name == "nt", reason="FIFO creation is POSIX-only")
def test_file_reference_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / ".secrets" / "fifo"
    fifo.parent.mkdir()
    os.mkfifo(fifo, mode=0o600)

    with pytest.raises(SecretResolutionError) as raised:
        _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/fifo"))

    assert raised.value.diagnostic.code == "SECRET_FILE_NOT_REGULAR"


def test_file_reference_rejects_final_symlink_to_external_canary(
    tmp_path: Path,
) -> None:
    secret_root = tmp_path / ".secrets"
    secret_root.mkdir()
    external = tmp_path / "external-canary"
    external.write_bytes(CANARY)
    link = secret_root / "linked-key"
    _create_symlink_or_skip(link, external)

    with pytest.raises(SecretResolutionError) as raised:
        _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/linked-key"))

    assert raised.value.diagnostic.code == "SECRET_FILE_SYMLINK"
    assert external.read_bytes() == CANARY
    assert CANARY not in (repr(raised.value) + str(raised.value)).encode()


def test_file_reference_rejects_parent_symlink_escape(tmp_path: Path) -> None:
    secret_root = tmp_path / ".secrets"
    secret_root.mkdir()
    external_root = tmp_path / "external-root"
    external_key = external_root / "key"
    _write_protected_secret(external_key, CANARY)
    _create_symlink_or_skip(
        secret_root / "nested",
        external_root,
        target_is_directory=True,
    )

    with pytest.raises(SecretResolutionError) as raised:
        _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/nested/key"))

    assert raised.value.diagnostic.code == "SECRET_FILE_SYMLINK"
    assert external_key.read_bytes() == CANARY


def test_file_reference_rejects_configured_root_reparse_escape(
    tmp_path: Path,
) -> None:
    external_root = tmp_path / "external-root"
    external_key = external_root / "key"
    _write_protected_secret(external_key, CANARY)
    linked_root = tmp_path / "linked-secrets"
    _create_symlink_or_skip(
        linked_root,
        external_root,
        target_is_directory=True,
    )
    resolver = SecretResolver(
        project_root=tmp_path,
        secret_roots=("linked-secrets",),
        environ={},
    )

    with pytest.raises(SecretResolutionError) as raised:
        resolver.resolve(FileSecretRef(file="linked-secrets/key"))

    assert raised.value.diagnostic.code == "SECRET_FILE_SYMLINK"
    assert external_key.read_bytes() == CANARY


def test_file_symlink_swap_after_fingerprint_cannot_read_external_canary(
    tmp_path: Path,
) -> None:
    secret_path = tmp_path / ".secrets" / "key"
    original = b"original-protected-key"
    _write_protected_secret(secret_path, original)
    external = tmp_path / "external-canary"
    external.write_bytes(CANARY)
    handle = _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/key"))
    secret_path.unlink()
    _create_symlink_or_skip(secret_path, external)
    called = False

    def callback(_material: memoryview[int]) -> None:
        nonlocal called
        called = True

    with pytest.raises(SecretResolutionError) as raised:
        handle.use_with(callback)

    assert not called
    assert raised.value.diagnostic.code == "SECRET_FILE_SYMLINK"
    assert external.read_bytes() == CANARY
    assert CANARY not in (repr(raised.value) + str(raised.value)).encode()


def test_file_parent_reparse_swap_after_fingerprint_cannot_read_external_canary(
    tmp_path: Path,
) -> None:
    nested = tmp_path / ".secrets" / "nested"
    secret_path = nested / "key"
    _write_protected_secret(secret_path, b"original-protected-key")
    external_root = tmp_path / "external-root"
    external_key = external_root / "key"
    _write_protected_secret(external_key, CANARY)
    handle = _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/nested/key"))
    secret_path.unlink()
    nested.rmdir()
    _create_symlink_or_skip(
        nested,
        external_root,
        target_is_directory=True,
    )
    called = False

    def callback(_material: memoryview[int]) -> None:
        nonlocal called
        called = True

    with pytest.raises(SecretResolutionError) as raised:
        handle.use_with(callback)

    assert not called
    assert raised.value.diagnostic.code == "SECRET_FILE_SYMLINK"
    assert external_key.read_bytes() == CANARY
    assert CANARY not in (repr(raised.value) + str(raised.value)).encode()


def test_file_regular_content_change_is_detected_before_callback(
    tmp_path: Path,
) -> None:
    secret_path = tmp_path / ".secrets" / "key"
    _write_protected_secret(secret_path, b"before-change")
    handle = _file_resolver(tmp_path).resolve(FileSecretRef(file=".secrets/key"))
    _write_protected_secret(secret_path, b"after-change")
    called = False

    def callback(_material: memoryview[int]) -> None:
        nonlocal called
        called = True

    with pytest.raises(SecretResolutionError) as raised:
        handle.use_with(callback)

    assert not called
    assert raised.value.diagnostic.category is ErrorCategory.KEY_UNAVAILABLE
    assert raised.value.diagnostic.code == "SECRET_VALUE_CHANGED"


def test_observer_credentials_compare_through_handle_with_one_safe_failure() -> None:
    credential = "observer-secret-canary"
    handle = SecretResolver(environ={"OBSERVER_TOKEN": credential}).resolve(
        EnvironmentSecretRef(env="OBSERVER_TOKEN")
    )

    assert verify_observer_credential(handle, credential) is None
    wrong = verify_observer_credential(handle, "wrong-observer-credential")
    missing = verify_observer_credential(handle, None)
    unavailable = verify_observer_credential(None, credential)

    assert wrong is not None
    assert missing is not None
    assert unavailable is not None
    for diagnostic in (wrong, missing, unavailable):
        assert diagnostic.category is ErrorCategory.OBSERVER_AUTH_ERROR
        assert diagnostic.code == "OBSERVER_AUTH_FAILED"
        rendered = diagnostic.model_dump_json()
        assert credential not in rendered
        assert "wrong-observer-credential" not in rendered
        assert "response" not in rendered.casefold()


def test_observer_changed_or_missing_resolved_credential_is_auth_error() -> None:
    environ = {"OBSERVER_TOKEN": "initial-token"}
    handle = SecretResolver(environ=environ).resolve(EnvironmentSecretRef(env="OBSERVER_TOKEN"))
    environ["OBSERVER_TOKEN"] = "changed-token"  # noqa: S105

    diagnostic = verify_observer_credential(handle, "changed-token")

    assert diagnostic is not None
    assert diagnostic.category is ErrorCategory.OBSERVER_AUTH_ERROR
    assert "initial-token" not in diagnostic.model_dump_json()
    assert "changed-token" not in diagnostic.model_dump_json()


def test_complete_run_directory_canary_scan_contains_only_safe_projections(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "project"
    secret_path = project_root / ".secrets" / "key"
    _write_protected_secret(secret_path, CANARY)
    handle = _file_resolver(project_root).resolve(FileSecretRef(file=".secrets/key"))
    observer_error = verify_observer_credential(handle, b"wrong")
    assert observer_error is not None

    run_directory = tmp_path / "run"
    (run_directory / "reports").mkdir(parents=True)
    (run_directory / "manifest.json").write_text(
        handle.model_dump_json(),
        encoding="utf-8",
    )
    (run_directory / "reports" / "observer.json").write_text(
        observer_error.model_dump_json(),
        encoding="utf-8",
    )
    (run_directory / "logs.jsonl").write_text(
        json.dumps({"secret": handle.model_dump(mode="json")}) + "\n",
        encoding="utf-8",
    )

    complete_artifact_bytes = b"\n".join(
        path.read_bytes() for path in sorted(run_directory.rglob("*")) if path.is_file()
    )
    assert CANARY not in complete_artifact_bytes
    assert base64.b64encode(CANARY) not in complete_artifact_bytes
