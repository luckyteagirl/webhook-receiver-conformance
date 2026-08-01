"""Build-artifact installation and minimal local run smoke test."""
# ruff: noqa: EM101, EM102, INP001, S603, T201, TRY003, TRY004

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_DYNAMIC_MANIFEST_KEYS: Final = frozenset({"created_at", "environment", "manifest_id"})
_DYNAMIC_TOOL_KEYS: Final = frozenset({"python"})
_UNSUPPORTED_EXIT: Final = 6
_SMOKE_PORT: Final = 38_765
_DIAGNOSTIC_LIMIT: Final = 8_192
_DIAGNOSTIC_HALF: Final = _DIAGNOSTIC_LIMIT // 2


class _Receiver(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args


class _SmokeServer(ThreadingHTTPServer):
    allow_reuse_address = False


def normalized_manifest_digest(document: Mapping[str, object]) -> str:
    """Return a platform- and runtime-neutral manifest conformance digest."""
    normalized = _normalize(document)
    encoded = json.dumps(
        normalized,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _normalize(value: object, *, parent: str | None = None) -> object:
    if isinstance(value, dict):
        mapping = cast("dict[object, object]", value)
        normalized: dict[str, object] = {}
        for raw_key, item in sorted(mapping.items(), key=lambda pair: str(pair[0])):
            key = str(raw_key)
            if key in _DYNAMIC_MANIFEST_KEYS:
                continue
            if parent == "tool" and key in _DYNAMIC_TOOL_KEYS:
                continue
            normalized[key] = _normalize(item, parent=key)
        return normalized
    if isinstance(value, list):
        return [_normalize(item, parent=parent) for item in cast("list[object]", value)]
    if isinstance(value, str):
        return value.replace("\\", "/")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError(f"manifest contains unsupported value: {type(value).__name__}")


def smoke_artifact(
    artifact: Path,
    *,
    python: str,
    exercise_runners: bool,
) -> dict[str, object]:
    """Install one wheel or sdist into a fresh environment and run locally."""
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required for package smoke tests")
    artifact = artifact.resolve(strict=True)
    artifact_digest = _file_digest(artifact)
    with tempfile.TemporaryDirectory(prefix=".smoke-package-", dir=Path.cwd()) as temporary:
        root = Path(temporary)
        environment = root / "environment"
        _run([uv, "venv", "--python", python, str(environment)])
        interpreter = _environment_executable(environment, "python")
        _run([uv, "pip", "install", "--python", str(interpreter), str(artifact)])
        command = _environment_executable(environment, "webhook-conformance")
        version = _json_command([str(command), "--json", "version"])
        if version.get("package") != "0.1.0":
            raise RuntimeError("installed package reported an unexpected version")
        project = root / "project"
        _run([str(command), "init", str(project)])
        config = project / "webhook-conformance.yaml"
        config.write_text(
            config.read_text(encoding="utf-8")
            .replace(
                "http://127.0.0.1:8000",
                f"http://127.0.0.1:{_SMOKE_PORT}",
            )
            .replace("allowed_ports: [8000]", f"allowed_ports: [{_SMOKE_PORT}]"),
            encoding="utf-8",
            newline="\n",
        )
        unsupported = project / "unsupported.yaml"
        unsupported.write_text(
            config.read_text(encoding="utf-8").replace(
                "schema_version: 1",
                "schema_version: 2",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        )
        unsupported_result = subprocess.run(
            [str(command), "run", "--config", str(unsupported)],
            cwd=project,
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            timeout=60,
        )
        if unsupported_result.returncode != _UNSUPPORTED_EXIT:
            diagnostic = unsupported_result.stderr.strip() or unsupported_result.stdout.strip()
            raise RuntimeError(
                "unsupported schema exited "
                f"{unsupported_result.returncode}, expected {_UNSUPPORTED_EXIT}: "
                f"{diagnostic[:4096]}"
            )
        if any(project.rglob("run.sqlite3")):
            raise RuntimeError("unsupported schema created a run database")
        project.joinpath(".webhook-conformance").mkdir(mode=0o700)
        environment_variables = {
            **os.environ,
            "NO_COLOR": "1",
            "WEBHOOK_TEST_SECRET": "package-smoke-local-secret",
        }
        result = _json_command(
            [
                str(command),
                "--json",
                "run",
                "--config",
                str(config),
                "--output",
                ".webhook-conformance/package-smoke",
            ],
            cwd=project,
            env=environment_variables,
        )
        if result.get("verdict") != "pass":
            raise RuntimeError("minimal local package run did not pass")
        run_directory_value = result.get("run_directory")
        if not isinstance(run_directory_value, str):
            raise RuntimeError("minimal local package run omitted run_directory")
        manifest = _json_file(Path(run_directory_value) / "run-manifest.json")
        runner_results = _exercise_ephemeral_runners(artifact) if exercise_runners else {}
        return {
            "artifact": artifact.name,
            "artifact_digest": artifact_digest,
            "manifest_digest": normalized_manifest_digest(manifest),
            "package": version["package"],
            "runners": runner_results,
            "unsupported_schema_exit": unsupported_result.returncode,
            "verdict": result["verdict"],
        }


def _exercise_ephemeral_runners(artifact: Path) -> dict[str, str]:
    results: dict[str, str] = {}
    uvx = shutil.which("uvx")
    if uvx is not None:
        document = _json_command(
            [uvx, "--from", str(artifact), "webhook-conformance", "--json", "version"]
        )
        results["uvx"] = str(document.get("package", "invalid"))
    pipx = shutil.which("pipx")
    if pipx is not None:
        document = _json_command(
            [
                pipx,
                "run",
                "--spec",
                str(artifact),
                "webhook-conformance",
                "--json",
                "version",
            ]
        )
        results["pipx"] = str(document.get("package", "invalid"))
    if not results:
        results["status"] = "no ephemeral runner available"
    if any(value not in {"0.1.0", "no ephemeral runner available"} for value in results.values()):
        raise RuntimeError("an ephemeral package runner reported an unexpected version")
    return results


def _json_command(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    completed = _run(arguments, cwd=cwd, env=env)
    document = json.loads(completed.stdout)
    if not isinstance(document, dict):
        raise RuntimeError("command did not emit one JSON object")
    return cast("dict[str, object]", document)


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(arguments),
        cwd=cwd,
        env=None if env is None else dict(env),
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=600,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip() or completed.stdout.strip()
        if len(diagnostic) > _DIAGNOSTIC_LIMIT:
            diagnostic = (
                f"{diagnostic[:_DIAGNOSTIC_HALF]}\n... diagnostic truncated ...\n"
                f"{diagnostic[-_DIAGNOSTIC_HALF:]}"
            )
        raise RuntimeError(f"command failed with exit {completed.returncode}: {diagnostic}")
    return completed


def _environment_executable(environment: Path, name: str) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / f"{name}.exe"
    return environment / "bin" / name


def _json_file(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError(f"{path.name} must contain a JSON object")
    return cast("dict[str, object]", document)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", action="append", required=True, type=Path)
    parser.add_argument("--python", default=f"{sys.version_info.major}.{sys.version_info.minor}")
    parser.add_argument("--exercise-runners", action="store_true")
    parser.add_argument("--expected-digest")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Run requested smoke checks and emit one stable JSON document."""
    options = _parser().parse_args(arguments)
    server = _SmokeServer(("127.0.0.1", _SMOKE_PORT), _Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        results = [
            smoke_artifact(
                artifact,
                python=options.python,
                exercise_runners=options.exercise_runners,
            )
            for artifact in options.artifact
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    digests = {str(result["manifest_digest"]) for result in results}
    if len(digests) != 1:
        raise RuntimeError("wheel and sdist produced different normalized manifests")
    actual_digest = next(iter(digests))
    if options.expected_digest is not None and actual_digest != options.expected_digest:
        raise RuntimeError(
            f"normalized manifest digest {actual_digest} does not match {options.expected_digest}"
        )
    print(
        json.dumps(
            {
                "artifacts": results,
                "normalized_manifest_digest": actual_digest,
                "python": options.python,
                "status": "pass",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
