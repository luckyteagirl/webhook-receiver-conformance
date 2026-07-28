"""Deterministic, offline-capable release policy and provenance checks."""
# ruff: noqa: C901, D102, EM101, EM102, INP001, PLR0911, PLR0912, PLR2004, T201, TRY003

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tomllib
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MALFORMED_INPUT: Final = 2
_POLICY_VIOLATION: Final = 3
_SEMVER: Final = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_DIGEST: Final = re.compile(r"^sha256:([0-9a-f]{64})$")
_CHANGELOG_FIELDS: Final = ("compatibility", "migration", "security", "schema")
_EXCEPTION_FIELDS: Final = frozenset({"vulnerability_id", "owner", "expires", "reason"})
_HIGH_SEVERITIES: Final = frozenset({"HIGH", "CRITICAL"})


class MalformedInputError(ValueError):
    """An input artifact does not satisfy its closed machine contract."""


class PolicyViolationError(RuntimeError):
    """A well-formed input violates release policy."""


@dataclass(frozen=True, slots=True)
class Subject:
    """A release subject identified by its publication name and SHA-256 digest."""

    name: str
    sha256: str

    @classmethod
    def from_path(cls, path: Path) -> Subject:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise MalformedInputError(f"subject is not a regular file: {path}")
        return cls(name=path.name, sha256=_file_sha256(resolved))

    @classmethod
    def from_values(cls, name: str, digest: str) -> Subject:
        if not name or any(ord(character) < 32 for character in name):
            raise MalformedInputError("subject name must be nonempty safe text")
        match = _DIGEST.fullmatch(digest)
        if match is None:
            raise MalformedInputError("subject digest must be canonical sha256:<hex>")
        return cls(name=name, sha256=match.group(1))

    @property
    def digest(self) -> str:
        return f"sha256:{self.sha256}"


@dataclass(frozen=True, slots=True)
class VulnerabilityException:
    """A time-bounded approval for one vulnerability identifier."""

    vulnerability_id: str
    owner: str
    expires: date
    reason: str


def load_exceptions(path: Path, *, as_of: date) -> dict[str, VulnerabilityException]:
    """Load the closed exception contract and reject expired approvals."""
    document = _json_object(path)
    if set(document) != {"schema_version", "exceptions"}:
        raise MalformedInputError(
            "exception file fields must be exactly schema_version and exceptions"
        )
    if document["schema_version"] != 1:
        raise MalformedInputError("exception file schema_version must be 1")
    entries = document["exceptions"]
    if not isinstance(entries, list):
        raise MalformedInputError("exceptions must be an array")
    approved: dict[str, VulnerabilityException] = {}
    for index, raw in enumerate(cast("list[object]", entries)):
        if not isinstance(raw, dict):
            raise MalformedInputError(f"exceptions[{index}] must be an object")
        entry = cast("dict[object, object]", raw)
        if set(entry) != _EXCEPTION_FIELDS:
            raise MalformedInputError(
                f"exceptions[{index}] fields must be exactly "
                "vulnerability_id, owner, expires, and reason"
            )
        vulnerability_id = _required_text(
            entry["vulnerability_id"], f"exceptions[{index}].vulnerability_id"
        ).upper()
        owner = _required_text(entry["owner"], f"exceptions[{index}].owner")
        reason = _required_text(entry["reason"], f"exceptions[{index}].reason")
        expiry = _iso_date(entry["expires"], f"exceptions[{index}].expires")
        if expiry < as_of:
            raise PolicyViolationError(
                f"exception {vulnerability_id} owned by {owner} expired on {expiry}"
            )
        if vulnerability_id in approved:
            raise MalformedInputError(f"duplicate vulnerability exception: {vulnerability_id}")
        approved[vulnerability_id] = VulnerabilityException(
            vulnerability_id=vulnerability_id,
            owner=owner,
            expires=expiry,
            reason=reason,
        )
    return approved


def check_release_policy(
    *,
    version: str,
    project: Path,
    changelog: Path,
    exceptions: Path,
    as_of: date,
) -> dict[str, object]:
    """Validate the release version, changelog entry, and exception contract."""
    if _SEMVER.fullmatch(version) is None:
        raise PolicyViolationError(f"release version is not canonical SemVer: {version}")
    project_document = _toml_object(project)
    project_table = project_document.get("project")
    if not isinstance(project_table, dict):
        raise MalformedInputError("pyproject.toml is missing [project]")
    package_version = project_table.get("version")
    if package_version != version:
        raise PolicyViolationError(
            f"release version {version} does not match project version {package_version!r}"
        )
    changelog_text = changelog.read_text(encoding="utf-8")
    entry = _changelog_entry(changelog_text, version)
    missing = [field for field in _CHANGELOG_FIELDS if field not in entry.casefold()]
    if missing:
        raise PolicyViolationError(f"changelog entry {version} does not name: {', '.join(missing)}")
    approved = load_exceptions(exceptions, as_of=as_of)
    return {
        "approved_exception_count": len(approved),
        "changelog_fields": list(_CHANGELOG_FIELDS),
        "status": "pass",
        "version": version,
    }


def check_vulnerability_reports(
    reports: Sequence[Path],
    *,
    exceptions: Path,
    as_of: date,
) -> dict[str, object]:
    """Reject unapproved HIGH or CRITICAL findings in Trivy or pip-audit JSON."""
    approved = load_exceptions(exceptions, as_of=as_of)
    findings: dict[str, str] = {}
    for report in reports:
        for vulnerability_id, severity in _vulnerabilities(_json_value(report)):
            normalized_id = vulnerability_id.upper()
            normalized_severity = severity.upper()
            if normalized_severity in _HIGH_SEVERITIES:
                findings[normalized_id] = normalized_severity
    unapproved = sorted(set(findings).difference(approved))
    if unapproved:
        details = ", ".join(f"{item} ({findings[item]})" for item in unapproved)
        raise PolicyViolationError(f"unapproved high-severity vulnerabilities: {details}")
    used = sorted(set(findings).intersection(approved))
    return {
        "approved_findings": used,
        "high_severity_finding_count": len(findings),
        "report_count": len(reports),
        "status": "pass",
    }


def make_spdx(subject: Subject, *, lockfile: Path) -> dict[str, object]:
    """Create a deterministic SPDX 2.3 inventory rooted at one release subject."""
    lock = _toml_object(lockfile)
    raw_packages = lock.get("package")
    if not isinstance(raw_packages, list):
        raise MalformedInputError("uv.lock must contain [[package]] entries")
    packages: list[dict[str, object]] = []
    relationships: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in cast("list[object]", raw_packages):
        if not isinstance(raw, dict):
            raise MalformedInputError("uv.lock package entry must be a table")
        package = cast("dict[object, object]", raw)
        name = _required_text(package.get("name"), "uv.lock package.name")
        version = _required_text(package.get("version"), f"uv.lock package {name}.version")
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        spdx_id = _spdx_package_id(name, version)
        packages.append(
            {
                "SPDXID": spdx_id,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "name": name,
                "versionInfo": version,
            }
        )
        relationships.append(
            {
                "relatedSpdxElement": spdx_id,
                "relationshipType": "DEPENDS_ON",
                "spdxElementId": "SPDXRef-ReleaseSubject",
            }
        )
    namespace_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"webhook-receiver-conformance:{subject.name}:{subject.sha256}",
    )
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": _spdx_created(),
            "creators": ["Tool: scripts/release_check.py"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": ["SPDXRef-ReleaseSubject"],
        "documentNamespace": f"urn:uuid:{namespace_id}",
        "files": [
            {
                "SPDXID": "SPDXRef-ReleaseSubject",
                "checksums": [{"algorithm": "SHA256", "checksumValue": subject.sha256}],
                "fileName": subject.name,
            }
        ],
        "name": f"{subject.name}-sbom",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }


def make_statement(subject: Subject) -> dict[str, object]:
    """Create a deterministic in-toto/SLSA statement for local digest validation."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": ("https://github.com/webhook-receiver-conformance/release-check@v1"),
                "externalParameters": {},
                "internalParameters": {},
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {"id": "scripts/release_check.py"},
                "metadata": {"invocationId": subject.sha256},
            },
        },
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"digest": {"sha256": subject.sha256}, "name": subject.name}],
    }


def verify_subject(
    subject: Subject,
    *,
    sbom: Path,
    attestation: Path,
) -> dict[str, object]:
    """Verify the exact subject name and digest in an SBOM and attestation."""
    sbom_document = _json_object(sbom)
    if not _sbom_has_subject(sbom_document, subject):
        raise PolicyViolationError(f"SBOM does not identify {subject.name} at {subject.digest}")
    attestation_document = _json_object(attestation)
    if not _attestation_has_subject(attestation_document, subject):
        raise PolicyViolationError(
            f"attestation does not identify {subject.name} at {subject.digest}"
        )
    return {"status": "pass", "subject": subject.name, "subject_digest": subject.digest}


def _sbom_has_subject(document: Mapping[str, object], subject: Subject) -> bool:
    if document.get("spdxVersion") in {"SPDX-2.2", "SPDX-2.3"}:
        files = document.get("files")
        if not isinstance(files, list):
            return False
        for raw in cast("list[object]", files):
            if not isinstance(raw, dict):
                continue
            item = cast("dict[object, object]", raw)
            if item.get("fileName") != subject.name:
                continue
            checksums = item.get("checksums")
            if isinstance(checksums, list) and any(
                isinstance(checksum, dict)
                and checksum.get("algorithm") == "SHA256"
                and str(checksum.get("checksumValue", "")).lower() == subject.sha256
                for checksum in cast("list[object]", checksums)
            ):
                return True
        return False
    if document.get("bomFormat") == "CycloneDX":
        metadata = document.get("metadata")
        if not isinstance(metadata, dict):
            return False
        component = cast("dict[object, object]", metadata).get("component")
        if not isinstance(component, dict):
            return False
        component_table = cast("dict[object, object]", component)
        if component_table.get("name") != subject.name:
            return False
        hashes = component_table.get("hashes")
        return isinstance(hashes, list) and any(
            isinstance(item, dict)
            and item.get("alg") == "SHA-256"
            and str(item.get("content", "")).lower() == subject.sha256
            for item in cast("list[object]", hashes)
        )
    raise MalformedInputError("SBOM must be SPDX 2.2/2.3 or CycloneDX")


def _attestation_has_subject(document: Mapping[str, object], subject: Subject) -> bool:
    subjects = document.get("subject")
    if not isinstance(subjects, list):
        raise MalformedInputError("attestation subject must be an array")
    return any(
        isinstance(raw, dict)
        and raw.get("name") == subject.name
        and isinstance(raw.get("digest"), dict)
        and cast("dict[object, object]", raw["digest"]).get("sha256") == subject.sha256
        for raw in cast("list[object]", subjects)
    )


def _vulnerabilities(document: object) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if not isinstance(document, dict):
        raise MalformedInputError("vulnerability report must be a JSON object")
    table = cast("dict[object, object]", document)
    if isinstance(table.get("Results"), list):
        for result in cast("list[object]", table["Results"]):
            if not isinstance(result, dict):
                continue
            vulnerabilities = cast("dict[object, object]", result).get("Vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                continue
            for raw in cast("list[object]", vulnerabilities):
                if not isinstance(raw, dict):
                    continue
                item = cast("dict[object, object]", raw)
                vulnerability_id = item.get("VulnerabilityID")
                severity = item.get("Severity")
                if isinstance(vulnerability_id, str) and isinstance(severity, str):
                    findings.append((vulnerability_id, severity))
        return findings
    if isinstance(table.get("dependencies"), list):
        for dependency in cast("list[object]", table["dependencies"]):
            if not isinstance(dependency, dict):
                continue
            vulnerabilities = cast("dict[object, object]", dependency).get("vulns", [])
            if not isinstance(vulnerabilities, list):
                continue
            for raw in cast("list[object]", vulnerabilities):
                if isinstance(raw, dict) and isinstance(raw.get("id"), str):
                    # pip-audit reports only known vulnerabilities and does not carry
                    # CVSS severity. Its release-action producer must enrich severity;
                    # absent severity is conservatively classified as HIGH.
                    severity = raw.get("severity", "HIGH")
                    if isinstance(severity, str):
                        findings.append((str(raw["id"]), severity))
        return findings
    raise MalformedInputError("unsupported vulnerability report format")


def _changelog_entry(text: str, version: str) -> str:
    heading = re.compile(
        rf"(?m)^##[ \t]+(?:\[{re.escape(version)}\]|{re.escape(version)})"
        r"(?:[ \t]+.*)?$"
    )
    match = heading.search(text)
    if match is None:
        raise PolicyViolationError(f"CHANGELOG.md has no entry for {version}")
    next_heading = re.search(r"(?m)^##[ \t]+", text[match.end() :])
    end = len(text) if next_heading is None else match.end() + next_heading.start()
    return text[match.start() : end]


def _spdx_package_id(name: str, version: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9.-]", "-", name)
    identifier = hashlib.sha256(f"{name}\0{version}".encode()).hexdigest()[:12]
    return f"SPDXRef-Package-{safe_name}-{identifier}"


def _spdx_created() -> str:
    epoch_text = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(epoch_text)
        created = datetime.fromtimestamp(epoch, tz=UTC)
    except (OverflowError, ValueError) as error:
        raise MalformedInputError("SOURCE_DATE_EPOCH must be a valid integer") from error
    return created.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MalformedInputError(f"{field} must be nonempty text")
    if len(value) > 1000 or any(ord(character) < 32 for character in value):
        raise MalformedInputError(f"{field} must be bounded safe text")
    return value.strip()


def _iso_date(value: object, field: str) -> date:
    if not isinstance(value, str):
        raise MalformedInputError(f"{field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise MalformedInputError(f"{field} must be an ISO date") from error


def _json_value(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MalformedInputError(f"cannot read JSON from {path}: {error}") from error


def _json_object(path: Path) -> dict[str, object]:
    document = _json_value(path)
    if not isinstance(document, dict):
        raise MalformedInputError(f"{path} must contain a JSON object")
    return cast("dict[str, object]", document)


def _toml_object(path: Path) -> dict[str, object]:
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise MalformedInputError(f"cannot read TOML from {path}: {error}") from error
    return cast("dict[str, object]", document)


def _write_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _subject_from_options(options: argparse.Namespace) -> Subject:
    if options.subject is not None:
        return Subject.from_path(cast("Path", options.subject))
    if options.subject_name is None or options.subject_digest is None:
        raise MalformedInputError("provide --subject or both --subject-name and --subject-digest")
    return Subject.from_values(options.subject_name, options.subject_digest)


def _add_subject_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--subject", type=Path)
    group.add_argument("--subject-name")
    parser.add_argument("--subject-digest")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    policy = subparsers.add_parser("policy", help="check version and release policy")
    policy.add_argument("--version", required=True)
    policy.add_argument("--project", type=Path, default=Path("pyproject.toml"))
    policy.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    policy.add_argument("--exceptions", type=Path, required=True)
    policy.add_argument(
        "--as-of",
        type=date.fromisoformat,
        default=datetime.now(tz=UTC).date(),
    )

    scan = subparsers.add_parser("scan", help="apply expiring vulnerability exceptions")
    scan.add_argument("--report", action="append", type=Path, required=True)
    scan.add_argument("--exceptions", type=Path, required=True)
    scan.add_argument(
        "--as-of",
        type=date.fromisoformat,
        default=datetime.now(tz=UTC).date(),
    )

    sbom = subparsers.add_parser("sbom", help="create an SPDX release SBOM")
    _add_subject_arguments(sbom)
    sbom.add_argument("--lockfile", type=Path, default=Path("uv.lock"))
    sbom.add_argument("--output", type=Path, required=True)

    statement = subparsers.add_parser(
        "statement", help="create a local digest-verification statement"
    )
    _add_subject_arguments(statement)
    statement.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="verify subject digest in SBOM and attestation")
    _add_subject_arguments(verify)
    verify.add_argument("--sbom", type=Path, required=True)
    verify.add_argument("--attestation", type=Path, required=True)
    return parser


def _execute(options: argparse.Namespace) -> dict[str, object]:
    if options.command == "policy":
        return check_release_policy(
            version=options.version,
            project=options.project,
            changelog=options.changelog,
            exceptions=options.exceptions,
            as_of=options.as_of,
        )
    if options.command == "scan":
        return check_vulnerability_reports(
            options.report,
            exceptions=options.exceptions,
            as_of=options.as_of,
        )
    subject = _subject_from_options(options)
    if options.command == "sbom":
        document = make_spdx(subject, lockfile=options.lockfile)
        _write_json(options.output, document)
        return {"output": str(options.output), "status": "pass", "subject": subject.name}
    if options.command == "statement":
        _write_json(options.output, make_statement(subject))
        return {"output": str(options.output), "status": "pass", "subject": subject.name}
    if options.command == "verify":
        return verify_subject(
            subject,
            sbom=options.sbom,
            attestation=options.attestation,
        )
    raise AssertionError(f"unhandled command: {options.command}")


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one check and emit a stable machine-readable result."""
    try:
        result = _execute(_parser().parse_args(arguments))
    except MalformedInputError as error:
        print(
            json.dumps(
                {"classification": "malformed_input", "message": str(error), "status": "fail"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return _MALFORMED_INPUT
    except (OSError, UnicodeError) as error:
        print(
            json.dumps(
                {"classification": "malformed_input", "message": str(error), "status": "fail"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return _MALFORMED_INPUT
    except PolicyViolationError as error:
        print(
            json.dumps(
                {
                    "classification": "policy_violation",
                    "message": str(error),
                    "status": "fail",
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return _POLICY_VIOLATION
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
