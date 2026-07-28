"""Deterministic, offline-capable release policy and provenance checks."""
# ruff: noqa: C901, D102, EM101, EM102, INP001, PLR0911, PLR0912, PLR0915, PLR2004, T201, TRY003

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
_LICENSE_POLICY_FIELDS: Final = frozenset(
    {
        "allowed_license_expressions",
        "build_requirements",
        "denied_license_expressions",
        "lockfile_sha256",
        "packages",
        "schema_version",
        "unknown_license_action",
    }
)
_LICENSE_PACKAGE_FIELDS: Final = frozenset(
    {"evidence", "license_expression", "name", "scopes", "version"}
)
_LICENSE_BUILD_FIELDS: Final = frozenset(
    {"evidence", "license_expression", "lock_status", "name", "requirement"}
)
_LICENSE_SCOPES: Final = frozenset({"build", "dev", "reference", "runtime"})
_BUILD_LOCK_STATUSES: Final = frozenset({"absent-from-lock", "present-in-lock"})
_REQUIREMENT_NAME: Final = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")


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


def check_license_policy(
    *,
    lockfile: Path,
    project: Path,
    policy: Path,
) -> dict[str, object]:
    """Validate the closed offline license inventory against the exact uv lock."""
    document = _json_object(policy)
    if set(document) != _LICENSE_POLICY_FIELDS:
        raise MalformedInputError(
            "license policy fields must be exactly allowed_license_expressions, "
            "build_requirements, denied_license_expressions, lockfile_sha256, packages, "
            "schema_version, and unknown_license_action"
        )
    if document["schema_version"] != 1:
        raise MalformedInputError("license policy schema_version must be 1")
    unknown_action = document["unknown_license_action"]
    if unknown_action != "deny":
        raise MalformedInputError("license policy unknown_license_action must be deny")
    expected_lock_digest = _required_text(
        document["lockfile_sha256"],
        "license policy lockfile_sha256",
    )
    if not re.fullmatch(r"[0-9a-f]{64}", expected_lock_digest):
        raise MalformedInputError("license policy lockfile_sha256 must be lowercase SHA-256")
    actual_lock_digest = _file_sha256(lockfile)
    if expected_lock_digest != actual_lock_digest:
        raise PolicyViolationError("license inventory does not identify the current uv.lock digest")

    allowed = frozenset(
        _sorted_unique_text_list(
            document["allowed_license_expressions"],
            "license policy allowed_license_expressions",
        )
    )
    denied = frozenset(
        _sorted_unique_text_list(
            document["denied_license_expressions"],
            "license policy denied_license_expressions",
        )
    )
    overlap = sorted(allowed.intersection(denied))
    if overlap:
        raise MalformedInputError(f"license allowlist and denylist overlap: {', '.join(overlap)}")

    locked_scopes, locked_names = _locked_dependency_scopes(
        lockfile=lockfile,
        project=project,
    )
    package_entries = _license_package_entries(document["packages"])
    missing = sorted(set(locked_scopes).difference(package_entries))
    extra = sorted(set(package_entries).difference(locked_scopes))
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(
                "missing " + ", ".join(f"{name}=={version}" for name, version in missing)
            )
        if extra:
            details.append(
                "not locked " + ", ".join(f"{name}=={version}" for name, version in extra)
            )
        raise PolicyViolationError("license package inventory mismatch: " + "; ".join(details))

    denied_packages: list[str] = []
    unknown_packages: list[str] = []
    inventory: list[dict[str, object]] = []
    scope_counts = dict.fromkeys(sorted(_LICENSE_SCOPES), 0)
    for key in sorted(locked_scopes):
        entry = package_entries[key]
        expression = cast("str", entry["license_expression"])
        classification = _license_classification(expression, allowed=allowed, denied=denied)
        label = f"{key[0]}=={key[1]} ({expression})"
        if classification == "denied":
            denied_packages.append(label)
        elif classification == "unknown":
            unknown_packages.append(label)
        scopes = cast("tuple[str, ...]", entry["scopes"])
        expected_scopes = locked_scopes[key]
        if scopes != expected_scopes:
            raise PolicyViolationError(
                f"license scopes for {key[0]}=={key[1]} are {list(scopes)!r}; "
                f"expected {list(expected_scopes)!r}"
            )
        for scope in scopes:
            scope_counts[scope] += 1
        inventory.append(
            {
                "evidence": entry["evidence"],
                "license_expression": expression,
                "name": key[0],
                "scopes": list(scopes),
                "status": classification,
                "version": key[1],
            }
        )

    build_inventory = _license_build_entries(
        document["build_requirements"],
        project=project,
        locked_names=locked_names,
    )
    for entry in build_inventory:
        expression = cast("str", entry["license_expression"])
        classification = _license_classification(expression, allowed=allowed, denied=denied)
        label = f"{entry['requirement']} ({expression})"
        if classification == "denied":
            denied_packages.append(label)
        elif classification == "unknown":
            unknown_packages.append(label)
        entry["status"] = classification

    if denied_packages:
        raise PolicyViolationError(
            "denied dependency licenses: " + ", ".join(sorted(denied_packages))
        )
    if unknown_packages:
        raise PolicyViolationError(
            "unknown dependency licenses are denied: " + ", ".join(sorted(unknown_packages))
        )
    return {
        "allowed_license_expressions": sorted(allowed),
        "build_requirements": build_inventory,
        "denied_license_expressions": sorted(denied),
        "lockfile_sha256": actual_lock_digest,
        "package_count": len(inventory),
        "packages": inventory,
        "scope_counts": scope_counts,
        "status": "pass",
        "unknown_license_action": unknown_action,
        "unlocked_build_requirement_count": sum(
            entry["lock_status"] == "absent-from-lock" for entry in build_inventory
        ),
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


def _locked_dependency_scopes(
    *,
    lockfile: Path,
    project: Path,
) -> tuple[dict[tuple[str, str], tuple[str, ...]], frozenset[str]]:
    lock = _toml_object(lockfile)
    raw_packages = lock.get("package")
    if not isinstance(raw_packages, list):
        raise MalformedInputError("uv.lock must contain [[package]] entries")
    packages: dict[tuple[str, str], dict[object, object]] = {}
    by_name: dict[str, list[tuple[str, str]]] = {}
    root: dict[object, object] | None = None
    for index, raw in enumerate(cast("list[object]", raw_packages)):
        if not isinstance(raw, dict):
            raise MalformedInputError(f"uv.lock package[{index}] must be a table")
        package = cast("dict[object, object]", raw)
        name = _normalized_package_name(
            _required_text(package.get("name"), f"uv.lock package[{index}].name")
        )
        version = _required_text(package.get("version"), f"uv.lock package {name}.version")
        key = (name, version)
        if key in packages:
            raise MalformedInputError(f"duplicate uv.lock package: {name}=={version}")
        packages[key] = package
        by_name.setdefault(name, []).append(key)
        source = package.get("source")
        if isinstance(source, dict) and cast("dict[object, object]", source).get("editable") == ".":
            if root is not None:
                raise MalformedInputError("uv.lock contains multiple editable root packages")
            root = package
    if root is None:
        raise MalformedInputError("uv.lock is missing the editable project root package")
    root_key = (
        _normalized_package_name(_required_text(root.get("name"), "uv.lock root package.name")),
        _required_text(root.get("version"), "uv.lock root package.version"),
    )
    external = set(packages).difference({root_key})
    scopes: dict[tuple[str, str], set[str]] = {key: set() for key in external}

    seeds: dict[str, list[dict[object, object]]] = {
        "runtime": _dependency_tables(root.get("dependencies", []), "root dependencies"),
        "reference": _group_dependency_tables(
            root.get("optional-dependencies", {}),
            "root optional-dependencies",
        ),
        "dev": _group_dependency_tables(
            root.get("dev-dependencies", {}),
            "root dev-dependencies",
        ),
        "build": [],
    }
    project_document = _toml_object(project)
    build_system = project_document.get("build-system")
    if not isinstance(build_system, dict):
        raise MalformedInputError("pyproject.toml is missing [build-system]")
    for requirement in _sorted_unique_text_list(
        cast("dict[object, object]", build_system).get("requires"),
        "build-system.requires",
        require_sorted=False,
    ):
        name = _requirement_package_name(requirement)
        candidates = by_name.get(name, [])
        if len(candidates) == 1:
            seeds["build"].append({"name": name, "version": candidates[0][1]})
        elif len(candidates) > 1:
            raise MalformedInputError(
                f"build requirement {requirement} matches multiple locked versions"
            )

    for scope, dependencies in seeds.items():
        pending = [_resolve_locked_dependency(item, by_name) for item in dependencies]
        while pending:
            key = pending.pop()
            if key not in external:
                raise MalformedInputError(
                    f"uv.lock dependency resolves outside external package set: {key[0]}=={key[1]}"
                )
            if scope in scopes[key]:
                continue
            scopes[key].add(scope)
            pending.extend(
                _resolve_locked_dependency(item, by_name)
                for item in _dependency_tables(
                    packages[key].get("dependencies", []),
                    f"uv.lock package {key[0]} dependencies",
                )
            )
    unreachable = sorted(key for key, values in scopes.items() if not values)
    if unreachable:
        raise PolicyViolationError(
            "uv.lock contains dependencies unreachable from runtime, reference, dev, or build "
            "roots: " + ", ".join(f"{name}=={version}" for name, version in unreachable)
        )
    return (
        {key: tuple(sorted(values)) for key, values in scopes.items()},
        frozenset(by_name),
    )


def _dependency_tables(value: object, field: str) -> list[dict[object, object]]:
    if not isinstance(value, list):
        raise MalformedInputError(f"{field} must be an array")
    result: list[dict[object, object]] = []
    for index, raw in enumerate(cast("list[object]", value)):
        if not isinstance(raw, dict):
            raise MalformedInputError(f"{field}[{index}] must be a table")
        result.append(cast("dict[object, object]", raw))
    return result


def _group_dependency_tables(value: object, field: str) -> list[dict[object, object]]:
    if not isinstance(value, dict):
        raise MalformedInputError(f"{field} must be a table")
    dependencies: list[dict[object, object]] = []
    for group, raw in cast("dict[object, object]", value).items():
        if not isinstance(group, str):
            raise MalformedInputError(f"{field} group names must be text")
        dependencies.extend(_dependency_tables(raw, f"{field}.{group}"))
    return dependencies


def _resolve_locked_dependency(
    dependency: Mapping[object, object],
    by_name: Mapping[str, list[tuple[str, str]]],
) -> tuple[str, str]:
    name = _normalized_package_name(
        _required_text(dependency.get("name"), "uv.lock dependency.name")
    )
    version = dependency.get("version")
    if version is not None:
        key = (name, _required_text(version, f"uv.lock dependency {name}.version"))
        if key not in by_name.get(name, []):
            raise MalformedInputError(f"uv.lock dependency does not resolve: {key[0]}=={key[1]}")
        return key
    candidates = by_name.get(name, [])
    if len(candidates) != 1:
        raise MalformedInputError(f"uv.lock dependency {name} requires an exact version to resolve")
    return candidates[0]


def _license_package_entries(
    value: object,
) -> dict[tuple[str, str], dict[str, object]]:
    if not isinstance(value, list):
        raise MalformedInputError("license policy packages must be an array")
    entries: dict[tuple[str, str], dict[str, object]] = {}
    for index, raw in enumerate(cast("list[object]", value)):
        if not isinstance(raw, dict):
            raise MalformedInputError(f"license policy packages[{index}] must be an object")
        item = cast("dict[object, object]", raw)
        if set(item) != _LICENSE_PACKAGE_FIELDS:
            raise MalformedInputError(
                f"license policy packages[{index}] fields must be exactly evidence, "
                "license_expression, name, scopes, and version"
            )
        raw_name = _required_text(item["name"], f"license policy packages[{index}].name")
        name = _normalized_package_name(raw_name)
        if raw_name != name:
            raise MalformedInputError(
                f"license policy packages[{index}].name must use normalized package spelling"
            )
        version = _required_text(item["version"], f"license policy packages[{index}].version")
        scopes = _sorted_unique_text_list(
            item["scopes"],
            f"license policy packages[{index}].scopes",
        )
        if not scopes or not set(scopes).issubset(_LICENSE_SCOPES):
            raise MalformedInputError(
                f"license policy packages[{index}].scopes contains an unsupported scope"
            )
        key = (name, version)
        if key in entries:
            raise MalformedInputError(f"duplicate license inventory package: {name}=={version}")
        entries[key] = {
            "evidence": _required_text(
                item["evidence"],
                f"license policy packages[{index}].evidence",
            ),
            "license_expression": _required_text(
                item["license_expression"],
                f"license policy packages[{index}].license_expression",
            ),
            "scopes": tuple(scopes),
        }
    sorted_keys = list(entries)
    if sorted_keys != sorted(sorted_keys):
        raise MalformedInputError("license policy packages must be sorted by name and version")
    return entries


def _license_build_entries(
    value: object,
    *,
    project: Path,
    locked_names: frozenset[str],
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise MalformedInputError("license policy build_requirements must be an array")
    project_document = _toml_object(project)
    build_system = project_document.get("build-system")
    if not isinstance(build_system, dict):
        raise MalformedInputError("pyproject.toml is missing [build-system]")
    declared = _sorted_unique_text_list(
        cast("dict[object, object]", build_system).get("requires"),
        "build-system.requires",
        require_sorted=False,
    )
    entries: list[dict[str, object]] = []
    for index, raw in enumerate(cast("list[object]", value)):
        if not isinstance(raw, dict):
            raise MalformedInputError(
                f"license policy build_requirements[{index}] must be an object"
            )
        item = cast("dict[object, object]", raw)
        if set(item) != _LICENSE_BUILD_FIELDS:
            raise MalformedInputError(
                f"license policy build_requirements[{index}] fields must be exactly evidence, "
                "license_expression, lock_status, name, and requirement"
            )
        requirement = _required_text(
            item["requirement"],
            f"license policy build_requirements[{index}].requirement",
        )
        name = _normalized_package_name(
            _required_text(
                item["name"],
                f"license policy build_requirements[{index}].name",
            )
        )
        if name != _requirement_package_name(requirement):
            raise MalformedInputError(
                f"license policy build requirement {requirement} has mismatched name {name}"
            )
        lock_status = _required_text(
            item["lock_status"],
            f"license policy build_requirements[{index}].lock_status",
        )
        if lock_status not in _BUILD_LOCK_STATUSES:
            raise MalformedInputError(
                f"license policy build_requirements[{index}].lock_status is unsupported"
            )
        actual_status = "present-in-lock" if name in locked_names else "absent-from-lock"
        if lock_status != actual_status:
            raise PolicyViolationError(
                f"build requirement {requirement} lock status is {actual_status}, "
                f"inventory records {lock_status}"
            )
        entries.append(
            {
                "evidence": _required_text(
                    item["evidence"],
                    f"license policy build_requirements[{index}].evidence",
                ),
                "license_expression": _required_text(
                    item["license_expression"],
                    f"license policy build_requirements[{index}].license_expression",
                ),
                "lock_status": lock_status,
                "name": name,
                "requirement": requirement,
            }
        )
    requirements = [cast("str", entry["requirement"]) for entry in entries]
    if requirements != sorted(requirements):
        raise MalformedInputError("license policy build_requirements must be sorted by requirement")
    if requirements != sorted(declared):
        raise PolicyViolationError(
            "license build requirement inventory does not match build-system.requires"
        )
    return entries


def _license_classification(
    expression: str,
    *,
    allowed: frozenset[str],
    denied: frozenset[str],
) -> str:
    if expression in denied:
        return "denied"
    if expression in allowed:
        return "allowed"
    return "unknown"


def _sorted_unique_text_list(
    value: object,
    field: str,
    *,
    require_sorted: bool = True,
) -> list[str]:
    if not isinstance(value, list):
        raise MalformedInputError(f"{field} must be an array")
    result = [
        _required_text(item, f"{field}[{index}]")
        for index, item in enumerate(cast("list[object]", value))
    ]
    if len(result) != len(set(result)):
        raise MalformedInputError(f"{field} must not contain duplicates")
    if require_sorted and result != sorted(result):
        raise MalformedInputError(f"{field} must be sorted")
    return result


def _normalized_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _requirement_package_name(requirement: str) -> str:
    match = _REQUIREMENT_NAME.match(requirement)
    if match is None:
        raise MalformedInputError(f"cannot identify build requirement name: {requirement}")
    return _normalized_package_name(match.group())


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

    licenses = subparsers.add_parser(
        "licenses",
        help="enforce the offline locked-dependency license inventory",
    )
    licenses.add_argument("--lockfile", type=Path, default=Path("uv.lock"))
    licenses.add_argument("--project", type=Path, default=Path("pyproject.toml"))
    licenses.add_argument(
        "--policy",
        type=Path,
        default=Path("validation/dependency-license-policy.json"),
    )
    licenses.add_argument("--output", type=Path)

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
    if options.command == "licenses":
        result = check_license_policy(
            lockfile=options.lockfile,
            project=options.project,
            policy=options.policy,
        )
        if options.output is not None:
            _write_json(options.output, result)
        return result
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
