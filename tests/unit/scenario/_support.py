"""Test builders for strict scenario semantic-validation inputs."""
# ruff: noqa: INP001, PLR0913, TC001

from __future__ import annotations

from webhook_receiver_conformance.config.models import ProjectConfig
from webhook_receiver_conformance.scenario.models import ScenarioValidationResult

type ConfigObject = dict[str, object]


def make_scenario(
    scenario_id: str = "baseline",
    *,
    events: list[ConfigObject] | None = None,
    steps: list[ConfigObject] | None = None,
    assertions: list[ConfigObject] | None = None,
    mutations: list[ConfigObject] | None = None,
    signer: str | None = "generic",
    count: int = 1,
    concurrency_group: str | None = None,
    retry: ConfigObject | None = None,
    baselines: list[ConfigObject] | None = None,
    description: str | None = None,
) -> ConfigObject:
    """Build one structurally valid scenario dictionary."""
    scenario_events = [{"id": "event", "fixture": "payload"}] if events is None else events
    if steps is None:
        deliver: ConfigObject = {"event": str(scenario_events[0]["id"]), "count": count}
        if signer is not None:
            deliver["signer"] = signer
        if mutations is not None:
            deliver["mutations"] = mutations
        if concurrency_group is not None:
            deliver["concurrency_group"] = concurrency_group
        if retry is not None:
            deliver["retry"] = retry
        scenario_steps: list[ConfigObject] = [{"deliver": deliver}]
        if concurrency_group is not None:
            scenario_steps.append({"barrier": concurrency_group})
    else:
        scenario_steps = steps
    scenario_assertions = (
        [
            {
                "id": "status",
                "type": "http-status",
                "attempt": {"event": str(scenario_events[0]["id"]), "mode": "all-terminal"},
                "expected": {"classes": ["2xx"]},
            }
        ]
        if assertions is None
        else assertions
    )
    result: ConfigObject = {
        "id": scenario_id,
        "events": scenario_events,
        "steps": scenario_steps,
        "assertions": scenario_assertions,
    }
    if baselines is not None:
        result["baselines"] = baselines
    if description is not None:
        result["description"] = description
    return result


def make_project(
    scenarios: list[ConfigObject],
    *,
    fixtures: list[ConfigObject] | None = None,
    fixture_media_type: str = "application/octet-stream",
    signers: ConfigObject | None = None,
    observers: ConfigObject | None = None,
    lifecycles: ConfigObject | None = None,
    max_events: int = 1000,
    max_attempts: int = 5000,
    max_request_bytes: int = 1_048_576,
) -> ProjectConfig:
    """Build a strict immutable ProjectConfig around supplied scenarios."""
    fixture_values = (
        [
            {
                "id": "payload",
                "path": "fixtures/payload.bin",
                "media_type": fixture_media_type,
            }
        ]
        if fixtures is None
        else fixtures
    )
    signer_values: ConfigObject = (
        {
            "generic": {
                "profile": "generic-hmac-sha256",
                "secret": {"generated": "hmac-256"},
                "header_name": "X-Test-Signature",
            }
        }
        if signers is None
        else signers
    )
    return ProjectConfig.model_validate(
        {
            "schema_version": 1,
            "project": {
                "name": "semantic-validation-test",
                "artifact_directory": ".artifacts",
            },
            "receiver": {
                "url": "http://127.0.0.1:8000/webhooks",
                "target_profile": "loopback",
                "timeouts": {
                    "connect": "1s",
                    "write": "1s",
                    "read": "1s",
                    "pool": "1s",
                    "total": "5s",
                },
            },
            "fixtures": fixture_values,
            "signers": signer_values,
            "observers": {} if observers is None else observers,
            "lifecycles": {} if lifecycles is None else lifecycles,
            "clock": {"mode": "real"},
            "limits": {
                "max_events": max_events,
                "max_attempts": max_attempts,
                "max_concurrency": 10,
                "max_request_bytes": max_request_bytes,
                "max_response_capture_bytes": 65_536,
            },
            "scenarios": scenarios,
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


def diagnostic_codes(result: ScenarioValidationResult) -> list[str]:
    """Extract codes from a validation result while keeping call sites concise."""
    return [str(diagnostic.code) for diagnostic in result.diagnostics]
