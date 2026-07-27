"""Authenticated HTTP observer over the guarded pinned transport."""
# ruff: noqa: BLE001, C901, D107, EM101, INP001, PLR0912, PLR2004, TRY003

from __future__ import annotations

from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

import anyio

from webhook_receiver_conformance.config.models import HttpObserverConfig
from webhook_receiver_conformance.errors import Diagnostic, ErrorCategory, ResultCategory
from webhook_receiver_conformance.http.evidence import AttemptErrorCode, AttemptOutcome, HeaderOwner
from webhook_receiver_conformance.http.executor import (
    HttpAttemptCommand,
    HttpAttemptExecutor,
    HttpHeader,
)
from webhook_receiver_conformance.network.policy import (
    DestinationPolicy,
    validate_destination_policy,
)
from webhook_receiver_conformance.observers.protocol import (
    HTTP_CAPABILITIES_PATH,
    HTTP_OBSERVE_PATH,
    MAX_OBSERVER_MESSAGE_BYTES,
    BuiltinObserverKind,
    Observer,
    ObserverOperation,
    ObserverRequest,
    ObserverResponse,
    canonical_observer_wire_bytes,
    parse_observer_response,
    validate_response_for_request,
)
from webhook_receiver_conformance.secrets import SecretHandle
from webhook_receiver_conformance.types import DiagnosticCode

_NANOSECONDS_PER_SECOND: Final = 1_000_000_000
_JSON_MEDIA_TYPE: Final = "application/json"
_REDIRECT_STATUSES: Final = frozenset(range(301, 309))


class HttpProbeObserverError(RuntimeError):
    """Secret-safe classified HTTP observer failure."""

    diagnostic: Diagnostic

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.code)


@dataclass(frozen=True, slots=True)
class HttpProbePolicies:
    """Separately authorized endpoint policies."""

    capabilities: DestinationPolicy
    observe: DestinationPolicy


class HttpProbeObserver(Observer):
    """Invoke the HTTP observer protocol through one guarded executor."""

    BUILTIN_KIND = BuiltinObserverKind.HTTP
    __slots__ = ("_config", "_executor", "_policies", "_token")

    def __init__(
        self,
        config: HttpObserverConfig,
        *,
        policies: HttpProbePolicies,
        executor: HttpAttemptExecutor,
        token: SecretHandle,
    ) -> None:
        if type(config) is not HttpObserverConfig:
            raise TypeError("config must be an HttpObserverConfig")
        if type(policies) is not HttpProbePolicies:
            raise TypeError("policies must be HttpProbePolicies")
        if type(executor) is not HttpAttemptExecutor:
            raise TypeError("executor must be an HttpAttemptExecutor")
        if type(token) is not SecretHandle:
            raise TypeError("token must be a SecretHandle")
        if token.reference != config.token:
            raise _error(
                ErrorCategory.CONFIGURATION_ERROR,
                "OBSERVER_TOKEN_REFERENCE_MISMATCH",
                "The resolved observer token does not match its configured reference.",
            )
        _validate_base_url(config.base_url)
        _validate_endpoint_policy(config.base_url, HTTP_CAPABILITIES_PATH, policies.capabilities)
        _validate_endpoint_policy(config.base_url, HTTP_OBSERVE_PATH, policies.observe)
        self._config = config
        self._policies = policies
        self._executor = executor
        self._token = token

    async def invoke(self, request: ObserverRequest) -> ObserverResponse:
        """POST one authenticated protocol request to its exact endpoint."""
        if type(request) is not ObserverRequest:
            raise TypeError("request must be an ObserverRequest")
        policy = (
            self._policies.capabilities
            if request.operation is ObserverOperation.CAPABILITIES
            else self._policies.observe
        )
        body = canonical_observer_wire_bytes(request)
        authorization = ""
        try:
            authorization = self._token.use_with(
                lambda value: f"Bearer {bytes(value).decode('utf-8', errors='strict')}"
            )
            command = HttpAttemptCommand(
                policy=policy,
                body=body,
                headers=(
                    HttpHeader("Authorization", authorization, HeaderOwner.SIGNER),
                    HttpHeader("Content-Type", _JSON_MEDIA_TYPE, HeaderOwner.USER),
                    HttpHeader("Accept", _JSON_MEDIA_TYPE, HeaderOwner.USER),
                ),
            )
        except Exception:
            raise _error(
                ErrorCategory.OBSERVER_AUTH_ERROR,
                "OBSERVER_CREDENTIAL_INVALID",
                "The configured HTTP observer credential cannot form a safe request.",
            ) from None
        try:
            with anyio.fail_after(
                self._config.timeouts.total.nanoseconds / _NANOSECONDS_PER_SECOND
            ):
                result = await self._executor.execute(command)
        except TimeoutError as error:
            raise _error(
                ErrorCategory.OBSERVER_TIMEOUT,
                "OBSERVER_TIMEOUT",
                "The HTTP observer exceeded its physical timeout.",
                retryable=True,
            ) from error
        finally:
            authorization = ""
        if result.outcome is not AttemptOutcome.RESPONSE or result.response is None:
            code = result.error.code if result.error is not None else None
            if code in {
                AttemptErrorCode.TOTAL_TIMEOUT,
                AttemptErrorCode.CONNECT_TIMEOUT,
                AttemptErrorCode.READ_TIMEOUT,
                AttemptErrorCode.WRITE_TIMEOUT,
                AttemptErrorCode.POOL_TIMEOUT,
            }:
                raise _error(
                    ErrorCategory.OBSERVER_TIMEOUT,
                    "OBSERVER_TIMEOUT",
                    "The HTTP observer exceeded its physical timeout.",
                    retryable=True,
                )
            if code in {
                AttemptErrorCode.RESPONSE_TOO_LARGE,
                AttemptErrorCode.RESOURCE_LIMIT,
            }:
                raise _error(
                    ErrorCategory.RESOURCE_LIMIT,
                    "OBSERVER_OUTPUT_LIMIT",
                    "The HTTP observer response exceeded its bounded output limit.",
                )
            raise _error(
                ErrorCategory.OBSERVER_HTTP_ERROR,
                "OBSERVER_HTTP_TRANSPORT",
                "The guarded HTTP observer transport failed.",
                retryable=True,
            )
        response = result.response
        if response.status in {401, 403}:
            raise _error(
                ErrorCategory.OBSERVER_AUTH_ERROR,
                "OBSERVER_AUTH_ERROR",
                "The HTTP observer rejected its configured credential.",
            )
        if response.status in _REDIRECT_STATUSES:
            raise _error(
                ErrorCategory.OBSERVER_HTTP_ERROR,
                "OBSERVER_REDIRECT_FORBIDDEN",
                "The HTTP observer returned a forbidden redirect.",
            )
        if not 200 <= response.status <= 299:
            raise _error(
                ErrorCategory.OBSERVER_HTTP_ERROR,
                "OBSERVER_HTTP_STATUS",
                "The HTTP observer returned a non-success status.",
            )
        if (
            response.truncated
            or not response.body_complete
            or response.body_bytes > MAX_OBSERVER_MESSAGE_BYTES
            or len(response.captured_body) > MAX_OBSERVER_MESSAGE_BYTES
        ):
            raise _error(
                ErrorCategory.RESOURCE_LIMIT,
                "OBSERVER_OUTPUT_LIMIT",
                "The HTTP observer response exceeded its bounded output limit.",
            )
        if response.media_type is None:
            raise _error(
                ErrorCategory.OBSERVER_PROTOCOL_ERROR,
                "OBSERVER_CONTENT_TYPE_MISSING",
                "The HTTP observer response omitted its required Content-Type header.",
            )
        if response.media_type != _JSON_MEDIA_TYPE:
            raise _error(
                ErrorCategory.OBSERVER_PROTOCOL_ERROR,
                "OBSERVER_CONTENT_TYPE_INVALID",
                "The HTTP observer response did not use the required JSON media type.",
            )
        try:
            parsed = parse_observer_response(response.captured_body)
            return validate_response_for_request(request, parsed)
        except Exception as error:
            diagnostic = getattr(error, "diagnostic", None)
            if isinstance(diagnostic, Diagnostic):
                raise HttpProbeObserverError(diagnostic) from None
            raise _error(
                ErrorCategory.OBSERVER_PROTOCOL_ERROR,
                "OBSERVER_PROTOCOL_ERROR",
                "The HTTP observer returned an invalid protocol response.",
            ) from error


def _validate_base_url(base_url: str) -> None:
    parsed = urlsplit(base_url)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
    ):
        raise _error(
            ErrorCategory.CONFIGURATION_ERROR,
            "OBSERVER_BASE_URL_INVALID",
            "The HTTP observer base URL is unsafe or ambiguous.",
        )


def _validate_endpoint_policy(
    base_url: str,
    endpoint: str,
    policy: DestinationPolicy,
) -> None:
    validate_destination_policy(policy)
    expected = urlsplit(f"{base_url.rstrip('/')}{endpoint}")
    destination = policy.destination
    if (
        destination.scheme != expected.scheme.lower()
        or destination.host != (expected.hostname or "").lower()
        or destination.path != expected.path
        or destination.query
        or destination.port != (expected.port or (443 if expected.scheme == "https" else 80))
    ):
        raise _error(
            ErrorCategory.CONFIGURATION_ERROR,
            "OBSERVER_ENDPOINT_POLICY_MISMATCH",
            "The HTTP observer endpoint policy does not match its configured base URL.",
        )


def _error(
    category: ErrorCategory,
    code: str,
    message: str,
    *,
    retryable: bool = False,
) -> HttpProbeObserverError:
    configuration_error = category is ErrorCategory.CONFIGURATION_ERROR
    return HttpProbeObserverError(
        Diagnostic(
            category=category,
            code=DiagnosticCode(code),
            message=message,
            retryable=retryable,
            safe_details={},
            result_category=(
                ResultCategory.INVALID_INPUT
                if configuration_error
                else ResultCategory.ENVIRONMENT_ERROR
            ),
            user_correctable=configuration_error,
            field_path="observers" if configuration_error else None,
            corrective_action=(
                "Correct the HTTP observer configuration." if configuration_error else None
            ),
        )
    )


__all__ = ["HttpProbeObserver", "HttpProbeObserverError", "HttpProbePolicies"]
