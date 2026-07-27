"""Guarded HTTP probe observer tests."""
# ruff: noqa: D101, D102, EM101, INP001, S105, SLF001, TRY003

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import anyio
import pytest

from webhook_receiver_conformance.config.models import (
    HttpObserverConfig,
    ReceiverConfig,
)
from webhook_receiver_conformance.errors import ErrorCategory
from webhook_receiver_conformance.http.executor import (
    HttpAttemptCommand,
    HttpAttemptExecutor,
    HttpLimits,
    HttpTimeouts,
)
from webhook_receiver_conformance.network.dialer import PinnedDestinationDialer
from webhook_receiver_conformance.network.policy import DestinationPolicy, parse_destination_policy
from webhook_receiver_conformance.network.transport import ConnectionPlan, PeerAddress
from webhook_receiver_conformance.observers.http_probe import (
    HttpProbeObserver,
    HttpProbeObserverError,
    HttpProbePolicies,
)
from webhook_receiver_conformance.observers.protocol import (
    ObserverOperation,
    ObserverRequest,
    ObserverResponseStatus,
)
from webhook_receiver_conformance.secrets import SecretResolver

if TYPE_CHECKING:
    from webhook_receiver_conformance.http.evidence import AttemptResult

REQUEST_ID = "request_01J00000000000000000000000"
TOKEN = "observer-token-secret-canary"


def _byte_list() -> list[bytes]:
    return []


def _stream_list() -> list[Stream]:
    return []


class UnusedResolver:
    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        del host, port
        raise AssertionError("literal loopback must not resolve")


@dataclass(frozen=True)
class AddressResolver:
    addresses: tuple[str, ...]

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        del host, port
        return self.addresses


@dataclass
class Stream:
    response: bytes
    peer: PeerAddress
    sent: list[bytes] = field(default_factory=_byte_list)
    closed: bool = False

    @property
    def peer_address(self) -> PeerAddress:
        return self.peer

    async def send(self, item: bytes) -> None:
        self.sent.append(item)

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        del max_bytes
        if self.response:
            response, self.response = self.response, b""
            return response
        return b""

    async def send_eof(self) -> None:
        return

    async def aclose(self) -> None:
        self.closed = True


@dataclass
class Connector:
    response: bytes
    connect_delay: float = 0
    calls: int = 0
    streams: list[Stream] = field(default_factory=_stream_list)

    async def connect(self, plan: ConnectionPlan) -> Stream:
        self.calls += 1
        if self.connect_delay:
            await anyio.sleep(self.connect_delay)
        stream = Stream(
            self.response,
            PeerAddress(plan.pinned_address, plan.port, plan.family),
        )
        self.streams.append(stream)
        return stream


def _config(base_url: str = "http://127.0.0.1:8765/probe") -> HttpObserverConfig:
    return HttpObserverConfig.model_validate(
        {
            "type": "http",
            "base_url": base_url,
            "token": {"env": "OBSERVER_TOKEN"},
            "timeouts": {"connect": "1s", "read": "1s", "total": "2s"},
        }
    )


def _policy(url: str) -> DestinationPolicy:
    return parse_destination_policy(
        ReceiverConfig.model_validate(
            {
                "url": url,
                "target_profile": "loopback",
                "allowed_ports": [8765],
                "timeouts": {
                    "connect": "1s",
                    "write": "1s",
                    "read": "1s",
                    "pool": "1s",
                    "total": "2s",
                },
            }
        )
    )


def _policies(base_url: str = "http://127.0.0.1:8765/probe") -> HttpProbePolicies:
    return HttpProbePolicies(
        capabilities=_policy(f"{base_url}/capabilities"),
        observe=_policy(f"{base_url}/observe"),
    )


def _response_body(request_id: str = REQUEST_ID) -> bytes:
    return json.dumps(
        {
            "protocol_version": "1.0",
            "request_id": request_id,
            "status": "ok",
            "capabilities": {
                "evidence_types": ["integer"],
                "evidence_keys": ["processing_count"],
                "read_only": True,
                "idempotent": True,
                "max_queries": 64,
                "supports_pending": True,
                "stable_snapshot_ids": True,
            },
            "snapshot_id": "snapshot-1",
            "evidence": [],
            "error": None,
        },
        separators=(",", ":"),
    ).encode()


def _wire(
    status: int,
    body: bytes,
    headers: bytes = b"Content-Type: application/json\r\n",
) -> bytes:
    return (
        f"HTTP/1.1 {status} Result\r\nContent-Length: {len(body)}\r\n".encode()
        + headers
        + b"\r\n"
        + body
    )


def _observer(
    connector: Connector,
    *,
    base_url: str = "http://127.0.0.1:8765/probe",
) -> HttpProbeObserver:
    executor = HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=UnusedResolver(),
            connector=connector,
        ),
        timeouts=HttpTimeouts(
            connect_ns=1_000_000_000,
            write_ns=1_000_000_000,
            read_ns=1_000_000_000,
            pool_ns=1_000_000_000,
            total_ns=2_000_000_000,
        ),
        limits=HttpLimits(
            response_capture_bytes=1_048_576,
            response_drain_bytes=1_048_576,
        ),
    )
    token = SecretResolver(environ={"OBSERVER_TOKEN": TOKEN}).resolve(_config(base_url).token)
    return HttpProbeObserver(
        _config(base_url),
        policies=_policies(base_url),
        executor=executor,
        token=token,
    )


def _request() -> ObserverRequest:
    return ObserverRequest.model_validate(
        {
            "protocol_version": "1.0",
            "request_id": REQUEST_ID,
            "operation": ObserverOperation.CAPABILITIES.value,
        }
    )


@pytest.mark.anyio
async def test_capabilities_uses_exact_path_auth_and_schema() -> None:
    connector = Connector(_wire(200, _response_body()))
    response = await _observer(connector).invoke(_request())

    assert response.status is ObserverResponseStatus.OK
    sent = b"".join(connector.streams[0].sent)
    assert sent.startswith(b"POST /probe/capabilities HTTP/1.1\r\n")
    assert f"Authorization: Bearer {TOKEN}\r\n".encode() in sent
    assert b'"request_id":"request_01J00000000000000000000000"' in sent
    assert connector.calls == 1


@pytest.mark.anyio
async def test_adapter_command_and_header_repr_omit_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = Connector(_wire(200, _response_body()))
    original = HttpAttemptExecutor.execute

    async def inspect_then_execute(
        executor: HttpAttemptExecutor,
        command: HttpAttemptCommand,
    ) -> AttemptResult:
        assert TOKEN not in repr(command)
        assert all(TOKEN not in repr(header) for header in command.headers)
        return await original(executor, command)

    monkeypatch.setattr(HttpAttemptExecutor, "execute", inspect_then_execute)
    await _observer(connector).invoke(_request())


@pytest.mark.anyio
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_redirect_and_auth_fail_without_followup_or_body_leak(status: int) -> None:
    secret_body = b"response-secret-canary"
    connector = Connector(_wire(status, secret_body, b"Location: http://127.0.0.1:8765/other\r\n"))

    with pytest.raises(HttpProbeObserverError) as captured:
        await _observer(connector).invoke(_request())

    assert connector.calls == 1
    assert secret_body.decode() not in repr(captured.value)
    assert TOKEN not in repr(captured.value)


@pytest.mark.anyio
@pytest.mark.parametrize("status", [401, 403])
async def test_wrong_credential_is_secret_safe_auth_error(status: int) -> None:
    connector = Connector(_wire(status, b"credential-debug-secret"))
    with pytest.raises(HttpProbeObserverError) as captured:
        await _observer(connector).invoke(_request())
    assert captured.value.diagnostic.category is ErrorCategory.OBSERVER_AUTH_ERROR
    assert captured.value.diagnostic.safe_details == {}
    assert "credential-debug-secret" not in repr(captured.value)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "body",
    [b"not-json", b"{}\n{}", b"\xff", _response_body("request_01J00000000000000000000001")],
)
async def test_malformed_or_uncorrelated_response_is_protocol_error(body: bytes) -> None:
    connector = Connector(_wire(200, body))
    with pytest.raises(HttpProbeObserverError) as captured:
        await _observer(connector).invoke(_request())
    assert captured.value.diagnostic.category is ErrorCategory.OBSERVER_PROTOCOL_ERROR


@pytest.mark.anyio
async def test_missing_response_content_type_name_is_protocol_error() -> None:
    connector = Connector(_wire(200, _response_body(), b"X-Safe: yes\r\n"))
    with pytest.raises(HttpProbeObserverError) as captured:
        await _observer(connector).invoke(_request())
    assert str(captured.value.diagnostic.code) == "OBSERVER_CONTENT_TYPE_MISSING"


@pytest.mark.anyio
async def test_wrong_response_content_type_is_protocol_error() -> None:
    connector = Connector(_wire(200, _response_body(), b"Content-Type: text/plain\r\n"))
    with pytest.raises(HttpProbeObserverError) as captured:
        await _observer(connector).invoke(_request())
    assert str(captured.value.diagnostic.code) == "OBSERVER_CONTENT_TYPE_INVALID"


@pytest.mark.anyio
async def test_json_content_type_parameters_are_accepted() -> None:
    connector = Connector(
        _wire(
            200,
            _response_body(),
            b"Content-Type: Application/JSON; charset=utf-8\r\n",
        )
    )
    response = await _observer(connector).invoke(_request())
    assert response.status is ObserverResponseStatus.OK


@pytest.mark.anyio
async def test_oversize_response_is_resource_limit() -> None:
    connector = Connector(_wire(200, b"x" * 1_048_577))
    with pytest.raises(HttpProbeObserverError) as captured:
        await _observer(connector).invoke(_request())
    assert captured.value.diagnostic.category is ErrorCategory.RESOURCE_LIMIT


@pytest.mark.anyio
async def test_hanging_transport_is_physical_timeout() -> None:
    connector = Connector(_wire(200, _response_body()), connect_delay=60)
    with pytest.raises(HttpProbeObserverError) as captured:
        await _observer(connector).invoke(_request())
    assert captured.value.diagnostic.category is ErrorCategory.OBSERVER_TIMEOUT


@pytest.mark.anyio
async def test_outer_cancellation_propagates() -> None:
    connector = Connector(_wire(200, _response_body()), connect_delay=60)
    observer = _observer(connector)
    cancellation_seen = anyio.Event()

    async def invoke() -> None:
        try:
            await observer.invoke(_request())
        except anyio.get_cancelled_exc_class():
            cancellation_seen.set()
            raise

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(invoke)
        await anyio.sleep(0.05)
        tasks.cancel_scope.cancel()
    assert cancellation_seen.is_set()


@pytest.mark.anyio
async def test_proxy_environment_is_never_consulted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    connector = Connector(_wire(200, _response_body()))
    assert (await _observer(connector).invoke(_request())).status is ObserverResponseStatus.OK
    assert connector.calls == 1


@pytest.mark.anyio
async def test_mixed_dns_answer_fails_closed_before_connect() -> None:
    base_url = "http://localhost:8765/probe"
    connector = Connector(_wire(200, _response_body()))
    executor = HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(
            resolver=AddressResolver(("127.0.0.1", "169.254.169.254")),
            connector=connector,
        ),
        timeouts=HttpTimeouts(
            connect_ns=1_000_000_000,
            write_ns=1_000_000_000,
            read_ns=1_000_000_000,
            pool_ns=1_000_000_000,
            total_ns=2_000_000_000,
        ),
    )
    config = _config(base_url)
    token = SecretResolver(environ={"OBSERVER_TOKEN": TOKEN}).resolve(config.token)
    observer = HttpProbeObserver(
        config,
        policies=_policies(base_url),
        executor=executor,
        token=token,
    )

    with pytest.raises(HttpProbeObserverError):
        await observer.invoke(_request())

    assert connector.calls == 0


@pytest.mark.parametrize(
    "base_url",
    [
        "http://user@127.0.0.1:8765/probe",
        "http://127.0.0.1:8765/probe?confused=1",
        "http://127.0.0.1:8765/probe#fragment",
    ],
)
def test_ambiguous_base_url_fails_before_network(base_url: str) -> None:
    connector = Connector(_wire(200, _response_body()))
    with pytest.raises((HttpProbeObserverError, ValueError)):
        _observer(connector, base_url=base_url)
    assert connector.calls == 0


def test_endpoint_and_token_mismatch_are_invalid_input_without_secret() -> None:
    connector = Connector(_wire(200, _response_body()))
    executor = HttpAttemptExecutor(
        dialer=PinnedDestinationDialer(resolver=UnusedResolver(), connector=connector),
        timeouts=HttpTimeouts(
            connect_ns=1_000_000_000,
            write_ns=1_000_000_000,
            read_ns=1_000_000_000,
            pool_ns=1_000_000_000,
            total_ns=2_000_000_000,
        ),
    )
    config = _config()
    wrong_token = SecretResolver(environ={"OTHER_TOKEN": TOKEN}).resolve(
        HttpObserverConfig.model_validate(
            {
                **config.model_dump(mode="json"),
                "token": {"env": "OTHER_TOKEN"},
            }
        ).token
    )
    with pytest.raises(HttpProbeObserverError) as token_error:
        HttpProbeObserver(
            config,
            policies=_policies(),
            executor=executor,
            token=wrong_token,
        )
    assert token_error.value.diagnostic.result_category.value == "invalid_input"
    assert token_error.value.diagnostic.user_correctable
    assert TOKEN not in repr(token_error.value)

    good_token = SecretResolver(environ={"OBSERVER_TOKEN": TOKEN}).resolve(config.token)
    mismatched = HttpProbePolicies(
        capabilities=_policy("http://127.0.0.1:8765/wrong/capabilities"),
        observe=_policies().observe,
    )
    with pytest.raises(HttpProbeObserverError) as endpoint_error:
        HttpProbeObserver(
            config,
            policies=mismatched,
            executor=executor,
            token=good_token,
        )
    assert endpoint_error.value.diagnostic.result_category.value == "invalid_input"
    assert TOKEN not in repr(endpoint_error.value)


@pytest.mark.anyio
@pytest.mark.parametrize("hostile_token", [TOKEN + "\r\nInjected: yes", "x" * 9000])
async def test_unsafe_bearer_value_is_classified_without_secret(
    hostile_token: str,
) -> None:
    connector = Connector(_wire(200, _response_body()))
    observer = _observer(connector)
    config = _config()
    hostile_handle = SecretResolver(environ={"OBSERVER_TOKEN": hostile_token}).resolve(config.token)
    observer = HttpProbeObserver(
        config,
        policies=_policies(),
        executor=observer._executor,  # pyright: ignore[reportPrivateUsage]
        token=hostile_handle,
    )
    with pytest.raises(HttpProbeObserverError) as captured:
        await observer.invoke(_request())
    assert str(captured.value.diagnostic.code) == "OBSERVER_CREDENTIAL_INVALID"
    assert hostile_token not in repr(captured.value)
    assert connector.calls == 0


@pytest.mark.anyio
async def test_non_utf8_bearer_is_classified_without_callback_detail() -> None:
    config = HttpObserverConfig.model_validate(
        {
            **_config().model_dump(mode="json"),
            "token": {"generated": "hmac-256"},
        }
    )
    connector = Connector(_wire(200, _response_body()))
    nominal = _observer(connector)
    token = SecretResolver(token_bytes=lambda _length: b"\xff" * 32).resolve(config.token)
    observer = HttpProbeObserver(
        config,
        policies=_policies(),
        executor=nominal._executor,  # pyright: ignore[reportPrivateUsage]
        token=token,
    )
    with pytest.raises(HttpProbeObserverError) as captured:
        await observer.invoke(_request())
    assert str(captured.value.diagnostic.code) == "OBSERVER_CREDENTIAL_INVALID"
    assert "utf" not in repr(captured.value).lower()
    assert connector.calls == 0


def test_source_uses_guarded_executor_and_never_convenience_network() -> None:
    source = Path("src/webhook_receiver_conformance/observers/http_probe.py").read_text(
        encoding="utf-8"
    )
    assert "HttpAttemptExecutor" in source
    assert "AsyncClient(" not in source
    assert "requests." not in source
