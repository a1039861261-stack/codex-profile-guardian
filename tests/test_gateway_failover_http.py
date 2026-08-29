from __future__ import annotations

import asyncio
from dataclasses import dataclass
import errno
import json
import socket
import socketserver
import ssl
import struct
import sys
import threading
import unittest
from urllib.parse import urlsplit

import aiohttp

from gateway.adapter import OpenAIResponsesAdapter
from gateway.attempts import SingleRouteAttemptRunner
from gateway.breaker import BreakerState, CircuitBreakerPolicy, CircuitBreakerRegistry, RouteKey
from gateway.cancellation import CancellationToken
from gateway.commit import Committer
from gateway.config import FailoverGroupConfig, RouteConfig, RouteRole
from gateway.failures import FailureClassifier
from gateway.models import CancelReason, CommitState, GatewayLimits
from gateway.request_snapshot import create_request_snapshot
from gateway.router import FailoverRouter
from gateway.secrets import InMemorySecretResolver
from gateway.service import FailoverGatewayCore
from tests.gateway_probe_support import (
    FAKE_BEARER,
    FIXTURE_MODEL,
    ProgrammableResponsesMock,
    ScriptedScenario,
    fixture_request,
    missing_terminal_scenario,
    text_sse_frames,
    trailing_garbage_scenario,
    truncated_tool_scenario,
)
from tests.test_gateway_core import RecordingDownstream


@dataclass(frozen=True)
class _UpstreamEndpoint:
    base_url: str


class _FailingResolver(aiohttp.abc.AbstractResolver):
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        self.calls.append((host, port))
        raise socket.gaierror(socket.EAI_NONAME, "synthetic_dns_failure")

    async def close(self) -> None:
        return


class _LoopbackTlsHandshakeFailureServer:
    def __init__(self) -> None:
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._connection_count = 0

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("tls_fixture_not_running")
        host, port = self._server.server_address
        return f"https://{host}:{port}/v1"

    @property
    def connection_count(self) -> int:
        with self._lock:
            return self._connection_count

    def start(self) -> "_LoopbackTlsHandshakeFailureServer":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                try:
                    self.request.recv(4096)
                except OSError:
                    return

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

            def get_request(self):
                connection, address = self.socket.accept()
                with owner._lock:
                    owner._connection_count += 1
                try:
                    return context.wrap_socket(connection, server_side=True), address
                except BaseException:
                    connection.close()
                    raise

        self._server = Server(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="guardian-g4-tls-fixture",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._server = None
        self._thread = None

    def __enter__(self) -> "_LoopbackTlsHandshakeFailureServer":
        return self.start()

    def __exit__(self, *_args) -> None:
        self.close()


class _LoopbackResetServer:
    def __init__(self) -> None:
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connection_count = 0

    @property
    def base_url(self) -> str:
        if self._listener is None:
            raise RuntimeError("reset_fixture_not_running")
        host, port = self._listener.getsockname()
        return f"http://{host}:{port}/v1"

    @property
    def connection_count(self) -> int:
        with self._lock:
            return self._connection_count

    def start(self) -> "_LoopbackResetServer":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)
        self._listener = listener
        self._thread = threading.Thread(
            target=self._serve,
            name="guardian-g4-reset-fixture",
            daemon=True,
        )
        self._thread.start()
        return self

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop.is_set():
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._connection_count += 1
            try:
                connection.settimeout(1)
                connection.recv(64 * 1024)
            except OSError:
                pass
            try:
                linger_format = "hh" if sys.platform == "win32" else "ii"
                connection.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_LINGER,
                    struct.pack(linger_format, 1, 0),
                )
            finally:
                connection.close()

    def close(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._listener = None
        self._thread = None

    def __enter__(self) -> "_LoopbackResetServer":
        return self.start()

    def __exit__(self, *_args) -> None:
        self.close()


@dataclass(frozen=True)
class _SyntheticConnectionKey:
    host: str
    port: int
    ssl: bool


class _ConnectionRefusingSession:
    def __init__(
        self,
        delegate: aiohttp.ClientSession,
        refused_hosts: set[str],
    ) -> None:
        self._delegate = delegate
        self._refused_hosts = frozenset(refused_hosts)
        self.calls: list[str] = []

    def post(self, url: str, *args, **kwargs):
        host = urlsplit(url).hostname or ""
        self.calls.append(host)
        if host not in self._refused_hosts:
            return self._delegate.post(url, *args, **kwargs)

        async def refuse_connection():
            key = _SyntheticConnectionKey(host=host, port=443, ssl=True)
            os_error = ConnectionRefusedError(
                errno.ECONNREFUSED,
                "synthetic_connection_refused",
            )
            raise aiohttp.ClientConnectorError(key, os_error)

        return refuse_connection()


class HttpFailoverMatrixTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.session = aiohttp.ClientSession()
        self.limits = GatewayLimits(
            max_request_bytes=1024 * 1024,
            max_response_bytes=1024 * 1024,
            read_chunk_bytes=257,
            connect_timeout_seconds=1,
            first_byte_timeout_seconds=0.2,
            idle_timeout_seconds=0.2,
            total_timeout_seconds=1,
        )

    async def asyncTearDown(self) -> None:
        await self.session.close()

    def router(
        self,
        primary_upstream,
        backup_upstream,
        *,
        primary_adapter_404=False,
        backup_adapter_404=False,
        session: aiohttp.ClientSession | None = None,
        limits: GatewayLimits | None = None,
    ):
        session = session or self.session
        limits = limits or self.limits
        primary_adapter = OpenAIResponsesAdapter(
            primary_upstream.base_url,
            action_required_statuses=frozenset({404}) if primary_adapter_404 else frozenset(),
        )
        primary_runner = SingleRouteAttemptRunner(session, primary_adapter, limits)
        backup_runner = SingleRouteAttemptRunner(
            session,
            OpenAIResponsesAdapter(
                backup_upstream.base_url,
                action_required_statuses=frozenset({404}) if backup_adapter_404 else frozenset(),
            ),
            limits,
        )
        policy = CircuitBreakerPolicy(
            failure_threshold=1,
            minimum_samples=1,
            window_size=10,
            recovery_success_threshold=1,
            base_cooldown_seconds=30,
            max_cooldown_seconds=300,
            jitter_ratio=0,
        )
        group = FailoverGroupConfig(
            instance_id="instance-http",
            group_id="group-http",
            revision=1,
            primary=RouteConfig(
                RouteRole.PRIMARY,
                "p1",
                "fp-p1",
                "openai-responses-v1",
                "secret:p1",
                primary_runner,
            ),
            backup=RouteConfig(
                RouteRole.BACKUP,
                "p2",
                "fp-p2",
                "openai-responses-v1",
                "secret:p2",
                backup_runner,
            ),
            allowed_models=(FIXTURE_MODEL,),
            breaker_policy=policy,
        )
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        router = FailoverRouter(
            group,
            breaker,
            FailureClassifier(),
            InMemorySecretResolver({"secret:p1": FAKE_BEARER, "secret:p2": FAKE_BEARER}),
        )
        return router, breaker

    def assert_failover_success(
        self,
        routed,
        *,
        failure_category: str,
    ) -> None:
        self.assertIsNotNone(routed.complete)
        self.assertEqual(routed.primary_failure.category, failure_category)
        self.assertIsNone(routed.backup_failure)
        self.assertTrue(routed.failover_used)
        self.assertEqual(
            [attempt.route.role for attempt in routed.attempts],
            [RouteRole.PRIMARY, RouteRole.BACKUP],
        )
        self.assertEqual(len({attempt.attempt_id for attempt in routed.attempts}), 2)

    async def assert_one_aggregated_error(
        self,
        router: FailoverRouter,
        *,
        limits: GatewayLimits | None = None,
        failure_category: str,
        possible_double_charge: bool,
        action_required: bool = False,
        http_status: int = 503,
        expected_attempts: list[dict] | None = None,
    ) -> dict:
        core = FailoverGatewayCore(router, limits or self.limits)
        downstream = RecordingDownstream()
        committer = Committer()
        result = await core.proxy(
            fixture_request(),
            {"content-type": "application/json"},
            "unused-ingress-token",
            downstream,
            CancellationToken(),
            committer,
        )
        payload = json.loads(downstream.body)
        rendered = downstream.body.decode("utf-8")
        self.assertEqual(result.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(committer.state, CommitState.ERROR_COMMITTED)
        self.assertTrue(downstream.prepared)
        self.assertTrue(downstream.finished)
        self.assertEqual(downstream.status, http_status)
        self.assertEqual(payload["error"]["code"], "guardian_all_routes_failed")
        self.assertEqual(rendered.count("guardian_all_routes_failed"), 1)
        self.assertEqual(
            payload["error"]["attempts"],
            expected_attempts
            or [
                {"role": "primary", "category": failure_category},
                {"role": "backup", "category": failure_category},
            ],
        )
        self.assertEqual(payload["error"]["possible_double_charge"], possible_double_charge)
        self.assertEqual(payload["error"]["action_required"], action_required)
        terminal_events = [
            event
            for event in core.journal.snapshot()
            if event["event"] == "commit_finished"
        ]
        self.assertEqual(len(terminal_events), 1)
        self.assertNotIn(FAKE_BEARER, rendered)
        self.assertNotIn("fixture input", rendered)
        return payload

    @staticmethod
    def timeout_cases() -> tuple[tuple[str, ScriptedScenario, GatewayLimits], ...]:
        frames = text_sse_frames("TIMEOUT_FIXTURE", response_id="resp_timeout_fixture")
        # IsolatedAsyncioTestCase enables asyncio debug mode.  On a busy Windows
        # host that can add more than 100 ms of scheduling overhead to the
        # otherwise immediate backup fixture.  Keep a wide gap between the
        # timeout that trips P1 and the budget that lets a zero-delay P2 finish;
        # the assertions below still prove each timeout class and exactly one
        # failover attempt without making the result depend on host speed.
        common = {
            "max_request_bytes": 1024 * 1024,
            "max_response_bytes": 1024 * 1024,
            "read_chunk_bytes": 257,
            "connect_timeout_seconds": 0.5,
        }
        return (
            (
                "first_byte",
                ScriptedScenario(
                    name="first_byte_timeout",
                    chunks=frames,
                    chunk_delays=(0.75,),
                ),
                GatewayLimits(
                    **common,
                    first_byte_timeout_seconds=0.35,
                    idle_timeout_seconds=0.50,
                    total_timeout_seconds=1.50,
                ),
            ),
            (
                "idle",
                ScriptedScenario(
                    name="idle_timeout",
                    chunks=frames,
                    chunk_delays=(0.0, 0.75),
                ),
                GatewayLimits(
                    **common,
                    first_byte_timeout_seconds=0.50,
                    idle_timeout_seconds=0.35,
                    total_timeout_seconds=1.50,
                ),
            ),
            (
                "total",
                ScriptedScenario(
                    name="total_timeout",
                    chunks=frames,
                    chunk_delays=tuple(0.25 for _frame in frames),
                ),
                GatewayLimits(
                    **common,
                    first_byte_timeout_seconds=0.50,
                    idle_timeout_seconds=0.50,
                    total_timeout_seconds=0.75,
                ),
            ),
        )

    def request_snapshot(self):
        return create_request_snapshot(
            fixture_request(),
            {"content-type": "application/json"},
            self.limits,
        )

    async def test_fr031_retryable_http_status_matrix(self) -> None:
        for status in (401, 403, 429, 500, 502, 503, 504):
            with self.subTest(status=status):
                headers = (("Retry-After", "120"),) if status == 429 else ()
                primary_scenario = ScriptedScenario(
                    name=f"http_{status}",
                    status=status,
                    content_type="application/json",
                    chunks=(b'{"private":"ignored"}',),
                    response_headers=headers,
                )
                backup_scenario = ScriptedScenario(
                    name="backup_success",
                    chunks=text_sse_frames("BACKUP_OK", response_id=f"resp_backup_{status}"),
                )
                with ProgrammableResponsesMock(lambda _request: primary_scenario) as primary_upstream:
                    with ProgrammableResponsesMock(lambda _request: backup_scenario) as backup_upstream:
                        router, breaker = self.router(primary_upstream, backup_upstream)
                        routed = await router.execute(self.request_snapshot(), CancellationToken())
                self.assertEqual(routed.complete.response_id, f"resp_backup_{status}")
                self.assertEqual(primary_upstream.request_count, 1)
                self.assertEqual(backup_upstream.request_count, 1)
                key = RouteKey("instance-http", "group-http", "primary", "p1")
                expected = BreakerState.OPEN_ACTION_REQUIRED if status in (401, 403) else BreakerState.OPEN_TEMPORARY
                self.assertEqual(breaker.snapshot(key).state, expected)

    async def test_fr031_retryable_http_status_both_routes_fail_once(self) -> None:
        for status in (401, 403, 429, 500, 502, 503, 504):
            with self.subTest(status=status):
                headers = (("Retry-After", "120"),) if status == 429 else ()
                scenario = ScriptedScenario(
                    name=f"http_{status}",
                    status=status,
                    content_type="application/json",
                    chunks=(b'{"private":"ignored"}',),
                    response_headers=headers,
                )
                with ProgrammableResponsesMock(lambda _request, value=scenario: value) as primary_upstream:
                    with ProgrammableResponsesMock(lambda _request, value=scenario: value) as backup_upstream:
                        router, breaker = self.router(primary_upstream, backup_upstream)
                        await self.assert_one_aggregated_error(
                            router,
                            failure_category="upstream_http_error",
                            possible_double_charge=False,
                            action_required=status in (401, 403),
                            http_status=503,
                            expected_attempts=[
                                {
                                    "role": "primary",
                                    "category": "upstream_http_error",
                                    "http_status": status,
                                },
                                {
                                    "role": "backup",
                                    "category": "upstream_http_error",
                                    "http_status": status,
                                },
                            ],
                        )
                self.assertEqual(primary_upstream.request_count, 1)
                self.assertEqual(backup_upstream.request_count, 1)
                expected = (
                    BreakerState.OPEN_ACTION_REQUIRED
                    if status in (401, 403)
                    else BreakerState.OPEN_TEMPORARY
                )
                self.assertEqual(
                    breaker.snapshot(RouteKey("instance-http", "group-http", "primary", "p1")).state,
                    expected,
                )
                self.assertEqual(
                    breaker.snapshot(RouteKey("instance-http", "group-http", "backup", "p2")).state,
                    expected,
                )

    async def test_fr031_nonretryable_http_status_matrix_never_calls_backup(self) -> None:
        for status in (400, 404, 409, 413, 415, 422):
            with self.subTest(status=status):
                primary_scenario = ScriptedScenario(
                    name=f"http_{status}",
                    status=status,
                    content_type="application/json",
                    chunks=(b'{"private":"ignored"}',),
                )
                with ProgrammableResponsesMock(lambda _request: primary_scenario) as primary_upstream:
                    with ProgrammableResponsesMock() as backup_upstream:
                        router, breaker = self.router(primary_upstream, backup_upstream)
                        routed = await router.execute(self.request_snapshot(), CancellationToken())
                self.assertIsNone(routed.complete)
                self.assertEqual(routed.primary_failure.http_status, status)
                self.assertEqual(primary_upstream.request_count, 1)
                self.assertEqual(backup_upstream.request_count, 0)
                state = breaker.snapshot(RouteKey("instance-http", "group-http", "primary", "p1"))
                self.assertEqual(state.state, BreakerState.UNKNOWN)

    async def test_profile_scoped_adapter_404_fails_over_and_opens_action_required(self) -> None:
        scenario = ScriptedScenario(name="adapter_404", status=404, content_type="application/json")
        with ProgrammableResponsesMock(lambda _request: scenario) as primary_upstream:
            with ProgrammableResponsesMock() as backup_upstream:
                router, breaker = self.router(primary_upstream, backup_upstream, primary_adapter_404=True)
                routed = await router.execute(self.request_snapshot(), CancellationToken())
        self.assertIsNotNone(routed.complete)
        self.assertEqual(backup_upstream.request_count, 1)
        state = breaker.snapshot(RouteKey("instance-http", "group-http", "primary", "p1"))
        self.assertEqual(state.state, BreakerState.OPEN_ACTION_REQUIRED)

    async def test_profile_scoped_adapter_404_both_routes_fail_once(self) -> None:
        scenario = ScriptedScenario(
            name="adapter_404",
            status=404,
            content_type="application/json",
            chunks=(b'{"private":"ignored"}',),
        )
        with ProgrammableResponsesMock(lambda _request: scenario) as primary_upstream:
            with ProgrammableResponsesMock(lambda _request: scenario) as backup_upstream:
                router, breaker = self.router(
                    primary_upstream,
                    backup_upstream,
                    primary_adapter_404=True,
                    backup_adapter_404=True,
                )
                await self.assert_one_aggregated_error(
                    router,
                    failure_category="upstream_http_error",
                    possible_double_charge=False,
                    action_required=True,
                    http_status=502,
                    expected_attempts=[
                        {
                            "role": "primary",
                            "category": "upstream_http_error",
                            "http_status": 404,
                        },
                        {
                            "role": "backup",
                            "category": "upstream_http_error",
                            "http_status": 404,
                        },
                    ],
                )
        self.assertEqual(primary_upstream.request_count, 1)
        self.assertEqual(backup_upstream.request_count, 1)
        self.assertEqual(
            breaker.snapshot(RouteKey("instance-http", "group-http", "primary", "p1")).state,
            BreakerState.OPEN_ACTION_REQUIRED,
        )
        self.assertEqual(
            breaker.snapshot(RouteKey("instance-http", "group-http", "backup", "p2")).state,
            BreakerState.OPEN_ACTION_REQUIRED,
        )

    async def test_protocol_failures_discard_primary_and_deliver_backup_only(self) -> None:
        for primary_scenario in (
            missing_terminal_scenario(),
            trailing_garbage_scenario(),
            truncated_tool_scenario(),
        ):
            with self.subTest(name=primary_scenario.name):
                backup_scenario = ScriptedScenario(
                    name="backup_success",
                    chunks=text_sse_frames("ONLY_BACKUP", response_id=f"resp_{primary_scenario.name}"),
                )
                with ProgrammableResponsesMock(lambda _request: primary_scenario) as primary_upstream:
                    with ProgrammableResponsesMock(lambda _request: backup_scenario) as backup_upstream:
                        router, _breaker = self.router(primary_upstream, backup_upstream)
                        routed = await router.execute(self.request_snapshot(), CancellationToken())
                self.assertEqual(routed.complete.response_id, f"resp_{primary_scenario.name}")
                self.assertNotIn(b"resp_g2_missing", routed.complete.body)
                self.assertEqual(primary_upstream.request_count, 1)
                self.assertEqual(backup_upstream.request_count, 1)

                with ProgrammableResponsesMock(
                    lambda _request, value=primary_scenario: value
                ) as primary_upstream:
                    with ProgrammableResponsesMock(
                        lambda _request, value=primary_scenario: value
                    ) as backup_upstream:
                        router, _breaker = self.router(primary_upstream, backup_upstream)
                        await self.assert_one_aggregated_error(
                            router,
                            failure_category="protocol_or_local_error",
                            possible_double_charge=True,
                            http_status=502,
                            expected_attempts=[
                                {
                                    "role": "primary",
                                    "category": "protocol_or_local_error",
                                    "http_status": 502,
                                },
                                {
                                    "role": "backup",
                                    "category": "protocol_or_local_error",
                                    "http_status": 502,
                                },
                            ],
                        )
                self.assertEqual(primary_upstream.request_count, 1)
                self.assertEqual(backup_upstream.request_count, 1)

    async def test_first_byte_idle_and_total_timeouts_fail_over_once(self) -> None:
        for name, scenario, limits in self.timeout_cases():
            with self.subTest(timeout=name):
                backup_scenario = ScriptedScenario(
                    name="backup_success",
                    chunks=text_sse_frames(
                        f"BACKUP_AFTER_{name.upper()}",
                        response_id=f"resp_backup_after_{name}",
                    ),
                )
                with ProgrammableResponsesMock(lambda _request, value=scenario: value) as primary_upstream:
                    with ProgrammableResponsesMock(lambda _request, value=backup_scenario: value) as backup_upstream:
                        router, _breaker = self.router(
                            primary_upstream,
                            backup_upstream,
                            limits=limits,
                        )
                        routed = await router.execute(self.request_snapshot(), CancellationToken())
                self.assert_failover_success(routed, failure_category="upstream_timeout")
                self.assertEqual(routed.complete.response_id, f"resp_backup_after_{name}")
                self.assertTrue(routed.possible_double_charge)
                self.assertEqual(primary_upstream.request_count, 1)
                self.assertEqual(backup_upstream.request_count, 1)

    async def test_first_byte_idle_and_total_timeouts_both_fail_once(self) -> None:
        for name, scenario, limits in self.timeout_cases():
            with self.subTest(timeout=name):
                with ProgrammableResponsesMock(lambda _request, value=scenario: value) as primary_upstream:
                    with ProgrammableResponsesMock(lambda _request, value=scenario: value) as backup_upstream:
                        router, _breaker = self.router(
                            primary_upstream,
                            backup_upstream,
                            limits=limits,
                        )
                        await self.assert_one_aggregated_error(
                            router,
                            limits=limits,
                            failure_category="upstream_timeout",
                            possible_double_charge=True,
                        )
                self.assertEqual(primary_upstream.request_count, 1)
                self.assertEqual(backup_upstream.request_count, 1)

    async def test_dns_resolution_failure_fails_over_and_both_fail_once(self) -> None:
        primary = _UpstreamEndpoint("https://p1.guardian.invalid/v1")
        resolver = _FailingResolver()
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            with ProgrammableResponsesMock() as backup_upstream:
                router, _breaker = self.router(
                    primary,
                    backup_upstream,
                    session=session,
                )
                routed = await router.execute(self.request_snapshot(), CancellationToken())
        self.assert_failover_success(routed, failure_category="upstream_transport_error")
        self.assertEqual([host for host, _port in resolver.calls], ["p1.guardian.invalid"])
        self.assertEqual(backup_upstream.request_count, 1)
        self.assertFalse(routed.possible_double_charge)

        resolver = _FailingResolver()
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            router, _breaker = self.router(
                primary,
                _UpstreamEndpoint("https://p2.guardian.invalid/v1"),
                session=session,
            )
            await self.assert_one_aggregated_error(
                router,
                failure_category="upstream_transport_error",
                possible_double_charge=False,
            )
        self.assertEqual(
            [host for host, _port in resolver.calls],
            ["p1.guardian.invalid", "p2.guardian.invalid"],
        )

    async def test_tls_handshake_failure_fails_over_and_both_fail_once(self) -> None:
        with _LoopbackTlsHandshakeFailureServer() as primary_upstream:
            with ProgrammableResponsesMock() as backup_upstream:
                router, _breaker = self.router(primary_upstream, backup_upstream)
                routed = await router.execute(self.request_snapshot(), CancellationToken())
        self.assert_failover_success(routed, failure_category="upstream_transport_error")
        self.assertEqual(primary_upstream.connection_count, 1)
        self.assertEqual(backup_upstream.request_count, 1)
        self.assertFalse(routed.possible_double_charge)

        with _LoopbackTlsHandshakeFailureServer() as primary_upstream:
            with _LoopbackTlsHandshakeFailureServer() as backup_upstream:
                router, _breaker = self.router(primary_upstream, backup_upstream)
                await self.assert_one_aggregated_error(
                    router,
                    failure_category="upstream_transport_error",
                    possible_double_charge=False,
                )
        self.assertEqual(primary_upstream.connection_count, 1)
        self.assertEqual(backup_upstream.connection_count, 1)

    async def test_connection_reset_fails_over_and_both_fail_once(self) -> None:
        with _LoopbackResetServer() as primary_upstream:
            with ProgrammableResponsesMock() as backup_upstream:
                router, _breaker = self.router(primary_upstream, backup_upstream)
                routed = await router.execute(self.request_snapshot(), CancellationToken())
        self.assert_failover_success(routed, failure_category="upstream_transport_error")
        self.assertEqual(primary_upstream.connection_count, 1)
        self.assertEqual(backup_upstream.request_count, 1)
        self.assertTrue(routed.possible_double_charge)

        with _LoopbackResetServer() as primary_upstream:
            with _LoopbackResetServer() as backup_upstream:
                router, _breaker = self.router(primary_upstream, backup_upstream)
                await self.assert_one_aggregated_error(
                    router,
                    failure_category="upstream_transport_error",
                    possible_double_charge=True,
                )
        self.assertEqual(primary_upstream.connection_count, 1)
        self.assertEqual(backup_upstream.connection_count, 1)

    async def test_connection_refused_fails_over_and_both_fail_once(self) -> None:
        primary_upstream = _UpstreamEndpoint("https://p1.refused.invalid/v1")
        refusing_session = _ConnectionRefusingSession(
            self.session,
            {"p1.refused.invalid"},
        )
        with ProgrammableResponsesMock() as backup_upstream:
            router, _breaker = self.router(
                primary_upstream,
                backup_upstream,
                session=refusing_session,
            )
            routed = await router.execute(self.request_snapshot(), CancellationToken())
        self.assert_failover_success(routed, failure_category="upstream_transport_error")
        self.assertFalse(routed.primary_failure.request_started)
        self.assertEqual(backup_upstream.request_count, 1)
        self.assertFalse(routed.possible_double_charge)
        self.assertEqual(refusing_session.calls.count("p1.refused.invalid"), 1)
        self.assertEqual(refusing_session.calls.count("127.0.0.1"), 1)

        refusing_session = _ConnectionRefusingSession(
            self.session,
            {"p1.refused.invalid", "p2.refused.invalid"},
        )
        router, _breaker = self.router(
            primary_upstream,
            _UpstreamEndpoint("https://p2.refused.invalid/v1"),
            session=refusing_session,
        )
        await self.assert_one_aggregated_error(
            router,
            failure_category="upstream_transport_error",
            possible_double_charge=False,
        )
        self.assertEqual(
            refusing_session.calls,
            ["p1.refused.invalid", "p2.refused.invalid"],
        )

    async def test_cancel_after_backup_receives_body_preserves_double_charge_flag(self) -> None:
        primary_scenario = ScriptedScenario(
            name="primary_timeout",
            chunks=text_sse_frames("LATE_PRIMARY"),
            chunk_delays=(0.4,),
        )
        backup_scenario = ScriptedScenario(
            name="backup_cancelled",
            chunks=text_sse_frames("LATE_BACKUP"),
            chunk_delays=(2.0,),
        )
        with ProgrammableResponsesMock(lambda _request: primary_scenario) as primary_upstream:
            with ProgrammableResponsesMock(lambda _request: backup_scenario) as backup_upstream:
                router, _breaker = self.router(primary_upstream, backup_upstream)
                cancellation = CancellationToken()
                task = asyncio.create_task(router.execute(self.request_snapshot(), cancellation))
                for _ in range(200):
                    if backup_upstream.request_count == 1:
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(backup_upstream.request_count, 1)
                cancellation.cancel(CancelReason.CLIENT_DISCONNECTED)
                routed = await asyncio.wait_for(task, timeout=2)
        self.assertEqual(routed.cancelled, CancelReason.CLIENT_DISCONNECTED)
        self.assertEqual(primary_upstream.request_count, 1)
        self.assertEqual(backup_upstream.request_count, 1)
        self.assertTrue(routed.possible_double_charge)


if __name__ == "__main__":
    unittest.main()
