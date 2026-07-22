from __future__ import annotations

import asyncio
from contextlib import suppress
import time

import aiohttp

from .adapter import OpenAIResponsesAdapter
from .buffer import BoundedMemoryBuffer
from .cancellation import CancellationToken, RequestCancelled
from .models import AttemptFailure, AttemptPhase, AttemptResult, CancelReason, GatewayError, GatewayLimits, RequestSnapshot
from .protocols.responses import ResponsesProtocolValidator
from .public_values import public_protocol_code


class _TrackedBytesPayload(aiohttp.payload.BytesPayload):
    def __init__(self, value: bytes, on_write) -> None:
        super().__init__(value)
        self._on_write = on_write

    async def write(self, writer) -> None:
        self._on_write()
        await super().write(writer)

    async def write_with_length(self, writer, content_length) -> None:
        self._on_write()
        await super().write_with_length(writer, content_length)


class SingleRouteAttemptRunner:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        adapter: OpenAIResponsesAdapter,
        limits: GatewayLimits,
        validator: ResponsesProtocolValidator | None = None,
    ) -> None:
        self._session = session
        self._adapter = adapter
        self._limits = limits
        self._validator = validator or ResponsesProtocolValidator()

    async def run(
        self,
        snapshot: RequestSnapshot,
        bearer: str,
        cancellation: CancellationToken,
    ) -> AttemptResult:
        phase = AttemptPhase.BEFORE_REQUEST
        request_started = False
        response_bytes_received = 0
        try:
            started = time.monotonic()
            cancellation.raise_if_cancelled()
            request = self._adapter.build_request(snapshot, bearer)
            phase = AttemptPhase.AWAITING_HEADERS

            def mark_request_started() -> None:
                nonlocal request_started
                request_started = True

            response = await self._await_with_cancel(
                self._session.post(
                    request.url,
                    data=_TrackedBytesPayload(request.body, mark_request_started),
                    headers=dict(request.headers),
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=None, connect=self._limits.connect_timeout_seconds),
                ),
                cancellation,
                self._limits.first_byte_timeout_seconds,
            )
            reusable_response = False
            try:
                if response.status < 200 or response.status >= 300:
                    return AttemptResult(
                        failure=AttemptFailure(
                            category="upstream_http_error",
                            public_code=f"guardian_upstream_http_{response.status}",
                            http_status=response.status,
                            possible_double_charge=False,
                            phase=phase,
                            request_started=request_started,
                            response_bytes_received=0,
                            retry_after=response.headers.get("Retry-After"),
                            adapter_action_required=self._adapter.is_action_required_status(response.status),
                            possible_server_side_effects=(
                                request_started and response.status >= 500
                            ),
                        )
                    )
                phase = AttemptPhase.READING_BODY
                buffer = BoundedMemoryBuffer(self._limits.max_response_bytes)
                deadline = started + self._limits.total_timeout_seconds
                first_chunk = True
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    chunk = await self._await_with_cancel(
                        response.content.read(self._limits.read_chunk_bytes),
                        cancellation,
                        min(
                            self._limits.first_byte_timeout_seconds if first_chunk else self._limits.idle_timeout_seconds,
                            remaining,
                        ),
                    )
                    if not chunk:
                        break
                    first_chunk = False
                    buffer.append(chunk, cancellation)
                    response_bytes_received += len(chunk)
                cancellation.raise_if_cancelled()
                chunks = buffer.seal()
                phase = AttemptPhase.VALIDATING
                complete = self._validator.validate(
                    response.status,
                    response.headers.get("Content-Type", ""),
                    chunks,
                    max_bytes=self._limits.max_response_bytes,
                )
                reusable_response = True
                return AttemptResult(complete=complete)
            finally:
                self._finalize_response(response, reusable_response)
        except RequestCancelled as exc:
            return AttemptResult(
                cancelled=exc.reason,
                request_started=request_started,
                response_bytes_received=response_bytes_received,
            )
        except asyncio.TimeoutError:
            possible_double_charge = phase is not AttemptPhase.BEFORE_REQUEST
            return AttemptResult(
                failure=AttemptFailure(
                    category="upstream_timeout",
                    public_code="guardian_upstream_timeout",
                    possible_double_charge=possible_double_charge,
                    phase=phase,
                    request_started=request_started,
                    response_bytes_received=response_bytes_received,
                    possible_server_side_effects=request_started,
                )
            )
        except GatewayError as exc:
            return AttemptResult(
                failure=AttemptFailure(
                    category="protocol_or_local_error",
                    public_code=(
                        exc.code
                        if exc.code in {
                            "guardian_response_too_large",
                            "guardian_upstream_credential_unavailable",
                        }
                        else public_protocol_code(exc.code)
                    ),
                    http_status=exc.http_status,
                    possible_double_charge=request_started and (
                        response_bytes_received > 0 or phase is AttemptPhase.VALIDATING
                    ),
                    phase=phase,
                    request_started=request_started,
                    response_bytes_received=response_bytes_received,
                    possible_server_side_effects=request_started and (
                        response_bytes_received > 0 or phase is AttemptPhase.VALIDATING
                    ),
                )
            )
        except (aiohttp.ClientError, OSError) as exc:
            definite_connection_failure = isinstance(
                exc,
                (
                    aiohttp.ClientConnectorError,
                    aiohttp.ClientConnectorDNSError,
                    aiohttp.ClientConnectorCertificateError,
                    aiohttp.ClientConnectorSSLError,
                    aiohttp.InvalidURL,
                ),
            )
            possible_double_charge = request_started and not definite_connection_failure
            return AttemptResult(
                failure=AttemptFailure(
                    category="upstream_transport_error",
                    public_code="guardian_upstream_transport_error",
                    possible_double_charge=possible_double_charge,
                    phase=phase,
                    request_started=request_started,
                    response_bytes_received=response_bytes_received,
                    possible_server_side_effects=possible_double_charge,
                )
            )

    async def _await_with_cancel(self, awaitable, cancellation: CancellationToken, timeout: float):
        operation = asyncio.ensure_future(awaitable)
        cancelled = asyncio.create_task(cancellation.wait())
        try:
            done, _pending = await asyncio.wait(
                {operation, cancelled},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancelled in done:
                reason = cancelled.result()
                await self._cancel_and_discard(operation)
                raise RequestCancelled(reason)
            if operation not in done:
                await self._cancel_and_discard(operation)
                raise asyncio.TimeoutError
            return operation.result()
        except BaseException:
            await self._cancel_and_discard(operation)
            raise
        finally:
            cancelled.cancel()
            with suppress(Exception, asyncio.CancelledError):
                await cancelled

    async def _cancel_and_discard(self, task: asyncio.Future) -> None:
        task.cancel()
        try:
            result = await task
        except (Exception, asyncio.CancelledError):
            return
        self._discard_abandoned_result(result)

    @staticmethod
    def _discard_abandoned_result(result) -> None:
        if isinstance(result, aiohttp.ClientResponse):
            result.close()

    @staticmethod
    def _finalize_response(response: aiohttp.ClientResponse, reusable: bool) -> None:
        if reusable:
            response.release()
        else:
            response.close()
