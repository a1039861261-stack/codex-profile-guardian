from __future__ import annotations

import asyncio
from typing import Protocol

from .cancellation import CancellationToken
from .models import BufferedResponse, CommitResult, CommitState


class DownstreamWriter(Protocol):
    async def prepare(self, status: int, content_type: str, content_length: int) -> None: ...

    async def write(self, chunk: bytes) -> None: ...

    async def finish(self) -> None: ...


class Committer:
    def __init__(self, chunk_bytes: int = 64 * 1024) -> None:
        if chunk_bytes <= 0:
            raise ValueError("commit_chunk_must_be_positive")
        self._chunk_bytes = chunk_bytes
        self._state = CommitState.UNCOMMITTED
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CommitState:
        return self._state

    @property
    def uncommitted(self) -> bool:
        return self._state is CommitState.UNCOMMITTED

    async def commit(
        self,
        response: BufferedResponse,
        downstream: DownstreamWriter,
        cancellation: CancellationToken,
    ) -> CommitResult:
        return await self._commit(
            response,
            downstream,
            cancellation,
            completed_state=CommitState.DELIVERED,
        )

    async def commit_error(
        self,
        response: BufferedResponse,
        downstream: DownstreamWriter,
        cancellation: CancellationToken,
    ) -> CommitResult:
        if response.status < 400:
            raise ValueError("error_response_requires_http_error_status")
        return await self._commit(
            response,
            downstream,
            cancellation,
            completed_state=CommitState.ERROR_COMMITTED,
        )

    async def _commit(
        self,
        response: BufferedResponse,
        downstream: DownstreamWriter,
        cancellation: CancellationToken,
        *,
        completed_state: CommitState,
    ) -> CommitResult:
        async with self._lock:
            if self._state is not CommitState.UNCOMMITTED:
                raise RuntimeError("response_already_committed")
            cancellation.raise_if_cancelled()
            self._state = CommitState.COMMITTING
            written = 0
            try:
                await downstream.prepare(response.status, response.content_type, len(response.body))
                for offset in range(0, len(response.body), self._chunk_bytes):
                    cancellation.raise_if_cancelled()
                    chunk = response.body[offset : offset + self._chunk_bytes]
                    await downstream.write(chunk)
                    written += len(chunk)
                cancellation.raise_if_cancelled()
                await downstream.finish()
                cancellation.raise_if_cancelled()
                self._state = completed_state
                return CommitResult(state=self._state, bytes_written=written)
            except (Exception, asyncio.CancelledError) as exc:
                self._state = CommitState.DELIVERY_UNCERTAIN
                return CommitResult(
                    state=self._state,
                    bytes_written=written,
                    error_type=type(exc).__name__,
                )
