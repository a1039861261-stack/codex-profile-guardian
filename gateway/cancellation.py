from __future__ import annotations

import asyncio

from .models import CancelReason


class CancellationToken:
    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._reason: CancelReason | None = None

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> CancelReason | None:
        return self._reason

    def cancel(self, reason: CancelReason) -> bool:
        if self._event.is_set():
            return False
        self._reason = reason
        self._event.set()
        return True

    async def wait(self) -> CancelReason:
        await self._event.wait()
        if self._reason is None:
            raise RuntimeError("cancel_reason_missing")
        return self._reason

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise RequestCancelled(self._reason or CancelReason.CLIENT_DISCONNECTED)


class RequestCancelled(Exception):
    def __init__(self, reason: CancelReason) -> None:
        super().__init__(reason.value)
        self.reason = reason
