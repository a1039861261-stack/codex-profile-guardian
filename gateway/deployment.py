from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
import inspect
from pathlib import Path
from typing import TypeAlias

from .platforms.windows import (
    InstalledRelease,
    ReleaseError,
    ReleasePointer,
    VersionedReleaseStore,
)


CallbackResult: TypeAlias = bool | Mapping[str, object] | None
LifecycleCallback: TypeAlias = Callable[[], CallbackResult | Awaitable[CallbackResult]]
ReleaseCallback: TypeAlias = Callable[[InstalledRelease], CallbackResult | Awaitable[CallbackResult]]


class GatewayDeploymentError(RuntimeError):
    def __init__(self, code: str, *, recovered: bool, cause: BaseException | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.recovered = recovered
        if cause is not None:
            self.__cause__ = cause


@dataclass(frozen=True, slots=True)
class UpgradeResult:
    previous_version: str
    active_version: str
    installed_path: Path
    content_sha256: str
    manifest_sha256: str


class GatewayDeploymentManager:
    def __init__(
        self,
        store: VersionedReleaseStore,
        *,
        drain: LifecycleCallback,
        stop: LifecycleCallback,
        start: ReleaseCallback,
        verify_health: ReleaseCallback,
    ) -> None:
        if not isinstance(store, VersionedReleaseStore):
            raise TypeError("gateway_deployment_store_required")
        for callback in (drain, stop, start, verify_health):
            if not callable(callback):
                raise TypeError("gateway_deployment_callback_required")
        self._store = store
        self._drain = drain
        self._stop = stop
        self._start = start
        self._verify_health = verify_health
        self._upgrade_lock = asyncio.Lock()

    async def upgrade(self, version: str, source: str | Path) -> UpgradeResult:
        async with self._upgrade_lock:
            return await self._upgrade_locked(version, source)

    async def _upgrade_locked(self, version: str, source: str | Path) -> UpgradeResult:
        try:
            previous_pointer = self._store.load_pointer()
        except ReleaseError as exc:
            raise GatewayDeploymentError(
                "gateway_upgrade_current_release_invalid",
                recovered=False,
                cause=exc,
            ) from exc
        if previous_pointer is None:
            raise GatewayDeploymentError("gateway_upgrade_current_release_missing", recovered=False)
        previous_release = self._store.inspect(previous_pointer.version)
        try:
            installed = self._store.install(version, source)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise GatewayDeploymentError("gateway_upgrade_install_failed", recovered=True, cause=exc) from exc

        activation_attempted = False
        stop_attempted = False
        old_process_stopped = False
        try:
            await self._invoke(self._drain, "gateway_upgrade_drain_failed")
            stop_attempted = True
            await self._invoke(self._stop, "gateway_upgrade_stop_failed")
            old_process_stopped = True
            activation_attempted = True
            self._store.activate(installed.version)
            await self._invoke(self._start, "gateway_upgrade_start_failed", installed)
            await self._require_healthy(installed)
        except BaseException as exc:
            recovered = await self._recover(
                previous_pointer,
                previous_release,
                activation_attempted=activation_attempted,
                stop_attempted=stop_attempted,
                old_process_stopped=old_process_stopped,
            )
            if isinstance(exc, asyncio.CancelledError):
                raise
            if isinstance(exc, GatewayDeploymentError):
                raise GatewayDeploymentError(exc.code, recovered=recovered, cause=exc.__cause__ or exc) from exc
            raise GatewayDeploymentError("gateway_upgrade_failed", recovered=recovered, cause=exc) from exc

        return UpgradeResult(
            previous_version=previous_release.version,
            active_version=installed.version,
            installed_path=installed.path,
            content_sha256=installed.content_sha256,
            manifest_sha256=installed.manifest_sha256,
        )

    async def _recover(
        self,
        previous_pointer: ReleasePointer,
        previous_release: InstalledRelease,
        *,
        activation_attempted: bool,
        stop_attempted: bool,
        old_process_stopped: bool,
    ) -> bool:
        try:
            if activation_attempted:
                try:
                    await self._invoke(
                        self._stop,
                        "gateway_upgrade_recovery_stop_failed",
                    )
                except BaseException:
                    return False
                self._store.restore_pointer(previous_pointer)
            if stop_attempted and not old_process_stopped and not activation_attempted:
                try:
                    await self._require_healthy(previous_release, recovery=True)
                    return self._store.load_pointer() == previous_pointer
                except BaseException:
                    pass
            if old_process_stopped or activation_attempted or stop_attempted:
                await self._invoke(
                    self._start,
                    "gateway_upgrade_recovery_start_failed",
                    previous_release,
                )
                await self._require_healthy(previous_release, recovery=True)
            return self._store.load_pointer() == previous_pointer
        except BaseException:
            return False

    async def _require_healthy(self, release: InstalledRelease, *, recovery: bool = False) -> None:
        code = "gateway_upgrade_recovery_health_failed" if recovery else "gateway_upgrade_health_failed"
        await self._invoke(self._verify_health, code, release)

    async def _invoke(self, callback: Callable[..., object], code: str, *args: object) -> None:
        try:
            resolved = await self._await_result(callback(*args))
        except asyncio.CancelledError:
            raise
        except GatewayDeploymentError:
            raise
        except Exception as exc:
            raise GatewayDeploymentError(code, recovered=False, cause=exc) from exc
        if not self._is_success(resolved):
            raise GatewayDeploymentError(code, recovered=False)

    @staticmethod
    async def _await_result(result: CallbackResult | Awaitable[CallbackResult]) -> CallbackResult:
        if inspect.isawaitable(result):
            return await result
        return result

    @staticmethod
    def _is_success(result: CallbackResult) -> bool:
        if result is None or result is True:
            return True
        if result is False:
            return False
        return result.get("ok") is True
