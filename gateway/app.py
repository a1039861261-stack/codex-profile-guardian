from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import sys
import time
from typing import Mapping
import uuid

import aiohttp
from aiohttp import web

from .breaker import BreakerSnapshot, BreakerState, CircuitBreakerRegistry
from .config import RouteRole
from .cleanup import cleanup_registered_spool
from .control import GatewayControlOperationError, GatewayControlServer
from .dpapi import protect_current_user, unprotect_current_user
from .failures import FailureClassifier
from .file_journal import RotatingAllowlistJournal
from .health import DiskWatermark
from .ingress import GatewayIngress
from .lifecycle_config import (
    ActiveConfigError,
    LifecycleConfig,
    load_active_config,
    parse_active_config,
)
from .runtime import AtomicFailoverRouterProvider
from .runtime_files import RuntimeDescriptor, RuntimeDescriptorStore, utc_now
from .secrets import PosixFileSecretResolver, ProtectedFileSecretResolver
from .service import FailoverGatewayCore
from .singleton import SingleInstanceLock
from .state import AtomicBreakerStateStore
from .tokens import PosixTokenStore, ProtectedTokenStore
from .platforms.linux import LinuxGatewayLayout, reject_link_chain
from .probe_scheduler import ModelsProbeResult, ModelsProbeScheduler


class GatewayHostError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _PreparedConfig:
    config: LifecycleConfig
    payload: bytes
    config_sha256: str
    base_revision: int
    base_file_sha256: str
    expires_at_monotonic: float
    expires_at_epoch: float
    pending_file_sha256: str


_PROFILE_SECRET_REFERENCE = re.compile(
    r"\Aprofile:[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}:r[1-9][0-9]{0,18}\Z"
)
_MAX_CONFIG_BYTES = 1024 * 1024


class GatewayProcessHost:
    def __init__(
        self,
        *,
        install_root: str | Path,
        config_path: str | Path,
        protect=protect_current_user,
        unprotect=unprotect_current_user,
        prepared_config_ttl_seconds: float = 300.0,
        platform: str = "windows",
        home: str | Path | None = None,
    ) -> None:
        if not 0 < prepared_config_ttl_seconds <= 3600:
            raise ValueError("gateway_prepared_config_ttl_invalid")
        if platform not in {"windows", "linux"}:
            raise ValueError("gateway_platform_invalid")
        self.platform = platform
        self.install_root = Path(install_root).resolve()
        self.config_path = Path(config_path).resolve()
        self._protect = protect
        self._unprotect = unprotect
        self._linux_layout: LinuxGatewayLayout | None = None
        if platform == "linux":
            if home is None:
                raise ValueError("gateway_linux_home_required")
            layout = LinuxGatewayLayout(Path(home))
            if self.install_root != layout.gateway_root.resolve():
                raise ValueError("gateway_linux_install_root_invalid")
            if self.config_path != (layout.config / "active.json").resolve():
                raise ValueError("gateway_linux_config_path_invalid")
            layout.ensure_private_directories()
            reject_link_chain(layout.home, self.config_path.parent)
            self._linux_layout = layout
            self._runtime_root = layout.state / "runtime"
            self._state_root = layout.state
            self._profiles_root = layout.secrets
            self._tokens_root = layout.config / "tokens"
            self._spool_root = layout.spool
            journal_path = layout.logs / "lifecycle.jsonl"
        else:
            if home is not None:
                raise ValueError("gateway_windows_home_forbidden")
            self._runtime_root = self.install_root / "gateway" / "runtime"
            self._state_root = self.install_root / "gateway" / "state"
            secrets_root = self.install_root / "gateway" / "secrets"
            self._profiles_root = secrets_root / "profiles"
            self._tokens_root = secrets_root / "tokens"
            self._spool_root = self.install_root / "gateway" / "spool"
            journal_path = self.install_root / "gateway" / "logs" / "lifecycle.jsonl"
        self._pending_config_path = self.config_path.parent / "pending" / "prepared.json"
        self._lock = SingleInstanceLock(self._runtime_root / "gateway.lock")
        self._descriptor_store = RuntimeDescriptorStore(self._runtime_root / "runtime.json")
        self._process_instance_id = uuid.uuid4().hex
        self._gateway_started_at = utc_now()
        self._process_started_at = _process_start_time()
        self._session: aiohttp.ClientSession | None = None
        self._config: LifecycleConfig | None = None
        self._breaker: CircuitBreakerRegistry | None = None
        self._provider: AtomicFailoverRouterProvider | None = None
        self._core: FailoverGatewayCore | None = None
        self._ingress: GatewayIngress | None = None
        self._data_runner: web.AppRunner | None = None
        self._control_runner: web.AppRunner | None = None
        self._data_site: web.TCPSite | None = None
        self._control_site: web.TCPSite | None = None
        self._probe_scheduler: ModelsProbeScheduler | None = None
        self._stop_event = asyncio.Event()
        self._phase = "created"
        self._tokens: Mapping[str, str] = {}
        self._secret_resolver: ProtectedFileSecretResolver | PosixFileSecretResolver | None = None
        self._disk: DiskWatermark | None = None
        self._journal = RotatingAllowlistJournal(journal_path)
        self._config_transaction_lock = asyncio.Lock()
        self._prepared_config_ttl_seconds = float(prepared_config_ttl_seconds)
        self._prepared_config: _PreparedConfig | None = None
        self._active_config_sha256 = ""
        self._active_file_sha256 = ""

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def config(self) -> LifecycleConfig:
        if self._config is None:
            raise RuntimeError("gateway_config_not_loaded")
        return self._config

    @property
    def ingress_token(self) -> str:
        return self._tokens["ingress"]

    @property
    def control_token(self) -> str:
        return self._tokens["control"]

    async def start(self) -> None:
        if self._phase != "created":
            raise GatewayHostError("gateway_host_already_started")
        self._phase = "starting"
        self._lock.acquire()
        try:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=ssl.create_default_context()),
                trust_env=False,
            )
            config = load_active_config(self.config_path, self._session)
            self._config = config
            active_payload = _canonical_config_payload_from_path(self.config_path)
            self._active_config_sha256 = _bytes_sha256(active_payload)
            self._active_file_sha256 = _sha256(self.config_path)
            self._ensure_version_pointer(config.version)
            resolver = self._build_secret_resolver()
            self._secret_resolver = resolver
            self._recover_prepared_config()
            self._preflight_ports(config)
            token_store = self._build_token_store()
            self._tokens = token_store.ensure()
            cleanup_registered_spool(
                self._spool_root,
                self._spool_root / "active.json",
            )
            self._disk = DiskWatermark(
                self._disk_watermark_root(),
                config.minimum_free_bytes,
            )
            breaker = CircuitBreakerRegistry()
            state_store = AtomicBreakerStateStore(self._state_root / "breaker.json")
            provider = AtomicFailoverRouterProvider(
                config.active_group,
                breaker,
                FailureClassifier(),
                resolver,
                state_store=state_store,
            )
            core = FailoverGatewayCore(provider, config.limits)
            ingress = GatewayIngress(
                core,
                config.limits,
                ingress_token=self.ingress_token,
                version=config.version,
                health_metadata=self._health_metadata,
                admission_check=self._admission_error,
                allowed_hosts=(
                    f"127.0.0.1:{config.data_port}",
                    f"localhost:{config.data_port}",
                ),
            )
            control = GatewayControlServer(
                control_token=self.control_token,
                status=self.status,
                drain=self.drain,
                resume=self.resume,
                reload_config=self.reload,
                prepare_config=self.prepare_config,
                activate_config=self.activate_config,
                abort_config=self.abort_config,
                failover_snapshot=self.failover_snapshot,
                failover_events=self.failover_events,
                retest_route=self.retest_route,
                stop=self.stop,
                allowed_hosts=(
                    f"127.0.0.1:{config.control_port}",
                    f"localhost:{config.control_port}",
                ),
            )
            data_runner = ingress.create_runner(access_log=None)
            control_runner = control.create_runner(access_log=None)
            await data_runner.setup()
            await control_runner.setup()
            data_site = web.TCPSite(data_runner, config.host, config.data_port)
            control_site = web.TCPSite(control_runner, config.host, config.control_port)
            await data_site.start()
            try:
                await control_site.start()
            except Exception:
                await data_runner.cleanup()
                raise
            self._breaker = breaker
            self._provider = provider
            self._core = core
            self._ingress = ingress
            self._data_runner = data_runner
            self._control_runner = control_runner
            self._data_site = data_site
            self._control_site = control_site
            if config.active_group.probe_policy.enabled:
                self._probe_scheduler = ModelsProbeScheduler(
                    config_provider=provider.current_config,
                    breaker=breaker,
                    session=self._session,
                    resolve_secret=resolver.resolve,
                    on_result=self._record_probe_result,
                )
                self._probe_scheduler.start()
            self._write_descriptor()
            self._phase = "running"
            self._record("gateway_started", "running")
        except Exception:
            await self._cleanup_started_resources()
            self._descriptor_store.remove_if_owned(self._process_instance_id)
            self._lock.release()
            self._phase = "failed"
            raise

    async def run(self) -> None:
        await self.start()
        await self._stop_event.wait()
        await self.close()

    async def drain(self, timeout_seconds: float | None = None) -> Mapping[str, object]:
        ingress = self._required_ingress()
        if self._phase not in {"running", "draining"}:
            raise GatewayHostError("gateway_drain_invalid_phase")
        timeout = self.config.drain_timeout_seconds if timeout_seconds is None else timeout_seconds
        self._phase = "draining"
        active = await ingress.begin_drain()
        drained = await ingress.wait_drained(timeout)
        self._write_descriptor()
        self._record(
            "gateway_drained" if drained else "gateway_drain_timeout",
            "drained" if drained else "timeout",
            active_requests=ingress.active_requests,
        )
        return {
            "ok": drained,
            "phase": self._phase,
            "initial_active_requests": active,
            "active_requests": ingress.active_requests,
        }

    async def resume(self) -> Mapping[str, object]:
        ingress = self._required_ingress()
        if self._phase not in {"running", "draining"}:
            raise GatewayHostError("gateway_resume_invalid_phase")
        await ingress.resume()
        self._phase = "running"
        self._write_descriptor()
        return {"ok": True, "phase": self._phase}

    async def prepare_config(self, document: Mapping[str, object]) -> Mapping[str, object]:
        if self._session is None or self._provider is None:
            raise GatewayControlOperationError(409, "guardian_config_gateway_not_running")
        if self._phase not in {"running", "draining"}:
            raise GatewayControlOperationError(409, "guardian_config_gateway_not_running")
        async with self._config_transaction_lock:
            self._expire_prepared_config()
            try:
                active_file_sha256 = _sha256(self.config_path)
            except OSError as exc:
                raise GatewayControlOperationError(
                    500,
                    "guardian_config_active_read_failed",
                ) from exc
            if active_file_sha256 != self._active_file_sha256:
                raise GatewayControlOperationError(409, "guardian_config_active_changed")
            try:
                payload = _canonical_config_payload(document)
            except (TypeError, ValueError) as exc:
                raise GatewayControlOperationError(400, "guardian_config_invalid") from exc
            if len(payload) > _MAX_CONFIG_BYTES:
                raise GatewayControlOperationError(413, "guardian_config_too_large")
            canonical_document = json.loads(payload.decode("utf-8"))
            try:
                candidate = parse_active_config(canonical_document, self._session)
            except ActiveConfigError as exc:
                raise GatewayControlOperationError(400, "guardian_config_invalid") from exc
            candidate_sha256 = _bytes_sha256(payload)
            current_revision = self.config.active_group.revision
            candidate_revision = candidate.active_group.revision
            if candidate_revision == current_revision:
                if candidate_sha256 != self._active_config_sha256:
                    raise GatewayControlOperationError(
                        409,
                        "guardian_config_revision_conflict",
                    )
                return {
                    "ok": True,
                    "phase": self._phase,
                    "config_revision": current_revision,
                    "config_sha256": candidate_sha256,
                    "state": "active",
                    "idempotent": True,
                }
            self._validate_prepared_candidate(candidate)
            existing = self._prepared_config
            if existing is not None:
                if (
                    existing.config.active_group.revision == candidate_revision
                    and existing.config_sha256 == candidate_sha256
                ):
                    return {
                        "ok": True,
                        "phase": self._phase,
                        "config_revision": candidate_revision,
                        "config_sha256": candidate_sha256,
                        "state": "prepared",
                        "idempotent": True,
                    }
                if existing.config.active_group.revision == candidate_revision:
                    raise GatewayControlOperationError(
                        409,
                        "guardian_config_revision_conflict",
                    )
                raise GatewayControlOperationError(
                    409,
                    "guardian_config_prepare_in_progress",
                )
            now_epoch = time.time()
            expires_at_epoch = now_epoch + self._prepared_config_ttl_seconds
            envelope = _prepared_envelope_payload(
                canonical_document,
                base_revision=current_revision,
                base_file_sha256=self._active_file_sha256,
                config_revision=candidate_revision,
                config_sha256=candidate_sha256,
                expires_at_epoch=expires_at_epoch,
            )
            try:
                _atomic_write_bytes(self._pending_config_path, envelope)
            except OSError as exc:
                raise GatewayControlOperationError(
                    500,
                    "guardian_config_prepare_write_failed",
                ) from exc
            self._prepared_config = _PreparedConfig(
                config=candidate,
                payload=payload,
                config_sha256=candidate_sha256,
                base_revision=current_revision,
                base_file_sha256=self._active_file_sha256,
                expires_at_monotonic=time.monotonic() + self._prepared_config_ttl_seconds,
                expires_at_epoch=expires_at_epoch,
                pending_file_sha256=_bytes_sha256(envelope),
            )
            return {
                "ok": True,
                "phase": self._phase,
                "config_revision": candidate_revision,
                "config_sha256": candidate_sha256,
                "state": "prepared",
                "idempotent": False,
            }

    async def activate_config(
        self,
        revision: int,
        config_sha256: str,
    ) -> Mapping[str, object]:
        if self._session is None or self._provider is None:
            raise GatewayControlOperationError(409, "guardian_config_gateway_not_running")
        if self._phase not in {"running", "draining"}:
            raise GatewayControlOperationError(409, "guardian_config_gateway_not_running")
        async with self._config_transaction_lock:
            current_revision = self.config.active_group.revision
            if revision == current_revision:
                if config_sha256 != self._active_config_sha256:
                    raise GatewayControlOperationError(
                        409,
                        "guardian_config_revision_conflict",
                    )
                return {
                    "ok": True,
                    "phase": self._phase,
                    "config_revision": current_revision,
                    "config_sha256": config_sha256,
                    "state": "active",
                    "idempotent": True,
                }
            expired = self._expire_prepared_config()
            prepared = self._prepared_config
            if prepared is None:
                code = (
                    "guardian_config_prepare_expired"
                    if expired
                    else "guardian_config_not_prepared"
                )
                raise GatewayControlOperationError(409, code)
            if revision != prepared.config.active_group.revision:
                raise GatewayControlOperationError(
                    409,
                    "guardian_config_revision_mismatch",
                )
            if config_sha256 != prepared.config_sha256:
                raise GatewayControlOperationError(409, "guardian_config_hash_mismatch")
            if prepared.base_revision != current_revision:
                self._discard_prepared_config()
                raise GatewayControlOperationError(409, "guardian_config_active_changed")
            try:
                active_file_sha256 = _sha256(self.config_path)
                pending_file_sha256 = _sha256(self._pending_config_path)
                old_payload = self.config_path.read_bytes()
            except OSError as exc:
                raise GatewayControlOperationError(
                    500,
                    "guardian_config_active_read_failed",
                ) from exc
            if (
                active_file_sha256 != prepared.base_file_sha256
                or active_file_sha256 != self._active_file_sha256
            ):
                self._discard_prepared_config()
                raise GatewayControlOperationError(409, "guardian_config_active_changed")
            if pending_file_sha256 != prepared.pending_file_sha256:
                self._discard_prepared_config()
                raise GatewayControlOperationError(409, "guardian_config_prepared_changed")

            next_disk = DiskWatermark(
                self._disk_watermark_root(),
                prepared.config.minimum_free_bytes,
            )
            candidate_temporary: Path | None = None
            rollback_temporary: Path | None = None
            replaced = False
            try:
                candidate_temporary = _write_sibling_temporary(
                    self.config_path,
                    prepared.payload,
                )
                rollback_temporary = _write_sibling_temporary(
                    self.config_path,
                    old_payload,
                )
                os.replace(candidate_temporary, self.config_path)
                candidate_temporary = None
                replaced = True
                self._provider.activate(prepared.config.active_group)
            except Exception as exc:
                if replaced:
                    try:
                        if rollback_temporary is None:
                            raise OSError("gateway_config_rollback_missing")
                        os.replace(rollback_temporary, self.config_path)
                        rollback_temporary = None
                    except OSError as rollback_exc:
                        self._phase = "failed"
                        if self._ingress is not None:
                            await self._ingress.begin_drain()
                        try:
                            self._write_descriptor()
                        except Exception:
                            pass
                        try:
                            self._record("gateway_config_rollback_failed", "failed")
                        except Exception:
                            pass
                        raise GatewayControlOperationError(
                            500,
                            "guardian_config_rollback_failed",
                        ) from rollback_exc
                if isinstance(exc, OSError):
                    raise GatewayControlOperationError(
                        500,
                        "guardian_config_activate_write_failed",
                    ) from exc
                raise GatewayControlOperationError(
                    409,
                    "guardian_config_activation_rejected",
                ) from exc
            finally:
                _unlink_quietly(candidate_temporary)
                _unlink_quietly(rollback_temporary)

            self._config = prepared.config
            self._disk = next_disk
            self._active_config_sha256 = prepared.config_sha256
            self._active_file_sha256 = prepared.config_sha256
            self._prepared_config = None
            pending_cleanup_complete = _unlink_quietly(self._pending_config_path)
            probe_scheduler_synced = self._reconcile_probe_scheduler_after_commit()
            descriptor_synced = True
            try:
                self._write_descriptor()
            except Exception:
                descriptor_synced = False
            try:
                self._record("gateway_config_activated", "running")
            except Exception:
                pass
            return {
                "ok": True,
                "phase": self._phase,
                "config_revision": revision,
                "config_sha256": config_sha256,
                "state": "active",
                "idempotent": False,
                "pending_cleanup_complete": pending_cleanup_complete,
                "probe_scheduler_synced": probe_scheduler_synced,
                "runtime_descriptor_synced": descriptor_synced,
            }

    async def abort_config(
        self,
        revision: int,
        config_sha256: str,
    ) -> Mapping[str, object]:
        if self._phase not in {"running", "draining"}:
            raise GatewayControlOperationError(409, "guardian_config_gateway_not_running")
        async with self._config_transaction_lock:
            expired = self._expire_prepared_config()
            prepared = self._prepared_config
            if prepared is None:
                if expired:
                    raise GatewayControlOperationError(409, "guardian_config_prepare_expired")
                return {
                    "ok": True,
                    "phase": self._phase,
                    "config_revision": self.config.active_group.revision,
                    "state": "not_prepared",
                    "idempotent": True,
                }
            if revision != prepared.config.active_group.revision:
                raise GatewayControlOperationError(409, "guardian_config_revision_mismatch")
            if config_sha256 != prepared.config_sha256:
                raise GatewayControlOperationError(409, "guardian_config_hash_mismatch")
            self._discard_prepared_config()
            try:
                self._record("gateway_config_aborted", self._phase)
            except Exception:
                pass
            return {
                "ok": True,
                "phase": self._phase,
                "config_revision": self.config.active_group.revision,
                "state": "aborted",
                "idempotent": False,
            }

    def failover_snapshot(self) -> Mapping[str, object]:
        config = self.config.active_group
        breaker = self._breaker
        if breaker is None:
            raise GatewayHostError("gateway_breaker_not_ready")
        snapshots = {
            item.route_key.route_role: item
            for item in breaker.snapshots()
            if item.route_key.group_id == config.group_id
        }
        primary = self._route_snapshot(snapshots.get("primary"), "primary")
        backup = self._route_snapshot(snapshots.get("backup"), "backup")
        probe_results = self._latest_probe_results()
        for role, route in (("primary", primary), ("backup", backup)):
            probe = probe_results.get(role)
            if probe is not None:
                route["last_status_category"] = str(
                    probe.get("http_status_category") or ""
                )
        recent = self._recent_business_events()
        carrier = self._carrier_from_events(recent, primary, backup)
        primary["carrying"] = carrier == "primary"
        backup["carrying"] = carrier == "backup"
        if primary["action_required"]:
            action = "check_primary"
        elif not self._route_available(primary) and not self._route_available(backup):
            action = "repair_route"
        else:
            action = "none"
        return {
            "source": "production",
            "view_state": "ready",
            "phase": self._phase,
            "config_revision": config.revision,
            "active_group_id": config.group_id,
            "carrier": carrier,
            "required_action": action,
            "routes": {"primary": primary, "backup": backup},
        }

    def failover_events(self) -> Mapping[str, object]:
        events: list[dict[str, object]] = []
        core = self._core
        if core is not None:
            for item in core.journal.snapshot():
                events.append(self._public_core_event(item))
        breaker = self._breaker
        if breaker is not None:
            for item in breaker.transition_events():
                events.append(
                    {
                        "event_id": item.event_id,
                        "timestamp": item.timestamp,
                        "event": "breaker_transition",
                        "status": item.new_state.value,
                        "route_role": item.route_key.route_role,
                        "failover_used": False,
                        "possible_double_charge": False,
                        "http_status_category": self._status_category(item.http_status),
                        "config_revision": item.config_revision,
                    }
                )
        for item in self._journal.snapshot(limit=256):
            events.append(self._public_lifecycle_event(item))
        events.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
        return {"source": "production", "items": events[:256]}

    async def retest_route(self, group_id: str, route_role: str) -> Mapping[str, object]:
        config = self.config.active_group
        if group_id != config.group_id:
            raise GatewayControlOperationError(409, "guardian_retest_group_not_active")
        try:
            role = RouteRole(route_role)
        except ValueError as exc:
            raise GatewayControlOperationError(400, "guardian_retest_role_invalid") from exc
        if self._session is None or self._breaker is None or self._secret_resolver is None:
            raise GatewayControlOperationError(409, "guardian_retest_gateway_not_ready")
        scheduler = ModelsProbeScheduler(
            config_provider=lambda: self.config.active_group,
            breaker=self._breaker,
            session=self._session,
            resolve_secret=self._secret_resolver.resolve,
            on_result=self._record_probe_result,
        )
        result = await scheduler.probe_role(role)
        snapshot = self.failover_snapshot()
        return {
            "source": "production",
            "group_id": group_id,
            "route_role": route_role,
            "ok": result.ok,
            "status": "success" if result.ok else result.category,
            "http_status_category": self._status_category(result.http_status),
            "config_revision": config.revision,
            "snapshot": snapshot,
        }

    def _recent_business_events(self) -> tuple[Mapping[str, object], ...]:
        core = self._core
        if core is None:
            return ()
        return tuple(reversed(core.journal.snapshot()))

    @staticmethod
    def _carrier_from_events(
        events: tuple[Mapping[str, object], ...],
        primary: Mapping[str, object],
        backup: Mapping[str, object],
    ) -> str | None:
        for item in events:
            if item.get("event") == "attempt_finished" and item.get("status") in {
                "completed",
                "failed",
                "incomplete",
            }:
                role = item.get("route_role")
                if role in {"primary", "backup"}:
                    return str(role)
        return None

    def _latest_probe_results(self) -> dict[str, Mapping[str, object]]:
        result: dict[str, Mapping[str, object]] = {}
        for item in reversed(self._journal.snapshot(limit=256)):
            role = item.get("route_role")
            if (
                item.get("event") == "models_probe_finished"
                and role in {"primary", "backup"}
                and role not in result
            ):
                result[str(role)] = item
        return result

    @staticmethod
    def _route_available(route: Mapping[str, object]) -> bool:
        return route.get("state") in {"closed", "unknown", "half_open"}

    @staticmethod
    def _route_snapshot(snapshot: BreakerSnapshot | None, role: str) -> dict[str, object]:
        if snapshot is None:
            return {
                "state": "unknown",
                "carrying": False,
                "last_status_category": "",
                "cooldown_seconds": None,
                "action_required": False,
            }
        cooldown = None
        if snapshot.open_until is not None:
            cooldown = max(0, int((snapshot.open_until - datetime.now(UTC)).total_seconds()))
        return {
            "state": snapshot.state.value,
            "carrying": False,
            "last_status_category": GatewayProcessHost._status_category(snapshot.last_http_status),
            "cooldown_seconds": cooldown,
            "action_required": snapshot.action_required,
        }

    @staticmethod
    def _public_core_event(item: Mapping[str, object]) -> dict[str, object]:
        return {
            "event_id": str(item.get("event_id") or ""),
            "timestamp": str(item.get("timestamp") or ""),
            "event": str(item.get("event") or "gateway_event"),
            "status": str(item.get("status") or "unknown"),
            "route_role": item.get("route_role") if item.get("route_role") in {"primary", "backup"} else "",
            "failover_used": bool(item.get("failover_used")),
            "possible_double_charge": bool(item.get("possible_double_charge")),
            "http_status_category": str(item.get("http_status_category") or ""),
            "config_revision": int(item.get("config_revision") or 0),
        }

    @staticmethod
    def _public_lifecycle_event(item: Mapping[str, object]) -> dict[str, object]:
        material = "|".join(
            str(item.get(key) or "")
            for key in ("timestamp", "event", "route_role", "config_revision")
        )
        return {
            "event_id": hashlib.sha256(material.encode("utf-8")).hexdigest()[:32],
            "timestamp": str(item.get("timestamp") or ""),
            "event": str(item.get("event") or "gateway_event"),
            "status": str(item.get("status") or "unknown"),
            "route_role": item.get("route_role") if item.get("route_role") in {"primary", "backup"} else "",
            "failover_used": False,
            "possible_double_charge": False,
            "http_status_category": str(item.get("http_status_category") or ""),
            "config_revision": int(item.get("config_revision") or 0),
        }

    @staticmethod
    def _status_category(status: int | None) -> str:
        if type(status) is not int or not 100 <= status <= 599:
            return ""
        return f"{status // 100}xx"

    def _validate_prepared_candidate(self, candidate: LifecycleConfig) -> None:
        current = self.config
        if candidate.instance_id != current.instance_id:
            raise GatewayControlOperationError(409, "guardian_config_instance_changed")
        if candidate.version != current.version:
            raise GatewayControlOperationError(409, "guardian_config_version_changed")
        if (
            candidate.host != current.host
            or candidate.data_port != current.data_port
            or candidate.control_port != current.control_port
        ):
            raise GatewayControlOperationError(409, "guardian_config_listen_changed")
        if candidate.limits != current.limits:
            raise GatewayControlOperationError(409, "guardian_config_limits_require_restart")
        if candidate.active_group.revision <= current.active_group.revision:
            raise GatewayControlOperationError(409, "guardian_config_revision_out_of_order")
        for route in (candidate.active_group.primary, candidate.active_group.backup):
            if _PROFILE_SECRET_REFERENCE.fullmatch(route.secret_ref) is None:
                raise GatewayControlOperationError(400, "guardian_config_secret_ref_invalid")
            if self._secret_resolver is None:
                raise GatewayControlOperationError(409, "guardian_config_gateway_not_running")
            try:
                self._secret_resolver.resolve(route.secret_ref)
            except Exception as exc:
                raise GatewayControlOperationError(
                    400,
                    "guardian_config_credential_unavailable",
                ) from exc

    def _recover_prepared_config(self) -> None:
        self._prepared_config = None
        try:
            envelope_payload = self._pending_config_path.read_bytes()
            if len(envelope_payload) > _MAX_CONFIG_BYTES + 4096:
                return
            envelope = json.loads(envelope_payload.decode("utf-8"))
            expected = {
                "schema_version",
                "base_revision",
                "base_file_sha256",
                "config_revision",
                "config_sha256",
                "expires_at_epoch",
                "config",
            }
            if not isinstance(envelope, dict) or set(envelope) != expected:
                return
            if envelope.get("schema_version") != 1:
                return
            base_revision = envelope.get("base_revision")
            config_revision = envelope.get("config_revision")
            base_file_sha256 = envelope.get("base_file_sha256")
            config_sha256 = envelope.get("config_sha256")
            expires_at_epoch = envelope.get("expires_at_epoch")
            document = envelope.get("config")
            if (
                type(base_revision) is not int
                or type(config_revision) is not int
                or not isinstance(base_file_sha256, str)
                or not _valid_sha256(base_file_sha256)
                or not isinstance(config_sha256, str)
                or not _valid_sha256(config_sha256)
                or isinstance(expires_at_epoch, bool)
                or not isinstance(expires_at_epoch, (int, float))
                or not isinstance(document, dict)
            ):
                return
            remaining = float(expires_at_epoch) - time.time()
            if not 0 < remaining <= self._prepared_config_ttl_seconds + 1:
                return
            if (
                base_revision != self.config.active_group.revision
                or base_file_sha256 != self._active_file_sha256
            ):
                return
            candidate_payload = _canonical_config_payload(document)
            if _bytes_sha256(candidate_payload) != config_sha256:
                return
            if self._session is None:
                return
            candidate = parse_active_config(document, self._session)
            if candidate.active_group.revision != config_revision:
                return
            self._validate_prepared_candidate(candidate)
            self._prepared_config = _PreparedConfig(
                config=candidate,
                payload=candidate_payload,
                config_sha256=config_sha256,
                base_revision=base_revision,
                base_file_sha256=base_file_sha256,
                expires_at_monotonic=time.monotonic() + remaining,
                expires_at_epoch=float(expires_at_epoch),
                pending_file_sha256=_bytes_sha256(envelope_payload),
            )
        except Exception:
            self._prepared_config = None

    def _expire_prepared_config(self) -> bool:
        prepared = self._prepared_config
        if prepared is None:
            return False
        if (
            time.monotonic() < prepared.expires_at_monotonic
            and time.time() < prepared.expires_at_epoch
            and prepared.base_revision == self.config.active_group.revision
        ):
            return False
        self._discard_prepared_config()
        return True

    def _discard_prepared_config(self) -> None:
        self._prepared_config = None
        _unlink_quietly(self._pending_config_path)

    def _reconcile_probe_scheduler_after_commit(self) -> bool:
        if self.config.active_group.probe_policy.enabled:
            if self._probe_scheduler is not None:
                return True
            if self._breaker is None or self._session is None or self._provider is None:
                return False
            resolver = self._build_secret_resolver()
            try:
                scheduler = ModelsProbeScheduler(
                    config_provider=self._provider.current_config,
                    breaker=self._breaker,
                    session=self._session,
                    resolve_secret=resolver.resolve,
                    on_result=self._record_probe_result,
                )
                scheduler.start()
                self._probe_scheduler = scheduler
                return True
            except Exception:
                return False
        scheduler = self._probe_scheduler
        if scheduler is None:
            return True
        self._probe_scheduler = None
        task = asyncio.create_task(scheduler.stop())
        task.add_done_callback(_consume_task_result)
        return True

    async def reload(self) -> Mapping[str, object]:
        if self._session is None or self._provider is None:
            raise GatewayHostError("gateway_not_running")
        if self._phase not in {"running", "draining"}:
            raise GatewayHostError("gateway_reload_invalid_phase")
        async with self._config_transaction_lock:
            self._expire_prepared_config()
            if self._prepared_config is not None:
                raise GatewayHostError("gateway_reload_prepare_in_progress")
            next_config = load_active_config(self.config_path, self._session)
            next_payload = _canonical_config_payload_from_path(self.config_path)
            next_config_sha256 = _bytes_sha256(next_payload)
            next_file_sha256 = _sha256(self.config_path)
            current = self.config
            if (
                next_config.instance_id != current.instance_id
                or next_config.host != current.host
                or next_config.data_port != current.data_port
                or next_config.control_port != current.control_port
                or next_config.version != current.version
            ):
                raise GatewayHostError("gateway_reload_requires_restart")
            if next_config.active_group.revision != current.active_group.revision:
                raise GatewayHostError("gateway_reload_requires_prepare_activate")
            if next_config_sha256 != self._active_config_sha256:
                raise GatewayHostError("gateway_reload_revision_conflict")
            self._active_file_sha256 = next_file_sha256
            return {
                "ok": True,
                "phase": self._phase,
                "config_revision": current.active_group.revision,
                "config_sha256": self._active_config_sha256,
                "idempotent": True,
            }

    async def stop(self, timeout_seconds: float | None = None) -> Mapping[str, object]:
        if self._phase not in {"running", "draining"}:
            raise GatewayHostError("gateway_stop_invalid_phase")
        result = await self.drain(timeout_seconds)
        if not result["ok"]:
            return result
        self._phase = "stopping"
        self._stop_event.set()
        return {"ok": True, "phase": self._phase, "active_requests": 0}

    async def close(self) -> None:
        if self._phase == "stopped":
            return
        ingress = self._ingress
        if ingress is not None:
            await ingress.begin_drain()
            if not await ingress.wait_drained(self.config.drain_timeout_seconds):
                await ingress.cancel_active()
                await ingress.wait_drained(self.config.drain_timeout_seconds)
        self._phase = "stopping"
        await self._cleanup_started_resources()
        self._descriptor_store.remove_if_owned(self._process_instance_id)
        self._lock.release()
        self._phase = "stopped"
        self._record("gateway_stopped", "stopped")

    def status(self) -> Mapping[str, object]:
        ingress = self._ingress
        config = self.config
        self._expire_prepared_config()
        prepared = self._prepared_config
        return {
            "ok": self._phase in {"running", "draining"},
            "phase": self._phase,
            "instance_id": config.instance_id,
            "process_instance_id": self._process_instance_id,
            "pid": os.getpid(),
            "process_started_at": self._process_started_at,
            "gateway_started_at": self._gateway_started_at,
            "version": config.version,
            "host": config.host,
            "data_port": config.data_port,
            "control_port": config.control_port,
            "config_revision": config.active_group.revision,
            "config_sha256": self._active_config_sha256,
            "active_group_id": config.active_group.group_id,
            "prepared_config": (
                None
                if prepared is None
                else {
                    "revision": prepared.config.active_group.revision,
                    "config_sha256": prepared.config_sha256,
                }
            ),
            "executable_path": str(Path(sys.executable).resolve()),
            "accepting": bool(ingress and ingress.accepting),
            "models_ready": bool(config.active_group.allowed_models)
            and config.active_group.primary.enabled
            and config.active_group.backup.enabled,
            "active_requests": ingress.active_requests if ingress else 0,
            "available_disk_bytes": self._disk.available_bytes() if self._disk else 0,
        }

    def _health_metadata(self) -> Mapping[str, object]:
        return {
            "phase": self._phase,
            "instance_id": self.config.instance_id,
            "process_instance_id": self._process_instance_id,
            "pid": os.getpid(),
            "process_started_at": self._process_started_at,
            "config_revision": self.config.active_group.revision,
        }

    def _write_descriptor(self) -> None:
        config = self.config
        descriptor = RuntimeDescriptor(
            schema_version=1,
            instance_id=config.instance_id,
            process_instance_id=self._process_instance_id,
            pid=os.getpid(),
            process_started_at=self._process_started_at,
            gateway_started_at=self._gateway_started_at,
            version=config.version,
            executable_path=str(Path(sys.executable).resolve()),
            host=config.host,
            data_port=config.data_port,
            control_port=config.control_port,
            control_endpoint=f"http://127.0.0.1:{config.control_port}",
            config_revision=config.active_group.revision,
            config_sha256=self._active_config_sha256,
            ingress_token_sha256=_text_sha256(self.ingress_token),
            control_token_sha256=_text_sha256(self.control_token),
        )
        self._descriptor_store.write(descriptor)

    def _ensure_version_pointer(self, version: str) -> None:
        linux_layout = getattr(self, "_linux_layout", None)
        if linux_layout is not None:
            pointer = linux_layout.current_pointer
            default_relative = f"versions/{version}"
            versions_root = linux_layout.versions.resolve()
        else:
            pointer = self.install_root / "gateway" / "current.json"
            default_relative = f"gateway/versions/{version}"
            versions_root = (self.install_root / "gateway" / "versions").resolve()
        if not pointer.is_file():
            raise GatewayHostError("gateway_current_pointer_missing")
        try:
            document = json.loads(pointer.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayHostError("gateway_current_pointer_invalid") from exc
        if not isinstance(document, dict) or document.get("schema_version") != 1:
            raise GatewayHostError("gateway_current_pointer_invalid")
        pointer_version = document.get("version", document.get("active_version"))
        if pointer_version != version:
            raise GatewayHostError("gateway_current_version_mismatch")
        relative_path = document.get("relative_path", default_relative)
        if not isinstance(relative_path, str):
            raise GatewayHostError("gateway_current_pointer_invalid")
        version_root = (self.install_root / relative_path).resolve()
        if versions_root not in version_root.parents or not version_root.is_dir():
            raise GatewayHostError("gateway_current_pointer_invalid")
        digest = document.get("manifest_sha256")
        if digest is not None:
            if not isinstance(digest, str):
                raise GatewayHostError("gateway_current_pointer_invalid")
            manifest = version_root / "manifest.json"
            if not manifest.is_file() or _sha256(manifest) != digest:
                raise GatewayHostError("gateway_current_manifest_mismatch")
        elif not (version_root / ".guardian-release.json").is_file():
            raise GatewayHostError("gateway_current_manifest_mismatch")

    def _build_secret_resolver(self):
        if self._linux_layout is not None:
            reject_link_chain(self._linux_layout.home, self._profiles_root)
            return PosixFileSecretResolver(self._profiles_root)
        return ProtectedFileSecretResolver(
            self._profiles_root,
            unprotect=self._unprotect,
        )

    def _build_token_store(self):
        if self._linux_layout is not None:
            reject_link_chain(self._linux_layout.home, self._tokens_root)
            return PosixTokenStore(self._tokens_root)
        return ProtectedTokenStore(
            self._tokens_root,
            protect=self._protect,
            unprotect=self._unprotect,
        )

    def _disk_watermark_root(self) -> Path:
        if self._linux_layout is not None:
            return self._linux_layout.state
        return self.install_root

    @staticmethod
    def _preflight_ports(config: LifecycleConfig) -> None:
        sockets: list[socket.socket] = []
        try:
            for port in (config.data_port, config.control_port):
                probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sockets.append(probe)
                exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
                if os.name == "nt" and exclusive is not None:
                    probe.setsockopt(socket.SOL_SOCKET, exclusive, 1)
                try:
                    probe.bind((config.host, port))
                except OSError as exc:
                    raise GatewayHostError(f"gateway_port_conflict:{port}") from exc
        finally:
            for probe in sockets:
                probe.close()

    async def _cleanup_started_resources(self) -> None:
        if self._probe_scheduler is not None:
            await self._probe_scheduler.stop()
            self._probe_scheduler = None
        for runner_name in ("_control_runner", "_data_runner"):
            runner = getattr(self, runner_name)
            if runner is not None:
                try:
                    await runner.cleanup()
                finally:
                    setattr(self, runner_name, None)
        if self._session is not None:
            await self._session.close()
            self._session = None

    def _required_ingress(self) -> GatewayIngress:
        if self._ingress is None:
            raise GatewayHostError("gateway_not_running")
        return self._ingress

    def _admission_error(self):
        if self._disk is None:
            raise GatewayHostError("gateway_disk_guard_missing")
        return self._disk.admission_error()

    def _record(self, event: str, status: str, *, active_requests: int = 0) -> None:
        config = self._config
        self._journal.append(
            {
                "event": event,
                "status": status,
                "timestamp": utc_now(),
                "version": config.version if config else "",
                "instance_id": config.instance_id if config else "",
                "process_instance_id": self._process_instance_id,
                "config_revision": config.active_group.revision if config else 0,
                "active_requests": active_requests,
            }
        )

    def _record_probe_result(self, result: ModelsProbeResult) -> None:
        config = self._config
        self._journal.append(
            {
                "event": "models_probe_finished",
                "status": "success" if result.ok else result.category,
                "timestamp": utc_now(),
                "version": config.version if config else "",
                "instance_id": config.instance_id if config else "",
                "process_instance_id": self._process_instance_id,
                "config_revision": config.active_group.revision if config else 0,
                "active_requests": self._ingress.active_requests if self._ingress else 0,
                "http_status_category": (
                    f"{result.http_status // 100}xx" if result.http_status else ""
                ),
                "route_role": result.role.value,
                "signal": "probe",
            }
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Codex Profile Guardian Gateway")
    parser.add_argument("--install-root", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--platform", choices=("windows", "linux"), default="windows")
    parser.add_argument("--home")
    return parser


async def _run_from_cli(args: argparse.Namespace) -> int:
    host = GatewayProcessHost(
        install_root=args.install_root,
        config_path=args.config,
        platform=args.platform,
        home=args.home,
    )
    loop = asyncio.get_running_loop()
    for name in ("SIGINT", "SIGTERM"):
        value = getattr(signal, name, None)
        if value is not None:
            try:
                loop.add_signal_handler(value, host._stop_event.set)
            except (NotImplementedError, RuntimeError):
                pass
    try:
        await host.run()
        return 0
    except ActiveConfigError:
        return 78
    except GatewayHostError:
        return 3
    finally:
        if host.phase not in {"created", "stopped"}:
            await host.close()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(_run_from_cli(args))


def _canonical_config_payload(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            dict(document),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _canonical_config_payload_from_path(path: Path) -> bytes:
    payload = path.read_bytes()
    if len(payload) > _MAX_CONFIG_BYTES:
        raise ActiveConfigError("gateway_config_too_large")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActiveConfigError("gateway_config_json_invalid") from exc
    if not isinstance(document, dict):
        raise ActiveConfigError("gateway_config_json_invalid")
    return _canonical_config_payload(document)


def _prepared_envelope_payload(
    document: Mapping[str, object],
    *,
    base_revision: int,
    base_file_sha256: str,
    config_revision: int,
    config_sha256: str,
    expires_at_epoch: float,
) -> bytes:
    envelope = {
        "schema_version": 1,
        "base_revision": base_revision,
        "base_file_sha256": base_file_sha256,
        "config_revision": config_revision,
        "config_sha256": config_sha256,
        "expires_at_epoch": expires_at_epoch,
        "config": dict(document),
    }
    return (
        json.dumps(
            envelope,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    temporary = _write_sibling_temporary(path, payload)
    try:
        os.replace(temporary, path)
        temporary = None
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    finally:
        _unlink_quietly(temporary)


def _write_sibling_temporary(path: Path, payload: bytes) -> Path:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(parent, stat.S_IRWXU)
    except OSError:
        pass
    temporary = parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        _unlink_quietly(temporary)
        raise


def _unlink_quietly(path: Path | None) -> bool:
    if path is None:
        return True
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _bytes_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _consume_task_result(task: asyncio.Task[object]) -> None:
    try:
        task.result()
    except (asyncio.CancelledError, Exception):
        pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _process_start_time() -> str:
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            kernel32.GetProcessTimes.argtypes = (
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.FILETIME),
                ctypes.POINTER(wintypes.FILETIME),
                ctypes.POINTER(wintypes.FILETIME),
                ctypes.POINTER(wintypes.FILETIME),
            )
            kernel32.GetProcessTimes.restype = wintypes.BOOL
            created = wintypes.FILETIME()
            exited = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not kernel32.GetProcessTimes(
                kernel32.GetCurrentProcess(),
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                raise OSError("GetProcessTimes failed")
            ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
            unix_seconds = ticks / 10_000_000 - 11_644_473_600
            return datetime.fromtimestamp(unix_seconds, UTC).isoformat()
        except Exception:
            pass
    return datetime.fromtimestamp(time.time(), UTC).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
