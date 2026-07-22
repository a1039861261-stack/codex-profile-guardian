from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
from threading import RLock
from typing import Any
import uuid

from gateway.runtime_files import (
    RuntimeDescriptor,
    RuntimeDescriptorStore,
    RuntimeFileError,
    read_process_identity,
)
from gateway.tokens import ProtectedTokenStore, TokenStoreError

from .failover import (
    FailoverActivationUncertain,
    FailoverConflictError,
    FailoverPublishError,
    GatewayActivationReceipt,
    PreparedGatewayConfig,
)


MAX_CONTROL_BYTES = 1024 * 1024
_PROFILE_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")


@dataclass(slots=True)
class _PreparedRecord:
    revision: int
    group_id: str
    config_sha256: str
    candidate: dict[str, object]
    previous_revision: int
    previous_group_id: str
    previous_document: dict[str, object]
    previous_config_sha256: str
    process_instance_id: str
    created_credentials: dict[Path, str]


CredentialSource = Callable[[str], bytes]
ProcessIdentityReader = Callable[[int], tuple[str, str] | None]


class ProductionGatewayController:
    source = "production"

    def __init__(
        self,
        *,
        install_root: str | Path,
        expected_executable: str | Path,
        expected_version: str,
        credential_source: CredentialSource,
        unprotect: Callable[[bytes], bytes],
        process_identity_reader: ProcessIdentityReader | None = None,
        timeout_seconds: float = 2.0,
    ) -> None:
        self.install_root = Path(install_root).resolve()
        self.expected_executable = Path(expected_executable).resolve()
        self.expected_version = str(expected_version)
        if not self.expected_version or not self.expected_executable.is_absolute():
            raise ValueError("gateway_controller_identity_invalid")
        if not 0.1 <= timeout_seconds <= 10:
            raise ValueError("gateway_controller_timeout_invalid")
        self.credential_source = credential_source
        self._unprotect = unprotect
        self._process_identity_reader = process_identity_reader or read_process_identity
        self.timeout_seconds = float(timeout_seconds)
        self.config_path = self.install_root / "gateway" / "config" / "active.json"
        self.runtime_store = RuntimeDescriptorStore(
            self.install_root / "gateway" / "runtime" / "runtime.json"
        )
        self.token_store = ProtectedTokenStore(
            self.install_root / "gateway" / "secrets" / "tokens",
            protect=lambda _payload: b"",
            unprotect=unprotect,
        )
        self.profile_secret_root = self.install_root / "gateway" / "secrets" / "profiles"
        self._prepared: dict[str, _PreparedRecord] = {}
        self._lock = RLock()

    def prepare(self, candidate: Mapping[str, object]) -> PreparedGatewayConfig:
        with self._lock:
            descriptor, status, control_token = self._verified_runtime()
            revision = candidate.get("revision")
            group_id = candidate.get("group_id")
            if type(revision) is not int or revision <= descriptor.config_revision:
                raise FailoverConflictError("gateway_production_revision_out_of_order")
            if not isinstance(group_id, str) or not group_id:
                raise FailoverPublishError("gateway_production_group_invalid")
            previous_document = self._read_active_document()
            lifecycle = self._lifecycle_candidate(candidate, previous_document)
            created = self._deploy_candidate_credentials(candidate)
            try:
                response = self._request(
                    descriptor,
                    control_token,
                    "POST",
                    "/control/v1/config/prepare",
                    lifecycle,
                )
                config_sha256 = self._required_sha(response, "config_sha256")
                if response.get("config_revision") != revision or response.get("state") not in {
                    "prepared",
                    "active",
                }:
                    raise FailoverPublishError("gateway_production_prepare_invalid")
            except Exception:
                self._cleanup_created(created)
                raise
            handle = uuid.uuid4().hex
            self._prepared[handle] = _PreparedRecord(
                revision=revision,
                group_id=group_id,
                config_sha256=config_sha256,
                candidate=dict(candidate),
                previous_revision=descriptor.config_revision,
                previous_group_id=str(status.get("active_group_id") or ""),
                previous_document=previous_document,
                previous_config_sha256=self._canonical_sha(previous_document),
                process_instance_id=descriptor.process_instance_id,
                created_credentials=created,
            )
            return PreparedGatewayConfig(revision, group_id, handle)

    def activate(self, prepared: PreparedGatewayConfig) -> GatewayActivationReceipt:
        with self._lock:
            record = self._prepared.get(prepared.handle)
            if record is None or record.revision != prepared.revision or record.group_id != prepared.group_id:
                raise FailoverPublishError("gateway_production_prepare_missing")
            descriptor, _status, control_token = self._verified_runtime(
                expected_revision=record.previous_revision
            )
            try:
                response = self._request(
                    descriptor,
                    control_token,
                    "POST",
                    "/control/v1/config/activate",
                    {
                        "revision": record.revision,
                        "config_sha256": record.config_sha256,
                    },
                )
            except FailoverPublishError as exc:
                verification = self._status_if_owned(control_token)
                if (
                    verification is not None
                    and verification.get("config_revision") == record.revision
                    and verification.get("active_group_id") == record.group_id
                ):
                    receipt = self._receipt(prepared, record)
                    self._prepared.pop(prepared.handle, None)
                    raise FailoverActivationUncertain(
                        "gateway_production_activate_result_uncertain",
                        receipt,
                    ) from exc
                raise
            if (
                response.get("config_revision") != record.revision
                or response.get("config_sha256") != record.config_sha256
                or response.get("state") != "active"
            ):
                raise FailoverPublishError("gateway_production_activate_invalid")
            self._prepared.pop(prepared.handle, None)
            return self._receipt(prepared, record)

    def rollback(self, receipt: GatewayActivationReceipt) -> GatewayActivationReceipt:
        with self._lock:
            if (
                not receipt.process_instance_id
                or not receipt.activated_config_sha256
                or not receipt.previous_config_sha256
                or not isinstance(receipt.previous_candidate, Mapping)
                or self._canonical_sha(receipt.previous_candidate)
                != receipt.previous_config_sha256
            ):
                raise FailoverPublishError("gateway_production_compensation_receipt_invalid")
            descriptor, status, token = self._verified_runtime(
                expected_revision=receipt.revision
            )
            if (
                descriptor.process_instance_id != receipt.process_instance_id
                or status.get("active_group_id") != receipt.group_id
                or status.get("config_sha256") != receipt.activated_config_sha256
            ):
                raise FailoverConflictError("gateway_production_compensation_conflict")
            current = self._read_active_document()
            if self._canonical_sha(current) != receipt.activated_config_sha256:
                raise FailoverConflictError("gateway_production_compensation_conflict")
            previous = json.loads(json.dumps(receipt.previous_candidate))
            active_group = previous.get("active_group")
            if not isinstance(active_group, dict):
                raise FailoverPublishError("gateway_production_compensation_receipt_invalid")
            compensation_revision = receipt.revision + 1
            active_group["revision"] = compensation_revision
            prepared = self._request(
                descriptor,
                token,
                "POST",
                "/control/v1/config/prepare",
                previous,
            )
            compensation_sha256 = self._required_sha(prepared, "config_sha256")
            activated = self._request(
                descriptor,
                token,
                "POST",
                "/control/v1/config/activate",
                {
                    "revision": compensation_revision,
                    "config_sha256": compensation_sha256,
                },
            )
            if (
                activated.get("state") != "active"
                or activated.get("config_revision") != compensation_revision
                or activated.get("config_sha256") != compensation_sha256
            ):
                raise FailoverPublishError("gateway_production_compensation_uncertain")
            verified, verified_status, _verified_token = self._verified_runtime(
                expected_revision=compensation_revision
            )
            if (
                verified.process_instance_id != receipt.process_instance_id
                or verified_status.get("active_group_id") != receipt.previous_group_id
                or verified_status.get("config_sha256") != compensation_sha256
            ):
                raise FailoverPublishError("gateway_production_compensation_uncertain")
            return GatewayActivationReceipt(
                previous_revision=receipt.revision,
                previous_group_id=receipt.group_id,
                revision=compensation_revision,
                group_id=receipt.previous_group_id or "",
                handle=uuid.uuid4().hex,
                previous_candidate=current,
                activated_config_sha256=compensation_sha256,
                previous_config_sha256=receipt.activated_config_sha256,
                process_instance_id=receipt.process_instance_id,
            )

    def abort(self, prepared: PreparedGatewayConfig) -> None:
        with self._lock:
            record = self._prepared.get(prepared.handle)
            if record is None:
                return
            descriptor, _status, control_token = self._verified_runtime(
                expected_revision=record.previous_revision
            )
            self._request(
                descriptor,
                control_token,
                "POST",
                "/control/v1/config/abort",
                {
                    "revision": record.revision,
                    "config_sha256": record.config_sha256,
                },
            )
            self._prepared.pop(prepared.handle, None)
            self._cleanup_created(record.created_credentials)

    def snapshot(self) -> Mapping[str, object]:
        with self._lock:
            try:
                descriptor, _status, token = self._verified_runtime()
                projected = self._request(
                    descriptor,
                    token,
                    "GET",
                    "/control/v1/failover/snapshot",
                    None,
                )
                return self._public_snapshot(projected, descriptor)
            except FailoverPublishError:
                return {
                    "source": "production",
                    "view_state": "error",
                    "tone": "danger",
                    "headline": "后台网关状态不可用",
                    "supporting": "已停止发布配置，请检查后台服务。",
                    "required_action": "repair_gateway",
                    "carrier": None,
                    "routes": {},
                    "alert": {
                        "code": "guardian_gateway_unavailable",
                        "persistent": True,
                        "tone": "danger",
                        "title": "后台网关不可用",
                        "next_action": "检查后台服务",
                    },
                    "online": False,
                    "stale": True,
                    "phase": "unavailable",
                    "version": self.expected_version,
                    "config_revision": 0,
                    "active_group_id": None,
                }

    def events(self) -> tuple[Mapping[str, object], ...]:
        with self._lock:
            descriptor, _status, token = self._verified_runtime()
            response = self._request(
                descriptor,
                token,
                "GET",
                "/control/v1/failover/events",
                None,
            )
            items = response.get("items")
            if not isinstance(items, list) or len(items) > 256:
                raise FailoverPublishError("gateway_production_events_invalid")
            return tuple(self._public_event(item) for item in items)

    def retest(self, group_id: str, route_role: str) -> Mapping[str, object]:
        if not isinstance(group_id, str) or not group_id or route_role not in {"primary", "backup"}:
            raise FailoverPublishError("gateway_production_retest_invalid")
        with self._lock:
            descriptor, status, token = self._verified_runtime()
            if status.get("active_group_id") != group_id:
                raise FailoverConflictError("failover_group_not_active")
            response = self._request(
                descriptor,
                token,
                "POST",
                "/control/v1/failover/retest",
                {"group_id": group_id, "route_role": route_role},
            )
            return {
                "source": "production",
                "group_id": group_id,
                "route_role": route_role,
                "ok": bool(response.get("ok")),
                "status": self._safe_text(response.get("status"), maximum=64),
                "http_status_category": self._status_category(
                    response.get("http_status_category")
                ),
                "config_revision": self._revision(response.get("config_revision")),
            }

    def referenced_profile_ids(self) -> frozenset[str]:
        with self._lock:
            result: set[str] = set()
            try:
                document = self._read_active_document()
                group = document.get("active_group")
                if isinstance(group, Mapping):
                    for role in ("primary", "backup"):
                        route = group.get(role)
                        profile_id = route.get("profile_id") if isinstance(route, Mapping) else None
                        if isinstance(profile_id, str):
                            result.add(profile_id)
            except FailoverPublishError:
                pass
            for record in self._prepared.values():
                for role in ("primary", "backup"):
                    route = record.candidate.get(role)
                    if isinstance(route, Mapping) and isinstance(route.get("profile_id"), str):
                        result.add(str(route["profile_id"]))
            return frozenset(result)

    def provider_status(self) -> Mapping[str, object]:
        with self._lock:
            descriptor, status, _control_token = self._verified_runtime()
            models_ready = status.get("models_ready")
            if type(models_ready) is not bool:
                raise FailoverPublishError("gateway_production_models_state_invalid")
            return {
                "ok": status.get("ok") is True,
                "phase": status.get("phase"),
                "host": status.get("host"),
                "data_port": descriptor.data_port,
                "config_revision": descriptor.config_revision,
                "instance_id": descriptor.instance_id,
                "models_ready": models_ready,
            }

    def _verified_runtime(
        self,
        *,
        expected_revision: int | None = None,
    ) -> tuple[RuntimeDescriptor, dict[str, object], str]:
        try:
            descriptor = self.runtime_store.read()
            control_token = self.token_store.read_existing("control")
        except (FileNotFoundError, RuntimeFileError, TokenStoreError) as exc:
            raise FailoverPublishError("gateway_production_runtime_unavailable") from exc
        if Path(descriptor.executable_path).resolve() != self.expected_executable:
            raise FailoverPublishError("gateway_production_executable_mismatch")
        if descriptor.version != self.expected_version:
            raise FailoverPublishError("gateway_production_version_mismatch")
        if expected_revision is not None and descriptor.config_revision != expected_revision:
            raise FailoverConflictError("gateway_production_revision_changed")
        if hashlib.sha256(control_token.encode("ascii")).hexdigest() != descriptor.control_token_sha256:
            raise FailoverPublishError("gateway_production_control_token_mismatch")
        identity = self._process_identity_reader(descriptor.pid)
        if identity is None:
            raise FailoverPublishError("gateway_production_process_missing")
        actual_executable, actual_started_at = identity
        if Path(actual_executable).resolve() != self.expected_executable:
            raise FailoverPublishError("gateway_production_process_mismatch")
        if not self._timestamps_match(actual_started_at, descriptor.process_started_at):
            raise FailoverPublishError("gateway_production_process_start_mismatch")
        status = self._request(
            descriptor,
            control_token,
            "GET",
            "/control/v1/status",
            None,
        )
        expected = {
            "instance_id": descriptor.instance_id,
            "process_instance_id": descriptor.process_instance_id,
            "pid": descriptor.pid,
            "process_started_at": descriptor.process_started_at,
            "version": descriptor.version,
            "executable_path": descriptor.executable_path,
            "control_port": descriptor.control_port,
            "config_revision": descriptor.config_revision,
        }
        if any(status.get(key) != value for key, value in expected.items()):
            raise FailoverPublishError("gateway_production_control_identity_mismatch")
        return descriptor, status, control_token

    def _status_if_owned(self, control_token: str) -> dict[str, object] | None:
        try:
            descriptor = self.runtime_store.read()
            if hashlib.sha256(control_token.encode("ascii")).hexdigest() != descriptor.control_token_sha256:
                return None
            return self._request(
                descriptor,
                control_token,
                "GET",
                "/control/v1/status",
                None,
            )
        except Exception:
            return None

    def _lifecycle_candidate(
        self,
        candidate: Mapping[str, object],
        document: Mapping[str, object],
    ) -> dict[str, object]:
        active_group = document.get("active_group")
        if not isinstance(active_group, dict):
            raise FailoverPublishError("gateway_production_active_config_invalid")
        revision = candidate["revision"]
        adapter_name = str(candidate["adapter_name"])
        next_group = {
            "revision": revision,
            "group_id": candidate["group_id"],
            "primary": self._route_document(candidate, "primary", adapter_name),
            "backup": self._route_document(candidate, "backup", adapter_name),
            "allowed_models": list(candidate["allowed_models"]),
            "breaker_policy": dict(candidate["breaker_policy"]),
            "probe_policy": dict(candidate["probe_policy"]),
            "state_compatibility": {},
        }
        result = dict(document)
        result["active_group"] = next_group
        return result

    @staticmethod
    def _route_document(
        candidate: Mapping[str, object],
        role: str,
        adapter_name: str,
    ) -> dict[str, object]:
        route = candidate.get(role)
        if not isinstance(route, Mapping):
            raise FailoverPublishError("gateway_production_candidate_invalid")
        profile_id = route.get("profile_id")
        revision = route.get("credential_revision")
        if (
            not isinstance(profile_id, str)
            or _PROFILE_ID.fullmatch(profile_id) is None
            or type(revision) is not int
            or revision <= 0
        ):
            raise FailoverPublishError("gateway_production_candidate_invalid")
        return {
            "profile_id": profile_id,
            "base_url": route["base_url"],
            "adapter_name": adapter_name,
            "secret_ref": f"profile:{profile_id}:r{revision}",
            "secret_suffix": "",
            "enabled": True,
            "protocol_compatibility": dict(
                route.get("protocol_compatibility") or {}
            ),
        }

    def _deploy_candidate_credentials(
        self,
        candidate: Mapping[str, object],
    ) -> dict[Path, str]:
        created: dict[Path, str] = {}
        try:
            self.profile_secret_root.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.profile_secret_root, stat.S_IRWXU)
            except OSError:
                pass
            for role in ("primary", "backup"):
                route = candidate.get(role)
                if not isinstance(route, Mapping):
                    raise FailoverPublishError("gateway_production_candidate_invalid")
                profile_id = str(route.get("profile_id") or "")
                revision = route.get("credential_revision")
                if _PROFILE_ID.fullmatch(profile_id) is None or type(revision) is not int or revision <= 0:
                    raise FailoverPublishError("gateway_production_candidate_invalid")
                protected = self.credential_source(profile_id)
                if not isinstance(protected, bytes) or not protected or len(protected) > MAX_CONTROL_BYTES:
                    raise FailoverPublishError("gateway_production_credential_invalid")
                try:
                    raw = self._unprotect(protected)
                except Exception as exc:
                    raise FailoverPublishError("gateway_production_credential_unavailable") from exc
                if not raw or raw in protected:
                    raise FailoverPublishError("gateway_production_credential_invalid")
                target = self.profile_secret_root / f"{profile_id}.r{revision}.dpapi"
                digest = hashlib.sha256(protected).hexdigest()
                if target.exists():
                    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                        raise FailoverConflictError("gateway_production_credential_revision_conflict")
                    continue
                self._atomic_write(target, protected)
                created[target] = digest
            return created
        except Exception:
            self._cleanup_created(created)
            raise

    def _cleanup_created(self, created: Mapping[Path, str]) -> None:
        for path, digest in created.items():
            try:
                if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest:
                    path.unlink()
            except OSError:
                raise FailoverPublishError("gateway_production_credential_cleanup_failed")

    def _read_active_document(self) -> dict[str, object]:
        try:
            payload = self.config_path.read_bytes()
            if len(payload) > MAX_CONTROL_BYTES:
                raise ValueError
            document = json.loads(payload.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise FailoverPublishError("gateway_production_active_config_invalid") from exc
        if not isinstance(document, dict):
            raise FailoverPublishError("gateway_production_active_config_invalid")
        return document

    def _request(
        self,
        descriptor: RuntimeDescriptor,
        control_token: str,
        method: str,
        path: str,
        document: Mapping[str, object] | None,
    ) -> dict[str, object]:
        if descriptor.host != "127.0.0.1" or not path.startswith("/control/v1/"):
            raise FailoverPublishError("gateway_production_control_target_invalid")
        payload = None
        headers = {
            "Authorization": f"Bearer {control_token}",
            "Host": f"127.0.0.1:{descriptor.control_port}",
            "Accept": "application/json",
        }
        if document is not None:
            payload = json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(payload) > MAX_CONTROL_BYTES:
                raise FailoverPublishError("gateway_production_control_payload_too_large")
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            descriptor.control_port,
            timeout=self.timeout_seconds,
        )
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            body = response.read(MAX_CONTROL_BYTES + 1)
        except OSError as exc:
            raise FailoverPublishError("gateway_production_control_unavailable") from exc
        finally:
            connection.close()
        if len(body) > MAX_CONTROL_BYTES:
            raise FailoverPublishError("gateway_production_control_response_too_large")
        try:
            result = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FailoverPublishError("gateway_production_control_response_invalid") from exc
        if not isinstance(result, dict):
            raise FailoverPublishError("gateway_production_control_response_invalid")
        if not 200 <= response.status < 300:
            error = result.get("error")
            code = error.get("code") if isinstance(error, Mapping) else None
            allowed = code if isinstance(code, str) and code.startswith("guardian_") else "gateway_control_rejected"
            raise FailoverPublishError(allowed)
        return result

    def _public_snapshot(
        self,
        value: Mapping[str, object],
        descriptor: RuntimeDescriptor,
    ) -> dict[str, object]:
        source = value.get("source")
        phase = value.get("phase")
        revision = self._revision(value.get("config_revision"))
        group_id = value.get("active_group_id")
        carrier = value.get("carrier")
        action = value.get("required_action")
        routes = value.get("routes")
        if (
            source != "production"
            or phase not in {"running", "draining"}
            or revision != descriptor.config_revision
            or not isinstance(group_id, str)
            or carrier not in {"primary", "backup", None}
            or action not in {"none", "check_primary", "repair_route"}
            or not isinstance(routes, Mapping)
        ):
            raise FailoverPublishError("gateway_production_snapshot_invalid")
        public_routes: dict[str, object] = {}
        for role in ("primary", "backup"):
            route = routes.get(role)
            if not isinstance(route, Mapping):
                raise FailoverPublishError("gateway_production_snapshot_invalid")
            state = route.get("state")
            cooldown = route.get("cooldown_seconds")
            if state not in {
                "unknown",
                "closed",
                "open_temporary",
                "half_open",
                "open_action_required",
                "disabled",
            } or (cooldown is not None and (type(cooldown) is not int or cooldown < 0)):
                raise FailoverPublishError("gateway_production_snapshot_invalid")
            public_routes[role] = {
                "state": state,
                "carrying": bool(route.get("carrying")),
                "last_status_category": self._status_category(
                    route.get("last_status_category")
                ),
                "cooldown_seconds": cooldown,
                "action_required": bool(route.get("action_required")),
            }
        return {
            "source": "production",
            "view_state": "ready",
            "required_action": action,
            "carrier": carrier,
            "routes": public_routes,
            "online": True,
            "stale": False,
            "phase": phase,
            "version": self.expected_version,
            "config_revision": revision,
            "active_group_id": group_id,
        }

    def _public_event(self, value: object) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise FailoverPublishError("gateway_production_events_invalid")
        event_id = self._safe_identifier(value.get("event_id"), maximum=128)
        timestamp = self._safe_text(value.get("timestamp"), maximum=64)
        event = self._safe_identifier(value.get("event"), maximum=64)
        status = self._safe_identifier(value.get("status"), maximum=64)
        route_role = value.get("route_role")
        if route_role not in {"primary", "backup", ""}:
            raise FailoverPublishError("gateway_production_events_invalid")
        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "event": event,
            "status": status,
            "route_role": route_role,
            "failover_used": bool(value.get("failover_used")),
            "possible_double_charge": bool(value.get("possible_double_charge")),
            "http_status_category": self._status_category(
                value.get("http_status_category")
            ),
            "config_revision": self._revision(value.get("config_revision")),
            "source": "production",
        }

    @staticmethod
    def _safe_text(value: object, *, maximum: int) -> str:
        if (
            not isinstance(value, str)
            or len(value) > maximum
            or any(ord(character) < 0x20 for character in value)
            or "://" in value.lower()
            or "bearer " in value.lower()
        ):
            raise FailoverPublishError("gateway_production_projection_invalid")
        return value

    @classmethod
    def _safe_identifier(cls, value: object, *, maximum: int) -> str:
        result = cls._safe_text(value, maximum=maximum)
        if not result or re.fullmatch(r"[A-Za-z0-9_-]+", result) is None:
            raise FailoverPublishError("gateway_production_projection_invalid")
        return result

    @staticmethod
    def _revision(value: object) -> int:
        if type(value) is not int or value < 0:
            raise FailoverPublishError("gateway_production_projection_invalid")
        return value

    @staticmethod
    def _status_category(value: object) -> str:
        if value not in {"", "1xx", "2xx", "3xx", "4xx", "5xx"}:
            raise FailoverPublishError("gateway_production_projection_invalid")
        return str(value)

    @staticmethod
    def _required_sha(document: Mapping[str, object], key: str) -> str:
        value = document.get(key)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise FailoverPublishError("gateway_production_control_response_invalid")
        return value

    @staticmethod
    def _receipt(
        prepared: PreparedGatewayConfig,
        record: _PreparedRecord,
    ) -> GatewayActivationReceipt:
        return GatewayActivationReceipt(
            previous_revision=record.previous_revision,
            previous_group_id=record.previous_group_id or None,
            revision=record.revision,
            group_id=record.group_id,
            handle=prepared.handle,
            previous_candidate=record.previous_document,
            activated_config_sha256=record.config_sha256,
            previous_config_sha256=record.previous_config_sha256,
            process_instance_id=record.process_instance_id,
        )

    @staticmethod
    def _canonical_sha(document: Mapping[str, object]) -> str:
        payload = (
            json.dumps(
                dict(document),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                stat.S_IRUSR | stat.S_IWUSR,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            raise FailoverPublishError("gateway_production_credential_write_failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except OSError:
                pass

    @staticmethod
    def _timestamps_match(first: str, second: str) -> bool:
        try:
            left = datetime.fromisoformat(first).astimezone(UTC)
            right = datetime.fromisoformat(second).astimezone(UTC)
        except (TypeError, ValueError):
            return False
        return abs((left - right).total_seconds()) <= 1.0


__all__ = ["ProductionGatewayController"]
