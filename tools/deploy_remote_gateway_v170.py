from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import uuid


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.guardian import GuardianService
from backend.remote_gateway import NasCompatibilityEvaluator, NasEnvironmentInspector, NasInspectionRequest
from backend.remote_gateway_deployment import NasDeploymentEnvelope, NasSshDeploymentTransport, deployment_plan_from_decision
from backend.remote_sync import discover_remote_hosts
from gateway.platforms.linux import LinuxGatewayLayout
from gateway.platforms.linux_deployment import LinuxDeploymentBundle, LinuxVersionedReleaseStore
from tools.remote_gateway_preflight import protected_snapshot


VERSION = "v1.7.0"


def _profile_models(profile: dict[str, object]) -> tuple[str, ...]:
    raw = profile.get("models")
    if isinstance(raw, list) and all(isinstance(item, str) and item for item in raw):
        return tuple(dict.fromkeys(raw))
    model = profile.get("model")
    if isinstance(model, str) and model:
        return (model,)
    raise RuntimeError("remote_gateway_profile_models_missing")


def _route(profile: dict[str, object], *, enabled: bool) -> dict[str, object]:
    profile_id = str(profile["id"])
    revision = profile.get("credential_revision", 1)
    if type(revision) is not int or revision < 1:
        raise RuntimeError("remote_gateway_profile_revision_invalid")
    compatibility = profile.get("protocol_compatibility") or {}
    if not isinstance(compatibility, dict):
        raise RuntimeError("remote_gateway_profile_compatibility_invalid")
    return {
        "profile_id": profile_id,
        "base_url": profile["base_url"],
        "adapter_name": "openai-responses-v1",
        "secret_ref": f"profile:{profile_id}:r{revision}",
        "secret_suffix": "",
        "enabled": enabled,
        "protocol_compatibility": compatibility,
    }


def _config(current: dict[str, object], secondary: dict[str, object]) -> dict[str, object]:
    allowed_model = _profile_models(current)[0]
    return {
        "schema_version": 1,
        "instance_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "guardian-remote-gateway-v1")),
        "gateway_version": VERSION,
        "listen": {"host": "127.0.0.1", "data_port": 18766, "control_port": 18767},
        "limits": {
            "max_request_bytes": 16 * 1024 * 1024,
            "max_response_bytes": 64 * 1024 * 1024,
            "read_chunk_bytes": 64 * 1024,
            "max_concurrent_requests": 4,
            "connect_timeout_seconds": 20,
            "first_byte_timeout_seconds": 180,
            "idle_timeout_seconds": 180,
            "total_timeout_seconds": 1800,
        },
        "lifecycle": {"minimum_free_bytes": 256 * 1024 * 1024, "drain_timeout_seconds": 300},
        "active_group": {
            "revision": 1,
            "group_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "guardian-remote-current-api-v1")),
            "primary": _route(current, enabled=True),
            "backup": _route(secondary, enabled=False),
            "allowed_models": [allowed_model],
            "breaker_policy": {
                "failure_threshold": 2,
                "protocol_failure_threshold": 1,
                "error_rate_threshold": None,
                "minimum_samples": 4,
                "window_size": 16,
                "recovery_success_threshold": 1,
                "base_cooldown_seconds": 30,
                "max_cooldown_seconds": 300,
                "jitter_ratio": 0.1,
            },
            "probe_policy": {
                "enabled": False,
                "mode": "models",
                "interval_seconds": 300,
                "timeout_seconds": 10,
                "allow_billable": False,
                "allow_action_required_auto_retest": False,
            },
            "state_compatibility": {},
        },
    }


def main() -> int:
    service = GuardianService(enable_failover_fixture=False)
    state = service._load_state()
    profiles = [dict(item) for item in state.get("profiles", []) if item.get("type") == "api"]
    if len(profiles) != 2:
        raise RuntimeError("remote_gateway_api_profile_count_invalid")
    current_id = state.get("current_profile")
    current = next((item for item in profiles if item.get("id") == current_id), None)
    if current is None:
        raise RuntimeError("remote_gateway_current_api_missing")
    secondary = next(item for item in profiles if item is not current)
    hosts = discover_remote_hosts(service.codex_home / ".codex-global-state.json")
    if len(hosts) != 1:
        raise RuntimeError("remote_gateway_host_count_invalid")
    host = hosts[0]
    inspection = NasEnvironmentInspector().inspect(host, NasInspectionRequest(18766, 18767))
    environment = inspection.get("environment") if inspection.get("ok") else None
    decision = NasCompatibilityEvaluator().evaluate(environment) if isinstance(environment, dict) else None
    if decision is None or not decision.compatible or decision.supervisor != "cron_user":
        raise RuntimeError("remote_gateway_preflight_failed")
    before = protected_snapshot(host)
    if before["active_turn_count"] != 0 or before["sqlite_integrity"] != "ok":
        raise RuntimeError("remote_gateway_protected_state_gate_failed")
    source = PROJECT_ROOT / "output" / "linux-gateway-v1.7.0-x86_64"
    if not source.is_dir():
        raise RuntimeError("remote_gateway_release_missing")
    with tempfile.TemporaryDirectory() as temporary_name:
        layout = LinuxGatewayLayout(Path(temporary_name) / "home")
        release = LinuxVersionedReleaseStore(layout).install(
            VERSION,
            source,
            architecture="x86_64",
            package_mode="locked_venv",
        )
        secrets: dict[str, str] = {}
        for profile in (current, secondary):
            profile_id = str(profile["id"])
            revision = profile.get("credential_revision", 1)
            raw = service.decrypt_secret(profile_id)
            try:
                secrets[f"{profile_id}.r{revision}"] = raw.decode("utf-8")
            finally:
                if isinstance(raw, bytearray):
                    raw[:] = b"\0" * len(raw)
        bundle = LinuxDeploymentBundle(config=_config(current, secondary), secrets=secrets)
        plan = deployment_plan_from_decision(decision, architecture="x86_64")
        envelope = NasDeploymentEnvelope.from_release(release, bundle, plan)
        receipt = NasSshDeploymentTransport(timeout=300).deploy(host, envelope)
        secrets.clear()
    if receipt.get("ok") is not True or receipt.get("active_version") != VERSION:
        print(json.dumps({
            "ok": False,
            "error_code": receipt.get("error_code"),
            "recovered": receipt.get("recovered"),
            "model_requests": 0,
        }, separators=(",", ":")))
        return 2
    after = protected_snapshot(host)
    stable = (
        before["protected_digest"] == after["protected_digest"]
        and before["protected_file_count"] == after["protected_file_count"]
        and after["sqlite_integrity"] == "ok"
        and after["active_turn_count"] == 0
    )
    if not stable:
        raise RuntimeError("remote_gateway_protected_state_changed")
    print(json.dumps({
        "ok": True,
        "version": receipt["active_version"],
        "manifest_sha256": receipt["manifest_sha256"],
        "config_sha256": receipt["config_sha256"],
        "supervisor": "cron_user",
        "backup_enabled": False,
        "protected_state_stable": True,
        "model_requests": 0,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
