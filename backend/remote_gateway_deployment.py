from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable, Mapping, Sequence

from gateway.platforms.linux_deployment import (
    LinuxDeploymentBundle,
    LinuxDeploymentPlan,
    LinuxInstalledRelease,
)

from .remote_gateway import BoundedProcessResult, run_bounded_process, ssh_inspection_command
from .remote_gateway import NasCompatibilityDecision


DEPLOYMENT_PROTOCOL = "guardian-nas-deployment-v1"
DEPLOYMENT_REMOTE_COMMAND = "python3 - guardian-nas-deployment-v1"
MAX_DEPLOYMENT_STDIN = 72 * 1024 * 1024
MAX_DEPLOYMENT_STDOUT = 16 * 1024
MAX_DEPLOYMENT_STDERR = 8 * 1024
_HASH = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
_SECRET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}(?:\.r[1-9][0-9]{0,18})?")
_RECEIPT_KEYS = (
    "protocol",
    "ok",
    "error_code",
    "recovered",
    "active_version",
    "manifest_sha256",
    "config_sha256",
)


class NasDeploymentTransportError(RuntimeError):
    pass


DeploymentRunner = Callable[
    [Sequence[str], bytes, float, int, int],
    BoundedProcessResult,
]


@dataclass(frozen=True, slots=True)
class NasDeploymentEnvelope:
    version: str
    architecture: str
    package_mode: str
    supervisor: str
    entrypoint: str
    manifest_sha256: str
    manifest_b64: str
    files: tuple[Mapping[str, object], ...]
    config: Mapping[str, object]
    secrets: Mapping[str, str]

    @classmethod
    def from_release(
        cls,
        release: LinuxInstalledRelease,
        bundle: LinuxDeploymentBundle,
        plan: LinuxDeploymentPlan,
    ) -> NasDeploymentEnvelope:
        if not isinstance(release, LinuxInstalledRelease):
            raise TypeError("nas_deployment_release_required")
        if not isinstance(bundle, LinuxDeploymentBundle):
            raise TypeError("nas_deployment_bundle_required")
        if not isinstance(plan, LinuxDeploymentPlan):
            raise TypeError("nas_deployment_plan_required")
        if (
            release.architecture != plan.architecture
            or release.package_mode != plan.package_mode
            or plan.supervisor not in {"systemd_user", "cron_user"}
        ):
            raise NasDeploymentTransportError("nas_deployment_plan_mismatch")
        try:
            bundle.validate_for_release(release)
        except Exception as exc:
            raise NasDeploymentTransportError("nas_deployment_bundle_invalid") from exc
        manifest_path = release.path / "manifest.json"
        try:
            manifest = manifest_path.read_bytes()
            document = json.loads(manifest.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NasDeploymentTransportError("nas_deployment_manifest_invalid") from exc
        if hashlib.sha256(manifest).hexdigest() != release.manifest_sha256:
            raise NasDeploymentTransportError("nas_deployment_manifest_mismatch")
        manifest_files = document.get("files") if isinstance(document, dict) else None
        if not isinstance(manifest_files, list):
            raise NasDeploymentTransportError("nas_deployment_manifest_invalid")
        packaged: list[Mapping[str, object]] = []
        for item in manifest_files:
            if not isinstance(item, dict) or set(item) != {"path", "size", "sha256", "mode"}:
                raise NasDeploymentTransportError("nas_deployment_manifest_invalid")
            relative = _relative_path(item.get("path"))
            path = release.path.joinpath(*PurePosixPath(relative).parts)
            if path.is_symlink() or not path.is_file():
                raise NasDeploymentTransportError("nas_deployment_release_changed")
            try:
                content = path.read_bytes()
            except OSError as exc:
                raise NasDeploymentTransportError("nas_deployment_release_changed") from exc
            size = item.get("size")
            digest = item.get("sha256")
            mode = item.get("mode")
            if (
                type(size) is not int
                or size != len(content)
                or not isinstance(digest, str)
                or _HASH.fullmatch(digest) is None
                or hashlib.sha256(content).hexdigest() != digest
                or mode not in {0o600, 0o700}
            ):
                raise NasDeploymentTransportError("nas_deployment_release_changed")
            packaged.append(
                {
                    "path": relative,
                    "size": size,
                    "sha256": digest,
                    "mode": mode,
                    "data_b64": base64.b64encode(content).decode("ascii"),
                }
            )
        payload = bundle.payload()
        try:
            bundle_document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NasDeploymentTransportError("nas_deployment_bundle_invalid") from exc
        config = bundle_document.get("config")
        secrets = bundle_document.get("secrets")
        if not isinstance(config, dict) or not isinstance(secrets, dict):
            raise NasDeploymentTransportError("nas_deployment_bundle_invalid")
        if any(not isinstance(name, str) or _SECRET_NAME.fullmatch(name) is None for name in secrets):
            raise NasDeploymentTransportError("nas_deployment_bundle_invalid")
        return cls(
            version=release.version,
            architecture=release.architecture,
            package_mode=release.package_mode,
            supervisor=plan.supervisor,
            entrypoint=release.entrypoint,
            manifest_sha256=release.manifest_sha256,
            manifest_b64=base64.b64encode(manifest).decode("ascii"),
            files=tuple(packaged),
            config=config,
            secrets=secrets,
        )

    def document(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "protocol": DEPLOYMENT_PROTOCOL,
            "version": self.version,
            "architecture": self.architecture,
            "package_mode": self.package_mode,
            "supervisor": self.supervisor,
            "entrypoint": self.entrypoint,
            "manifest_sha256": self.manifest_sha256,
            "manifest_b64": self.manifest_b64,
            "files": [dict(item) for item in self.files],
            "config": dict(self.config),
            "secrets": dict(self.secrets),
        }


def deployment_plan_from_decision(
    decision: NasCompatibilityDecision,
    *,
    architecture: str,
) -> LinuxDeploymentPlan:
    if not isinstance(decision, NasCompatibilityDecision):
        raise TypeError("nas_compatibility_decision_required")
    if (
        not decision.compatible
        or decision.blockers
        or decision.package_mode != "locked_venv"
        or decision.supervisor not in {"systemd_user", "cron_user"}
    ):
        raise NasDeploymentTransportError("nas_deployment_environment_incompatible")
    return LinuxDeploymentPlan(
        architecture=architecture,
        package_mode=decision.package_mode,
        supervisor=decision.supervisor,
    )


def ssh_deployment_command(host: Mapping[str, Any]) -> list[str]:
    command = ssh_inspection_command(host)
    command[-1] = DEPLOYMENT_REMOTE_COMMAND
    return command


def render_deployment_stdin(envelope: NasDeploymentEnvelope) -> bytes:
    if not isinstance(envelope, NasDeploymentEnvelope):
        raise TypeError("nas_deployment_envelope_required")
    _validate_envelope(envelope)
    encoded = base64.b64encode(
        json.dumps(
            envelope.document(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")
    script = _REMOTE_DEPLOYMENT_WORKER.replace("__GUARDIAN_PAYLOAD_B64__", repr(encoded))
    payload = script.encode("utf-8")
    if len(payload) > MAX_DEPLOYMENT_STDIN:
        raise NasDeploymentTransportError("nas_deployment_input_too_large")
    return payload


def parse_deployment_receipt(payload: bytes) -> dict[str, object]:
    if len(payload) > MAX_DEPLOYMENT_STDOUT:
        raise NasDeploymentTransportError("nas_deployment_output_too_large")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NasDeploymentTransportError("nas_deployment_output_invalid") from exc
    if not isinstance(document, dict) or tuple(document) != _RECEIPT_KEYS:
        raise NasDeploymentTransportError("nas_deployment_output_invalid")
    if document.get("protocol") != DEPLOYMENT_PROTOCOL or type(document.get("ok")) is not bool:
        raise NasDeploymentTransportError("nas_deployment_output_invalid")
    if type(document.get("recovered")) is not bool:
        raise NasDeploymentTransportError("nas_deployment_output_invalid")
    for key in ("error_code", "active_version", "manifest_sha256", "config_sha256"):
        value = document.get(key)
        if value is not None and not isinstance(value, str):
            raise NasDeploymentTransportError("nas_deployment_output_invalid")
    if document["ok"]:
        if document["error_code"] is not None or _VERSION.fullmatch(document["active_version"] or "") is None:
            raise NasDeploymentTransportError("nas_deployment_output_invalid")
        if _HASH.fullmatch(document["manifest_sha256"] or "") is None or _HASH.fullmatch(document["config_sha256"] or "") is None:
            raise NasDeploymentTransportError("nas_deployment_output_invalid")
    else:
        if not isinstance(document["error_code"], str) or re.fullmatch(r"nas_deployment_[a-z0-9_]{1,96}", document["error_code"]) is None:
            raise NasDeploymentTransportError("nas_deployment_output_invalid")
        for key in ("active_version", "manifest_sha256", "config_sha256"):
            if document[key] is not None:
                raise NasDeploymentTransportError("nas_deployment_output_invalid")
    return document


class NasSshDeploymentTransport:
    def __init__(
        self,
        *,
        runner: DeploymentRunner | None = None,
        timeout: float = 180.0,
    ) -> None:
        if timeout <= 0 or timeout > 600:
            raise ValueError("nas_deployment_timeout_invalid")
        self.runner = runner or run_bounded_process
        self.timeout = timeout

    def deploy(self, host: Mapping[str, Any], envelope: NasDeploymentEnvelope) -> dict[str, object]:
        command = ssh_deployment_command(host)
        stdin = render_deployment_stdin(envelope)
        result = self.runner(
            command,
            stdin,
            self.timeout,
            MAX_DEPLOYMENT_STDOUT,
            MAX_DEPLOYMENT_STDERR,
        )
        if result.timed_out:
            raise NasDeploymentTransportError("nas_deployment_timeout")
        if result.stdout_truncated or result.stderr_truncated:
            raise NasDeploymentTransportError("nas_deployment_output_too_large")
        if result.returncode != 0:
            raise NasDeploymentTransportError("nas_deployment_ssh_failed")
        return parse_deployment_receipt(result.stdout)


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise NasDeploymentTransportError("nas_deployment_manifest_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise NasDeploymentTransportError("nas_deployment_manifest_invalid")
    return path.as_posix()


def _validate_envelope(envelope: NasDeploymentEnvelope) -> None:
    if _VERSION.fullmatch(envelope.version) is None:
        raise NasDeploymentTransportError("nas_deployment_envelope_invalid")
    if (
        envelope.architecture not in {"x86_64", "aarch64"}
        or envelope.package_mode != "locked_venv"
        or envelope.supervisor not in {"systemd_user", "cron_user"}
    ):
        raise NasDeploymentTransportError("nas_deployment_envelope_invalid")
    entrypoint = _relative_path(envelope.entrypoint)
    if _HASH.fullmatch(envelope.manifest_sha256) is None:
        raise NasDeploymentTransportError("nas_deployment_envelope_invalid")
    try:
        manifest = base64.b64decode(envelope.manifest_b64, validate=True)
        manifest_document = json.loads(manifest.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NasDeploymentTransportError("nas_deployment_manifest_invalid") from exc
    if hashlib.sha256(manifest).hexdigest() != envelope.manifest_sha256:
        raise NasDeploymentTransportError("nas_deployment_manifest_mismatch")
    if not isinstance(manifest_document, dict) or set(manifest_document) != {
        "schema_version",
        "version",
        "architecture",
        "package_mode",
        "entrypoint",
        "transaction_id",
        "content_sha256",
        "files",
    }:
        raise NasDeploymentTransportError("nas_deployment_manifest_invalid")
    if (
        manifest_document.get("schema_version") != 1
        or manifest_document.get("version") != envelope.version
        or manifest_document.get("architecture") != envelope.architecture
        or manifest_document.get("package_mode") != envelope.package_mode
        or manifest_document.get("entrypoint") != entrypoint
    ):
        raise NasDeploymentTransportError("nas_deployment_manifest_mismatch")
    manifest_files = manifest_document.get("files")
    if not isinstance(manifest_files, list) or len(manifest_files) != len(envelope.files) or len(manifest_files) > 512:
        raise NasDeploymentTransportError("nas_deployment_manifest_invalid")
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    total = 0
    for packaged, manifest_item in zip(envelope.files, manifest_files, strict=True):
        if not isinstance(packaged, Mapping) or set(packaged) != {
            "path",
            "size",
            "sha256",
            "mode",
            "data_b64",
        }:
            raise NasDeploymentTransportError("nas_deployment_envelope_invalid")
        if not isinstance(manifest_item, dict) or set(manifest_item) != {"path", "size", "sha256", "mode"}:
            raise NasDeploymentTransportError("nas_deployment_manifest_invalid")
        relative = _relative_path(packaged.get("path"))
        size = packaged.get("size")
        digest = packaged.get("sha256")
        mode = packaged.get("mode")
        data_b64 = packaged.get("data_b64")
        executable_paths = {entrypoint, "bin/guardian-gateway-supervisor"}
        expected_mode = 0o700 if relative in executable_paths else 0o600
        if (
            relative in seen
            or type(size) is not int
            or size < 0
            or not isinstance(digest, str)
            or _HASH.fullmatch(digest) is None
            or mode != expected_mode
            or not isinstance(data_b64, str)
        ):
            raise NasDeploymentTransportError("nas_deployment_envelope_invalid")
        try:
            content = base64.b64decode(data_b64, validate=True)
        except ValueError as exc:
            raise NasDeploymentTransportError("nas_deployment_envelope_invalid") from exc
        if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
            raise NasDeploymentTransportError("nas_deployment_release_changed")
        normalized_item = {"path": relative, "size": size, "sha256": digest, "mode": mode}
        if manifest_item != normalized_item:
            raise NasDeploymentTransportError("nas_deployment_manifest_mismatch")
        normalized.append(normalized_item)
        seen.add(relative)
        total += size
        if total > 64 * 1024 * 1024:
            raise NasDeploymentTransportError("nas_deployment_input_too_large")
    if entrypoint not in seen:
        raise NasDeploymentTransportError("nas_deployment_entrypoint_missing")
    canonical = json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(canonical).hexdigest() != manifest_document.get("content_sha256"):
        raise NasDeploymentTransportError("nas_deployment_manifest_mismatch")
    if not isinstance(envelope.config, Mapping) or not isinstance(envelope.secrets, Mapping):
        raise NasDeploymentTransportError("nas_deployment_bundle_invalid")
    for name, value in envelope.secrets.items():
        if (
            not isinstance(name, str)
            or _SECRET_NAME.fullmatch(name) is None
            or not isinstance(value, str)
            or not value
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise NasDeploymentTransportError("nas_deployment_bundle_invalid")


_REMOTE_DEPLOYMENT_WORKER = r'''from __future__ import annotations
import base64, hashlib, http.client, json, os, platform, re, shlex, shutil, socket, stat, subprocess, sys, time, uuid
from pathlib import Path, PurePosixPath

PROTOCOL = "guardian-nas-deployment-v1"
UNIT_NAME = "codex-profile-guardian-gateway.service"
CRON_BEGIN = "# BEGIN CODEX PROFILE GUARDIAN GATEWAY"
CRON_END = "# END CODEX PROFILE GUARDIAN GATEWAY"
payload_b64 = __GUARDIAN_PAYLOAD_B64__

def fail(code, recovered):
    print(json.dumps({"protocol": PROTOCOL, "ok": False, "error_code": code, "recovered": recovered, "active_version": None, "manifest_sha256": None, "config_sha256": None}, separators=(",", ":")))

def transaction_error_code(exc):
    code = str(exc)
    allowed = {
        "nas_deployment_crontab_invalid",
        "nas_deployment_crontab_write_failed",
        "nas_deployment_drain_failed",
        "nas_deployment_health_failed",
        "nas_deployment_port_unavailable",
        "nas_deployment_stop_failed",
        "nas_deployment_supervisor_missing",
        "nas_deployment_token_invalid",
    }
    return code if code in allowed else "nas_deployment_transaction_failed"

def safe_path(root, relative):
    value = PurePosixPath(relative)
    if value.is_absolute() or any(part in {"", ".", ".."} for part in value.parts):
        raise RuntimeError("nas_deployment_path_invalid")
    return root.joinpath(*value.parts)

def reject_links(home, path):
    relative = path.relative_to(home)
    current = home
    if current.is_symlink():
        raise RuntimeError("nas_deployment_link_forbidden")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError("nas_deployment_link_forbidden")

def atomic_write(home, path, content, mode):
    reject_links(home, path.parent)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    reject_links(home, path.parent)
    if path.is_symlink():
        raise RuntimeError("nas_deployment_link_forbidden")
    temporary = path.parent / ("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try: temporary.unlink()
        except OSError: pass

def snapshot(path):
    if path.is_symlink():
        raise RuntimeError("nas_deployment_link_forbidden")
    try: return (True, bytearray(path.read_bytes()), stat.S_IMODE(path.stat().st_mode))
    except FileNotFoundError: return (False, bytearray(), 0o600)

def restore(home, path, value):
    existed, content, mode = value
    if existed: atomic_write(home, path, bytes(content), mode)
    else: path.unlink(missing_ok=True)

def service(*args, check=True):
    return subprocess.run(["systemctl", "--user", *args], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=check)

def read_crontab():
    result = subprocess.run(["crontab", "-l"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode == 0:
        return bytes(result.stdout)
    if result.returncode == 1:
        return b""
    raise RuntimeError("nas_deployment_crontab_unavailable")

def write_crontab(content):
    result = subprocess.run(["crontab", "-"], input=content, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode != 0:
        raise RuntimeError("nas_deployment_crontab_write_failed")

def cron_without_managed(content):
    text = content.decode("utf-8")
    if text.count(CRON_BEGIN) != text.count(CRON_END) or text.count(CRON_BEGIN) > 1:
        raise RuntimeError("nas_deployment_crontab_invalid")
    pattern = re.compile(re.escape(CRON_BEGIN) + r".*?" + re.escape(CRON_END) + r"\s*", re.S)
    cleaned, count = pattern.subn("", text)
    if count != text.count(CRON_BEGIN):
        raise RuntimeError("nas_deployment_crontab_invalid")
    return cleaned.rstrip()

def cron_content(previous, supervisor, share, config_root, home):
    base = cron_without_managed(previous)
    arguments = [str(supervisor), "--install-root", str(share), "--config", str(config_root / "active.json"), "--platform", "linux", "--home", str(home)]
    line = "* * * * * " + " ".join(shlex.quote(value) for value in arguments) + " >/dev/null 2>&1"
    managed = CRON_BEGIN + "\n" + line + "\n" + CRON_END + "\n"
    prefix = (base + "\n") if base else ""
    return prefix.encode("utf-8") + managed.encode("utf-8")

def start_cron_supervisor(supervisor, share, config_root, home):
    subprocess.Popen(
        [str(supervisor), "--install-root", str(share), "--config", str(config_root / "active.json"), "--platform", "linux", "--home", str(home)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )

def require_environment(document):
    if document.get("architecture") != platform.machine() or document.get("package_mode") != "locked_venv":
        raise RuntimeError("nas_deployment_environment_drift")
    if sys.version_info < (3, 11):
        raise RuntimeError("nas_deployment_environment_drift")
    supervisor = document.get("supervisor")
    if supervisor == "systemd_user":
        service("show-environment")
    elif supervisor == "cron_user":
        if shutil.which("crontab") is None or subprocess.run(["systemctl", "is-active", "--quiet", "cron.service"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode != 0:
            raise RuntimeError("nas_deployment_environment_drift")
    else:
        raise RuntimeError("nas_deployment_environment_drift")
    validate_config(document.get("config"))

def validate_config(config):
    listen = config.get("listen") if isinstance(config, dict) else None
    if not isinstance(listen, dict) or listen.get("host") != "127.0.0.1":
        raise RuntimeError("nas_deployment_config_invalid")
    ports = (listen.get("data_port"), listen.get("control_port"))
    if any(type(port) is not int or port < 1024 or port > 65535 for port in ports) or ports[0] == ports[1]:
        raise RuntimeError("nas_deployment_config_invalid")

def require_ports_available(config):
    validate_config(config)
    ports = (config["listen"]["data_port"], config["listen"]["control_port"])
    sockets = []
    try:
        for port in ports:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(probe)
            probe.bind(("127.0.0.1", port))
    except OSError:
        raise RuntimeError("nas_deployment_port_unavailable")
    finally:
        for probe in sockets: probe.close()

def read_token(path):
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode) & (stat.S_IRWXG | stat.S_IRWXO):
        raise RuntimeError("nas_deployment_token_invalid")
    token = path.read_text(encoding="ascii")
    if len(token) < 48 or len(token) > 256 or any(ord(character) < 0x21 or ord(character) > 0x7E for character in token):
        raise RuntimeError("nas_deployment_token_invalid")
    return token

def request_json(port, method, path, token, *, body=None, timeout=5, expected_status=200):
    headers = {"Authorization": "Bearer " + token, "Host": "127.0.0.1:" + str(port)}
    encoded = None
    if body is not None:
        encoded = json.dumps(body, separators=(",", ":"))
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        payload = response.read(64 * 1024 + 1)
        if response.status != expected_status or len(payload) > 64 * 1024:
            raise RuntimeError("nas_deployment_http_check_failed")
        result = json.loads(payload.decode("utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError("nas_deployment_http_check_failed")
        return result
    finally:
        connection.close()

def drain_gateway(config_root, config):
    token_path = config_root / "tokens" / "control.token"
    token = read_token(token_path)
    timeout = config["lifecycle"]["drain_timeout_seconds"]
    result = request_json(config["listen"]["control_port"], "POST", "/control/v1/drain", token, body={"timeout_seconds": timeout}, timeout=max(5, min(305, timeout + 5)))
    if result.get("ok") is not True or result.get("active_requests") != 0:
        raise RuntimeError("nas_deployment_drain_failed")

def stop_gateway(config_root, config):
    token = read_token(config_root / "tokens" / "control.token")
    timeout = config["lifecycle"]["drain_timeout_seconds"]
    result = request_json(config["listen"]["control_port"], "POST", "/control/v1/stop", token, body={"timeout_seconds": timeout}, timeout=max(5, min(305, timeout + 5)), expected_status=202)
    if result.get("ok") is not True:
        raise RuntimeError("nas_deployment_stop_failed")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", config["listen"]["control_port"]), timeout=0.2):
                pass
        except OSError:
            return
        time.sleep(0.2)
    raise RuntimeError("nas_deployment_stop_failed")

def verify_gateway(config_root, config):
    validate_config(config)
    version = config["gateway_version"]
    instance = config["instance_id"]
    revision = config["active_group"]["revision"]
    models = config["active_group"]["allowed_models"]
    deadline = time.monotonic() + 20
    last_error = None
    while time.monotonic() < deadline:
        try:
            ingress = read_token(config_root / "tokens" / "ingress.token")
            control = read_token(config_root / "tokens" / "control.token")
            health = request_json(config["listen"]["data_port"], "GET", "/health", ingress)
            published = request_json(config["listen"]["data_port"], "GET", "/v1/models", ingress)
            status = request_json(config["listen"]["control_port"], "GET", "/control/v1/status", control)
            if health.get("ok") is not True or health.get("version") != version or health.get("instance_id") != instance or health.get("config_revision") != revision or health.get("accepting") is not True:
                raise RuntimeError("nas_deployment_health_identity_mismatch")
            if [item.get("id") for item in published.get("data", []) if isinstance(item, dict)] != models:
                raise RuntimeError("nas_deployment_models_mismatch")
            if status.get("ok") is not True or status.get("phase") != "running" or status.get("version") != version or status.get("instance_id") != instance or status.get("config_revision") != revision or status.get("data_port") != config["listen"]["data_port"] or status.get("control_port") != config["listen"]["control_port"]:
                raise RuntimeError("nas_deployment_control_identity_mismatch")
            if status.get("process_instance_id") != health.get("process_instance_id"):
                raise RuntimeError("nas_deployment_process_identity_mismatch")
            return
        except Exception as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError("nas_deployment_health_failed") from last_error

def validate_manifest(document):
    manifest = base64.b64decode(document["manifest_b64"], validate=True)
    if hashlib.sha256(manifest).hexdigest() != document["manifest_sha256"]:
        raise RuntimeError("nas_deployment_payload_invalid")
    manifest_document = json.loads(manifest.decode("utf-8"))
    if set(manifest_document) != {"schema_version", "version", "architecture", "package_mode", "entrypoint", "transaction_id", "content_sha256", "files"}:
        raise RuntimeError("nas_deployment_payload_invalid")
    if manifest_document["schema_version"] != 1 or any(manifest_document[key] != document[key] for key in ("version", "architecture", "package_mode", "entrypoint")):
        raise RuntimeError("nas_deployment_payload_invalid")
    files = document.get("files")
    if not isinstance(files, list) or len(files) != len(manifest_document["files"]) or len(files) > 512:
        raise RuntimeError("nas_deployment_payload_invalid")
    normalized = []
    seen = set()
    total = 0
    for item, manifest_item in zip(files, manifest_document["files"], strict=True):
        if set(item) != {"path", "size", "sha256", "mode", "data_b64"} or set(manifest_item) != {"path", "size", "sha256", "mode"}:
            raise RuntimeError("nas_deployment_payload_invalid")
        relative = PurePosixPath(item["path"])
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts) or item["path"] in seen:
            raise RuntimeError("nas_deployment_payload_invalid")
        executable_paths = {document["entrypoint"], "bin/guardian-gateway-supervisor"}
        expected_mode = 0o700 if item["path"] in executable_paths else 0o600
        content = base64.b64decode(item["data_b64"], validate=True)
        if type(item["size"]) is not int or item["size"] != len(content) or hashlib.sha256(content).hexdigest() != item["sha256"] or item["mode"] != expected_mode:
            raise RuntimeError("nas_deployment_payload_invalid")
        normalized_item = {"path": item["path"], "size": item["size"], "sha256": item["sha256"], "mode": item["mode"]}
        if normalized_item != manifest_item:
            raise RuntimeError("nas_deployment_payload_invalid")
        normalized.append(normalized_item); seen.add(item["path"]); total += item["size"]
        if total > 64 * 1024 * 1024:
            raise RuntimeError("nas_deployment_payload_invalid")
    if document["entrypoint"] not in seen:
        raise RuntimeError("nas_deployment_payload_invalid")
    canonical = json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(canonical).hexdigest() != manifest_document["content_sha256"]:
        raise RuntimeError("nas_deployment_payload_invalid")
    return manifest

def main():
    if len(sys.argv) != 2 or sys.argv[1] != PROTOCOL or os.name != "posix":
        fail("nas_deployment_runtime_invalid", True); return 0
    try:
        document = json.loads(base64.b64decode(payload_b64, validate=True))
        if document.get("protocol") != PROTOCOL or document.get("schema_version") != 1:
            raise RuntimeError("nas_deployment_payload_invalid")
        version = document["version"]
        if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version) is None:
            raise RuntimeError("nas_deployment_payload_invalid")
        manifest = validate_manifest(document)
        require_environment(document)
        home = Path.home().resolve()
        share = home / ".local" / "share" / "codex-profile-guardian-gateway"
        versions = share / "versions"
        config_root = home / ".config" / "codex-profile-guardian-gateway"
        secrets_root = config_root / "secrets"
        state_root = home / ".local" / "state" / "codex-profile-guardian-gateway"
        unit = home / ".config" / "systemd" / "user" / UNIT_NAME
        pointer = share / "current.json"
        lock = state_root / "deployment.state-uncertain.json"
        directories = [share, versions, config_root, secrets_root, state_root]
        if document["supervisor"] == "systemd_user":
            directories.append(unit.parent)
        for path in directories:
            reject_links(home, path)
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)
        if lock.exists() or lock.is_symlink():
            fail("nas_deployment_state_uncertain_locked", False); return 0
        target = versions / version
        if target.exists() or target.is_symlink():
            fail("nas_deployment_release_exists", True); return 0
        stage = versions / ("." + version + "." + uuid.uuid4().hex + ".tmp")
        stage.mkdir(mode=0o700)
        try:
            for item in document["files"]:
                path = safe_path(stage, item["path"])
                content = base64.b64decode(item["data_b64"], validate=True)
                if len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["sha256"] or item["mode"] not in {0o600, 0o700}:
                    raise RuntimeError("nas_deployment_payload_invalid")
                atomic_write(stage, path, content, item["mode"])
            atomic_write(stage, stage / "manifest.json", manifest, 0o600)
            os.replace(stage, target)
        finally:
            try: shutil.rmtree(stage)
            except OSError: pass
        secret_paths = []
        for name in sorted(document["secrets"]):
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}(?:\.r[1-9][0-9]{0,18})?", name) is None:
                raise RuntimeError("nas_deployment_payload_invalid")
            secret_paths.append(secrets_root / (name + ".key"))
        paths = [config_root / "active.json", pointer, *secret_paths]
        if document["supervisor"] == "systemd_user":
            paths.append(unit)
        snapshots = {path: snapshot(path) for path in paths}
        crontab_snapshot = read_crontab() if document["supervisor"] == "cron_user" else None
        previous = None
        previous_config = None
        if snapshots[pointer][0]:
            try: previous = json.loads(bytes(snapshots[pointer][1]).decode("utf-8")).get("version")
            except Exception: raise RuntimeError("nas_deployment_pointer_invalid")
            if not snapshots[config_root / "active.json"][0]:
                raise RuntimeError("nas_deployment_previous_config_missing")
            try: previous_config = json.loads(bytes(snapshots[config_root / "active.json"][1]).decode("utf-8"))
            except Exception: raise RuntimeError("nas_deployment_previous_config_invalid")
            validate_config(previous_config)
        stopped = False
        try:
            if previous:
                if document["supervisor"] == "cron_user":
                    write_crontab((cron_without_managed(crontab_snapshot) + "\n").encode("utf-8") if cron_without_managed(crontab_snapshot) else b"")
                drain_gateway(config_root, previous_config)
                if document["supervisor"] == "systemd_user":
                    service("stop", UNIT_NAME)
                else:
                    stop_gateway(config_root, previous_config)
                stopped = True
            require_ports_available(document["config"])
            config = (json.dumps(document["config"], ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
            atomic_write(home, config_root / "active.json", config, 0o600)
            for name, value in document["secrets"].items():
                if not isinstance(value, str) or not value or any(ord(char) < 0x20 for char in value):
                    raise RuntimeError("nas_deployment_payload_invalid")
                atomic_write(home, secrets_root / (name + ".key"), value.encode(), 0o600)
            executable = target / document["entrypoint"]
            pointer_doc = {"schema_version": 1, "version": version, "relative_path": "versions/" + version, "manifest_sha256": document["manifest_sha256"], "previous_version": previous}
            atomic_write(home, pointer, (json.dumps(pointer_doc, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o600)
            if document["supervisor"] == "systemd_user":
                unit_text = "[Unit]\nDescription=Codex Profile Guardian Gateway\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart=\"{}\" --install-root \"{}\" --config \"{}\" --platform linux --home \"{}\"\nRestart=on-failure\nRestartSec=5s\nStartLimitIntervalSec=300\nStartLimitBurst=5\nNoNewPrivileges=true\nPrivateTmp=true\nUMask=0077\n\n[Install]\nWantedBy=default.target\n".format(executable, share, config_root / "active.json", home)
                atomic_write(home, unit, unit_text.encode(), 0o600)
                service("daemon-reload")
                service("restart", UNIT_NAME)
                service("is-active", "--quiet", UNIT_NAME)
            else:
                cron_supervisor = target / "bin" / "guardian-gateway-supervisor"
                if not cron_supervisor.is_file() or cron_supervisor.is_symlink():
                    raise RuntimeError("nas_deployment_supervisor_missing")
                write_crontab(cron_content(crontab_snapshot, cron_supervisor, share, config_root, home))
                start_cron_supervisor(cron_supervisor, share, config_root, home)
            verify_gateway(config_root, document["config"])
            print(json.dumps({"protocol": PROTOCOL, "ok": True, "error_code": None, "recovered": True, "active_version": version, "manifest_sha256": document["manifest_sha256"], "config_sha256": hashlib.sha256(config).hexdigest()}, separators=(",", ":")))
            return 0
        except Exception as transaction_error:
            recovered = True
            try:
                if document["supervisor"] == "systemd_user":
                    service("stop", UNIT_NAME, check=False)
                else:
                    try: stop_gateway(config_root, document["config"])
                    except Exception: pass
                for path in reversed(paths): restore(home, path, snapshots[path])
                if document["supervisor"] == "systemd_user":
                    service("daemon-reload")
                else:
                    write_crontab(crontab_snapshot)
                if previous:
                    if document["supervisor"] == "systemd_user":
                        service("restart", UNIT_NAME)
                        service("is-active", "--quiet", UNIT_NAME)
                    else:
                        previous_pointer = json.loads(bytes(snapshots[pointer][1]).decode("utf-8"))
                        previous_supervisor = share / previous_pointer["relative_path"] / "bin" / "guardian-gateway-supervisor"
                        start_cron_supervisor(previous_supervisor, share, config_root, home)
                    verify_gateway(config_root, previous_config)
            except Exception:
                recovered = False
            for _path, (_existed, content, _mode) in snapshots.items():
                for index in range(len(content)): content[index] = 0
            if not recovered:
                try: atomic_write(home, lock, b'{"schema_version":1,"error_code":"nas_deployment_state_uncertain"}\n', 0o600)
                except Exception: pass
            fail(transaction_error_code(transaction_error), recovered)
            return 0
    except Exception:
        fail("nas_deployment_payload_invalid", True)
        return 0

raise SystemExit(main())
'''


__all__ = [
    "DEPLOYMENT_PROTOCOL",
    "DEPLOYMENT_REMOTE_COMMAND",
    "MAX_DEPLOYMENT_STDERR",
    "MAX_DEPLOYMENT_STDIN",
    "MAX_DEPLOYMENT_STDOUT",
    "NasDeploymentEnvelope",
    "NasDeploymentTransportError",
    "NasSshDeploymentTransport",
    "deployment_plan_from_decision",
    "parse_deployment_receipt",
    "render_deployment_stdin",
    "ssh_deployment_command",
]
