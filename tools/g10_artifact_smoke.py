from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERSION = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
RELEASE_VERSION = f"v{VERSION}"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.dpapi import unprotect_current_user
from gateway.runtime_files import RuntimeDescriptorStore
from gateway.tokens import ProtectedTokenStore


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def isolated_gateway_ports() -> tuple[int, int]:
    data_port = free_port()
    control_port = free_port()
    while control_port == data_port:
        control_port = free_port()
    return data_port, control_port


def assign_isolated_gateway_ports(config_path: Path) -> tuple[int, int]:
    document = json.loads(config_path.read_text(encoding="utf-8"))
    listen = document.get("listen")
    if not isinstance(listen, dict) or listen.get("host") != "127.0.0.1":
        raise RuntimeError("artifact_gateway_listen_invalid")
    data_port, control_port = isolated_gateway_ports()
    listen["data_port"] = data_port
    listen["control_port"] = control_port
    config_path.write_text(
        json.dumps(document, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return data_port, control_port


def request_json(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
    cookie: str | None = None,
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, str], dict[str, object]]:
    headers = {"Host": f"127.0.0.1:{port}", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    payload = None
    if body is not None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(payload))
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(method, path, body=payload, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    response_headers = {key.lower(): value for key, value in response.getheaders()}
    connection.close()
    document = json.loads(raw.decode("utf-8")) if raw else {}
    return response.status, response_headers, document


def wait_until(predicate, *, timeout: float = 20.0):
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as exc:  # bounded polling; only the final error is surfaced
            last_error = exc
        time.sleep(0.2)
    if last_error is not None:
        raise RuntimeError("artifact_smoke_timeout") from last_error
    raise RuntimeError("artifact_smoke_timeout")


def run_checked(command: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        creationflags=0x08000000 if os.name == "nt" else 0,
    )
    if completed.returncode != 0:
        raise RuntimeError("artifact_install_command_failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--staging", required=True)
    args = parser.parse_args()
    staging = Path(args.staging).resolve()
    required = {
        "install.ps1",
        "uninstall.ps1",
        "CodexProfileGuardian.exe",
        "CodexProfileGuardianSecret.exe",
        "GuardianGateway.exe",
        "GuardianGatewaySupervisor.exe",
        "README-CN.md",
        "LICENSE",
        "VERSION",
    }
    if not staging.is_dir() or not required.issubset({path.name for path in staging.iterdir()}):
        raise RuntimeError("artifact_staging_invalid")

    project_root = Path(__file__).resolve().parents[1]
    temporary_root = project_root / "_tmp"
    temporary_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="g10-artifact-", dir=temporary_root) as temporary:
        root = Path(temporary)
        local_app_data = root / "local-app-data"
        install_root = local_app_data / "Codex Profile Guardian"
        start_menu = root / "start-menu"
        desktop = root / "desktop"
        desktop.mkdir()
        shortcut = desktop / "Codex Profile Guardian.lnk"
        codex_home = root / "codex-home"
        codex_home.mkdir()
        environment = os.environ.copy()
        environment["LOCALAPPDATA"] = str(local_app_data)

        install_command = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(staging / "install.ps1"),
            "-NoLaunch",
            "-SkipRegistry",
            "-SkipScheduledTask",
            "-InstallBase",
            str(install_root),
            "-StartMenuDir",
            str(start_menu),
            "-DesktopShortcut",
            str(shortcut),
        ]
        run_checked(install_command, cwd=staging, env=environment)

        config_path = install_root / "gateway" / "config" / "active.json"
        isolated_data_port, isolated_control_port = assign_isolated_gateway_ports(config_path)
        supervisor_executable = (
            install_root
            / "gateway"
            / "versions"
            / RELEASE_VERSION
            / "GuardianGatewaySupervisor.exe"
        )
        supervisor = subprocess.Popen(
            [
                str(supervisor_executable),
                "--layout-root",
                str(install_root),
                "--config-file",
                str(config_path),
            ],
            cwd=supervisor_executable.parent,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        main_process: subprocess.Popen[bytes] | None = None
        try:
            descriptor_store = RuntimeDescriptorStore(
                install_root / "gateway" / "runtime" / "runtime.json"
            )
            descriptor = wait_until(lambda: descriptor_store.read())
            if (descriptor.data_port, descriptor.control_port) != (
                isolated_data_port,
                isolated_control_port,
            ):
                raise RuntimeError("artifact_gateway_port_drift")
            token_store = ProtectedTokenStore(
                install_root / "gateway" / "secrets" / "tokens",
                protect=lambda _payload: b"",
                unprotect=unprotect_current_user,
            )
            ingress = token_store.read_existing("ingress")
            control = token_store.read_existing("control")
            status, _, health = request_json(descriptor.data_port, "GET", "/health", token=ingress)
            if status != 200 or health.get("ok") is not True:
                raise RuntimeError("artifact_gateway_health_failed")
            status, _, control_status = request_json(
                descriptor.control_port,
                "GET",
                "/control/v1/status",
                token=control,
            )
            if (
                status != 200
                or control_status.get("version") != RELEASE_VERSION
                or control_status.get("models_ready") is not False
            ):
                raise RuntimeError("artifact_gateway_identity_failed")

            old_process_instance = descriptor.process_instance_id
            old_gateway_pid = descriptor.pid
            run_checked(install_command, cwd=staging, env=environment)
            supervisor.wait(timeout=20)
            if supervisor.returncode is None:
                raise RuntimeError("artifact_upgrade_supervisor_not_stopped")
            try:
                os.kill(old_gateway_pid, 0)
            except OSError:
                pass
            else:
                raise RuntimeError("artifact_upgrade_old_gateway_survived")

            supervisor = subprocess.Popen(
                [
                    str(supervisor_executable),
                    "--layout-root",
                    str(install_root),
                    "--config-file",
                    str(config_path),
                ],
                cwd=supervisor_executable.parent,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            descriptor = wait_until(
                lambda: (
                    candidate
                    if (candidate := descriptor_store.read()).process_instance_id
                    != old_process_instance
                    else None
                )
            )
            control = token_store.read_existing("control")
            status, _, control_status = request_json(
                descriptor.control_port,
                "GET",
                "/control/v1/status",
                token=control,
            )
            if status != 200 or control_status.get("phase") != "running":
                raise RuntimeError("artifact_upgrade_restart_failed")

            management_port = free_port()
            main_executable = install_root / "app" / RELEASE_VERSION / "CodexProfileGuardian.exe"
            main_process = subprocess.Popen(
                [
                    str(main_executable),
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(management_port),
                    "--codex-home",
                    str(codex_home),
                ],
                cwd=main_executable.parent,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )

            session_headers = wait_until(
                lambda: request_json(management_port, "GET", "/api/session")
                if main_process.poll() is None
                else None
            )
            if session_headers[0] != 200:
                raise RuntimeError("artifact_guardian_session_failed")
            cookie = session_headers[1].get("set-cookie", "").split(";", 1)[0]
            status, _, overview = request_json(
                management_port,
                "GET",
                "/api/failover/overview",
                cookie=cookie,
            )
            data = overview.get("data") if isinstance(overview, dict) else None
            if (
                status != 200
                or not isinstance(data, dict)
                or data.get("source") != "production"
                or data.get("gateway", {}).get("online") is not True
            ):
                raise RuntimeError("artifact_guardian_gateway_bridge_failed")

            status, _, stopped = request_json(
                descriptor.control_port,
                "POST",
                "/control/v1/stop",
                token=control,
                body={},
            )
            if status != 202 or stopped.get("ok") is not True:
                raise RuntimeError("artifact_gateway_stop_failed")
            supervisor.wait(timeout=20)
            if supervisor.returncode != 0:
                raise RuntimeError("artifact_supervisor_exit_failed")
        finally:
            if main_process is not None and main_process.poll() is None:
                main_process.terminate()
                try:
                    main_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    main_process.kill()
            if supervisor.poll() is None:
                supervisor.terminate()
                try:
                    supervisor.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    supervisor.kill()

        retained = install_root / "profiles.json"
        retained.write_text('{"fixture":true}\n', encoding="utf-8")
        run_checked(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(install_root / "app" / RELEASE_VERSION / "uninstall.ps1"),
                "-Quiet",
                "-SkipRegistry",
                "-SkipScheduledTask",
                "-StartMenuDir",
                str(start_menu),
                "-DesktopShortcut",
                str(shortcut),
            ],
            cwd=staging,
            env=environment,
        )
        if not retained.is_file() or not config_path.is_file():
            raise RuntimeError("artifact_uninstall_retention_failed")
        if (install_root / "app").exists() or (install_root / "gateway" / "versions").exists():
            raise RuntimeError("artifact_uninstall_program_cleanup_failed")

    print(
        json.dumps(
            {
                "ok": True,
                "version": VERSION,
                "gateway_health": True,
                "guardian_production_bridge": True,
                "upgrade_drain": True,
                "upgrade_process_replaced": True,
                "supervisor_graceful_stop": True,
                "uninstall_retained_user_data": True,
                "real_provider_used": False,
                "real_scheduled_task_registered": False,
                "registry_modified": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
