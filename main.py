from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import sys
import threading
import time
import webbrowser

from backend.guardian import APP_NAME, APP_VERSION, GuardianError, GuardianService
from backend.server import start_server
from gateway.dpapi import unprotect_current_user
from gateway.tokens import read_gateway_ingress_token


def resource_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class QuotaRefreshWorker:
    def __init__(self, service: GuardianService, interval_seconds: float = 60.0) -> None:
        self.service = service
        self.interval_seconds = interval_seconds
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="guardian-quota-refresh",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        self.thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.service.refresh_official_quotas()
            except Exception:
                pass
            if self.stop_event.wait(self.interval_seconds):
                return


class UpdateRefreshWorker:
    def __init__(
        self,
        service: GuardianService,
        interval_seconds: float = 30 * 60,
        startup_delay_seconds: float = 5.0,
    ) -> None:
        self.service = service
        self.interval_seconds = interval_seconds
        self.startup_delay_seconds = startup_delay_seconds
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="guardian-update-refresh",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        self.thread.join(timeout=timeout)

    def _run(self) -> None:
        if self.stop_event.wait(self.startup_delay_seconds):
            return
        while not self.stop_event.is_set():
            try:
                self.service.automatic_update_cycle()
            except Exception:
                pass
            if self.stop_event.wait(self.interval_seconds):
                return


def installed_gateway_options() -> dict[str, object]:
    if not getattr(sys, "frozen", False) and os.environ.get(
        "GUARDIAN_ENABLE_PRODUCTION_GATEWAY"
    ) != "1":
        return {}
    local_app_data = Path(
        os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
    )
    install_root = (local_app_data / APP_NAME).resolve()
    gateway_version = f"v{APP_VERSION}"
    gateway_executable = (
        install_root
        / "gateway"
        / "versions"
        / gateway_version
        / "GuardianGateway.exe"
    )
    if not gateway_executable.is_file():
        return {}
    return {
        "gateway_install_root": install_root,
        "gateway_expected_executable": gateway_executable,
        "gateway_expected_version": gateway_version,
        "provider_auth_command": [
            str(Path(sys.executable).resolve()),
            "gateway-ingress",
            str(install_root),
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Codex Profile Guardian")
    parser.add_argument(
        "command",
        nargs="?",
        default="desktop",
        choices=["desktop", "serve", "secret", "gateway-ingress"],
    )
    parser.add_argument("value", nargs="?")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--codex-home")
    parser.add_argument("--data-dir")
    parser.add_argument("--claude-local-appdata")
    parser.add_argument("--cc-switch-home")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "gateway-ingress":
        if not args.value:
            return 2
        try:
            token = read_gateway_ingress_token(
                args.value,
                unprotect=unprotect_current_user,
            )
            sys.stdout.buffer.write(token.encode("ascii"))
            sys.stdout.buffer.flush()
            return 0
        except Exception:
            return 1

    service = GuardianService(
        codex_home=args.codex_home,
        data_dir=args.data_dir,
        claude_local_appdata=args.claude_local_appdata,
        cc_switch_home=args.cc_switch_home,
        **installed_gateway_options(),
    )
    if args.command == "secret":
        if not args.value:
            return 2
        try:
            sys.stdout.buffer.write(service.decrypt_secret(args.value))
            sys.stdout.buffer.flush()
            return 0
        except Exception:
            return 1

    quota_worker = QuotaRefreshWorker(service)
    update_worker = UpdateRefreshWorker(service)
    quota_worker.start()
    update_worker.start()
    port = args.port or free_port()
    web_root = resource_root() / "dist"
    try:
        server = start_server(service, web_root, args.host, port)
    except Exception:
        quota_worker.stop()
        update_worker.stop()
        raise
    url = f"http://{args.host}:{port}"
    if args.command == "serve":
        print(url, flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            server.shutdown()
        finally:
            quota_worker.stop()
            update_worker.stop()
        return 0

    try:
        import webview

        window = webview.create_window(
            "Codex Profile Guardian",
            url,
            width=1480,
            height=920,
            min_size=(1060, 680),
            background_color="#f5f6f7",
        )
        webview.start(debug=False)
    except ImportError:
        webbrowser.open(url)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    finally:
        quota_worker.stop()
        update_worker.stop()
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
