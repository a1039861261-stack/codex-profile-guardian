from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import winreg


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERSION = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
UNINSTALL_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Codex Profile Guardian"


def registry_snapshot() -> dict[str, object] | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_SUBKEY) as key:
            result: dict[str, object] = {}
            index = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, index)
                except OSError:
                    break
                result[name] = [value, value_type]
                index += 1
            return result
    except FileNotFoundError:
        return None


def task_snapshot() -> tuple[int, bytes]:
    completed = subprocess.run(
        ["schtasks.exe", "/Query", "/TN", "Codex Profile Guardian Gateway", "/XML"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=0x08000000,
    )
    return completed.returncode, completed.stdout


def shortcut_properties(path: Path) -> dict[str, str]:
    escaped = str(path).replace("'", "''")
    script = (
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('"
        + escaped
        + "'); [pscustomobject]@{TargetPath=$s.TargetPath;IconLocation=$s.IconLocation} | ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        creationflags=0x08000000,
    )
    if completed.returncode != 0:
        raise RuntimeError("shortcut_query_failed")
    return json.loads(completed.stdout)


def assert_same_bytes(left: Path, right: Path) -> None:
    if left.read_bytes() != right.read_bytes():
        raise RuntimeError(f"installed_payload_mismatch:{left.name}")


def visible_window_titles() -> set[str]:
    titles: set[str] = set()
    enum_windows = ctypes.windll.user32.EnumWindows
    get_length = ctypes.windll.user32.GetWindowTextLengthW
    get_text = ctypes.windll.user32.GetWindowTextW
    is_visible = ctypes.windll.user32.IsWindowVisible
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    @callback_type
    def callback(window: int, _parameter: int) -> bool:
        if is_visible(window):
            length = get_length(window)
            if length:
                buffer = ctypes.create_unicode_buffer(length + 1)
                get_text(window, buffer, length + 1)
                titles.add(buffer.value)
        return True

    enum_windows(callback, 0)
    return titles


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--installer", required=True)
    parser.add_argument("--portable", required=True)
    args = parser.parse_args()
    installer = Path(args.installer).resolve()
    portable = Path(args.portable).resolve()
    if not installer.is_file() or not portable.is_dir():
        raise RuntimeError("installer_smoke_input_missing")

    real_version_root = Path(os.environ["LOCALAPPDATA"]) / "Codex Profile Guardian" / "app" / f"v{VERSION}"
    real_version_existed = real_version_root.exists()
    before_registry = registry_snapshot()
    before_task = task_snapshot()
    temporary_parent = PROJECT_ROOT / "_tmp"
    temporary_parent.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="installer-exe-smoke-", dir=temporary_parent) as temporary:
        smoke_root = Path(temporary)
        result_path = smoke_root / "result.json"
        process = subprocess.Popen(
            [
                str(installer),
                "--smoke-root",
                str(smoke_root),
                "--result-file",
                str(result_path),
                "--gui-smoke",
                "--auto-close",
            ],
            cwd=installer.parent,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=0x08000000,
        )
        gui_seen = False
        deadline = time.monotonic() + 240
        while process.poll() is None and time.monotonic() < deadline:
            if "Codex Profile Guardian 安装程序" in visible_window_titles():
                gui_seen = True
            time.sleep(0.05)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
            raise RuntimeError("installer_exe_timeout")
        if process.returncode != 0 or not result_path.is_file():
            raise RuntimeError(f"installer_exe_failed:{process.returncode}")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if (
            result.get("ok") is not True
            or result.get("version") != VERSION
            or result.get("smoke_mode") is not True
            or result.get("gui_started") is not True
            or not gui_seen
        ):
            raise RuntimeError("installer_exe_result_invalid")

        install_base = smoke_root / "install"
        app_root = install_base / "app" / f"v{VERSION}"
        gateway_root = install_base / "gateway" / "versions" / f"v{VERSION}"
        for name in ("CodexProfileGuardian.exe", "CodexProfileGuardianSecret.exe", "README-CN.md", "LICENSE"):
            assert_same_bytes(app_root / name, portable / name)
        for name in ("GuardianGateway.exe", "GuardianGatewaySupervisor.exe"):
            assert_same_bytes(gateway_root / name, portable / name)

        desktop_shortcut = smoke_root / "desktop" / "Codex Profile Guardian.lnk"
        start_shortcut = smoke_root / "start-menu" / "Codex Profile Guardian.lnk"
        target = (app_root / "CodexProfileGuardian.exe").resolve()
        for shortcut in (desktop_shortcut, start_shortcut):
            properties = shortcut_properties(shortcut)
            if Path(properties["TargetPath"]).resolve() != target:
                raise RuntimeError("installer_shortcut_target_invalid")
            icon_location = properties["IconLocation"].rsplit(",", 1)[0]
            if Path(icon_location).resolve() != target:
                raise RuntimeError("installer_shortcut_icon_invalid")

    if registry_snapshot() != before_registry:
        raise RuntimeError("installer_smoke_modified_registry")
    if task_snapshot() != before_task:
        raise RuntimeError("installer_smoke_modified_scheduled_task")
    if real_version_root.exists() != real_version_existed:
        raise RuntimeError("installer_smoke_modified_real_install_root")

    print(
        json.dumps(
            {
                "ok": True,
                "version": VERSION,
                "final_exe_launched": True,
                "gui_window_observed": True,
                "isolated_install_completed": True,
                "shortcuts_verified": True,
                "logo_verified": True,
                "registry_modified": False,
                "scheduled_task_modified": False,
                "real_install_root_modified": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
