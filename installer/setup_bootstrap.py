from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import traceback


PRODUCT = "Codex Profile Guardian"
CREATE_NO_WINDOW = 0x08000000


def bundle_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def payload_root() -> Path:
    return bundle_root() / "payload"


def load_manifest(root: Path) -> dict[str, object]:
    path = root / "payload-manifest.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    if (
        document.get("schema_version") != 1
        or document.get("product") != PRODUCT
        or not isinstance(document.get("files"), list)
    ):
        raise RuntimeError("安装包载荷清单无效。")
    return document


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def verify_payload(root: Path, manifest: dict[str, object]) -> str:
    if manifest.get("schema_version") != 1 or manifest.get("product") != PRODUCT:
        raise RuntimeError("安装包载荷清单无效。")
    version = str(manifest.get("version", "")).strip()
    entries = manifest.get("files")
    if not version or not isinstance(entries, list):
        raise RuntimeError("安装包版本或载荷清单缺失。")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("安装包载荷清单无效。")
        name = str(entry.get("name", ""))
        if not name or Path(name).name != name or name in seen:
            raise RuntimeError("安装包载荷名称无效。")
        seen.add(name)
        try:
            expected_size = int(entry.get("bytes", -1))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("安装包载荷大小无效。") from exc
        expected_hash = str(entry.get("sha256", "")).upper()
        candidate = root / name
        if expected_size < 0 or not candidate.is_file() or candidate.stat().st_size != expected_size:
            raise RuntimeError(f"安装文件缺失或大小不符：{name}")
        if sha256_file(candidate) != expected_hash:
            raise RuntimeError(f"安装文件校验失败：{name}")
    required = {"install.ps1", "uninstall.ps1", "VERSION", "guardian.ico"}
    if not required.issubset(seen):
        raise RuntimeError("安装包必要载荷缺失。")
    return version


def build_install_command(root: Path, *, smoke_root: Path | None) -> list[str]:
    command = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(root / "install.ps1"),
        "-NoSuccessPopup",
    ]
    if smoke_root is not None:
        smoke_root = smoke_root.resolve()
        desktop = smoke_root / "desktop"
        desktop.mkdir(parents=True, exist_ok=True)
        command.extend(
            [
                "-NoLaunch",
                "-SkipRegistry",
                "-SkipScheduledTask",
                "-InstallBase",
                str(smoke_root / "install"),
                "-StartMenuDir",
                str(smoke_root / "start-menu"),
                "-DesktopShortcut",
                str(desktop / f"{PRODUCT}.lnk"),
            ]
        )
    return command


def write_result(path: Path | None, document: dict[str, object]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def run_install(command: list[str], log_path: Path) -> tuple[int, str]:
    started = time.time()
    completed = subprocess.run(
        command,
        cwd=payload_root(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=CREATE_NO_WINDOW,
    )
    output = completed.stdout or ""
    log_path.write_text(
        f"product={PRODUCT}\nstarted={started}\nexit_code={completed.returncode}\n{output}",
        encoding="utf-8",
    )
    return completed.returncode, output


def run_silent(args: argparse.Namespace) -> int:
    result_path = Path(args.result_file).resolve() if args.result_file else None
    try:
        root = payload_root()
        manifest = load_manifest(root)
        version = verify_payload(root, manifest)
        smoke_root = Path(args.smoke_root).resolve() if args.smoke_root else None
        log_path = Path(tempfile.gettempdir()) / f"CodexProfileGuardianSetup-v{version}.log"
        exit_code, _ = run_install(build_install_command(root, smoke_root=smoke_root), log_path)
        result = {
            "ok": exit_code == 0,
            "version": version,
            "exit_code": exit_code,
            "smoke_mode": smoke_root is not None,
            "log": str(log_path),
        }
        write_result(result_path, result)
        return 0 if result["ok"] else 1
    except Exception as exc:
        write_result(result_path, {"ok": False, "error": str(exc), "smoke_mode": bool(args.smoke_root)})
        return 1


def run_gui(args: argparse.Namespace) -> int:
    import tkinter as tk
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title(f"{PRODUCT} 安装程序")
    root.geometry("520x220")
    root.resizable(False, False)
    try:
        root.iconbitmap(str(payload_root() / "guardian.ico"))
    except Exception:
        pass

    frame = ttk.Frame(root, padding=28)
    frame.pack(fill="both", expand=True)
    title = ttk.Label(frame, text=f"正在安装 {PRODUCT}", font=("Microsoft YaHei UI", 15, "bold"))
    title.pack(anchor="w")
    status = ttk.Label(frame, text="正在校验完整安装文件，请稍候……", font=("Microsoft YaHei UI", 10))
    status.pack(anchor="w", pady=(16, 14))
    progress = ttk.Progressbar(frame, mode="indeterminate")
    progress.pack(fill="x")
    progress.start(12)
    root.protocol("WM_DELETE_WINDOW", lambda: None)

    state: dict[str, object] = {}
    result_path = Path(args.result_file).resolve() if args.result_file else None
    smoke_root = Path(args.smoke_root).resolve() if args.smoke_root else None

    def worker() -> None:
        try:
            payload = payload_root()
            manifest = load_manifest(payload)
            version = verify_payload(payload, manifest)
            state["version"] = version
            root.after(0, lambda: status.configure(text="正在安装程序文件并配置后台网关……"))
            log_path = Path(tempfile.gettempdir()) / f"CodexProfileGuardianSetup-v{version}.log"
            exit_code, output = run_install(build_install_command(payload, smoke_root=smoke_root), log_path)
            state.update(exit_code=exit_code, output=output, log=log_path)
        except Exception as exc:
            state.update(exit_code=1, output=str(exc), trace=traceback.format_exc())
        root.after(0, finish)

    def finish() -> None:
        progress.stop()
        exit_code = int(state.get("exit_code", 1))
        result = {
            "ok": exit_code == 0,
            "version": state.get("version", ""),
            "exit_code": exit_code,
            "smoke_mode": smoke_root is not None,
            "gui_started": True,
            "log": str(state.get("log", "")),
        }
        write_result(result_path, result)
        if exit_code == 0:
            status.configure(text=f"{PRODUCT} v{state.get('version', '')} 已安装完成。")
            root.update_idletasks()
            if args.auto_close:
                root.destroy()
                return
            messagebox.showinfo("安装完成", f"{PRODUCT} 已安装完成，桌面快捷方式已经创建。", parent=root)
            root.destroy()
            return
        status.configure(text="安装失败，原有版本已由事务安装程序保留或恢复。")
        output = str(state.get("output", "")).strip().splitlines()
        detail = output[-1] if output else "未知错误"
        log = state.get("log")
        suffix = f"\n\n日志：{log}" if log else ""
        if args.auto_close:
            root.destroy()
            return
        messagebox.showerror("安装失败", f"{detail}{suffix}", parent=root)
        root.protocol("WM_DELETE_WINDOW", root.destroy)

    threading.Thread(target=worker, daemon=True).start()
    root.mainloop()
    return 0 if int(state.get("exit_code", 1)) == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("--smoke-root")
    parser.add_argument("--result-file")
    parser.add_argument("--gui-smoke", action="store_true")
    parser.add_argument("--auto-close", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.smoke_root and not args.gui_smoke:
        args.silent = True
    return run_silent(args) if args.silent else run_gui(args)


if __name__ == "__main__":
    raise SystemExit(main())
