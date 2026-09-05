"""Graceful Windows desktop shutdown. Never terminate a process or a CLI tree."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import json
import os
import subprocess
import time
from typing import Callable


def desktop_process_filter() -> str:
    return (
        "(($_.Name -ieq 'ChatGPT.exe') -or ($_.Name -ieq 'Codex.exe')) -and ("
        "$_.ExecutablePath -match '\\\\WindowsApps\\\\OpenAI\\.Codex_[^\\\\]+\\\\app\\\\(ChatGPT|Codex)\\.exe$' -or "
        "$_.CommandLine -match '--remote-debugging-port=')"
    )


# Only identities and roles leave PowerShell. No command lines, titles or paths
# can reach an API response or the audit log. StartTime is the exact FILETIME;
# CIM CreationDate alone loses sub-microsecond precision on Windows.
PROCESS_QUERY_SCRIPT = r"""
$ErrorActionPreference='Stop'
try {
    $all=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.Name -ieq 'ChatGPT.exe' -or $_.Name -ieq 'codex.exe'
    })
    $runtime='^' + [regex]::Escape((Join-Path $env:LOCALAPPDATA 'OpenAI\Codex\bin')) + '\\[^\\]+\\codex\.exe$'
    $rows=@(foreach($item in $all) {
        if (-not $item.ExecutablePath) { throw 'identity_unavailable' }
        $desktop=@($item | Where-Object { __DESKTOP_FILTER__ }).Count -gt 0
        $packaged=$item.ExecutablePath -match '\\WindowsApps\\OpenAI\.Codex_[^\\]+\\app\\resources\\codex\.exe$'
        $server=$item.Name -ieq 'codex.exe' -and $item.CommandLine -match '(^|\s)app-server(\s|$)' -and ($packaged -or $item.ExecutablePath -match $runtime)
        if (-not $desktop -and -not $server) { continue }
        if (-not $item.CommandLine) { throw 'identity_unavailable' }
        $proc=Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        try {
            $started=$proc.StartTime.ToFileTimeUtc()
            if ([Math]::Abs($started - $item.CreationDate.ToFileTimeUtc()) -ge 10) { throw 'identity_changed' }
            $kind=if ($desktop) {
                if ($item.CommandLine -match '(^|\s)--type[=\s]') { 'desktop_child' } else { 'desktop' }
            } elseif ($packaged) { 'packaged_server' } else { 'runtime_server' }
            [ordered]@{ pid=[int]$item.ProcessId; parent_pid=[int]$item.ParentProcessId; started=$started; kind=$kind }
        } catch {
            # Disappearance during shutdown is normal, but an unreadable live
            # process or a reused PID must still fail closed.
            if (-not $proc.HasExited) { throw }
        } finally { $proc.Dispose() }
    })
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{version=1; processes=$rows} -Compress -Depth 4))
    exit 0
} catch { [Console]::Out.WriteLine('{"error":"process_query_failed"}'); exit 2 }
""".replace("__DESKTOP_FILTER__", desktop_process_filter())


@dataclass(frozen=True)
class CodexProcess:
    pid: int
    parent_pid: int
    started: int
    kind: str

    @property
    def identity(self) -> tuple[int, int]:
        return self.pid, self.started


def query_codex_processes() -> list[CodexProcess] | None:
    if os.name != "nt":
        return []
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", PROCESS_QUERY_SCRIPT],
            capture_output=True, text=True, timeout=5, creationflags=0x08000000,
        )
        if result.returncode != 0:
            return None
        payload = json.loads(result.stdout)
        if payload.get("version") != 1 or not isinstance(payload.get("processes"), list):
            return None
        processes = []
        for row in payload["processes"]:
            if (
                not isinstance(row, dict)
                or any(type(row.get(key)) is not int for key in ("pid", "parent_pid", "started"))
                or row["pid"] <= 0 or row["parent_pid"] < 0 or row["started"] <= 0
                or row.get("kind") not in {"desktop", "desktop_child", "packaged_server", "runtime_server"}
            ):
                return None
            processes.append(CodexProcess(row["pid"], row["parent_pid"], row["started"], row["kind"]))
        if len({p.pid for p in processes}) != len(processes):
            return None
        return processes
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError):
        return None


def related_processes(processes: list[CodexProcess]) -> list[CodexProcess]:
    """New shared-runtime CLIs require live desktop ancestry, not just a path."""
    by_pid = {p.pid: p for p in processes}
    related = []
    for process in processes:
        if process.kind != "runtime_server":
            related.append(process)
            continue
        child = process
        seen = {child.pid}
        while (parent := by_pid.get(child.parent_pid)) is not None:
            # Parent PIDs may have been reused. Never infer ownership backwards
            # in time or through a cyclic/inconsistent snapshot.
            if parent.pid in seen or parent.started > child.started:
                break
            if parent.kind == "desktop":
                related.append(process)
                break
            seen.add(parent.pid)
            child = parent
    return related


class WindowsWindowCloser:
    """Post WM_CLOSE only to verified desktop UI windows; do not touch children."""

    def __init__(self) -> None:
        self.sent: set[tuple[int, int, int]] = set()
        self.disabled_windows = False
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        signatures = (
            (self.kernel32.OpenProcess, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            (self.kernel32.CloseHandle, [wintypes.HANDLE], wintypes.BOOL),
            (self.kernel32.WaitForSingleObject, [wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            (self.kernel32.GetProcessTimes, [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4, wintypes.BOOL),
            (self.user32.EnumWindows, [self.callback_type, wintypes.LPARAM], wintypes.BOOL),
            (self.user32.GetWindowThreadProcessId, [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)], wintypes.DWORD),
            (self.user32.IsWindowVisible, [wintypes.HWND], wintypes.BOOL),
            (self.user32.IsWindowEnabled, [wintypes.HWND], wintypes.BOOL),
            (self.user32.GetWindow, [wintypes.HWND, wintypes.UINT], wintypes.HWND),
            (self.user32.PostMessageW, [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM], wintypes.BOOL),
        )
        for function, arguments, result in signatures:
            function.argtypes, function.restype = arguments, result

    def request(self, process: CodexProcess) -> None:
        if process.kind != "desktop":
            return
        # Query + synchronize only: no PROCESS_TERMINATE, injection or console
        # signals. The handle also binds validation to this process instance.
        handle = self.kernel32.OpenProcess(0x1000 | 0x100000, False, process.pid)
        if not handle:
            code = ctypes.get_last_error()
            if code == 87:  # Process already exited.
                return
            raise ctypes.WinError(code)
        try:
            created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
            if not self.kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
                raise ctypes.WinError(ctypes.get_last_error())
            if (created.dwHighDateTime << 32 | created.dwLowDateTime) != process.started:
                raise OSError(0, "process_identity_changed")
            failures = []

            @self.callback_type
            def visit(hwnd: int, _parameter: int) -> bool:
                owner_pid = wintypes.DWORD()
                self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
                if owner_pid.value != process.pid or not self.user32.IsWindowVisible(hwnd) or self.user32.GetWindow(hwnd, 4):
                    return True
                if not self.user32.IsWindowEnabled(hwnd):
                    self.disabled_windows = True
                    return True
                identity = (*process.identity, int(hwnd))
                if identity in self.sent:
                    return True
                state = self.kernel32.WaitForSingleObject(handle, 0)
                if state == 0:  # Exited during enumeration; never target a reused PID.
                    return True
                if state != 258:
                    failures.append(ctypes.get_last_error())
                    return False
                if not self.user32.PostMessageW(hwnd, 0x0010, 0, 0):
                    code = ctypes.get_last_error()
                    if code != 1400:  # A window can disappear during a normal close.
                        failures.append(code)
                else:
                    self.sent.add(identity)
                return True

            if not self.user32.EnumWindows(visit, 0) and not failures:
                failures.append(ctypes.get_last_error())
            if failures:
                raise ctypes.WinError(failures[0])
        finally:
            self.kernel32.CloseHandle(handle)


def close_codex_gracefully(
    timeout_seconds: float = 30,
    *,
    query: Callable[[], list[CodexProcess] | None] = query_codex_processes,
    observed: tuple[CodexProcess, ...] = (),
    closer: WindowsWindowCloser | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    started = clock()
    timeout_seconds = max(1.0, min(60.0, float(timeout_seconds)))
    deadline = started + timeout_seconds
    known = {p.identity for p in observed}
    initial_desktops = {p.identity for p in observed if p.kind == "desktop"} if observed else None
    remaining: list[CodexProcess] = []

    def report(ok: bool, reason: str, win32_error: int | None = None) -> dict:
        return {
            "ok": ok, "reason": reason, "wait_seconds": timeout_seconds,
            "elapsed_ms": round((clock() - started) * 1000),
            "requested_windows": len(closer.sent) if closer else 0,
            "remaining_count": len(remaining),
            "remaining": [{"pid": p.pid, "kind": p.kind} for p in remaining[:20]],
            "win32_error": win32_error,
        }

    while True:
        snapshot = query()
        if snapshot is None:
            return report(False, "process_query_failed")
        selected = related_processes(snapshot)
        known.update(p.identity for p in selected)
        # Keep already-observed children even after the desktop parent exits.
        # A later, independent CLI with a recycled PID is NOT the same child.
        remaining = [p for p in snapshot if p.identity in known]
        if not remaining:
            return report(True, "closed")
        desktops = {p.identity for p in remaining if p.kind == "desktop"}
        if initial_desktops is None:
            initial_desktops = desktops
        elif desktops - initial_desktops:
            return report(False, "desktop_restarted")
        if clock() >= deadline:
            reason = "exit_timeout" if closer and closer.sent else "window_disabled" if closer and closer.disabled_windows else "no_close_window"
            return report(False, reason)
        try:
            if closer is None:
                closer = WindowsWindowCloser()
            for process in remaining:
                if process.kind == "desktop":
                    closer.request(process)
        except OSError as exc:
            return report(False, "window_close_failed", getattr(exc, "winerror", None))
        sleep(min(0.4, max(0.0, deadline - clock())))
