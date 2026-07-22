from __future__ import annotations

import os
import signal
import subprocess


current_pid = os.getpid()
output = subprocess.check_output(["ps", "-eo", "pid=,args="], text=True)
killed: list[int] = []
for line in output.splitlines():
    line = line.strip()
    if not line:
        continue
    pid_text, _, args = line.partition(" ")
    try:
        pid = int(pid_text)
    except ValueError:
        continue
    if pid == current_pid:
        continue
    if "codex app-server" in args:
        try:
            os.kill(pid, signal.SIGTERM)
            killed.append(pid)
        except ProcessLookupError:
            pass
print({"killed": killed}, flush=True)
