from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.remote_sync import discover_remote_hosts


REMOTE_ENABLE_SCRIPT = r'''
import json, os, subprocess, time

uid = os.getuid()
user = subprocess.run(
    ["id", "-un"], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5
).stdout.strip()
enabled = subprocess.run(
    ["loginctl", "enable-linger", user],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    timeout=10,
).returncode == 0
runtime = f"/run/user/{uid}"
ready = False
if enabled:
    environment = os.environ.copy()
    environment["XDG_RUNTIME_DIR"] = runtime
    environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={runtime}/bus"
    for _ in range(20):
        try:
            ready = subprocess.run(
                ["systemctl", "--user", "show-environment"],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).returncode == 0
        except Exception:
            ready = False
        if ready:
            break
        time.sleep(0.25)
print(json.dumps({"schema_version":1,"linger_enabled":enabled,"systemd_user_ready":ready}, separators=(",", ":")))
'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-home", default=str(Path.home() / ".codex"))
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args()
    if not args.confirm:
        raise RuntimeError("remote_supervisor_confirmation_required")
    hosts = discover_remote_hosts(Path(args.codex_home) / ".codex-global-state.json")
    if len(hosts) != 1:
        raise RuntimeError("remote_host_count_not_one")
    host = hosts[0]
    command = [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ClearAllForwardings=yes",
        "-p",
        str(host["port"]),
        str(host["target"]),
        "python3 - guardian-enable-user-supervisor-v1",
    ]
    completed = subprocess.run(
        command,
        input=REMOTE_ENABLE_SCRIPT.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        creationflags=0x08000000 if sys.platform == "win32" else 0,
    )
    if completed.returncode != 0 or len(completed.stdout) > 4096:
        raise RuntimeError("remote_supervisor_enable_failed")
    try:
        document = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("remote_supervisor_receipt_invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "linger_enabled", "systemd_user_ready"}
        or document.get("schema_version") != 1
        or type(document.get("linger_enabled")) is not bool
        or type(document.get("systemd_user_ready")) is not bool
    ):
        raise RuntimeError("remote_supervisor_receipt_invalid")
    print(json.dumps(document, separators=(",", ":")))
    return 0 if document["linger_enabled"] and document["systemd_user_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
