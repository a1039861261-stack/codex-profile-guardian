from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.guardian import GuardianService
from backend.remote_gateway import (
    NasCompatibilityEvaluator,
    NasEnvironmentInspector,
    NasInspectionRequest,
)
from backend.remote_sync import discover_remote_hosts


REMOTE_PROTECTED_STATE_SCRIPT = r'''
import hashlib, json, os, shutil, sqlite3, subprocess, sys, time
from pathlib import Path

home = Path.home() / ".codex"
roots = (home / "sessions", home / "archived_sessions")
fixed = (
    home / "state_5.sqlite",
    home / "state_5.sqlite-wal",
    home / "state_5.sqlite-shm",
    home / "session_index.jsonl",
)

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

files = []
for root in roots:
    if root.is_dir():
        files.extend(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
files.extend(path for path in fixed if path.is_file() and not path.is_symlink())
files = sorted(set(files), key=lambda path: str(path.relative_to(home)).replace("\\", "/"))
aggregate = hashlib.sha256()
for path in files:
    relative = str(path.relative_to(home)).replace("\\", "/").encode("utf-8")
    digest = sha256(path).encode("ascii")
    aggregate.update(len(relative).to_bytes(4, "big"))
    aggregate.update(relative)
    aggregate.update(digest)

integrity = "missing"
db = home / "state_5.sqlite"
rollouts = []
if db.is_file():
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        rollouts = [Path(row[0]) for row in connection.execute(
            "SELECT rollout_path FROM threads WHERE rollout_path IS NOT NULL"
        )]
    finally:
        connection.close()

active = 0
for path in rollouts:
    if not path.is_file() or time.time() - path.stat().st_mtime > 600:
        continue
    size = path.stat().st_size
    with path.open("rb") as source:
        source.seek(max(0, size - 8 * 1024 * 1024))
        tail = source.read()
    state = None
    for raw in reversed(tail.splitlines()):
        try:
            item = json.loads(raw)
        except Exception:
            continue
        body = item.get("payload") if isinstance(item, dict) else None
        kind = body.get("type") if isinstance(body, dict) else None
        if kind in {"task_started", "task_complete", "turn_aborted"}:
            state = kind
            break
    if state == "task_started":
        active += 1

sudo_noninteractive = False
if shutil.which("sudo"):
    try:
        sudo_noninteractive = subprocess.run(
            ["sudo", "-n", "true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).returncode == 0
    except Exception:
        sudo_noninteractive = False

user_manager_state = "unknown"
user_manager_result = "unknown"
user_manager_exit_status = -1
try:
    unit = f"user@{os.getuid()}.service"
    result = subprocess.run(
        ["systemctl", "show", unit, "--property=ActiveState,Result,ExecMainStatus"],
        stdin=subprocess.DEVNULL,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
    )
    fields = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value
    candidate = fields.get("ActiveState")
    if candidate in {"active", "inactive", "failed", "activating", "deactivating"}:
        user_manager_state = candidate
    candidate_result = fields.get("Result")
    if candidate_result and candidate_result.replace("-", "").isalnum():
        user_manager_result = candidate_result[:64]
    candidate_status = fields.get("ExecMainStatus")
    if candidate_status and candidate_status.isdecimal():
        user_manager_exit_status = int(candidate_status)
except Exception:
    pass
crontab_available = shutil.which("crontab") is not None
cron_service_active = False
try:
    cron_service_active = subprocess.run(
        ["systemctl", "is-active", "cron.service"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
    ).returncode == 0
except Exception:
    cron_service_active = False

print(json.dumps({
    "schema_version": 1,
    "active_turn_count": active,
    "protected_file_count": len(files),
    "protected_digest": aggregate.hexdigest(),
    "sqlite_integrity": integrity,
    "sudo_noninteractive": sudo_noninteractive,
    "user_manager_state": user_manager_state,
    "user_manager_result": user_manager_result,
    "user_manager_exit_status": user_manager_exit_status,
    "crontab_available": crontab_available,
    "cron_service_active": cron_service_active,
}, separators=(",", ":")))
'''


def protected_snapshot(host: dict[str, object]) -> dict[str, object]:
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
        "python3 - guardian-remote-protected-state-v1",
    ]
    completed = subprocess.run(
        command,
        input=REMOTE_PROTECTED_STATE_SCRIPT.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        creationflags=0x08000000 if sys.platform == "win32" else 0,
    )
    if completed.returncode != 0 or len(completed.stdout) > 4096:
        raise RuntimeError("remote_protected_snapshot_failed")
    try:
        document = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("remote_protected_snapshot_invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "schema_version",
            "active_turn_count",
            "protected_file_count",
            "protected_digest",
            "sqlite_integrity",
            "sudo_noninteractive",
            "user_manager_state",
            "user_manager_result",
            "user_manager_exit_status",
            "crontab_available",
            "cron_service_active",
        }
        or document.get("schema_version") != 1
        or type(document.get("active_turn_count")) is not int
        or type(document.get("protected_file_count")) is not int
        or not isinstance(document.get("protected_digest"), str)
        or len(document["protected_digest"]) != 64
        or any(character not in "0123456789abcdef" for character in document["protected_digest"])
        or document.get("sqlite_integrity") not in {"ok", "missing"}
        or type(document.get("sudo_noninteractive")) is not bool
        or document.get("user_manager_state")
        not in {"active", "inactive", "failed", "activating", "deactivating", "unknown"}
        or not isinstance(document.get("user_manager_result"), str)
        or len(document.get("user_manager_result")) > 64
        or type(document.get("user_manager_exit_status")) is not int
        or type(document.get("crontab_available")) is not bool
        or type(document.get("cron_service_active")) is not bool
    ):
        raise RuntimeError("remote_protected_snapshot_invalid")
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-home", default=str(Path.home() / ".codex"))
    parser.add_argument("--data-port", type=int, default=18766)
    parser.add_argument("--control-port", type=int, default=18767)
    args = parser.parse_args()
    hosts = discover_remote_hosts(Path(args.codex_home) / ".codex-global-state.json")
    if len(hosts) != 1:
        raise RuntimeError("remote_host_count_not_one")
    host = hosts[0]
    inspection = NasEnvironmentInspector().inspect(
        host,
        NasInspectionRequest(args.data_port, args.control_port),
    )
    environment = inspection.get("environment") if inspection.get("ok") else None
    decision = (
        NasCompatibilityEvaluator().evaluate(environment)
        if isinstance(environment, dict)
        else None
    )
    protected = protected_snapshot(host)
    public_environment = {}
    if isinstance(environment, dict):
        for key in (
            "architecture",
            "kernel_name",
            "os_id",
            "os_version",
            "python_command",
            "python_version",
            "glibc_version",
            "openssl_version",
            "supervisor",
            "data_port_state",
            "control_port_state",
            "disk_available_kib",
            "memory_available_kib",
        ):
            public_environment[key] = environment.get(key)
    print(
        json.dumps(
            {
                "ok": inspection.get("ok") is True,
                "read_only": True,
                "host_count": 1,
                "environment": public_environment,
                "compatibility": decision.as_public_document() if decision else None,
                "protected": protected,
                "snapshot_fingerprint": hashlib.sha256(
                    json.dumps(protected, sort_keys=True).encode("utf-8")
                ).hexdigest(),
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
