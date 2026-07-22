from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib
from typing import Any


PORTABLE_TOP_LEVEL = (
    "model",
    "model_provider",
    "model_reasoning_effort",
    "service_tier",
    "disable_response_storage",
    "sandbox_mode",
    "personality",
)
PORTABLE_TABLES = ("features", "memories")


def portable_config(raw: bytes) -> dict[str, Any]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {"top": {}, "tables": {}}
    top = {
        key: value[key]
        for key in PORTABLE_TOP_LEVEL
        if key in value and isinstance(value[key], (str, bool, int, float, list))
    }
    tables: dict[str, dict[str, Any]] = {}
    for table_name in PORTABLE_TABLES:
        table = value.get(table_name)
        if not isinstance(table, dict):
            continue
        tables[table_name] = {
            key: item
            for key, item in table.items()
            if isinstance(item, (str, bool, int, float, list))
        }
    return {"top": top, "tables": tables}


def discover_remote_hosts(global_state_path: Path) -> list[dict[str, Any]]:
    try:
        state = json.loads(global_state_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    result = []
    seen = set()
    for item in state.get("codex-managed-remote-connections") or []:
        if not isinstance(item, dict):
            continue
        target = str(item.get("hostname") or item.get("alias") or "").strip()
        if not target or target in seen or not re.fullmatch(r"[A-Za-z0-9_.:@-]+", target):
            continue
        port = int(item.get("sshPort") or 22)
        if port < 1 or port > 65535:
            continue
        seen.add(target)
        result.append(
            {
                "target": target,
                "port": port,
                "display_name": str(item.get("displayName") or target)[:80],
                "host_id": str(item.get("hostId") or "")[:200],
            }
        )
    return result


def _auth_metadata(raw: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(raw)
        tokens = value.get("tokens") or {}
        identity = tokens.get("account_id")
        if not identity:
            token = str(tokens.get("access_token") or "")
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            identity = claims.get("chatgpt_account_id") or claims.get("sub")
        if not identity:
            return None
        refresh_key = tuple(int(item) for item in re.findall(r"\d+", str(value.get("last_refresh") or ""))[:7])
        return {
            "account_fingerprint": hashlib.sha256(str(identity).encode("utf-8")).hexdigest(),
            "refresh_order": refresh_key,
        }
    except (IndexError, ValueError, TypeError, json.JSONDecodeError):
        return None


_REMOTE_APPLY_SCRIPT = r'''
import base64, datetime, json, os, re, shutil, subprocess, sys, time
from pathlib import Path
try:
    import tomllib
except Exception:
    tomllib = None

def toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    raise ValueError("unsupported portable TOML value")

def table_header(line):
    match = re.match(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$", line)
    return match.group(1).strip() if match else None

def set_top_values(lines, values):
    first_table = next((i for i, line in enumerate(lines) if table_header(line)), len(lines))
    found = set()
    for index in range(first_table):
        match = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=", lines[index])
        if match and match.group(1) in values:
            key = match.group(1)
            lines[index] = f"{key} = {toml_value(values[key])}"
            found.add(key)
    missing = [f"{key} = {toml_value(value)}" for key, value in values.items() if key not in found]
    if missing:
        lines[first_table:first_table] = missing + ([""] if first_table < len(lines) else [])
    return lines

def remove_top_keys(lines, keys):
    first_table = next((i for i, line in enumerate(lines) if table_header(line)), len(lines))
    output = []
    for index, line in enumerate(lines):
        if index < first_table:
            match = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=", line)
            if match and match.group(1) in keys:
                continue
        output.append(line)
    return output

def set_table_values(lines, table_name, values):
    if not values:
        return lines
    start = next((i for i, line in enumerate(lines) if table_header(line) == table_name), None)
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"[{table_name}]")
        lines.extend(f"{key} = {toml_value(value)}" for key, value in values.items())
        return lines
    end = next((i for i in range(start + 1, len(lines)) if table_header(lines[i])), len(lines))
    found = set()
    for index in range(start + 1, end):
        match = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=", lines[index])
        if match and match.group(1) in values:
            key = match.group(1)
            lines[index] = f"{key} = {toml_value(values[key])}"
            found.add(key)
    missing = [f"{key} = {toml_value(value)}" for key, value in values.items() if key not in found]
    lines[end:end] = missing
    return lines

def atomic_write(path, data, mode=None):
    temp = path.with_name(path.name + ".guardian.tmp")
    temp.write_bytes(data)
    if mode is not None:
        os.chmod(temp, mode)
    os.replace(temp, path)

def app_server_processes():
    output = subprocess.run(
        "pgrep -af '[c]odex.*app-server' || true",
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=5,
    ).stdout
    return [line for line in output.splitlines() if line.strip()]

def stop_app_server():
    if os.name != "posix" or shutil.which("pgrep") is None or shutil.which("pkill") is None:
        return {"before": 0, "after": 0, "skipped": True}
    before = app_server_processes()
    after = before
    if before:
        subprocess.run(
            "pkill -TERM -f '[c]odex.*app-server' >/dev/null 2>&1 || true",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        time.sleep(0.7)
        after = app_server_processes()
    if after:
        subprocess.run(
            "pkill -KILL -f '[c]odex.*app-server' >/dev/null 2>&1 || true",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        time.sleep(0.3)
        after = app_server_processes()
    if after:
        raise RuntimeError("codex app-server could not be stopped")
    return {"before": len(before), "after": 0}

def ensure_no_recent_active_turn(home):
    db = home / "state_5.sqlite"
    if not db.is_file():
        return
    import sqlite3
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    try:
        paths = [Path(row[0]) for row in connection.execute("SELECT rollout_path FROM threads WHERE rollout_path IS NOT NULL")]
    finally:
        connection.close()
    busy = []
    for path in paths:
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
            busy.append(path.name)
    if busy:
        raise RuntimeError("SSH Codex still has an active turn; retry after it finishes: " + ", ".join(busy[:3]))

def repair_thread_provider(home, target_provider):
    db = home / "state_5.sqlite"
    if not target_provider or not db.is_file():
        return {"updated": 0, "integrity": "missing"}
    import sqlite3
    connection = sqlite3.connect(str(db), timeout=10)
    try:
        before = dict(connection.execute("SELECT id, archived FROM threads").fetchall())
        updated = connection.execute(
            "UPDATE threads SET model_provider=? WHERE model_provider IS NULL OR model_provider != ?",
            (target_provider, target_provider),
        ).rowcount
        after = dict(connection.execute("SELECT id, archived FROM threads").fetchall())
        if before != after:
            raise RuntimeError("archive mapping changed")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError("sqlite integrity failed: " + str(integrity))
        connection.commit()
        return {"updated": updated, "integrity": integrity}
    finally:
        connection.close()

payload = globals().get("_guardian_payload")
if payload is None:
    payload = json.load(sys.stdin)
home = Path.home() / ".codex"
home.mkdir(parents=True, exist_ok=True)
ensure_no_recent_active_turn(home)
app_server = stop_app_server()
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
backup = home / "guardian-backups" / stamp
backup.mkdir(parents=True, exist_ok=False)
auth_path = home / "auth.json"
config_path = home / "config.toml"
for source in (
    auth_path,
    config_path,
    home / "state_5.sqlite",
    home / "state_5.sqlite-wal",
    home / "state_5.sqlite-shm",
    home / "session_index.jsonl",
):
    if source.is_file():
        shutil.copy2(source, backup / source.name)

auth_bytes = base64.b64decode(payload["auth_b64"])
config_before = config_path.read_text(encoding="utf-8") if config_path.is_file() else ""
lines = config_before.splitlines()
lines = remove_top_keys(lines, {"preferred_auth_method"})
portable = payload.get("portable_config") or {}
top = portable.get("top") or {}
lines = set_top_values(lines, top)
if "model" not in top:
    lines = remove_top_keys(lines, {"model"})
for table_name, values in (portable.get("tables") or {}).items():
    lines = set_table_values(lines, table_name, values or {})
config_after = "\n".join(lines).rstrip() + "\n"
if tomllib is not None:
    tomllib.loads(config_after)
atomic_write(auth_path, auth_bytes, 0o600)
atomic_write(config_path, config_after.encode("utf-8"), 0o600)
print(json.dumps({"ok": True, "backup": backup.name, "config_bytes": len(config_after.encode("utf-8")), "app_server": app_server, "history": {"shared_history_reconcile_pending": True}}))
'''

_REMOTE_API_APPLY_SCRIPT = r'''
import base64, datetime, json, os, re, shutil, subprocess, sys, time
from pathlib import Path
try:
    import tomllib
except Exception:
    tomllib = None

MANAGED_START = "# BEGIN CODEX PROFILE GUARDIAN MANAGED"
MANAGED_END = "# END CODEX PROFILE GUARDIAN MANAGED"

def toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    raise ValueError("unsupported portable TOML value")

def table_header(line):
    match = re.match(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$", line)
    return match.group(1).strip() if match else None

def remove_managed_blocks(text):
    pattern = re.compile(re.escape(MANAGED_START) + r".*?" + re.escape(MANAGED_END) + r"\s*", re.S)
    return pattern.sub("", text).rstrip() + "\n" if text.strip() else ""

def set_top_values(lines, values):
    first_table = next((i for i, line in enumerate(lines) if table_header(line)), len(lines))
    found = set()
    for index in range(first_table):
        match = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=", lines[index])
        if match and match.group(1) in values:
            key = match.group(1)
            lines[index] = f"{key} = {toml_value(values[key])}"
            found.add(key)
    missing = [f"{key} = {toml_value(value)}" for key, value in values.items() if key not in found]
    if missing:
        lines[first_table:first_table] = missing + ([""] if first_table < len(lines) else [])
    return lines

def remove_top_keys(lines, keys):
    first_table = next((i for i, line in enumerate(lines) if table_header(line)), len(lines))
    output = []
    for index, line in enumerate(lines):
        if index < first_table:
            match = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=", line)
            if match and match.group(1) in keys:
                continue
        output.append(line)
    return output

def set_table_values(lines, table_name, values):
    if not values:
        return lines
    start = next((i for i, line in enumerate(lines) if table_header(line) == table_name), None)
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"[{table_name}]")
        lines.extend(f"{key} = {toml_value(value)}" for key, value in values.items())
        return lines
    end = next((i for i in range(start + 1, len(lines)) if table_header(lines[i])), len(lines))
    found = set()
    for index in range(start + 1, end):
        match = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=", lines[index])
        if match and match.group(1) in values:
            key = match.group(1)
            lines[index] = f"{key} = {toml_value(values[key])}"
            found.add(key)
    lines[end:end] = [f"{key} = {toml_value(value)}" for key, value in values.items() if key not in found]
    return lines

def atomic_write(path, data, mode=None):
    temp = path.with_name(path.name + ".guardian.tmp")
    temp.write_bytes(data)
    if mode is not None:
        os.chmod(temp, mode)
    os.replace(temp, path)

def app_server_processes():
    output = subprocess.run(
        "pgrep -af '[c]odex.*app-server' || true",
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=5,
    ).stdout
    return [line for line in output.splitlines() if line.strip()]

def stop_app_server():
    if os.name != "posix" or shutil.which("pgrep") is None or shutil.which("pkill") is None:
        return {"before": 0, "after": 0, "skipped": True}
    before = app_server_processes()
    after = before
    if before:
        subprocess.run(
            "pkill -TERM -f '[c]odex.*app-server' >/dev/null 2>&1 || true",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        time.sleep(0.7)
        after = app_server_processes()
    if after:
        subprocess.run(
            "pkill -KILL -f '[c]odex.*app-server' >/dev/null 2>&1 || true",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        time.sleep(0.3)
        after = app_server_processes()
    if after:
        raise RuntimeError("codex app-server could not be stopped")
    return {"before": len(before), "after": 0}

def ensure_no_recent_active_turn(home):
    db = home / "state_5.sqlite"
    if not db.is_file():
        return
    import sqlite3
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    try:
        paths = [Path(row[0]) for row in connection.execute("SELECT rollout_path FROM threads WHERE rollout_path IS NOT NULL")]
    finally:
        connection.close()
    busy = []
    for path in paths:
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
            busy.append(path.name)
    if busy:
        raise RuntimeError("SSH Codex still has an active turn; retry after it finishes: " + ", ".join(busy[:3]))

def repair_thread_provider(home, target_provider):
    db = home / "state_5.sqlite"
    if not target_provider or not db.is_file():
        return {"updated": 0, "integrity": "missing"}
    import sqlite3
    connection = sqlite3.connect(str(db), timeout=10)
    try:
        before = dict(connection.execute("SELECT id, archived FROM threads").fetchall())
        updated = connection.execute(
            "UPDATE threads SET model_provider=? WHERE model_provider IS NULL OR model_provider != ?",
            (target_provider, target_provider),
        ).rowcount
        after = dict(connection.execute("SELECT id, archived FROM threads").fetchall())
        if before != after:
            raise RuntimeError("archive mapping changed")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError("sqlite integrity failed: " + str(integrity))
        connection.commit()
        return {"updated": updated, "integrity": integrity}
    finally:
        connection.close()

payload = globals().get("_guardian_payload")
if payload is None:
    payload = json.load(sys.stdin)
provider = payload["provider"]
provider_id = provider["provider_id"]
if not re.fullmatch(r"[A-Za-z0-9_.-]+", provider_id):
    raise SystemExit("invalid provider id")

home = Path.home() / ".codex"
home.mkdir(parents=True, exist_ok=True)
ensure_no_recent_active_turn(home)
app_server = stop_app_server()
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
backup = home / "guardian-backups" / stamp
backup.mkdir(parents=True, exist_ok=False)
config_path = home / "config.toml"
if config_path.is_file():
    shutil.copy2(config_path, backup / "config.toml")
for source in (
    home / "state_5.sqlite",
    home / "state_5.sqlite-wal",
    home / "state_5.sqlite-shm",
    home / "session_index.jsonl",
):
    if source.is_file():
        shutil.copy2(source, backup / source.name)

api_dir = home / "guardian-api-profiles"
api_dir.mkdir(parents=True, exist_ok=True)
os.chmod(api_dir, 0o700)
key_path = api_dir / f"{provider_id}.key"
api_key = base64.b64decode(payload["api_key_b64"])
atomic_write(key_path, api_key, 0o600)

config_before = config_path.read_text(encoding="utf-8") if config_path.is_file() else ""
lines = remove_managed_blocks(config_before).splitlines()
lines = remove_top_keys(lines, {"preferred_auth_method"})
portable = payload.get("portable_config") or {}
top = dict(portable.get("top") or {})
top["model_provider"] = provider_id
model = str(provider.get("model") or "").strip()
if model:
    top["model"] = model
else:
    top.pop("model", None)
lines = set_top_values(lines, top)
if not model:
    lines = remove_top_keys(lines, {"model"})
for table_name, values in (portable.get("tables") or {}).items():
    lines = set_table_values(lines, table_name, values or {})
if lines and lines[-1].strip():
    lines.append("")
managed = [
    MANAGED_START,
    f"[model_providers.{provider_id}]",
    f"name = {toml_value(provider['name'])}",
    f"base_url = {toml_value(provider['base_url'])}",
    'wire_api = "responses"',
    "",
    f"[model_providers.{provider_id}.auth]",
    'command = "/bin/cat"',
    "args = [" + toml_value(str(key_path)) + "]",
    "timeout_ms = 5000",
    "refresh_interval_ms = 0",
    MANAGED_END,
]
config_after = "\n".join(lines + managed).rstrip() + "\n"
if tomllib is not None:
    tomllib.loads(config_after)
atomic_write(config_path, config_after.encode("utf-8"), 0o600)
print(json.dumps({
    "ok": True,
    "backup": backup.name,
    "config_bytes": len(config_after.encode("utf-8")),
    "provider_id": provider_id,
    "key_path": str(key_path),
    "app_server": app_server,
    "history": {"shared_history_reconcile_pending": True},
}))
'''


def _ssh_command(host: dict[str, Any], remote_command: str) -> list[str]:
    return [
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
        remote_command,
    ]


def _run_ssh(
    host: dict[str, Any],
    remote_command: str,
    *,
    retries: int = 3,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    last: subprocess.CompletedProcess[str] | None = None
    for attempt in range(max(1, retries)):
        last = subprocess.run(_ssh_command(host, remote_command), **kwargs)
        if last.returncode == 0:
            return last
        if attempt + 1 < retries:
            time.sleep(1.5 * (attempt + 1))
    assert last is not None
    return last


_REMOTE_RECONCILE_SCRIPT = r'''
import base64, datetime, hashlib, json, os, shutil, sqlite3, subprocess, time
from pathlib import Path
try:
    import tomllib
except Exception:
    tomllib = None

home = Path.home() / ".codex"
sessions_root = (home / "sessions").resolve()
archive_root = (home / "archived_sessions").resolve()
config_text = (home / "config.toml").read_text(encoding="utf-8-sig")
target = None
if tomllib is not None:
    try:
        target = str(tomllib.loads(config_text).get("model_provider") or "")
    except Exception:
        target = None
if not target:
    for line in config_text.splitlines():
        line = line.strip()
        if line.startswith("model_provider") and "=" in line:
            target = line.split("=", 1)[1].strip().strip('"')
            break
if not target:
    target = "openai"
db = home / "state_5.sqlite"
if not db.is_file():
    raise RuntimeError("state_5.sqlite missing")

def stop_app_server():
    if os.name != "posix" or shutil.which("pgrep") is None or shutil.which("pkill") is None:
        return {"before": 0, "after": 0, "skipped": True}
    before = subprocess.run(
        "pgrep -af '[c]odex.*app-server' || true", shell=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5,
    ).stdout.strip()
    if before:
        subprocess.run(
            "pkill -TERM -f '[c]odex.*app-server' >/dev/null 2>&1 || true",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        )
        time.sleep(0.5)
    after = subprocess.run(
        "pgrep -af '[c]odex.*app-server' || true", shell=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5,
    ).stdout.strip()
    if after:
        subprocess.run(
            "pkill -KILL -f '[c]odex.*app-server' >/dev/null 2>&1 || true",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        )
        time.sleep(0.2)
        after = subprocess.run(
            "pgrep -af '[c]odex.*app-server' || true", shell=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5,
        ).stdout.strip()
    result = {"before": len(before.splitlines()) if before else 0, "after": len(after.splitlines()) if after else 0}
    if result["after"]:
        raise RuntimeError("codex app-server could not be stopped")
    return result

def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()

def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def read_meta(path):
    with path.open("rb") as source:
        first = source.readline()
    try:
        item = json.loads(first.decode("utf-8-sig", errors="strict"))
    except Exception as exc:
        raise RuntimeError("invalid rollout first line: " + str(path)) from exc
    payload = item.get("payload") if isinstance(item, dict) else None
    if item.get("type") != "session_meta" or not isinstance(payload, dict) or not payload.get("id"):
        raise RuntimeError("invalid session_meta: " + str(path))
    return {"path": path.resolve(), "first": first, "item": item, "id": str(payload["id"]), "body_size": path.stat().st_size - len(first)}

def body_prefix(shorter, longer):
    if shorter["body_size"] > longer["body_size"]:
        return False
    with shorter["path"].open("rb") as left, longer["path"].open("rb") as right:
        left.readline(); right.readline()
        remaining = shorter["body_size"]
        while remaining:
            size = min(1024 * 1024, remaining)
            a = left.read(size); b = right.read(size)
            if a != b or not a:
                return False
            remaining -= len(a)
    return True

def body_guard(path):
    with path.open("rb") as source:
        first = source.readline()
        body_size = path.stat().st_size - len(first)
        head = source.read(min(65536, body_size))
        if body_size > 65536:
            source.seek(max(len(first), path.stat().st_size - 65536))
            tail = source.read(65536)
        else:
            tail = head
    return body_size, sha256_bytes(head), sha256_bytes(tail)

def body_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        source.readline()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def replace_first_line(path, raw):
    temp = path.with_name(path.name + ".guardian-restore.tmp")
    with path.open("rb") as source, temp.open("wb") as target_file:
        source.readline(); target_file.write(raw); shutil.copyfileobj(source, target_file, length=1024 * 1024)
        target_file.flush(); os.fsync(target_file.fileno())
    os.replace(temp, path)

def patch_provider(path, target_provider):
    stat = path.stat()
    before_guard = body_guard(path)
    with path.open("rb") as source:
        first = source.readline()
    item = json.loads(first.decode("utf-8-sig", errors="strict"))
    payload = item["payload"]
    if payload.get("model_provider") == target_provider:
        return {"changed": False, "mode": "unchanged", "first": first}
    payload["model_provider"] = target_provider
    had_newline = first.endswith(b"\n")
    capacity = len(first) - (1 if had_newline else 0)
    encoded = json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= capacity:
        output = encoded + (b" " * (capacity - len(encoded))) + (b"\n" if had_newline else b"")
        with path.open("r+b") as target_file:
            target_file.seek(0); target_file.write(output); target_file.flush(); os.fsync(target_file.fileno())
        mode = "in_place"
    else:
        before_hash = body_hash(path)
        temp = path.with_name(path.name + ".guardian.tmp")
        with path.open("rb") as source, temp.open("wb") as target_file:
            source.readline(); target_file.write(encoded + b"\n"); shutil.copyfileobj(source, target_file, length=1024 * 1024)
            target_file.flush(); os.fsync(target_file.fileno())
        os.replace(temp, path)
        if body_hash(path) != before_hash:
            raise RuntimeError("rollout body changed during stream rewrite: " + str(path))
        mode = "stream"
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    if body_guard(path) != before_guard:
        raise RuntimeError("rollout body guard changed: " + str(path))
    return {"changed": True, "mode": mode, "first": first}

def under(path, root):
    return path == root or root in path.parents

app_server = stop_app_server()
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
backup = home / "guardian-backups" / (stamp + "-shared-history-reconcile")
backup.mkdir(parents=True, exist_ok=False)
for name in ("state_5.sqlite", "state_5.sqlite-wal", "state_5.sqlite-shm", "session_index.jsonl"):
    source = home / name
    if source.is_file():
        shutil.copy2(source, backup / name)

connection = sqlite3.connect(str(db), timeout=15)
connection.execute("PRAGMA busy_timeout=15000")
moves = []
patched = []
committed = False
try:
    rows = list(connection.execute("SELECT id, archived, rollout_path, model_provider FROM threads").fetchall())
    baseline = {str(row[0]): {"archived": int(row[1] or 0), "path": str(Path(row[2]).resolve()), "provider": row[3]} for row in rows}
    if len(baseline) != len(rows):
        raise RuntimeError("duplicate thread id in sqlite")
    physical = sorted(
        set((home / "sessions").rglob("*.jsonl")) | set((home / "archived_sessions").rglob("*.jsonl")),
        key=lambda item: str(item),
    )
    groups = {}
    for path in physical:
        info = read_meta(path)
        groups.setdefault(info["id"], []).append(info)
    if set(groups) != set(baseline):
        missing = sorted(set(baseline) - set(groups))
        orphan = sorted(set(groups) - set(baseline))
        raise RuntimeError("rollout/sqlite id mismatch missing=%s orphan=%s" % (missing[:5], orphan[:5]))

    index_path = home / "session_index.jsonl"
    index_bytes = index_path.read_bytes() if index_path.is_file() else None
    index_rows = 0
    if index_bytes is not None:
        for raw in index_bytes.splitlines():
            if not raw.strip():
                continue
            index_rows += 1
            item = json.loads(raw.decode("utf-8-sig"))
            item_id = str(item.get("id") or "")
            if item_id not in baseline or baseline[item_id]["archived"]:
                raise RuntimeError("session_index contains missing or archived thread: " + item_id)

    plans = {}
    duplicate_threads = 0
    for thread_id, candidates in groups.items():
        row = baseline[thread_id]
        current = next((item for item in candidates if str(item["path"]) == row["path"]), None)
        supersets = [item for item in candidates if all(body_prefix(other, item) for other in candidates)]
        if not supersets:
            raise RuntimeError("divergent duplicate rollout bodies: " + thread_id)
        if current in supersets:
            canonical = current
        else:
            matching = [item for item in supersets if under(item["path"], archive_root) == bool(row["archived"])]
            canonical = sorted(matching or supersets, key=lambda item: (-item["body_size"], str(item["path"])))[0]
        if len(candidates) > 1:
            duplicate_threads += 1
        desired_archived = bool(row["archived"])
        if under(canonical["path"], archive_root) == desired_archived:
            destination = canonical["path"]
        else:
            current_path = Path(row["path"])
            correct_current_root = under(current_path, archive_root) == desired_archived
            if correct_current_root:
                destination = current_path
            else:
                destination = (archive_root if desired_archived else sessions_root / "guardian-recovered") / canonical["path"].name
        plans[thread_id] = {"canonical": canonical, "destination": destination, "losers": [item for item in candidates if item is not canonical]}

    quarantine = home / "guardian-quarantine" / stamp
    manifest = []
    for thread_id, plan in plans.items():
        for loser in plan["losers"]:
            relative = loser["path"].relative_to(home.resolve())
            destination = quarantine / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise RuntimeError("quarantine collision: " + str(destination))
            os.replace(loser["path"], destination)
            moves.append((loser["path"], destination))
            manifest.append({"id": thread_id, "original": str(loser["path"]), "quarantine": str(destination), "size": destination.stat().st_size, "sha256": file_sha256(destination)})
        canonical_path = plan["canonical"]["path"]
        destination = plan["destination"]
        if canonical_path != destination:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise RuntimeError("canonical destination still occupied: " + str(destination))
            os.replace(canonical_path, destination)
            moves.append((canonical_path, destination))
        plan["final"] = destination

    first_line_backup = backup / "session-meta-first-lines.jsonl"
    meta_changed = 0
    meta_stream_rewrites = 0
    with first_line_backup.open("w", encoding="utf-8") as handle:
        for thread_id, plan in plans.items():
            path = plan["final"]
            with path.open("rb") as source:
                first = source.readline()
            handle.write(json.dumps({"id": thread_id, "archived": baseline[thread_id]["archived"], "path": str(path), "first_line_b64": base64.b64encode(first).decode("ascii")}, ensure_ascii=False, separators=(",", ":")) + "\n")
            patched.append((path, first))
            patch = patch_provider(path, target)
            if patch["changed"]:
                meta_changed += 1
                if patch["mode"] == "stream":
                    meta_stream_rewrites += 1

    connection.execute("BEGIN IMMEDIATE")
    archived_before = dict(connection.execute("SELECT id, archived FROM threads").fetchall())
    updated = 0
    for thread_id, plan in plans.items():
        updated += connection.execute(
            "UPDATE threads SET model_provider=?, rollout_path=? WHERE id=? AND (model_provider IS NULL OR model_provider<>? OR rollout_path<>?)",
            (target, str(plan["final"]), thread_id, target, str(plan["final"])),
        ).rowcount
    archived_after = dict(connection.execute("SELECT id, archived FROM threads").fetchall())
    if archived_before != archived_after:
        raise RuntimeError("archive mapping changed")
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise RuntimeError("sqlite integrity failed: " + str(integrity))
    connection.commit()
    committed = True

    verified_groups = {}
    for path in sorted(set((home / "sessions").rglob("*.jsonl")) | set((home / "archived_sessions").rglob("*.jsonl")), key=lambda item: str(item)):
        info = read_meta(path)
        verified_groups.setdefault(info["id"], []).append(info)
    if set(verified_groups) != set(baseline) or any(len(items) != 1 for items in verified_groups.values()):
        raise RuntimeError("rollout uniqueness verification failed")
    for thread_id, items in verified_groups.items():
        info = items[0]
        if str(info["path"]) != str(plans[thread_id]["final"]):
            raise RuntimeError("rollout path verification failed: " + thread_id)
        if info["item"]["payload"].get("model_provider") != target:
            raise RuntimeError("rollout provider verification failed: " + thread_id)
    if index_bytes is not None and index_path.read_bytes() != index_bytes:
        raise RuntimeError("session_index changed")
    if manifest:
        quarantine.mkdir(parents=True, exist_ok=True)
        (quarantine / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result = {
        "target": target,
        "updated": updated,
        "rollout_files_updated": meta_changed,
        "rollout_stream_rewrites": meta_stream_rewrites,
        "memory_mode_removed": 0,
        "rollout_files_skipped": 0,
        "duplicate_thread_count": duplicate_threads,
        "duplicate_files_quarantined": len(manifest),
        "duplicate_conflicts": 0,
        "index_rows": index_rows,
        "index_preserved": index_bytes is not None,
        "index_sha256": sha256_bytes(index_bytes) if index_bytes is not None else None,
        "archived_count": sum(int(value) for value in archived_before.values()),
        "active_count": len(archived_before) - sum(int(value) for value in archived_before.values()),
        "archive_preserved": True,
        "shared_history_preserved": True,
        "integrity": integrity,
        "backup": backup.name,
        "app_server": app_server,
        "paths": {thread_id: str(plan["final"]) for thread_id, plan in plans.items()},
        "archives": {thread_id: baseline[thread_id]["archived"] for thread_id in sorted(baseline)},
    }
except Exception:
    if committed:
        try:
            connection.execute("BEGIN IMMEDIATE")
            for thread_id, original in baseline.items():
                connection.execute(
                    "UPDATE threads SET model_provider=?, rollout_path=? WHERE id=?",
                    (original.get("provider"), original["path"], thread_id),
                )
            connection.commit()
        except Exception:
            connection.rollback()
    else:
        connection.rollback()
    for path, first in reversed(patched):
        if path.is_file():
            replace_first_line(path, first)
    for original, moved in reversed(moves):
        if moved.exists() and not original.exists():
            original.parent.mkdir(parents=True, exist_ok=True)
            os.replace(moved, original)
    raise
finally:
    connection.close()
print(json.dumps(result, ensure_ascii=False))
'''


_REMOTE_VERIFY_SCRIPT = r'''
import hashlib, json, sqlite3, time
from pathlib import Path

payload = globals().get("_guardian_payload")
if payload is None:
    payload = json.load(__import__("sys").stdin)
time.sleep(1.2)
home = Path.home() / ".codex"
db = home / "state_5.sqlite"
expected_archives = {str(key): int(value) for key, value in (payload.get("archives") or {}).items()}
expected_paths = {str(key): str(value) for key, value in (payload.get("paths") or {}).items()}
target = str(payload.get("target") or "")
if not db.is_file() or not target:
    raise RuntimeError("post-sync verification inputs missing")

def first_meta(path):
    with path.open("rb") as source:
        raw = source.readline()
    item = json.loads(raw.decode("utf-8-sig"))
    body = item.get("payload") if isinstance(item, dict) else None
    if item.get("type") != "session_meta" or not isinstance(body, dict) or not body.get("id"):
        raise RuntimeError("invalid session meta: " + str(path))
    return str(body["id"]), str(body.get("model_provider") or "")

connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=15)
connection.execute("PRAGMA busy_timeout=15000")
try:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    rows = list(connection.execute("SELECT id, archived, rollout_path, model_provider FROM threads"))
finally:
    connection.close()
if integrity != "ok":
    raise RuntimeError("post-sync sqlite integrity failed: " + str(integrity))
actual_archives = {str(row[0]): int(row[1] or 0) for row in rows}
actual_paths = {str(row[0]): str(Path(row[2]).resolve()) for row in rows}
if actual_archives != expected_archives:
    raise RuntimeError("post-sync archive mapping changed")
if actual_paths != {key: str(Path(value).resolve()) for key, value in expected_paths.items()}:
    raise RuntimeError("post-sync rollout paths changed")
if any(str(row[3] or "") != target for row in rows):
    raise RuntimeError("post-sync database provider mismatch")

physical = {}
for path in sorted(set((home / "sessions").rglob("*.jsonl")) | set((home / "archived_sessions").rglob("*.jsonl")), key=lambda item: str(item)):
    thread_id, provider = first_meta(path)
    physical.setdefault(thread_id, []).append((str(path.resolve()), provider))
if set(physical) != set(actual_archives) or any(len(items) != 1 for items in physical.values()):
    raise RuntimeError("post-sync rollout uniqueness changed")
for thread_id, items in physical.items():
    if items[0][0] != actual_paths[thread_id] or items[0][1] != target:
        raise RuntimeError("post-sync rollout metadata changed: " + thread_id)

index = home / "session_index.jsonl"
index_hash = None
if index.is_file():
    raw = index.read_bytes()
    index_hash = hashlib.sha256(raw).hexdigest()
if index_hash != payload.get("index_sha256"):
    raise RuntimeError("post-sync session_index changed")
print(json.dumps({"ok": True, "post_restart_verified": True, "thread_count": len(rows), "active_count": sum(1 for value in actual_archives.values() if not value), "archived_count": sum(actual_archives.values()), "index_sha256": index_hash}, ensure_ascii=False))
'''


def _script_with_payload(script: str, payload: str) -> str:
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    return (
        "import base64, json\n"
        f"_guardian_payload = json.loads(base64.b64decode({encoded!r}))\n"
        + script
    )


def _combined_apply_script(apply_script: str, payload: str) -> str:
    """Send the transaction through encrypted SSH stdin.

    Keeping the script and payload out of argv avoids Windows' command-length
    limit and keeps API credentials out of remote process listings.
    """
    return _script_with_payload(
        apply_script + "\n" + _REMOTE_RECONCILE_SCRIPT,
        payload,
    )


def _verify_remote_script(payload: str) -> str:
    return _script_with_payload(_REMOTE_VERIFY_SCRIPT, payload)


def _restart_and_reconcile_command() -> str:
    # Kept for compatibility with older callers; new syncs use one combined
    # apply/reconcile process plus a read-only post-restart audit.
    return "python3 -"


def sync_official_to_remotes(
    auth_bytes: bytes,
    config_bytes: bytes,
    global_state_path: Path,
) -> tuple[dict[str, Any], bytes]:
    hosts = discover_remote_hosts(global_state_path)
    if not hosts:
        return {"host_count": 0, "success_count": 0, "results": []}, auth_bytes
    flags = 0x08000000 if os.name == "nt" else 0
    authority = auth_bytes
    authority_meta = _auth_metadata(authority)
    read_command = (
        "python3 -c \"import base64,pathlib; p=pathlib.Path.home()/'.codex'/'auth.json'; "
        "print(base64.b64encode(p.read_bytes()).decode('ascii') if p.is_file() else '')\""
    )
    for host in hosts:
        try:
            fetched = _run_ssh(
                host,
                read_command,
                capture_output=True,
                text=True,
                timeout=12,
                creationflags=flags,
            )
            if fetched.returncode != 0:
                continue
            candidate = base64.b64decode((fetched.stdout or "").strip(), validate=True)
            candidate_meta = _auth_metadata(candidate)
            if (
                authority_meta
                and candidate_meta
                and candidate_meta["account_fingerprint"] == authority_meta["account_fingerprint"]
                and candidate_meta["refresh_order"] > authority_meta["refresh_order"]
            ):
                authority = candidate
                authority_meta = candidate_meta
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
    payload = json.dumps(
        {
            "auth_b64": base64.b64encode(authority).decode("ascii"),
            "portable_config": portable_config(config_bytes),
        },
        ensure_ascii=False,
    )
    transaction_script = _combined_apply_script(_REMOTE_APPLY_SCRIPT, payload)
    results = []
    for host in hosts:
        public = {key: host[key] for key in ("display_name", "host_id")}
        try:
            applied = _run_ssh(
                host,
                "python3 -",
                input=transaction_script,
                capture_output=True,
                text=True,
                timeout=90,
                creationflags=flags,
            )
            if applied.returncode != 0:
                raise RuntimeError((applied.stderr or "SSH 同步失败").strip().splitlines()[-1])
            output_lines = [line for line in (applied.stdout or "").splitlines() if line.strip()]
            if len(output_lines) < 2:
                raise RuntimeError("远端未返回配置与历史双重确认")
            response = json.loads(output_lines[-2])
            history = json.loads(output_lines[-1])
            if not response.get("ok"):
                raise RuntimeError("远端没有确认写入成功")
            if not history.get("shared_history_preserved"):
                raise RuntimeError("远端聊天保护校验未通过")
            verification_payload = json.dumps(
                {
                    "target": history.get("target"),
                    "archives": history.get("archives"),
                    "paths": history.get("paths"),
                    "index_sha256": history.get("index_sha256"),
                },
                ensure_ascii=False,
            )
            verified = _run_ssh(
                host,
                "python3 -",
                input=_verify_remote_script(verification_payload),
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=flags,
            )
            post_restart = None
            if verified.returncode == 0 and (verified.stdout or "").strip():
                post_restart = json.loads(verified.stdout.strip().splitlines()[-1])
            if verified.returncode != 0 or not post_restart or not post_restart.get("post_restart_verified"):
                raise RuntimeError((verified.stderr or "SSH 重启后聊天校验失败").strip().splitlines()[-1])
            results.append(
                {
                    **public,
                    "ok": True,
                    "backup": response.get("backup"),
                    "config_bytes": response.get("config_bytes"),
                    "history": history,
                    "post_restart": post_restart,
                }
            )
        except Exception as exc:
            results.append({**public, "ok": False, "error": str(exc)[:240]})
    return {
        "host_count": len(hosts),
        "success_count": sum(1 for item in results if item.get("ok")),
        "results": results,
        "synced_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }, authority


def sync_api_profile_to_remotes(
    profile: dict[str, Any],
    api_key: bytes,
    config_bytes: bytes,
    global_state_path: Path,
) -> dict[str, Any]:
    hosts = discover_remote_hosts(global_state_path)
    if not hosts:
        return {"host_count": 0, "success_count": 0, "results": []}
    payload = json.dumps(
        {
            "provider": {
                "provider_id": str(profile["provider_id"]),
                "name": str(profile["name"]),
                "base_url": str(profile["base_url"]),
                "model": str(profile["model"]),
            },
            "api_key_b64": base64.b64encode(api_key).decode("ascii"),
            "portable_config": portable_config(config_bytes),
        },
        ensure_ascii=False,
    )
    transaction_script = _combined_apply_script(_REMOTE_API_APPLY_SCRIPT, payload)
    flags = 0x08000000 if os.name == "nt" else 0
    results = []
    for host in hosts:
        public = {key: host[key] for key in ("display_name", "host_id")}
        try:
            applied = _run_ssh(
                host,
                "python3 -",
                input=transaction_script,
                capture_output=True,
                text=True,
                timeout=90,
                creationflags=flags,
            )
            if applied.returncode != 0:
                raise RuntimeError((applied.stderr or "SSH API 同步失败").strip().splitlines()[-1])
            output_lines = [line for line in (applied.stdout or "").splitlines() if line.strip()]
            if len(output_lines) < 2:
                raise RuntimeError("远端未返回 API 配置与历史双重确认")
            response = json.loads(output_lines[-2])
            history = json.loads(output_lines[-1])
            if not response.get("ok"):
                raise RuntimeError("远端没有确认 API 配置写入成功")
            if not history.get("shared_history_preserved"):
                raise RuntimeError("远端聊天保护校验未通过")
            verification_payload = json.dumps(
                {
                    "target": history.get("target"),
                    "archives": history.get("archives"),
                    "paths": history.get("paths"),
                    "index_sha256": history.get("index_sha256"),
                },
                ensure_ascii=False,
            )
            verified = _run_ssh(
                host,
                "python3 -",
                input=_verify_remote_script(verification_payload),
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=flags,
            )
            post_restart = None
            if verified.returncode == 0 and (verified.stdout or "").strip():
                post_restart = json.loads(verified.stdout.strip().splitlines()[-1])
            if verified.returncode != 0 or not post_restart or not post_restart.get("post_restart_verified"):
                raise RuntimeError((verified.stderr or "SSH 重启后聊天校验失败").strip().splitlines()[-1])
            results.append(
                {
                    **public,
                    "ok": True,
                    "backup": response.get("backup"),
                    "config_bytes": response.get("config_bytes"),
                    "provider_id": response.get("provider_id"),
                    "key_path": response.get("key_path"),
                    "history": history,
                    "post_restart": post_restart,
                }
            )
        except Exception as exc:
            results.append({**public, "ok": False, "error": str(exc)[:240]})
    return {
        "host_count": len(hosts),
        "success_count": sum(1 for item in results if item.get("ok")),
        "results": results,
        "synced_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "kind": "api",
    }
