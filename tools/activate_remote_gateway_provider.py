from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.guardian import GuardianService
from backend.remote_sync import discover_remote_hosts
from tools.remote_gateway_preflight import protected_snapshot


REMOTE_SCRIPT = r'''
import datetime, json, os, re, signal, stat, time, tomllib, uuid
from pathlib import Path

PROVIDER_ID = "guardian_gateway"
START = "# >>> Codex Profile Guardian Failover >>>"
END = "# <<< Codex Profile Guardian Failover <<<"
home = Path.home()
codex = home / ".codex"
config = codex / "config.toml"
token = home / ".config" / "codex-profile-guardian-gateway" / "tokens" / "ingress.token"
if token.is_symlink() or not token.is_file() or stat.S_IMODE(os.stat(token, follow_symlinks=False).st_mode) != 0o600:
    raise SystemExit(20)

payload = json.loads(__PAYLOAD__)
model = payload["model"]
if not isinstance(model, str) or not model or any(ord(ch) < 0x20 for ch in model):
    raise SystemExit(21)

active = []
for proc in Path("/proc").iterdir():
    if not proc.name.isdigit():
        continue
    try:
        args = [item.decode("utf-8", "replace") for item in (proc / "cmdline").read_bytes().split(b"\0") if item]
    except Exception:
        continue
    if "app-server" in args:
        active.append(int(proc.name))

current = config.read_bytes() if config.is_file() else b""
text = current.decode("utf-8-sig")
pattern = re.compile(re.escape(START) + r".*?" + re.escape(END) + r"\s*", re.S)
if text.count(START) != text.count(END) or text.count(START) > 1:
    raise SystemExit(22)
text = pattern.sub("", text)
lines = text.lstrip("\ufeff").splitlines()
first_table = next((index for index, line in enumerate(lines) if re.match(r"^\s*\[\[?[^]]+\]\]?\s*(?:#.*)?$", line)), len(lines))
root = lines[:first_table]
tables = lines[first_table:]
values = {"model_provider": PROVIDER_ID, "model": model}
written = set()
updated = []
for line in root:
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*=", line)
    key = match.group(1) if match else None
    if key not in values:
        updated.append(line)
        continue
    if key not in written:
        updated.append(key + " = " + json.dumps(values[key], ensure_ascii=False))
        written.add(key)
for key, value in values.items():
    if key not in written:
        updated.append(key + " = " + json.dumps(value, ensure_ascii=False))
if tables and updated and updated[-1].strip():
    updated.append("")
base = "\n".join(updated + tables).rstrip()
managed = [
    START,
    "[model_providers.guardian_gateway]",
    'name = "Guardian Gateway"',
    'base_url = "http://127.0.0.1:18766/v1"',
    'wire_api = "responses"',
    "request_max_retries = 0",
    "stream_max_retries = 0",
    "",
    "[model_providers.guardian_gateway.auth]",
    'command = "/bin/cat"',
    "args = [" + json.dumps(str(token)) + "]",
    "timeout_ms = 5000",
    "refresh_interval_ms = 0",
    END,
    "",
]
target = (base + "\n\n" + "\n".join(managed)).encode("utf-8")
document = tomllib.loads(target.decode("utf-8"))
provider = document.get("model_providers", {}).get(PROVIDER_ID, {})
auth = provider.get("auth", {})
if document.get("model_provider") != PROVIDER_ID or document.get("model") != model or provider.get("base_url") != "http://127.0.0.1:18766/v1" or provider.get("wire_api") != "responses" or provider.get("request_max_retries") != 0 or provider.get("stream_max_retries") != 0 or auth.get("command") != "/bin/cat" or auth.get("args") != [str(token)]:
    raise SystemExit(23)

backup_root = codex / "guardian-provider-activation"
backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(backup_root, 0o700)
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
backup = backup_root / (stamp + "-config-before.toml")
backup.write_bytes(current)
os.chmod(backup, 0o600)
temporary = config.parent / (".config.toml." + uuid.uuid4().hex + ".tmp")
descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(descriptor, "wb") as stream:
    stream.write(target)
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, config)
os.chmod(config, 0o600)
try:
    verified = tomllib.loads(config.read_text(encoding="utf-8"))
    if verified.get("model_provider") != PROVIDER_ID or verified.get("model") != model:
        raise RuntimeError
except Exception:
    config.write_bytes(current)
    os.chmod(config, 0o600)
    raise SystemExit(24)

for pid in active:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
deadline = time.time() + 10
remaining = list(active)
while remaining and time.time() < deadline:
    remaining = [pid for pid in remaining if Path("/proc", str(pid)).exists()]
    if remaining:
        time.sleep(0.2)
if remaining:
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    time.sleep(0.5)
if any(Path("/proc", str(pid)).exists() for pid in remaining):
    config.write_bytes(current)
    os.chmod(config, 0o600)
    raise SystemExit(25)
print(json.dumps({"ok": True, "provider": PROVIDER_ID, "model_set": True, "app_server_stopped": len(active), "backup_created": True}, separators=(",", ":")))
'''


def main() -> int:
    service = GuardianService(enable_failover_fixture=False)
    state = service._load_state()
    current = next(
        (
            item
            for item in state.get("profiles", [])
            if item.get("id") == state.get("current_profile") and item.get("type") == "api"
        ),
        None,
    )
    if current is None or not isinstance(current.get("model"), str):
        raise RuntimeError("remote_provider_current_api_invalid")
    hosts = discover_remote_hosts(service.codex_home / ".codex-global-state.json")
    if len(hosts) != 1:
        raise RuntimeError("remote_provider_host_count_invalid")
    host = hosts[0]
    before = protected_snapshot(host)
    if before["active_turn_count"] != 0 or before["sqlite_integrity"] != "ok":
        raise RuntimeError("remote_provider_protected_gate_failed")
    script = REMOTE_SCRIPT.replace(
        "__PAYLOAD__",
        repr(json.dumps({"model": current["model"]}, ensure_ascii=True, separators=(",", ":"))),
    )
    command = [
        "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
        "-o", "ClearAllForwardings=yes", "-p", str(host["port"]), str(host["target"]),
        "python3 - guardian-activate-gateway-provider-v1",
    ]
    completed = subprocess.run(
        command,
        input=script.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        creationflags=0x08000000 if sys.platform == "win32" else 0,
    )
    if completed.returncode != 0 or len(completed.stdout) > 4096:
        raise RuntimeError("remote_provider_activation_failed")
    result = json.loads(completed.stdout.decode("utf-8"))
    after = protected_snapshot(host)
    if (
        before["protected_digest"] != after["protected_digest"]
        or before["protected_file_count"] != after["protected_file_count"]
        or after["sqlite_integrity"] != "ok"
        or after["active_turn_count"] != 0
    ):
        raise RuntimeError("remote_provider_protected_state_changed")
    print(json.dumps({
        "ok": result.get("ok") is True,
        "provider": result.get("provider"),
        "model_set": result.get("model_set") is True,
        "app_server_stopped": result.get("app_server_stopped"),
        "protected_state_stable": True,
        "model_requests": 0,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
