from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.guardian import GuardianService, atomic_write


service = GuardianService()
backup = service.create_backup("before-history-partition-restore")
state = service._load_state()
provider_by_profile = {profile["id"]: profile["provider_id"] for profile in state["profiles"]}

switches: list[tuple[int, str]] = []
for line in service.logs_path.read_text(encoding="utf-8").splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if event.get("action") != "profile.switch" or event.get("status") != "success":
        continue
    profile_id = (event.get("details") or {}).get("profile_id")
    if profile_id not in provider_by_profile:
        continue
    timestamp = dt.datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    switches.append((int(timestamp.timestamp() * 1000), provider_by_profile[profile_id]))
switches.sort()

db = service.codex_home / "state_5.sqlite"
connection = sqlite3.connect(str(db), timeout=10)
try:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(threads)")}
    rows = connection.execute(
        "SELECT id, rollout_path, created_at, created_at_ms, archived FROM threads"
    ).fetchall()
    archived_before = {row[0]: row[4] for row in rows}
    assignments: dict[str, str] = {}
    rollout_paths: dict[str, Path] = {}
    for thread_id, rollout_path, created_at, created_at_ms, _archived in rows:
        timestamp_ms = int(created_at_ms or 0)
        if not timestamp_ms:
            try:
                timestamp_ms = int(float(created_at) * 1000)
            except (TypeError, ValueError):
                timestamp_ms = 0
        provider = "openai"
        for switch_ms, switch_provider in switches:
            if switch_ms <= timestamp_ms:
                provider = switch_provider
            else:
                break
        assignments[thread_id] = provider
        if rollout_path:
            rollout_paths[thread_id] = Path(rollout_path)
    for thread_id, provider in assignments.items():
        connection.execute(
            "UPDATE threads SET model_provider=? WHERE id=?",
            (provider, thread_id),
        )
    archived_after = {
        row[0]: row[1] for row in connection.execute("SELECT id, archived FROM threads")
    }
    if archived_before != archived_after:
        raise RuntimeError("archive mapping changed")
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise RuntimeError(f"sqlite integrity failed: {integrity}")
    connection.commit()
finally:
    connection.close()

jsonl_changed = 0
jsonl_locked: list[str] = []
for thread_id, path in rollout_paths.items():
    if not path.is_file():
        continue
    output: list[str] = []
    changed = False
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            output.append(line)
            continue
        if item.get("type") == "session_meta" and isinstance(item.get("payload"), dict):
            if item["payload"].get("model_provider") != assignments[thread_id]:
                item["payload"]["model_provider"] = assignments[thread_id]
                line = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                changed = True
        output.append(line)
    if changed:
        try:
            atomic_write(path, ("\n".join(output) + "\n").encode("utf-8"))
            jsonl_changed += 1
        except PermissionError:
            jsonl_locked.append(str(path))

counts: dict[str, int] = {}
for provider in assignments.values():
    counts[provider] = counts.get(provider, 0) + 1
print(
    json.dumps(
        {
            "backup": backup["name"],
            "counts": counts,
            "jsonl_files_changed": jsonl_changed,
            "jsonl_locked": jsonl_locked,
            "integrity": integrity,
            "archived_count": sum(archived_before.values()),
        },
        ensure_ascii=False,
    )
)
