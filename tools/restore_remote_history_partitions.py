from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sqlite3
from pathlib import Path


home = Path.home() / ".codex"
baseline_db = (
    home / "guardian-backups" / "20260707-135205-provider-repair" / "state_5.sqlite"
)
stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S-history-partition-restore")
backup = home / "guardian-backups" / stamp
backup.mkdir(parents=True, exist_ok=False)
for name in ("state_5.sqlite", "session_index.jsonl"):
    source = home / name
    if source.exists():
        shutil.copy2(source, backup / name)


def thread_ids(path: Path) -> set[str]:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        return {row[0] for row in connection.execute("SELECT id FROM threads")}
    finally:
        connection.close()


official_ids = thread_ids(baseline_db)
connection = sqlite3.connect(str(home / "state_5.sqlite"), timeout=10)
try:
    rows = connection.execute(
        "SELECT id, rollout_path, archived FROM threads"
    ).fetchall()
    archived_before = {row[0]: row[2] for row in rows}
    assignments = {
        thread_id: ("openai" if thread_id in official_ids else "guardian_85bbf61de173")
        for thread_id, _rollout_path, _archived in rows
    }
    rollout_paths = {
        thread_id: Path(rollout_path)
        for thread_id, rollout_path, _archived in rows
        if rollout_path
    }
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
        temporary = path.with_name(path.name + ".guardian.tmp")
        temporary.write_text("\n".join(output) + "\n", encoding="utf-8")
        os.replace(temporary, path)
        jsonl_changed += 1

counts: dict[str, int] = {}
for provider in assignments.values():
    counts[provider] = counts.get(provider, 0) + 1
print(
    json.dumps(
        {
            "backup": backup.name,
            "counts": counts,
            "jsonl_files_changed": jsonl_changed,
            "integrity": integrity,
            "archived_count": sum(archived_before.values()),
        },
        ensure_ascii=False,
    ),
    flush=True,
)
