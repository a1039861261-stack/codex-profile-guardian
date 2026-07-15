from __future__ import annotations

import datetime as dt
import json
import shutil
import sqlite3
from pathlib import Path


def current_provider(home: Path) -> str:
    for line in (home / "config.toml").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("model_provider") and "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
    raise RuntimeError("remote config has no model_provider")


home = Path.home() / ".codex"
target = current_provider(home)
stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S-db-provider-repair")
backup = home / "guardian-backups" / stamp
backup.mkdir(parents=True, exist_ok=False)
for name in ("state_5.sqlite", "session_index.jsonl"):
    source = home / name
    if source.exists():
        shutil.copy2(source, backup / name)

connection = sqlite3.connect(str(home / "state_5.sqlite"), timeout=10)
try:
    before = dict(
        connection.execute(
            "SELECT model_provider, COUNT(1) FROM threads GROUP BY model_provider"
        ).fetchall()
    )
    archived_before = dict(connection.execute("SELECT id, archived FROM threads").fetchall())
    updated = connection.execute(
        "UPDATE threads SET model_provider=? WHERE model_provider IS NULL OR model_provider != ?",
        (target, target),
    ).rowcount
    archived_after = dict(connection.execute("SELECT id, archived FROM threads").fetchall())
    if archived_before != archived_after:
        raise RuntimeError("archive mapping changed")
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise RuntimeError(f"sqlite integrity failed: {integrity}")
    connection.commit()
    after = dict(
        connection.execute(
            "SELECT model_provider, COUNT(1) FROM threads GROUP BY model_provider"
        ).fetchall()
    )
finally:
    connection.close()
print(
    json.dumps(
        {
            "ok": True,
            "target": target,
            "backup": backup.name,
            "before": before,
            "updated": updated,
            "after": after,
            "integrity": integrity,
        },
        ensure_ascii=False,
    ),
    flush=True,
)
