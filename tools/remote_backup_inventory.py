from __future__ import annotations

import json
import sqlite3
from pathlib import Path


home = Path.home() / ".codex"
rows = []
for db in sorted((home / "guardian-backups").glob("*/state_5.sqlite")):
    try:
        connection = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            rows.append(
                {
                    "name": db.parent.name,
                    "total": connection.execute("SELECT COUNT(1) FROM threads").fetchone()[0],
                    "providers": dict(
                        connection.execute(
                            "SELECT model_provider, COUNT(1) FROM threads GROUP BY model_provider"
                        ).fetchall()
                    ),
                    "archived": dict(
                        connection.execute(
                            "SELECT archived, COUNT(1) FROM threads GROUP BY archived"
                        ).fetchall()
                    ),
                }
            )
        finally:
            connection.close()
    except Exception as exc:
        rows.append({"name": db.parent.name, "error": str(exc)})
print(json.dumps(rows, ensure_ascii=False, indent=2), flush=True)
