from __future__ import annotations

import json
import sqlite3
from pathlib import Path


home = Path.home() / ".codex"
connection = sqlite3.connect(str(home / "state_5.sqlite"), timeout=5)
try:
    result = {
        "integrity": connection.execute("PRAGMA integrity_check").fetchone()[0],
        "providers": dict(
            connection.execute(
                "SELECT model_provider, COUNT(1) FROM threads GROUP BY model_provider"
            ).fetchall()
        ),
        "archived": dict(
            connection.execute("SELECT archived, COUNT(1) FROM threads GROUP BY archived").fetchall()
        ),
        "total": connection.execute("SELECT COUNT(1) FROM threads").fetchone()[0],
    }
finally:
    connection.close()
print(json.dumps(result, ensure_ascii=False), flush=True)
