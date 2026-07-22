from __future__ import annotations

import json
import sqlite3
from pathlib import Path


home = Path.home() / ".codex"
baseline = home / "guardian-backups" / "20260707-135205-provider-repair" / "state_5.sqlite"


def rows(path: Path) -> dict[str, dict]:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        return {
            row[0]: {
                "created_at": row[1],
                "created_at_ms": row[2],
                "provider": row[3],
                "archived": row[4],
            }
            for row in connection.execute(
                "SELECT id, created_at, created_at_ms, model_provider, archived FROM threads"
            )
        }
    finally:
        connection.close()


before = rows(baseline)
current = rows(home / "state_5.sqlite")
print(
    json.dumps(
        {
            "baseline_count": len(before),
            "current_count": len(current),
            "new_after_baseline": [
                {"id": thread_id, **current[thread_id]}
                for thread_id in sorted(set(current) - set(before))
            ],
            "missing_from_current": sorted(set(before) - set(current)),
        },
        ensure_ascii=False,
        indent=2,
    ),
    flush=True,
)
