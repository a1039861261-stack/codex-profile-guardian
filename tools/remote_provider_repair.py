from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path


def current_provider(home: Path) -> str:
    for line in (home / "config.toml").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("model_provider") and "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
    raise RuntimeError("remote config has no model_provider")


def rewrite_session_file(path: Path, target: str) -> bool:
    changed = False
    output: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return False
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            output.append(line)
            continue
        if item.get("type") == "session_meta" and isinstance(item.get("payload"), dict):
            if item["payload"].get("model_provider") != target:
                item["payload"]["model_provider"] = target
                line = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                changed = True
        output.append(line)
    if changed:
        temporary = path.with_name(path.name + ".guardian.tmp")
        temporary.write_text("\n".join(output) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    return changed


def replace_model_provider(value, target: str) -> bool:
    changed = False
    if isinstance(value, dict):
        for key, item in list(value.items()):
            if key == "model_provider" and item != target:
                value[key] = target
                changed = True
            else:
                changed = replace_model_provider(item, target) or changed
    elif isinstance(value, list):
        for item in value:
            changed = replace_model_provider(item, target) or changed
    return changed


def rewrite_index(path: Path, target: str) -> int:
    if not path.exists():
        return 0
    changed_count = 0
    output: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            output.append(line)
            continue
        if replace_model_provider(item, target):
            changed_count += 1
            line = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        output.append(line)
    if changed_count:
        temporary = path.with_name(path.name + ".guardian.tmp")
        temporary.write_text("\n".join(output) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    return changed_count


def main() -> int:
    home = Path.home() / ".codex"
    target = current_provider(home)
    db = home / "state_5.sqlite"
    connection = sqlite3.connect(str(db), timeout=10)
    try:
        before = dict(
            connection.execute(
                "SELECT model_provider, COUNT(*) FROM threads GROUP BY model_provider"
            ).fetchall()
        )
        archived_before = dict(connection.execute("SELECT id, archived FROM threads").fetchall())
        updated = connection.execute(
            "UPDATE threads SET model_provider=? "
            "WHERE model_provider IS NULL OR model_provider != ?",
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
                "SELECT model_provider, COUNT(*) FROM threads GROUP BY model_provider"
            ).fetchall()
        )
    finally:
        connection.close()
    session_files = list((home / "sessions").rglob("*.jsonl")) if (home / "sessions").exists() else []
    session_files += (
        list((home / "archived_sessions").glob("*.jsonl"))
        if (home / "archived_sessions").exists()
        else []
    )
    jsonl_changed = sum(1 for path in session_files if rewrite_session_file(path, target))
    index_changed = rewrite_index(home / "session_index.jsonl", target)
    print(
        json.dumps(
            {
                "target": target,
                "before": before,
                "updated": updated,
                "after": after,
                "integrity": integrity,
                "jsonl_files_changed": jsonl_changed,
                "index_lines_changed": index_changed,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )
    os.system("pkill -TERM -f '[c]odex.*app-server' >/dev/null 2>&1 || true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
