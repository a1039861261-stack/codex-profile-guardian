from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.guardian import GuardianService


def auth_payload(account: str, refresh: str) -> str:
    return json.dumps(
        {
            "OPENAI_API_KEY": None,
            "last_refresh": "2026-07-06T00:00:00Z",
            "tokens": {
                "account_id": account,
                "access_token": f"access-{account}",
                "refresh_token": refresh,
                "id_token": f"id-{account}",
            },
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if root.exists():
        shutil.rmtree(root)
    codex = root / ".codex"
    data = root / "appdata"
    sessions = codex / "sessions" / "2026" / "07" / "06"
    archived = codex / "archived_sessions"
    sessions.mkdir(parents=True)
    archived.mkdir(parents=True)
    (codex / "auth.json").write_text(auth_payload("official-a", "refresh-a"), encoding="utf-8")
    (codex / "config.toml").write_text(
        'model = "gpt-5.5"\nmodel_provider = "openai"\n', encoding="utf-8"
    )
    db = sqlite3.connect(codex / "state_5.sqlite")
    db.execute(
        "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, created_at TEXT, updated_at TEXT, "
        "source TEXT, model_provider TEXT, cwd TEXT, title TEXT, first_user_message TEXT, has_user_event INTEGER, "
        "archived INTEGER, created_at_ms INTEGER)"
    )
    for index in range(19):
        thread_id = f"019f330a-e611-70a2-8b98-{index:012d}"
        is_archived = index >= 14
        path = (archived if is_archived else sessions) / f"rollout-2026-07-06T00-00-{index:02d}-{thread_id}.jsonl"
        path.write_text(
            json.dumps({"type": "session_meta", "payload": {"id": thread_id, "model_provider": "openai"}}) + "\n",
            encoding="utf-8",
        )
        db.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                thread_id,
                str(path),
                "2026-07-06T00:00:00Z",
                "2026-07-06T00:00:00Z",
                "vscode",
                "openai",
                str(root),
                f"演示会话 {index + 1}",
                f"演示会话 {index + 1}",
                1,
                1 if is_archived else 0,
                index,
            ),
        )
    db.commit()
    db.close()

    service = GuardianService(codex_home=codex, data_dir=data, helper_command=["guardian-demo.exe"])
    first = service.capture_official("个人 Plus", "gpt-5.5")
    (codex / "auth.json").write_text(auth_payload("official-b", "refresh-b"), encoding="utf-8")
    service.capture_official("工作账号", "gpt-5.4")
    service.create_api_profile("APIKEY.FUN", "https://api.example.invalid/v1", "fixture-api-key", "gpt-5.4")
    state = service._load_state()
    state["current_profile"] = first["id"]
    for profile in state["profiles"]:
        if profile["id"] == first["id"]:
            profile["last_used_at"] = "2026-07-06T00:20:00+00:00"
    service._save_state(state)
    service.create_backup("before-switch")
    print(json.dumps({"codex_home": str(codex), "data_dir": str(data)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
