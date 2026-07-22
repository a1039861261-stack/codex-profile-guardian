from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.guardian import GuardianService


service = GuardianService()
provider, _model = service._read_config_provider()
backup = service.create_backup("before-shared-history-live-repair")
backup_root = service.backups_dir / backup["name"]
try:
    migration = service._migrate_thread_provider(provider)
    migration["shared_history_preserved"] = True
except Exception:
    service._restore_files_from_backup(backup_root)
    raise

print(
    json.dumps(
        {
            "provider": provider,
            "backup": backup["name"],
            "migration": migration,
            "database": service._database_status(),
        },
        ensure_ascii=False,
    )
)
