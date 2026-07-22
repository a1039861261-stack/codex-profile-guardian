from __future__ import annotations

import json
from pathlib import Path
import re


class SpoolCleanupError(RuntimeError):
    pass


_SAFE_NAME = re.compile(r"\A[a-f0-9]{32}\.spool\Z")


def cleanup_registered_spool(spool_dir: str | Path, registry_path: str | Path) -> int:
    root = Path(spool_dir).resolve()
    registry = Path(registry_path)
    if not registry.exists():
        return 0
    try:
        document = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SpoolCleanupError("spool_registry_invalid") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise SpoolCleanupError("spool_registry_invalid")
    entries = document.get("files")
    if not isinstance(entries, list) or not all(isinstance(name, str) for name in entries):
        raise SpoolCleanupError("spool_registry_invalid")
    removed = 0
    for name in entries:
        if _SAFE_NAME.fullmatch(name) is None:
            raise SpoolCleanupError("spool_registry_entry_invalid")
        target = (root / name).resolve()
        if target.parent != root or target.is_symlink():
            raise SpoolCleanupError("spool_registry_entry_invalid")
        try:
            target.unlink()
            removed += 1
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise SpoolCleanupError("spool_cleanup_failed") from exc
    try:
        registry.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise SpoolCleanupError("spool_registry_cleanup_failed") from exc
    return removed
