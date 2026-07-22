from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import tempfile


EXPECTED_FILES = {
    "sessions/rollout-2026-04-13T18-50-20-019d8676-b6a0-74e0-8942-352728642774.jsonl": "aae786cb21c749c78f3188cd7c286a2acf0c386c36d80df3245cfbd47f3ceaba",
    "sessions/rollout-2026-04-15T20-31-51-019d9120-6172-7bd2-8cb9-a989631a9374.jsonl": "54e289f6e623a73cedfdcdf64cab1c13c378f88424141aff799db65832d5d9b5",
    "archived_sessions/rollout-2026-04-13T17-34-44-019d8631-7f2c-7402-8526-2145da6fec6a.jsonl": "ae87c8264afde809d9e3ffeddfc94890f6efd02a47da05502b84cc35cb6cd65f",
    "archived_sessions/rollout-2026-04-13T18-50-20-019d8676-b6a0-74e0-8942-352728642774.jsonl": "861409ebee940645e096f8faa604e83905bcf546c6307377bba6fe31fa4c14cc",
    "archived_sessions/rollout-2026-04-15T20-31-51-019d9120-6172-7bd2-8cb9-a989631a9374.jsonl": "e082f699292b385dcc6e48485adde673511cf1873ddf94d202cbdf7772a0f9d8",
}


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_target(root: Path, relative: str) -> Path:
    value = PurePosixPath(relative)
    if value.is_absolute() or any(part in {"", ".", ".."} for part in value.parts):
        raise RuntimeError("repair_path_invalid")
    target = root.joinpath(*value.parts)
    if target.is_symlink() or any(parent.is_symlink() for parent in target.parents if parent != root.parent):
        raise RuntimeError("repair_link_forbidden")
    return target


def logical_records(payload: bytes) -> tuple[list[bytes], list[dict[str, int]]]:
    lines = payload.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    records: list[bytes] = []
    repairs: list[dict[str, int]] = []
    index = 0
    while index < len(lines):
        raw = lines[index].removesuffix(b"\r")
        if not raw.strip():
            index += 1
            continue
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            start = index
            buffer = raw
            while True:
                try:
                    value = json.loads(buffer.decode("utf-8"), strict=False)
                    break
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    index += 1
                    if index >= len(lines):
                        raise RuntimeError("repair_record_unrecoverable") from exc
                    buffer += b"\n" + lines[index].removesuffix(b"\r")
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            json.loads(encoded)
            records.append(encoded + b"\n")
            repairs.append(
                {
                    "start_line": start + 1,
                    "end_line": index + 1,
                    "physical_lines": index - start + 1,
                }
            )
        else:
            if not isinstance(value, dict):
                raise RuntimeError("repair_record_not_object")
            records.append(raw + b"\n")
        index += 1
    if not records:
        raise RuntimeError("repair_file_empty")
    first = json.loads(records[0])
    if first.get("type") != "session_meta" or not isinstance(first.get("payload"), dict):
        raise RuntimeError("repair_session_meta_invalid")
    return records, repairs


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def database_snapshot(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        rows = connection.execute(
            "SELECT id, archived, rollout_path FROM threads ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    canonical = json.dumps(rows, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return {
        "integrity": integrity,
        "thread_count": len(rows),
        "mapping_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def resolve_document(root: Path, overlay: Path | None, relative: str) -> Path:
    if overlay is not None:
        candidate = safe_target(overlay, relative)
        if candidate.is_file():
            return candidate
    return safe_target(root, relative)


def records_after_session_meta(path: Path) -> bytes:
    payload = path.read_bytes()
    separator = payload.find(b"\n")
    if separator < 0:
        raise RuntimeError("repair_session_meta_separator_missing")
    return payload[separator + 1 :]


def validate_all(root: Path, overlay: Path | None) -> tuple[int, int]:
    file_count = 0
    record_count = 0
    for folder in ("sessions", "archived_sessions"):
        source_root = root / folder
        if not source_root.is_dir():
            continue
        for source in sorted(source_root.rglob("*.jsonl")):
            relative = source.relative_to(root).as_posix()
            path = resolve_document(root, overlay, relative)
            with path.open("rb") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise RuntimeError("repair_validation_record_not_object")
                    record_count += 1
            file_count += 1
    return file_count, record_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--overlay", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    overlay = args.overlay.resolve() if args.overlay else None
    if not root.is_dir() or (args.apply and overlay is not None):
        raise RuntimeError("repair_arguments_invalid")
    if not args.apply and overlay is None:
        raise RuntimeError("repair_overlay_required")

    database_before = database_snapshot(root / "state_5.sqlite")
    index_path = root / "session_index.jsonl"
    index_before = file_hash(index_path) if index_path.is_file() else None
    report: list[dict[str, object]] = []
    staged_payloads: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="guardian-jsonl-repair-") as staging_name:
        staging = Path(staging_name)
        for relative, expected_hash in EXPECTED_FILES.items():
            source = safe_target(root, relative)
            if not source.is_file() or file_hash(source) != expected_hash:
                raise RuntimeError("repair_source_hash_mismatch")
            records, repairs = logical_records(source.read_bytes())
            if not repairs:
                raise RuntimeError("repair_not_required")
            payload = b"".join(records)
            staged_payloads[relative] = payload
            staged = safe_target(staging, relative)
            atomic_write(staged, payload)
            report.append(
                {
                    "path_fingerprint": hashlib.sha256(relative.encode("utf-8")).hexdigest()[:12],
                    "logical_records": len(records),
                    "repair_blocks": len(repairs),
                    "repaired_sha256": file_hash(staged),
                }
            )

        for relative in (
            "sessions/rollout-2026-04-13T18-50-20-019d8676-b6a0-74e0-8942-352728642774.jsonl",
            "sessions/rollout-2026-04-15T20-31-51-019d9120-6172-7bd2-8cb9-a989631a9374.jsonl",
        ):
            archived = "archived_sessions/" + PurePosixPath(relative).name
            if records_after_session_meta(safe_target(staging, relative)) != records_after_session_meta(
                safe_target(staging, archived)
            ):
                raise RuntimeError("repair_duplicate_event_sequence_mismatch")

        validate_all(root, staging)
        if args.apply:
            originals = {
                relative: safe_target(root, relative).read_bytes() for relative in EXPECTED_FILES
            }
            changed: list[str] = []
            try:
                for relative, payload in staged_payloads.items():
                    atomic_write(safe_target(root, relative), payload)
                    changed.append(relative)
                validate_all(root, None)
            except Exception:
                for relative in reversed(changed):
                    atomic_write(safe_target(root, relative), originals[relative])
                raise
        else:
            for relative, payload in staged_payloads.items():
                atomic_write(safe_target(overlay, relative), payload)

    for relative in (
        "sessions/rollout-2026-04-13T18-50-20-019d8676-b6a0-74e0-8942-352728642774.jsonl",
        "sessions/rollout-2026-04-15T20-31-51-019d9120-6172-7bd2-8cb9-a989631a9374.jsonl",
    ):
        archived = "archived_sessions/" + PurePosixPath(relative).name
        effective_overlay = None if args.apply else overlay
        if records_after_session_meta(
            resolve_document(root, effective_overlay, relative)
        ) != records_after_session_meta(
            resolve_document(root, effective_overlay, archived)
        ):
            raise RuntimeError("repair_duplicate_event_sequence_mismatch")

    file_count, record_count = validate_all(root, None if args.apply else overlay)
    database_after = database_snapshot(root / "state_5.sqlite")
    index_after = file_hash(index_path) if index_path.is_file() else None
    if database_before != database_after or index_before != index_after:
        raise RuntimeError("repair_protected_mapping_changed")
    if database_after["integrity"] != "ok":
        raise RuntimeError("repair_sqlite_integrity_failed")

    print(
        json.dumps(
            {
                "ok": True,
                "mode": "apply" if args.apply else "overlay",
                "files_repaired": len(report),
                "jsonl_files_validated": file_count,
                "logical_records_validated": record_count,
                "database": database_after,
                "index_unchanged": True,
                "files": report,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
