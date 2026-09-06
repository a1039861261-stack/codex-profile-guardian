"""Read-only compatibility checks for Codex's immutable paginated rollouts.

Source contract: openai/codex 6af345407d9c2a568da9d01b6c4b81a9e61495c0,
thread-store/src/local/{rollout_lineage,thread_rollout_resolver,revert_thread}.rs
and rollout/src/rollout_file_name.rs. A thread ID is not a rollout ID.
No chat text, paths or IDs are included in the public summary.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
import uuid

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_NAME = re.compile(r"rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-(" + _UUID + r")(?:_(" + _UUID + r"))?\.jsonl")
BLOCKED_MESSAGE = (
    "聊天历史依赖尚未通过检查，已停止切换和冲突隔离。"
    "请保留完整冷备与隔离库，先核对缺失的源历史；切回账号不会自动恢复缺失文件。"
)


def rollout_identity(path: Path):
    match = _NAME.fullmatch(path.name)
    if not match:
        return None
    return (str(uuid.UUID(match[1])), str(uuid.UUID(match[2] or match[1])))


def inspect_lineage(entries, compressed_files=(), references=None):
    issues = defaultdict(set)
    protected = set()
    by_rollout = defaultdict(list)
    by_path = {item["path"]: item for item in entries}
    edges = {}
    paginated = []
    for entry in entries:
        identity = rollout_identity(entry["path"])
        if identity:
            by_rollout[identity[1]].append(entry)
        modern = (
            entry.get("history_mode") == "paginated"
            or entry.get("history_base") is not None
            or bool(identity and identity[0] != identity[1])
        )
        if not modern:
            continue
        protected.add(entry["thread_id"])
        paginated.append(entry)
        if entry.get("history_mode") != "paginated":
            issues["invalid_history_mode"].add(entry["path"])
        if not identity or identity[0] != entry["thread_id"]:
            issues["invalid_rollout_name"].add(entry["path"])
        base = entry.get("history_base")
        if base is None:
            continue
        if (
            not isinstance(base, dict)
            or not isinstance(base.get("thread_id"), str)
            or re.fullmatch(_UUID, base["thread_id"]) is None
            or type(base.get("end_byte_offset")) is not int
            or base["end_byte_offset"] < 0
            or type(base.get("end_ordinal_exclusive")) is not int
            or base["end_ordinal_exclusive"] < 1
        ):
            issues["invalid_history_base"].add(entry["path"])
            continue
        if identity:
            edges[identity[1]] = str(uuid.UUID(base["thread_id"]))

    for entry in paginated:
        identity = rollout_identity(entry["path"])
        if identity and len(by_rollout[identity[1]]) != 1:
            issues["ambiguous_rollout"].add(identity[1])
        base = entry.get("history_base")
        if not identity or identity[1] not in edges:
            continue
        source_id = edges[identity[1]]
        sources = by_rollout.get(source_id, [])
        # Even malformed/legacy sources must never be offered for quarantine.
        protected.update(item["thread_id"] for item in sources)
        if not sources:
            issues["missing_source_rollout"].add(source_id)
            continue
        if len(sources) != 1:
            issues["ambiguous_source_rollout"].add(source_id)
            continue
        source = sources[0]
        if source.get("history_mode") != "paginated":
            issues["source_not_paginated"].add(source_id)
        if base["end_byte_offset"] > source["path"].stat().st_size:
            issues["source_offset_out_of_bounds"].add(source_id)

    finished = set()
    for start in edges:
        path = set()
        current = start
        while current in edges and current not in finished:
            if current in path:
                issues["lineage_cycle"].add(current)
                break
            path.add(current)
            current = edges[current]
        finished.update(path)

    if references is not None:
        for thread_id, reference in references.items():
            if thread_id not in protected and reference.get("history_mode") != "paginated":
                continue
            # Paginated SQLite paths are authoritative. An older rollout with
            # the same thread ID is not a fallback for a missing current file.
            entry = by_path.get(reference["path"])
            if entry is None or entry["thread_id"] != thread_id:
                issues["missing_current_rollout"].add(thread_id)
            elif entry.get("history_mode") != "paginated":
                issues["current_not_paginated"].add(thread_id)
            elif entry["archived"] != reference["archived"]:
                issues["current_archive_mismatch"].add(thread_id)

    for path in compressed_files:
        # Never read compressed data as JSONL, rename it, or silently ignore it.
        issues["compressed_rollout_unsupported"].add(path)
    counts = {key: len(values) for key, values in sorted(issues.items()) if values}
    return {
        "protected_thread_ids": protected,
        "public": {
            "checked": True,
            "ready": not counts,
            "paginated_rollout_count": len(paginated),
            "protected_rollout_count": sum(item["thread_id"] in protected for item in entries),
            "compressed_rollout_count": len(compressed_files),
            "issue_counts": counts,
            "message": BLOCKED_MESSAGE if counts else (
                "分页历史依赖检查通过，相关历史文件全部保留，不参与冲突隔离。"
                if paginated else "未发现分页历史依赖异常。"
            ),
            "conversation_open_verified": False,
        },
    }
