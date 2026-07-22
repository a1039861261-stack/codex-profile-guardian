from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from io import BytesIO
import json
import re
import stat
from typing import Mapping, Sequence
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile, ZipInfo


SCHEMA_VERSION = 1
MAX_EVENTS = 100
MAX_HOSTS = 32
MAX_MEMBER_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024

_MEMBERS = (
    "gateway-status.json",
    "gateway-events.json",
    "gateway-hosts.json",
)
_SENSITIVE_TEXT = re.compile(
    r"(?i)(?:authorization|cookie|bearer\s|api[_-]?key|token|secret|prompt|response|tool[_-]?(?:call|arguments?))"
)
_WINDOWS_PATH = re.compile(r"(?i)(?:^|\s)[a-z]:[\\/]")
_UUID = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
_CODE = re.compile(r"[a-z0-9_]{1,96}")
_VERSION = re.compile(r"v?[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")


class DiagnosticBundleError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DiagnosticBundle:
    filename: str
    content_type: str
    payload: bytes
    generated_at: str


def build_diagnostic_bundle(
    *,
    gateway_status: Mapping[str, object],
    gateway_events: Mapping[str, object],
    gateway_hosts: Mapping[str, object],
    generated_at: str | None = None,
) -> DiagnosticBundle:
    timestamp = _timestamp(generated_at or datetime.now(UTC).isoformat())
    status = _validate_gateway_status(gateway_status)
    events = _validate_gateway_events(gateway_events)
    hosts = _validate_gateway_hosts(gateway_hosts)
    payloads = {
        "gateway-status.json": _json_bytes(status),
        "gateway-events.json": _json_bytes(events),
        "gateway-hosts.json": _json_bytes(hosts),
    }
    if any(len(payload) > MAX_MEMBER_BYTES for payload in payloads.values()):
        raise DiagnosticBundleError("diagnostic_member_too_large")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": timestamp,
        "redaction_policy": "strict_allowlist_v1",
        "files": [
            {
                "name": name,
                "size": len(payloads[name]),
                "sha256": hashlib.sha256(payloads[name]).hexdigest(),
            }
            for name in _MEMBERS
        ],
        "limits": {
            "events": MAX_EVENTS,
            "hosts": MAX_HOSTS,
            "member_bytes": MAX_MEMBER_BYTES,
            "archive_bytes": MAX_ARCHIVE_BYTES,
        },
    }
    manifest_payload = _json_bytes(manifest)
    if len(manifest_payload) > MAX_MEMBER_BYTES:
        raise DiagnosticBundleError("diagnostic_manifest_too_large")
    archive = _zip_bytes(
        {"manifest.json": manifest_payload, **payloads},
        timestamp=timestamp,
    )
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise DiagnosticBundleError("diagnostic_archive_too_large")
    verify_diagnostic_bundle(archive)
    parsed = datetime.fromisoformat(timestamp).astimezone(UTC)
    filename = f"guardian-diagnostics-{parsed.strftime('%Y%m%dT%H%M%SZ')}.zip"
    return DiagnosticBundle(
        filename=filename,
        content_type="application/zip",
        payload=archive,
        generated_at=timestamp,
    )


def verify_diagnostic_bundle(payload: bytes) -> dict[str, object]:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_ARCHIVE_BYTES:
        raise DiagnosticBundleError("diagnostic_archive_invalid")
    try:
        with ZipFile(BytesIO(payload), mode="r") as archive:
            names = archive.namelist()
            expected = ["manifest.json", *_MEMBERS]
            if names != expected or len(names) != len(set(names)):
                raise DiagnosticBundleError("diagnostic_archive_members_invalid")
            documents: dict[str, bytes] = {}
            for info in archive.infolist():
                if (
                    info.is_dir()
                    or info.flag_bits & 0x1
                    or info.file_size > MAX_MEMBER_BYTES
                    or ((info.external_attr >> 16) & 0o777) != 0o600
                ):
                    raise DiagnosticBundleError("diagnostic_archive_member_invalid")
                data = archive.read(info.filename)
                if len(data) != info.file_size:
                    raise DiagnosticBundleError("diagnostic_archive_member_invalid")
                documents[info.filename] = data
    except DiagnosticBundleError:
        raise
    except (BadZipFile, KeyError, OSError, RuntimeError) as exc:
        raise DiagnosticBundleError("diagnostic_archive_invalid") from exc

    manifest = _json_object(documents["manifest.json"], "diagnostic_manifest_invalid")
    _exact_keys(
        manifest,
        {"schema_version", "generated_at", "redaction_policy", "files", "limits"},
        "diagnostic_manifest_invalid",
    )
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise DiagnosticBundleError("diagnostic_manifest_invalid")
    _timestamp(manifest.get("generated_at"))
    if manifest.get("redaction_policy") != "strict_allowlist_v1":
        raise DiagnosticBundleError("diagnostic_manifest_invalid")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != len(_MEMBERS):
        raise DiagnosticBundleError("diagnostic_manifest_invalid")
    for expected_name, item in zip(_MEMBERS, files, strict=True):
        entry = _mapping(item, "diagnostic_manifest_invalid")
        _exact_keys(entry, {"name", "size", "sha256"}, "diagnostic_manifest_invalid")
        content = documents[expected_name]
        if (
            entry.get("name") != expected_name
            or entry.get("size") != len(content)
            or entry.get("sha256") != hashlib.sha256(content).hexdigest()
        ):
            raise DiagnosticBundleError("diagnostic_manifest_hash_mismatch")
    limits = _mapping(manifest.get("limits"), "diagnostic_manifest_invalid")
    _exact_keys(
        limits,
        {"events", "hosts", "member_bytes", "archive_bytes"},
        "diagnostic_manifest_invalid",
    )
    if limits != {
        "events": MAX_EVENTS,
        "hosts": MAX_HOSTS,
        "member_bytes": MAX_MEMBER_BYTES,
        "archive_bytes": MAX_ARCHIVE_BYTES,
    }:
        raise DiagnosticBundleError("diagnostic_manifest_invalid")
    _validate_gateway_status(
        _json_object(documents["gateway-status.json"], "diagnostic_status_schema_invalid")
    )
    _validate_gateway_events(
        _json_object(documents["gateway-events.json"], "diagnostic_events_schema_invalid")
    )
    _validate_gateway_hosts(
        _json_object(documents["gateway-hosts.json"], "diagnostic_hosts_schema_invalid")
    )
    return dict(manifest)


def _validate_gateway_status(value: Mapping[str, object]) -> dict[str, object]:
    _exact_keys(
        value,
        {
            "schema_version",
            "source",
            "stale",
            "collected_at",
            "view_state",
            "summary",
            "gateway",
            "routes",
        },
        "diagnostic_status_schema_invalid",
    )
    if value.get("schema_version") != SCHEMA_VERSION:
        raise DiagnosticBundleError("diagnostic_status_schema_invalid")
    summary = _mapping(value.get("summary"), "diagnostic_status_summary_invalid")
    _exact_keys(
        summary,
        {"tone", "headline", "supporting", "required_action", "carrier"},
        "diagnostic_status_summary_invalid",
    )
    gateway = _mapping(value.get("gateway"), "diagnostic_gateway_schema_invalid")
    _exact_keys(
        gateway,
        {
            "source",
            "online",
            "phase",
            "state",
            "version",
            "config_revision",
            "configuration_drift",
        },
        "diagnostic_gateway_schema_invalid",
    )
    routes = _mapping(value.get("routes"), "diagnostic_routes_schema_invalid")
    _exact_keys(routes, {"primary", "backup"}, "diagnostic_routes_schema_invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "source": _enum(value.get("source"), {"fixture", "production"}, "diagnostic_source_invalid"),
        "stale": _boolean(value.get("stale"), "diagnostic_stale_invalid"),
        "collected_at": _nullable_timestamp(value.get("collected_at")),
        "view_state": _enum(
            value.get("view_state"),
            {"ready", "loading", "empty", "error"},
            "diagnostic_view_state_invalid",
        ),
        "summary": {
            "tone": _enum(summary.get("tone"), {"good", "warning", "danger", "neutral"}, "diagnostic_tone_invalid"),
            "headline": _safe_text(summary.get("headline"), maximum=120),
            "supporting": _safe_text(summary.get("supporting"), maximum=320),
            "required_action": _enum(
                summary.get("required_action"),
                {"none", "check_primary", "repair_route", "reload"},
                "diagnostic_action_invalid",
            ),
            "carrier": _nullable_enum(summary.get("carrier"), {"primary", "backup"}, "diagnostic_carrier_invalid"),
        },
        "gateway": {
            "source": _enum(gateway.get("source"), {"fixture", "production"}, "diagnostic_source_invalid"),
            "online": _boolean(gateway.get("online"), "diagnostic_gateway_online_invalid"),
            "phase": _code(gateway.get("phase"), allow_empty=False),
            "state": _code(gateway.get("state"), allow_empty=False),
            "version": _version(gateway.get("version")),
            "config_revision": _nonnegative_integer(gateway.get("config_revision"), "diagnostic_revision_invalid"),
            "configuration_drift": _boolean(gateway.get("configuration_drift"), "diagnostic_drift_invalid"),
        },
        "routes": {
            role: _validate_route(_mapping(routes.get(role), "diagnostic_route_invalid"))
            for role in ("primary", "backup")
        },
    }


def _validate_route(value: Mapping[str, object]) -> dict[str, object]:
    _exact_keys(
        value,
        {"state", "carrying", "cooldown_seconds", "status_category", "action_required"},
        "diagnostic_route_schema_invalid",
    )
    cooldown = value.get("cooldown_seconds")
    if cooldown is not None:
        cooldown = _bounded_integer(cooldown, 0, 86400, "diagnostic_route_cooldown_invalid")
    return {
        "state": _enum(
            value.get("state"),
            {"unknown", "closed", "open_temporary", "half_open", "open_action_required", "disabled"},
            "diagnostic_route_state_invalid",
        ),
        "carrying": _boolean(value.get("carrying"), "diagnostic_route_carrying_invalid"),
        "cooldown_seconds": cooldown,
        "status_category": _code(value.get("status_category"), allow_empty=True),
        "action_required": _boolean(value.get("action_required"), "diagnostic_route_action_invalid"),
    }


def _validate_gateway_events(value: Mapping[str, object]) -> dict[str, object]:
    _exact_keys(
        value,
        {"schema_version", "source", "stale", "collected_at", "items"},
        "diagnostic_events_schema_invalid",
    )
    if value.get("schema_version") != SCHEMA_VERSION:
        raise DiagnosticBundleError("diagnostic_events_schema_invalid")
    items = value.get("items")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        raise DiagnosticBundleError("diagnostic_events_invalid")
    if len(items) > MAX_EVENTS:
        raise DiagnosticBundleError("diagnostic_events_limit_exceeded")
    normalized = []
    for item in items:
        event = _mapping(item, "diagnostic_event_invalid")
        _exact_keys(
            event,
            {"timestamp", "event", "status", "route_role", "source"},
            "diagnostic_event_schema_invalid",
        )
        normalized.append(
            {
                "timestamp": _nullable_timestamp(event.get("timestamp")),
                "event": _code(event.get("event"), allow_empty=False),
                "status": _code(event.get("status"), allow_empty=False),
                "route_role": _enum(event.get("route_role"), {"", "primary", "backup"}, "diagnostic_event_role_invalid"),
                "source": _enum(event.get("source"), {"fixture", "production"}, "diagnostic_source_invalid"),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "source": _enum(value.get("source"), {"fixture", "production"}, "diagnostic_source_invalid"),
        "stale": _boolean(value.get("stale"), "diagnostic_stale_invalid"),
        "collected_at": _nullable_timestamp(value.get("collected_at")),
        "items": normalized,
    }


def _validate_gateway_hosts(value: Mapping[str, object]) -> dict[str, object]:
    _exact_keys(
        value,
        {"schema_version", "checked_at", "items"},
        "diagnostic_hosts_schema_invalid",
    )
    if value.get("schema_version") != SCHEMA_VERSION:
        raise DiagnosticBundleError("diagnostic_hosts_schema_invalid")
    items = value.get("items")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        raise DiagnosticBundleError("diagnostic_hosts_invalid")
    if len(items) > MAX_HOSTS:
        raise DiagnosticBundleError("diagnostic_hosts_limit_exceeded")
    normalized = []
    for item in items:
        host = _mapping(item, "diagnostic_host_invalid")
        _exact_keys(
            host,
            {
                "host_index",
                "kind",
                "online",
                "stale",
                "collected_at",
                "version",
                "config_revision",
                "phase",
                "carrier",
                "routes",
                "error_code",
            },
            "diagnostic_host_schema_invalid",
        )
        routes = _mapping(host.get("routes"), "diagnostic_host_routes_invalid")
        _exact_keys(routes, {"primary", "backup"}, "diagnostic_host_routes_invalid")
        version = host.get("version")
        revision = host.get("config_revision")
        error_code = host.get("error_code")
        normalized.append(
            {
                "host_index": _bounded_integer(host.get("host_index"), 1, MAX_HOSTS, "diagnostic_host_index_invalid"),
                "kind": _enum(host.get("kind"), {"windows", "nas"}, "diagnostic_host_kind_invalid"),
                "online": _boolean(host.get("online"), "diagnostic_host_online_invalid"),
                "stale": _boolean(host.get("stale"), "diagnostic_host_stale_invalid"),
                "collected_at": _nullable_timestamp(host.get("collected_at")),
                "version": None if version is None else _version(version),
                "config_revision": None if revision is None else _nonnegative_integer(revision, "diagnostic_revision_invalid"),
                "phase": _code(host.get("phase"), allow_empty=False),
                "carrier": _nullable_enum(host.get("carrier"), {"primary", "backup"}, "diagnostic_carrier_invalid"),
                "routes": {
                    "primary": _code(routes.get("primary"), allow_empty=False),
                    "backup": _code(routes.get("backup"), allow_empty=False),
                },
                "error_code": None if error_code is None else _code(error_code, allow_empty=False),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "checked_at": _nullable_timestamp(value.get("checked_at")),
        "items": normalized,
    }


def _json_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DiagnosticBundleError("diagnostic_serialization_failed") from exc


def _json_object(payload: bytes, code: str) -> Mapping[str, object]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiagnosticBundleError(code) from exc
    if not isinstance(value, Mapping):
        raise DiagnosticBundleError(code)
    return value


def _zip_bytes(payloads: Mapping[str, bytes], *, timestamp: str) -> bytes:
    expected = {"manifest.json", *_MEMBERS}
    if set(payloads) != expected:
        raise DiagnosticBundleError("diagnostic_archive_members_invalid")
    moment = datetime.fromisoformat(timestamp).astimezone(UTC)
    date_time = (moment.year, moment.month, moment.day, moment.hour, moment.minute, moment.second)
    stream = BytesIO()
    with ZipFile(stream, mode="w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in ("manifest.json", *_MEMBERS):
            info = ZipInfo(name, date_time=date_time)
            info.compress_type = ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, payloads[name])
    return stream.getvalue()


def _mapping(value: object, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DiagnosticBundleError(code)
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise DiagnosticBundleError(code)


def _boolean(value: object, code: str) -> bool:
    if type(value) is not bool:
        raise DiagnosticBundleError(code)
    return value


def _bounded_integer(value: object, minimum: int, maximum: int, code: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DiagnosticBundleError(code)
    return value


def _nonnegative_integer(value: object, code: str) -> int:
    return _bounded_integer(value, 0, 2**63 - 1, code)


def _enum(value: object, allowed: set[str], code: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise DiagnosticBundleError(code)
    return value


def _nullable_enum(value: object, allowed: set[str], code: str) -> str | None:
    if value is None:
        return None
    return _enum(value, allowed, code)


def _safe_text(value: object, *, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise DiagnosticBundleError("diagnostic_text_invalid")
    if any(ord(character) < 0x20 for character in value):
        raise DiagnosticBundleError("diagnostic_text_invalid")
    if (
        "://" in value
        or "@" in value
        or _WINDOWS_PATH.search(value)
        or _UUID.search(value)
        or _SENSITIVE_TEXT.search(value)
    ):
        raise DiagnosticBundleError("diagnostic_sensitive_text_rejected")
    return value


def _code(value: object, *, allow_empty: bool) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise DiagnosticBundleError("diagnostic_code_invalid")
    return value


def _version(value: object) -> str:
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        raise DiagnosticBundleError("diagnostic_version_invalid")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise DiagnosticBundleError("diagnostic_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise DiagnosticBundleError("diagnostic_timestamp_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DiagnosticBundleError("diagnostic_timestamp_invalid")
    return parsed.astimezone(UTC).isoformat()


def _nullable_timestamp(value: object) -> str | None:
    if value is None or value == "":
        return None
    return _timestamp(value)
