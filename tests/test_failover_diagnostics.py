from __future__ import annotations

import hashlib
from io import BytesIO
import json
import stat
import unittest
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from backend import failover_diagnostics as diagnostics
from backend.failover_diagnostics import (
    DiagnosticBundleError,
    build_diagnostic_bundle,
    verify_diagnostic_bundle,
)


GENERATED_AT = "2026-07-14T02:30:00+00:00"


def status_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "source": "fixture",
        "stale": False,
        "collected_at": GENERATED_AT,
        "view_state": "ready",
        "summary": {
            "tone": "good",
            "headline": "主线路运行正常",
            "supporting": "请求由 P1 承载，P2 保持待命。",
            "required_action": "none",
            "carrier": "primary",
        },
        "gateway": {
            "source": "fixture",
            "online": True,
            "phase": "running",
            "state": "fixture_running",
            "version": "v1.7.0-fixture",
            "config_revision": 7,
            "configuration_drift": False,
        },
        "routes": {
            "primary": {
                "state": "closed",
                "carrying": True,
                "cooldown_seconds": None,
                "status_category": "success",
                "action_required": False,
            },
            "backup": {
                "state": "closed",
                "carrying": False,
                "cooldown_seconds": None,
                "status_category": "unknown",
                "action_required": False,
            },
        },
    }


def events_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "source": "fixture",
        "stale": False,
        "collected_at": GENERATED_AT,
        "items": [
            {
                "timestamp": GENERATED_AT,
                "event": "route_retested",
                "status": "success",
                "route_role": "primary",
                "source": "fixture",
            }
        ],
    }


def hosts_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "checked_at": GENERATED_AT,
        "items": [
            {
                "host_index": 1,
                "kind": "windows",
                "online": True,
                "stale": False,
                "collected_at": GENERATED_AT,
                "version": "v1.7.0-fixture",
                "config_revision": 7,
                "phase": "running",
                "carrier": "primary",
                "routes": {"primary": "closed", "backup": "closed"},
                "error_code": None,
            }
        ],
    }


class FailoverDiagnosticBundleTests(unittest.TestCase):
    def test_bundle_has_fixed_members_manifest_hashes_and_private_permissions(self) -> None:
        bundle = build_diagnostic_bundle(
            gateway_status=status_fixture(),
            gateway_events=events_fixture(),
            gateway_hosts=hosts_fixture(),
            generated_at=GENERATED_AT,
        )
        self.assertEqual(bundle.filename, "guardian-diagnostics-20260714T023000Z.zip")
        self.assertEqual(bundle.content_type, "application/zip")
        manifest = verify_diagnostic_bundle(bundle.payload)
        self.assertEqual(manifest["redaction_policy"], "strict_allowlist_v1")
        with ZipFile(BytesIO(bundle.payload), "r") as archive:
            self.assertEqual(
                archive.namelist(),
                [
                    "manifest.json",
                    "gateway-status.json",
                    "gateway-events.json",
                    "gateway-hosts.json",
                ],
            )
            for info in archive.infolist():
                self.assertEqual((info.external_attr >> 16) & 0o777, 0o600)
            manifest_document = json.loads(archive.read("manifest.json"))
            for item in manifest_document["files"]:
                payload = archive.read(item["name"])
                self.assertEqual(item["size"], len(payload))
                self.assertEqual(item["sha256"], hashlib.sha256(payload).hexdigest())

    def test_bundle_contains_no_identifier_address_or_content_fields(self) -> None:
        bundle = build_diagnostic_bundle(
            gateway_status=status_fixture(),
            gateway_events=events_fixture(),
            gateway_hosts=hosts_fixture(),
            generated_at=GENERATED_AT,
        )
        with ZipFile(BytesIO(bundle.payload), "r") as archive:
            text = "\n".join(
                archive.read(name).decode("utf-8") for name in archive.namelist()
            ).lower()
        for forbidden in (
            "profile_id",
            "group_id",
            "request_id",
            "attempt_id",
            "thread_id",
            "host_key",
            "display_name",
            "base_url",
            "authorization",
            "cookie",
            "prompt",
            "tool_arguments",
            "executable_path",
            "control_token",
            "ssh_target",
        ):
            self.assertNotIn(forbidden, text)

    def test_unexpected_or_sensitive_fields_fail_closed(self) -> None:
        status = status_fixture()
        status["control_token"] = "fixture-secret"
        with self.assertRaisesRegex(DiagnosticBundleError, "diagnostic_status_schema_invalid"):
            build_diagnostic_bundle(
                gateway_status=status,
                gateway_events=events_fixture(),
                gateway_hosts=hosts_fixture(),
                generated_at=GENERATED_AT,
            )

        status = status_fixture()
        status["summary"]["supporting"] = "Bearer PRIVATE-CANARY"  # type: ignore[index]
        with self.assertRaisesRegex(DiagnosticBundleError, "diagnostic_sensitive_text_rejected"):
            build_diagnostic_bundle(
                gateway_status=status,
                gateway_events=events_fixture(),
                gateway_hosts=hosts_fixture(),
                generated_at=GENERATED_AT,
            )

    def test_event_and_host_limits_fail_closed(self) -> None:
        events = events_fixture()
        events["items"] = events["items"] * (diagnostics.MAX_EVENTS + 1)  # type: ignore[operator]
        with self.assertRaisesRegex(DiagnosticBundleError, "diagnostic_events_limit_exceeded"):
            build_diagnostic_bundle(
                gateway_status=status_fixture(),
                gateway_events=events,
                gateway_hosts=hosts_fixture(),
                generated_at=GENERATED_AT,
            )

        hosts = hosts_fixture()
        hosts["items"] = [
            {**hosts_fixture()["items"][0], "host_index": index}  # type: ignore[index]
            for index in range(1, diagnostics.MAX_HOSTS + 2)
        ]
        with self.assertRaisesRegex(DiagnosticBundleError, "diagnostic_hosts_limit_exceeded"):
            build_diagnostic_bundle(
                gateway_status=status_fixture(),
                gateway_events=events_fixture(),
                gateway_hosts=hosts,
                generated_at=GENERATED_AT,
            )

    def test_archive_size_limit_is_enforced(self) -> None:
        with patch.object(diagnostics, "MAX_ARCHIVE_BYTES", 1):
            with self.assertRaisesRegex(DiagnosticBundleError, "diagnostic_archive_too_large"):
                build_diagnostic_bundle(
                    gateway_status=status_fixture(),
                    gateway_events=events_fixture(),
                    gateway_hosts=hosts_fixture(),
                    generated_at=GENERATED_AT,
                )

    def test_manifest_detects_member_tampering(self) -> None:
        bundle = build_diagnostic_bundle(
            gateway_status=status_fixture(),
            gateway_events=events_fixture(),
            gateway_hosts=hosts_fixture(),
            generated_at=GENERATED_AT,
        )
        with ZipFile(BytesIO(bundle.payload), "r") as original:
            documents = {name: original.read(name) for name in original.namelist()}
            date_time = original.getinfo("manifest.json").date_time
        status = json.loads(documents["gateway-status.json"])
        status["gateway"]["online"] = False
        documents["gateway-status.json"] = json.dumps(status).encode("utf-8")
        tampered = BytesIO()
        with ZipFile(tampered, "w", compression=ZIP_DEFLATED) as archive:
            for name in ["manifest.json", *diagnostics._MEMBERS]:
                info = ZipInfo(name, date_time=date_time)
                info.compress_type = ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, documents[name])
        with self.assertRaisesRegex(DiagnosticBundleError, "diagnostic_manifest_hash_mismatch"):
            verify_diagnostic_bundle(tampered.getvalue())

    def test_archive_with_extra_member_is_rejected(self) -> None:
        bundle = build_diagnostic_bundle(
            gateway_status=status_fixture(),
            gateway_events=events_fixture(),
            gateway_hosts=hosts_fixture(),
            generated_at=GENERATED_AT,
        )
        with ZipFile(BytesIO(bundle.payload), "r") as original:
            documents = {name: original.read(name) for name in original.namelist()}
            date_time = original.getinfo("manifest.json").date_time
        extra = BytesIO()
        with ZipFile(extra, "w", compression=ZIP_DEFLATED) as archive:
            for name, payload in [*documents.items(), ("runtime.json", b"{}")]:
                info = ZipInfo(name, date_time=date_time)
                info.compress_type = ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, payload)
        with self.assertRaisesRegex(DiagnosticBundleError, "diagnostic_archive_members_invalid"):
            verify_diagnostic_bundle(extra.getvalue())


if __name__ == "__main__":
    unittest.main()
