from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import tempfile
import unittest

from backend.remote_gateway import BoundedProcessResult
from backend.remote_gateway_status import (
    RemoteGatewayStatusCollector,
    RemoteGatewayStatusError,
    RemoteGatewayStatusService,
    STATUS_PROTOCOL,
    STATUS_REMOTE_COMMAND,
    parse_status_receipt,
    render_status_worker,
    ssh_status_command,
)


NOW = "2026-07-14T00:30:00+00:00"
PRIVATE_CANARY = "FULL-PRIVATE-NAS-STATUS-CANARY"


def _receipt(*, ok: bool = True) -> bytes:
    document = {
        "protocol": STATUS_PROTOCOL,
        "ok": ok,
        "error_code": None if ok else "nas_gateway_status_unavailable",
        "collected_at": NOW if ok else None,
        "version": "v1.7.0" if ok else None,
        "config_revision": 7 if ok else None,
        "phase": "running" if ok else None,
        "carrier": "backup" if ok else None,
        "primary_state": "open_temporary" if ok else None,
        "backup_state": "closed" if ok else None,
    }
    return json.dumps(document, separators=(",", ":")).encode()


class RecordingRunner:
    def __init__(self, result: BoundedProcessResult) -> None:
        self.result = result
        self.calls = []

    def __call__(self, command, stdin, timeout, max_stdout, max_stderr):
        self.calls.append((list(command), stdin, timeout, max_stdout, max_stderr))
        return self.result


class ScriptedCollector:
    def __init__(self, values) -> None:
        self.values = list(values)
        self.calls = []

    def collect(self, host):
        self.calls.append(dict(host))
        return self.values.pop(0)


class RemoteGatewayStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.host = {
            "target": "guardian@fixture-nas",
            "port": 22,
            "display_name": "工作室 NAS",
            "host_id": "fixture-host-id",
        }

    def test_fixed_command_and_worker_are_read_only_and_secret_free(self) -> None:
        command = ssh_status_command(self.host)
        worker = render_status_worker()
        self.assertEqual(command[-1], STATUS_REMOTE_COMMAND)
        self.assertIn(b"/control/v1/status", worker)
        self.assertIn(b"/control/v1/failover/snapshot", worker)
        self.assertIn(b"control.token", worker)
        self.assertNotIn(b".codex", worker)
        self.assertNotIn(b"session_index", worker)
        self.assertNotIn(b"Authorization: Bearer", worker)
        for forbidden in ("rm ", "mv ", "systemctl", "chmod", "chown", "mkdir"):
            self.assertNotIn(forbidden, worker.decode("utf-8"))

    def test_receipt_parser_is_exact_and_rejects_hostile_values(self) -> None:
        parsed = parse_status_receipt(_receipt())
        self.assertEqual(parsed["carrier"], "backup")
        hostile = json.loads(_receipt())
        hostile["secret"] = PRIVATE_CANARY
        with self.assertRaisesRegex(RemoteGatewayStatusError, "nas_gateway_status_output_invalid"):
            parse_status_receipt(json.dumps(hostile).encode())
        hostile = json.loads(_receipt())
        hostile["version"] = "v1.7.0\nBearer secret"
        with self.assertRaisesRegex(RemoteGatewayStatusError, "nas_gateway_status_output_invalid"):
            parse_status_receipt(json.dumps(hostile).encode())

    def test_collector_never_returns_stderr_or_target(self) -> None:
        runner = RecordingRunner(BoundedProcessResult(0, _receipt(), b""))
        result = RemoteGatewayStatusCollector(runner=runner).collect(self.host)
        self.assertTrue(result["ok"])
        command, worker, *_rest = runner.calls[0]
        self.assertNotIn(PRIVATE_CANARY, "\0".join(command))
        self.assertNotIn(b"fixture-host-id", worker)

        failed = RemoteGatewayStatusCollector(
            runner=RecordingRunner(
                BoundedProcessResult(255, b"", f"Bearer {PRIVATE_CANARY}".encode())
            )
        ).collect(self.host)
        self.assertEqual(failed, {"ok": False, "error_code": "nas_gateway_status_ssh_failed"})
        self.assertNotIn(PRIVATE_CANARY, json.dumps(failed))

    def test_snapshot_never_calls_collector_and_marks_cache_stale(self) -> None:
        collector = ScriptedCollector([])
        service = self._service(collector)
        first = service.snapshot()
        self.assertEqual(collector.calls, [])
        self.assertEqual([item["kind"] for item in first["items"]], ["windows", "nas"])
        self.assertTrue(first["items"][1]["stale"])
        self.assertEqual(first["items"][1]["error_code"], "nas_gateway_status_not_collected")
        serialized = json.dumps(first, ensure_ascii=False)
        self.assertNotIn("fixture-nas", serialized)
        self.assertNotIn("fixture-host-id", serialized)

        service.collector = ScriptedCollector([json.loads(_receipt())])
        fresh = service.refresh()
        self.assertFalse(fresh["items"][1]["stale"])
        cached = service.snapshot()
        self.assertTrue(cached["items"][1]["stale"])
        self.assertEqual(cached["items"][1]["carrier"], "backup")

    def test_refresh_failure_preserves_last_projection_as_stale(self) -> None:
        service = self._service(ScriptedCollector([json.loads(_receipt())]))
        service.refresh()
        service.collector = ScriptedCollector(
            [{"ok": False, "error_code": "nas_gateway_status_timeout"}]
        )
        failed = service.refresh()
        remote = failed["items"][1]
        self.assertFalse(remote["online"])
        self.assertTrue(remote["stale"])
        self.assertEqual(remote["version"], "v1.7.0")
        self.assertEqual(remote["error_code"], "nas_gateway_status_timeout")

    def test_corrupt_cache_fails_closed_without_network(self) -> None:
        cache = self.root / "remote-status.json"
        cache.write_text('{"secret":"' + PRIVATE_CANARY + '"}', encoding="utf-8")
        collector = ScriptedCollector([])
        result = self._service(collector, cache=cache).snapshot()
        self.assertEqual(collector.calls, [])
        self.assertEqual(result["items"][1]["error_code"], "nas_gateway_status_not_collected")
        self.assertNotIn(PRIVATE_CANARY, json.dumps(result))

    def _service(self, collector, *, cache: Path | None = None) -> RemoteGatewayStatusService:
        return RemoteGatewayStatusService(
            cache_path=cache or self.root / "remote-status.json",
            hosts_provider=lambda: [self.host],
            local_snapshot_provider=lambda: {
                "version": "v1.7.0",
                "config_revision": 7,
                "phase": "running",
                "carrier": "primary",
                "routes": {
                    "primary": {"state": "closed"},
                    "backup": {"state": "closed"},
                },
            },
            collector=collector,
            clock=lambda: NOW,
        )


if __name__ == "__main__":
    unittest.main()
