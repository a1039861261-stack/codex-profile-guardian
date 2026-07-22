from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import aiohttp

from backend.provider_activation import ProviderActivationCoordinator
from gateway.app import GatewayProcessHost
from gateway.cancellation import CancellationToken
from gateway.commit import Committer
from gateway.models import AttemptResult, CommitState, GatewayError, GatewayLimits
from gateway.service import SingleRouteGatewayCore
from tests.gateway_probe_support import (
    ProgrammableResponsesMock,
    ScriptedScenario,
    fixture_request,
    text_scenario,
)
from tests.test_gateway_core import RecordingDownstream, _buffered
from tests.test_gateway_g5_lifecycle import (
    _authorization,
    _config_document,
    _free_port,
    _protect,
    _unprotect,
    _write_fixture_install,
)


class GatewayG8IntegrityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.hosts: list[GatewayProcessHost] = []
        self.mocks: list[ProgrammableResponsesMock] = []

    async def asyncTearDown(self) -> None:
        for host in reversed(self.hosts):
            if host.phase not in {"created", "stopped"}:
                await host.close()
        for mock in reversed(self.mocks):
            mock.close()

    def _mock(self, scenario: ScriptedScenario, name: str) -> ProgrammableResponsesMock:
        mock = ProgrammableResponsesMock(lambda _request: scenario, route_name=name).start()
        self.mocks.append(mock)
        return mock

    def _codex_fixture(self, name: str, *, index_present: bool) -> tuple[Path, bytes]:
        codex_home = self.root / name / ".codex"
        codex_home.mkdir(parents=True)
        original_config = (
            'model = "fixture-model"\n'
            'model_provider = "openai"\n'
            'custom_unknown = "preserve-me"\n'
            '[features]\n'
            'memories = true\n'
            '[mcp_servers.fixture]\n'
            'command = "fixture-mcp"\n'
            '[projects."C:/fixture/project"]\n'
            'trust_level = "trusted"\n'
        ).encode()
        (codex_home / "config.toml").write_bytes(original_config)
        active = codex_home / "sessions" / "2026" / "07" / "active.jsonl"
        archived = codex_home / "archived_sessions" / "archived.jsonl"
        active.parent.mkdir(parents=True)
        archived.parent.mkdir(parents=True)
        active.write_bytes(
            b'{"id":"active-fixture","archived":false}\n'
            + b'{"type":"message","body":"fixture-long-line-'
            + b"x" * 128 * 1024
            + b'"}\n'
        )
        archived.write_bytes(
            b'{"id":"archived-fixture","archived":true}\n'
            b'{"type":"message","body":"fixture-archived"}\n'
        )
        if index_present:
            (codex_home / "session_index.jsonl").write_bytes(
                b'{"id":"active-fixture","path":"sessions/2026/07/active.jsonl"}\n'
            )
        database = codex_home / "state_5.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, archived INTEGER NOT NULL, cwd TEXT NOT NULL)"
            )
            connection.executemany(
                "INSERT INTO threads(id, archived, cwd) VALUES (?, ?, ?)",
                [
                    ("active-fixture", 0, "C:/fixture/project"),
                    ("archived-fixture", 1, "C:/fixture/other"),
                ],
            )
            connection.commit()
        return codex_home, original_config

    @staticmethod
    def _snapshot(codex_home: Path) -> dict[str, object]:
        file_hashes: dict[str, str] = {}
        for root_name in ("sessions", "archived_sessions"):
            root = codex_home / root_name
            for path in sorted(item for item in root.rglob("*") if item.is_file()):
                relative = path.relative_to(codex_home).as_posix()
                file_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        index = codex_home / "session_index.jsonl"
        database = codex_home / "state_5.sqlite"
        connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            rows = connection.execute(
                "SELECT id, archived, cwd FROM threads ORDER BY id"
            ).fetchall()
        finally:
            connection.close()
        return {
            "file_hashes": file_hashes,
            "paths": sorted(file_hashes),
            "index_present": index.exists(),
            "index_sha256": hashlib.sha256(index.read_bytes()).hexdigest() if index.exists() else None,
            "sqlite_sha256": hashlib.sha256(database.read_bytes()).hexdigest(),
            "sqlite_integrity": integrity,
            "sqlite_rows": rows,
        }

    def _host(self, root: Path) -> tuple[GatewayProcessHost, dict[str, object]]:
        primary = self._mock(
            ScriptedScenario(
                name="g8-primary-503",
                status=503,
                content_type="application/json",
                chunks=(b'{"private":"discard-primary"}',),
            ),
            "G8 P1",
        )
        backup = self._mock(text_scenario(text="G8_BACKUP_COMPLETE"), "G8 P2")
        data_port = _free_port()
        control_port = _free_port(excluding={data_port})
        document = _config_document(
            primary_url=primary.base_url,
            backup_url=backup.base_url,
            data_port=data_port,
            control_port=control_port,
        )
        document["instance_id"] = f"g8-{root.name}-instance"
        config = _write_fixture_install(root / "gateway-install", document)
        host = GatewayProcessHost(
            install_root=config.parents[2],
            config_path=config,
            protect=_protect,
            unprotect=_unprotect,
        )
        self.hosts.append(host)
        return host, document

    @staticmethod
    def _gateway_status(host: GatewayProcessHost, document: dict[str, object]) -> dict[str, object]:
        return {
            "ok": host.phase == "running",
            "phase": host.phase,
            "host": "127.0.0.1",
            "data_port": int(document["listen"]["data_port"]),
            "config_revision": int(document["active_group"]["revision"]),
            "instance_id": str(document["instance_id"]),
            "models_ready": host.phase == "running",
        }

    async def _request(self, host: GatewayProcessHost, document: dict[str, object]) -> bytes:
        async with aiohttp.ClientSession() as client:
            async with client.post(
                f"http://127.0.0.1:{document['listen']['data_port']}/v1/responses",
                data=fixture_request(),
                headers={
                    **_authorization(host.ingress_token),
                    "Content-Type": "application/json",
                },
            ) as response:
                body = await response.read()
                self.assertEqual(response.status, 200, body)
                return body

    async def test_activation_failover_restart_restore_preserves_all_chat_state(self) -> None:
        for index_present in (True, False):
            with self.subTest(index_present=index_present):
                case_root = self.root / ("with-index" if index_present else "without-index")
                codex_home, original_config = self._codex_fixture(
                    case_root.name,
                    index_present=index_present,
                )
                before = self._snapshot(codex_home)
                self.assertEqual(before["sqlite_integrity"], "ok")
                host, document = self._host(case_root)
                await host.start()
                coordinator = ProviderActivationCoordinator(
                    codex_home=codex_home,
                    data_dir=case_root / "guardian-data",
                    gateway_status=lambda: self._gateway_status(host, document),
                    auth_command=("guardian-helper", "gateway-ingress", "fixture-data"),
                )

                coordinator.activate(expected_revision=1)
                first_body = await self._request(host, document)
                self.assertIn(b"G8_BACKUP_COMPLETE", first_body)
                await host.close()

                restarted = GatewayProcessHost(
                    install_root=host.install_root,
                    config_path=host.config_path,
                    protect=_protect,
                    unprotect=_unprotect,
                )
                self.hosts.append(restarted)
                await restarted.start()
                coordinator._gateway_status = lambda: self._gateway_status(restarted, document)
                second_body = await self._request(restarted, document)
                self.assertIn(b"G8_BACKUP_COMPLETE", second_body)
                coordinator.restore()
                await restarted.close()

                after = self._snapshot(codex_home)
                self.assertEqual(after, before)
                self.assertEqual((codex_home / "config.toml").read_bytes(), original_config)
                primary, backup = self.mocks[-2:]
                self.assertEqual(primary.request_count, 1)
                self.assertEqual(backup.request_count, 2)
                protected_markers = (
                    b"fixture-long-line-",
                    b"fixture-archived",
                    b"active-fixture",
                )
                for path in host.install_root.rglob("*"):
                    if path.is_file():
                        payload = path.read_bytes()
                        for marker in protected_markers:
                            self.assertNotIn(marker, payload, str(path))

    async def test_resource_gate_bounds_1_10_50_100_concurrency_without_residue(self) -> None:
        for batch_size in (1, 10, 50, 100):
            with self.subTest(batch_size=batch_size):
                expected_active = min(batch_size, 4)
                expected_busy = batch_size - expected_active

                class BlockingRunner:
                    def __init__(self) -> None:
                        self.entered = 0
                        self.all_entered = asyncio.Event()
                        self.release = asyncio.Event()

                    async def run(self, _snapshot, _bearer, _cancellation):
                        self.entered += 1
                        if self.entered == expected_active:
                            self.all_entered.set()
                        await self.release.wait()
                        return AttemptResult(complete=_buffered())

                limits = GatewayLimits(max_concurrent_requests=4)
                runner = BlockingRunner()
                core = SingleRouteGatewayCore(runner, limits)

                async def proxy_one():
                    return await core.proxy(
                        fixture_request(),
                        {"content-type": "application/json"},
                        "fixture-bearer",
                        RecordingDownstream(),
                        CancellationToken(),
                        Committer(),
                    )

                admitted = [asyncio.create_task(proxy_one()) for _ in range(expected_active)]
                await asyncio.wait_for(runner.all_entered.wait(), timeout=1)
                self.assertEqual(core.active_requests, expected_active)

                rejected = await asyncio.gather(
                    *(proxy_one() for _ in range(expected_busy)),
                    return_exceptions=True,
                )
                self.assertEqual(len(rejected), expected_busy)
                self.assertTrue(
                    all(
                        isinstance(error, GatewayError)
                        and error.code == "guardian_gateway_busy"
                        for error in rejected
                    )
                )
                self.assertEqual(core.active_requests, expected_active)
                self.assertEqual(runner.entered, expected_active)

                runner.release.set()
                delivered = await asyncio.gather(*admitted)
                self.assertEqual(
                    [result.state for result in delivered],
                    [CommitState.DELIVERED] * expected_active,
                )
                self.assertEqual(core.active_requests, 0)

    async def test_sustained_batches_leave_no_capacity_or_task_residue_and_bound_journal(self) -> None:
        class YieldingRunner:
            def __init__(self) -> None:
                self.active = 0
                self.peak = 0
                self.total = 0

            async def run(self, _snapshot, _bearer, _cancellation):
                self.active += 1
                self.total += 1
                self.peak = max(self.peak, self.active)
                try:
                    await asyncio.sleep(0)
                    return AttemptResult(complete=_buffered())
                finally:
                    self.active -= 1

        runner = YieldingRunner()
        core = SingleRouteGatewayCore(runner, GatewayLimits(max_concurrent_requests=8))
        tasks_before = {task for task in asyncio.all_tasks() if not task.done()}

        async def proxy_one():
            return await core.proxy(
                fixture_request(),
                {"content-type": "application/json"},
                "fixture-bearer",
                RecordingDownstream(),
                CancellationToken(),
                Committer(),
            )

        for _round in range(50):
            results = await asyncio.gather(*(proxy_one() for _ in range(8)))
            self.assertEqual([result.state for result in results], [CommitState.DELIVERED] * 8)
            self.assertEqual(core.active_requests, 0)
            self.assertEqual(runner.active, 0)

        await asyncio.sleep(0)
        tasks_after = {task for task in asyncio.all_tasks() if not task.done()}
        self.assertFalse(tasks_after - tasks_before)
        self.assertEqual(runner.total, 400)
        self.assertEqual(runner.peak, 8)
        events = core.journal.snapshot()
        self.assertEqual(len(events), 256)
        self.assertTrue(
            all({"request_id", "event", "model", "status"} <= set(event) for event in events)
        )
        serialized = json.dumps(events, ensure_ascii=False).lower()
        for forbidden in ("authorization", "bearer ", "fixture-bearer", "prompt", "response"):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
