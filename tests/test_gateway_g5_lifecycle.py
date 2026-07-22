from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import aiohttp
from aiohttp import web

from gateway.app import GatewayHostError, GatewayProcessHost
from gateway.cleanup import SpoolCleanupError, cleanup_registered_spool
from gateway.dpapi import protect_current_user, unprotect_current_user
from gateway.file_journal import RotatingAllowlistJournal
from gateway.health import DiskWatermark
from gateway.lifecycle_config import ActiveConfigError, load_active_config
from gateway.runtime_files import (
    RuntimeDescriptor,
    RuntimeDescriptorStore,
    RuntimeOwnerVerificationError,
    verify_runtime_owner,
)
from gateway.singleton import SingletonAlreadyRunning
from gateway.tokens import ProtectedTokenStore, read_gateway_ingress_token, read_gateway_token
from tests.gateway_probe_support import (
    FAKE_BEARER,
    FIXTURE_MODEL,
    ProgrammableResponsesMock,
    ScriptedScenario,
    fixture_request,
    text_scenario,
)


VERSION = "v1.7.0"


def _protect(value: bytes) -> bytes:
    return b"G5-FIXTURE\x00" + bytes(byte ^ 0xA5 for byte in value)


def _unprotect(value: bytes) -> bytes:
    prefix = b"G5-FIXTURE\x00"
    if not value.startswith(prefix):
        raise ValueError("fixture_ciphertext_invalid")
    return bytes(byte ^ 0xA5 for byte in value[len(prefix) :])


def _free_port(*, excluding: set[int] | None = None) -> int:
    blocked = excluding or set()
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])
        if port >= 1024 and port not in blocked:
            return port


def _config_document(
    *,
    primary_url: str,
    backup_url: str,
    data_port: int,
    control_port: int,
    revision: int = 1,
    minimum_free_bytes: int = 1024 * 1024,
) -> dict[str, object]:
    route_common = {
        "adapter_name": "openai-responses-v1",
        "enabled": True,
    }
    return {
        "schema_version": 1,
        "instance_id": "g5-fixture-instance",
        "gateway_version": VERSION,
        "listen": {
            "host": "127.0.0.1",
            "data_port": data_port,
            "control_port": control_port,
        },
        "limits": {
            "max_request_bytes": 1024 * 1024,
            "max_response_bytes": 1024 * 1024,
            "read_chunk_bytes": 4096,
            "max_concurrent_requests": 4,
            "connect_timeout_seconds": 1,
            "first_byte_timeout_seconds": 1,
            "idle_timeout_seconds": 2,
            "total_timeout_seconds": 5,
        },
        "lifecycle": {
            "minimum_free_bytes": minimum_free_bytes,
            "drain_timeout_seconds": 2,
        },
        "active_group": {
            "revision": revision,
            "group_id": "g5-fixture-group",
            "primary": {
                **route_common,
                "profile_id": "g5-primary",
                "base_url": primary_url,
                "secret_ref": "profile:g5-primary",
                "secret_suffix": "P1",
            },
            "backup": {
                **route_common,
                "profile_id": "g5-backup",
                "base_url": backup_url,
                "secret_ref": "profile:g5-backup",
                "secret_suffix": "P2",
            },
            "allowed_models": [FIXTURE_MODEL],
            "breaker_policy": {
                "failure_threshold": 1,
                "protocol_failure_threshold": 1,
                "error_rate_threshold": None,
                "minimum_samples": 1,
                "window_size": 8,
                "recovery_success_threshold": 1,
                "base_cooldown_seconds": 30,
                "max_cooldown_seconds": 300,
                "jitter_ratio": 0,
            },
            "probe_policy": {
                "enabled": False,
                "mode": "models",
                "interval_seconds": 30,
                "timeout_seconds": 1,
                "allow_billable": False,
                "allow_action_required_auto_retest": False,
            },
            "state_compatibility": {},
        },
    }


def _write_fixture_install(
    root: Path,
    document: dict[str, object],
) -> Path:
    version_root = root / "gateway" / "versions" / VERSION
    version_root.mkdir(parents=True)
    (version_root / ".guardian-release.json").write_text("{}\n", encoding="utf-8")
    current = {
        "schema_version": 1,
        "version": VERSION,
        "relative_path": f"gateway/versions/{VERSION}",
    }
    (root / "gateway" / "current.json").write_text(
        json.dumps(current, sort_keys=True),
        encoding="utf-8",
    )
    config_path = root / "gateway" / "config" / "active.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    profiles = root / "gateway" / "secrets" / "profiles"
    profiles.mkdir(parents=True)
    for profile_id in ("g5-primary", "g5-backup"):
        (profiles / f"{profile_id}.dpapi").write_bytes(_protect(FAKE_BEARER.encode("ascii")))
    return config_path


def _authorization(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


class LifecyclePrimitiveTests(unittest.IsolatedAsyncioTestCase):
    async def test_active_config_is_loopback_fixed_and_rejects_unsafe_shapes(self) -> None:
        data_port = _free_port()
        control_port = _free_port(excluding={data_port})
        document = _config_document(
            primary_url="http://127.0.0.1:18001/v1",
            backup_url="http://127.0.0.1:18002/v1",
            data_port=data_port,
            control_port=control_port,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "active.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            async with aiohttp.ClientSession() as session:
                parsed = load_active_config(path, session)
                self.assertEqual(parsed.host, "127.0.0.1")
                self.assertEqual((parsed.data_port, parsed.control_port), (data_port, control_port))

                compatible = json.loads(json.dumps(document))
                compatible["active_group"]["primary"]["protocol_compatibility"] = {
                    "allow_terminal_output_missing_item_ids": True,
                    "allow_terminal_output_missing_item_status": True,
                    "allow_function_call_arguments_done_missing_name": True,
                }
                path.write_text(json.dumps(compatible), encoding="utf-8")
                compatible_parsed = load_active_config(path, session)
                self.assertTrue(
                    compatible_parsed.active_group.primary.protocol_compatibility[
                        "allow_terminal_output_missing_item_ids"
                    ]
                )
                self.assertTrue(
                    compatible_parsed.active_group.primary.protocol_compatibility[
                        "allow_function_call_arguments_done_missing_name"
                    ]
                )
                self.assertNotEqual(
                    parsed.active_group.primary.fingerprint,
                    compatible_parsed.active_group.primary.fingerprint,
                )

                invalid_compatibility = json.loads(json.dumps(document))
                invalid_compatibility["active_group"]["primary"][
                    "protocol_compatibility"
                ] = {"allow_unknown_relaxation": True}
                path.write_text(
                    json.dumps(invalid_compatibility), encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    ActiveConfigError, "protocol_compatibility_invalid"
                ):
                    load_active_config(path, session)

                unsafe = json.loads(json.dumps(document))
                unsafe["listen"]["host"] = "0.0.0.0"
                path.write_text(json.dumps(unsafe), encoding="utf-8")
                with self.assertRaisesRegex(ActiveConfigError, "loopback"):
                    load_active_config(path, session)

                same_port = json.loads(json.dumps(document))
                same_port["listen"]["control_port"] = data_port
                path.write_text(json.dumps(same_port), encoding="utf-8")
                with self.assertRaisesRegex(ActiveConfigError, "ports_must_be_distinct"):
                    load_active_config(path, session)

    async def test_tokens_are_distinct_encrypted_stable_and_rotatable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ProtectedTokenStore(root, protect=_protect, unprotect=_unprotect)
            first = dict(store.ensure())
            second = dict(store.ensure())
            self.assertEqual(first, second)
            self.assertNotEqual(first["ingress"], first["control"])
            for purpose, value in first.items():
                ciphertext = (root / f"{purpose}.token.dpapi").read_bytes()
                self.assertNotIn(value.encode("ascii"), ciphertext)
            rotated = store.rotate("control")
            self.assertNotEqual(rotated, first["control"])
            self.assertEqual(store.ensure()["ingress"], first["ingress"])
            self.assertEqual(store.ensure()["control"], rotated)

    async def test_fixed_provider_helper_reads_only_existing_ingress_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token_dir = root / "gateway" / "secrets" / "tokens"
            store = ProtectedTokenStore(token_dir, protect=_protect, unprotect=_unprotect)
            values = dict(store.ensure())
            self.assertEqual(
                read_gateway_ingress_token(root, unprotect=_unprotect),
                values["ingress"],
            )
            self.assertEqual(
                read_gateway_token(root, "control", unprotect=_unprotect),
                values["control"],
            )
            self.assertNotEqual(values["ingress"], values["control"])
            (token_dir / "ingress.token.dpapi").unlink()
            with self.assertRaises(FileNotFoundError):
                read_gateway_ingress_token(root, unprotect=_unprotect)
            self.assertFalse((token_dir / "ingress.token.dpapi").exists())

    async def test_runtime_descriptor_contains_only_hashes_and_owner_removal_is_guarded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.json"
            descriptor = RuntimeDescriptor(
                schema_version=1,
                instance_id="fixture-instance",
                process_instance_id="fixture-process",
                pid=os.getpid(),
                process_started_at="2026-07-12T00:00:00+00:00",
                gateway_started_at="2026-07-12T00:00:01+00:00",
                version=VERSION,
                executable_path=str(Path(sys.executable).resolve()),
                host="127.0.0.1",
                data_port=42001,
                control_port=42002,
                control_endpoint="http://127.0.0.1:42002",
                config_revision=1,
                config_sha256="1" * 64,
                ingress_token_sha256="2" * 64,
                control_token_sha256="3" * 64,
            )
            store = RuntimeDescriptorStore(path)
            store.write(descriptor)
            serialized = path.read_text(encoding="utf-8").lower()
            for forbidden in ("authorization", "bearer ", "cookie", FAKE_BEARER.lower()):
                self.assertNotIn(forbidden, serialized)
            self.assertEqual(store.read(), descriptor)
            self.assertFalse(store.remove_if_owned("different-process"))
            self.assertTrue(path.exists())
            self.assertTrue(store.remove_if_owned("fixture-process"))
            self.assertFalse(path.exists())
            with self.assertRaisesRegex(ValueError, "tokens_must_be_distinct"):
                replace(descriptor, control_token_sha256=descriptor.ingress_token_sha256)

    async def test_runtime_owner_verifier_requires_process_identity_and_control_handshake(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = Path(sys.executable).resolve()
            token = "fixture-control-token"
            control_port = _free_port()
            descriptor = RuntimeDescriptor(
                schema_version=1,
                instance_id="fixture-instance",
                process_instance_id="fixture-process",
                pid=os.getpid(),
                process_started_at="2026-07-12T00:00:00+00:00",
                gateway_started_at="2026-07-12T00:00:01+00:00",
                version=VERSION,
                executable_path=str(executable),
                host="127.0.0.1",
                data_port=_free_port(excluding={control_port}),
                control_port=control_port,
                control_endpoint=f"http://127.0.0.1:{control_port}",
                config_revision=7,
                config_sha256="1" * 64,
                ingress_token_sha256="2" * 64,
                control_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            )
            store = RuntimeDescriptorStore(root / "runtime.json")
            store.write(descriptor)

            async def status(request: web.Request) -> web.Response:
                self.assertEqual(request.headers["Authorization"], f"Bearer {token}")
                return web.json_response(
                    {
                        "ok": True,
                        "instance_id": descriptor.instance_id,
                        "process_instance_id": descriptor.process_instance_id,
                        "pid": descriptor.pid,
                        "process_started_at": descriptor.process_started_at,
                        "version": descriptor.version,
                        "executable_path": descriptor.executable_path,
                        "control_port": descriptor.control_port,
                        "config_revision": descriptor.config_revision,
                    }
                )

            app = web.Application()
            app.router.add_get("/control/v1/status", status)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", control_port)
            await site.start()
            try:
                async with aiohttp.ClientSession() as session:
                    verified = await verify_runtime_owner(
                        store,
                        control_token=token,
                        expected_executable=executable,
                        expected_version=VERSION,
                        expected_revision=7,
                        session=session,
                        process_identity_reader=lambda _pid: (
                            str(executable),
                            descriptor.process_started_at,
                        ),
                    )
                    self.assertEqual(verified.descriptor, descriptor)
                    with self.assertRaisesRegex(
                        RuntimeOwnerVerificationError,
                        "process_start_mismatch",
                    ):
                        await verify_runtime_owner(
                            store,
                            control_token=token,
                            expected_executable=executable,
                            expected_version=VERSION,
                            expected_revision=7,
                            session=session,
                            process_identity_reader=lambda _pid: (
                                str(executable),
                                "2026-07-12T00:00:03+00:00",
                            ),
                        )
                    with self.assertRaisesRegex(
                        RuntimeOwnerVerificationError,
                        "control_token_mismatch",
                    ):
                        await verify_runtime_owner(
                            store,
                            control_token="wrong-token",
                            expected_executable=executable,
                            expected_version=VERSION,
                            expected_revision=7,
                            session=session,
                            process_identity_reader=lambda _pid: (
                                str(executable),
                                descriptor.process_started_at,
                            ),
                        )
            finally:
                await runner.cleanup()

    @unittest.skipUnless(os.name == "nt", "Windows current-user DPAPI")
    async def test_current_user_dpapi_round_trip_uses_real_windows_context(self) -> None:
        canary = secrets.token_bytes(64)
        protected = protect_current_user(canary)
        self.assertNotEqual(protected, canary)
        self.assertNotIn(canary, protected)
        self.assertEqual(unprotect_current_user(protected), canary)

    async def test_spool_cleanup_is_registry_bounded_and_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spool = root / "spool"
            spool.mkdir()
            registered = spool / ("a" * 32 + ".spool")
            unregistered = spool / ("b" * 32 + ".spool")
            registered.write_bytes(b"registered")
            unregistered.write_bytes(b"unregistered")
            registry = spool / "active.json"
            registry.write_text(
                json.dumps({"schema_version": 1, "files": [registered.name]}),
                encoding="utf-8",
            )
            self.assertEqual(cleanup_registered_spool(spool, registry), 1)
            self.assertFalse(registered.exists())
            self.assertTrue(unregistered.exists())
            registry.write_text(
                json.dumps({"schema_version": 1, "files": ["../outside.spool"]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SpoolCleanupError, "entry_invalid"):
                cleanup_registered_spool(spool, registry)
            self.assertTrue(unregistered.exists())

    async def test_disk_watermark_fails_closed_when_low_or_unknown(self) -> None:
        watermark = DiskWatermark(Path.cwd(), 1024)
        with patch("gateway.health.shutil.disk_usage", return_value=SimpleNamespace(free=1023)):
            error = watermark.admission_error()
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "guardian_disk_low_watermark")
        with patch("gateway.health.shutil.disk_usage", side_effect=OSError("fixture")):
            error = watermark.admission_error()
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "guardian_disk_status_unavailable")

    async def test_file_journal_enforces_allowlist_and_rotates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = RotatingAllowlistJournal(path, max_bytes=160, backups=1, memory_capacity=4)
            event = {
                "event": "gateway_started",
                "status": "running",
                "timestamp": "2026-07-12T00:00:00+00:00",
            }
            journal.append(event)
            journal.append({**event, "event": "gateway_stopped"})
            self.assertTrue(path.exists())
            self.assertTrue(path.with_suffix(".jsonl.1").exists())
            with self.assertRaisesRegex(ValueError, "schema_violation"):
                journal.append({**event, "authorization": "fixture-secret"})


class GatewayProcessLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.mocks: list[ProgrammableResponsesMock] = []
        self.hosts: list[GatewayProcessHost] = []
        self.tasks: list[asyncio.Task[None]] = []

    async def asyncTearDown(self) -> None:
        for host in reversed(self.hosts):
            if host.phase not in {"created", "stopped", "failed"}:
                await host.close()
        for task in reversed(self.tasks):
            if not task.done():
                task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        for mock in reversed(self.mocks):
            mock.close()
        self.temporary.cleanup()

    def _start_mock(self, scenario: ScriptedScenario, name: str) -> ProgrammableResponsesMock:
        mock = ProgrammableResponsesMock(lambda _request: scenario, route_name=name).start()
        self.mocks.append(mock)
        return mock

    def _install(
        self,
        primary: ProgrammableResponsesMock,
        backup: ProgrammableResponsesMock,
        *,
        root_name: str,
        revision: int = 1,
    ) -> tuple[Path, dict[str, object]]:
        data_port = _free_port()
        control_port = _free_port(excluding={data_port})
        document = _config_document(
            primary_url=primary.base_url,
            backup_url=backup.base_url,
            data_port=data_port,
            control_port=control_port,
            revision=revision,
        )
        root = self.root / root_name
        config = _write_fixture_install(root, document)
        return config, document

    def _new_host(self, config: Path) -> GatewayProcessHost:
        host = GatewayProcessHost(
            install_root=config.parents[2],
            config_path=config,
            protect=_protect,
            unprotect=_unprotect,
        )
        self.hosts.append(host)
        return host

    async def _run_host(self, host: GatewayProcessHost) -> asyncio.Task[None]:
        task = asyncio.create_task(host.run())
        self.tasks.append(task)
        for _ in range(200):
            if host.phase == "running":
                return task
            if task.done():
                await task
            await asyncio.sleep(0.01)
        self.fail("gateway_host_start_timeout")

    async def test_independent_host_auth_drain_resume_stop_and_no_secret_artifacts(self) -> None:
        primary = self._start_mock(text_scenario(text="G5_PRIMARY_OK"), "P1")
        backup = self._start_mock(text_scenario(text="G5_BACKUP_UNUSED"), "P2")
        config, document = self._install(primary, backup, root_name="host-lifecycle")
        host = self._new_host(config)
        run_task = await self._run_host(host)
        self.assertIsNotNone(host._session)
        self.assertIsInstance(host._session.connector._ssl, ssl.SSLContext)
        data_port = document["listen"]["data_port"]
        control_port = document["listen"]["control_port"]
        descriptor_path = host.install_root / "gateway" / "runtime" / "runtime.json"
        descriptor = RuntimeDescriptorStore(descriptor_path).read()
        self.assertEqual((descriptor.data_port, descriptor.control_port), (data_port, control_port))
        self.assertEqual(descriptor.config_revision, 1)
        self.assertNotEqual(descriptor.ingress_token_sha256, descriptor.control_token_sha256)

        async with aiohttp.ClientSession() as client:
            health_url = f"http://127.0.0.1:{data_port}/health"
            status_url = f"http://127.0.0.1:{control_port}/control/v1/status"
            async with client.get(health_url) as response:
                self.assertEqual(response.status, 401)
            async with client.get(health_url, headers=_authorization(host.control_token)) as response:
                self.assertEqual(response.status, 401)
            async with client.get(health_url, headers=_authorization(host.ingress_token)) as response:
                health = await response.json()
                self.assertEqual(response.status, 200)
                self.assertEqual(health["phase"], "running")
                self.assertEqual(health["config_revision"], 1)
            for method, url in (
                ("GET", health_url),
                ("GET", f"http://127.0.0.1:{data_port}/v1/models"),
                ("POST", f"http://127.0.0.1:{data_port}/v1/responses"),
                ("OPTIONS", f"http://127.0.0.1:{data_port}/v1/responses"),
            ):
                async with client.request(
                    method,
                    url,
                    headers={
                        **_authorization(host.ingress_token),
                        "Origin": "https://fixture.invalid",
                        "Access-Control-Request-Method": "POST",
                    },
                ) as response:
                    rejected = await response.json()
                    self.assertEqual(response.status, 403, (method, url, rejected))
                    self.assertEqual(
                        rejected["error"]["code"],
                        "guardian_browser_origin_rejected",
                    )
            async with client.get(status_url, headers=_authorization(host.ingress_token)) as response:
                self.assertEqual(response.status, 401)
            async with client.get(
                status_url,
                headers={**_authorization(host.control_token), "Origin": "https://fixture.invalid"},
            ) as response:
                self.assertEqual(response.status, 403)

            response_url = f"http://127.0.0.1:{data_port}/v1/responses"
            async with client.post(
                response_url,
                data=fixture_request(),
                headers={**_authorization(host.ingress_token), "Content-Type": "application/json"},
            ) as response:
                body = await response.read()
                self.assertEqual(response.status, 200)
                self.assertIn(b"response.completed", body)
            self.assertEqual((primary.request_count, backup.request_count), (1, 0))

            drain_url = f"http://127.0.0.1:{control_port}/control/v1/drain"
            async with client.post(
                drain_url,
                json={"timeout_seconds": 1},
                headers=_authorization(host.control_token),
            ) as response:
                drained = await response.json()
                self.assertEqual(response.status, 200)
                self.assertTrue(drained["ok"])
                self.assertEqual(drained["phase"], "draining")
            async with client.post(
                response_url,
                data=fixture_request(),
                headers={**_authorization(host.ingress_token), "Content-Type": "application/json"},
            ) as response:
                rejected = await response.json()
                self.assertEqual(response.status, 503)
                self.assertEqual(rejected["error"]["code"], "guardian_gateway_draining")
            self.assertEqual((primary.request_count, backup.request_count), (1, 0))

            resume_url = f"http://127.0.0.1:{control_port}/control/v1/resume"
            async with client.post(resume_url, headers=_authorization(host.control_token)) as response:
                resumed = await response.json()
                self.assertEqual(response.status, 200)
                self.assertEqual(resumed["phase"], "running")
            async with client.post(
                response_url,
                data=fixture_request(),
                headers={**_authorization(host.ingress_token), "Content-Type": "application/json"},
            ) as response:
                await response.read()
                self.assertEqual(response.status, 200)
            self.assertEqual((primary.request_count, backup.request_count), (2, 0))

            stop_url = f"http://127.0.0.1:{control_port}/control/v1/stop"
            async with client.post(
                stop_url,
                json={"timeout_seconds": 1},
                headers=_authorization(host.control_token),
            ) as response:
                stopped = await response.json()
                self.assertEqual(response.status, 202)
                self.assertEqual(stopped["phase"], "stopping")

        await asyncio.wait_for(run_task, timeout=5)
        self.assertEqual(host.phase, "stopped")
        self.assertFalse(descriptor_path.exists())
        for port in (data_port, control_port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", port))

        forbidden = (FAKE_BEARER.encode("ascii"), b"Synthetic G2 prompt")
        for path in host.install_root.rglob("*"):
            if path.is_file():
                payload = path.read_bytes()
                for value in forbidden:
                    self.assertNotIn(value, payload, str(path))

    async def test_single_instance_and_port_conflict_fail_without_port_drift(self) -> None:
        primary = self._start_mock(text_scenario(text="G5_PRIMARY_OK"), "P1")
        backup = self._start_mock(text_scenario(text="G5_BACKUP_OK"), "P2")
        config, document = self._install(primary, backup, root_name="single-instance")
        first = self._new_host(config)
        await first.start()
        second = self._new_host(config)
        with self.assertRaises(SingletonAlreadyRunning):
            await second.start()
        self.assertEqual(first.phase, "running")
        await first.close()

        conflict_config, conflict_document = self._install(
            primary,
            backup,
            root_name="port-conflict",
        )
        conflict_port = int(conflict_document["listen"]["data_port"])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(("127.0.0.1", conflict_port))
            occupied.listen(1)
            blocked = self._new_host(conflict_config)
            with self.assertRaisesRegex(GatewayHostError, f"port_conflict:{conflict_port}"):
                await blocked.start()
            self.assertEqual(blocked.phase, "failed")
            self.assertFalse((blocked.install_root / "gateway" / "runtime" / "runtime.json").exists())
        recovered = self._new_host(conflict_config)
        await recovered.start()
        self.assertEqual(recovered.config.data_port, conflict_port)
        await recovered.close()

    async def test_restart_reuses_tokens_and_restores_action_required_breaker(self) -> None:
        auth_failure = ScriptedScenario(
            name="auth-rejected",
            status=401,
            content_type="application/json",
            chunks=(b'{"error":{"type":"fixture_auth_rejected"}}',),
        )
        primary = self._start_mock(auth_failure, "P1")
        backup = self._start_mock(text_scenario(text="G5_BACKUP_OK"), "P2")
        config, document = self._install(primary, backup, root_name="restart-state")
        first = self._new_host(config)
        await first.start()
        first_tokens = (first.ingress_token, first.control_token)
        response_url = f"http://127.0.0.1:{document['listen']['data_port']}/v1/responses"
        async with aiohttp.ClientSession() as client:
            async with client.post(
                response_url,
                data=fixture_request(),
                headers={**_authorization(first.ingress_token), "Content-Type": "application/json"},
            ) as response:
                body = await response.read()
                self.assertEqual(response.status, 200)
                self.assertIn(b"response.completed", body)
        self.assertEqual((primary.request_count, backup.request_count), (1, 1))
        state_path = first.install_root / "gateway" / "state" / "breaker.json"
        self.assertTrue(state_path.is_file())
        state_before = state_path.read_bytes()
        self.assertIn(b"open_action_required", state_before)
        await first.close()

        second = self._new_host(config)
        await second.start()
        self.assertEqual((second.ingress_token, second.control_token), first_tokens)
        self.assertEqual(second._provider.restored_routes, 2)
        async with aiohttp.ClientSession() as client:
            async with client.post(
                response_url,
                data=fixture_request(),
                headers={**_authorization(second.ingress_token), "Content-Type": "application/json"},
            ) as response:
                await response.read()
                self.assertEqual(response.status, 200)
        self.assertEqual((primary.request_count, backup.request_count), (1, 2))
        restored = json.loads(state_path.read_text(encoding="utf-8"))
        route_states = {
            (route["route_role"], route["state"])
            for route in restored["routes"]
        }
        self.assertIn(("primary", "open_action_required"), route_states)
        self.assertIn(("backup", "closed"), route_states)
        await second.close()


if __name__ == "__main__":
    unittest.main()
