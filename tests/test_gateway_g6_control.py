from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import aiohttp

from gateway.app import GatewayProcessHost
from gateway.breaker import CircuitBreakerRegistry, RouteKey
from gateway.cancellation import CancellationToken
from gateway.config import RouteRole
from gateway.failures import FailureClassifier
from gateway.models import AttemptResult, GatewayLimits
from gateway.request_snapshot import create_request_snapshot
from gateway.runtime import AtomicFailoverRouterProvider
from gateway.secrets import InMemorySecretResolver
from gateway.secrets import ProtectedFileSecretResolver
from tests.gateway_probe_support import FAKE_BEARER, fixture_request
from tests.test_gateway_g5_lifecycle import (
    _authorization,
    _config_document,
    _free_port,
    _protect,
    _unprotect,
    _write_fixture_install,
)
from tests.test_gateway_router import ScriptedRunner, buffered, group, route


class GatewayG6ControlTransactionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hosts: list[GatewayProcessHost] = []

    async def asyncTearDown(self) -> None:
        for host in reversed(self.hosts):
            if host.phase not in {"created", "stopped"}:
                await host.close()
        self.temporary.cleanup()

    async def _start_host(
        self,
        name: str,
        *,
        prepared_config_ttl_seconds: float = 300.0,
        existing_config: Path | None = None,
    ) -> tuple[GatewayProcessHost, Path, dict[str, object]]:
        if existing_config is None:
            data_port = _free_port()
            control_port = _free_port(excluding={data_port})
            document = _config_document(
                primary_url="http://127.0.0.1:18001/v1",
                backup_url="http://127.0.0.1:18002/v1",
                data_port=data_port,
                control_port=control_port,
            )
            config_path = _write_fixture_install(self.root / name, document)
        else:
            config_path = existing_config
            document = json.loads(config_path.read_text(encoding="utf-8"))
        host = GatewayProcessHost(
            install_root=config_path.parents[2],
            config_path=config_path,
            protect=_protect,
            unprotect=_unprotect,
            prepared_config_ttl_seconds=prepared_config_ttl_seconds,
        )
        self.hosts.append(host)
        await host.start()
        profiles = host.install_root / "gateway" / "secrets" / "profiles"
        for profile_id in ("g5-primary", "g5-backup"):
            legacy = profiles / f"{profile_id}.dpapi"
            for revision in (2, 3):
                (profiles / f"{profile_id}.r{revision}.dpapi").write_bytes(
                    legacy.read_bytes()
                )
        return host, config_path, document

    @staticmethod
    def _candidate(document: dict[str, object], *, revision: int = 2) -> dict[str, object]:
        candidate = deepcopy(document)
        group_document = candidate["active_group"]
        assert isinstance(group_document, dict)
        group_document["revision"] = revision
        group_document["group_id"] = "2ffda5e2-4d16-46fe-9b7c-0d91286c2b8a"
        group_document["primary"]["secret_ref"] = f"profile:g5-primary:r{revision}"
        group_document["backup"]["secret_ref"] = f"profile:g5-backup:r{revision}"
        return candidate

    @staticmethod
    async def _post(
        client: aiohttp.ClientSession,
        url: str,
        host: GatewayProcessHost,
        payload: dict[str, object],
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object]]:
        request_headers = _authorization(host.control_token)
        if headers:
            request_headers.update(headers)
        async with client.post(url, json=payload, headers=request_headers) as response:
            return response.status, await response.json()

    async def test_prepare_activate_is_private_atomic_cross_group_and_idempotent(self) -> None:
        host, config_path, document = await self._start_host("happy")
        candidate = self._candidate(document)
        before = config_path.read_bytes()
        control_port = document["listen"]["control_port"]
        base = f"http://127.0.0.1:{control_port}/control/v1"
        prepare_url = f"{base}/config/prepare"
        activate_url = f"{base}/config/activate"

        async with aiohttp.ClientSession() as client:
            async with client.post(prepare_url, json=candidate) as response:
                self.assertEqual(response.status, 401)
            status, rejected = await self._post(
                client,
                prepare_url,
                host,
                candidate,
                headers={"Origin": "https://fixture.invalid"},
            )
            self.assertEqual(status, 403)
            self.assertEqual(
                rejected["error"]["code"],
                "guardian_control_browser_origin_rejected",
            )

            status, prepared = await self._post(client, prepare_url, host, candidate)
            self.assertEqual(status, 200)
            self.assertEqual(prepared["state"], "prepared")
            self.assertFalse(prepared["idempotent"])
            config_sha256 = prepared["config_sha256"]
            self.assertEqual(config_path.read_bytes(), before)
            pending_path = config_path.parent / "pending" / "prepared.json"
            self.assertTrue(pending_path.is_file())

            async with client.get(
                f"{base}/status",
                headers=_authorization(host.control_token),
            ) as response:
                public_status = await response.json()
            self.assertEqual(public_status["config_revision"], 1)
            self.assertEqual(
                public_status["prepared_config"],
                {"revision": 2, "config_sha256": config_sha256},
            )
            serialized_status = json.dumps(public_status, sort_keys=True)
            self.assertNotIn(host.control_token, serialized_status)
            self.assertNotIn("profile:g5-primary", serialized_status)
            self.assertNotIn(candidate["active_group"]["group_id"], serialized_status)

            status, repeated_prepare = await self._post(client, prepare_url, host, candidate)
            self.assertEqual(status, 200)
            self.assertTrue(repeated_prepare["idempotent"])

            conflicting = deepcopy(candidate)
            conflicting["active_group"]["primary"]["base_url"] = (
                "http://127.0.0.1:18003/v1"
            )
            status, conflict = await self._post(client, prepare_url, host, conflicting)
            self.assertEqual(status, 409)
            self.assertEqual(conflict["error"]["code"], "guardian_config_revision_conflict")

            status, mismatch = await self._post(
                client,
                activate_url,
                host,
                {"revision": 2, "config_sha256": "0" * 64},
            )
            self.assertEqual(status, 409)
            self.assertEqual(mismatch["error"]["code"], "guardian_config_hash_mismatch")
            self.assertEqual(config_path.read_bytes(), before)
            self.assertEqual(host.config.active_group.revision, 1)

            status, activated = await self._post(
                client,
                activate_url,
                host,
                {"revision": 2, "config_sha256": config_sha256},
            )
            self.assertEqual(status, 200)
            self.assertFalse(activated["idempotent"])
            self.assertEqual(host.config.active_group.revision, 2)
            self.assertEqual(host.config.active_group.group_id, candidate["active_group"]["group_id"])
            self.assertEqual(host._provider.current_config().revision, 2)
            self.assertFalse(pending_path.exists())

            status, repeated_activate = await self._post(
                client,
                activate_url,
                host,
                {"revision": 2, "config_sha256": config_sha256},
            )
            self.assertEqual(status, 200)
            self.assertTrue(repeated_activate["idempotent"])

            status, active_prepare = await self._post(client, prepare_url, host, candidate)
            self.assertEqual(status, 200)
            self.assertEqual(active_prepare["state"], "active")
            self.assertTrue(active_prepare["idempotent"])

            async with client.post(
                f"{base}/reload",
                headers=_authorization(host.control_token),
            ) as response:
                await response.read()
                self.assertEqual(response.status, 404)

    async def test_abort_requires_auth_and_exact_prepared_revision_and_hash(self) -> None:
        host, _config_path, document = await self._start_host("abort")
        candidate = self._candidate(document)
        control_port = document["listen"]["control_port"]
        base = f"http://127.0.0.1:{control_port}/control/v1/config"
        async with aiohttp.ClientSession() as client:
            status, prepared = await self._post(client, f"{base}/prepare", host, candidate)
            self.assertEqual(status, 200)
            async with client.post(
                f"{base}/abort",
                json={
                    "revision": 2,
                    "config_sha256": prepared["config_sha256"],
                },
            ) as response:
                self.assertEqual(response.status, 401)

            status, mismatch = await self._post(
                client,
                f"{base}/abort",
                host,
                {"revision": 2, "config_sha256": "0" * 64},
            )
            self.assertEqual(status, 409)
            self.assertEqual(mismatch["error"]["code"], "guardian_config_hash_mismatch")
            self.assertIsNotNone(host.status()["prepared_config"])

            status, aborted = await self._post(
                client,
                f"{base}/abort",
                host,
                {"revision": 2, "config_sha256": prepared["config_sha256"]},
            )
            self.assertEqual(status, 200)
            self.assertEqual(aborted["state"], "aborted")
            self.assertFalse(aborted["idempotent"])
            self.assertIsNone(host.status()["prepared_config"])

            status, repeated = await self._post(
                client,
                f"{base}/abort",
                host,
                {"revision": 2, "config_sha256": prepared["config_sha256"]},
            )
            self.assertEqual(status, 200)
            self.assertEqual(repeated["state"], "not_prepared")
            self.assertTrue(repeated["idempotent"])

    async def test_prepare_rejects_plaintext_refs_restart_fields_and_out_of_order_revision(self) -> None:
        host, _config_path, document = await self._start_host("validation")
        control_port = document["listen"]["control_port"]
        prepare_url = f"http://127.0.0.1:{control_port}/control/v1/config/prepare"

        cases: list[tuple[str, dict[str, object], str]] = []
        plaintext = self._candidate(document)
        plaintext["active_group"]["primary"]["secret_ref"] = "sk-plaintext-fixture"
        cases.append(("plaintext", plaintext, "guardian_config_secret_ref_invalid"))
        stale = self._candidate(document, revision=1)
        cases.append(("stale", stale, "guardian_config_revision_conflict"))
        wrong_instance = self._candidate(document)
        wrong_instance["instance_id"] = "different-instance"
        cases.append(("instance", wrong_instance, "guardian_config_instance_changed"))
        wrong_version = self._candidate(document)
        wrong_version["gateway_version"] = "v9.9.9"
        cases.append(("version", wrong_version, "guardian_config_version_changed"))
        wrong_port = self._candidate(document)
        wrong_port["listen"]["data_port"] = _free_port()
        cases.append(("port", wrong_port, "guardian_config_listen_changed"))
        arbitrary_path = self._candidate(document)
        arbitrary_path["config_path"] = "C:/outside/active.json"
        cases.append(("arbitrary-path", arbitrary_path, "guardian_config_invalid"))

        missing_credential = self._candidate(document)
        missing_credential["active_group"]["primary"]["secret_ref"] = (
            "profile:missing-profile:r2"
        )
        cases.append(
            (
                "missing-credential",
                missing_credential,
                "guardian_config_credential_unavailable",
            )
        )

        async with aiohttp.ClientSession() as client:
            for name, candidate, code in cases:
                with self.subTest(name=name):
                    status, body = await self._post(client, prepare_url, host, candidate)
                    self.assertIn(status, {400, 409})
                    self.assertEqual(body["error"]["code"], code)
        self.assertEqual(host.config.active_group.revision, 1)
        self.assertIsNone(host.status()["prepared_config"])

    async def test_prepared_candidate_survives_restart_without_becoming_active(self) -> None:
        first, config_path, document = await self._start_host(
            "restart",
            prepared_config_ttl_seconds=5,
        )
        candidate = self._candidate(document)
        control_port = document["listen"]["control_port"]
        prepare_url = f"http://127.0.0.1:{control_port}/control/v1/config/prepare"
        async with aiohttp.ClientSession() as client:
            status, prepared = await self._post(client, prepare_url, first, candidate)
        self.assertEqual(status, 200)
        active_before_restart = config_path.read_bytes()
        await first.close()

        restarted, _path, _document = await self._start_host(
            "restart",
            prepared_config_ttl_seconds=5,
            existing_config=config_path,
        )
        self.assertEqual(config_path.read_bytes(), active_before_restart)
        self.assertEqual(restarted.config.active_group.revision, 1)
        self.assertEqual(restarted._provider.current_config().revision, 1)
        self.assertEqual(restarted.status()["prepared_config"]["revision"], 2)

        activate_url = f"http://127.0.0.1:{control_port}/control/v1/config/activate"
        async with aiohttp.ClientSession() as client:
            status, activated = await self._post(
                client,
                activate_url,
                restarted,
                {"revision": 2, "config_sha256": prepared["config_sha256"]},
            )
        self.assertEqual(status, 200)
        self.assertEqual(activated["state"], "active")

    async def test_expired_and_failed_activation_keep_old_file_and_revision(self) -> None:
        host, config_path, document = await self._start_host("rollback")
        candidate = self._candidate(document)
        before = config_path.read_bytes()
        control_port = document["listen"]["control_port"]
        base = f"http://127.0.0.1:{control_port}/control/v1/config"
        async with aiohttp.ClientSession() as client:
            status, prepared = await self._post(client, f"{base}/prepare", host, candidate)
            self.assertEqual(status, 200)
            with patch.object(host._provider, "activate", side_effect=ValueError("fixture")):
                status, failed = await self._post(
                    client,
                    f"{base}/activate",
                    host,
                    {"revision": 2, "config_sha256": prepared["config_sha256"]},
                )
            self.assertEqual(status, 409)
            self.assertEqual(failed["error"]["code"], "guardian_config_activation_rejected")
            self.assertEqual(config_path.read_bytes(), before)
            self.assertEqual(host.config.active_group.revision, 1)
            self.assertEqual(host._provider.current_config().revision, 1)

            self.assertIsNotNone(host._prepared_config)
            host._prepared_config = replace(
                host._prepared_config,
                expires_at_monotonic=0.0,
                expires_at_epoch=0.0,
            )
            status, expired = await self._post(
                client,
                f"{base}/activate",
                host,
                {"revision": 2, "config_sha256": prepared["config_sha256"]},
            )
            self.assertEqual(status, 409)
            self.assertEqual(expired["error"]["code"], "guardian_config_prepare_expired")
        self.assertEqual(config_path.read_bytes(), before)
        self.assertEqual(host.config.active_group.revision, 1)

    async def test_rollback_write_failure_fails_closed(self) -> None:
        host, config_path, document = await self._start_host("rollback-fails-closed")
        candidate = self._candidate(document)
        control_port = document["listen"]["control_port"]
        base = f"http://127.0.0.1:{control_port}/control/v1/config"
        real_replace = __import__("os").replace
        replacements = 0

        def fail_second_config_replace(source, destination):
            nonlocal replacements
            if Path(destination).resolve() == config_path.resolve():
                replacements += 1
                if replacements == 2:
                    raise OSError("fixture rollback write failure")
            return real_replace(source, destination)

        async with aiohttp.ClientSession() as client:
            status, prepared = await self._post(client, f"{base}/prepare", host, candidate)
            self.assertEqual(status, 200)
            with patch.object(host._provider, "activate", side_effect=ValueError("fixture")), patch(
                "gateway.app.os.replace",
                side_effect=fail_second_config_replace,
            ):
                status, failed = await self._post(
                    client,
                    f"{base}/activate",
                    host,
                    {"revision": 2, "config_sha256": prepared["config_sha256"]},
                )
        self.assertEqual(status, 500)
        self.assertEqual(failed["error"]["code"], "guardian_config_rollback_failed")
        self.assertEqual(host.phase, "failed")
        self.assertFalse(host.status()["ok"])
        self.assertFalse(host._ingress.accepting)
        self.assertEqual(host._provider.current_config().revision, 1)


class CrossGroupRouterRetirementTests(unittest.IsolatedAsyncioTestCase):
    async def test_versioned_secret_refs_keep_old_credentials_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_secret = "fixture-old-secret-value"
            new_secret = "fixture-new-secret-value"
            (root / "profile-a.r1.dpapi").write_bytes(_protect(old_secret.encode()))
            (root / "profile-a.r2.dpapi").write_bytes(_protect(new_secret.encode()))
            resolver = ProtectedFileSecretResolver(root, unprotect=_unprotect)
            self.assertEqual(resolver.resolve("profile:profile-a:r1"), old_secret)
            self.assertEqual(resolver.resolve("profile:profile-a:r2"), new_secret)
            self.assertEqual(resolver.resolve("profile:profile-a:r1"), old_secret)

    async def test_credential_revision_changes_route_fingerprint(self) -> None:
        from gateway.lifecycle_config import parse_active_config

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = _config_document(
                primary_url="http://127.0.0.1:18001/v1",
                backup_url="http://127.0.0.1:18002/v1",
                data_port=_free_port(),
                control_port=_free_port(),
            )
            primary = document["active_group"]["primary"]
            primary["secret_ref"] = "profile:g5-primary:r1"
            first = parse_active_config(document, None, runner_factory=lambda *_args: ScriptedRunner())
            primary["secret_ref"] = "profile:g5-primary:r2"
            second = parse_active_config(document, None, runner_factory=lambda *_args: ScriptedRunner())

            self.assertNotEqual(
                first.active_group.primary.fingerprint,
                second.active_group.primary.fingerprint,
            )

    async def test_old_group_router_and_breakers_live_until_lease_release(self) -> None:
        old_config = group(
            route(
                RouteRole.PRIMARY,
                "p1",
                ScriptedRunner(AttemptResult(complete=buffered("old-primary"))),
                fingerprint="old-primary-fingerprint",
            ),
            route(
                RouteRole.BACKUP,
                "p2",
                ScriptedRunner(AttemptResult(complete=buffered("old-backup"))),
                fingerprint="old-backup-fingerprint",
            ),
        )
        new_config = replace(
            group(
                route(
                    RouteRole.PRIMARY,
                    "p3",
                    ScriptedRunner(AttemptResult(complete=buffered("new-primary"))),
                    fingerprint="new-primary-fingerprint",
                ),
                route(
                    RouteRole.BACKUP,
                    "p4",
                    ScriptedRunner(AttemptResult(complete=buffered("new-backup"))),
                    fingerprint="new-backup-fingerprint",
                ),
                revision=2,
            ),
            group_id="group-2",
        )
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        provider = AtomicFailoverRouterProvider(
            old_config,
            breaker,
            FailureClassifier(),
            InMemorySecretResolver(
                {
                    "secret:p1": FAKE_BEARER,
                    "secret:p2": FAKE_BEARER,
                    "secret:p3": FAKE_BEARER,
                    "secret:p4": FAKE_BEARER,
                }
            ),
        )
        old_lease = provider.acquire()
        provider.activate(new_config)
        self.assertEqual(provider.current_config().group_id, "group-2")
        self.assertEqual({item.route_key.group_id for item in breaker.snapshots()}, {"group-2"})

        old_primary_key = RouteKey("instance-1", "group-1", "primary", "p1")
        self.assertIsNotNone(
            breaker.snapshot_version(
                old_primary_key,
                config_revision=1,
                route_fingerprint="old-primary-fingerprint",
            )
        )
        request = create_request_snapshot(
            fixture_request(),
            {"content-type": "application/json"},
            GatewayLimits(),
        )
        result = await old_lease.router.execute(request, CancellationToken())
        self.assertEqual(result.complete.response_id, "old-primary")
        old_lease.release()
        self.assertIsNone(
            breaker.snapshot_version(
                old_primary_key,
                config_revision=1,
                route_fingerprint="old-primary-fingerprint",
            )
        )
        self.assertEqual(breaker.active_pin_count(), 0)


if __name__ == "__main__":
    unittest.main()
