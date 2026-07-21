from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from backend.failover import (
    AtomicFailoverDocumentStore,
    FailoverConflictError,
    FailoverManagementService,
    FailoverPublishError,
    FailoverStoreError,
)
from backend.gateway_controller import ProductionGatewayController
from gateway.app import GatewayProcessHost
from tests.gateway_probe_support import FAKE_BEARER
from tests.test_gateway_g5_lifecycle import (
    _config_document,
    _free_port,
    _protect,
    _unprotect,
    _write_fixture_install,
)


class ProductionGatewayControllerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        data_port = _free_port()
        control_port = _free_port(excluding={data_port})
        self.document = _config_document(
            primary_url="http://127.0.0.1:18001/v1",
            backup_url="http://127.0.0.1:18002/v1",
            data_port=data_port,
            control_port=control_port,
        )
        self.config_path = _write_fixture_install(self.root, self.document)
        self.host = GatewayProcessHost(
            install_root=self.root,
            config_path=self.config_path,
            protect=_protect,
            unprotect=_unprotect,
        )
        await self.host.start()
        self.profile_ciphertexts = {
            "api-primary": _protect(b"fixture-production-primary"),
            "api-backup": _protect(b"fixture-production-backup"),
        }
        self.controller = ProductionGatewayController(
            install_root=self.root,
            expected_executable=Path(__import__("sys").executable),
            expected_version=str(self.document["gateway_version"]),
            credential_source=self.profile_ciphertexts.__getitem__,
            unprotect=_unprotect,
            process_identity_reader=lambda pid: (
                str(Path(__import__("sys").executable).resolve()),
                self.host.status()["process_started_at"],
            ) if pid == self.host.status()["pid"] else None,
        )

    async def asyncTearDown(self) -> None:
        if self.host.phase not in {"created", "stopped"}:
            await self.host.close()
        self.temporary.cleanup()

    def candidate(self, *, revision: int = 2) -> dict[str, object]:
        return {
            "schema_version": 1,
            "revision": revision,
            "instance_id": self.document["instance_id"],
            "group_id": "2ffda5e2-4d16-46fe-9b7c-0d91286c2b8a",
            "allowed_models": list(self.document["active_group"]["allowed_models"]),
            "adapter_name": "openai-responses-v1",
            "primary": {
                "profile_id": "api-primary",
                "base_url": "http://127.0.0.1:18003/v1",
                "credential_revision": revision,
                "protocol_compatibility": {
                    "allow_terminal_output_omission": False,
                    "allow_terminal_output_missing_item_ids": True,
                    "allow_terminal_output_missing_item_status": True,
                    "allow_function_call_arguments_done_missing_name": True,
                },
            },
            "backup": {
                "profile_id": "api-backup",
                "base_url": "http://127.0.0.1:18004/v1",
                "credential_revision": revision,
                "protocol_compatibility": {
                    "allow_terminal_output_omission": True,
                    "allow_terminal_output_missing_item_ids": False,
                    "allow_terminal_output_missing_item_status": False,
                    "allow_function_call_arguments_done_missing_name": False,
                },
            },
            "breaker_policy": dict(self.document["active_group"]["breaker_policy"]),
            "probe_policy": dict(self.document["active_group"]["probe_policy"]),
        }

    def credential_path(self, profile_id: str, revision: int = 2) -> Path:
        return self.root / "gateway" / "secrets" / "profiles" / f"{profile_id}.r{revision}.dpapi"

    async def test_prepare_activate_uses_verified_loopback_and_versioned_ciphertexts(self) -> None:
        prepared = await asyncio.to_thread(self.controller.prepare, self.candidate())
        self.assertEqual(prepared.revision, 2)
        self.assertEqual(self.host.status()["prepared_config"]["revision"], 2)
        for profile_id in self.profile_ciphertexts:
            target = self.credential_path(profile_id)
            self.assertEqual(target.read_bytes(), self.profile_ciphertexts[profile_id])
            self.assertNotIn(FAKE_BEARER.encode(), target.read_bytes())

        receipt = await asyncio.to_thread(self.controller.activate, prepared)
        self.assertEqual((receipt.previous_revision, receipt.revision), (1, 2))
        self.assertEqual(self.host.status()["config_revision"], 2)
        active = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(active["active_group"]["primary"]["secret_ref"], "profile:api-primary:r2")
        self.assertTrue(
            active["active_group"]["primary"]["protocol_compatibility"][
                "allow_terminal_output_missing_item_status"
            ]
        )
        self.assertTrue(
            active["active_group"]["primary"]["protocol_compatibility"][
                "allow_function_call_arguments_done_missing_name"
            ]
        )
        self.assertTrue(
            active["active_group"]["backup"]["protocol_compatibility"][
                "allow_terminal_output_omission"
            ]
        )
        self.assertNotIn("fixture-production-primary", json.dumps(active))
        snapshot = await asyncio.to_thread(self.controller.snapshot)
        self.assertEqual(snapshot["source"], "production")
        self.assertEqual(snapshot["config_revision"], 2)
        self.assertNotIn("control", json.dumps(snapshot).lower())

    async def test_production_snapshot_events_and_management_source_are_redacted(self) -> None:
        snapshot = await asyncio.to_thread(self.controller.snapshot)
        events = await asyncio.to_thread(self.controller.events)
        serialized = json.dumps({"snapshot": snapshot, "events": events}, sort_keys=True)
        self.assertEqual(snapshot["source"], "production")
        self.assertEqual(set(snapshot["routes"]), {"primary", "backup"})
        self.assertIsNone(snapshot["carrier"])
        self.assertTrue(events)
        for forbidden in (
            "://",
            "Bearer ",
            "api-primary",
            "api-backup",
            "secret_ref",
            "fingerprint",
            "request_id",
            "fixture-model",
        ):
            self.assertNotIn(forbidden, serialized)

        profiles = (
            {
                "id": "api-primary",
                "name": "Primary",
                "type": "api",
                "base_url": "http://127.0.0.1:18003/v1",
                "model": self.document["active_group"]["allowed_models"][0],
                "adapter_name": "openai-responses-v1",
                "secret_file": "api-primary.dpapi",
                "secret_hint": "••••P001",
                "credential_revision": 2,
            },
            {
                "id": "api-backup",
                "name": "Backup",
                "type": "api",
                "base_url": "http://127.0.0.1:18004/v1",
                "model": self.document["active_group"]["allowed_models"][0],
                "adapter_name": "openai-responses-v1",
                "secret_file": "api-backup.dpapi",
                "secret_hint": "••••P002",
                "credential_revision": 2,
            },
        )
        service = FailoverManagementService(
            AtomicFailoverDocumentStore(self.root / "source" / "groups.json"),
            lambda: profiles,
            self.controller,
        )
        overview = await asyncio.to_thread(service.overview)
        event_page = await asyncio.to_thread(service.list_events)
        self.assertEqual(overview["source"], "production")
        self.assertEqual(overview["gateway"]["source"], "production")
        self.assertEqual(overview["capabilities"]["publish_target"], "production")
        self.assertEqual(event_page["source"], "production")

    async def test_abort_removes_only_new_matching_credentials_and_is_idempotent(self) -> None:
        candidate = self.candidate()
        prepared = await asyncio.to_thread(self.controller.prepare, candidate)
        primary = self.credential_path("api-primary")
        backup = self.credential_path("api-backup")
        self.assertTrue(primary.is_file() and backup.is_file())
        await asyncio.to_thread(self.controller.abort, prepared)
        self.assertIsNone(self.host.status()["prepared_config"])
        self.assertFalse(primary.exists())
        self.assertFalse(backup.exists())
        await asyncio.to_thread(self.controller.abort, prepared)

    async def test_existing_credential_revision_conflict_stops_before_prepare(self) -> None:
        target = self.credential_path("api-primary")
        target.write_bytes(_protect(b"different-fixture-secret"))
        before = self.host.status()["prepared_config"]
        with self.assertRaisesRegex(
            FailoverConflictError,
            "gateway_production_credential_revision_conflict",
        ):
            await asyncio.to_thread(self.controller.prepare, self.candidate())
        self.assertEqual(self.host.status()["prepared_config"], before)
        self.assertEqual(target.read_bytes(), _protect(b"different-fixture-secret"))
        self.assertFalse(self.credential_path("api-backup").exists())

    async def test_runtime_identity_drift_stops_before_credentials_or_network_mutation(self) -> None:
        controller = ProductionGatewayController(
            install_root=self.root,
            expected_executable=self.root / "wrong.exe",
            expected_version=str(self.document["gateway_version"]),
            credential_source=self.profile_ciphertexts.__getitem__,
            unprotect=_unprotect,
            process_identity_reader=lambda _pid: None,
        )
        with self.assertRaisesRegex(
            FailoverPublishError,
            "gateway_production_executable_mismatch",
        ):
            await asyncio.to_thread(controller.prepare, self.candidate())
        self.assertFalse(self.credential_path("api-primary").exists())
        self.assertIsNone(self.host.status()["prepared_config"])

    async def test_revision_drift_and_wrong_abort_hash_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            FailoverConflictError,
            "gateway_production_revision_out_of_order",
        ):
            await asyncio.to_thread(self.controller.prepare, self.candidate(revision=1))
        prepared = await asyncio.to_thread(self.controller.prepare, self.candidate())
        record = self.controller._prepared[prepared.handle]
        changed = deepcopy(record)
        changed.config_sha256 = hashlib.sha256(b"wrong").hexdigest()
        self.controller._prepared[prepared.handle] = changed
        with self.assertRaisesRegex(FailoverPublishError, "guardian_config_hash_mismatch"):
            await asyncio.to_thread(self.controller.abort, prepared)
        self.assertIsNotNone(self.host.status()["prepared_config"])
        self.assertTrue(self.credential_path("api-primary").exists())

    async def test_management_publish_succeeds_and_store_failure_is_state_uncertain(self) -> None:
        profiles = (
            {
                "id": "api-primary",
                "name": "Primary",
                "type": "api",
                "base_url": "http://127.0.0.1:18003/v1",
                "model": self.document["active_group"]["allowed_models"][0],
                "adapter_name": "openai-responses-v1",
                "secret_file": "api-primary.dpapi",
                "secret_hint": "••••P001",
                "credential_revision": 2,
            },
            {
                "id": "api-backup",
                "name": "Backup",
                "type": "api",
                "base_url": "http://127.0.0.1:18004/v1",
                "model": self.document["active_group"]["allowed_models"][0],
                "adapter_name": "openai-responses-v1",
                "secret_file": "api-backup.dpapi",
                "secret_hint": "••••P002",
                "credential_revision": 2,
            },
        )
        store = AtomicFailoverDocumentStore(self.root / "management" / "groups.json")
        service = FailoverManagementService(store, lambda: profiles, self.controller)
        created = await asyncio.to_thread(
            service.create_group,
            {
                "name": "Production fixture",
                "enabled": True,
                "primary_profile_id": "api-primary",
                "backup_profile_id": "api-backup",
                "allowed_models": [self.document["active_group"]["allowed_models"][0]],
            },
            expected_revision=0,
        )
        group_id = created["group"]["id"]
        published = await asyncio.to_thread(
            service.publish_group,
            group_id,
            expected_revision=1,
        )
        self.assertTrue(published["published"])
        self.assertEqual(self.host.status()["config_revision"], 2)

        second = await asyncio.to_thread(
            service.create_group,
            {
                "name": "Second production fixture",
                "enabled": True,
                "primary_profile_id": "api-backup",
                "backup_profile_id": "api-primary",
                "allowed_models": [self.document["active_group"]["allowed_models"][0]],
            },
            expected_revision=2,
        )
        original_save = store.save

        def fail_save(document, *, expected_revision):
            if expected_revision == 3:
                raise FailoverStoreError("fixture_store_write_failed")
            return original_save(document, expected_revision=expected_revision)

        store.save = fail_save
        with self.assertRaisesRegex(
            FailoverPublishError,
            "failover_publish_compensated",
        ):
            await asyncio.to_thread(
                service.publish_group,
                second["group"]["id"],
                expected_revision=3,
            )
        self.assertEqual(self.host.status()["config_revision"], 5)
        compensated = store.load()
        self.assertEqual(compensated["revision"], 5)
        self.assertEqual(compensated["active_group_id"], group_id)
        self.assertEqual(
            self.host.status()["active_group_id"],
            group_id,
        )

    async def test_compensation_refuses_when_a_later_activation_won(self) -> None:
        first = await asyncio.to_thread(self.controller.prepare, self.candidate(revision=2))
        receipt = await asyncio.to_thread(self.controller.activate, first)
        second_candidate = self.candidate(revision=3)
        second_candidate["group_id"] = "d888d5ef-a0b0-4aca-a895-94431fe1f0ef"
        second = await asyncio.to_thread(self.controller.prepare, second_candidate)
        await asyncio.to_thread(self.controller.activate, second)

        with self.assertRaisesRegex(
            FailoverConflictError,
            "gateway_production_revision_changed",
        ):
            await asyncio.to_thread(self.controller.rollback, receipt)
        self.assertEqual(self.host.status()["config_revision"], 3)

    async def test_failed_compensation_locks_future_publication(self) -> None:
        profiles = (
            {
                "id": "api-primary",
                "name": "Primary",
                "type": "api",
                "base_url": "http://127.0.0.1:18003/v1",
                "model": self.document["active_group"]["allowed_models"][0],
                "adapter_name": "openai-responses-v1",
                "secret_file": "api-primary.dpapi",
                "secret_hint": "••••P001",
                "credential_revision": 2,
            },
            {
                "id": "api-backup",
                "name": "Backup",
                "type": "api",
                "base_url": "http://127.0.0.1:18004/v1",
                "model": self.document["active_group"]["allowed_models"][0],
                "adapter_name": "openai-responses-v1",
                "secret_file": "api-backup.dpapi",
                "secret_hint": "••••P002",
                "credential_revision": 2,
            },
        )
        store = AtomicFailoverDocumentStore(self.root / "locked" / "groups.json")
        service = FailoverManagementService(store, lambda: profiles, self.controller)
        created = await asyncio.to_thread(
            service.create_group,
            {
                "name": "Lock fixture",
                "enabled": True,
                "primary_profile_id": "api-primary",
                "backup_profile_id": "api-backup",
                "allowed_models": [self.document["active_group"]["allowed_models"][0]],
            },
            expected_revision=0,
        )
        original_save = store.save

        def fail_save(document, *, expected_revision):
            if expected_revision == 1:
                raise FailoverStoreError("fixture_store_write_failed")
            return original_save(document, expected_revision=expected_revision)

        store.save = fail_save
        original_rollback = self.controller.rollback
        self.controller.rollback = lambda _receipt: (_ for _ in ()).throw(
            FailoverPublishError("fixture_compensation_failed")
        )
        with self.assertRaisesRegex(
            FailoverPublishError,
            "failover_publish_state_uncertain",
        ):
            await asyncio.to_thread(
                service.publish_group,
                created["group"]["id"],
                expected_revision=1,
            )
        self.controller.rollback = original_rollback
        self.assertTrue(store.uncertain_path.is_file())
        with self.assertRaisesRegex(
            FailoverConflictError,
            "failover_state_uncertain_locked",
        ):
            await asyncio.to_thread(
                service.publish_group,
                created["group"]["id"],
                expected_revision=1,
            )


if __name__ == "__main__":
    unittest.main()
