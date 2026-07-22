from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from backend.failover import (
    AtomicFailoverDocumentStore,
    FailoverConflictError,
    FailoverManagementService,
    FailoverPublishError,
    FailoverStoreError,
    FailoverValidationError,
    FixtureGatewayController,
)


NOW = "2026-07-12T12:00:00+00:00"
FULL_PRIMARY_URL = "https://primary.fixture.invalid/v1"
FULL_BACKUP_URL = "https://backup.fixture.invalid/v1"
FULL_THIRD_URL = "https://third.fixture.invalid/v1"
PRIVATE_CANARY = "FULL-PRIVATE-FIXTURE-CANARY"


def profiles() -> list[dict[str, object]]:
    return [
        {
            "id": "api-primary",
            "type": "api",
            "has_secret": True,
            "credential_revision": 1,
            "name": "主线路样例",
            "base_url": FULL_PRIMARY_URL,
            "wire_api": "responses",
            "secret_hint": "••••P111",
            "api_key": PRIVATE_CANARY,
            "control_token": PRIVATE_CANARY,
            "capabilities": {
                "adapter_name": "openai-responses-v1",
                "models": ["fixture-common", "fixture-primary-only"],
                "protocol_compatibility": {
                    "allow_terminal_output_missing_item_ids": True,
                    "allow_terminal_output_missing_item_status": True,
                    "allow_function_call_arguments_done_missing_name": True,
                },
            },
        },
        {
            "id": "api-backup",
            "type": "api",
            "has_secret": True,
            "credential_revision": 1,
            "name": "备用线路样例",
            "base_url": FULL_BACKUP_URL,
            "wire_api": "responses",
            "secret_hint": "••••B222",
            "capabilities": {
                "adapter_name": "openai-responses-v1",
                "models": ["fixture-common", "fixture-backup-only"],
                "protocol_compatibility": {
                    "allow_terminal_output_omission": True,
                },
            },
        },
        {
            "id": "api-third",
            "type": "api",
            "has_secret": True,
            "credential_revision": 1,
            "name": "第二容灾组备用",
            "base_url": FULL_THIRD_URL,
            "adapter_name": "openai-responses-v1",
            "secret_hint": "••••T333",
            "models": ["fixture-common"],
        },
        {
            "id": "official-account",
            "type": "official",
            "name": "官方账号",
            "model": "fixture-common",
        },
        {
            "id": "api-invalid-url",
            "type": "api",
            "has_secret": True,
            "credential_revision": 1,
            "name": "不安全地址",
            "base_url": "http://not-loopback.fixture.invalid/v1",
            "wire_api": "responses",
            "models": ["fixture-common"],
        },
        {
            "id": "api-invalid-adapter",
            "type": "api",
            "has_secret": True,
            "credential_revision": 1,
            "name": "不支持的适配器",
            "base_url": "https://adapter.fixture.invalid/v1",
            "adapter_name": "unsupported-adapter",
            "models": ["fixture-common"],
        },
    ]


def group_values(
    *,
    name: str = "默认容灾组",
    primary: str = "api-primary",
    backup: str = "api-backup",
    models: list[str] | None = None,
    enabled: bool = True,
) -> dict[str, object]:
    result: dict[str, object] = {
        "name": name,
        "enabled": enabled,
        "primary_profile_id": primary,
        "backup_profile_id": backup,
    }
    if models is not None:
        result["allowed_models"] = models
    return result


class SaveFailingStore(AtomicFailoverDocumentStore):
    fail_next_save = False

    def save(self, document, *, expected_revision):
        if self.fail_next_save:
            self.fail_next_save = False
            raise FailoverStoreError("fixture_store_write_failed")
        return super().save(document, expected_revision=expected_revision)


class CompensationFailingStore(AtomicFailoverDocumentStore):
    def save_compensation(self, document, *, expected_revision, compensation_revision):
        raise FailoverStoreError("fixture_compensation_write_failed")


class FailoverTestCase(unittest.TestCase):
    store_type = AtomicFailoverDocumentStore

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "gateway" / "config" / "groups.json"
        self.store = self.store_type(self.path)
        self.controller = FixtureGatewayController(clock=lambda: NOW)
        self.service = FailoverManagementService(
            self.store,
            profiles(),
            self.controller,
            clock=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self, *, expected_revision: int = 0, **overrides) -> dict[str, object]:
        values = group_values(**overrides)
        return self.service.create_group(values, expected_revision=expected_revision)


class AtomicFailoverDocumentStoreTests(FailoverTestCase):
    def test_initialization_is_idempotent_and_starts_at_revision_zero(self) -> None:
        first = self.store.initialize()
        original = self.path.read_bytes()
        second = AtomicFailoverDocumentStore(self.path).initialize()

        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], 1)
        self.assertEqual(first["revision"], 0)
        self.assertIsNone(first["active_group_id"])
        self.assertEqual(first["groups"], [])
        self.assertEqual(str(uuid.UUID(first["instance_id"])), first["instance_id"])
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.path.parent.glob(".*.tmp")), [])

    def test_corrupt_or_future_document_fails_closed_without_reinitializing(self) -> None:
        for payload in (
            b"{not-json",
            json.dumps(
                {
                    "schema_version": 99,
                    "revision": 0,
                    "instance_id": str(uuid.uuid4()),
                    "active_group_id": None,
                    "groups": [],
                }
            ).encode("utf-8"),
        ):
            with self.subTest(payload=payload[:20]):
                self.path.write_bytes(payload)
                with self.assertRaises(FailoverStoreError):
                    AtomicFailoverDocumentStore(self.path).initialize()
                self.assertEqual(self.path.read_bytes(), payload)

    def test_store_rejects_revision_skip_and_instance_replacement(self) -> None:
        current = self.store.load()
        skipped = deepcopy(current)
        skipped["revision"] = 2
        with self.assertRaises(FailoverConflictError):
            self.store.save(skipped, expected_revision=0)

        replaced = deepcopy(current)
        replaced["revision"] = 1
        replaced["instance_id"] = str(uuid.uuid4())
        with self.assertRaises(FailoverConflictError):
            self.store.save(replaced, expected_revision=0)

        compensation = deepcopy(current)
        compensation["revision"] = 2
        saved = self.store.save_compensation(
            compensation,
            expected_revision=0,
            compensation_revision=2,
        )
        self.assertEqual(saved["revision"], 2)
        with self.assertRaisesRegex(
            FailoverConflictError,
            "failover_compensation_revision_invalid",
        ):
            self.store.save_compensation(
                {**saved, "revision": 4},
                expected_revision=2,
                compensation_revision=5,
            )

    def test_state_uncertain_lock_persists_and_blocks_publish(self) -> None:
        self.store.mark_state_uncertain("failover_compensation_failed")
        self.assertTrue(self.store.uncertain_path.is_file())
        with self.assertRaisesRegex(
            FailoverConflictError,
            "failover_state_uncertain_locked",
        ):
            AtomicFailoverDocumentStore(self.path).assert_publish_allowed()


class FailoverCrudTests(FailoverTestCase):
    def test_crud_requires_expected_revision_and_preserves_group_uuid(self) -> None:
        created = self.create()
        group_id = created["group"]["id"]
        self.assertEqual(created["revision"], 1)
        self.assertEqual(str(uuid.UUID(group_id)), group_id)

        with self.assertRaises(FailoverConflictError):
            self.service.update_group(group_id, {"name": "过期写入"}, expected_revision=0)
        with self.assertRaises(FailoverConflictError):
            self.service.update_group(
                group_id,
                {"id": str(uuid.uuid4()), "name": "试图换 UUID"},
                expected_revision=1,
            )

        updated = self.service.update_group(group_id, {"name": "已重命名"}, expected_revision=1)
        self.assertEqual(updated["revision"], 2)
        self.assertEqual(updated["group"]["id"], group_id)
        self.assertEqual(updated["group"]["name"], "已重命名")

        deleted = self.service.delete_group(group_id, expected_revision=2)
        self.assertEqual(deleted["revision"], 3)
        self.assertEqual(deleted["deleted_group_id"], group_id)
        self.assertEqual(self.service.list_groups()["groups"], [])

    def test_noop_update_is_idempotent_and_does_not_consume_revision(self) -> None:
        created = self.create()
        group_id = created["group"]["id"]
        unchanged = self.service.update_group(
            group_id,
            {"id": group_id, "name": "默认容灾组"},
            expected_revision=1,
        )
        self.assertEqual(unchanged["revision"], 1)
        self.assertEqual(self.store.load()["revision"], 1)

    def test_group_document_contains_references_and_policy_but_no_route_secrets(self) -> None:
        self.create(models=["fixture-common"])
        serialized = self.path.read_text(encoding="utf-8")
        document = json.loads(serialized)

        self.assertIn("primary_profile_id", serialized)
        self.assertIn("breaker_policy", serialized)
        for forbidden in (
            FULL_PRIMARY_URL,
            FULL_BACKUP_URL,
            PRIVATE_CANARY,
            "base_url",
            "secret_ref",
            "fingerprint",
            "key_suffix",
            "token",
            "hash",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(set(document), {"schema_version", "revision", "instance_id", "active_group_id", "groups"})

    def test_routes_must_be_distinct_and_reference_api_profiles(self) -> None:
        with self.assertRaisesRegex(FailoverValidationError, "failover_routes_must_be_distinct"):
            self.create(primary="api-primary", backup="api-primary")
        with self.assertRaisesRegex(FailoverValidationError, "failover_profile_must_be_api"):
            self.create(primary="official-account")

    def test_model_selection_must_be_nonempty_subset_of_both_routes(self) -> None:
        created = self.create(models=None)
        self.assertEqual(created["group"]["allowed_models"], ["fixture-common"])

        with self.assertRaisesRegex(FailoverValidationError, "failover_model_not_in_intersection"):
            self.service.create_group(
                group_values(models=["fixture-primary-only"]),
                expected_revision=1,
            )

    def test_adapter_and_base_url_are_validated_before_document_write(self) -> None:
        original = self.path.read_bytes()
        with self.assertRaisesRegex(FailoverValidationError, "failover_adapter_unsupported"):
            self.create(primary="api-invalid-adapter")
        self.assertEqual(self.path.read_bytes(), original)

        with self.assertRaisesRegex(FailoverValidationError, "failover_profile_insecure_base_url"):
            self.create(primary="api-invalid-url")
        self.assertEqual(self.path.read_bytes(), original)

    def test_profile_reference_index_is_complete(self) -> None:
        self.create()
        self.assertEqual(
            self.service.referenced_profile_ids(),
            frozenset({"api-primary", "api-backup"}),
        )

    def test_cross_store_compare_and_swap_rejects_stale_writer(self) -> None:
        second = AtomicFailoverDocumentStore(self.path)
        first_document = self.store.load()
        second_document = second.load()
        first_document["revision"] = 1
        first_document["groups"] = []
        second_document["revision"] = 1
        second_document["groups"] = []

        saved = self.store.save(first_document, expected_revision=0)
        self.assertEqual(saved["revision"], 1)
        with self.assertRaisesRegex(FailoverConflictError, "failover_revision_conflict"):
            second.save(second_document, expected_revision=0)


class FailoverPublishTests(FailoverTestCase):
    def _two_groups(self):
        first = self.create()
        second = self.create(
            expected_revision=1,
            name="第二容灾组",
            primary="api-backup",
            backup="api-third",
        )
        return first["group"]["id"], second["group"]["id"]

    def test_publish_uses_prepare_then_activate_and_supports_group_switch(self) -> None:
        first_id, second_id = self._two_groups()

        first_publish = self.service.publish_group(first_id, expected_revision=2)
        self.assertEqual(first_publish["revision"], 3)
        self.assertEqual(self.controller.active_group_id, first_id)
        self.assertEqual(self.controller.active_revision, 3)

        second_publish = self.service.publish_group(second_id, expected_revision=3)
        self.assertEqual(second_publish["revision"], 4)
        self.assertEqual(self.controller.active_group_id, second_id)
        self.assertEqual(self.controller.active_revision, 4)
        self.assertEqual(self.controller.call_log, ["prepare", "activate", "prepare", "activate"])
        active = self.controller._active_candidate
        self.assertTrue(
            active["primary"]["protocol_compatibility"][
                "allow_terminal_output_omission"
            ]
        )
        self.assertFalse(
            active["backup"]["protocol_compatibility"][
                "allow_terminal_output_missing_item_ids"
            ]
        )

    def test_prepare_and_activate_failure_preserve_document_and_active_revision(self) -> None:
        first_id, second_id = self._two_groups()
        self.service.publish_group(first_id, expected_revision=2)
        before = self.store.load()

        self.controller.fail_next_prepare()
        with self.assertRaisesRegex(FailoverPublishError, "gateway_fixture_prepare_failed"):
            self.service.publish_group(second_id, expected_revision=3)
        self.assertEqual(self.store.load(), before)
        self.assertEqual((self.controller.active_group_id, self.controller.active_revision), (first_id, 3))

        self.controller.fail_next_activate()
        with self.assertRaisesRegex(FailoverPublishError, "gateway_fixture_activate_failed"):
            self.service.publish_group(second_id, expected_revision=3)
        self.assertEqual(self.store.load(), before)
        self.assertEqual((self.controller.active_group_id, self.controller.active_revision), (first_id, 3))
        self.assertEqual(self.controller.call_log[-3:], ["prepare", "activate", "abort"])

    def test_store_failure_after_activation_rolls_controller_back(self) -> None:
        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "groups.json"
        self.store = SaveFailingStore(self.path)
        self.controller = FixtureGatewayController(clock=lambda: NOW)
        self.service = FailoverManagementService(
            self.store,
            profiles(),
            self.controller,
            clock=lambda: NOW,
        )
        first_id, second_id = self._two_groups()
        self.service.publish_group(first_id, expected_revision=2)
        before = self.store.load()
        self.store.fail_next_save = True

        with self.assertRaisesRegex(FailoverStoreError, "fixture_store_write_failed"):
            self.service.publish_group(second_id, expected_revision=3)

        self.assertEqual(self.store.load(), before)
        self.assertEqual((self.controller.active_group_id, self.controller.active_revision), (first_id, 3))
        self.assertEqual(self.controller.call_log[-3:], ["prepare", "activate", "rollback"])

    def test_active_group_cannot_be_deleted_or_published_when_disabled(self) -> None:
        active = self.create()
        group_id = active["group"]["id"]
        self.service.publish_group(group_id, expected_revision=1)
        with self.assertRaisesRegex(FailoverConflictError, "failover_active_group_delete_forbidden"):
            self.service.delete_group(group_id, expected_revision=2)

        disabled = self.create(expected_revision=2, name="停用组", enabled=False)
        with self.assertRaisesRegex(FailoverConflictError, "failover_group_disabled"):
            self.service.publish_group(disabled["group"]["id"], expected_revision=3)

    def test_active_group_cannot_be_disabled(self) -> None:
        active = self.create()
        group_id = active["group"]["id"]
        self.service.publish_group(group_id, expected_revision=1)

        with self.assertRaisesRegex(FailoverConflictError, "failover_active_group_disable_forbidden"):
            self.service.update_group(group_id, {"enabled": False}, expected_revision=2)

        self.assertTrue(self.store.load()["groups"][0]["enabled"])
        self.assertEqual(self.controller.active_group_id, group_id)

    def test_activation_committed_then_failed_is_rolled_back(self) -> None:
        first_id, second_id = self._two_groups()
        self.service.publish_group(first_id, expected_revision=2)
        before = self.store.load()
        self.controller.fail_next_activate_after_commit()

        with self.assertRaisesRegex(FailoverPublishError, "gateway_fixture_activate_result_uncertain"):
            self.service.publish_group(second_id, expected_revision=3)

        self.assertEqual(self.store.load(), before)
        self.assertEqual((self.controller.active_group_id, self.controller.active_revision), (first_id, 3))
        self.assertEqual(self.controller.call_log[-3:], ["prepare", "activate", "rollback"])


class FailoverOverviewTests(FailoverTestCase):
    def setUp(self) -> None:
        super().setUp()
        created = self.create(models=["fixture-common"])
        self.group_id = created["group"]["id"]
        self.service.publish_group(self.group_id, expected_revision=1)

    def test_overview_is_profile_joined_but_strictly_redacted(self) -> None:
        overview = self.service.overview()
        serialized = json.dumps(overview, ensure_ascii=False, sort_keys=True)

        self.assertEqual(overview["source"], "fixture")
        self.assertFalse(overview["stale"])
        self.assertEqual(overview["collected_at"], NOW)
        self.assertEqual(overview["group"]["id"], self.group_id)
        self.assertEqual([route["label"] for route in overview["group"]["routes"]], ["P1", "P2"])
        self.assertEqual(overview["group"]["capabilities"]["model_intersection"], ["fixture-common"])
        self.assertEqual(overview["gateway"]["config_revision"], 2)
        self.assertFalse(overview["gateway"]["configuration_drift"])
        self.assertEqual(
            {option["id"] for option in overview["profile_options"] if option["eligible"]},
            {"api-primary", "api-backup", "api-third"},
        )
        self.assertNotIn("official-account", serialized)
        for forbidden in (
            FULL_PRIMARY_URL,
            FULL_BACKUP_URL,
            FULL_THIRD_URL,
            PRIVATE_CANARY,
            "base_url",
            "secret_ref",
            "fingerprint",
            "control_token",
            "ingress_token",
            "token_hash",
            "raw_error",
            "Authorization",
            "Bearer ",
            "://",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_all_seven_fixture_scenarios_have_stable_public_states(self) -> None:
        expected = {
            "healthy": ("ready", "primary", False),
            "degraded": ("ready", "backup", False),
            "action": ("ready", "backup", False),
            "failed": ("ready", None, False),
            "loading": ("loading", None, False),
            "empty": ("empty", None, False),
            "error": ("error", None, True),
        }
        for scenario, (view_state, carrier, stale) in expected.items():
            with self.subTest(scenario=scenario):
                self.controller.set_scenario(scenario)
                overview = self.service.overview()
                self.assertEqual(overview["view_state"], view_state)
                self.assertEqual(overview["summary"]["carrier"], carrier)
                self.assertEqual(overview["stale"], stale)
                if scenario == "empty":
                    self.assertIsNone(overview["group"])
                serialized = json.dumps(overview, ensure_ascii=False)
                self.assertNotIn("://", serialized)
                self.assertNotIn(PRIVATE_CANARY, serialized)

    def test_event_pagination_is_bounded_and_public(self) -> None:
        self.controller.set_scenario("degraded")
        self.controller.set_scenario("action")
        first = self.service.list_events(offset=0, limit=2)
        second = self.service.list_events(offset=2, limit=2)

        self.assertEqual(len(first["items"]), 2)
        self.assertEqual(first["next_offset"], 2)
        self.assertTrue(second["items"])
        self.assertNotEqual(first["items"], second["items"])
        self.assertNotIn("://", json.dumps(first, ensure_ascii=False))
        with self.assertRaises(FailoverValidationError):
            self.service.list_events(offset=-1, limit=1)
        with self.assertRaises(FailoverValidationError):
            self.service.list_events(offset=0, limit=101)

    def test_retest_changes_only_fixture_runtime_state(self) -> None:
        self.controller.set_scenario("action")
        before_bytes = self.path.read_bytes()
        before_document = self.store.load()
        before_network = self.controller.network_calls

        result = self.service.retest_route(
            self.group_id,
            "primary",
            expected_revision=2,
        )

        self.assertEqual(result["summary"]["carrier"], "primary")
        self.assertEqual(result["group"]["routes"][0]["state"], "closed")
        self.assertEqual(self.path.read_bytes(), before_bytes)
        self.assertEqual(self.store.load(), before_document)
        self.assertEqual(self.controller.network_calls, before_network)
        self.assertIn("retest:primary", self.controller.call_log)

    def test_group_edit_after_publish_is_reported_as_configuration_drift(self) -> None:
        updated = self.service.update_group(
            self.group_id,
            {"name": "等待重新发布"},
            expected_revision=2,
        )
        self.assertEqual(updated["revision"], 3)
        overview = self.service.overview()
        self.assertEqual(overview["gateway"]["config_revision"], 2)
        self.assertTrue(overview["gateway"]["configuration_drift"])

    def test_non_active_group_edit_does_not_create_active_configuration_drift(self) -> None:
        second = self.create(
            expected_revision=2,
            name="非活动组",
            primary="api-backup",
            backup="api-third",
        )
        second_id = second["group"]["id"]
        updated = self.service.update_group(second_id, {"name": "非活动组已编辑"}, expected_revision=3)
        self.assertEqual(updated["revision"], 4)

        overview = self.service.overview(self.group_id)
        self.assertFalse(overview["gateway"]["configuration_drift"])
        self.assertEqual(overview["gateway"]["config_revision"], 2)

    def test_controller_canary_is_never_exposed_by_overview_or_events(self) -> None:
        original_snapshot = self.controller.snapshot
        original_events = self.controller.events
        self.controller.snapshot = lambda: {
            **original_snapshot(),
            "message": PRIVATE_CANARY,
            "prompt": PRIVATE_CANARY,
            "api_key": PRIVATE_CANARY,
        }
        self.controller.events = lambda: (
            {
                "event_id": "canary-event",
                "timestamp": NOW,
                "event": "unknown_canary_event",
                "status": "ready",
                "route_role": "primary",
                "message": PRIVATE_CANARY,
                "prompt": PRIVATE_CANARY,
            },
            *original_events(),
        )

        overview = json.dumps(self.service.overview(), ensure_ascii=False)
        events = json.dumps(self.service.list_events(limit=100), ensure_ascii=False)
        self.assertNotIn(PRIVATE_CANARY, overview)
        self.assertNotIn(PRIVATE_CANARY, events)


if __name__ == "__main__":
    unittest.main()
