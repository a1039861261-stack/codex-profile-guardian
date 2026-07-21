from __future__ import annotations

from pathlib import Path
from dataclasses import replace
import asyncio
import json
import tempfile
import unittest

from aiohttp.test_utils import TestClient, TestServer

from gateway.breaker import BreakerState, BreakerStateStoreError, CircuitBreakerRegistry, RouteKey
from gateway.cancellation import CancellationToken
from gateway.commit import Committer
from gateway.failures import FailureClassifier
from gateway.runtime import AtomicFailoverRouterProvider
from gateway.secrets import InMemorySecretResolver
from gateway.state import AtomicBreakerStateStore
from tests.gateway_probe_support import FAKE_BEARER, FIXTURE_MODEL, fixture_request
from tests.test_gateway_core import RecordingDownstream
from tests.test_gateway_router import (
    BlockingRunner,
    MutableSecretResolver,
    ScriptedRunner,
    buffered,
    group,
    route,
    temporary_failure,
)
from gateway.config import RouteRole
from gateway.models import AttemptResult, GatewayLimits
from gateway.request_snapshot import create_request_snapshot
from gateway.service import FailoverGatewayCore
from gateway.ingress import GatewayIngress


class AtomicFailoverRouterProviderTests(unittest.TestCase):
    def config(self, revision=1, primary_fingerprint=None, backup_fingerprint=None):
        return group(
            route(
                RouteRole.PRIMARY,
                "p1",
                ScriptedRunner(AttemptResult(complete=buffered(f"resp-primary-{revision}"))),
                fingerprint=primary_fingerprint or f"fp-p1-v{revision}",
            ),
            route(
                RouteRole.BACKUP,
                "p2",
                ScriptedRunner(AttemptResult(complete=buffered(f"resp-backup-{revision}"))),
                fingerprint=backup_fingerprint or f"fp-p2-v{revision}",
            ),
            revision=revision,
        )

    def provider(self, config, breaker, store=None):
        return AtomicFailoverRouterProvider(
            config,
            breaker,
            FailureClassifier(),
            InMemorySecretResolver({"secret:p1": FAKE_BEARER, "secret:p2": FAKE_BEARER}),
            state_store=store,
        )

    def test_startup_registers_routes_then_restores_persisted_breakers(self) -> None:
        config = self.config()
        primary_key = RouteKey("instance-1", "group-1", "primary", "p1")
        with tempfile.TemporaryDirectory() as directory:
            store = AtomicBreakerStateStore(Path(directory) / "breaker.json")
            source = CircuitBreakerRegistry(rng=lambda: 0)
            self.provider(config, source, store)
            admission = source.acquire(
                primary_key,
                config_revision=1,
                route_fingerprint="fp-p1-v1",
                attempt_id="auth-failure",
            )
            source.record_action_required(admission.ticket, failure_category="auth_rejected")

            restarted = CircuitBreakerRegistry(rng=lambda: 0)
            provider = self.provider(config, restarted, store)
            self.assertEqual(provider.restored_routes, 2)
            snapshot = restarted.snapshot(primary_key)
            assert snapshot is not None
            self.assertEqual(snapshot.state, BreakerState.OPEN_ACTION_REQUIRED)

    def test_activation_swaps_router_atomically_and_increases_revision(self) -> None:
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        provider = self.provider(self.config(), breaker)
        old_lease = provider.acquire()
        old_router = old_lease.router
        previous = provider.activate(self.config(revision=2))
        new_lease = provider.acquire()
        new_router = new_lease.router
        self.assertEqual(previous.revision, 1)
        self.assertEqual(old_router.group.revision, 1)
        self.assertEqual(new_router.group.revision, 2)
        old_lease.release()
        new_lease.release()
        with self.assertRaises(ValueError):
            provider.activate(self.config(revision=2))

    def test_corrupt_state_stops_startup_instead_of_resetting_breakers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "breaker.json"
            path.write_text("not-json", encoding="utf-8")
            with self.assertRaises(BreakerStateStoreError):
                self.provider(
                    self.config(),
                    CircuitBreakerRegistry(rng=lambda: 0),
                    AtomicBreakerStateStore(path),
                )

    def test_failed_activation_keeps_previous_router_and_revision(self) -> None:
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        provider = self.provider(self.config(), breaker)
        invalid = self.config(revision=2)
        invalid = replace(
            invalid,
            backup=replace(invalid.backup, fingerprint="invalid fingerprint with spaces"),
        )
        with self.assertRaises(ValueError):
            provider.activate(invalid)
        self.assertEqual(provider.current_config().revision, 1)

    def test_persistence_failure_rolls_back_router_and_breaker_revision(self) -> None:
        class ToggleStore:
            def __init__(self):
                self.document = None
                self.fail = False

            def load(self):
                return self.document

            def save(self, document):
                if self.fail:
                    raise BreakerStateStoreError("fixture_write_failed")
                self.document = document

        store = ToggleStore()
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        provider = self.provider(self.config(), breaker, store)
        store.fail = True
        with self.assertRaises(BreakerStateStoreError):
            provider.activate(self.config(revision=2))
        self.assertEqual(provider.current_config().revision, 1)
        snapshots = breaker.snapshots()
        self.assertEqual({snapshot.config_revision for snapshot in snapshots}, {1})

    def test_acquired_router_lease_survives_activation_before_execute(self) -> None:
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        provider = self.provider(self.config(), breaker)
        old_lease = provider.acquire()
        provider.activate(self.config(revision=2))
        request = fixture_request()
        snapshot = create_request_snapshot(
            request,
            {"content-type": "application/json"},
            GatewayLimits(),
        )
        result = asyncio.run(old_lease.router.execute(snapshot, CancellationToken()))
        old_lease.release()
        self.assertEqual(result.complete.response_id, "resp-primary-1")
        self.assertEqual(provider.current_config().revision, 2)
        self.assertEqual(breaker.active_pin_count(), 0)

    def test_profile_replacement_retires_old_current_routes_but_keeps_leased_snapshot(self) -> None:
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        provider = self.provider(self.config(), breaker)
        old_lease = provider.acquire()
        replacement = group(
            route(
                RouteRole.PRIMARY,
                "p3",
                ScriptedRunner(AttemptResult(complete=buffered("resp-primary-2"))),
                fingerprint="fp-p3-v2",
            ),
            route(
                RouteRole.BACKUP,
                "p4",
                ScriptedRunner(AttemptResult(complete=buffered("resp-backup-2"))),
                fingerprint="fp-p4-v2",
            ),
            revision=2,
        )
        provider.activate(replacement)

        current = breaker.snapshots()
        self.assertEqual({item.route_key.profile_id for item in current}, {"p3", "p4"})
        request = create_request_snapshot(
            fixture_request(),
            {"content-type": "application/json"},
            GatewayLimits(),
        )
        old_result = asyncio.run(old_lease.router.execute(request, CancellationToken()))
        old_lease.release()
        self.assertEqual(old_result.complete.response_id, "resp-primary-1")
        self.assertEqual(breaker.active_pin_count(), 0)
        self.assertEqual({item.route_key.profile_id for item in breaker.snapshots()}, {"p3", "p4"})


class AtomicFailoverCoreRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def config(self, revision=1):
        return group(
            route(
                RouteRole.PRIMARY,
                "p1",
                ScriptedRunner(AttemptResult(complete=buffered(f"resp-primary-{revision}"))),
                fingerprint=f"fp-p1-v{revision}",
            ),
            route(
                RouteRole.BACKUP,
                "p2",
                ScriptedRunner(AttemptResult(complete=buffered(f"resp-backup-{revision}"))),
                fingerprint=f"fp-p2-v{revision}",
            ),
            revision=revision,
        )

    def provider(self, config, breaker):
        return AtomicFailoverRouterProvider(
            config,
            breaker,
            FailureClassifier(),
            InMemorySecretResolver({"secret:p1": FAKE_BEARER, "secret:p2": FAKE_BEARER}),
        )

    async def proxy(self, core):
        downstream = RecordingDownstream()
        result = await core.proxy(
            fixture_request(),
            {"content-type": "application/json"},
            "unused",
            downstream,
            CancellationToken(),
            Committer(),
        )
        return result, downstream

    async def test_inflight_request_keeps_old_router_while_new_request_uses_activated_revision(self) -> None:
        old_primary = BlockingRunner(temporary_failure())
        old_backup = ScriptedRunner(AttemptResult(complete=buffered("resp_old_backup", b"old-backup")))
        old_config = group(
            route(RouteRole.PRIMARY, "p1", old_primary, fingerprint="fp-p1-v1"),
            route(RouteRole.BACKUP, "p2", old_backup, fingerprint="fp-p2-v1"),
        )
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        provider = self.provider(old_config, breaker)
        core = FailoverGatewayCore(provider, GatewayLimits())
        old_request = asyncio.create_task(self.proxy(core))
        await asyncio.wait_for(old_primary.entered.wait(), timeout=1)

        new_primary = ScriptedRunner(AttemptResult(complete=buffered("resp_new", b"new-primary")))
        new_config = group(
            route(RouteRole.PRIMARY, "p1", new_primary, fingerprint="fp-p1-v2"),
            route(
                RouteRole.BACKUP,
                "p2",
                ScriptedRunner(AttemptResult(complete=buffered("resp_new_backup"))),
                fingerprint="fp-p2-v2",
            ),
            revision=2,
        )
        provider.activate(new_config)
        old_primary.release.set()
        _old_result, old_downstream = await old_request
        _new_result, new_downstream = await self.proxy(core)
        self.assertEqual(old_downstream.body, b"old-backup")
        self.assertEqual(new_downstream.body, b"new-primary")
        self.assertEqual(len(old_backup.calls), 1)
        self.assertEqual(len(new_primary.calls), 1)
        self.assertEqual(breaker.active_pin_count(), 0)

    async def test_ingress_models_and_post_validation_follow_atomic_revision(self) -> None:
        model_a = FIXTURE_MODEL
        model_b = "fixture-model-b"
        primary_a = ScriptedRunner(AttemptResult(complete=buffered("resp-a", b"model-a")))
        config_a = replace(
            self.config(),
            primary=replace(self.config().primary, runner=primary_a),
            allowed_models=(model_a,),
        )
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        provider = self.provider(config_a, breaker)
        core = FailoverGatewayCore(provider, GatewayLimits())
        ingress = GatewayIngress(
            core,
            GatewayLimits(),
            ingress_token="fixture-ingress-token",
        )
        client = TestClient(TestServer(ingress.create_app(), handler_cancellation=True))
        await client.start_server()
        auth = {"Authorization": "Bearer fixture-ingress-token"}
        try:
            first_models = await (await client.get("/v1/models", headers=auth)).json()
            self.assertEqual([item["id"] for item in first_models["data"]], [model_a])

            primary_b = ScriptedRunner(AttemptResult(complete=buffered("resp-b", b"model-b")))
            config_b = replace(
                self.config(revision=2),
                primary=replace(self.config(revision=2).primary, runner=primary_b),
                allowed_models=(model_b,),
            )
            provider.activate(config_b)

            current_models = await (await client.get("/v1/models", headers=auth)).json()
            self.assertEqual([item["id"] for item in current_models["data"]], [model_b])

            old_payload = json.loads(fixture_request().decode("utf-8"))
            old_response = await client.post(
                "/v1/responses",
                data=json.dumps(old_payload).encode("utf-8"),
                headers={**auth, "Content-Type": "application/json"},
            )
            self.assertEqual(old_response.status, 400)
            self.assertEqual((await old_response.json())["error"]["code"], "guardian_model_not_allowed")

            new_payload = dict(old_payload, model=model_b)
            new_response = await client.post(
                "/v1/responses",
                data=json.dumps(new_payload).encode("utf-8"),
                headers={**auth, "Content-Type": "application/json"},
            )
            self.assertEqual(new_response.status, 200)
            self.assertEqual(await new_response.read(), b"model-b")
            self.assertEqual(len(primary_a.calls), 0)
            self.assertEqual(len(primary_b.calls), 1)
        finally:
            await client.close()

    async def test_hot_revision_keeps_old_lease_and_new_catalog_in_one_concurrent_flow(self) -> None:
        model_a = FIXTURE_MODEL
        model_b = "fixture-model-b"
        old_primary = BlockingRunner(AttemptResult(complete=buffered("resp-old-a", b"old-model-a")))
        old_backup = ScriptedRunner(AttemptResult(complete=buffered("unused-old-backup")))
        config_a = replace(
            group(
                route(RouteRole.PRIMARY, "p1", old_primary, fingerprint="fp-p1-v1"),
                route(RouteRole.BACKUP, "p2", old_backup, fingerprint="fp-p2-v1"),
            ),
            allowed_models=(model_a,),
        )
        resolver = MutableSecretResolver(
            {"secret:p1": FAKE_BEARER, "secret:p2": FAKE_BEARER}
        )
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        provider = AtomicFailoverRouterProvider(
            config_a,
            breaker,
            FailureClassifier(),
            resolver,
        )
        core = FailoverGatewayCore(provider, GatewayLimits())
        ingress = GatewayIngress(
            core,
            GatewayLimits(),
            ingress_token="fixture-ingress-token",
        )
        client = TestClient(TestServer(ingress.create_app(), handler_cancellation=True))
        await client.start_server()
        headers = {
            "Authorization": "Bearer fixture-ingress-token",
            "Content-Type": "application/json",
        }
        payload_a = json.loads(fixture_request().decode("utf-8"))
        old_task = asyncio.create_task(
            client.post(
                "/v1/responses",
                data=json.dumps(payload_a).encode("utf-8"),
                headers=headers,
            )
        )
        try:
            await asyncio.wait_for(old_primary.entered.wait(), timeout=1)
            resolver_calls_after_old_lease = len(resolver.calls)

            new_primary = ScriptedRunner(
                AttemptResult(complete=buffered("resp-new-b", b"new-model-b"))
            )
            new_backup = ScriptedRunner(
                AttemptResult(complete=buffered("unused-new-backup"))
            )
            config_b = replace(
                group(
                    route(RouteRole.PRIMARY, "p1", new_primary, fingerprint="fp-p1-v2"),
                    route(RouteRole.BACKUP, "p2", new_backup, fingerprint="fp-p2-v2"),
                    revision=2,
                ),
                allowed_models=(model_b,),
            )
            provider.activate(config_b)

            current_models = await (await client.get("/v1/models", headers=headers)).json()
            self.assertEqual([item["id"] for item in current_models["data"]], [model_b])

            rejected_old_model = await client.post(
                "/v1/responses",
                data=json.dumps(payload_a).encode("utf-8"),
                headers=headers,
            )
            self.assertEqual(rejected_old_model.status, 400)
            self.assertEqual(
                (await rejected_old_model.json())["error"]["code"],
                "guardian_model_not_allowed",
            )
            self.assertEqual(len(resolver.calls), resolver_calls_after_old_lease)
            self.assertEqual(len(new_primary.calls), 0)
            self.assertEqual(len(new_backup.calls), 0)

            payload_b = dict(payload_a, model=model_b)
            accepted_new_model = await client.post(
                "/v1/responses",
                data=json.dumps(payload_b).encode("utf-8"),
                headers=headers,
            )
            self.assertEqual(accepted_new_model.status, 200)
            self.assertEqual(await accepted_new_model.read(), b"new-model-b")
            self.assertEqual(len(new_primary.calls), 1)
            self.assertEqual(len(new_backup.calls), 0)
            self.assertEqual(len(resolver.calls), resolver_calls_after_old_lease + 2)

            old_primary.release.set()
            old_response = await asyncio.wait_for(old_task, timeout=1)
            self.assertEqual(old_response.status, 200)
            self.assertEqual(await old_response.read(), b"old-model-a")
            self.assertEqual(old_primary.calls, 1)
            self.assertEqual(len(old_backup.calls), 0)
            self.assertEqual(provider.current_config().revision, 2)
            self.assertEqual(breaker.active_pin_count(), 0)
        finally:
            old_primary.release.set()
            if not old_task.done():
                old_response = await asyncio.wait_for(old_task, timeout=1)
                await old_response.read()
            await client.close()


if __name__ == "__main__":
    unittest.main()
