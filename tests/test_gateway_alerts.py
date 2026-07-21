from __future__ import annotations

import json
import unittest

from gateway.alerts import action_required_alert
from gateway.breaker import BreakerState, CircuitBreakerPolicy, CircuitBreakerRegistry, RouteKey
from gateway.config import RouteConfig, RouteRole
from tests.test_gateway_router import ScriptedRunner


class RouteAlertTests(unittest.TestCase):
    def test_action_required_alert_is_persistent_and_redacted(self) -> None:
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        key = RouteKey("instance-alert", "group-alert", "primary", "profile-alert")
        policy = CircuitBreakerPolicy(minimum_samples=1, window_size=2)
        breaker.configure_route(
            key,
            config_revision=1,
            route_fingerprint="fp-alert",
            policy=policy,
        )
        admission = breaker.acquire(
            key,
            config_revision=1,
            route_fingerprint="fp-alert",
            attempt_id="alert-attempt",
        )
        breaker.record_action_required(
            admission.ticket,
            failure_category="upstream_http_error",
            http_status=401,
        )
        route = RouteConfig(
            RouteRole.PRIMARY,
            "profile-alert",
            "fp-alert",
            "openai-responses-v1",
            "secret:canary-do-not-render",
            ScriptedRunner(),
            "VAv7",
        )
        alert = action_required_alert(route, breaker.snapshot(key), backup_carrying=True)
        rendered = json.dumps(alert.__dict__ if hasattr(alert, "__dict__") else {
            field: getattr(alert, field) for field in alert.__slots__
        }, ensure_ascii=False)
        self.assertTrue(alert.persistent)
        self.assertEqual(alert.key_suffix, "VAv7")
        self.assertTrue(alert.backup_carrying)
        self.assertEqual(alert.http_status, 401)
        self.assertEqual(alert.breaker_state, BreakerState.OPEN_ACTION_REQUIRED.value)
        self.assertIn("检查 Key", alert.next_action)
        self.assertNotIn("canary-do-not-render", rendered)

        retest = breaker.acquire(
            key,
            config_revision=1,
            route_fingerprint="fp-alert",
            attempt_id="manual-retest",
            manual_probe=True,
        )
        self.assertTrue(retest.allowed)
        during_retest = action_required_alert(route, breaker.snapshot(key), backup_carrying=True)
        self.assertIsNotNone(during_retest)
        self.assertTrue(during_retest.persistent)
        self.assertEqual(during_retest.breaker_state, BreakerState.HALF_OPEN.value)

        breaker.record_success(retest.ticket)
        self.assertIsNotNone(action_required_alert(route, breaker.snapshot(key), backup_carrying=True))
        final_retest = breaker.acquire(
            key,
            config_revision=1,
            route_fingerprint="fp-alert",
            attempt_id="manual-retest-final",
            manual_probe=True,
        )
        self.assertTrue(final_retest.allowed)
        breaker.record_success(final_retest.ticket)
        self.assertIsNone(action_required_alert(route, breaker.snapshot(key), backup_carrying=False))


if __name__ == "__main__":
    unittest.main()
