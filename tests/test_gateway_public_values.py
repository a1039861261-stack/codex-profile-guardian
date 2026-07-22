from __future__ import annotations

import json
import unittest

from gateway.errors import all_routes_failed_response, gateway_error_response
from gateway.ingress import GatewayIngress
from gateway.public_values import normalize_public_gateway_code


class PublicGatewayErrorTests(unittest.TestCase):
    def test_known_gateway_and_attempt_codes_are_preserved(self) -> None:
        self.assertEqual(
            normalize_public_gateway_code("guardian_model_not_allowed"),
            "guardian_model_not_allowed",
        )
        self.assertEqual(
            normalize_public_gateway_code("guardian_upstream_http_503"),
            "guardian_upstream_http_503",
        )

    def test_unknown_code_and_message_are_closed_at_shared_renderer(self) -> None:
        response = gateway_error_response(
            status=418,
            code="secret_internal_branch_canary",
            message="secret-message-canary",
        )
        payload = json.loads(response.body)
        self.assertEqual(response.status, 500)
        self.assertEqual(payload["error"]["code"], "guardian_internal_error")
        self.assertEqual(payload["error"]["message"], "本地网关内部错误。")
        self.assertNotIn("canary", response.body.decode("utf-8"))

    def test_ingress_direct_error_body_uses_same_public_code_closure(self) -> None:
        body = GatewayIngress._error_body(
            "internal_protocol_detail_canary",
            "secret-message-canary",
        )
        payload = json.loads(body)
        self.assertEqual(payload["error"]["code"], "guardian_internal_error")
        self.assertNotIn("canary", body.decode("utf-8"))

    def test_all_routes_failed_rejects_arbitrary_breaker_reason(self) -> None:
        response = all_routes_failed_response(
            request_id="fixture-request",
            primary=None,
            backup=None,
            possible_double_charge=False,
            action_required=False,
            primary_unavailable="secret-breaker-reason-canary",
        )
        payload = json.loads(response.body)
        self.assertEqual(response.status, 500)
        self.assertEqual(payload["error"]["code"], "guardian_internal_error")
        self.assertNotIn("canary", response.body.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
