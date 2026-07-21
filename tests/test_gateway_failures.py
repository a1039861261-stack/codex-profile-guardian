from __future__ import annotations

from datetime import datetime, timezone
from email.utils import format_datetime
import unittest

from gateway.failures import FailureClassifier, parse_retry_after
from gateway.models import AttemptFailure, AttemptPhase, FailureDisposition


class FailureClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.classifier = FailureClassifier()

    def classify(self, failure: AttemptFailure):
        return self.classifier.classify(failure, now_wall=1_700_000_000, max_retry_after_seconds=300)

    def test_fr031_http_matrix(self) -> None:
        for status in (401, 403):
            with self.subTest(status=status):
                decision = self.classify(AttemptFailure("upstream_http_error", f"guardian_upstream_http_{status}", status))
                self.assertEqual(decision.disposition, FailureDisposition.RETRYABLE_ACTION_REQUIRED)
                self.assertTrue(decision.retry_on_backup)
                self.assertTrue(decision.action_required)
        for status in (429, 500, 502, 503, 504):
            with self.subTest(status=status):
                decision = self.classify(AttemptFailure("upstream_http_error", f"guardian_upstream_http_{status}", status))
                self.assertEqual(decision.disposition, FailureDisposition.RETRYABLE_TEMPORARY)
                self.assertTrue(decision.retry_on_backup)
                self.assertFalse(decision.action_required)
        for status in (400, 404, 409, 413, 415, 422):
            with self.subTest(status=status):
                decision = self.classify(AttemptFailure("upstream_http_error", f"guardian_upstream_http_{status}", status))
                self.assertEqual(decision.disposition, FailureDisposition.NON_RETRYABLE)
                self.assertFalse(decision.retry_on_backup)
                self.assertFalse(decision.breaker_failure)

    def test_adapter_404_is_profile_scoped(self) -> None:
        ordinary = self.classify(AttemptFailure("upstream_http_error", "guardian_upstream_http_404", 404))
        adapted = self.classify(
            AttemptFailure("upstream_http_error", "guardian_upstream_http_404", 404, adapter_action_required=True)
        )
        self.assertFalse(ordinary.retry_on_backup)
        self.assertEqual(adapted.disposition, FailureDisposition.RETRYABLE_ACTION_REQUIRED)
        self.assertTrue(adapted.action_required)

    def test_transport_timeout_protocol_and_local_failures(self) -> None:
        for category in ("upstream_timeout", "upstream_transport_error"):
            code = (
                "guardian_upstream_timeout"
                if category == "upstream_timeout"
                else "guardian_upstream_transport_error"
            )
            decision = self.classify(AttemptFailure(category, code, request_started=True))
            self.assertTrue(decision.retry_on_backup)
        protocol = self.classify(
            AttemptFailure(
                "protocol_or_local_error",
                "guardian_upstream_protocol_error",
                502,
                request_started=True,
                response_bytes_received=20,
            )
        )
        overflow = self.classify(
            AttemptFailure(
                "protocol_or_local_error",
                "guardian_response_too_large",
                502,
                request_started=True,
                response_bytes_received=20,
            )
        )
        self.assertTrue(protocol.retry_on_backup)
        self.assertFalse(overflow.retry_on_backup)
        self.assertFalse(overflow.breaker_failure)

    def test_possible_double_charge_uses_attempt_evidence(self) -> None:
        before_send = self.classify(
            AttemptFailure(
                "upstream_transport_error",
                "guardian_upstream_transport_error",
                phase=AttemptPhase.AWAITING_HEADERS,
                request_started=True,
                possible_double_charge=False,
            )
        )
        partial = self.classify(
            AttemptFailure(
                "upstream_transport_error",
                "guardian_upstream_transport_error",
                phase=AttemptPhase.READING_BODY,
                request_started=True,
                response_bytes_received=10,
                possible_double_charge=True,
            )
        )
        self.assertFalse(before_send.possible_double_charge)
        self.assertTrue(partial.possible_double_charge)

    def test_retry_after_parsing_is_bounded(self) -> None:
        now = 1_700_000_000.0
        future = format_datetime(datetime.fromtimestamp(now + 120, timezone.utc), usegmt=True)
        self.assertEqual(parse_retry_after("30", now_wall=now, maximum=300), 30)
        self.assertEqual(parse_retry_after("9999", now_wall=now, maximum=300), 300)
        self.assertEqual(parse_retry_after(future, now_wall=now, maximum=300), 120)
        for value in (None, "", "invalid", "-1", "0", "1.5", "NaN", "9" * 200):
            with self.subTest(value=value):
                self.assertIsNone(parse_retry_after(value, now_wall=now, maximum=300))

    def test_attempt_failure_rejects_unknown_public_values_at_boundary(self) -> None:
        canary = "valid-format-secret-canary"
        with self.assertRaisesRegex(ValueError, "attempt_failure_category_invalid"):
            AttemptFailure(canary, "guardian_upstream_transport_error")
        with self.assertRaisesRegex(ValueError, "attempt_public_code_invalid"):
            AttemptFailure("upstream_transport_error", canary)


if __name__ == "__main__":
    unittest.main()
