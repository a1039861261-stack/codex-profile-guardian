"""Deterministic force-fallback safety tests; no production process discovery."""
from dataclasses import replace
import json
import unittest
from unittest.mock import Mock, patch

from backend.codex_lifecycle import (
    CodexProcess, close_codex_gracefully, desktop_owned_processes,
)
from backend.guardian import GuardianPublicError
from tests.test_codex_lifecycle import FakeClock, FakeCloser


class FakeTerminator:
    def __init__(self):
        self.terminated = set()
        self.calls = []

    def terminate(self, processes, guard):
        guard()
        self.calls.append(list(processes))
        self.terminated.update(p.identity for p in processes)


class ForceCloseTests(unittest.TestCase):
    desktop = CodexProcess(100, 1, 1000, "desktop", True)
    renderer = CodexProcess(101, 100, 1001, "desktop_child", True)
    server = CodexProcess(102, 100, 1002, "runtime_server", True)
    independent = CodexProcess(200, 1, 1003, "runtime_server", True)

    def close(self, query, **options):
        clock = FakeClock()
        closer = options.pop("closer", FakeCloser())
        terminator = options.pop("terminator", FakeTerminator())
        guard = options.pop("before_force", Mock())
        result = close_codex_gracefully(
            2, query=lambda: query(clock.now, terminator),
            clock=clock, sleep=clock.sleep, closer=closer,
            terminator=terminator, before_force=guard, **options,
        )
        return result, terminator, guard, clock

    def test_opt_in_does_not_force_a_normal_exit(self):
        result, terminator, guard, _ = self.close(
            lambda now, t: [self.desktop] if now < 1 else [], force_after_timeout=True,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["reason"], "closed")
        self.assertEqual(result["forced_count"], 0)
        self.assertFalse(terminator.calls)
        guard.assert_not_called()

    def test_default_graceful_caller_never_forces_even_with_a_guard(self):
        result, terminator, guard, _ = self.close(lambda now, t: [self.desktop])
        self.assertFalse(result["ok"])
        self.assertFalse(result["force_attempted"])
        self.assertFalse(terminator.calls)
        guard.assert_not_called()

    def test_forces_only_proven_desktop_family_and_verifies_full_exit(self):
        family = [self.desktop, self.renderer, self.server]
        result, terminator, guard, clock = self.close(
            lambda now, t: [p for p in family if p.identity not in t.terminated] + [self.independent],
            force_after_timeout=True,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reason"], "forced_closed")
        self.assertEqual(result["forced_count"], 3)
        self.assertEqual(terminator.calls, [family])
        self.assertGreaterEqual(clock.now, 2)
        guard.assert_called_once_with()

    def test_window_already_hidden_still_exits_verified_desktop(self):
        closer = FakeCloser()
        closer.request = Mock()
        result, terminator, _, _ = self.close(
            lambda now, t: [] if t.calls else [self.desktop],
            closer=closer, force_after_timeout=True,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["requested_windows"], 0)
        self.assertEqual(terminator.calls, [[self.desktop]])

    def test_owned_server_retains_authority_after_parent_closes(self):
        result, terminator, _, _ = self.close(
            lambda now, t: ([self.desktop, self.server] if now < 1 else
                           [] if t.calls else [self.server]),
            force_after_timeout=True,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(terminator.calls, [[self.server]])

    def test_ownership_survives_between_service_precheck_and_shutdown(self):
        result, terminator, _, _ = self.close(
            lambda now, t: [] if t.calls else [self.server],
            observed=(self.server,), force_owned=(self.server,), force_after_timeout=True,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(terminator.calls, [[self.server]])

    def test_orphan_packaged_server_and_untrusted_desktop_block_all_force(self):
        orphan = CodexProcess(300, 999, 1005, "packaged_server", True)
        untrusted = replace(self.desktop, force_eligible=False)
        for snapshot in ([self.desktop, orphan], [untrusted]):
            with self.subTest(snapshot=snapshot):
                result, terminator, guard, _ = self.close(
                    lambda now, t: snapshot, force_after_timeout=True,
                )
                self.assertEqual(result["reason"], "force_ownership_uncertain")
                self.assertFalse(terminator.calls)
                guard.assert_not_called()

    def test_missing_guard_does_not_enable_force(self):
        result, terminator, _, _ = self.close(
            lambda now, t: [self.desktop], force_after_timeout=True, before_force=None,
        )
        self.assertEqual(result["reason"], "force_guard_missing")
        self.assertFalse(terminator.calls)

    def test_active_or_uncertain_turn_on_recheck_never_terminates(self):
        for code in ("codex_active_turn", "codex_turn_state_uncertain"):
            with self.subTest(code=code):
                terminator = FakeTerminator()
                guard = Mock(side_effect=GuardianPublicError(code, "fixture blocked"))
                with self.assertRaises(GuardianPublicError):
                    self.close(lambda now, t: [self.desktop], force_after_timeout=True,
                               terminator=terminator, before_force=guard)
                guard.assert_called_once_with()
                self.assertFalse(terminator.calls)

    def test_disabled_modal_blocks_force_even_after_a_close_was_sent(self):
        closer = FakeCloser()
        closer.disabled_windows = True
        result, terminator, _, _ = self.close(
            lambda now, t: [self.desktop], closer=closer, force_after_timeout=True,
        )
        self.assertEqual(result["reason"], "window_disabled")
        self.assertFalse(terminator.calls)

    def test_query_failure_and_new_desktop_never_force(self):
        restarted = replace(self.desktop, started=9000)
        for final, reason in ((None, "process_query_failed"), ([restarted], "desktop_restarted")):
            with self.subTest(reason=reason):
                result, terminator, _, _ = self.close(
                    lambda now, t: [self.desktop] if now < 1 else final,
                    force_after_timeout=True,
                )
                self.assertEqual(result["reason"], reason)
                self.assertFalse(terminator.calls)

    def test_pid_reuse_does_not_inherit_former_child_authority(self):
        reused = replace(self.server, parent_pid=1, started=9000)
        result, terminator, _, _ = self.close(
            lambda now, t: [self.desktop, self.server] if now < 1 else [reused],
            force_after_timeout=True,
        )
        self.assertTrue(result["ok"])
        self.assertFalse(terminator.calls)

    def test_permission_failure_is_redacted_and_never_claims_success(self):
        terminator = FakeTerminator()
        failure = OSError("private-path-or-command")
        failure.winerror = 5
        terminator.terminate = Mock(side_effect=failure)
        result, _, _, _ = self.close(
            lambda now, t: [self.desktop], terminator=terminator, force_after_timeout=True,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "force_termination_failed")
        self.assertEqual(result["win32_error"], 5)
        self.assertNotIn("private", json.dumps(result))

    def test_termination_request_is_not_success_until_all_processes_are_gone(self):
        result, terminator, _, clock = self.close(
            lambda now, t: [self.desktop], force_after_timeout=True,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "force_exit_timeout")
        self.assertEqual(len(terminator.calls), 1)
        self.assertGreaterEqual(clock.now, 7)

    def test_new_desktop_after_force_aborts_without_another_termination(self):
        restarted = replace(self.desktop, started=9000)
        result, terminator, _, _ = self.close(
            lambda now, t: [restarted] if t.calls else [self.desktop],
            force_after_timeout=True,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "desktop_restarted")
        self.assertEqual(terminator.calls, [[self.desktop]])

    def test_strict_ownership_rejects_unproven_parent_and_cycles(self):
        nested = CodexProcess(103, 102, 1004, "packaged_server", True)
        self.assertEqual(desktop_owned_processes(
            [self.desktop, self.server, nested, self.independent]),
            [self.desktop, self.server, nested])
        for parent in (replace(self.desktop, started=9000),
                       replace(self.desktop, force_eligible=False)):
            self.assertNotIn(self.server, desktop_owned_processes([parent, self.server]))
        cyclic = [CodexProcess(1, 2, 1, "runtime_server", True),
                  CodexProcess(2, 1, 1, "packaged_server", True)]
        self.assertEqual(desktop_owned_processes(cyclic), [])


if __name__ == "__main__":
    unittest.main()
