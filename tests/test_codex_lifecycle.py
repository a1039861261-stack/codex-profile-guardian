import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from backend.codex_lifecycle import (
    CodexProcess, PROCESS_QUERY_SCRIPT, close_codex_gracefully,
    query_codex_processes, related_processes,
)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeCloser:
    def __init__(self):
        self.sent = set()
        self.disabled_windows = False
        self.requested = []

    def request(self, process):
        self.requested.append(process.identity)
        self.sent.add((*process.identity, 500))


class CodexLifecycleTests(unittest.TestCase):
    desktop = CodexProcess(100, 1, 1000, "desktop")
    renderer = CodexProcess(101, 100, 1001, "desktop_child")
    server = CodexProcess(102, 100, 1002, "runtime_server")
    independent = CodexProcess(200, 1, 1003, "runtime_server")

    def run_close(self, query, *, closer=None, timeout=30):
        clock = FakeClock()
        closer = closer or FakeCloser()
        result = close_codex_gracefully(
            timeout, query=lambda: query(clock.now), closer=closer, clock=clock, sleep=clock.sleep,
        )
        return result, closer, clock

    def test_runtime_server_requires_desktop_ancestry_not_only_executable_path(self):
        self.assertEqual(
            related_processes([self.desktop, self.renderer, self.server, self.independent]),
            [self.desktop, self.renderer, self.server],
        )

    def test_owned_nested_server_and_old_packaged_orphan_are_tracked(self):
        nested = CodexProcess(103, 102, 1004, "runtime_server")
        packaged = CodexProcess(104, 999, 1005, "packaged_server")
        self.assertEqual(related_processes([self.desktop, self.server, nested, packaged]), [self.desktop, self.server, nested, packaged])

    def test_reused_parent_pid_and_cycles_never_prove_runtime_ownership(self):
        newer_parent = CodexProcess(100, 1, 9000, "desktop")
        self.assertNotIn(self.server, related_processes([newer_parent, self.server]))
        cyclic = [CodexProcess(1, 2, 1, "runtime_server"), CodexProcess(2, 1, 1, "runtime_server")]
        self.assertEqual(related_processes(cyclic), [])

    def test_waits_past_old_five_second_cutoff(self):
        result, closer, clock = self.run_close(lambda now: [self.desktop, self.server] if now < 8 else [])
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(clock.now, 8)
        self.assertEqual(set(closer.requested), {self.desktop.identity})

    def test_tracks_owned_child_after_desktop_exits_without_closing_it(self):
        def query(now):
            if now < 1:
                return [self.desktop, self.server, self.independent]
            if now < 7:
                return [self.server, self.independent]
            return [self.independent]
        result, closer, clock = self.run_close(query)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(clock.now, 7)
        self.assertEqual(set(closer.requested), {self.desktop.identity})

    def test_never_treats_owned_orphan_as_closed_on_timeout(self):
        result, _, _ = self.run_close(lambda now: [self.desktop, self.server] if now < 1 else [self.server])
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "exit_timeout")
        self.assertEqual(result["remaining"], [{"pid": 102, "kind": "runtime_server"}])
        self.assertGreaterEqual(result["elapsed_ms"], 30000)

    def test_ownership_survives_parent_exit_between_precheck_and_close(self):
        clock = FakeClock()
        closer = FakeCloser()
        result = close_codex_gracefully(
            2, query=lambda: [self.server, self.independent], observed=(self.desktop, self.server),
            closer=closer, clock=clock, sleep=clock.sleep,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["remaining"], [{"pid": 102, "kind": "runtime_server"}])
        self.assertFalse(closer.sent)

    def test_independent_cli_reusing_owned_child_pid_is_not_closed_or_waited_on(self):
        reused = CodexProcess(102, 1, 9000, "runtime_server")
        result, closer, _ = self.run_close(lambda now: [self.desktop, self.server] if now < 1 else [reused])
        self.assertTrue(result["ok"])
        self.assertNotIn(reused.identity, closer.requested)

    def test_new_desktop_during_shutdown_aborts_without_closing_new_instance(self):
        restarted = CodexProcess(100, 1, 9000, "desktop")
        result, closer, _ = self.run_close(lambda now: [self.desktop] if now < 1 else [restarted])
        self.assertEqual(result["reason"], "desktop_restarted")
        self.assertFalse(result["ok"])
        self.assertNotIn(restarted.identity, closer.requested)

    def test_initial_and_mid_shutdown_query_failures_are_not_success(self):
        for query in (lambda now: None, lambda now: [self.desktop] if now < 1 else None):
            with self.subTest(query=query):
                result, _, _ = self.run_close(query)
                self.assertFalse(result["ok"])
                self.assertEqual(result["reason"], "process_query_failed")

    def test_missing_window_and_disabled_window_get_distinct_reasons(self):
        for disabled, reason in ((False, "no_close_window"), (True, "window_disabled")):
            closer = FakeCloser()
            closer.disabled_windows = disabled
            closer.request = Mock()
            result, _, _ = self.run_close(lambda now: [self.desktop], closer=closer)
            self.assertEqual(result["reason"], reason)
            self.assertFalse(result["ok"])

    def test_access_denied_excludes_exception_text_from_public_report(self):
        closer = FakeCloser()
        failure = OSError("sensitive-command-line-and-path")
        failure.winerror = 5
        closer.request = Mock(side_effect=failure)
        result, _, _ = self.run_close(lambda now: [self.desktop], closer=closer)
        self.assertEqual(result["reason"], "window_close_failed")
        self.assertEqual(result["win32_error"], 5)
        self.assertNotIn("sensitive", json.dumps(result))

    def test_native_backend_has_no_forced_termination_or_task_tree_command(self):
        from pathlib import Path
        source = (Path(__file__).resolve().parents[1] / "backend" / "codex_lifecycle.py").read_text(encoding="utf-8")
        for forbidden in ("taskkill", "TerminateProcess(", "Stop-Process", "GenerateConsoleCtrlEvent", ".kill("):
            self.assertNotIn(forbidden, source)
        self.assertIn("PostMessageW(hwnd, 0x0010, 0, 0)", source)

    def test_snapshot_parser_requires_complete_valid_identity_records(self):
        valid = {"version": 1, "processes": [self.desktop.__dict__]}
        with patch("backend.codex_lifecycle.os.name", "nt"), patch(
            "backend.codex_lifecycle.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps(valid), ""),
        ) as run:
            self.assertEqual(query_codex_processes(), [self.desktop])
        self.assertEqual(run.call_args.kwargs["creationflags"], 0x08000000)
        invalid = ["{}", "null", '[]', '{"version":1,"processes":null}',
                   json.dumps({"version": 1, "processes": [{"pid": True}]}),
                   json.dumps({"version": 1, "processes": [self.desktop.__dict__] * 2})]
        for payload in invalid:
            with self.subTest(payload=payload), patch("backend.codex_lifecycle.os.name", "nt"), patch(
                "backend.codex_lifecycle.subprocess.run", return_value=subprocess.CompletedProcess([], 0, payload, ""),
            ):
                self.assertIsNone(query_codex_processes())

    def test_snapshot_query_errors_and_timeout_are_unknown_not_empty(self):
        with patch("backend.codex_lifecycle.os.name", "nt"):
            with patch("backend.codex_lifecycle.subprocess.run", return_value=subprocess.CompletedProcess([], 2, "", "private-data")):
                self.assertIsNone(query_codex_processes())
            with patch("backend.codex_lifecycle.subprocess.run", side_effect=subprocess.TimeoutExpired("query", 5)):
                self.assertIsNone(query_codex_processes())

    def test_snapshot_script_knows_both_layouts_but_exports_no_raw_command_line(self):
        self.assertIn("OpenAI\\Codex\\bin", PROCESS_QUERY_SCRIPT)
        self.assertIn("resources\\\\codex", PROCESS_QUERY_SCRIPT)
        output = PROCESS_QUERY_SCRIPT.split("[ordered]@{", 1)[1].split("}", 1)[0]
        self.assertNotIn("CommandLine", output)
        self.assertNotIn("ExecutablePath", output)


if __name__ == "__main__":
    unittest.main()
