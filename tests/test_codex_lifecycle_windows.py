import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import Mock

from backend.codex_lifecycle import CodexProcess, WindowsWindowCloser, WindowsProcessTerminator, close_codex_gracefully


@unittest.skipUnless(os.name == "nt", "Win32 graceful-close integration")
class WindowsCloseIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = []

    def tearDown(self):
        # Exact Popen handles of disposable test processes only. Never enumerate
        # or kill a user process, actual Codex, a name, or an arbitrary PID.
        for process, _ in self.fixtures:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def start_fixture(self, *, mode="close", delay=0, windows=1, kind="desktop"):
        fixture = Path(__file__).parent / "fixtures" / "codex_close_window.py"
        process = subprocess.Popen(
            # Windows venv python.exe is a redirector with a different child
            # PID. The base interpreter gives this test a direct process handle.
            [getattr(sys, "_base_executable", sys.executable), "-B", str(fixture), mode, str(delay), str(windows)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000,
        )
        self.fixtures.append((process, None))
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
        line = ready.get(timeout=10)
        self.assertTrue(line, "isolated test window did not start")
        data = json.loads(line)
        self.assertEqual(data["pid"], process.pid)
        identity = CodexProcess(process.pid, os.getpid(), data["started"], kind, True)
        self.fixtures[-1] = (process, identity)
        return process, identity

    def snapshot(self):
        # An explicit allowlist populated ONLY by this test's Popen handles.
        # Never use the production discovery function for a close integration.
        return [identity for process, identity in self.fixtures if identity and process.poll() is None]

    def test_real_native_window_closes_and_waits_more_than_five_seconds(self):
        process, _ = self.start_fixture(delay=6100)
        started = time.monotonic()
        result = close_codex_gracefully(12, query=self.snapshot)
        self.assertTrue(result["ok"], result)
        self.assertGreater(time.monotonic() - started, 5)
        self.assertEqual(result["requested_windows"], 1)
        self.assertEqual(process.wait(timeout=2), 0)

    def test_all_windows_close_but_an_independent_cli_is_untouched(self):
        target, _ = self.start_fixture(windows=2)
        independent, _ = self.start_fixture(kind="runtime_server")
        result = close_codex_gracefully(5, query=self.snapshot)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["requested_windows"], 2)
        self.assertEqual(target.wait(timeout=2), 0)
        self.assertIsNone(independent.poll())

    def test_refusing_window_stays_alive_after_timeout(self):
        process, _ = self.start_fixture(mode="ignore")
        result = close_codex_gracefully(1, query=self.snapshot)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "exit_timeout")
        self.assertEqual(result["requested_windows"], 1)
        self.assertIsNone(process.poll())

    def test_wrong_process_creation_time_never_receives_close(self):
        process, identity = self.start_fixture()
        wrong = CodexProcess(identity.pid, identity.parent_pid, identity.started + 1, "desktop")
        closer = WindowsWindowCloser()
        result = close_codex_gracefully(1, query=lambda: [wrong], closer=closer)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "window_close_failed")
        self.assertEqual(result["requested_windows"], 0)
        self.assertIsNone(process.poll())


    def test_background_survives_window_close_then_guarded_force_exits_it(self):
        target, _ = self.start_fixture(mode="background")
        independent, _ = self.start_fixture(kind="runtime_server")
        guard = Mock()
        result = close_codex_gracefully(
            1, query=self.snapshot, force_after_timeout=True, before_force=guard,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reason"], "forced_closed")
        self.assertEqual(result["forced_count"], 1)
        self.assertEqual(result["requested_windows"], 1)
        guard.assert_called_once_with()
        self.assertEqual(target.wait(timeout=2), 1)
        self.assertIsNone(independent.poll())

    def test_refusing_window_can_be_forced_only_after_task_guard(self):
        target, _ = self.start_fixture(mode="ignore")
        result = close_codex_gracefully(
            1, query=self.snapshot, force_after_timeout=True, before_force=lambda: None,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["forced_count"], 1)
        self.assertEqual(target.wait(timeout=2), 1)

    def test_batch_identity_mismatch_never_terminates_even_first_valid_process(self):
        first, identity = self.start_fixture(mode="ignore")
        second, other = self.start_fixture(mode="ignore")
        wrong = CodexProcess(other.pid, other.parent_pid, other.started + 1, "desktop", True)
        terminator = WindowsProcessTerminator()
        guard = Mock()
        with self.assertRaises(OSError):
            terminator.terminate([identity, wrong], guard)
        self.assertFalse(terminator.terminated)
        guard.assert_not_called()
        self.assertIsNone(first.poll())
        self.assertIsNone(second.poll())

    def test_new_activity_after_handles_are_pinned_prevents_termination(self):
        target, identity = self.start_fixture(mode="ignore")
        terminator = WindowsProcessTerminator()
        guard = Mock(side_effect=RuntimeError("active_fixture"))
        with self.assertRaisesRegex(RuntimeError, "active_fixture"):
            terminator.terminate([identity], guard)
        guard.assert_called_once_with()
        self.assertFalse(terminator.terminated)
        self.assertIsNone(target.poll())


if __name__ == "__main__":
    unittest.main()
