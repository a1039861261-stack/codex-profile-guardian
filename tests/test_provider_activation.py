from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from backend.provider_activation import (
    PROVIDER_ID,
    ProviderActivationCoordinator,
    ProviderActivationError,
)
from gateway.dpapi import protect_current_user, unprotect_current_user
from gateway.tokens import ProtectedTokenStore


class ProviderActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.codex = self.root / ".codex"
        self.data = self.root / "guardian-data"
        self.codex.mkdir()
        self.original = (
            'model = "fixture-model"\n'
            'model_provider = "openai"\n'
            '[features]\n'
            'memories = true\n'
        ).encode("utf-8")
        (self.codex / "config.toml").write_bytes(self.original)
        for relative, payload in (
            ("sessions/active.jsonl", b"active fixture\n"),
            ("archived_sessions/old.jsonl", b"archived fixture\n"),
            ("session_index.jsonl", b"index fixture\n"),
            ("state_5.sqlite", b"sqlite fixture\n"),
        ):
            path = self.codex / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.protected_hashes = self._protected_hashes()
        self.gateway = {
            "ok": True,
            "phase": "running",
            "host": "127.0.0.1",
            "data_port": 43117,
            "config_revision": 7,
            "instance_id": "fixture-instance",
            "models_ready": True,
        }
        self.coordinator = ProviderActivationCoordinator(
            codex_home=self.codex,
            data_dir=self.data,
            gateway_status=lambda: self.gateway,
            auth_command=("guardian-helper.exe", "gateway-token", str(self.data)),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _protected_hashes(self) -> dict[str, str]:
        result = {}
        for relative in (
            "sessions/active.jsonl",
            "archived_sessions/old.jsonl",
            "session_index.jsonl",
            "state_5.sqlite",
        ):
            payload = (self.codex / relative).read_bytes()
            result[relative] = hashlib.sha256(payload).hexdigest()
        return result

    def test_activation_uses_fixed_loopback_provider_and_preserves_chat_files(self) -> None:
        result = self.coordinator.activate(expected_revision=7)
        self.assertEqual(result["status"], "active")
        config = (self.codex / "config.toml").read_text(encoding="utf-8")
        self.assertIn(f'model_provider = "{PROVIDER_ID}"', config)
        self.assertIn('base_url = "http://127.0.0.1:43117/v1"', config)
        self.assertIn("request_max_retries = 0", config)
        self.assertIn("stream_max_retries = 0", config)
        self.assertIn('model = "fixture-model"', config)
        self.assertIn("memories = true", config)
        self.assertNotIn("upstream-secret", config)
        self.assertEqual(self._protected_hashes(), self.protected_hashes)
        self.assertEqual(self.coordinator.activate(expected_revision=7), result)

    def test_gateway_must_be_ready_before_config_changes(self) -> None:
        self.gateway["models_ready"] = False
        with self.assertRaisesRegex(ProviderActivationError, "models_not_ready"):
            self.coordinator.activate(expected_revision=7)
        self.assertEqual((self.codex / "config.toml").read_bytes(), self.original)
        self.assertFalse(self.coordinator.state_path.exists())

    def test_restore_is_exact_and_refuses_config_drift(self) -> None:
        self.coordinator.activate(expected_revision=7)
        restored = self.coordinator.restore()
        self.assertEqual(restored["status"], "restored")
        self.assertEqual((self.codex / "config.toml").read_bytes(), self.original)
        self.assertEqual(self._protected_hashes(), self.protected_hashes)

        second = ProviderActivationCoordinator(
            codex_home=self.codex,
            data_dir=self.root / "second-data",
            gateway_status=lambda: self.gateway,
            auth_command=("guardian-helper.exe", "gateway-token", str(self.data)),
        )
        second.activate(expected_revision=7)
        with (self.codex / "config.toml").open("ab") as stream:
            stream.write(b"# user drift\n")
        with self.assertRaisesRegex(ProviderActivationError, "config_drift"):
            second.restore()

    def test_config_write_failure_rolls_back_original(self) -> None:
        calls = 0

        def failing_writer(path: Path, payload: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("fixture write failure")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)

        coordinator = ProviderActivationCoordinator(
            codex_home=self.codex,
            data_dir=self.root / "failing-data",
            gateway_status=lambda: self.gateway,
            auth_command=("guardian-helper.exe", "gateway-token", str(self.data)),
            config_writer=failing_writer,
        )
        with self.assertRaisesRegex(ProviderActivationError, "activation_failed"):
            coordinator.activate(expected_revision=7)
        self.assertEqual((self.codex / "config.toml").read_bytes(), self.original)

    def test_gateway_identity_change_rolls_back_original(self) -> None:
        calls = 0

        def changing_gateway() -> dict[str, object]:
            nonlocal calls
            calls += 1
            value = dict(self.gateway)
            if calls > 1:
                value["instance_id"] = "replacement-instance"
            return value

        coordinator = ProviderActivationCoordinator(
            codex_home=self.codex,
            data_dir=self.root / "identity-change-data",
            gateway_status=changing_gateway,
            auth_command=("guardian-helper.exe", "gateway-ingress", str(self.data)),
        )
        with self.assertRaisesRegex(ProviderActivationError, "identity_changed"):
            coordinator.activate(expected_revision=7)
        self.assertEqual((self.codex / "config.toml").read_bytes(), self.original)

    def test_restore_removes_config_when_original_was_absent(self) -> None:
        self.coordinator.config_path.unlink()
        self.coordinator.activate(expected_revision=7)
        self.assertTrue(self.coordinator.config_path.is_file())
        restored = self.coordinator.restore()
        self.assertEqual(restored["status"], "restored")
        self.assertFalse(self.coordinator.config_path.exists())
        self.assertEqual(self._protected_hashes(), self.protected_hashes)

    @unittest.skipUnless(os.name == "nt", "Windows current-user DPAPI helper")
    def test_gateway_ingress_helper_returns_only_local_token(self) -> None:
        token_store = ProtectedTokenStore(
            self.data / "gateway" / "secrets" / "tokens",
            protect=protect_current_user,
            unprotect=unprotect_current_user,
        )
        values = dict(token_store.ensure())
        command = [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "main.py"),
            "gateway-ingress",
            str(self.data),
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.decode("ascii"), values["ingress"])
        self.assertNotIn(values["control"].encode("ascii"), completed.stdout)
        self.assertNotIn(values["ingress"], subprocess.list2cmdline(command))


if __name__ == "__main__":
    unittest.main()
