from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from gateway.platforms.linux import (
    LinuxGatewayLayout,
    LinuxPlatformError,
    StdinBundleApplier,
    SystemdUserUnit,
)
from gateway.secrets import PosixFileSecretResolver
from gateway.tokens import PosixTokenStore, TokenStoreError


class LinuxGatewayPlatformTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name).resolve()
        self.layout = LinuxGatewayLayout(self.home)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_stdin_bundle_is_atomic_private_and_resolvable(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX permission semantics require a POSIX runtime")
        document = {
            "schema_version": 1,
            "config": {"schema_version": 1, "active_group": {"revision": 2}},
            "secrets": {
                "primary.r2": "fixture-primary",
                "backup.r2": "fixture-backup",
            },
        }
        result = StdinBundleApplier(self.layout).apply(
            io.BytesIO(json.dumps(document).encode("utf-8"))
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["secret_count"], 2)
        for path in (self.layout.config, self.layout.secrets, self.layout.state):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for path in (
            self.layout.config / "active.json",
            self.layout.secrets / "primary.r2.key",
            self.layout.secrets / "backup.r2.key",
        ):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        resolver = PosixFileSecretResolver(self.layout.secrets)
        self.assertEqual(resolver.resolve("profile:primary:r2"), "fixture-primary")

    def test_posix_secret_and_token_permissions_fail_closed(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX permission semantics require a POSIX runtime")
        self.layout.ensure_private_directories()
        secret = self.layout.secrets / "primary.r2.key"
        secret.write_text("fixture-primary", encoding="utf-8")
        secret.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "guardian_upstream_credential_unavailable"):
            PosixFileSecretResolver(self.layout.secrets).resolve("profile:primary:r2")

        store = PosixTokenStore(self.layout.config / "tokens")
        values = store.ensure()
        self.assertNotEqual(values["ingress"], values["control"])
        ingress = self.layout.config / "tokens" / "ingress.token"
        self.assertEqual(stat.S_IMODE(ingress.stat().st_mode), 0o600)
        ingress.chmod(0o644)
        with self.assertRaisesRegex(TokenStoreError, "gateway_token_read_failed"):
            store.read_existing("ingress")

    def test_bundle_rejects_traversal_links_and_oversize(self) -> None:
        invalid = {
            "schema_version": 1,
            "config": {},
            "secrets": {"../escape": "fixture"},
        }
        with self.assertRaisesRegex(LinuxPlatformError, "linux_gateway_bundle_secret_invalid"):
            StdinBundleApplier(self.layout).apply(io.BytesIO(json.dumps(invalid).encode()))
        with self.assertRaisesRegex(LinuxPlatformError, "linux_gateway_bundle_too_large"):
            StdinBundleApplier(self.layout, max_bytes=4).apply(io.BytesIO(b"12345"))

    def test_systemd_user_unit_contains_paths_but_no_credentials(self) -> None:
        unit = SystemdUserUnit(
            executable=self.layout.release_path("v1.7.0") / "guardian-gateway",
            install_root=self.layout.gateway_root,
            config_path=self.layout.config / "active.json",
        ).render()
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("StartLimitBurst=5", unit)
        self.assertIn("UMask=0077", unit)
        self.assertNotIn("Bearer", unit)
        self.assertNotIn("fixture-primary", unit)

    def test_systemd_unit_quotes_spaces_and_rejects_specifiers(self) -> None:
        unit = SystemdUserUnit(
            executable=self.home / "release with space" / "guardian-gateway",
            install_root=self.layout.gateway_root,
            config_path=self.layout.config / "active config.json",
        ).render()
        self.assertIn('ExecStart="', unit)
        self.assertIn('" --install-root "', unit)
        with self.assertRaisesRegex(LinuxPlatformError, "linux_gateway_unit_argument_invalid"):
            SystemdUserUnit(
                executable=self.home / "%n" / "guardian-gateway",
                install_root=self.layout.gateway_root,
                config_path=self.layout.config / "active.json",
            ).render()


if __name__ == "__main__":
    unittest.main()
