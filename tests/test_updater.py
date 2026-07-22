from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib import error as urlerror

from backend.updater import (
    MAX_RELEASE_BYTES,
    RELEASES_API,
    GitHubReleaseUpdater,
    UpdateError,
    _default_fetch,
    parse_version,
)


class ReleaseFixture:
    def __init__(self, version: str = "1.9.0", payload: bytes = b"verified-installer") -> None:
        self.version = version
        self.payload = payload
        self.installer_name = f"CodexProfileGuardianSetup-v{version}.exe"
        self.manifest_name = f"Codex-Profile-Guardian-v{version}-manifest.json"
        self.installer_url = f"https://github.com/a1039861261-stack/codex-profile-guardian/releases/download/v{version}/{self.installer_name}"
        self.manifest_url = f"https://github.com/a1039861261-stack/codex-profile-guardian/releases/download/v{version}/{self.manifest_name}"
        self.release = {
            "tag_name": f"v{version}",
            "draft": False,
            "prerelease": False,
            "html_url": f"https://github.com/a1039861261-stack/codex-profile-guardian/releases/tag/v{version}",
            "assets": [
                {"name": self.installer_name, "browser_download_url": self.installer_url, "size": len(payload)},
                {"name": self.manifest_name, "browser_download_url": self.manifest_url, "size": 1},
            ],
        }
        self.manifest = {
            "product": "Codex Profile Guardian",
            "version": version,
            "artifacts": [{
                "name": self.installer_name,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }],
        }

    def fetch(self, url: str, headers, limit: int):
        if url == RELEASES_API:
            return json.dumps(self.release).encode("utf-8"), {"ETag": '"fixture-etag"'}
        if url == self.manifest_url:
            return json.dumps(self.manifest).encode("utf-8"), {}
        if url == self.installer_url:
            return self.payload, {}
        raise AssertionError(f"unexpected URL: {url}")


class GitHubReleaseUpdaterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def updater(self, fixture: ReleaseFixture, *, current: str = "1.8.7", launcher=None):
        return GitHubReleaseUpdater(
            current,
            self.root,
            fetch=fixture.fetch,
            launcher=launcher or (lambda path: None),
        )

    def test_semantic_version_parsing_and_invalid_values(self) -> None:
        self.assertEqual(parse_version("v1.10.2"), (1, 10, 2))
        for value in ("1.2", "1.02.3", "latest", "1.2.3-beta"):
            with self.subTest(value=value), self.assertRaises(UpdateError):
                parse_version(value)

    def test_newer_release_download_and_explicit_verified_install(self) -> None:
        fixture = ReleaseFixture()
        launched: list[Path] = []
        updater = self.updater(fixture, launcher=launched.append)
        self.assertEqual(updater.check()["state"], "available")
        self.assertEqual(updater.download()["state"], "downloaded")
        with self.assertRaisesRegex(UpdateError, "update_install_confirmation_required"):
            updater.install(confirmed=False)
        result = updater.install(confirmed=True)
        self.assertEqual(result["state"], "installing")
        self.assertEqual(len(launched), 1)
        self.assertTrue(launched[0].is_file())
        self.assertTrue(str(launched[0]).startswith(str((self.root / "updates").resolve())))

    def test_current_and_older_releases_are_not_offered(self) -> None:
        for version in ("1.8.7", "1.8.6"):
            with self.subTest(version=version):
                fixture = ReleaseFixture(version)
                updater = GitHubReleaseUpdater("1.8.7", self.root / version, fetch=fixture.fetch)
                self.assertEqual(updater.check()["state"], "up_to_date")
                with self.assertRaisesRegex(UpdateError, "update_not_available"):
                    updater.download()

    def test_draft_prerelease_and_malformed_release_are_rejected(self) -> None:
        variants = [
            ("draft", {"draft": True}),
            ("prerelease", {"prerelease": True}),
            ("malformed", {"assets": "invalid"}),
        ]
        for name, change in variants:
            with self.subTest(name=name):
                fixture = ReleaseFixture()
                fixture.release.update(change)
                result = self.updater(fixture).check()
                self.assertEqual(result["state"], "error")
                self.assertIsNotNone(result["error_code"])

    def test_missing_assets_and_manifest_identity_are_rejected(self) -> None:
        fixture = ReleaseFixture()
        fixture.release["assets"] = fixture.release["assets"][:1]
        self.assertEqual(self.updater(fixture).check()["error_code"], "update_assets_missing")

        fixture = ReleaseFixture()
        fixture.manifest["product"] = "Other Product"
        self.assertEqual(self.updater(fixture).check()["error_code"], "update_manifest_identity_mismatch")

        fixture = ReleaseFixture()
        fixture.manifest["version"] = "9.9.9"
        self.assertEqual(self.updater(fixture).check()["error_code"], "update_manifest_identity_mismatch")

    def test_manifest_and_installer_integrity_mismatches_are_rejected(self) -> None:
        fixture = ReleaseFixture()
        fixture.release["assets"][0]["size"] += 1
        self.assertEqual(self.updater(fixture).check()["error_code"], "update_manifest_installer_invalid")

        fixture = ReleaseFixture()
        fixture.manifest["artifacts"][0]["sha256"] = "0" * 64
        updater = self.updater(fixture)
        self.assertEqual(updater.check()["state"], "available")
        with self.assertRaisesRegex(UpdateError, "update_installer_hash_mismatch"):
            updater.download()

        fixture = ReleaseFixture()
        updater = self.updater(fixture)
        updater.check()
        fixture.payload += b"changed"
        with self.assertRaisesRegex(UpdateError, "update_installer_size_mismatch"):
            updater.download()

    def test_rejects_untrusted_or_insecure_asset_urls(self) -> None:
        for url in (
            "http://github.com/release.exe",
            "https://example.invalid/release.exe",
            "https://user:password@github.com/release.exe",
        ):
            with self.subTest(url=url):
                fixture = ReleaseFixture()
                fixture.release["assets"][0]["browser_download_url"] = url
                self.assertEqual(self.updater(fixture).check()["error_code"], "update_url_rejected")

    def test_tampered_download_is_refused_before_launcher(self) -> None:
        fixture = ReleaseFixture()
        launched: list[Path] = []
        updater = self.updater(fixture, launcher=launched.append)
        updater.check()
        updater.download()
        target = next((self.root / "updates").glob("v*/*.exe"))
        target.write_bytes(b"tampered-package")
        with self.assertRaises(UpdateError):
            updater.install(confirmed=True)
        self.assertEqual(launched, [])

    def test_public_status_does_not_expose_local_paths_or_manifest_hash(self) -> None:
        fixture = ReleaseFixture()
        updater = self.updater(fixture)
        updater.check()
        updater.download()
        serialized = json.dumps(updater.status(), sort_keys=True)
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn(fixture.manifest["artifacts"][0]["sha256"], serialized)
        self.assertNotIn("installer_file", updater.status())

    def test_etag_is_reused_and_not_modified_keeps_last_result(self) -> None:
        fixture = ReleaseFixture()
        calls = 0

        def fetch(url, headers, limit):
            nonlocal calls
            if url == RELEASES_API:
                calls += 1
                if calls == 2:
                    self.assertEqual(headers.get("If-None-Match"), '"fixture-etag"')
                    raise UpdateError("update_not_modified")
            return fixture.fetch(url, headers, limit)

        updater = GitHubReleaseUpdater("1.8.7", self.root, fetch=fetch)
        self.assertEqual(updater.check()["state"], "available")
        self.assertEqual(updater.check()["state"], "available")

    def test_private_repository_and_rate_limit_are_mapped(self) -> None:
        for status, code in ((404, "update_repository_unavailable"), (403, "update_rate_limited"), (429, "update_rate_limited")):
            error = urlerror.HTTPError(RELEASES_API, status, "fixture", {}, None)
            with self.subTest(status=status), patch("backend.updater.urlrequest.urlopen", side_effect=error):
                with self.assertRaisesRegex(UpdateError, code):
                    _default_fetch(RELEASES_API, {}, MAX_RELEASE_BYTES)


if __name__ == "__main__":
    unittest.main()
