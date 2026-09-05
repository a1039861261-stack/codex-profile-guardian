from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CloudReleaseContractTests(unittest.TestCase):
    def test_cloud_build_keeps_all_acceptance_gates(self) -> None:
        workflow = (ROOT / '.github/workflows/windows-release.yml').read_text(encoding='utf-8')
        self.assertIn('runs-on: windows-2022', workflow)
        self.assertNotIn('self-hosted', workflow)
        self.assertIn('build-release.ps1 -IsolatedHostedRunner', workflow)
        for forbidden in ('-SkipTests', '-SkipInstaller', '-AllowDirty', 'pull_request_target'):
            self.assertNotIn(forbidden, workflow)
        self.assertIn('retention-days: 3', workflow)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.publish && github.ref == 'refs/heads/main'", workflow)

    def test_publisher_fails_closed_and_verifies_uploads(self) -> None:
        source = (ROOT / 'tools/publish-github-release.ps1').read_text(encoding='utf-8')
        self.assertIn('verify-release-assets.ps1', source)
        self.assertIn('GITHUB_EVENT_NAME', source)
        self.assertIn('matching-refs/tags/', source)
        self.assertIn('--draft', source)
        self.assertIn('digest -cne $Digest', source)
        self.assertNotIn('--clobber', source)
        self.assertNotIn('release delete', source)
        self.assertLess(source.index('digest -cne $Digest'), source.index('release edit'))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell baseline guard requires Windows')
    def test_baseline_guards_host_identity_and_preserves_local_gate(self) -> None:
        release = (ROOT / 'tools/build-release.ps1').read_text(encoding='utf-8')
        function = 'function Assert-StableBaseline {' + release.split('function Assert-StableBaseline {', 1)[1].split('\nSet-Location $ProjectRoot', 1)[0]
        scenarios = (
            ('local-missing', False, '', '', '1.10.5', '', False),
            ('local-spoofed', True, 'false', 'github-hosted', '1.10.5', '', False),
            ('self-hosted', True, 'true', 'self-hosted', '1.10.5', '', False),
            ('mixed-baseline', True, 'true', 'github-hosted', '1.10.5', 'fixture.exe', False),
            ('stable-version', True, 'true', 'github-hosted', '1.6.2', '', False),
            ('ephemeral', True, 'true', 'github-hosted', '1.10.5', '', True),
        )
        with tempfile.TemporaryDirectory(prefix='guardian-ci-guard-') as temporary:
            for name, isolated, actions, runner, version, stable, expected_ok in scenarios:
                with self.subTest(name=name):
                    env = dict(os.environ, GITHUB_ACTIONS=actions, RUNNER_ENVIRONMENT=runner,
                               FIXTURE_OUTPUT=temporary, FIXTURE_VERSION=version,
                               FIXTURE_ISOLATED=str(isolated), FIXTURE_STABLE=stable)
                    script = ("$ErrorActionPreference='Stop'; $OutputRoot=$env:FIXTURE_OUTPUT; "
                              "$Version=$env:FIXTURE_VERSION; $StableInstaller=$env:FIXTURE_STABLE; "
                              "$IsolatedHostedRunner=$env:FIXTURE_ISOLATED -eq 'True';\n" + function +
                              "\ntry { Assert-StableBaseline; exit 0 } catch { Write-Output $_.Exception.Message; exit 1 }")
                    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                            env=env, capture_output=True, text=True, timeout=20,
                                            creationflags=0x08000000)
                    self.assertEqual(result.returncode == 0, expected_ok, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
