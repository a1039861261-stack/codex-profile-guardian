from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]


class CloudReleaseContractTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'PowerShell artifact verifier requires Windows')
    def test_artifact_verifier_accepts_complete_release_and_rejects_tampering(self) -> None:
        version = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
        commit = 'a' * 40
        binaries = ('CodexProfileGuardian.exe', 'CodexProfileGuardianSecret.exe',
                    'GuardianGateway.exe', 'GuardianGatewaySupervisor.exe')
        with tempfile.TemporaryDirectory(prefix='guardian-ci-assets-') as temporary:
            output = Path(temporary).resolve()
            archive = output / f'Codex-Profile-Guardian-Windows-x64-v{version}.zip'
            entries = []
            with zipfile.ZipFile(archive, 'w') as bundle:
                for name in binaries:
                    content = ('public-fixture-' + name).encode()
                    bundle.writestr(name, content)
                    entries.append(dict(name=name, relative_path=f'Codex-Profile-Guardian-Portable-v{version}/{name}',
                                        bytes=len(content), sha256=hashlib.sha256(content).hexdigest().upper()))
                bundle.writestr('VERSION', version)
                bundle.writestr('README-CN.md', 'public fixture')
                bundle.writestr('LICENSE', 'public fixture')
            installer = output / f'CodexProfileGuardianSetup-v{version}.exe'
            installer.write_bytes(b'public-fixture-installer')
            for asset in (archive, installer):
                content = asset.read_bytes()
                entries.append(dict(name=asset.name, relative_path=asset.name, bytes=len(content),
                                    sha256=hashlib.sha256(content).hexdigest().upper()))
            manifest = output / f'Codex-Profile-Guardian-v{version}-manifest.json'
            manifest.write_text(json.dumps(dict(product='Codex Profile Guardian', version=version,
                                                source_commit=commit, artifacts=entries)), encoding='utf-8')
            (output / f'Codex-Profile-Guardian-v{version}-SHA256SUMS.txt').write_text(
                '\n'.join(f"{entry['sha256']}  {entry['relative_path']}" for entry in entries) + '\n', encoding='utf-8')

            def verify(expected_commit: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
                                       str(ROOT / 'tools/verify-release-assets.ps1'), '-OutputRoot', str(output),
                                       '-ExpectedCommit', expected_commit], capture_output=True, text=True,
                                      timeout=20, creationflags=0x08000000)

            valid = verify(commit)
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
            self.assertNotEqual(verify('b' * 40).returncode, 0)
            installer.write_bytes(b'changed-public-fixture-installer')
            self.assertNotEqual(verify(commit).returncode, 0)

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
