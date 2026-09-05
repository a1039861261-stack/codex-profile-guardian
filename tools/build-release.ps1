param(
    [switch]$SkipTests,
    [switch]$SkipInstaller,
    [switch]$AllowDirty,
    [switch]$IsolatedHostedRunner,
    [string]$StableInstaller = $env:GUARDIAN_STABLE_INSTALLER
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Version = (Get-Content -LiteralPath (Join-Path $ProjectRoot "VERSION") -Raw -Encoding UTF8).Trim()
$GatewayVersion = "v$Version"
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$PyInstaller = Join-Path $ProjectRoot ".venv\Scripts\pyinstaller.exe"
$OutputRoot = Join-Path $ProjectRoot "output"
$PortableName = "Codex-Profile-Guardian-Portable-v$Version"
$PortableRoot = Join-Path $OutputRoot $PortableName
$PortableStage = Join-Path $ProjectRoot "_tmp\release-$Version\portable"
$ZipPath = Join-Path $OutputRoot "Codex-Profile-Guardian-Windows-x64-v$Version.zip"
$InstallerPath = Join-Path $OutputRoot "CodexProfileGuardianSetup-v$Version.exe"
$ManifestPath = Join-Path $OutputRoot "Codex-Profile-Guardian-v$Version-manifest.json"
$SumsPath = Join-Path $OutputRoot "Codex-Profile-Guardian-v$Version-SHA256SUMS.txt"

function Invoke-Checked {
    param([string]$FilePath, [string[]]$Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $FilePath $($Arguments -join ' ')"
    }
}

function Read-PackageVersion {
    return [string]((Get-Content -LiteralPath (Join-Path $ProjectRoot "package.json") -Raw -Encoding UTF8 | ConvertFrom-Json).version)
}

function Assert-VersionConsistency {
    if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw "VERSION is invalid: $Version" }
    if ((Read-PackageVersion) -ne $Version) { throw "package.json version drift" }
    $Guardian = Get-Content -LiteralPath (Join-Path $ProjectRoot "backend\guardian.py") -Raw -Encoding UTF8
    if ($Guardian -notmatch ('APP_VERSION\s*=\s*"' + [regex]::Escape($Version) + '"')) { throw "backend version drift" }
    $Install = Get-Content -LiteralPath (Join-Path $ProjectRoot "installer\install.ps1") -Raw -Encoding UTF8
    if ($Install -notmatch ('\$Version\s*=\s*"' + [regex]::Escape($Version) + '"')) { throw "installer version drift" }
}

function Assert-StableBaseline {
    if ($IsolatedHostedRunner) {
        if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted") {
            throw "IsolatedHostedRunner requires an ephemeral GitHub-hosted runner"
        }
        if (-not [string]::IsNullOrWhiteSpace($StableInstaller)) {
            throw "Hosted isolation must not mount a local stable installer"
        }
        if ($Version -eq "1.6.2" -or (Test-Path -LiteralPath (Join-Path $OutputRoot "CodexProfileGuardianSetup-v1.6.2.exe"))) {
            throw "Hosted release must not contain or overwrite the v1.6.2 baseline"
        }
        return "absent_on_ephemeral_github_runner"
    }
    if ([string]::IsNullOrWhiteSpace($StableInstaller)) {
        throw "Stable v1.6.2 installer path is required via -StableInstaller or GUARDIAN_STABLE_INSTALLER"
    }
    $Stable = [System.IO.Path]::GetFullPath($StableInstaller)
    $Expected = "8B5EDA7461BD02E677CA5881804A1D90D25D994FCB46439AE9A9D642AAFABC40"
    if (-not (Test-Path -LiteralPath $Stable)) { throw "Stable v1.6.2 installer is missing" }
    if ((Get-FileHash -LiteralPath $Stable -Algorithm SHA256).Hash -ne $Expected) {
        throw "Stable v1.6.2 installer hash changed"
    }
    return "verified_local_file"
}

Set-Location $ProjectRoot
Assert-VersionConsistency
$BaselineVerification = Assert-StableBaseline
if (-not $AllowDirty) {
    $Dirty = @(git status --porcelain)
    if ($LASTEXITCODE -ne 0 -or $Dirty.Count -ne 0) { throw "Release build requires a clean worktree" }
}

if (-not (Test-Path -LiteralPath $Python) -or -not (Test-Path -LiteralPath $PyInstaller)) {
    throw "Python release environment is missing"
}

if (-not $SkipTests) {
    Invoke-Checked $Python @("-B", "-m", "unittest", "discover", "-s", "tests", "-v")
}
Invoke-Checked $Python @("-m", "pip", "check")
Invoke-Checked $Python @("-B", "-m", "compileall", "-q", "backend", "gateway", "main.py", "secret_helper.py", "guardian_gateway.py", "guardian_gateway_supervisor.py")
Invoke-Checked "pnpm.cmd" @("run", "build")
Invoke-Checked $Python @("-B", "tools\public_release_audit.py")
Invoke-Checked "git.exe" @("diff", "--check")

foreach ($Spec in @(
    "guardian.spec",
    "secret-helper.spec",
    "guardian-gateway.spec",
    "guardian-gateway-supervisor.spec"
)) {
    Invoke-Checked $PyInstaller @("--clean", "--noconfirm", $Spec)
}

$RequiredDist = [ordered]@{
    "CodexProfileGuardian.exe" = "CodexProfileGuardian.exe"
    "CodexProfileGuardianSecret.exe" = "CodexProfileGuardianSecret.exe"
    "GuardianGateway.exe" = "GuardianGateway.exe"
    "GuardianGatewaySupervisor.exe" = "GuardianGatewaySupervisor.exe"
}
foreach ($SourceName in $RequiredDist.Keys) {
    if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "dist\$SourceName"))) {
        throw "Missing PyInstaller artifact: $SourceName"
    }
}

$StageParent = Split-Path -Parent $PortableStage
if (Test-Path -LiteralPath $StageParent) {
    Remove-Item -LiteralPath $StageParent -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $PortableStage -Force | Out-Null
foreach ($SourceName in $RequiredDist.Keys) {
    Copy-Item -LiteralPath (Join-Path $ProjectRoot "dist\$SourceName") -Destination (Join-Path $PortableStage $RequiredDist[$SourceName]) -Force
}
Copy-Item -LiteralPath (Join-Path $ProjectRoot "README.md") -Destination (Join-Path $PortableStage "README-CN.md") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "LICENSE") -Destination (Join-Path $PortableStage "LICENSE") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "VERSION") -Destination (Join-Path $PortableStage "VERSION") -Force

if (Test-Path -LiteralPath $PortableRoot) { Remove-Item -LiteralPath $PortableRoot -Recurse -Force }
Move-Item -LiteralPath $PortableStage -Destination $PortableRoot
if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
Compress-Archive -Path (Join-Path $PortableRoot "*") -DestinationPath $ZipPath -CompressionLevel Optimal

if (-not $SkipInstaller) {
    & (Join-Path $ProjectRoot "installer\build-installer.ps1")
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $InstallerPath)) {
        throw "Installer build failed"
    }
    Invoke-Checked $Python @(
        "-B",
        "tools\g10_artifact_smoke.py",
        "--staging",
        (Join-Path $ProjectRoot "_tmp\installer-v$Version\staging")
    )
    Invoke-Checked $Python @(
        "-B",
        "tools\installer_exe_smoke.py",
        "--installer",
        $InstallerPath,
        "--portable",
        $PortableRoot
    )
}

$Artifacts = @(
    Join-Path $PortableRoot "CodexProfileGuardian.exe"
    Join-Path $PortableRoot "CodexProfileGuardianSecret.exe"
    Join-Path $PortableRoot "GuardianGateway.exe"
    Join-Path $PortableRoot "GuardianGatewaySupervisor.exe"
    $ZipPath
)
if (-not $SkipInstaller) { $Artifacts += $InstallerPath }

$Entries = foreach ($Artifact in $Artifacts) {
    $Item = Get-Item -LiteralPath $Artifact
    [ordered]@{
        name = $Item.Name
        relative_path = $Item.FullName.Substring($OutputRoot.TrimEnd("\").Length + 1).Replace("\", "/")
        bytes = $Item.Length
        sha256 = (Get-FileHash -LiteralPath $Item.FullName -Algorithm SHA256).Hash
    }
}
$Manifest = [ordered]@{
    schema_version = 1
    product = "Codex Profile Guardian"
    version = $Version
    gateway_version = $GatewayVersion
    generated_at = [DateTimeOffset]::UtcNow.ToString("o")
    signed = $false
    source_commit = (git rev-parse HEAD).Trim()
    source_tree = (git rev-parse 'HEAD^{tree}').Trim()
    stable_baseline = [ordered]@{
        version = "1.6.2"
        sha256 = "8B5EDA7461BD02E677CA5881804A1D90D25D994FCB46439AE9A9D642AAFABC40"
        verification = $BaselineVerification
    }
    artifacts = @($Entries)
}
$Utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ManifestPath, (($Manifest | ConvertTo-Json -Depth 6) + "`n"), $Utf8)
$SumLines = $Entries | ForEach-Object { "$($_.sha256)  $($_.relative_path)" }
[System.IO.File]::WriteAllLines($SumsPath, $SumLines, $Utf8)

[ordered]@{
    ok = $true
    version = $Version
    portable = $PortableRoot
    zip = $ZipPath
    installer = if ($SkipInstaller) { $null } else { $InstallerPath }
    manifest = $ManifestPath
    sha256sums = $SumsPath
    artifact_count = $Entries.Count
} | ConvertTo-Json -Depth 4
