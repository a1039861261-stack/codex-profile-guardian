$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Version = (Get-Content -LiteralPath (Join-Path $ProjectRoot "VERSION") -Raw -Encoding UTF8).Trim()
$PortableDir = Join-Path $ProjectRoot "output\Codex-Profile-Guardian-Portable-v$Version"
$OutputDir = Join-Path $ProjectRoot "output"
$BuildRoot = Join-Path $ProjectRoot "_tmp\installer-v$Version"
$StagingDir = Join-Path $BuildRoot "staging"
$InstallerPath = Join-Path $OutputDir "CodexProfileGuardianSetup-v$Version.exe"
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$PyInstaller = Join-Path $ProjectRoot ".venv\Scripts\pyinstaller.exe"
$IconPath = Join-Path $ProjectRoot "assets\guardian.ico"

foreach ($Path in @($BuildRoot, $StagingDir)) {
    $FullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not $FullPath.StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe build path: $FullPath"
    }
}

$Required = @(
    "CodexProfileGuardian.exe",
    "CodexProfileGuardianSecret.exe",
    "GuardianGateway.exe",
    "GuardianGatewaySupervisor.exe",
    "README-CN.md",
    "LICENSE"
)
foreach ($Name in $Required) {
    if (-not (Test-Path -LiteralPath (Join-Path $PortableDir $Name))) {
        throw "Portable build file not found: $Name"
    }
}
foreach ($Path in @($Python, $PyInstaller, $IconPath)) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "Installer build dependency not found: $Path" }
}

if (Test-Path -LiteralPath $BuildRoot) {
    Remove-Item -LiteralPath $BuildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

foreach ($Name in $Required) {
    Copy-Item -LiteralPath (Join-Path $PortableDir $Name) -Destination (Join-Path $StagingDir $Name) -Force
}
Copy-Item -LiteralPath $IconPath -Destination (Join-Path $StagingDir "guardian.ico") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "installer\install.ps1") -Destination (Join-Path $StagingDir "install.ps1") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "installer\uninstall.ps1") -Destination (Join-Path $StagingDir "uninstall.ps1") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "VERSION") -Destination (Join-Path $StagingDir "VERSION") -Force

$ManifestFiles = foreach ($Path in Get-ChildItem -LiteralPath $StagingDir -File | Sort-Object Name) {
    [ordered]@{
        name = $Path.Name
        bytes = $Path.Length
        sha256 = (Get-FileHash -LiteralPath $Path.FullName -Algorithm SHA256).Hash
    }
}
$Manifest = [ordered]@{
    schema_version = 1
    product = "Codex Profile Guardian"
    version = $Version
    files = @($ManifestFiles)
}
$Utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    (Join-Path $StagingDir "payload-manifest.json"),
    (($Manifest | ConvertTo-Json -Depth 5) + "`n"),
    $Utf8
)

if (Test-Path -LiteralPath $InstallerPath) {
    Remove-Item -LiteralPath $InstallerPath -Force
}

& $PyInstaller @(
    "--clean",
    "--noconfirm",
    "--onefile",
    "--windowed",
    "--name", "CodexProfileGuardianSetup-v$Version",
    "--icon", $IconPath,
    "--distpath", (Join-Path $BuildRoot "dist"),
    "--workpath", (Join-Path $BuildRoot "work"),
    "--specpath", (Join-Path $BuildRoot "spec"),
    "--add-data", "$StagingDir;payload",
    (Join-Path $ProjectRoot "installer\setup_bootstrap.py")
)
if ($LASTEXITCODE -ne 0) { throw "Installer PyInstaller build failed" }

$BuiltInstaller = Join-Path $BuildRoot "dist\CodexProfileGuardianSetup-v$Version.exe"
if (-not (Test-Path -LiteralPath $BuiltInstaller)) { throw "Installer was not created: $BuiltInstaller" }
Copy-Item -LiteralPath $BuiltInstaller -Destination $InstallerPath -Force

$Hash = Get-FileHash -Algorithm SHA256 -LiteralPath $InstallerPath
[pscustomobject]@{
    Installer = $InstallerPath
    Bytes = (Get-Item -LiteralPath $InstallerPath).Length
    SHA256 = $Hash.Hash
    Staging = $StagingDir
    Packaging = "pyinstaller-onefile-bootstrap"
} | ConvertTo-Json -Depth 3
