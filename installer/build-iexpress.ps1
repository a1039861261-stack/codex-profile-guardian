$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Version = (Get-Content -LiteralPath (Join-Path $ProjectRoot "VERSION") -Raw -Encoding UTF8).Trim()
$PortableDir = Join-Path $ProjectRoot "output\Codex-Profile-Guardian-Portable-v$Version"
$OutputDir = Join-Path $ProjectRoot "output"
$BuildRoot = Join-Path $ProjectRoot "_tmp\installer-v$Version"
$StagingDir = Join-Path $BuildRoot "staging"
$InstallerPath = Join-Path $OutputDir "CodexProfileGuardianSetup-v$Version.exe"
$SedPath = Join-Path $BuildRoot "CodexProfileGuardianSetup-v$Version.sed"
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
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

if (Test-Path -LiteralPath $BuildRoot) {
    Remove-Item -LiteralPath $BuildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

foreach ($Name in $Required) {
    Copy-Item -LiteralPath (Join-Path $PortableDir $Name) -Destination (Join-Path $StagingDir $Name) -Force
}
Copy-Item -LiteralPath (Join-Path $ProjectRoot "installer\install.ps1") -Destination (Join-Path $StagingDir "install.ps1") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "installer\uninstall.ps1") -Destination (Join-Path $StagingDir "uninstall.ps1") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "VERSION") -Destination (Join-Path $StagingDir "VERSION") -Force

if (Test-Path -LiteralPath $InstallerPath) {
    Remove-Item -LiteralPath $InstallerPath -Force
}

$SourcePath = $StagingDir.TrimEnd("\")
$TargetPath = $InstallerPath
$SedContent = @"
[Version]
Class=IEXPRESS
SEDVersion=3

[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles

[SourceFiles]
SourceFiles0=$SourcePath

[SourceFiles0]
%FILE0%=
%FILE1%=
%FILE2%=
%FILE3%=
%FILE4%=
%FILE5%=
%FILE6%=
%FILE7%=
%FILE8%=

[Strings]
InstallPrompt=
DisplayLicense=LICENSE
FinishMessage=
TargetName=$TargetPath
FriendlyName=Codex Profile Guardian Setup
AppLaunched=powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1
PostInstallCmd=<None>
AdminQuietInstCmd=powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1 -NoLaunch
UserQuietInstCmd=powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1 -NoLaunch
FILE0=install.ps1
FILE1=uninstall.ps1
FILE2=CodexProfileGuardian.exe
FILE3=CodexProfileGuardianSecret.exe
FILE4=GuardianGateway.exe
FILE5=GuardianGatewaySupervisor.exe
FILE6=README-CN.md
FILE7=LICENSE
FILE8=VERSION
"@

Set-Content -LiteralPath $SedPath -Value $SedContent -Encoding ASCII

$IExpress = Join-Path $env:WINDIR "system32\iexpress.exe"
if (-not (Test-Path -LiteralPath $IExpress)) {
    throw "iexpress.exe not found"
}
$Process = Start-Process -FilePath $IExpress -ArgumentList @("/N", "/Q", $SedPath) -WindowStyle Hidden -PassThru
Wait-Process -Id $Process.Id -Timeout 120 -ErrorAction SilentlyContinue
for ($Index = 0; $Index -lt 60; $Index++) {
    if ((Test-Path -LiteralPath $InstallerPath) -and (Get-Item -LiteralPath $InstallerPath).Length -gt 1000000) {
        break
    }
    Start-Sleep -Seconds 1
}
if (-not (Test-Path -LiteralPath $InstallerPath)) {
    throw "Installer was not created: $InstallerPath"
}
if ((Get-Item -LiteralPath $InstallerPath).Length -lt 1000000) {
    throw "Installer is unexpectedly small: $InstallerPath"
}
if (-not (Test-Path -LiteralPath $Python)) {
    throw "Release Python environment not found: $Python"
}
if (-not (Test-Path -LiteralPath $IconPath)) {
    throw "Guardian icon not found: $IconPath"
}
& $Python -B (Join-Path $ProjectRoot "tools\stamp_pe_icon.py") $InstallerPath $IconPath
if ($LASTEXITCODE -ne 0) {
    throw "Installer icon stamping failed"
}

$Hash = Get-FileHash -Algorithm SHA256 -LiteralPath $InstallerPath
[pscustomobject]@{
    Installer = $InstallerPath
    Bytes = (Get-Item -LiteralPath $InstallerPath).Length
    SHA256 = $Hash.Hash
    Staging = $StagingDir
    Sed = $SedPath
} | ConvertTo-Json -Depth 3
