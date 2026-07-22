param(
    [switch]$RemoveUserData,
    [switch]$Quiet,
    [switch]$SkipRegistry,
    [switch]$SkipScheduledTask,
    [string]$StartMenuDir,
    [string]$DesktopShortcut
)

$ErrorActionPreference = "Stop"
$AppName = "Codex Profile Guardian"
$TaskName = "Codex Profile Guardian Gateway"
$InstallBase = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$InstallBase = [System.IO.Path]::GetFullPath($InstallBase)
$UninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Codex Profile Guardian"
$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RunValueName = "Codex Profile Guardian Gateway"
if (-not $StartMenuDir) {
    $StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) $AppName
}
if (-not $DesktopShortcut) {
    $DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "$AppName.lnk"
}

function Invoke-ScheduledTaskCommand {
    param([string[]]$Arguments)
    $PreviousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        & schtasks.exe @Arguments 2>$null | Out-Null
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PreviousPreference
    }
}

function Get-Sha256Text {
    param([string]$Value)
    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
    $Digest = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($Digest.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $Digest.Dispose()
    }
}

function Stop-InstalledGateway {
    $RuntimePath = Join-Path $InstallBase "gateway\runtime\runtime.json"
    $Helper = Join-Path $PSScriptRoot "CodexProfileGuardianSecret.exe"
    if (-not (Test-Path -LiteralPath $RuntimePath) -or -not (Test-Path -LiteralPath $Helper)) { return }
    try {
        $Runtime = Get-Content -LiteralPath $RuntimePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $ExpectedExecutable = [System.IO.Path]::GetFullPath([string]$Runtime.executable_path)
        $ExpectedPrefix = $InstallBase.TrimEnd("\") + "\"
        if (
            -not $ExpectedExecutable.StartsWith($ExpectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]$Runtime.host -ne "127.0.0.1" -or
            [string]$Runtime.control_endpoint -ne ("http://127.0.0.1:{0}" -f [int]$Runtime.control_port)
        ) { return }
        $Process = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f [int]$Runtime.pid) -ErrorAction SilentlyContinue
        if (
            $null -eq $Process -or
            -not $Process.ExecutablePath -or
            -not ([System.IO.Path]::GetFullPath([string]$Process.ExecutablePath)).Equals(
                $ExpectedExecutable,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) { return }
        $ControlToken = (& $Helper gateway-control $InstallBase) -join ""
        if (
            $LASTEXITCODE -ne 0 -or
            [string]::IsNullOrWhiteSpace($ControlToken) -or
            (Get-Sha256Text -Value $ControlToken) -ne [string]$Runtime.control_token_sha256
        ) { return }
        try {
            $Headers = @{ Authorization = "Bearer $ControlToken" }
            $Body = '{"timeout_seconds":30}'
            $Drain = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($Runtime.control_endpoint)/control/v1/drain" -Headers $Headers -ContentType "application/json" -Body $Body -TimeoutSec 40
            if ($Drain.ok -ne $true -or [int]$Drain.active_requests -ne 0) { return }
            $Stop = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($Runtime.control_endpoint)/control/v1/stop" -Headers $Headers -ContentType "application/json" -Body $Body -TimeoutSec 40
            if ($Stop.ok -ne $true) { return }
        } finally {
            $ControlToken = $null
            $Headers = $null
        }
        $Deadline = [DateTime]::UtcNow.AddSeconds(20)
        while ([DateTime]::UtcNow -lt $Deadline -and (Get-Process -Id ([int]$Runtime.pid) -ErrorAction SilentlyContinue)) {
            Start-Sleep -Milliseconds 200
        }
    } catch {
        return
    }
}

function Get-InstalledProgramProcesses {
    return @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -in @(
                    "CodexProfileGuardian.exe",
                    "GuardianGateway.exe",
                    "GuardianGatewaySupervisor.exe"
                ) -and
                $_.ExecutablePath -and
                $_.ExecutablePath.StartsWith($InstallBase, [System.StringComparison]::OrdinalIgnoreCase)
            }
    )
}

function Remove-InstalledProgramPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $ResolvedParent = [System.IO.Path]::GetFullPath((Split-Path -Parent $Path)).TrimEnd("\") + "\"
    $ExpectedPrefix = $InstallBase.TrimEnd("\") + "\"
    if (-not $ResolvedParent.StartsWith($ExpectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the install root: $Path"
    }
    for ($Attempt = 0; $Attempt -lt 20; $Attempt++) {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $Path)) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "Unable to remove installed program path: $Path"
}

Stop-InstalledGateway
if (-not $SkipScheduledTask) {
    [void](Invoke-ScheduledTaskCommand -Arguments @("/End", "/TN", $TaskName))
    [void](Invoke-ScheduledTaskCommand -Arguments @("/Delete", "/TN", $TaskName, "/F"))
}
Remove-ItemProperty -LiteralPath $RunKey -Name $RunValueName -Force -ErrorAction SilentlyContinue

$InstalledProcesses = @(Get-InstalledProgramProcesses)
$InstalledProcesses | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
$ProcessDeadline = [DateTime]::UtcNow.AddSeconds(10)
while ([DateTime]::UtcNow -lt $ProcessDeadline -and @(Get-InstalledProgramProcesses).Count -gt 0) {
    Start-Sleep -Milliseconds 200
}

Remove-Item -LiteralPath $DesktopShortcut -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $StartMenuDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-InstalledProgramPath -Path (Join-Path $InstallBase "app")
Remove-InstalledProgramPath -Path (Join-Path $InstallBase "bin")
Remove-InstalledProgramPath -Path (Join-Path $InstallBase "gateway\versions")
Remove-Item -LiteralPath (Join-Path $InstallBase "gateway\current.json") -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $InstallBase "gateway\tasks") -Recurse -Force -ErrorAction SilentlyContinue
if (-not $SkipRegistry) {
    Remove-Item -LiteralPath $UninstallKey -Recurse -Force -ErrorAction SilentlyContinue
}

if ($RemoveUserData) {
    $Leaf = Split-Path -Leaf $InstallBase
    if ($Leaf -ne $AppName) {
        throw "Refusing to remove an unexpected install root: $InstallBase"
    }
    Remove-Item -LiteralPath $InstallBase -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $Quiet) {
    $Shell = New-Object -ComObject WScript.Shell
    $Shell.Popup("Codex Profile Guardian has been uninstalled. Guardian user data is kept by default.", 8, "Codex Profile Guardian", 64) | Out-Null
}
