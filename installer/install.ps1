param(
    [switch]$NoLaunch,
    [switch]$SkipRegistry,
    [switch]$SkipScheduledTask,
    [string]$InstallBase,
    [string]$StartMenuDir,
    [string]$DesktopShortcut,
    [ValidateSet("", "after_stage", "after_pointer", "after_shortcuts")]
    [string]$TestFailStage = ""
)

$ErrorActionPreference = "Stop"

$AppName = "Codex Profile Guardian"
$Version = "1.10.1"
$GatewayVersion = "v$Version"
$TaskName = "Codex Profile Guardian Gateway"
$DataPort = 18766
$ControlPort = 18767

$ExplicitInstallBase = -not [string]::IsNullOrWhiteSpace($InstallBase)
if (-not $ExplicitInstallBase) {
    $InstallBase = Join-Path $env:LOCALAPPDATA $AppName
}
$InstallBase = [System.IO.Path]::GetFullPath($InstallBase)
$InstallRoot = Join-Path $InstallBase "app\v$Version"
$GatewayRoot = Join-Path $InstallBase "gateway"
$GatewayReleaseRoot = Join-Path $GatewayRoot "versions\$GatewayVersion"
$GatewayConfigPath = Join-Path $GatewayRoot "config\active.json"
$SupervisorStatePath = Join-Path $GatewayRoot "state\supervisor.json"
$GatewayPointerPath = Join-Path $GatewayRoot "current.json"
$TaskDefinitionPath = Join-Path $GatewayRoot "tasks\$TaskName.xml"
if (-not $StartMenuDir) {
    $StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) $AppName
}
if (-not $DesktopShortcut) {
    $DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "$AppName.lnk"
}
$StartMenuShortcut = Join-Path $StartMenuDir "$AppName.lnk"
$MainExe = Join-Path $InstallRoot "CodexProfileGuardian.exe"
$SupervisorExe = Join-Path $GatewayReleaseRoot "GuardianGatewaySupervisor.exe"
$UninstallScript = Join-Path $InstallRoot "uninstall.ps1"
$UninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Codex Profile Guardian"
$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RunValueName = "Codex Profile Guardian Gateway"
$TransactionId = [guid]::NewGuid().ToString("N")
$TransactionRoot = Join-Path $InstallBase "transactions\$TransactionId"
$StageAppRoot = Join-Path $TransactionRoot "stage\app"
$StageGatewayRoot = Join-Path $TransactionRoot "stage\gateway"
$BackupAppRoot = Join-Path $TransactionRoot "backup\app"
$BackupGatewayRoot = Join-Path $TransactionRoot "backup\gateway"
$BackupFilesRoot = Join-Path $TransactionRoot "backup\files"

if ($TestFailStage -and (-not $ExplicitInstallBase -or -not $SkipRegistry -or -not $SkipScheduledTask)) {
    throw "Installer fault injection is restricted to isolated tests."
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Value)
    $Parent = Split-Path -Parent $Path
    if ($Parent) {
        New-Item -ItemType Directory -Path $Parent -Force | Out-Null
    }
    $Encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $Encoding)
}

function Write-Utf8NoBomAtomic {
    param([string]$Path, [string]$Value)
    $Parent = Split-Path -Parent $Path
    if ($Parent) {
        New-Item -ItemType Directory -Path $Parent -Force | Out-Null
    }
    $Temporary = Join-Path $Parent (".{0}.{1}.tmp" -f (Split-Path -Leaf $Path), [guid]::NewGuid().ToString("N"))
    try {
        Write-Utf8NoBom -Path $Temporary -Value $Value
        Move-Item -LiteralPath $Temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $Temporary -Force -ErrorAction SilentlyContinue
    }
}

function Assert-WithinInstallBase {
    param([string]$Path)
    $Resolved = [System.IO.Path]::GetFullPath($Path)
    $Prefix = $InstallBase.TrimEnd("\") + "\"
    if (-not $Resolved.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe install path: $Resolved"
    }
    return $Resolved
}

function Stop-InstalledProcesses {
    param([string[]]$Names = @("CodexProfileGuardian.exe", "GuardianGatewaySupervisor.exe"))
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -in $Names -and
            $_.ExecutablePath -and
            $_.ExecutablePath.StartsWith($InstallBase, [System.StringComparison]::OrdinalIgnoreCase)
        } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
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

function Stop-GatewayForUpgrade {
    Stop-InstalledProcesses -Names @("CodexProfileGuardian.exe", "GuardianGatewaySupervisor.exe")
    $Gateways = @(
        Get-CimInstance Win32_Process -Filter "Name = 'GuardianGateway.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ExecutablePath -and
                $_.ExecutablePath.StartsWith($InstallBase, [System.StringComparison]::OrdinalIgnoreCase)
            }
    )
    if ($Gateways.Count -eq 0) { return }

    $RuntimePath = Join-Path $GatewayRoot "runtime\runtime.json"
    if (-not (Test-Path -LiteralPath $RuntimePath)) {
        throw "Running Gateway has no verifiable runtime descriptor."
    }
    try {
        $Runtime = Get-Content -LiteralPath $RuntimePath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Running Gateway runtime descriptor is invalid."
    }
    $Gateway = $Gateways | Where-Object { [int]$_.ProcessId -eq [int]$Runtime.pid } | Select-Object -First 1
    if ($null -eq $Gateway) { throw "Running Gateway PID did not match the runtime descriptor." }
    if (
        -not $Runtime.executable_path -or
        -not ([System.IO.Path]::GetFullPath([string]$Runtime.executable_path)).Equals(
            [System.IO.Path]::GetFullPath([string]$Gateway.ExecutablePath),
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$Runtime.host -ne "127.0.0.1" -or
        [string]$Runtime.control_endpoint -ne ("http://127.0.0.1:{0}" -f [int]$Runtime.control_port)
    ) {
        throw "Running Gateway identity could not be verified."
    }
    foreach ($Process in $Gateways) {
        if (-not ([System.IO.Path]::GetFullPath([string]$Process.ExecutablePath)).Equals(
            [System.IO.Path]::GetFullPath([string]$Runtime.executable_path),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Running Gateway process set contains an unexpected executable."
        }
    }
    $Helper = Join-Path $PSScriptRoot "CodexProfileGuardianSecret.exe"
    if (-not (Test-Path -LiteralPath $Helper)) { throw "Gateway control helper is missing." }
    $ControlToken = (& $Helper gateway-control $InstallBase) -join ""
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ControlToken)) {
        throw "Gateway control token could not be resolved."
    }
    if ((Get-Sha256Text -Value $ControlToken) -ne [string]$Runtime.control_token_sha256) {
        throw "Gateway control token did not match the runtime descriptor."
    }
    $Headers = @{ Authorization = "Bearer $ControlToken" }
    $Body = '{"timeout_seconds":30}'
    try {
        $Drain = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($Runtime.control_endpoint)/control/v1/drain" -Headers $Headers -ContentType "application/json" -Body $Body -TimeoutSec 40
        if ($Drain.ok -ne $true -or $Drain.phase -ne "draining" -or [int]$Drain.active_requests -ne 0) {
            throw "Gateway did not confirm drained state."
        }
        $Stop = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($Runtime.control_endpoint)/control/v1/stop" -Headers $Headers -ContentType "application/json" -Body $Body -TimeoutSec 40
        if ($Stop.ok -ne $true) { throw "Gateway did not accept stop." }
    } finally {
        $ControlToken = $null
        $Headers = $null
    }
    $GatewayPids = @($Gateways | ForEach-Object { [int]$_.ProcessId })
    $Deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $Deadline -and @($GatewayPids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }).Count -gt 0) {
        Start-Sleep -Milliseconds 200
    }
    foreach ($GatewayPid in $GatewayPids) {
        if (Get-Process -Id $GatewayPid -ErrorAction SilentlyContinue) {
            Stop-Process -Id $GatewayPid -Force -ErrorAction Stop
        }
    }
}

function New-Shortcut {
    param(
        [string]$Path,
        [string]$Target,
        [string]$WorkingDirectory,
        [string]$Description
    )
    $Shell = New-Object -ComObject WScript.Shell
    $Shortcut = $Shell.CreateShortcut($Path)
    $Shortcut.TargetPath = $Target
    $Shortcut.WorkingDirectory = $WorkingDirectory
    $Shortcut.Description = $Description
    $Shortcut.IconLocation = "$Target,0"
    $Shortcut.Save()
}

function Get-BigEndianBytes {
    param([UInt64]$Value, [int]$Length)
    $Bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($Bytes) }
    if ($Length -eq 4) { return $Bytes[4..7] }
    return $Bytes
}

function Get-GatewayContentHash {
    param([string]$Root)
    $Digest = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Prefix = $Root.TrimEnd("\") + "\"
        $Files = Get-ChildItem -LiteralPath $Root -Recurse -File |
            Where-Object { $_.Name -ne "manifest.json" } |
            Sort-Object { $_.FullName.Substring($Prefix.Length).Replace("\", "/") }
        foreach ($File in $Files) {
            $Relative = $File.FullName.Substring($Prefix.Length).Replace("\", "/")
            $NameBytes = [System.Text.Encoding]::UTF8.GetBytes($Relative)
            $LengthBytes = Get-BigEndianBytes -Value ([UInt64]$NameBytes.Length) -Length 4
            [void]$Digest.TransformBlock($LengthBytes, 0, $LengthBytes.Length, $null, 0)
            [void]$Digest.TransformBlock($NameBytes, 0, $NameBytes.Length, $null, 0)
            $SizeBytes = Get-BigEndianBytes -Value ([UInt64]$File.Length) -Length 8
            [void]$Digest.TransformBlock($SizeBytes, 0, $SizeBytes.Length, $null, 0)
            $Stream = [System.IO.File]::OpenRead($File.FullName)
            try {
                $Buffer = New-Object byte[] (1024 * 1024)
                while (($Read = $Stream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
                    [void]$Digest.TransformBlock($Buffer, 0, $Read, $null, 0)
                }
            } finally {
                $Stream.Dispose()
            }
        }
        [void]$Digest.TransformFinalBlock([byte[]]::new(0), 0, 0)
        return ([BitConverter]::ToString($Digest.Hash)).Replace("-", "").ToLowerInvariant()
    } finally {
        $Digest.Dispose()
    }
}

function Write-GatewayReleaseManifest {
    param([string]$ReleaseRoot)
    $ContentHash = Get-GatewayContentHash -Root $ReleaseRoot
    $TransactionId = "install-v170"
    $Manifest = [ordered]@{
        schema_version = 1
        version = $GatewayVersion
        content_sha256 = $ContentHash
        transaction_id = $TransactionId
    }
    $ManifestJson = $Manifest | ConvertTo-Json -Compress
    $ManifestPath = Join-Path $ReleaseRoot "manifest.json"
    Write-Utf8NoBom -Path $ManifestPath -Value ($ManifestJson + "`n")
}

function Write-GatewayPointer {
    $ManifestPath = Join-Path $GatewayReleaseRoot "manifest.json"
    $ManifestHash = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $PreviousVersion = $null
    if (Test-Path -LiteralPath $GatewayPointerPath) {
        try {
            $Existing = Get-Content -LiteralPath $GatewayPointerPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($Existing.version -and $Existing.version -ne $GatewayVersion) {
                $PreviousVersion = [string]$Existing.version
            }
        } catch {
            throw "Existing gateway pointer is invalid."
        }
    }
    $Pointer = [ordered]@{
        schema_version = 1
        version = $GatewayVersion
        relative_path = "gateway/versions/$GatewayVersion"
        manifest_sha256 = $ManifestHash
        previous_version = $PreviousVersion
    }
    Write-Utf8NoBomAtomic -Path $GatewayPointerPath -Value (($Pointer | ConvertTo-Json -Compress) + "`n")
}

function Write-BootstrapGatewayConfig {
    if (Test-Path -LiteralPath $GatewayConfigPath) { return }
    $Document = [ordered]@{
        schema_version = 1
        instance_id = [guid]::NewGuid().ToString()
        gateway_version = $GatewayVersion
        listen = [ordered]@{
            host = "127.0.0.1"
            data_port = $DataPort
            control_port = $ControlPort
        }
        limits = [ordered]@{
            max_request_bytes = 8388608
            max_response_bytes = 16777216
            read_chunk_bytes = 65536
            max_concurrent_requests = 8
            connect_timeout_seconds = 20
            first_byte_timeout_seconds = 120
            idle_timeout_seconds = 120
            total_timeout_seconds = 1800
        }
        lifecycle = [ordered]@{
            minimum_free_bytes = 536870912
            drain_timeout_seconds = 30
        }
        active_group = [ordered]@{
            revision = 1
            group_id = "00000000-0000-4000-8000-000000000001"
            primary = [ordered]@{
                profile_id = "bootstrap-primary"
                base_url = "http://127.0.0.1:9/v1"
                adapter_name = "openai-responses-v1"
                secret_ref = "profile:bootstrap-primary:r1"
                secret_suffix = ""
                enabled = $false
                protocol_compatibility = @{}
            }
            backup = [ordered]@{
                profile_id = "bootstrap-backup"
                base_url = "http://127.0.0.1:9/v1"
                adapter_name = "openai-responses-v1"
                secret_ref = "profile:bootstrap-backup:r1"
                secret_suffix = ""
                enabled = $false
                protocol_compatibility = @{}
            }
            allowed_models = @("guardian-bootstrap-disabled")
            breaker_policy = [ordered]@{
                failure_threshold = 1
                protocol_failure_threshold = 1
                error_rate_threshold = $null
                minimum_samples = 1
                window_size = 8
                recovery_success_threshold = 1
                base_cooldown_seconds = 30
                max_cooldown_seconds = 300
                jitter_ratio = 0
            }
            probe_policy = [ordered]@{
                enabled = $false
                mode = "models"
                interval_seconds = 30
                timeout_seconds = 5
                allow_billable = $false
                allow_action_required_auto_retest = $false
            }
            state_compatibility = @{}
        }
    }
    Write-Utf8NoBom -Path $GatewayConfigPath -Value (($Document | ConvertTo-Json -Depth 12 -Compress) + "`n")
}

function Update-GatewayConfigVersion {
    if (-not (Test-Path -LiteralPath $GatewayConfigPath)) {
        throw "Gateway config is missing after bootstrap."
    }
    try {
        $Document = Get-Content -LiteralPath $GatewayConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Existing gateway config is invalid."
    }
    if ([int]$Document.schema_version -ne 1 -or -not $Document.gateway_version) {
        throw "Existing gateway config schema is unsupported."
    }
    if ([string]$Document.gateway_version -eq $GatewayVersion) { return }
    $Document.gateway_version = $GatewayVersion
    Write-Utf8NoBomAtomic -Path $GatewayConfigPath -Value (($Document | ConvertTo-Json -Depth 12 -Compress) + "`n")
}

function Write-ScheduledTaskDefinition {
    $UserId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $Arguments = "--layout-root `"$InstallBase`" --config-file `"$GatewayConfigPath`""
    $EscapedUser = [System.Security.SecurityElement]::Escape($UserId)
    $EscapedCommand = [System.Security.SecurityElement]::Escape($SupervisorExe)
    $EscapedArguments = [System.Security.SecurityElement]::Escape($Arguments)
    $EscapedWorking = [System.Security.SecurityElement]::Escape($GatewayRoot)
    $Xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Codex Profile Guardian user-level gateway supervisor</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>$EscapedUser</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="CurrentUser"><UserId>$EscapedUser</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions Context="CurrentUser"><Exec><Command>$EscapedCommand</Command><Arguments>$EscapedArguments</Arguments><WorkingDirectory>$EscapedWorking</WorkingDirectory></Exec></Actions>
</Task>
"@
    New-Item -ItemType Directory -Path (Split-Path -Parent $TaskDefinitionPath) -Force | Out-Null
    [System.IO.File]::WriteAllText($TaskDefinitionPath, $Xml, (New-Object System.Text.UnicodeEncoding($false, $true)))
}

function Backup-FileIfPresent {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    New-Item -ItemType Directory -Path $BackupFilesRoot -Force | Out-Null
    Copy-Item -LiteralPath $Path -Destination (Join-Path $BackupFilesRoot $Name) -Force
    return $true
}

function Restore-FileBackup {
    param([string]$Path, [string]$Name, [bool]$Existed)
    if ($Existed) {
        $Parent = Split-Path -Parent $Path
        if ($Parent) { New-Item -ItemType Directory -Path $Parent -Force | Out-Null }
        Copy-Item -LiteralPath (Join-Path $BackupFilesRoot $Name) -Destination $Path -Force
    } else {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function Get-UninstallRegistrySnapshot {
    if ($SkipRegistry -or -not (Test-Path -LiteralPath $UninstallKey)) { return $null }
    $Item = Get-ItemProperty -LiteralPath $UninstallKey
    $Result = [ordered]@{}
    foreach ($Name in @(
        "DisplayName", "DisplayVersion", "Publisher", "InstallLocation", "DisplayIcon",
        "UninstallString", "QuietUninstallString", "NoModify", "NoRepair"
    )) {
        if ($null -ne $Item.$Name) { $Result[$Name] = $Item.$Name }
    }
    return $Result
}

function Restore-UninstallRegistrySnapshot {
    param($Snapshot)
    if ($SkipRegistry) { return }
    if ($null -eq $Snapshot) {
        Remove-Item -LiteralPath $UninstallKey -Recurse -Force -ErrorAction SilentlyContinue
        return
    }
    New-Item -Path $UninstallKey -Force | Out-Null
    foreach ($Entry in $Snapshot.GetEnumerator()) {
        if ($Entry.Key -in @("NoModify", "NoRepair")) {
            Set-ItemProperty -Path $UninstallKey -Name $Entry.Key -Value ([int]$Entry.Value) -Type DWord
        } else {
            Set-ItemProperty -Path $UninstallKey -Name $Entry.Key -Value ([string]$Entry.Value)
        }
    }
}

function Invoke-ScheduledTaskCommand {
    param(
        [string[]]$Arguments,
        [switch]$CaptureOutput
    )
    $PreviousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        if ($CaptureOutput) {
            $Output = @(& schtasks.exe @Arguments 2>$null)
        } else {
            & schtasks.exe @Arguments 2>$null | Out-Null
            $Output = @()
        }
        $ExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PreviousPreference
    }
    return [pscustomobject]@{
        ExitCode = $ExitCode
        Output = $Output
    }
}

function Wait-GatewayStartup {
    $RuntimePath = Join-Path $GatewayRoot "runtime\runtime.json"
    $ExpectedGateway = [System.IO.Path]::GetFullPath((Join-Path $GatewayReleaseRoot "GuardianGateway.exe"))
    $Helper = Join-Path $InstallRoot "CodexProfileGuardianSecret.exe"
    $Deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $Deadline) {
        if (Test-Path -LiteralPath $RuntimePath) {
            try {
                $Runtime = Get-Content -LiteralPath $RuntimePath -Raw -Encoding UTF8 | ConvertFrom-Json
                $RuntimeExecutable = [System.IO.Path]::GetFullPath([string]$Runtime.executable_path)
                [void](Get-Process -Id ([int]$Runtime.pid) -ErrorAction Stop)
                $IngressToken = (& $Helper gateway-ingress $InstallBase) -join ""
                if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($IngressToken)) {
                    throw "Gateway ingress token could not be resolved."
                }
                $Headers = @{ Authorization = "Bearer $IngressToken" }
                $Health = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "http://127.0.0.1:$DataPort/health" -Headers $Headers -TimeoutSec 2
                if (
                    [string]$Runtime.version -eq $GatewayVersion -and
                    $RuntimeExecutable.Equals($ExpectedGateway, [System.StringComparison]::OrdinalIgnoreCase) -and
                    [int]$Runtime.data_port -eq $DataPort -and
                    [int]$Runtime.control_port -eq $ControlPort -and
                    [string]$Health.version -eq $GatewayVersion -and
                    $Health.ok -eq $true
                ) {
                    $IngressToken = $null
                    $Headers = $null
                    return
                }
            } catch {
                # Startup is asynchronous; retry until the bounded deadline.
            } finally {
                $IngressToken = $null
                $Headers = $null
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Gateway scheduled task did not reach a verified running state."
}

foreach ($Path in @(
    $InstallRoot,
    $GatewayReleaseRoot,
    (Split-Path -Parent $GatewayConfigPath),
    $TransactionRoot,
    $StageAppRoot,
    $StageGatewayRoot,
    $BackupAppRoot,
    $BackupGatewayRoot,
    $BackupFilesRoot
)) {
    [void](Assert-WithinInstallBase $Path)
}

$AppExisted = Test-Path -LiteralPath $InstallRoot
$GatewayReleaseExisted = Test-Path -LiteralPath $GatewayReleaseRoot
$ConfigExisted = Backup-FileIfPresent -Path $GatewayConfigPath -Name "active.json"
$SupervisorStateExisted = Backup-FileIfPresent -Path $SupervisorStatePath -Name "supervisor.json"
$PointerExisted = Backup-FileIfPresent -Path $GatewayPointerPath -Name "current.json"
$TaskDefinitionExisted = Backup-FileIfPresent -Path $TaskDefinitionPath -Name "task.xml"
$DesktopShortcutExisted = Backup-FileIfPresent -Path $DesktopShortcut -Name "desktop.lnk"
$StartMenuShortcutExisted = Backup-FileIfPresent -Path $StartMenuShortcut -Name "start-menu.lnk"
$RegistrySnapshot = Get-UninstallRegistrySnapshot
$PreviousRunValue = $null
$PreviousRunValueExisted = $false
if (-not $SkipScheduledTask -and (Test-Path -LiteralPath $RunKey)) {
    $RunProperties = Get-ItemProperty -LiteralPath $RunKey -ErrorAction SilentlyContinue
    if ($null -ne $RunProperties -and $null -ne $RunProperties.$RunValueName) {
        $PreviousRunValue = [string]$RunProperties.$RunValueName
        $PreviousRunValueExisted = $true
    }
}
$PreviousTaskXml = $null
$PreviousTaskExisted = $false
$ProcessesStopped = $false
if (-not $SkipScheduledTask) {
    $TaskQuery = Invoke-ScheduledTaskCommand -Arguments @("/Query", "/TN", $TaskName, "/XML") -CaptureOutput
    $PreviousTaskXml = $TaskQuery.Output -join "`r`n"
    $PreviousTaskExisted = $TaskQuery.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($PreviousTaskXml)
}

try {
    New-Item -ItemType Directory -Path $StageAppRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $StageGatewayRoot -Force | Out-Null
    foreach ($Name in @("CodexProfileGuardian.exe", "CodexProfileGuardianSecret.exe", "README-CN.md", "LICENSE", "uninstall.ps1")) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $Name) -Destination (Join-Path $StageAppRoot $Name) -Force
    }
    foreach ($Name in @("GuardianGateway.exe", "GuardianGatewaySupervisor.exe")) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $Name) -Destination (Join-Path $StageGatewayRoot $Name) -Force
    }
    Write-GatewayReleaseManifest -ReleaseRoot $StageGatewayRoot
    if ($TestFailStage -eq "after_stage") { throw "Injected installer failure after stage." }

    if (-not $SkipScheduledTask) {
        [void](Invoke-ScheduledTaskCommand -Arguments @("/End", "/TN", $TaskName))
    }
    Stop-GatewayForUpgrade
    $ProcessesStopped = $true

    if ($AppExisted) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $BackupAppRoot) -Force | Out-Null
        Move-Item -LiteralPath $InstallRoot -Destination $BackupAppRoot
    }
    if ($GatewayReleaseExisted) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $BackupGatewayRoot) -Force | Out-Null
        Move-Item -LiteralPath $GatewayReleaseRoot -Destination $BackupGatewayRoot
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $InstallRoot) -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $GatewayReleaseRoot) -Force | Out-Null
    Move-Item -LiteralPath $StageAppRoot -Destination $InstallRoot
    Move-Item -LiteralPath $StageGatewayRoot -Destination $GatewayReleaseRoot

    Write-GatewayPointer
    Write-BootstrapGatewayConfig
    Update-GatewayConfigVersion
    Remove-Item -LiteralPath $SupervisorStatePath -Force -ErrorAction SilentlyContinue
    Write-ScheduledTaskDefinition
    if ($TestFailStage -eq "after_pointer") { throw "Injected installer failure after pointer." }

    New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null
    New-Shortcut -Path $DesktopShortcut -Target $MainExe -WorkingDirectory $InstallRoot -Description "Manage Codex profiles and the local failover gateway"
    New-Shortcut -Path $StartMenuShortcut -Target $MainExe -WorkingDirectory $InstallRoot -Description "Manage Codex profiles and the local failover gateway"

    if (-not $SkipRegistry) {
        New-Item -Path $UninstallKey -Force | Out-Null
        Set-ItemProperty -Path $UninstallKey -Name DisplayName -Value $AppName
        Set-ItemProperty -Path $UninstallKey -Name DisplayVersion -Value $Version
        Set-ItemProperty -Path $UninstallKey -Name Publisher -Value "Codex Profile Guardian"
        Set-ItemProperty -Path $UninstallKey -Name InstallLocation -Value $InstallRoot
        Set-ItemProperty -Path $UninstallKey -Name DisplayIcon -Value $MainExe
        Set-ItemProperty -Path $UninstallKey -Name UninstallString -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$UninstallScript`""
        Set-ItemProperty -Path $UninstallKey -Name QuietUninstallString -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$UninstallScript`" -Quiet"
        Set-ItemProperty -Path $UninstallKey -Name NoModify -Value 1 -Type DWord
        Set-ItemProperty -Path $UninstallKey -Name NoRepair -Value 1 -Type DWord
    }

    if (-not $SkipScheduledTask) {
        $Create = Invoke-ScheduledTaskCommand -Arguments @("/Create", "/TN", $TaskName, "/XML", $TaskDefinitionPath, "/F")
        if ($Create.ExitCode -eq 0) {
            Remove-ItemProperty -LiteralPath $RunKey -Name $RunValueName -Force -ErrorAction SilentlyContinue
            $Run = Invoke-ScheduledTaskCommand -Arguments @("/Run", "/TN", $TaskName)
            if ($Run.ExitCode -ne 0) { throw "Gateway scheduled task start failed." }
        } else {
            New-Item -Path $RunKey -Force | Out-Null
            $RunCommand = "`"$SupervisorExe`" --layout-root `"$InstallBase`" --config-file `"$GatewayConfigPath`""
            Set-ItemProperty -LiteralPath $RunKey -Name $RunValueName -Value $RunCommand
            Start-Process -FilePath $SupervisorExe -ArgumentList "--layout-root `"$InstallBase`" --config-file `"$GatewayConfigPath`"" -WorkingDirectory $GatewayRoot -WindowStyle Hidden
        }
        Wait-GatewayStartup
    }
    if ($TestFailStage -eq "after_shortcuts") { throw "Injected installer failure after shortcuts." }

    if (-not $NoLaunch) {
        Start-Process -FilePath $MainExe -WorkingDirectory $InstallRoot
    }
    Remove-Item -LiteralPath $TransactionRoot -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    if (-not $SkipScheduledTask) {
        [void](Invoke-ScheduledTaskCommand -Arguments @("/End", "/TN", $TaskName))
        [void](Invoke-ScheduledTaskCommand -Arguments @("/Delete", "/TN", $TaskName, "/F"))
    }
    if ($ProcessesStopped) {
        Stop-InstalledProcesses -Names @("CodexProfileGuardian.exe", "GuardianGateway.exe", "GuardianGatewaySupervisor.exe")
    }
    foreach ($Path in @($InstallRoot, $GatewayReleaseRoot)) {
        [void](Assert-WithinInstallBase $Path)
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $BackupAppRoot) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $InstallRoot) -Force | Out-Null
        Move-Item -LiteralPath $BackupAppRoot -Destination $InstallRoot
    }
    if (Test-Path -LiteralPath $BackupGatewayRoot) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $GatewayReleaseRoot) -Force | Out-Null
        Move-Item -LiteralPath $BackupGatewayRoot -Destination $GatewayReleaseRoot
    }
    Restore-FileBackup -Path $GatewayPointerPath -Name "current.json" -Existed $PointerExisted
    Restore-FileBackup -Path $TaskDefinitionPath -Name "task.xml" -Existed $TaskDefinitionExisted
    Restore-FileBackup -Path $DesktopShortcut -Name "desktop.lnk" -Existed $DesktopShortcutExisted
    Restore-FileBackup -Path $StartMenuShortcut -Name "start-menu.lnk" -Existed $StartMenuShortcutExisted
    Restore-FileBackup -Path $GatewayConfigPath -Name "active.json" -Existed $ConfigExisted
    Restore-FileBackup -Path $SupervisorStatePath -Name "supervisor.json" -Existed $SupervisorStateExisted
    Restore-UninstallRegistrySnapshot -Snapshot $RegistrySnapshot
    if (-not $SkipScheduledTask) {
        if ($PreviousRunValueExisted) {
            New-Item -Path $RunKey -Force | Out-Null
            Set-ItemProperty -LiteralPath $RunKey -Name $RunValueName -Value $PreviousRunValue
        } else {
            Remove-ItemProperty -LiteralPath $RunKey -Name $RunValueName -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $SkipScheduledTask -and $PreviousTaskExisted) {
        $PreviousTaskPath = Join-Path $TransactionRoot "previous-task.xml"
        [System.IO.File]::WriteAllText($PreviousTaskPath, $PreviousTaskXml, (New-Object System.Text.UnicodeEncoding($false, $true)))
        $RestoreTask = Invoke-ScheduledTaskCommand -Arguments @("/Create", "/TN", $TaskName, "/XML", $PreviousTaskPath, "/F")
        if ($RestoreTask.ExitCode -eq 0) {
            [void](Invoke-ScheduledTaskCommand -Arguments @("/Run", "/TN", $TaskName))
        }
    }
    Remove-Item -LiteralPath $TransactionRoot -Recurse -Force -ErrorAction SilentlyContinue
    throw
}

if (-not $NoLaunch) {
    $Shell = New-Object -ComObject WScript.Shell
    $Shell.Popup("Codex Profile Guardian v$Version installed.", 6, "Codex Profile Guardian", 64) | Out-Null
}
