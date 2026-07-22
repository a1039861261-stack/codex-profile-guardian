[CmdletBinding()]
param(
    [string]$BackupRoot = (Join-Path $env:LOCALAPPDATA 'Codex Profile Guardian\backups'),
    [switch]$Apply,
    [switch]$NoPrompt
)

$ErrorActionPreference = 'Stop'
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    return ('{0:N0} B' -f $Bytes)
}

function Get-DirectoryBytes {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0L }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { return 0L }
    return [int64]$sum
}

function Test-IsUnderPath {
    param([string]$Child, [string]$Parent)
    $childFull = [System.IO.Path]::GetFullPath($Child).TrimEnd('\')
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $childFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase) -or
        $childFull.StartsWith($parentFull + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Write-Utf8NoBomText {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8NoBom)
}

function Append-Utf8NoBomLine {
    param([string]$Path, [string]$Line)
    [System.IO.File]::AppendAllText($Path, $Line + [Environment]::NewLine, $script:Utf8NoBom)
}

function Get-FirstLineBytes {
    param([string]$Path)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $bytes = New-Object System.Collections.Generic.List[byte]
        while ($true) {
            $b = $stream.ReadByte()
            if ($b -lt 0) { break }
            $bytes.Add([byte]$b)
            if ($b -eq 10) { break }
        }
        return $bytes.ToArray()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-RolloutRelative {
    param([string]$FilePath, [string]$BackupDir)
    $pairs = @(
        @{ Prefix = (Join-Path $BackupDir 'files\sessions'); Root = 'sessions' },
        @{ Prefix = (Join-Path $BackupDir 'files\archived_sessions'); Root = 'archived_sessions' },
        @{ Prefix = (Join-Path $BackupDir 'sessions'); Root = 'sessions' },
        @{ Prefix = (Join-Path $BackupDir 'archived_sessions'); Root = 'archived_sessions' }
    )
    foreach ($pair in $pairs) {
        $prefix = [System.IO.Path]::GetFullPath($pair.Prefix).TrimEnd('\')
        $file = [System.IO.Path]::GetFullPath($FilePath)
        if ($file.StartsWith($prefix + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $tail = $file.Substring(($prefix + '\').Length)
            return ($pair.Root + '\' + $tail)
        }
    }
    return $null
}

$root = (Resolve-Path -LiteralPath $BackupRoot -ErrorAction Stop).Path
$requiredSuffix = [System.IO.Path]::Combine('Codex Profile Guardian', 'backups')
if (-not $root.EndsWith($requiredSuffix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refuse to operate: BackupRoot must end with '$requiredSuffix'. Current: $root"
}

$beforeBytes = Get-DirectoryBytes $root
$backupDirs = Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop
$targets = New-Object System.Collections.Generic.List[object]
$candidateBytes = 0L
$candidateFiles = 0

foreach ($backup in $backupDirs) {
    if (-not (Test-Path -LiteralPath (Join-Path $backup.FullName 'manifest.json') -PathType Leaf)) {
        continue
    }
    foreach ($folder in @(
        (Join-Path $backup.FullName 'files\sessions'),
        (Join-Path $backup.FullName 'files\archived_sessions'),
        (Join-Path $backup.FullName 'sessions'),
        (Join-Path $backup.FullName 'archived_sessions')
    )) {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
            continue
        }
        $resolvedFolder = (Resolve-Path -LiteralPath $folder).Path
        if (-not (Test-IsUnderPath $resolvedFolder $root) -or -not (Test-IsUnderPath $resolvedFolder $backup.FullName)) {
            throw "Unsafe delete target detected: $resolvedFolder"
        }
        $files = Get-ChildItem -LiteralPath $resolvedFolder -Recurse -Force -File -Filter '*.jsonl' -ErrorAction SilentlyContinue
        $bytes = ($files | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $bytes) { $bytes = 0L }
        $count = ($files | Measure-Object).Count
        if ($count -gt 0) {
            $targets.Add([pscustomobject]@{ BackupDir = $backup.FullName; Folder = $resolvedFolder; Bytes = [int64]$bytes; Files = [int]$count }) | Out-Null
            $candidateBytes += [int64]$bytes
            $candidateFiles += [int]$count
        }
    }
}

Write-Host ''
Write-Host 'Codex Profile Guardian emergency backup slim'
Write-Host ('Backup root : {0}' -f $root)
Write-Host ('Current size: {0}' -f (Format-Size $beforeBytes))
Write-Host ('Slim target : {0} in {1} duplicated chat JSONL files' -f (Format-Size $candidateBytes), $candidateFiles)
Write-Host ''

if ($targets.Count -eq 0) {
    Write-Host 'No duplicated chat backup bodies were found. Nothing to slim.'
    exit 0
}

if (-not $Apply -and -not $NoPrompt) {
    Write-Host 'This keeps real Codex chats untouched and only removes duplicated chat bodies inside Guardian backups.'
    $answer = Read-Host 'Type YES to slim these old backups now'
    if ($answer -ne 'YES') {
        Write-Host 'Cancelled. No files were changed.'
        exit 0
    }
    $Apply = $true
}

if (-not $Apply) {
    Write-Host 'Preview only. Re-run with -Apply to actually slim backups.'
    exit 0
}

$freed = 0L
$processedFolders = 0

foreach ($target in $targets) {
    $backupDir = $target.BackupDir
    $snapshot = Join-Path $backupDir 'rollout-first-lines.jsonl'
    if (-not (Test-Path -LiteralPath $snapshot -PathType Leaf)) {
        Write-Utf8NoBomText -Path $snapshot -Text ''
    }
    $existing = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    Get-Content -LiteralPath $snapshot -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) { return }
        try {
            $obj = $_.TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
            if ($obj.relative) { [void]$existing.Add([string]$obj.relative) }
        }
        catch {}
    }

    $files = Get-ChildItem -LiteralPath $target.Folder -Recurse -Force -File -Filter '*.jsonl' -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $relative = Get-RolloutRelative $file.FullName $backupDir
        if (-not $relative -or $existing.Contains($relative)) {
            continue
        }
        $firstLine = Get-FirstLineBytes $file.FullName
        $lineObj = [ordered]@{
            relative = $relative
            size = [int64]$file.Length
            mtime_ns = 0
            first_line_b64 = [Convert]::ToBase64String($firstLine)
        }
        Append-Utf8NoBomLine -Path $snapshot -Line (($lineObj | ConvertTo-Json -Compress))
        [void]$existing.Add($relative)
    }

    $deleteBytes = Get-DirectoryBytes $target.Folder
    Remove-Item -LiteralPath $target.Folder -Recurse -Force
    $freed += $deleteBytes
    $processedFolders += 1

    $manifestPath = Join-Path $backupDir 'manifest.json'
    try {
        $manifestText = [System.IO.File]::ReadAllText($manifestPath, [System.Text.Encoding]::UTF8).TrimStart([char]0xFEFF)
        $manifest = $manifestText | ConvertFrom-Json
        $manifest | Add-Member -NotePropertyName backup_mode -NotePropertyValue 'lightweight-first-line-compacted' -Force
        $oldBytes = 0L
        if ($manifest.PSObject.Properties.Name -contains 'compacted_duplicate_rollout_bytes') {
            $oldBytes = [int64]$manifest.compacted_duplicate_rollout_bytes
        }
        $manifest | Add-Member -NotePropertyName compacted_duplicate_rollout_bytes -NotePropertyValue ($oldBytes + $deleteBytes) -Force
        $manifest | Add-Member -NotePropertyName compacted_at -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
        if ($manifest.PSObject.Properties.Name -contains 'copied_files') {
            $kept = @($manifest.copied_files | Where-Object {
                $text = [string]$_
                -not ($text.StartsWith('sessions', [StringComparison]::OrdinalIgnoreCase) -or
                    $text.StartsWith('archived_sessions', [StringComparison]::OrdinalIgnoreCase))
            })
            $manifest.copied_files = $kept
        }
        Write-Utf8NoBomText -Path $manifestPath -Text (($manifest | ConvertTo-Json -Depth 10) + [Environment]::NewLine)
    }
    catch {
        Write-Warning ('Manifest update skipped for {0}: {1}' -f $backupDir, $_.Exception.Message)
    }
}

$afterBytes = Get-DirectoryBytes $root

Write-Host ''
Write-Host 'Done.'
Write-Host ('Processed folders: {0}' -f $processedFolders)
Write-Host ('Freed estimate   : {0}' -f (Format-Size $freed))
Write-Host ('Backup size now  : {0}' -f (Format-Size $afterBytes))
Write-Host ''
Write-Host 'Next step: install CodexProfileGuardianSetup-latest.exe so future backups stay lightweight.'
