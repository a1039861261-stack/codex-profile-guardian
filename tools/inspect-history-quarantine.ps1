# Read-only inspection of a Guardian quarantine and its full cold backup.
# Only a new JSON report is written. No history, database, credential, or process changes.
param([string]$QuarantinePath, [string]$ReportPath)

function Invoke-GuardianQuarantineCheck {
    param([string]$QuarantinePath, [string]$ReportPath)
$ErrorActionPreference = 'Stop'
function Assert-LocalPath([string]$Value) {
    if ($Value -notmatch '^[A-Za-z]:[\\/]' -or $Value.Substring(2).Contains(':')) {
        throw 'local_path_required'
    }
    $full = [IO.Path]::GetFullPath($Value).TrimEnd('\', '/')
    $cursor = $full
    while ($cursor -and $cursor.Length -gt 3) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'reparse_point_refused'
            }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    return $full
}
function Join-Scoped([string]$Root, [string]$Relative) {
    if ([string]::IsNullOrWhiteSpace($Relative) -or
        $Relative -match '(^|[\\/])\.{1,2}([\\/]|$)|:|^[\\/]' -or
        $Relative -match '[\x00-\x1f]') { throw 'relative_path_invalid' }
    $target = Assert-LocalPath (Join-Path $Root $Relative)
    if (-not $target.StartsWith($Root.TrimEnd('\', '/') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'path_outside_root'
    }
    return $target
}
function Read-Manifest([string]$Path) {
    if (-not [IO.File]::Exists($Path) -or (Get-Item -LiteralPath $Path).Length -gt 32MB) {
        throw 'manifest_missing_or_oversized'
    }
    return ([IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json)
}
function Get-Snapshot([string]$Path, [bool]$Metadata) {
    if (-not [IO.File]::Exists($Path)) { return [ordered]@{exists=$false} }
    $stream = $null
    $digest = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $digest = [Security.Cryptography.SHA256]::Create()
        $snapshot = [ordered]@{
            exists=$true; size=$stream.Length
            sha256=([BitConverter]::ToString($digest.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        }
        if ($Metadata) {
            $null = $stream.Seek(0, [IO.SeekOrigin]::Begin)
            $bytes = New-Object byte[] (1MB)
            $count = 0
            $newline = -1
            while ($count -lt $bytes.Length -and $newline -lt 0) {
                $read = $stream.Read($bytes, $count, [Math]::Min(4096, $bytes.Length - $count))
                if ($read -eq 0) { break }
                $count += $read
                $newline = [Array]::IndexOf($bytes, [byte]10, 0, $count)
            }
            if ($newline -lt 0 -and $count -eq $bytes.Length) { throw 'metadata_limit' }
            $lineLength = if ($newline -ge 0) { $newline } else { $count }
            $utf8 = New-Object Text.UTF8Encoding($false, $true)
            $meta = $utf8.GetString($bytes, 0, $lineLength) | ConvertFrom-Json
            $uuid = '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$'
            if ($meta.type -cne 'session_meta' -or [string]$meta.payload.id -notmatch $uuid) {
                throw 'metadata_identity_invalid'
            }
            $snapshot.thread_id = [string]$meta.payload.id
            $snapshot.first_line_bytes = $lineLength + [int]($newline -ge 0)
            $snapshot.history_mode = if ($meta.payload.history_mode -ceq 'paginated') {'paginated'} elseif ($null -eq $meta.payload.history_mode) {'absent'} else {'other'}
            $snapshot.history_base = $null
            if ($null -ne $meta.payload.history_base) {
                $base = $meta.payload.history_base
                if ([string]$base.thread_id -notmatch $uuid -or
                    [string]$base.end_byte_offset -notmatch '^\d+$' -or
                    [string]$base.end_ordinal_exclusive -notmatch '^[1-9]\d*$') { throw 'history_base_invalid' }
                $snapshot.history_base = [ordered]@{
                    thread_id=[string]$base.thread_id
                    end_byte_offset=[string]$base.end_byte_offset
                    end_ordinal_exclusive=[string]$base.end_ordinal_exclusive
                }
            }
        }
        return $snapshot
    } catch {
        # Never return arbitrary exception text or JSON/chat content.
        return [ordered]@{exists=$true; readable=$false; error_type=$_.Exception.GetType().Name}
    } finally {
        if ($digest) { $digest.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}
function Test-RecordedHash($Snapshot, $Entry) {
    return ($Snapshot.exists -and $null -ne $Snapshot.sha256 -and
        [string]$Entry.sha256 -match '^[a-fA-F0-9]{64}$' -and
        [string]$Snapshot.size -ceq [string]$Entry.size -and $Snapshot.sha256 -ieq [string]$Entry.sha256)
}

$stage = 'input'
$report = $null
try {
    if ([string]::IsNullOrWhiteSpace($QuarantinePath)) {
        $QuarantinePath = Read-Host 'Paste the full Guardian quarantine folder path'
    }
    $quarantineRoot = Assert-LocalPath $QuarantinePath.Trim().Trim('"')
    if ([IO.Path]::GetFileName($quarantineRoot) -notmatch '^\d{8}-\d{6}-\d{6}-divergent-history$' -or
        [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($quarantineRoot)) -cne 'history-conflicts') {
        throw 'quarantine_directory_invalid'
    }
    $guardianRoot = Assert-LocalPath ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($quarantineRoot)))
    $stage = 'quarantine_manifest'
    $qm = Read-Manifest (Join-Scoped $quarantineRoot 'manifest.json')
    if ($qm.schema_version -ne 1 -or $qm.state -cne 'complete' -or
        [string]$qm.cold_backup -notmatch '^\d{8}-\d{6}-\d{6}-before-conflict-isolation$') { throw 'quarantine_manifest_invalid' }
    $coldRoot = Join-Scoped $guardianRoot ('history-cold-backups\' + $qm.cold_backup)
    if (Test-Path -LiteralPath (Join-Scoped $coldRoot 'INCOMPLETE.json')) { throw 'cold_backup_incomplete' }
    $stage = 'cold_manifest'
    $cm = Read-Manifest (Join-Scoped $coldRoot 'manifest.json')
    if ($cm.schema_version -ne 1 -or $cm.name -cne $qm.cold_backup -or $cm.backup_mode -cne 'full-history-cold') {
        throw 'cold_manifest_invalid'
    }
    $codexRoot = Assert-LocalPath ([string]$cm.codex_home)
    if ($codexRoot.Length -lt 4 -or -not [IO.Directory]::Exists($codexRoot)) { throw 'codex_root_missing' }
    $uuidPart = '[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
    $filePattern = '^(?:sessions|archived_sessions)[\\/](?:\d{4}[\\/]\d{2}[\\/]\d{2}[\\/])?rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-(' + $uuidPart + ')(?:_(' + $uuidPart + '))?\.jsonl$'
    $coldByRelative = @{}
    foreach ($entry in @($cm.files)) {
        $relative = ([string]$entry.relative).Replace('/', '\')
        if ($coldByRelative.ContainsKey($relative)) { throw 'duplicate_cold_entry' }
        $coldByRelative[$relative] = $entry
    }
    $seen = @{}
    $threadIds = @{}
    $rows = @()
    $stage = 'quarantine_files'
    foreach ($entry in @($qm.files)) {
        $relative = ([string]$entry.relative).Replace('/', '\')
        if ($relative -notmatch $filePattern -or $seen.ContainsKey($relative)) { throw 'quarantine_entry_invalid' }
        $threadId = $Matches[1].ToLowerInvariant()
        $seen[$relative] = $true
        $threadIds[$threadId] = $true
        $coldEntry = $coldByRelative[$relative]
        if ($null -eq $coldEntry -or $coldEntry.sha256 -cne $entry.sha256 -or $coldEntry.size -ne $entry.size) {
            throw 'manifest_records_disagree'
        }
        $source = Get-Snapshot (Join-Scoped $quarantineRoot ('files\' + $relative)) $true
        $cold = Get-Snapshot (Join-Scoped $coldRoot ('files\' + $relative)) $true
        $current = Get-Snapshot (Join-Scoped $codexRoot $relative) $true
        $rows += [ordered]@{
            relative=$relative; expected_sha256=[string]$entry.sha256; expected_size=$entry.size
            quarantine=$source; cold=$cold; current=$current
            quarantine_verified=((Test-RecordedHash $source $entry) -and $source.thread_id -ieq $threadId)
            cold_verified=((Test-RecordedHash $cold $entry) -and $cold.thread_id -ieq $threadId)
        }
    }
    if ($rows.Count -eq 0) { throw 'empty_quarantine' }
    $stage = 'related_current_files'
    $remaining = @()
    foreach ($entry in @($cm.files)) {
        $relative = ([string]$entry.relative).Replace('/', '\')
        if ($relative -match $filePattern -and $threadIds.ContainsKey($Matches[1].ToLowerInvariant()) -and -not $seen.ContainsKey($relative)) {
            $remaining += [ordered]@{relative=$relative; current=(Get-Snapshot (Join-Scoped $codexRoot $relative) $true)}
        }
    }
    $report = [ordered]@{
        schema_version=1; check='guardian-quarantine-readonly'; inspected_at=[DateTime]::UtcNow.ToString('o')
        history_modified=$false; credentials_read=$false; database_opened=$false
        restore_ready=$false; limitation='Inspection only; no live database/lineage validation or recovery was performed.'
        codex_home=$codexRoot; quarantine_batch=[IO.Path]::GetFileName($quarantineRoot); cold_backup=$cm.name
        backup_recorded_integrity=$cm.database.integrity; backup_recorded_thread_count=$cm.database.thread_count
        database_rows_repointed=$qm.database_rows_repointed; files=$rows; related_current_files=$remaining
        verified_quarantine_files=@($rows | Where-Object {$_.quarantine_verified}).Count
        verified_cold_files=@($rows | Where-Object {$_.cold_verified}).Count
        missing_original_files=@($rows | Where-Object {-not $_.current.exists}).Count
    }
} catch {
    $report = [ordered]@{schema_version=1; check='guardian-quarantine-readonly'; history_modified=$false; restore_ready=$false; failed_stage=$stage; error_type=$_.Exception.GetType().Name}
}
# CreateNew and path checks prevent overwriting existing data or placing a report in protected storage.
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path ([Environment]::GetFolderPath('Desktop')) ('GuardianHistoryCheck-' + [DateTime]::Now.ToString('yyyyMMdd-HHmmss') + '.json')
}
$reportTarget = Assert-LocalPath $ReportPath
foreach ($protectedRoot in @($codexRoot, $guardianRoot)) {
    if ($protectedRoot -and ($reportTarget.Equals($protectedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $reportTarget.StartsWith($protectedRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase))) { throw 'report_in_protected_storage' }
}
$reportBytes = [Text.Encoding]::UTF8.GetBytes(($report | ConvertTo-Json -Depth 12))
$reportStream = [IO.File]::Open($reportTarget, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $reportStream.Write($reportBytes, 0, $reportBytes.Length) } finally { $reportStream.Dispose() }
Write-Output ('Report saved: ' + $reportTarget)
}
Invoke-GuardianQuarantineCheck -QuarantinePath $QuarantinePath -ReportPath $ReportPath
