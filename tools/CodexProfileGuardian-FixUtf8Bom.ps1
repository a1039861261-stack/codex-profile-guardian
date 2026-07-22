[CmdletBinding()]
param(
    [string]$GuardianDataRoot = (Join-Path $env:LOCALAPPDATA 'Codex Profile Guardian')
)

$ErrorActionPreference = 'Stop'

function Test-IsUnderPath {
    param([string]$Child, [string]$Parent)
    $childFull = [System.IO.Path]::GetFullPath($Child).TrimEnd('\')
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $childFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase) -or
        $childFull.StartsWith($parentFull + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Write-Utf8NoBomBytes {
    param([string]$Path, [byte[]]$Bytes)
    $tmp = $Path + '.guardian-bomfix.tmp'
    [System.IO.File]::WriteAllBytes($tmp, $Bytes)
    [System.IO.File]::Copy($tmp, $Path, $true)
    Remove-Item -LiteralPath $tmp -Force
}

$root = (Resolve-Path -LiteralPath $GuardianDataRoot -ErrorAction Stop).Path
$expected = [System.IO.Path]::Combine('Codex Profile Guardian')
if (-not $root.EndsWith($expected, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refuse to operate outside a Codex Profile Guardian data directory: $root"
}

$targets = New-Object System.Collections.Generic.List[string]
foreach ($name in @('profiles.json', 'events.jsonl')) {
    $path = Join-Path $root $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $targets.Add((Resolve-Path -LiteralPath $path).Path) | Out-Null
    }
}

$backupRoot = Join-Path $root 'backups'
if (Test-Path -LiteralPath $backupRoot -PathType Container) {
    Get-ChildItem -LiteralPath $backupRoot -Recurse -Force -File -Include 'manifest.json','rollout-first-lines.jsonl' |
        ForEach-Object { $targets.Add($_.FullName) | Out-Null }
}

$checked = 0
$fixed = 0
foreach ($path in $targets) {
    if (-not (Test-IsUnderPath $path $root)) {
        throw "Unsafe path detected: $path"
    }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $checked += 1
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $newBytes = New-Object byte[] ($bytes.Length - 3)
        [Array]::Copy($bytes, 3, $newBytes, 0, $newBytes.Length)
        Write-Utf8NoBomBytes -Path $path -Bytes $newBytes
        $fixed += 1
    }
}

Write-Host ''
Write-Host 'Codex Profile Guardian UTF-8 BOM repair'
Write-Host ('Data root : {0}' -f $root)
Write-Host ('Checked   : {0}' -f $checked)
Write-Host ('Fixed     : {0}' -f $fixed)
Write-Host ''
Write-Host 'Done. You can open Codex Profile Guardian again.'
