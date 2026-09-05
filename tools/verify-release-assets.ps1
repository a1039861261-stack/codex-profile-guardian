param(
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedCommit
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Version = (Get-Content -LiteralPath (Join-Path $ProjectRoot 'VERSION') -Raw).Trim()
$AssetRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$Manifest = Get-Content -LiteralPath (Join-Path $AssetRoot "Codex-Profile-Guardian-v$Version-manifest.json") -Raw | ConvertFrom-Json
if ($Manifest.product -ne 'Codex Profile Guardian' -or $Manifest.version -ne $Version -or $Manifest.source_commit -cne $ExpectedCommit) {
    throw 'Release identity or source commit mismatch'
}
$ExpectedNames = @('CodexProfileGuardian.exe', 'CodexProfileGuardianSecret.exe', 'GuardianGateway.exe', 'GuardianGatewaySupervisor.exe', "Codex-Profile-Guardian-Windows-x64-v$Version.zip", "CodexProfileGuardianSetup-v$Version.exe")
if ($Manifest.artifacts.Count -ne 6 -or (Compare-Object ($ExpectedNames | Sort-Object) ($Manifest.artifacts.name | Sort-Object))) {
    throw 'Unexpected release artifact set'
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$Archive = [IO.Compression.ZipFile]::OpenRead((Join-Path $AssetRoot "Codex-Profile-Guardian-Windows-x64-v$Version.zip"))
try {
    $ExpectedZipNames = @('CodexProfileGuardian.exe', 'CodexProfileGuardianSecret.exe', 'GuardianGateway.exe', 'GuardianGatewaySupervisor.exe', 'README-CN.md', 'LICENSE', 'VERSION')
    if ($Archive.Entries.Count -ne 7 -or (Compare-Object ($ExpectedZipNames | Sort-Object) ($Archive.Entries.FullName | Sort-Object))) {
        throw 'Unexpected portable ZIP contents'
    }
    $VersionReader = [IO.StreamReader]::new($Archive.GetEntry('VERSION').Open())
    try { if ($VersionReader.ReadToEnd().Trim() -ne $Version) { throw 'ZIP version mismatch' } }
    finally { $VersionReader.Dispose() }
    $Sums = Get-Content -LiteralPath (Join-Path $AssetRoot "Codex-Profile-Guardian-v$Version-SHA256SUMS.txt")
    if ($Sums.Count -ne 6) { throw 'Unexpected SHA256SUMS entry count' }
    foreach ($Entry in $Manifest.artifacts) {
        $ExpectedRelative = if ($Entry.name.EndsWith('.exe') -and -not $Entry.name.StartsWith('CodexProfileGuardianSetup-')) {
            "Codex-Profile-Guardian-Portable-v$Version/$($Entry.name)"
        } else { $Entry.name }
        if ($Entry.relative_path -cne $ExpectedRelative -or $Entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid manifest artifact path or hash' }
        if ($ExpectedRelative.Contains('/')) {
            $ZipEntry = $Archive.GetEntry($Entry.name)
            $Size = $ZipEntry.Length
            $Stream = $ZipEntry.Open()
        } else {
            $File = Get-Item -LiteralPath (Join-Path $AssetRoot $Entry.name)
            $Size = $File.Length
            $Stream = $File.OpenRead()
        }
        $Hasher = [Security.Cryptography.SHA256]::Create()
        try { $Hash = [BitConverter]::ToString($Hasher.ComputeHash($Stream)).Replace('-', '') }
        finally { $Stream.Dispose(); $Hasher.Dispose() }
        if ($Size -ne $Entry.bytes -or $Hash -ne $Entry.sha256 -or "$($Entry.sha256)  $ExpectedRelative" -cnotin $Sums) {
            throw "Artifact size/hash mismatch: $($Entry.name)"
        }
    }
}
finally { $Archive.Dispose() }
[pscustomobject]@{ ok = $true; version = $Version; source_commit = $ExpectedCommit; artifacts_verified = 6; zip_entries = 7 } | ConvertTo-Json
