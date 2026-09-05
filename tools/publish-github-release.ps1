param(
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)][string]$Commit
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Version = (Get-Content -LiteralPath (Join-Path $ProjectRoot 'VERSION') -Raw).Trim()
$Repo = 'a1039861261-stack/codex-profile-guardian'
$Tag = "v$Version"
if ($Commit -notmatch '^[a-f0-9]{40}$' -or $Version -eq '1.6.2') { throw 'Invalid new release target' }
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_EVENT_NAME -ne 'workflow_dispatch' -or $env:GITHUB_REF -ne 'refs/heads/main' -or $env:GITHUB_REPOSITORY -ne $Repo -or $Commit -cne $env:GITHUB_SHA) {
    throw 'Publication requires an explicit manual dispatch on the official main branch'
}
& (Join-Path $PSScriptRoot 'verify-release-assets.ps1') -OutputRoot $OutputRoot -ExpectedCommit $Commit
$Main = gh api "repos/$Repo/commits/main" --jq .sha
if ($LASTEXITCODE -ne 0 -or $Main.Trim() -cne $Commit) { throw 'Main changed or could not be verified' }
$ExistingTags = gh api "repos/$Repo/git/matching-refs/tags/$Tag" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or @($ExistingTags | Where-Object ref -EQ "refs/tags/$Tag").Count -gt 0) { throw 'Version tag already exists or lookup failed; never overwrite it' }
$Files = @(
    Join-Path $OutputRoot "CodexProfileGuardianSetup-v$Version.exe"
    Join-Path $OutputRoot "Codex-Profile-Guardian-Windows-x64-v$Version.zip"
    Join-Path $OutputRoot "Codex-Profile-Guardian-v$Version-manifest.json"
    Join-Path $OutputRoot "Codex-Profile-Guardian-v$Version-SHA256SUMS.txt"
)
gh release create $Tag @Files --repo $Repo --target $Commit --title "Codex Profile Guardian $Tag" --generate-notes --draft
if ($LASTEXITCODE -ne 0) { throw 'Draft creation failed; inspect it before retrying' }
$Release = gh release view $Tag --repo $Repo --json assets,isDraft | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $Release.isDraft -or $Release.assets.Count -ne 4) { throw 'Draft asset verification failed; not published' }
foreach ($FilePath in $Files) {
    $File = Get-Item -LiteralPath $FilePath
    $Asset = @($Release.assets | Where-Object name -CEQ $File.Name)
    $Digest = 'sha256:' + (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Asset.Count -ne 1 -or $Asset[0].size -ne $File.Length -or $Asset[0].digest -cne $Digest) { throw 'Uploaded asset mismatch; draft retained, not published' }
}
gh release edit $Tag --repo $Repo --draft=false --latest
if ($LASTEXITCODE -ne 0) { throw 'Publication result uncertain; inspect before retrying' }
