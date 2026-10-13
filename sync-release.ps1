# Sync origin/master to github/master and sync origin/release-<version> & github/release-<version>
# Usage: .\sync-release.ps1 <version>
# Also supports: .\sync-release.ps1 -Version <version>
# Example: .\sync-release.ps1 1.0.2

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Version
)

$ErrorActionPreference = "Stop"
$ReleaseBranch = "release-$Version"

Write-Host "[SYNC] >>> Sync start. Version: $Version, release branch: $ReleaseBranch" -ForegroundColor Cyan
Write-Host ""

# Go to repo root (support both root and scripts directory)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path (Join-Path $ScriptDir ".git")) {
    # Current directory is repo root
    $RepoRoot = $ScriptDir
} else {
    # Repo root is parent of scripts directory
    $RepoRoot = Split-Path -Parent $ScriptDir
}
Set-Location $RepoRoot

# Check remotes
$remotes = git remote
if ($remotes -notcontains "origin") {
    Write-Host "[ERROR] remote 'origin' not found." -ForegroundColor Red
    exit 1
}
if ($remotes -notcontains "github") {
    Write-Host "[ERROR] remote 'github' not found." -ForegroundColor Red
    Write-Host "Hint: git remote add github <github-repo-url>"
    exit 1
}

# Fetch latest origin/master
Write-Host "[SYNC] >>> Fetch origin/master ..." -ForegroundColor Cyan
git fetch origin master
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Before creating release branch, ensure no same-name branch exists on remotes
Write-Host "[SYNC] >>> Check if branch $ReleaseBranch already exists on remotes ..." -ForegroundColor Cyan
$originBranch = git ls-remote --heads origin $ReleaseBranch
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($originBranch) {
    Write-Host "[ERROR] origin already has branch $ReleaseBranch. abort." -ForegroundColor Red
    exit 1
}
$githubBranch = git ls-remote --heads github $ReleaseBranch
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($githubBranch) {
    Write-Host "[ERROR] github already has branch $ReleaseBranch. abort." -ForegroundColor Red
    exit 1
}

# 1. Push origin/master -> github/master
Write-Host "[SYNC] >>> Push origin/master -> github/master" -ForegroundColor Cyan
git push github origin/master:refs/heads/master
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 2. Create release-<version> on origin
Write-Host "[SYNC] >>> Create branch $ReleaseBranch on origin ..." -ForegroundColor Cyan
git push origin origin/master:refs/heads/$ReleaseBranch
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 3. Push origin/master -> github/release-<version>
Write-Host "[SYNC] >>> Push origin/master -> github/$ReleaseBranch" -ForegroundColor Cyan
git push github origin/master:refs/heads/$ReleaseBranch
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host ("[SYNC] [OK] sync done: github/master and github/{0} are now same as origin/master." -f $ReleaseBranch) -ForegroundColor Cyan
